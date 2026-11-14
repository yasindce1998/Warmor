#!/usr/bin/env bash
# kind e2e test for the Helm chart (docs/operations.md, deploy/helm/warmor).
#
# Builds the image (or reuses WARMOR_IMAGE), loads it into a fresh kind
# cluster, installs the chart and verifies the daemon actually runs: pods
# Ready, policy loaded, metrics served. This is the test that fails when
# the chart stops starting.
#
# Usage: ./scripts/kind-e2e.sh [image-tag]
#        WARMOR_IMAGE=warmor:e2e ./scripts/kind-e2e.sh   # skip the build
set -euo pipefail

TAG="${1:-warmor:e2e}"
IMAGE="${WARMOR_IMAGE:-}"
CLUSTER="warmor-e2e"
RELEASE="warmor-e2e"
KCTX=(--context "kind-$CLUSTER")
DIAGNOSTICS_DIR="${WARMOR_E2E_DIAGNOSTICS_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/warmor-kind-e2e-diagnostics}"

for tool in docker kind kubectl helm curl; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done

collect_diagnostics() {
  # Run before deleting the cluster, including when Helm --wait fails before
  # the explicit pod wait. Keep every read bounded and avoid policy contents,
  # kubeconfigs, Secrets and full environment dumps in CI logs/artifacts.
  echo "--- collecting failed kind e2e diagnostics" >&2
  kubectl "${KCTX[@]}" --request-timeout=10s get nodes -o wide || true
  kubectl "${KCTX[@]}" --request-timeout=10s get daemonsets,deployments,pods -o wide || true
  kubectl "${KCTX[@]}" --request-timeout=10s describe pods \
    -l "app.kubernetes.io/instance=$RELEASE" || true
  kubectl "${KCTX[@]}" --request-timeout=10s get events \
    --sort-by=.metadata.creationTimestamp || true
  local container
  for container in validate-policy warmor controller; do
    kubectl "${KCTX[@]}" --request-timeout=10s logs \
      -l "app.kubernetes.io/instance=$RELEASE" -c "$container" \
      --tail=100 --timestamps=true --prefix=true || true
    kubectl "${KCTX[@]}" --request-timeout=10s logs \
      -l "app.kubernetes.io/instance=$RELEASE" -c "$container" \
      --previous --tail=100 --timestamps=true --prefix=true || true
  done
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    # Diagnostic/storage failures must not hide the original Helm/probe error
    # or prevent deletion of this disposable test cluster.
    if mkdir -p "$DIAGNOSTICS_DIR"; then
      collect_diagnostics >"$DIAGNOSTICS_DIR/diagnostics.log" 2>&1 || true
      cat "$DIAGNOSTICS_DIR/diagnostics.log" >&2 || true
    else
      collect_diagnostics >&2 || true
    fi
  fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT

if [ -z "$IMAGE" ]; then
  echo "--- building image $TAG"
  docker build -f deploy/Dockerfile -t "$TAG" "$(dirname "$0")/.."
  IMAGE="$TAG"
fi

echo "--- creating kind cluster"
kind create cluster --name "$CLUSTER" --wait 60s
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "--- installing chart"
helm install "$RELEASE" deploy/helm/warmor/ \
  --set image.repository="$(echo "$IMAGE" | cut -d: -f1)" \
  --set image.tag="$(echo "$IMAGE" | cut -d: -f2)" \
  --set image.pullPolicy=Never \
  --wait --timeout 300s

echo "--- waiting for daemon pods"
kubectl --context "kind-$CLUSTER" wait --for=condition=Ready pod \
  -l app.kubernetes.io/name=warmor --timeout=300s

echo "--- checking metrics endpoint (the daemon's health signal)"
# Auto scope evaluates discovered pod cgroups, not arbitrary host execs.
# Metrics verify local startup, not kernel blocking:
#   warmor_ebpf_loader_status 1          -> eBPF programs loaded
#   warmor_policy_info{path=...wasm} 1   -> the policy actually loaded
METRICS=$(kubectl --context "kind-$CLUSTER" run metrics-check --rm -i --restart=Never \
  --image=curlimages/curl:latest --command -- \
  curl -sf "http://${RELEASE}-metrics:9090/metrics" 2>/dev/null \
  | grep -E "^warmor_(policy_info|ebpf_loader_status)" | head -3 || true)
echo "$METRICS"
echo "$METRICS" | grep -q '^warmor_policy_info{path="/etc/warmor/policy.wasm"' || {
  echo "error: policy_info metric missing - the baked-in policy did not load" >&2; exit 1; }
echo "$METRICS" | grep -q "^warmor_ebpf_loader_status 1" || {
  echo "error: ebpf_loader_status is not 1" >&2; exit 1; }

echo "--- sample daemon logs"
kubectl --context "kind-$CLUSTER" logs -c warmor \
  -l app.kubernetes.io/name=warmor --tail 3 2>/dev/null | cut -c1-140 || true

echo
echo "PASS: chart installs and the daemon runs"

# ---------------------------------------------------------------------------
# WarmorPolicy controller phase: enable the controller, apply a CR and
# verify it compiles, publishes and hot-reloads on the nodes. This is
# the test that fails when the WarmorPolicy path stops working.
# ---------------------------------------------------------------------------
CTL_TAG="warmor-controller:e2e"
CTL_IMAGE="${WARMOR_CONTROLLER_IMAGE:-}"

if [ -z "$CTL_IMAGE" ]; then
  echo "--- building controller image $CTL_TAG"
  # Shares the Go builder stage cache with the daemon build above.
  docker build -f deploy/Dockerfile --target controller -t "$CTL_TAG" "$(dirname "$0")/.."
  CTL_IMAGE="$CTL_TAG"
fi
kind load docker-image "$CTL_IMAGE" --name "$CLUSTER"

echo "--- enabling the WarmorPolicy controller"
# Helm only installs CRDs on initial install; it does not upgrade crds/.
# Apply the publication-status schema explicitly before upgrading the controller.
kubectl --context "kind-$CLUSTER" apply -f deploy/helm/warmor/crds/warmorpolicy-crd.yaml
kubectl --context "kind-$CLUSTER" wait --for=condition=Established \
  crd/warmorpolicies.warmor.io --timeout=60s
helm upgrade "$RELEASE" deploy/helm/warmor/ \
  --set image.repository="$(echo "$IMAGE" | cut -d: -f1)" \
  --set image.tag="$(echo "$IMAGE" | cut -d: -f2)" \
  --set image.pullPolicy=Never \
  --set controller.enabled=true \
  --set controller.image.repository="$(echo "$CTL_IMAGE" | cut -d: -f1)" \
  --set controller.image.tag="$(echo "$CTL_IMAGE" | cut -d: -f2)" \
  --set controller.image.pullPolicy=Never \
  --wait --timeout 300s

echo "--- waiting for the controller's first sync (the baked default policy)"
wait_for() { # wait_for <description> <timeout-s> <command...>
  local desc="$1" timeout="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "error: timed out waiting for $desc" >&2; return 1
    fi
    sleep 3
  done
}
EFFECTIVE_CM="${RELEASE}-effective-policy"
wait_for "the effective policy ConfigMap" 300 \
  kubectl "${KCTX[@]}" get configmap "$EFFECTIVE_CM"
echo "✓ ConfigMap $EFFECTIVE_CM created"

echo "--- applying a WarmorPolicy"
kubectl "${KCTX[@]}" apply -f - <<'EOF'
apiVersion: warmor.io/v1alpha1
kind: WarmorPolicy
metadata:
  name: e2e-test
spec:
  name: e2e-test
  version: 42
  defaultAction: allow
  rules:
    - name: block-cr-marker-exec
      event: process
      conditions:
        all:
          - path: { glob: "/var/tmp/warmor-cr-*" }
      action: deny
      reason: "e2e test rule"
EOF

cr_is_published() {
  # These are publication assertions only. Applied stays Unknown until real
  # authenticated exact-digest node acknowledgements exist.
  [ "$(kubectl "${KCTX[@]}" get warmorpolicy e2e-test -o jsonpath='{.status.phase}' 2>/dev/null)" = "Published" ] &&
    [ "$(kubectl "${KCTX[@]}" get warmorpolicy e2e-test -o jsonpath='{.status.conditions[?(@.type=="Published")].status}' 2>/dev/null)" = "True" ]
}
echo "--- waiting for the CR to compile and publish (not node application)"
wait_for "WarmorPolicy e2e-test publication" 300 cr_is_published
echo "✓ WarmorPolicy e2e-test is $(kubectl "${KCTX[@]}" get warmorpolicy e2e-test -o jsonpath='{.status.phase}')"

cm_has_source() {
  kubectl "${KCTX[@]}" get configmap "$EFFECTIVE_CM" \
    -o jsonpath='{.metadata.annotations.warmor\.io/sources}' 2>/dev/null | grep -q e2e-test
}
wait_for "the effective policy to include e2e-test" 60 cm_has_source
echo "✓ effective policy sources: $(kubectl "${KCTX[@]}" get configmap "$EFFECTIVE_CM" -o jsonpath='{.metadata.annotations.warmor\.io/sources}')"

# The reload log line is informational, not gating: whether the daemon
# logs "Policy reloaded successfully" depends on kubelet mount timing —
# if the ConfigMap's new content is mounted before the daemon first
# starts cleanly, the policy may already be loaded without a reload event.
# The audit probe below observes decisions separately. The full log is
# searched because pod events on the shared kind kernel can flood it.
# Scope the log selector to the daemon pod: the bare app name also
# matches the controller pod once it is deployed, and kubectl refuses a
# multi-pod logs call without --prefix.
if kubectl "${KCTX[@]}" logs -c warmor \
  -l app.kubernetes.io/name=warmor,component=daemon \
  2>/dev/null | grep -q "Policy reloaded successfully"; then
  echo "✓ daemon hot-reloaded the WarmorPolicy from the ConfigMap"
else
  echo "ℹ no reload event logged (policy likely mounted at daemon start)"
fi

# Audit smoke: the CR denies exec of /var/tmp/warmor-cr-* — a path the baked
# default policy does not cover (it only blocks /tmp/**). The intended chain is:
# CR → compile → ConfigMap → kubelet mount → daemon reload → policy
# evaluation → would-deny. Audit mode remains enabled throughout this test.
# The deny is asserted through the warmor_events_total{action="DENY"}
# counter rather than log grepping: a busy pod can rotate logs rapidly.
# This aggregate counter can include unrelated denies; it is not authenticated
# per-node, exact-digest activation evidence or proof of successful enforcement.
# The counter is monotonic and
# survives rotation. The daemon is hostNetwork, so its metrics endpoint
# is reachable on the node IP.
# Host execution is deliberately NOT the probe: auto scope excludes it. Create
# a non-root pod AFTER startup and retry beyond the reconciliation lag.
echo "--- verifying the CR policy is audit-evaluated on a new pod"
NODE_IP=$(kubectl "${KCTX[@]}" get nodes \
  -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
deny_count() {
  curl -sf --max-time 5 "http://$NODE_IP:9090/metrics" 2>/dev/null \
    | awk '/^warmor_events_total\{action="DENY"\}/ {print $2}'
}
MARKER="/var/tmp/warmor-cr-marker-$$"
PROBE="warmor-audit-probe"
kubectl "${KCTX[@]}" run "$PROBE" --image=busybox:1.37 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsUser":10001,"runAsGroup":10001,"runAsNonRoot":true}}}' \
  --command -- sleep 600
kubectl "${KCTX[@]}" wait --for=condition=Ready "pod/$PROBE" --timeout=120s
# The counter family only exists after the daemon's first deny ever, so a
# fresh daemon scraping 0 denies returns nothing — treat that as 0.
BEFORE_DENIES=$(deny_count)
BEFORE_DENIES=${BEFORE_DENIES:-0}
policy_audit_observed() {
  # Re-exec per retry: the daemon's reload lags the ConfigMap update by
  # kubelet propagation plus its 2s mtime poll, and until it lands the
  # marker exec is allowed (the default policy does not cover /var/tmp).
  kubectl "${KCTX[@]}" exec "$PROBE" -- sh -c 'printf "#!/bin/sh\nexit 0\n" > "$1" && chmod 755 "$1" && "$1"' sh "$MARKER" >/dev/null 2>&1 || return 1
  local now
  now=$(deny_count)
  [ -n "$now" ] && [ "$now" -gt "$BEFORE_DENIES" ]
}
if ! wait_for "the daemon to audit-evaluate the policy on the new pod" 240 policy_audit_observed; then
  echo "error: deny counter did not move (before=$BEFORE_DENIES now=$(deny_count))" >&2
  exit 1
fi
kubectl "${KCTX[@]}" delete pod "$PROBE" --wait=true
echo "✓ daemon evaluated the policy on a new non-root pod without terminating it"

echo
echo "PASS: WarmorPolicy CRs compile, publish and hot-reload"
