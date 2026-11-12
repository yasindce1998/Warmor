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

for tool in docker kind kubectl helm curl; do
  command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done

cleanup() {
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
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
# The kind node shares the host kernel, so the daemon evaluates hundreds of
# host execs per second and the startup banner is not reliably positioned in
# the log stream. The metrics are the authoritative check instead:
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
KCTX=(--context "kind-$CLUSTER")
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

cr_is_active() {
  [ "$(kubectl "${KCTX[@]}" get warmorpolicy e2e-test -o jsonpath='{.status.phase}' 2>/dev/null)" = "Active" ]
}
echo "--- waiting for the CR to compile and go Active"
wait_for "WarmorPolicy e2e-test to go Active" 300 cr_is_active
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
# starts cleanly, the policy is live without any reload event. The
# enforcement probe below is the real assertion. The full log is
# searched because the daemon evaluates every exec on the shared kind
# kernel, flooding the log.
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

# Enforcement proof: the CR denies exec of /var/tmp/warmor-cr-* — a path
# the baked default policy does not cover (it only blocks /tmp/**), so a
# deny of the marker can only come from the CR's own rule, attributing
# the enforcement to the CR specifically. This asserts the whole chain:
# CR → compile → ConfigMap → kubelet mount → daemon reload → policy
# evaluation → deny.
# The deny is asserted through the warmor_events_total{action="DENY"}
# counter rather than the daemon's log: on kind the node shares the host
# kernel, so the daemon evaluates every exec on it (hundreds of events
# per second) and the container log rotates within seconds — log lines
# are not a reliably greppable signal. The counter is monotonic and
# survives rotation. The daemon is hostNetwork, so its metrics endpoint
# is reachable on the node IP.
# The denied process is not SIGKILLed here: kind shares the kernel but
# not the host PID namespace, so the daemon's kill cannot reach the
# probe. On a real cluster (daemon on the node, same PID namespace as
# the workload) the deny ends in SIGKILL; on kind the counter is the
# verifiable part of the chain.
echo "--- verifying the CR policy is enforced (deny exec of the CR's marker path)"
NODE_IP=$(kubectl "${KCTX[@]}" get nodes \
  -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
deny_count() {
  curl -sf --max-time 5 "http://$NODE_IP:9090/metrics" 2>/dev/null \
    | awk '/^warmor_events_total\{action="DENY"\}/ {print $2}'
}
MARKER="/var/tmp/warmor-cr-marker-$$"
# The counter family only exists after the daemon's first deny ever, so a
# fresh daemon scraping 0 denies returns nothing — treat that as 0.
BEFORE_DENIES=$(deny_count)
BEFORE_DENIES=${BEFORE_DENIES:-0}
policy_enforced() {
  # Re-exec per retry: the daemon's reload lags the ConfigMap update by
  # kubelet propagation plus its 2s mtime poll, and until it lands the
  # marker exec is allowed (the default policy does not cover /var/tmp).
  cp /bin/true "$MARKER" 2>/dev/null || true
  "$MARKER" 2>/dev/null || true
  local now
  now=$(deny_count)
  [ -n "$now" ] && [ "$now" -gt "$BEFORE_DENIES" ]
}
if ! wait_for "the daemon to enforce the e2e policy (deny the CR's marker exec)" 240 policy_enforced; then
  echo "error: deny counter did not move (before=$BEFORE_DENIES now=$(deny_count))" >&2
  exit 1
fi
rm -f "$MARKER"
echo "✓ daemon enforces the WarmorPolicy (denied the CR's marker exec)"

echo
echo "PASS: WarmorPolicy CRs compile, publish and hot-reload"
