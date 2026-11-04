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

for tool in docker kind kubectl helm; do
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
