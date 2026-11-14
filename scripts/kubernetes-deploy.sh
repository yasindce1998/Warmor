#!/usr/bin/env bash
# Compile, validate and mount the actual selected policy. DRY_RUN=true performs
# only local rendering/client dry-run; no cluster reads/writes. Retain old
# content-addressed ConfigMaps for rollback rather than overwriting policy bytes.
set -euo pipefail

MODE=""
POLICY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode|--policy)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      if [[ "$1" == --mode ]]; then MODE="$2"; else POLICY="$2"; fi
      shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$MODE" == audit || "$MODE" == enforce ]] || { echo "--mode audit|enforce is required" >&2; exit 2; }
[[ -f "$POLICY" ]] || { echo "--policy must name an existing file: $POLICY" >&2; exit 2; }
NAMESPACE="${NAMESPACE:-warmor-system}"
RELEASE="${RELEASE:-warmor}"
CHART="${CHART:-deploy/helm/warmor}"
IMAGE="${IMAGE:-ghcr.io/yasindce1998/warmor}"
TAG="${TAG:-latest}"
DRY_RUN="${DRY_RUN:-false}"
[[ "$DRY_RUN" == true || "$DRY_RUN" == false ]] || { echo "DRY_RUN must be true or false" >&2; exit 2; }
[[ "$RELEASE" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ && ${#RELEASE} -le 40 ]] || { echo "RELEASE must be a DNS label of at most 40 characters" >&2; exit 2; }
if [[ "$MODE" == enforce && "${CONFIRM_NODE_WIDE_POLICY:-false}" != true ]]; then
  echo "enforcement requires CONFIRM_NODE_WIDE_POLICY=true; auto includes Warmor/system pods, not selectors" >&2
  exit 2
fi
if [[ "$DRY_RUN" == false && -z "${KUBE_CONTEXT:-}" ]]; then
  echo "live deployment requires explicit KUBE_CONTEXT (use DRY_RUN=true for local rendering)" >&2
  exit 2
fi
for tool in helm kubectl sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
TEMP_ROOT="${TMPDIR:-/tmp}"
if [[ -z "${TMPDIR:-}" && -d /tmp/opencode && -w /tmp/opencode ]]; then TEMP_ROOT=/tmp/opencode; fi
WORK=$(mktemp -d "$TEMP_ROOT/warmor-deploy.XXXXXXXX")
trap 'rm -f "$WORK/policy.wasm" "$WORK/configmap.yaml" "$WORK/rendered.yaml"; rmdir "$WORK"' EXIT
case "$POLICY" in
  *.wasm) cp -- "$POLICY" "$WORK/policy.wasm" ;;
  *.yaml|*.yml)
    compiler=(go run ./cmd/warmor-compile)
    if [[ -n "${WARMOR_COMPILE:-}" ]]; then compiler=("$WARMOR_COMPILE"); fi
    "${compiler[@]}" -o "$WORK/policy.wasm" "$POLICY" >&2 ;;
  *) echo "policy must be .yaml, .yml or .wasm (never silently ignored)" >&2; exit 2 ;;
esac
[[ -s "$WORK/policy.wasm" ]] || { echo "compiler produced no binary" >&2; exit 1; }
size=$(wc -c < "$WORK/policy.wasm")
[[ "$size" -le 786432 ]] || { echo "policy exceeds conservative 768KiB ConfigMap artifact budget" >&2; exit 1; }
validator=(go run ./cmd/warmor-daemon)
if [[ -n "${WARMOR_DAEMON:-}" ]]; then validator=("$WARMOR_DAEMON"); fi
"${validator[@]}" --validate-policy "$WORK/policy.wasm" >&2
HASH=$(sha256sum "$WORK/policy.wasm")
HASH="${HASH%% *}"
CM="${RELEASE}-policy-${HASH:0:16}"
kubectl create configmap "$CM" --namespace "$NAMESPACE" \
  --from-file="policy.wasm=$WORK/policy.wasm" --dry-run=client -o yaml > "$WORK/configmap.yaml"
VALUES=(--namespace "$NAMESPACE" --set-string "image.repository=$IMAGE" --set-string "image.tag=$TAG"
  --set-string "policy.existingConfigMap=$CM" --set controller.enabled=false)
if [[ "$MODE" == enforce ]]; then
  VALUES+=(--set daemon.auditMode=false --set daemon.lsmEnforce=true --set daemon.requireLSM=true
    --set daemon.confirmNodeWidePolicy=true --set-string daemon.cgroupFilter=auto)
else
  VALUES+=(--set daemon.auditMode=true --set daemon.lsmEnforce=false --set daemon.requireLSM=false
    --set daemon.defaultDeny=false --set-string daemon.cgroupFilter=auto)
fi
# Render before any cluster write. Reset old release values so audit transitions
# cannot accidentally inherit enforcement flags from the previous revision.
helm template "$RELEASE" "$CHART" "${VALUES[@]}" > "$WORK/rendered.yaml"
echo "Selected policy $POLICY -> $CM (sha256:$HASH), mode=$MODE, dry_run=$DRY_RUN" >&2
if [[ "$DRY_RUN" == true ]]; then
  cat "$WORK/configmap.yaml"
  echo "---"
  cat "$WORK/rendered.yaml"
  exit 0
fi
CTX=(--context "$KUBE_CONTEXT")
kubectl "${CTX[@]}" create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl "${CTX[@]}" apply -f -
kubectl "${CTX[@]}" apply -f "$WORK/configmap.yaml"
helm upgrade --install "$RELEASE" "$CHART" --kube-context "$KUBE_CONTEXT" \
  --reset-values "${VALUES[@]}" --wait --timeout 5m
