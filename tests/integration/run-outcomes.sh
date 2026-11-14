#!/usr/bin/env bash
# Build on the host; execute the daemon ONLY inside a disposable vimto VM.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

usage() {
  echo 'Usage: tests/integration/run-outcomes.sh [--build-only]'
  echo 'Requires Go, Rust wasm32-unknown-unknown; full run also needs vimto and QEMU.'
  echo 'Optional: VIMTO=/path/to/vimto KERNEL=/absolute/vmlinuz-or-OCI-reference'
}
BUILD_ONLY=false
# When Go invokes the suite through -exec, vimto sees a Go test binary, not
# this script. Both artifact binaries and repository paths stay on shared disk.
case "${1:-}" in
  --build-only) BUILD_ONLY=true ;;
  --help|-h) usage; exit 0 ;;
  '') ;;
  *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then usage >&2; exit 2; fi

for tool in go cargo rustup sha256sum; do
  command -v "$tool" >/dev/null || { echo "error: $tool is required" >&2; exit 1; }
done
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"
KERNEL="${KERNEL:-ghcr.io/cilium/ci-kernels:stable-selftests}"
if ! "$BUILD_ONLY"; then
  [ -x "$VIMTO" ] || { echo "error: vimto not found at $VIMTO; install lmb.io/vimto@v0.4.0" >&2; exit 1; }
  case "$(uname -m)" in
    x86_64) QEMU=qemu-system-x86_64 ;;
    aarch64) QEMU=qemu-system-aarch64 ;;
    *) echo 'error: unsupported VM architecture' >&2; exit 1 ;;
  esac
  command -v "$QEMU" >/dev/null || { echo "error: $QEMU is required" >&2; exit 1; }
fi

mkdir -p tests/integration/artifacts
ARTIFACTS="$(mktemp -d "$ROOT/tests/integration/artifacts/run.XXXXXX")"
chmod 0755 "$ARTIFACTS"
echo "Outcome artifacts: $ARTIFACTS (retained on success and failure)"
export CGO_ENABLED=0
export WARMOR_OUTCOME_ARTIFACTS="$ARTIFACTS"
go build -o "$ARTIFACTS/warmor-daemon" ./cmd/warmor-daemon
go test -c -tags integration -o "$ARTIFACTS/outcomes.test" ./tests/integration
WARMOR_OUTCOME_PREPARE=1 "$ARTIFACTS/outcomes.test" \
  -test.v -test.run '^TestPrepareOutcomeArtifacts$' | tee "$ARTIFACTS/build.log"
{
  git rev-parse HEAD
  git status --short
  go version
  rustc --version
  echo "kernel=$KERNEL"
} > "$ARTIFACTS/build-info.txt"
sha256sum "$ARTIFACTS/warmor-daemon" "$ARTIFACTS/outcomes.test" \
  "$ARTIFACTS/"*.wasm > "$ARTIFACTS/SHA256SUMS"
if "$BUILD_ONLY"; then
  echo 'BUILD ONLY: artifacts validated; no kernel prevention or termination claim.'
  exit 0
fi

# No sudo, host daemon, Docker, kind, kubectl, or host enforcement fallback.
WARMOR_OUTCOME_VM=1 "$VIMTO" -kernel "$KERNEL" -- \
  go test -v -count=1 -tags integration -timeout 180s \
  -run '^TestDaemonOutcomes$' ./tests/integration | tee "$ARTIFACTS/outcomes.log"
# A skipped/mis-selected suite must not turn a successful go-test exit into
# enforcement proof. The guest writes this only after every outcome/cleanup.
grep -qx 'whole-daemon outcomes passed in vimto' "$ARTIFACTS/outcome-success.txt"
