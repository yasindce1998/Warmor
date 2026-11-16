#!/usr/bin/env bash
# Build on the host; execute the daemon ONLY inside a disposable vimto VM.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# Go 1.26's VCS discovery recognizes .git directories but not worktree .git
# files and otherwise stamps the enclosing checkout's HEAD. Bind Git queries
# to this exact worktree; never bless mismatched embedded revision metadata.
WORKTREE_GIT_DIR="$(git rev-parse --absolute-git-dir)"
go_with_worktree_vcs() {
  # Scope provenance overrides to Go itself. Exporting them for the complete
  # runner can redirect unrelated fixture Git commands despite their own cwd.
  GIT_DIR="$WORKTREE_GIT_DIR" GIT_WORK_TREE="$ROOT" go "$@"
}

usage() {
  echo 'Usage: tests/integration/run-outcomes.sh [--build-only] [--policy-host [--atomic-generations]]'
  echo 'Requires Go, Rust wasm32-unknown-unknown; full run also needs vimto and QEMU.'
  echo 'Optional: VIMTO=/path/to/vimto KERNEL=/absolute/vmlinuz-or-OCI-reference'
}
BUILD_ONLY=false
POLICY_HOST=false
ATOMIC=false
# vimto executes the exact prepared, hashed test binaries, not a second build.
for arg in "$@"; do
  case "$arg" in
    --build-only) ! "$BUILD_ONLY" || exit 2; BUILD_ONLY=true ;;
    --policy-host) ! "$POLICY_HOST" || exit 2; POLICY_HOST=true ;;
    --atomic-generations) ! "$ATOMIC" || exit 2; ATOMIC=true ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if "$ATOMIC" && ! "$POLICY_HOST"; then usage >&2; exit 2; fi
# Inherited controls must never silently alter the legacy gate.
unset WARMOR_OUTCOME_POLICY_HOST WARMOR_OUTCOME_ATOMIC_GENERATIONS
unset WARMOR_TEST_HOST_PHASE_SOCKET WARMOR_TEST_HOST_PHASE_DIGESTS
if "$POLICY_HOST"; then export WARMOR_OUTCOME_POLICY_HOST=1; fi
if "$ATOMIC"; then export WARMOR_OUTCOME_ATOMIC_GENERATIONS=1; fi

for tool in go cargo rustup sha256sum; do
  command -v "$tool" >/dev/null || { echo "error: $tool is required" >&2; exit 1; }
done
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"
KERNEL="${KERNEL:-ghcr.io/cilium/ci-kernels:stable-selftests}"
if ! "$BUILD_ONLY"; then
  command -v timeout >/dev/null || { echo 'error: GNU timeout is required to bound VM startup' >&2; exit 1; }
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
git rev-parse HEAD > "$ARTIFACTS/source-sha.txt"
if "$POLICY_HOST"; then
  # Explicit test-only paired protocol: production/release builds omit it.
  go_with_worktree_vcs build -tags policyhost_phaseproof -o "$ARTIFACTS/warmor-daemon" ./cmd/warmor-daemon
  go_with_worktree_vcs build -tags policyhost_phaseproof -o "$ARTIFACTS/warmor-policy-host" ./cmd/warmor-policy-host
  sha256sum "$ARTIFACTS/warmor-policy-host" | cut -d ' ' -f1 > "$ARTIFACTS/POLICY_HOST_SHA256"
else
  go_with_worktree_vcs build -o "$ARTIFACTS/warmor-daemon" ./cmd/warmor-daemon
fi
go_with_worktree_vcs test -c -tags integration -o "$ARTIFACTS/outcomes.test" ./tests/integration
go_with_worktree_vcs test -c -tags integration -o "$ARTIFACTS/kernel.test" ./internal/ebpf
test "$(git rev-parse HEAD)" = "$(cat "$ARTIFACTS/source-sha.txt")"
WARMOR_OUTCOME_PREPARE=1 "$ARTIFACTS/outcomes.test" \
  -test.v -test.run '^TestPrepareOutcomeArtifacts$' | tee "$ARTIFACTS/build.log"
{
  git rev-parse HEAD
  git status --short
  go version
  rustc --version
  echo "kernel=$KERNEL"
  echo "policy_host=$POLICY_HOST atomic_generations=$ATOMIC"
  echo "test_only_phase_profile=$POLICY_HOST (no deadline changes; paired load barrier before real compilation)"
  echo 'BPF objects below are the exact go:embed inputs used by both binaries.'
} > "$ARTIFACTS/build-info.txt"
sha256sum "$ARTIFACTS/source-sha.txt" "$ARTIFACTS/warmor-daemon" "$ARTIFACTS/outcomes.test" "$ARTIFACTS/kernel.test" \
  "$ARTIFACTS/"*.wasm "$ROOT"/internal/ebpf/*_bpf*.o \
  "$ROOT"/internal/ebpf/*_bpf*.go "$ROOT"/bpf/*.bpf.c "$ROOT"/bpf/*.h > "$ARTIFACTS/SHA256SUMS"
if "$POLICY_HOST"; then
  sha256sum "$ARTIFACTS/warmor-policy-host" "$ARTIFACTS/POLICY_HOST_SHA256" \
    "$ARTIFACTS/fixture-public.pem" "$ARTIFACTS/"*.sig \
    "$ARTIFACTS/reviewed-declaration-digests.txt" >> "$ARTIFACTS/SHA256SUMS"
fi
if "$BUILD_ONLY"; then
  echo 'BUILD ONLY: artifacts validated; no kernel prevention or termination claim.'
  exit 0
fi

# No sudo, host daemon, Docker, kind, kubectl, or host enforcement fallback.
WARMOR_OUTCOME_VM=1 WARMOR_REQUIRE_BPF_LSM=1 bash tests/integration/run-vm.sh verifier "$ARTIFACTS" \
  "$VIMTO" -kernel "$KERNEL" exec -- \
  "$ARTIFACTS/kernel.test" -test.v -test.count=1 -test.timeout=120s \
  -test.run '^TestLSM_(LoadAndAttach|StopReadersInterruptsIdleMonitors|ExactExecCollisionFirstMatchDefaultDenyAndScope|ExactAuditDeniesAreNotKernelRefusals|ExactEndpointCollisionDefaultDeny|TruncatedExecCannotHitExactAllow|ExactIPv6AndMappedEndpointIdentities)$'
for test in LoadAndAttach StopReadersInterruptsIdleMonitors ExactExecCollisionFirstMatchDefaultDenyAndScope ExactAuditDeniesAreNotKernelRefusals ExactEndpointCollisionDefaultDeny TruncatedExecCannotHitExactAllow ExactIPv6AndMappedEndpointIdentities; do
  grep -q -- "^--- PASS: TestLSM_${test} " "$ARTIFACTS/verifier.log"
done
if "$POLICY_HOST"; then
  bash tests/integration/check-host-outcomes.sh --verifier "$ARTIFACTS/verifier.log"
fi
WARMOR_OUTCOME_VM=1 bash tests/integration/run-vm.sh outcomes "$ARTIFACTS" \
  "$VIMTO" -kernel "$KERNEL" exec -- \
  "$ARTIFACTS/outcomes.test" -test.v -test.count=1 -test.timeout=180s \
  -test.run '^TestDaemonOutcomes$'
# A skipped/mis-selected suite must not turn a successful go-test exit into
# enforcement proof. The guest writes this only after every outcome/cleanup.
grep -qx 'whole-daemon outcomes passed in vimto' "$ARTIFACTS/outcome-success.txt"
if "$POLICY_HOST"; then
  bash tests/integration/check-host-outcomes.sh "$ARTIFACTS/outcomes.log"
fi
