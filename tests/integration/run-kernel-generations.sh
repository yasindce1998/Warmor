#!/usr/bin/env bash
# Strict, non-skippable kernel-generation evidence. Enforcing tests execute ONLY
# as a prepared binary in a private vimto VM; never a host fallback.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

required_tests() {
  cat <<'TESTS'
TestLSM_GenerationVMRequirements
TestLSM_GenerationPrepareSwitchRetireExec
TestLSM_GenerationEndpointCollisionAndDynamicScope
TestLSM_GenerationConcurrentVerdictsFlushAndRetire
TestLSM_GenerationFlushQueuedOldNoWakeup
TestLSM_GenerationIntegrityCoexistence
TestLSM_LoadAndAttach
TestLSM_ExactExecCollisionFirstMatchDefaultDenyAndScope
TestLSM_ExactAuditDeniesAreNotKernelRefusals
TestLSM_ExactEndpointCollisionDefaultDeny
TestIntegrity_EnforceAllowsListedBlocksUnlisted
TESTS
}

check_log() {
  local log="$1" test
  [ -s "$log" ] || { echo 'error: missing/empty generation VM log' >&2; return 1; }
  # A skip of ANY selected fixture/subtest invalidates this evidence, even if
  # another run printed a PASS line for the parent. Never trust go-test exit 0
  # alone: a typo in selection or incompatible BTF can otherwise go green.
  if grep -Eq -- '(^|[[:space:]])--- (SKIP|FAIL):|^FAIL([[:space:]]|$)|panic:|\[no tests to run\]' "$log"; then
    echo 'error: skipped/failed/mis-selected generation VM fixture' >&2
    return 1
  fi
  while IFS= read -r test; do
    if [ "$(grep -Ec -- "^--- PASS: ${test} \([0-9.]+s\)$" "$log" || true)" != 1 ]; then
      echo "error: expected exactly one non-skipped PASS: $test" >&2
      return 1
    fi
  done < <(required_tests)
  grep -qx 'PASS' "$log" || { echo 'error: missing final VM test PASS' >&2; return 1; }
}

usage() {
  echo 'Usage: tests/integration/run-kernel-generations.sh [--build-only | --list-tests | --check-log FILE]'
  echo 'Full run requires KERNEL=/absolute/vmlinuz EXPECT_KERNEL_MINOR=6.1 (or 6.18) and vimto/QEMU.'
  echo 'Full run always requires BPF LSM + IMA and a PASS for every manifest fixture.'
}
BUILD_ONLY=false
case "${1:-}" in
  --help|-h) [ "$#" -eq 1 ] || exit 2; usage; exit 0 ;;
  --list-tests) [ "$#" -eq 1 ] || exit 2; required_tests; exit 0 ;;
  --check-log) [ "$#" -eq 2 ] || exit 2; check_log "$2"; exit ;;
  --build-only) [ "$#" -eq 1 ] || exit 2; BUILD_ONLY=true ;;
  '') [ "$#" -eq 0 ] || exit 2 ;;
  *) usage >&2; exit 2 ;;
esac
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"
if ! "$BUILD_ONLY"; then
  [ -n "${KERNEL:-}" ] && [ -n "${EXPECT_KERNEL_MINOR:-}" ] || { usage >&2; exit 2; }
  case "$KERNEL" in /*) [ -f "$KERNEL" ] || exit 2 ;; *) echo 'error: use the built IMA kernel absolute path' >&2; exit 2 ;; esac
  [ -x "$VIMTO" ] || { echo 'error: install lmb.io/vimto@v0.4.0' >&2; exit 1; }
  command -v qemu-system-x86_64 >/dev/null
fi

mkdir -p tests/integration/artifacts
ARTIFACTS="$(mktemp -d "$ROOT/tests/integration/artifacts/generations.XXXXXX")"
chmod 0755 "$ARTIFACTS"
echo "Generation artifacts: $ARTIFACTS"
CGO_ENABLED=0 go test -c -tags integration -o "$ARTIFACTS/kernel.test" ./internal/ebpf
required_tests > "$ARTIFACTS/required-tests.txt"
{
  git rev-parse HEAD
  git status --short
  go version
  echo "kernel=${KERNEL:-not-run}"
  echo "expect_kernel_minor=${EXPECT_KERNEL_MINOR:-not-run}"
  echo 'WARMOR_REQUIRE_BPF_LSM=1 WARMOR_REQUIRE_IMA=1'
  echo 'Binary and embedded BPF inputs below are exactly those supplied to vimto.'
} > "$ARTIFACTS/build-info.txt"
sha256sum "$ARTIFACTS/kernel.test" "$ARTIFACTS/required-tests.txt" \
  "$ROOT"/internal/ebpf/*_bpf*.o "$ROOT"/internal/ebpf/*_bpf*.go \
  "$ROOT"/bpf/*.bpf.c "$ROOT"/bpf/*.h > "$ARTIFACTS/SHA256SUMS"
if [ -n "${KERNEL:-}" ] && [ -f "$KERNEL" ]; then
  sha256sum "$KERNEL" >> "$ARTIFACTS/SHA256SUMS"
fi
if "$BUILD_ONLY"; then
  echo 'BUILD ONLY: no VM, verifier, or runtime enforcement evidence.'
  exit 0
fi

selection="^($(required_tests | paste -sd '|' -))$"
# No sudo, host test execution, daemon, Docker, cluster or fallback. env is
# propagated by vimto into the VM; the requirements fixture proves it arrived.
# The shared wrapper bounds pre-guest startup too and replaces Actions' closed
# stdin with /dev/null, retaining generations.log and generations-status.txt.
WARMOR_REQUIRE_BPF_LSM=1 WARMOR_REQUIRE_IMA=1 WARMOR_GENERATION_VM_GATE=1 \
WARMOR_EXPECT_KERNEL_MINOR="$EXPECT_KERNEL_MINOR" \
  bash tests/integration/run-vm.sh generations "$ARTIFACTS" \
  "$VIMTO" -kernel "$KERNEL" exec -- "$ARTIFACTS/kernel.test" \
  -test.v -test.count=1 -test.timeout=180s -test.run "$selection"
check_log "$ARTIFACTS/generations.log"
echo 'Strict non-skipped kernel-generation VM gate passed.'
