#!/usr/bin/env bash
# Strict, non-skippable broad LSM hook + WASM-feedback evidence. The enforcing
# tests execute ONLY as a prepared binary in a private vimto VM; never a host
# fallback. Bind/listen/ptrace/mount blocking and the WASM decision feedback
# loop previously ran without an oracle, so a silent skip left CI green.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

required_tests() {
  cat <<'TESTS'
TestLSM_WASMFeedbackLoop
TestLSM_ExecBlocked
TestLSM_ConnectBlocked
TestLSM_BindBlocked
TestLSM_ListenBlocked
TestLSM_PtraceBlocked
TestLSM_MountBlocked
TESTS
}

check_log() {
  local log="$1" test
  [ -s "$log" ] || { echo 'error: missing/empty LSM hook VM log' >&2; return 1; }
  # A skip of ANY selected fixture/subtest invalidates this evidence, even if
  # another run printed a PASS line for the parent. Never trust go-test exit 0
  # alone: a typo in selection or incompatible BTF can otherwise go green.
  if grep -Eq -- '(^|[[:space:]])--- (SKIP|FAIL):|^FAIL([[:space:]]|$)|panic:|\[no tests to run\]' "$log"; then
    echo 'error: skipped/failed/mis-selected LSM hook fixture' >&2
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
  echo 'Usage: tests/integration/run-lsm-hooks.sh [--build-only | --list-tests | --check-log FILE]'
  echo 'Full run requires KERNEL=/absolute/vmlinuz EXPECT_KERNEL_MINOR=6.1 (or 6.18) and vimto/QEMU.'
  echo 'Full run always requires BPF LSM and a PASS for every manifest fixture.'
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
  case "${EXPECT_KERNEL_MINOR}" in 6.1|6.18) ;; *) echo 'error: expect kernel minor 6.1 or 6.18' >&2; exit 2 ;; esac
  case "$KERNEL" in /*) [ -f "$KERNEL" ] || exit 2 ;; *) echo 'error: use the built IMA kernel absolute path' >&2; exit 2 ;; esac
  [ -x "$VIMTO" ] || { echo 'error: install lmb.io/vimto@v0.4.0' >&2; exit 1; }
  command -v qemu-system-x86_64 >/dev/null
fi

mkdir -p tests/integration/artifacts
ARTIFACTS="$(mktemp -d "$ROOT/tests/integration/artifacts/lsm-hooks.XXXXXX")"
chmod 0755 "$ARTIFACTS"
echo "LSM hook artifacts: $ARTIFACTS"
CGO_ENABLED=0 go test -c -tags integration -o "$ARTIFACTS/kernel.test" ./internal/ebpf
required_tests > "$ARTIFACTS/required-tests.txt"
{
  git rev-parse HEAD
  git status --short
  go version
  echo "kernel=${KERNEL:-not-run}"
  echo "expect_kernel_minor=${EXPECT_KERNEL_MINOR:-not-run}"
  echo 'WARMOR_REQUIRE_BPF_LSM=1'
  echo 'Binary and embedded BPF inputs below are exactly those supplied to vimto.'
} > "$ARTIFACTS/build-info.txt"
sha256sum "$ARTIFACTS/kernel.test" "$ARTIFACTS/required-tests.txt" \
  "$ROOT"/internal/ebpf/*_bpf*.o "$ROOT"/internal/ebpf/*_bpf*.go \
  "$ROOT"/bpf/*.bpf.c "$ROOT"/bpf/*.h > "$ARTIFACTS/SHA256SUMS"
if [ -n "${KERNEL:-}" ] && [ -f "$KERNEL" ]; then
  sha256sum "$KERNEL" >> "$ARTIFACTS/SHA256SUMS"
fi
if "$BUILD_ONLY"; then
  echo 'BUILD ONLY: no VM, verifier, or runtime hook enforcement evidence.'
  exit 0
fi

selection="^($(required_tests | paste -sd '|' -))$"
# WARMOR_REQUIRE_BPF_LSM makes an unavailable hook/BTF fail closed instead of
# skipping. env is propagated by vimto into the VM; the shared wrapper bounds
# pre-guest startup too and replaces Actions' closed stdin with /dev/null.
WARMOR_REQUIRE_BPF_LSM=1 \
  bash tests/integration/run-vm.sh lsm-hooks "$ARTIFACTS" \
  "$VIMTO" -kernel "$KERNEL" exec -- "$ARTIFACTS/kernel.test" \
  -test.v -test.count=1 -test.timeout=120s -test.run "$selection"
check_log "$ARTIFACTS/lsm-hooks.log"
echo 'Strict non-skipped LSM hook/WASM-feedback VM gate passed.'
