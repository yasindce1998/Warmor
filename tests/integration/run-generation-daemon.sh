#!/usr/bin/env bash
# Whole daemon, explicit generation flag, exact prepared binaries; VM ONLY.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
required_tests() {
  cat <<'TESTS'
TestDaemonGenerationOutcomes
TESTS
}
check_log() {
  local log="$1" test
  [ -s "$log" ] || return 1
  if grep -Eq -- '(^|[[:space:]])--- (SKIP|FAIL):|^FAIL([[:space:]]|$)|panic:|\[no tests to run\]' "$log"; then return 1; fi
  while IFS= read -r test; do
    [ "$(grep -Ec -- "^--- PASS: ${test} \([0-9.]+s\)$" "$log" || true)" = 1 ] || return 1
  done < <(required_tests)
  for test in opposing-captured-reload-LKG-and-idle-shutdown fleet-live-durable-and-drain-pending-no-false-ack SIGTERM-cancels-held-generation-worker; do
    [ "$(grep -Ec -- "^    --- PASS: TestDaemonGenerationOutcomes/${test} \([0-9.]+s\)$" "$log" || true)" = 1 ] || return 1
  done
  grep -qx PASS "$log"
}
BUILD_ONLY=false
case "${1:-}" in
  --list-tests) [ "$#" -eq 1 ] || exit 2; required_tests; exit 0 ;;
  --check-log) [ "$#" -eq 2 ] || exit 2; check_log "$2"; exit ;;
  --build-only) [ "$#" -eq 1 ] || exit 2; BUILD_ONLY=true ;;
  '') [ "$#" -eq 0 ] || exit 2 ;;
  *) echo 'Usage: run-generation-daemon.sh [--build-only | --list-tests | --check-log FILE]' >&2; exit 2 ;;
esac
for tool in go cargo rustup sha256sum; do command -v "$tool" >/dev/null; done
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"
if ! "$BUILD_ONLY"; then
  case "${EXPECT_KERNEL_MINOR:-}" in 6.1|6.18) ;; *) echo 'require EXPECT_KERNEL_MINOR=6.1 or 6.18' >&2; exit 2 ;; esac
  case "${KERNEL:-}" in /*) [ -f "$KERNEL" ] || exit 2 ;; *) echo 'require absolute built KERNEL' >&2; exit 2 ;; esac
  [ -x "$VIMTO" ] || exit 1
  command -v qemu-system-x86_64 >/dev/null
  command -v timeout >/dev/null
fi
mkdir -p tests/integration/artifacts
ARTIFACTS="$(mktemp -d "$ROOT/tests/integration/artifacts/generation-daemon.XXXXXX")"
chmod 0755 "$ARTIFACTS"
echo "Generation daemon artifacts: $ARTIFACTS"
export CGO_ENABLED=0 WARMOR_OUTCOME_ARTIFACTS="$ARTIFACTS"
# Fault flags and controls are absent from the normal daemon. Both tags AND
# actual private vimto identity are required to arm the instrumented profile.
go build -tags 'integration generation_daemon_vm' -o "$ARTIFACTS/warmor-daemon" ./cmd/warmor-daemon
go build -o "$ARTIFACTS/warmor-daemon-release" ./cmd/warmor-daemon
go test -c -tags integration -o "$ARTIFACTS/outcomes.test" ./tests/integration
WARMOR_OUTCOME_PREPARE=1 "$ARTIFACTS/outcomes.test" -test.v -test.run '^TestPrepareGenerationDaemonArtifacts$' | tee "$ARTIFACTS/build.log"
required_tests > "$ARTIFACTS/required-tests.txt"
{
  git rev-parse HEAD
  git status --short
  go version
  rustc --version
  echo 'profile=integration,generation_daemon_vm (not release)'
  echo 'flags=--experimental-atomic-generations --require-lsm --lsm-enforce --default-deny'
  echo "kernel=${KERNEL:-not-run} minor=${EXPECT_KERNEL_MINOR:-not-run}"
} > "$ARTIFACTS/build-info.txt"
sha256sum "$ARTIFACTS/warmor-daemon" "$ARTIFACTS/warmor-daemon-release" "$ARTIFACTS/outcomes.test" \
  "$ARTIFACTS/required-tests.txt" "$ARTIFACTS/"*.wasm "$ARTIFACTS/allowed" "$ARTIFACTS/first-denied" \
  "$ARTIFACTS/reload-denied" "$ARTIFACTS/rule-audit" "$ARTIFACTS/global-audit" "$ARTIFACTS/file-victim" \
  "$ROOT"/internal/ebpf/*_bpf*.o "$ROOT"/internal/ebpf/*_bpf*.go "$ROOT"/bpf/*.bpf.c "$ROOT"/bpf/*.h > "$ARTIFACTS/SHA256SUMS"
if [ -n "${KERNEL:-}" ] && [ -f "$KERNEL" ]; then sha256sum "$KERNEL" >> "$ARTIFACTS/SHA256SUMS"; fi
if "$BUILD_ONLY"; then echo 'BUILD ONLY: no VM or whole-daemon enforcement outcome proof.'; exit 0; fi
WARMOR_OUTCOME_VM=1 WARMOR_GENERATION_DAEMON_VM=1 WARMOR_EXPECT_KERNEL_MINOR="$EXPECT_KERNEL_MINOR" \
  bash tests/integration/run-vm.sh generation-daemon "$ARTIFACTS" \
  "$VIMTO" -kernel "$KERNEL" exec -- "$ARTIFACTS/outcomes.test" \
  -test.v -test.count=1 -test.timeout=240s -test.run '^TestDaemonGenerationOutcomes$'
check_log "$ARTIFACTS/generation-daemon.log"
grep -qx 'whole-daemon generation outcomes passed in vimto' "$ARTIFACTS/generation-daemon-success.txt"
echo 'Strict whole-daemon generation outcomes passed (not signed/Host combination proof).'
