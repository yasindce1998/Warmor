#!/usr/bin/env bash
# Offline usable oracle: exit zero / a parent PASS alone cannot bless a skip.
set -euo pipefail
log="${1:?outcomes log required}"
[ "$#" -eq 1 ] && [ -s "$log" ] || exit 2
if grep -Eq -- '(^|[[:space:]])--- (SKIP|FAIL):|^FAIL([[:space:]]|$)|panic:|\[no tests to run\]' "$log"; then
  echo 'error: skipped/failed/mis-selected supervised host fixture' >&2
  exit 1
fi
for test in baseline-without-daemon allow-first-deny-and-rejected-reload-LKG global-audit-never-blocks-or-kills nonroot-process-actually-terminated signed-host-load-failures-keep-LKG dead-host-never-serves-cached-allow SIGTERM-cancels-candidate-and-reaps-hosts; do
  [ "$(grep -Ec -- "^[[:space:]]+--- PASS: TestDaemonOutcomes/${test} \([0-9.]+s\)$" "$log" || true)" = 1 ] || {
    echo "error: expected exactly one supervised outcome PASS: $test" >&2; exit 1;
  }
done
for test in compile-heavy init-loop signed-malformed; do
  [ "$(grep -Ec -- "^[[:space:]]+--- PASS: TestDaemonOutcomes/signed-host-load-failures-keep-LKG/${test} \([0-9.]+s\)$" "$log" || true)" = 1 ] || exit 1
done
[ "$(grep -Ec -- '^--- PASS: TestDaemonOutcomes \([0-9.]+s\)$' "$log" || true)" = 1 ]
grep -qx 'PASS' "$log"
