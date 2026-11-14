#!/usr/bin/env bash
# Bound the host-side cache/boot/transport wait as well as the guest test timer.
# The caller supplies vimto, never the daemon/test executable as a host command.
set -euo pipefail
# A diagnostic QUIT must not leave QEMU core dumps in the checkout.
ulimit -c 0
PHASE="${1:?VM phase required}"
ARTIFACTS="${2:?artifact directory required}"
shift 2
case "$PHASE" in
  verifier) LIMIT=300s ;;
  outcomes) LIMIT=360s ;;
  generations) LIMIT=420s ;;
  generation-daemon) LIMIT=480s ;;
  *) echo "error: unknown VM phase $PHASE" >&2; exit 2 ;;
esac
LOG="$ARTIFACTS/$PHASE.log"
STATUS="$ARTIFACTS/$PHASE-status.txt"
{
  echo "phase=$PHASE"
  echo "host_deadline=$LIMIT guest_timeout_is_separate=true"
  date -u '+started=%Y-%m-%dT%H:%M:%SZ'
  echo "cache=${XDG_CACHE_HOME:-default}"
} | tee "$STATUS"
# QUIT obtains Go stacks if vimto is stuck before guest tests start. The whole
# command process group (including QEMU) is bounded; no --foreground or retry.
# Capture stderr too: boot/transport failures must reach the retained artifact.
# Actions supplies a pipe already at EOF as stdin. Passing that directly to
# QEMU disconnects the virtio stdio port before guest output can be written.
# vimto v0.4.0 recognizes /dev/null and substitutes its own held-open pipe;
# use that path explicitly, as go test -exec does in the lower-level LSM gate.
if LC_ALL=C GOTRACEBACK=all timeout --verbose --signal=QUIT --kill-after=15s "$LIMIT" "$@" </dev/null 2>&1 | tee "$LOG"; then
  echo 'exit=0' >> "$STATUS"
else
  code=$?
  deadline=false
  # GNU timeout can return 137 when its hard-kill grace expires. Neither 137
  # nor 124 alone proves a deadline: the launcher may return either itself.
  if { [ "$code" -eq 124 ] || [ "$code" -eq 137 ]; } &&
      grep -Fq 'timeout: sending signal QUIT to command ' "$LOG"; then
    deadline=true
  fi
  {
    echo "exit=$code"
    echo "deadline_expired=$deadline"
    date -u '+failed=%Y-%m-%dT%H:%M:%SZ'
    echo 'No prevention or termination proof: VM phase did not complete.'
    ps -eo pid,ppid,stat,etime,args
    df -h "$ARTIFACTS" "${XDG_CACHE_HOME:-$HOME/.cache}"
    free -m
  } >> "$STATUS" 2>&1 || true
  echo "error: $PHASE VM phase failed (status $code); see $LOG and $STATUS" >&2
  exit "$code"
fi
