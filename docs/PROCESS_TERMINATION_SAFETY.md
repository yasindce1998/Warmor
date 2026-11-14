# Linux asynchronous termination safety

A userspace DENY decision is not proof that the operation was blocked. Tracepoint
events and LSM misses can reach userspace after the observed operation completed.
Only a reported kernel denial establishes synchronous refusal. Termination is
best-effort containment of the process that produced a live event.

## Target verification

Linux termination uses `pidfd_open`, then `pidfd_send_signal` with SIGKILL.
**There is no numeric `kill` fallback.** Acquire the pidfd before reading process
start time: exit/reuse afterward cannot redirect the fd to a replacement.

Verification requires:

- Original nonzero `bpf_ktime_get_ns` from a trusted live kernel sensor in
  `Event.KernelTimestampNS`. Display wall time (`Timestamp`) is never identity.
  Replays, remote inputs, and synthetic events must not be promoted to trusted
  live sensor inputs. This change transports existing timestamps without changing
  BPF layouts or generated objects.
- The daemon in the **initial PID namespace**, with matching procfs visibility.
  The BPF helper emits initial-namespace TGIDs; interpreting them as local PIDs
  in a nested daemon namespace could kill unrelated processes. Detection uses
  Linux's reserved initial PID namespace inode, not `/proc/1` equality or an
  ambiguous `NS_GET_PARENT` permission error. Containers need `hostPID: true`.
  Descendant-namespace workloads are supported from a host-PID daemon; targets
  need not share the daemon's namespace.
- Real procfs at `/proc`, verifiable zero monotonic/boottime time-namespace
  offsets, a working monotonic clock, and `AT_CLKTCK` from the daemon aux vector.
- Valid `/proc/PID/stat` starttime whose **entire start tick strictly precedes**
  the event. Same-tick starts are ambiguous and refused. Future timestamps are
  refused too.

Proc starttime uses CLOCK_BOOTTIME, rounded down to USER_HZ ticks. The sensor
uses initial CLOCK_MONOTONIC. BOOTTIME includes suspend and is never less than
MONOTONIC. At startup the verifier samples a conservative lower bound on prior
suspend (BOOTTIME first, then MONOTONIC). It only adds this bound to events
generated after the sample. Older events use raw MONOTONIC as a safe lower
bound. The entire process start tick must precede the resulting lower bound on
event BOOTTIME. A process born after the event cannot pass.

**Never add a current suspend offset to an old queued event**: this could make
a stale event appear newer than a replacement process. There is no wall-time
conversion, clock-step tolerance, or guessed historical suspend correction.
Additional suspend after startup can conservatively refuse young processes
until their monotonic age exceeds that additional suspend time. A future sensor
ABI with exact kernel lifetime identity could remove this availability limit
and same-tick ambiguity; no BPF ABI change is needed for the present verifier.

PID 0, PID 1, out-of-range PIDs, missing/malformed evidence, unsupported pidfds,
clock uncertainty, invisible/exited processes, and namespace mismatches produce
explicit unsuccessful outcomes. No error enables an unsafe fallback. This can
reduce containment on restricted/old deployments; it does not change already
active synchronous LSM blocking.

## Races and limitations

- Exit/reuse before pidfd acquisition is rejected by start/event ordering.
  Exit/reuse afterward cannot redirect the fd. A `/proc` read could observe a
  replacement but cannot make the fd signal it.
- Identity is a process lifetime, not a particular executable image. A later
  exec in the same lifetime is not detected by this verifier.
- Accepted SIGKILL is asynchronous: it is not an observed exit, nor proof that
  the original operation or its side effects were prevented.
- UID/CAP_KILL permissions and seccomp still apply. Isolated real deployment
  tests must cover non-root workloads and actual container security contexts.
- Only Linux receives this verifier. Experimental macOS behavior is unchanged;
  Windows retains the existing process-handle/start-time check.

## Observable outcomes and required serialization

Every `ActionResult` carries per-event fields reset before each enforcement:

| Field | Meaning |
| --- | --- |
| `EnforcementAttempted` | A userspace termination syscall was issued. Merely opening a pidfd or rejecting identity is not an attempt. |
| `Enforced` | The OS accepted termination, or the kernel already refused the operation. Never inferred merely from DENY. |
| `EnforcementError` | Syscall failure or reason no termination syscall was safe/possible. Empty for audit-only decisions. |

`EnforcementStats` exposes `EnforcementAttempted`, `EnforcementSucceeded`,
`EnforcementFailed`, `EnforcementRefused` for userspace termination.
`warmor_process_terminations_total{outcome="attempted|succeeded|failed|refused"}`
exposes the same distinctions. Attempted = succeeded + failed once complete;
refused means no termination syscall. Kernel denials are not termination
attempts. `Denied` remains a decision count, not an enforcement-success count.
Audit decisions never terminate.

Event serialization must copy all three result fields. The compatibility
`SecurityEvent.Enforced` must use `result.Enforced`, not `Action == DENY &&
!Audit`. Kernel denial recording explicitly sets it. Preserve the separate
kernel-enforced marker to distinguish synchronous blocking from asynchronous
accepted termination. The streaming agent owns this serialization integration.

## Test boundary

Synthetic PIDs only use fully injected OS operations, covering stale/reused
PIDs, wrong namespaces, missing/future timestamps, clock ticks, suspend offset
safety, unavailable pidfds, and permission errors. Real SIGKILL tests target
only dedicated owned sleeper children in separate process groups. Tests skip
with a reason if their environment cannot establish required guarantees. No
host-wide enforcing daemon is needed or started.
