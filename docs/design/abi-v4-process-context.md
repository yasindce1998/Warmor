# ABI version 4: process context fields

Status: implemented on `feat/abi-v4-process-context` (see STATUS.md).
Owner: enforcer + policy host.

## The gap

The Rust policy crates under `policies/` read `args`, `parent_comm`,
`cgroup_id` and `direction` from the JSON event document — several of
their rules are keyed on exactly those fields (mining-pool arguments,
remote-service parents, ingress ports). The host never sent any of them,
and the Linux exec sensor did not capture argv or the parent at all, so
those rules could never fire. Windows/ETW was the odd one out: it
already filled `Process.Args`, but the JSON ABI dropped them on the
floor.

Two things were missing, and this change does both:

1. **Capture**: the exec tracepoint now reads argv, the parent's comm
   and the parent's PID (PPID).
2. **Transport**: JSON ABI version 4 carries the captured fields to
   modules that declare it.

## Capture (bpf/execve_monitor.bpf.c, tracepoint path only)

`struct execve_event` grows at the end (no layout change to existing
fields):

| field              | size        | source |
|--------------------|-------------|--------|
| `ppid`             | `__u32`     | `task->real_parent->tgid` |
| `parent_comm[16]`  | 16 bytes    | `task->real_parent->comm` |
| `args[16][64]`     | 1024 bytes  | the syscall's `argv`, walked with `bpf_probe_read_user` |

Notes:

- The parent read uses the same minimal CO-RE view pattern as
  `lsm_ptrace.bpf.c` (`task_struct___warmor` with `real_parent`), so it
  relocates against kernel BTF and works back to 5.10.
- The argv walk is bounded (16 args, 64 bytes each). A longer argument
  is truncated; arguments after the 16th are not captured. A failed
  pointer read stops the walk. Missing args are all-zero — a ringbuf
  reservation is zeroed, so userspace can tell "no args captured" from
  "empty argv".
- The event grows from ~300 to ~1340 bytes. The 256 KiB ring still
  holds ~190 in-flight events, which is far above the reader's measured
  drain rate.
- The LSM exec hook does **not** grow: `bprm_check_security` has no
  argv, and LSM-origin events are recorded (not re-synced) today. An
  exec therefore carries argv only on its tracepoint event. Windows/ETW
  fills `Args` from the process command line, as it already did.

## Transport (JSON ABI version 4)

A module opts in by exporting `abi_version() -> 4` (host range becomes
1–4). Version 4 adds these keys, only for modules declaring it — the
same gating rule as the temporal keys in version 3:

| key            | types     | value |
|----------------|-----------|-------|
| `cgroup_id`    | all       | the event's cgroup (0 when unknown) |
| `parent_comm`  | PROCESS   | the parent's comm ("" when unknown) |
| `args`         | PROCESS   | argv as an array (≤16 entries, truncated to 64 bytes each; `[]` when none) |
| `direction`    | NETWORK   | `"egress"` for connect/sendto, `"ingress"` for recvfrom |

Modules that declare nothing, or 1–3, see exactly the document they see
today — a crate built against the old contract cannot start failing on
unknown keys.

`bytes_sent` / `bytes_recv` stay unset: no sensor produces them (the
sendto/recvfrom hooks do not exist yet). When they do, they slot into
version 4's contract without a new version, since no released module
can be relying on their absence in a way a new key would break — the
gating exists for strict parsers, and a module declaring 4 that reads
those fields would have to be written after they exist.

## Lineage (free rider)

`RecordExec` was fed a hard-coded `ppid = 0`, so the lineage tracker's
ancestry was always empty (see STATUS.md). The tracepoint now provides
a real PPID, and the enforcer passes it through. Ancestry on Linux
works from this change on; `parent_comm` in the ABI is filled from the
sensor, not the tracker, so it does not depend on tracker state.

## Crate updates

All 10 crates now export `abi_version() -> 4` (seven previously
declared 2 or 3; `advanced`, `example` and `multi` declared nothing).
Their rules on `args`, `parent_comm` and `direction` become live and
are covered by new cases in `TestPolicyCrates`.

## Out of scope

- `sendto`/`recvfrom` capture (separate roadmap item).
- `parent_comm` on LSM-origin exec events.
- The binary ABI (`evaluate_event`, used by YAML-compiled policies):
  its fixed layout has no room for a variable-length argv, and
  YAML-compiled policies express arg rules through the compiler, not
  the wire fields.
- Per-field cache keys for crate policies (`warmor_fields_read` is a
  YAML-compiler export; crates still PID-key the decision cache).
