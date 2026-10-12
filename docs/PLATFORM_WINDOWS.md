# Windows Platform Guide

Warmor on Windows uses **[eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows)**
wherever a kernel hook exists, and **ETW** for everything else.

> **Status: beta.** The ETW path is exercised by CI on a real Windows runner.
> The eBPF-for-Windows programs are written against the official SDK headers
> but have **not yet been built or run in CI**: hosted runners can't load
> kernel drivers. Verify them on a test-signed Windows 11 / Server 2022 VM
> before relying on kernel blocking.

## How it works

Each event type is served by **one** backend, chosen at startup:

| Event | Primary: eBPF-for-Windows | Fallback | Enforcement with eBPF | Enforcement on fallback |
|---|---|---|---|---|
| Process start | `process` hook (needs [ntosebpfext](https://github.com/microsoft/ntosebpfext)) | ETW Microsoft-Windows-Kernel-Process | **Creation denied in the kernel** for cached image decisions | Detect, then `TerminateProcess` |
| Process exit | same hook | ETW Kernel-Process | not forwarded; updates the process table | same |
| Outbound connect (TCP, first UDP send to a peer) | `cgroup/connect4`, `connect6` | ETW Microsoft-Windows-Kernel-Network | **Rejected in the kernel** (`BPF_SOCK_ADDR_VERDICT_REJECT`) | Detect, then terminate |
| Inbound accept | `cgroup/recv_accept4`, `recv_accept6` | ETW Kernel-Network | **Rejected in the kernel** | Detect, then terminate |
| File open/create/write/delete/rename | *no eBPF hook exists* | ETW Microsoft-Windows-Kernel-File (always) | — | Detect, then terminate |

An ETW provider is only enabled for event types eBPF doesn't own, so no event
is reported twice.

### Backend selection

| Condition at startup | Result |
|---|---|
| `--no-lsm` | ETW for everything |
| eBPF-for-Windows not installed (`ebpfapi.dll` or `\\.\ebpfctl` missing) | ETW for everything |
| `warmor_net.sys` loads and both connect hooks attach | Network on eBPF (accept hooks are best effort) |
| `warmor_proc.sys` loads and the process hook attaches (ntosebpfext installed) | Process on eBPF |
| `--require-lsm` and no eBPF hook attached | Startup fails |
| An ETW provider can't be enabled | That event type is reported as not monitored |

The daemon logs the outcome, for example:

```
Windows: PROCESS → eBPF-for-Windows (kernel blocking)
Windows: NETWORK → eBPF-for-Windows (kernel blocking)
Windows: FILE    → ETW (detect, then terminate)
```

### Decision flow

eBPF-for-Windows programs can't wait for userspace, so the WASM evaluator is
never in the blocking path. Instead, decisions are cached in the kernel:

1. A hook sees an operation, looks it up in its policy map, and reports it
   over a ring buffer. With no rule, the operation is allowed.
2. The daemon evaluates the event with the WASM policy, exactly as on Linux,
   and enforces it (terminating the process for a deny).
3. The decision is written to the kernel map (`proc_deny` or `net_policy`).
   From then on the same operation is decided **synchronously in the kernel**.

Kernel keys always include the **image** (FNV-1a 64 of the lowercased NT path),
so a decision only applies to the executable it was made for. Network keys
also include family, direction, protocol and the remote address and port.
Userspace keeps a PID → image map (`proc_info`) for the network hooks, fed
from process events and a startup snapshot.

Allow decisions remove the key. Audit mode writes rules that only report
(`verdict = audit`) and never block.

### Identity and PID reuse

Windows recycles PIDs quickly, and ETW delivers events late. Before
terminating, the daemon opens the process and compares its creation time
with the event's. If the PID now belongs to a newer process, it is left
alone. The check and `TerminateProcess` use the same handle.

## Event fields on Windows

| Field | Value |
|---|---|
| `comm` | Lowercased image file name, e.g. `powershell.exe` (Windows names are case-insensitive) |
| `path` (process) | Drive-letter image path, e.g. `C:\Windows\System32\cmd.exe` (translated from the NT device path) |
| `args` (process) | Command line split with `CommandLineToArgvW` rules. The eBPF hook copies it in the kernel. ETW has no command line, so the consumer reads it from the live process; processes that exit within ETW's ~1 s delivery delay have no `args` in ETW mode. **Note:** the WASM policy ABI does not pass `args` yet on any platform, so `args` conditions in YAML currently compile to a path check. |
| file `operation` | `open`, `create`, `write` (first write per handle only), `delete`, `rename`. There is no `read`: ETW has no read-intent event, and read I/O events are too noisy to subscribe to. |
| network `operation` | `connect`, `accept`, `sendto` (UDP, deduplicated per peer for 10 s) |
| network `protocol` | `tcp`, `udp`, `tcp6`, `udp6` (IPv4-mapped addresses are unmapped) |

The daemon ignores its own file and network I/O.

## Requirements

- **Windows:** any supported x64 version for ETW. eBPF-for-Windows needs
  **Windows 11 or Server 2022** or later.
- **Administrator.** The service runs as LocalSystem.
- **Optional:** eBPF-for-Windows, plus ntosebpfext for process enforcement.

## Building

### Daemon

```powershell
go build -o warmor-daemon.exe .\cmd\warmor-daemon
```

### eBPF programs (optional)

The programs live in [`bpf-windows/`](../bpf-windows/README.md) and are
built as **native images** (`.sys` drivers) with
`bpf-windows/build.ps1`. That script runs clang, then eBPF-for-Windows'
`Convert-BpfToNative.ps1` (PREVAIL verification + bpf2c).

Install the images into a `bpf\` directory next to `warmor-daemon.exe`.

Signing:

- **Test machines:** test-sign the `.sys` files and run
  `bcdedit /set testsigning on`.
- **Production (memory integrity / HVCI on):** only native images signed
  through Microsoft's attestation signing load. JIT mode does not work
  under HVCI, and the interpreter only exists in debug builds of
  eBPF-for-Windows.

## Running

```powershell
# Console, as Administrator
.\warmor-daemon.exe --policy C:\Warmor\policy.wasm

# ETW only, even if eBPF-for-Windows is installed
.\warmor-daemon.exe --policy C:\Warmor\policy.wasm --no-lsm

# Refuse to start without kernel enforcement
.\warmor-daemon.exe --policy C:\Warmor\policy.wasm --require-lsm
```

`--lsm-enforce` and `--cgroup-filter` have no effect on Windows. The policy
file is watched and reloaded on change, since Windows has no `SIGHUP`.

### Windows service

```powershell
# Flags after "install" are stored with the service; relative paths are
# made absolute (services start in System32).
.\warmor-daemon.exe service install --policy .\policy.wasm --audit
.\warmor-daemon.exe service start
.\warmor-daemon.exe service stop
.\warmor-daemon.exe service uninstall   # stops it first
```

The service:

- starts automatically and is restarted by the SCM if it exits (after 5 s,
  30 s, then 60 s);
- logs to `%ProgramData%\Warmor\warmor-daemon.log`;
- writes start, stop and failure messages to the Application event log
  (source `warmor`).

Event-log lines are written at the zerolog severity (error, warning or info).

## Limitations

- **Files are detect-then-terminate only.** eBPF-for-Windows has no file
  hook; blocking would need a minifilter driver.
- **No registry or LSASS-handle monitoring.** The ETW Threat-Intelligence
  provider requires a protected (PPL) process.
- **Race at process start.** A process that connects before its creation
  event reaches userspace isn't in `proc_info` yet, so that first connect is
  decided in userspace.
- **Dual-stack sockets.** An IPv4 peer reached through an IPv6 socket (IPv4-mapped)
  misses the kernel fast path; userspace still enforces it.
- **Enforcement stops with the daemon.** Programs and maps are not pinned:
  if the daemon exits, the hooks detach and everything is allowed until it
  restarts (the SCM restarts the service).
- **No runtime health check.** If eBPF-for-Windows fails while the daemon is
  running, the daemon does not switch that event type to ETW.
- **Command-line rules can't block in the kernel.** Kernel process
  decisions depend only on the image path.
- **Bind/listen are not hooked.** eBPF-for-Windows has `cgroup/bind*` and
  `cgroup/listen*` attach types, but Warmor doesn't use them yet.
- `JobObjectSandbox` and `SetProcessIntegrityLevel`
  (`internal/enforcer/sandbox_windows.go`) exist but are not wired into the
  enforcer yet.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `eBPF-for-Windows unavailable, using ETW` | Runtime not installed, or the driver isn't running (`sc query ebpfcore`, `sc query netebpfext`). |
| `no native images (warmor_net.sys, warmor_proc.sys)` | Build them with `bpf-windows/build.ps1` and copy them to `<install dir>\bpf\`. |
| `process enforcement unavailable (is ntosebpfext installed?)` | Install ntosebpfext, or accept ETW for processes. |
| `attach warmor_connect4: ...` | Image not signed, or signed for test mode while test signing is off. |
| `ETW: ... provider unavailable` | Not elevated, or the 64-session system limit was reached (`logman query -ets`). |
| ETW session left over after a crash | Handled automatically on the next start. To remove it by hand: `logman stop WarmorETW -ets`. |

Inspect the session:

```powershell
logman query WarmorETW -ets
```

## Continuous integration

`.github/workflows/windows-ci.yml`, on `windows-latest`:

- builds and runs the unit tests (the decoding and translation logic is
  portable and also tested on Linux);
- runs `TestConsumerSmoke` as Administrator, a real ETW session against the
  kernel providers that checks process, file and network events end to end;
- runs `TestStructLayout`, which pins the ETW struct sizes to the 64-bit
  Windows SDK.

The eBPF programs need a self-hosted, test-signed VM; that job doesn't exist
yet.

## References

- [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows): hooks in `include/ebpf_nethooks.h`, `include/ebpf_structs.h`
- [ntosebpfext](https://github.com/microsoft/ntosebpfext): process hook, `include/ebpf_ntos_hooks.h`
- [cilium/ebpf Windows support](https://ebpf-go.dev/guides/windows-support/)
- [Native code generation](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/NativeCodeGeneration.md)
