# eBPF-for-Windows programs

Kernel programs for [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows).
The daemon loads them through `internal/platform/efw` (cilium/ebpf). If
eBPF-for-Windows isn't installed or a program fails to load, that event type
falls back to ETW.

| File | Hook | Needs | Effect |
|---|---|---|---|
| `warmor_net.c` | `cgroup/connect4`, `cgroup/connect6`, `cgroup/recv_accept4`, `cgroup/recv_accept6` | eBPF-for-Windows (netebpfext) | Blocks connects/accepts in the kernel (`BPF_SOCK_ADDR_VERDICT_REJECT`) |
| `warmor_proc.c` | `process` | eBPF-for-Windows + [ntosebpfext](https://github.com/microsoft/ntosebpfext) | Denies process creation (`STATUS_ACCESS_DENIED`) |
| `warmor_efw.h` | | | Record, key and value layouts shared with `internal/platform/efw/records.go` |

## How decisions reach the kernel

1. Each hook reports every operation to userspace over a ring buffer.
2. The daemon evaluates the event with the WASM policy, as on Linux.
3. The decision is written into `net_policy` or `proc_deny`, keyed on the
   **image** (FNV-1a 64 of the lowercased NT path) and, for network rules,
   the remote endpoint. The next identical attempt is decided in the kernel.

Userspace keeps `proc_info` (PID → image hash) up to date from process
events, so the network hooks know which executable is connecting. A process
that connects before userspace has seen it is decided in userspace (detect,
then terminate).

## Building

`build.ps1` compiles with clang, then runs eBPF-for-Windows'
`Convert-BpfToNative.ps1` (PREVAIL verification + bpf2c) to produce
`warmor_net.sys` and `warmor_proc.sys`. See the header of `build.ps1` for
the parameters. Copy the images into a `bpf\` directory next to
`warmor-daemon.exe`.

Native images are kernel drivers:

- **Test machines:** test-sign them and enable test signing
  (`bcdedit /set testsigning on`).
- **Production (memory integrity / HVCI on):** they must be signed through
  Microsoft's attestation signing. JIT mode doesn't work under HVCI.

> These programs have not yet been built or run on Windows in this
> repository's CI. Hosted runners can't load kernel drivers, so verifying
> them needs a self-hosted Windows 11 / Server 2022 VM with test signing on.
