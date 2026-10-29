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

How the daemon selects between these programs and ETW, how decisions reach
the kernel maps, and the build/signing steps (`build.ps1` →
`Convert-BpfToNative.ps1`, test signing vs attestation signing) are
documented in the
[Windows platform guide](../docs/PLATFORM_WINDOWS.md#building).

> These programs have not yet been built or run on Windows in this
> repository's CI. Hosted runners can't load kernel drivers, so verifying
> them needs a self-hosted Windows 11 / Server 2022 VM with test signing on.
