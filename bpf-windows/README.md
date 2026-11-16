# eBPF-for-Windows programs

Kernel programs for [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows).
The daemon loads them through `internal/platform/efw` (cilium/ebpf). If
eBPF-for-Windows isn't installed or a program fails to load, that event type
falls back to ETW.

| File | Hook | Needs | Effect |
|---|---|---|---|
| `warmor_net.c` | `cgroup/connect4`, `connect6`, `recv_accept4`, `recv_accept6`, `bind4`, `bind6`, `listen4`, `listen6` | eBPF-for-Windows >= 1.4 (netebpfext) | Blocks connects/accepts/binds/listens in the kernel (`BPF_SOCK_ADDR_VERDICT_REJECT`). Captures requesting-user identity via `bpf_is_current_admin`, `bpf_get_current_logon_id` and `bpf_get_socket_cookie`. |
| `warmor_proc.c` | `process` | eBPF-for-Windows + [ntosebpfext](https://github.com/microsoft/ntosebpfext) | Denies process creation (`STATUS_ACCESS_DENIED`); captures account name/domain from the token. |
| `warmor_efw.h` | | | Record, key and value layouts shared with `internal/platform/efw/records.go` |

How the daemon selects between these programs and ETW, how decisions reach
the kernel maps, and the build/signing steps (`build.ps1` →
`Convert-BpfToNative.ps1`, test signing vs attestation signing) are
documented in the
[Windows platform guide](../docs/PLATFORM_WINDOWS.md#building).

> These programs have not yet been built or run on Windows in this
> repository's CI. Hosted runners can't load kernel drivers, so verifying
> them needs a self-hosted Windows 11 / Server 2022 VM with test signing on.
