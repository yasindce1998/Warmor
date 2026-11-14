# Release platform support

| Download | Included daemon | Verification / limitations |
| --- | --- | --- |
| Linux AMD64 / ARM64 | Yes | Native build, Go tests, version and policy-validation smoke tests. Container tests validate the baked WASM policy. Kernel enforcement is **not** established by these unprivileged smoke tests. |
| Windows AMD64 | Experimental ETW daemon | Native build, Go tests and CLI smoke tests. No native eBPF `.sys` drivers are included; no kernel-blocking claim. |
| macOS AMD64 / ARM64 | **No — tools only** | Native tools-only tests with cgo disabled. No ESF backend, daemon, signed System Extension or notarization is shipped. |

macOS ESF requires a working cgo/SDK implementation and Apple entitlements,
code signing and notarization. The existing cgo backend is not validated by the
tools-only build. Build-from-source instructions are experimental, not a promise
that the native backend compiles or runs on the current SDK.

Windows native eBPF programs still require a pinned eBPF-for-Windows/ntosebpfext
SDK, WDK/native compiler, signing infrastructure and isolated driver-capable
runners. Hosted Go tests do not verify these programs. See the platform guides
and `bpf-windows/README.md`; these remain release-support blockers, not optional
tests silently marked successful.

`warmor-compile` needs a Rust toolchain and the `wasm32-unknown-unknown` target
to compile policies on the user's machine. The daemon container includes a
precompiled default policy; the controller image includes its Rust toolchain.
