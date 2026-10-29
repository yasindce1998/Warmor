# macOS Platform Guide

> **Status on `main`: Experimental, detection only.** The ESF client answers
> **every AUTH event with ALLOW**, so nothing is blocked on macOS today. The
> cgo ESF code is never compiled in CI (`CGO_ENABLED=0`). Release binaries are
> also built with `CGO_ENABLED=0`, so the released macOS `warmor-daemon`
> cannot start the ESF platform; build from source with cgo and the macOS SDK.
> See [Feature Status](STATUS.md).

## Architecture

```
Application → Syscall → ESF Hook → ESF Client (cgo) → warmor Daemon → WASM → Decision
```

**Implementation files:**
- `internal/platform/darwin.go` — platform implementation
- `internal/platform/esf/client.go` — ESF client
- `internal/platform/esf/bridge.c` — C bridge
- `macos/SystemExtension/` — System Extension config

The daemon requires cgo (`CGO_ENABLED=1`) and the macOS SDK to build the ESF
path; without cgo the daemon runs but cannot start a platform.

## Requirements

- macOS 10.15+ (Catalina), x86_64 or ARM64
- Root (required to create the ESF client)
- System Extension approval (System Settings → Privacy & Security)
- Full Disk Access for the daemon (file path resolution)
- Xcode Command Line Tools, Go 1.26+, Rust 1.70+ with
  `wasm32-unknown-unknown` for building policies

## Building

```bash
# 1. Build a WASM policy (any platform's policy works — see policies/cross-platform)
cd policies/cross-platform
cargo build --release --target wasm32-unknown-unknown
cd ../..

# 2. Build the daemon with cgo
export CGO_ENABLED=1
go build -o warmor-daemon ./cmd/warmor-daemon
```

For distribution, the binary must be code-signed (Developer ID) with the
entitlements in `macos/SystemExtension/warmor.entitlements` and packaged as a
System Extension bundle; see Apple's
[Code Signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
and [Notarization](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
guides.

## Running

```bash
sudo ./warmor-daemon --policy policies/cross-platform/target/wasm32-unknown-unknown/release/cross_platform_policy.wasm
```

On first run, grant Full Disk Access and approve the System Extension in
System Settings; the daemon logs warnings if either is missing. Events are
evaluated by the same WASM policies as on Linux, but every decision is
effectively ALLOW (see the status note above).

## ESF Event Types

**AUTH (could block; always answered ALLOW on `main`):**
- `ES_EVENT_TYPE_AUTH_EXEC` — process execution
- `ES_EVENT_TYPE_AUTH_OPEN` — file open
- `ES_EVENT_TYPE_AUTH_CREATE` — file creation

**NOTIFY (monitoring only):**
- `ES_EVENT_TYPE_NOTIFY_EXIT` — process termination
- `ES_EVENT_TYPE_NOTIFY_WRITE` — file write
- `ES_EVENT_TYPE_NOTIFY_CONNECT` — network connection

## Capabilities

```go
Capabilities{
    ProcessMonitoring: true,
    FileMonitoring:    true,
    NetworkMonitoring: true,
    Enforcement:       false, // AUTH events are answered ALLOW on main
}
```

## Debugging

```bash
# ESF / System Extension status
systemextensionsctl list
sudo lsof -c warmor-daemon | grep EndpointSecurity

# Stream the daemon's logs
log stream --predicate 'process == "warmor-daemon"' --level debug
```

## Continuous Integration

macOS builds are validated on every push and PR via
`.github/workflows/macos-ci.yml`:

- **Runner:** `macos-latest`
- **Build:** `CGO_ENABLED=0 go build ./...` (CGO disabled — ESF SDK headers
  unavailable on the runner, so the ESF path itself is not compiled in CI)
- **Tests:** `CGO_ENABLED=0 go test -race -short -coverprofile=coverage.out ./...`
- **Coverage gate:** fails the build below 40%
- Tests requiring Endpoint Security entitlements are skipped via `-short`

## Limitations

1. **No enforcement** — every AUTH event is answered ALLOW
2. **Not exercised end to end** — the cgo ESF code is never compiled in CI
3. **Network events are NOTIFY only** — cannot block by design
4. **System Extension required** — manual approval, code signing for distribution
5. **Release binaries cannot start the platform** — built with `CGO_ENABLED=0`

## What is needed to reach enforcement

- Answer AUTH events with the WASM decision (currently hardcoded ALLOW)
- Build and test the cgo ESF path in CI (self-hosted runner with entitlements)
- Package and sign the System Extension

## References

- [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
- [System Extensions](https://developer.apple.com/documentation/systemextensions)
- [TCC (Transparency, Consent, and Control)](https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources)
