# macOS Platform Guide

> **Status on `main`: Experimental, detection only.** The ESF client answers
> **every AUTH event with ALLOW**, so nothing is blocked on macOS today. The
> cgo ESF code is not compiled in CI (`CGO_ENABLED=0`). New release archives
> contain **tools only; no macOS daemon**. Older cgo-disabled daemon downloads
> cannot start ESF. Building from source with cgo is experimental and remains
> unverified against the native SDK; it is not a supported runnable artifact.
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

### Private recording paths and migration

Recording intentionally rejects **all symlink parent components**, including
macOS's standard `/var` → `/private/var` and `/tmp` → `/private/tmp` aliases.
Use an explicit physical path such as `/private/var/log/warmor/events.ndjson`,
not `/var/log/warmor/events.ndjson`. File recordings require an existing trusted
parent; do not write directly into the shared `/private/tmp` directory.

For a root-owned recording (after building/configuring the daemon as above):

```bash
sudo install -d -o root -g wheel -m 0700 /private/var/log/warmor
sudo ./warmor-daemon --policy policy.wasm \
  --event-sink file:/private/var/log/warmor/events.ndjson
# Read the same private log with an appropriately authorized account:
sudo ./warmor-learn --events /private/var/log/warmor/events.ndjson -o learned.yaml
```

**Upgrade existing configuration:** replace the known system-alias prefix in
`--event-sink file:<path>` or an embedded `simulator.NewEventStore` directory with
its physical spelling. `/var/...` and `/private/var/...` normally refer to the
same existing files, so this prefix change alone does not require moving logs.
Inspect ownership, permissions and remaining components first; do not blindly
resolve arbitrary symlinks or relax directory permissions to bypass a refusal.
A missing directory or unsafe owner/mode still needs correction separately.

The daemon reports the rejected component and an actionable hint, for example:

```text
open event log: open recording parent "/var": configure a physical directory path without symlink components; recording does not follow symlink parents (macOS: use /private/var instead of /var, or /private/tmp instead of /tmp): not a directory
```

The recorder does not automatically canonicalize CLI paths or `$TMPDIR`.
Only test-owned temporary fixture roots are resolved for native tests. The
descriptor-relative no-follow checks, 0600 files, private store directories,
rotation protections and default export redaction remain unchanged. See
[policy tooling and recording contracts](POLICY_TOOL_CONTRACTS.md).

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

- **Runner:** `macos-15`
- **Build:** `CGO_ENABLED=0 go build ./...` (CGO disabled — ESF SDK headers
  the ESF path itself is not compiled or validated in CI)
- **Tests:** `CGO_ENABLED=0 go test -short -coverprofile=coverage.out ./...`
- No race-detector claim: Go's race detector requires cgo
- **Coverage gate:** fails the build below 40%
- Tests requiring Endpoint Security entitlements are skipped via `-short`

## Limitations

1. **No enforcement** — every AUTH event is answered ALLOW
2. **Not exercised end to end** — the cgo ESF code is never compiled in CI
3. **Network events are NOTIFY only** — cannot block by design
4. **System Extension required** — manual approval, code signing for distribution
5. **No macOS daemon in new releases** — tools-only archives deliberately omit
   the nonfunctional cgo-disabled daemon; see [release support](RELEASE_SUPPORT.md)

## What is needed to reach enforcement

- Answer AUTH events with the WASM decision (currently hardcoded ALLOW)
- Build and test the cgo ESF path in CI (self-hosted runner with entitlements)
- Package and sign the System Extension

## References

- [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
- [System Extensions](https://developer.apple.com/documentation/systemextensions)
- [TCC (Transparency, Consent, and Control)](https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources)
