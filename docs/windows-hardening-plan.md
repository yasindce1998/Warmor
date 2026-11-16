# Windows hardening plan (2026)

This document is the actionable plan for taking Windows from experimental beta
to a platform we can honestly call production-good. It consolidates the 2026
code audits and the upstream eBPF-for-Windows research. See
[PLATFORM_WINDOWS.md](PLATFORM_WINDOWS.md) for current behaviour.

## Where things stand

See [PLATFORM_WINDOWS.md](PLATFORM_WINDOWS.md) for the platform's current
behaviour and [Feature Status](STATUS.md) for the current status matrix.

## Upstream eBPF-for-Windows: what changed by 2026

- **Not GA.** All releases through v1.7.0 (16 Oct 2026) are still labelled
  *Pre-release*. Supported OS: Windows 11 / Server 2022+. PREVAIL is a distinct
  verifier; programs that pass on Linux can fail here, and v1.7 changed
  verification contracts. Pin a version and re-verify on upgrade.
- **Proof-of-Verification (PoV) signing is the hard production gate.** Since
  v1.0-rc2 native modules must carry an eBPF-verification-EKU signature from
  Microsoft's signing pipeline. Self-signing, attestation signing and WHQL
  alone will not make `warmor_net.sys`/`warmor_proc.sys` load under ebpfcore.
  The runtime binaries themselves are still documented as not Microsoft
  production-signed. **Resolve both questions before planning production.**
- **HVCI:** JIT is impossible and the interpreter is debug-only; native `.sys`
  is the only production path. PoV hashes program-type descriptors and helper
  prototypes, so every SDK/extension upgrade means rebuild and re-sign.
- **ntosebpfext** is maintained and can deny process creation by returning
  `STATUS_ACCESS_DENIED`. It is a separate signed driver and its program type
  must be registered in the eBPF Store. Its account helpers are now used for
  process identity.
- **Attach types:** `cgroup/connect4/6`, `recv_accept4/6`,
  `connect_authorization4/6` (v1.3), `bind4/6` and `listen4/6` (v1.4) are
  available. `BPF_PROG_TYPE_BIND` is deprecated (v1.6). There is **no
  filesystem hook** — only a design proposal.
- **Reliability:** ring-buffer async callbacks were deprecated (v1.5). Upstream
  issue #5624 (Oct 2026) reports an unbounded NonPaged-pool leak per native
  module load. Add Driver Verifier + pool tracking and avoid load/unload churn.
- **CI setup is documented upstream:** `SelfHostedRunnerSetup.md`,
  `1es/Setup.ps1`, `vm-setup.md` — nested virtualization, Secure Boot off,
  TESTSIGNING on, an admin service account.

## Phase 0 — cheap, hosted runners

1. Promote the ETW smoke test from "events observed" to detect-then-terminate
   outcome assertions; run the cross-compiled-only rejection/DACL tests on a
   hosted Windows runner.
2. Wire alerts on backend transitions to `none`. Keep `--require-lsm`
   semantics explicit: it means "an eBPF hook attached", not "all event types
   kernel-blocked".
3. Deny-only Event Viewer logging behind an opt-in flag; never one event per
   evaluation.
4. DACL setup helper for the policy-server snapshot parent directory.
5. Identity exposure — done. Network records carry `is_admin`, `logon_id` and
   `socket_cookie`; process records carry account name/domain. Exported on
   events and in the WASM JSON ABI. A future ABI-6 contract can add YAML
   condition fields and fields-read bits for cache-key soundness.

## Phase 1 — driver-capable self-hosted CI (the real blocker)

6. Stand up a self-hosted Win11 / Server 2022 test-signed VM runner using the
   upstream scripts.
7. Build `warmor_net.sys` / `warmor_proc.sys` in CI against a **pinned**
   eBPF-for-Windows + ntosebpfext SDK (`build.ps1` → `Convert-BpfToNative.ps1`
   → PREVAIL). No native images ship in releases today.
8. Prove **outcomes** on the VM: cached connect/accept/bind/listen REJECT,
   process creation denied with `STATUS_ACCESS_DENIED`, and the decision flow.
   Add Driver Verifier + pool tracking.
9. VM-validate the endpoint mapping: with distinct local and peer addresses,
   confirm the RECV_ACCEPT field mapping, then simplify `warmor_sock_addr()`.
10. Attempt **map pinning** so enforcement does not vanish when the daemon
    exits; add an eBPF audit-mode behaviour test.

## Phase 2 — functional parity (new components)

11. **File blocking via a minifilter driver** (no eBPF file hook exists).
12. **Registry + LSASS-handle monitoring** via ETW Threat-Intelligence in a
    PPL-protected process.
13. **Native Windows atomic revision backend** for `--server` fleet
    publication.
14. Close the dual-stack (IPv4-mapped) kernel-key gap and the process-start
    race by populating `proc_info` earlier.
15. **Wire the sandbox code** — `JobObjectSandbox` and
    `SetProcessIntegrityLevel` exist but are not called; needs a trigger and
    job-handle lifecycle design.

## Phase 3 — release gate

16. Integrate native driver/outcome jobs into `release.yml`; today Windows
    archives contain only the ETW daemon, no `.sys`.
17. Re-evaluate the beta label only after end-to-end outcome tests pass on a
    driver-capable VM and the signing question is resolved.

## Decisions needed before Phase 1

- Access to Microsoft's eBPF-verification-EKU signing pipeline for our native
  modules.
- Timing for production signing of the eBPF-for-Windows runtime binaries.
- Ownership/cost of a persistent self-hosted, test-signed Windows VM.
