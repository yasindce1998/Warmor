# Production-readiness checklist

Tracks the work in [PRODUCTION_READINESS_PLAN.md](PRODUCTION_READINESS_PLAN.md)
against the source at `2e9b43b` (2026-11-19). **Warmor is not production-ready.**
The plan stays the historical assessment; [STATUS.md](STATUS.md) is the feature
inventory; this page is the open/closed ledger.

Evidence key: **[code]** read in source at `2e9b43b`; **[gh]** read from the
GitHub API on 2026-11-24; **[docs]** taken from STATUS.md or a design doc and not
re-verified here. Local `go build`, `go vet` and `go test ./...` passed on this
commit (69 packages ok, 0 failed). That run was unprivileged: no `-race`, no
kernel/VM tests, no cluster, and CI results on GitHub were not checked.

## Done

- [x] Strict YAML: unknown fields rejected (`KnownFields(true)`). [code]
- [x] argv and network-operation rules evaluated for real (ABI 5). [docs]
- [x] Invalid WASM verdicts fail closed and are never cached or synced. [docs]
- [x] Exact structured kernel keys replace the 32-bit hash match. [docs]
- [x] Global `--audit` overrides kernel, userspace and integrity enforcement. [docs]
- [x] pidfd-verified termination with separate attempted/failed/refused/succeeded outcomes. [docs]
- [x] Fleet principal binding: a non-admin JWT subject or cert CommonName must equal the agent ID, else 403 (`authorizeAgent`, used by register, heartbeat and policy query). Admins bypass it by design. [code]
- [x] Durable fleet state, TLS required unless `--insecure`. [docs]
- [x] Full (policy ID, version, digest) comparison; failed activation retried; last-known-good kept. [docs]
- [x] Controller keeps the last accepted policy on an invalid CR edit. [docs]
- [x] Helm: `auditMode: true` and `cgroupFilter: auto` by default, `CAP_KILL` added, `values.schema.json`, linux/amd64 scheduling, digest overrides. [code]
- [x] Fail-closed on ring loss, tracepoint drop counters, truncation flags, tracepoint/LSM dedup. [code]
- [x] Capture-quality gate `--on-incomplete-input` (ABI 6). Default is `log`. [code]
- [x] Dynamic kernel feedback for bind, listen, mount and ptrace. [code]
- [x] Kernel-sync telemetry and `--require-enforce-posture`. [code]
- [x] Rust toolchain pinned (1.100.0) and hermetic compiler build. [code]
- [x] Release workflow: govulncheck, Trivy, SBOMs, attestations, checksum verification, weekly scheduled scan. [code]
- [x] Windows ETW and Linux LSM/IMA VM workflows exist. [code]

## Open: blockers before recommending enforcement

- [ ] **Branch protection.** `main` returns `protected: false` and there are 0 rulesets. [gh]
- [ ] **Release gated on CI.** `release.yml` runs its own `tests` job on tag, PR and a weekly schedule. Nothing makes a release wait on `ci.yml` or the kernel VM workflows. [code]
- [ ] **Generation-atomic reload by default.** The default rebuild has an allow-on-miss window. The atomic path is opt-in, incompatible with signed assignments and telemetry, and lacks full whole-daemon VM evidence. [docs]
- [ ] **Per-workload routing.** Nothing in `cmd/`, `internal/enforcer` or `internal/controller` imports `internal/workload`. Every non-nil pod selector stays Pending. [code]
- [ ] **Automatic rollback.** `CanaryAnalyzer` has no non-test caller. [code]

## Open: Kubernetes beta (plan Gate 2)

- [ ] Multi-node real-cluster tests. `scripts/kind-e2e.sh` has no multi-node or CNI setup. [code]
- [ ] Enforcement outcome proof in pods: the kind test cannot show a process was killed. Non-root pod termination is not tested on a real node. [docs]
- [ ] ARM64 execution. No arm64 runner or qemu-arm path in any workflow. [code]
- [ ] CRI-O and containerd, cgroup v2 systemd/cgroupfs, CNI, node-restart and chart/CRD-upgrade tests. [docs]
- [ ] Controller leader election (none found). [code]
- [ ] Signed and immutable controller artifact. The ConfigMap is unsigned and mutable. [docs]
- [ ] Hard compilation isolation (CPU/RSS/deadline). See [wasm-compilation-isolation.md](design/wasm-compilation-isolation.md). [docs]
- [ ] Applied status from every node. Node receipts are opt-in and are self-reports, not attestation. [docs]

## Open: fleet candidate (plan Gate 3)

- [ ] HA or replicated server state. Today it is a single-writer snapshot rewritten on every heartbeat. [docs]
- [ ] Durable drift and canary state. [docs]
- [ ] Load and soak budgets measured under pod limits. `PERFORMANCE.md` is from October and missed the memory target (60–128 MB vs <50 MB). [docs]
- [ ] Documented, noninteractive last-known-good recovery runbook. [docs]
- [ ] Signed attribution for telemetry. It is sealed pending a contract. [docs]

## Open: coverage, platforms and hygiene

- [ ] Inode, content and mount-namespace file identity. Matching is by literal path. [docs]
- [ ] `sendto` and `recvfrom` hooks. [docs]
- [ ] macOS ESF: releases are tools-only, every AUTH event is answered ALLOW, cgo path unvalidated. [code]
- [ ] Windows eBPF programs built and run in CI. The Windows workflow does not build them. [code]
- [ ] Vulnerability scanning on every CI run. `ci.yml` has none; scans run only in `release.yml`. [code]
- [ ] `dependabot.yml` or `renovate.json`. Neither exists. [code]
- [ ] SECURITY.md response-time commitment. It states none. [code]
- [ ] Remove the committed `tests/release/__pycache__/test_release.cpython-314.pyc` and ignore `__pycache__`. [code]

## Suggested order

1. Enable branch protection and make releases depend on CI.
2. Whole-daemon VM evidence for the generation path; decide on making it default.
3. Wire workload identity into routing, with a multi-node real-cluster test.
4. Rollout actuator and rollback using acknowledged telemetry.
5. Load and soak tests under pod limits; HA or backup-restore for fleet state.
6. Cross-platform items only after the Linux and Kubernetes gates pass.
