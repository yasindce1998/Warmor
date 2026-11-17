# Whole-daemon outcome gate

This is a **disposable-VM-only** test of the real `cmd/warmor-daemon`, compiler-generated WASM policies, and BPF-LSM hooks. It does not run an enforcing daemon on the host, in kind, or in the current Kubernetes cluster. `tests/e2e_enforcement_test.sh` is a compatibility wrapper for this runner; the old unsafe standalone shell test has been removed.

## What a passing VM run proves

| Gate | Required observable outcome |
| --- | --- |
| Baseline | Controlled ELF executables and file reads succeed as actual uid/euid 65534 without a daemon. Permissions, missing utilities and unavailable networks cannot masquerade as enforcement. |
| Allow | The allowed nonroot executable exits zero and writes the exact expected marker while enforcement is active. |
| First-event default deny | After the daemon reports the eligible exec domain active, the **first attempt** at an unlisted executable fails to start with `errors.Is(err, syscall.EPERM)` and creates no marker. There is no retry-until-denied or cache warm-up. |
| Per-rule audit | A `mode: audit` deny runs successfully with a marker and exits normally while global enforcement is active. An attributed deny/audit event confirms the rule was exercised. |
| Global audit | With `--audit --lsm-enforce --default-deny`, an otherwise-denied executable runs successfully, writes its marker, and survives to normal exit; an attributed event confirms would-deny evaluation. |
| Rejected reload / LKG | An invalid WASM candidate and SIGHUP cause an acknowledged reload failure. The old allow and first-attempt deny behavior remain. A previously unseen uid-dependent file event is still evaluated and terminates its process, exercising the LKG evaluator rather than just cached kernel entries. |
| Real nonroot termination | A live uid/euid 65534 child signals readiness, then is released to open a controlled readable file. Its actual wait status must be **SIGKILL**, with a matching file-policy deny event for its PID and UID. Exit code 137, EPERM at exec, an incremented deny counter, a timeout, and the harness's cleanup kill cannot pass this gate. |

The termination test is asynchronous containment: it deliberately **does not claim the file open or a subsequent side effect was prevented**. Synchronous prevention is asserted separately using exec's exact EPERM and absence of a side effect. All workloads are scoped to one private cgroup, created by the test; the daemon and harness stay outside it. Child placement uses `CLONE_INTO_CGROUP` before exec, not a shell that migrates itself after starting.

## Run

Host requirements: Linux amd64/arm64, Go from `go.mod`, Rust with `wasm32-unknown-unknown`, QEMU, GNU `timeout`, `ip` (iproute2), and statically built vimto:

```sh
CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0
rustup target add wasm32-unknown-unknown
# After changing BPF sources, regenerate embedded bindings with clang/libbpf:
BPF2GO_CFLAGS='-D__TARGET_ARCH_x86 -mcpu=v1' go generate ./internal/ebpf
bash tests/integration/run-outcomes.sh
```

The architecture define above is for amd64; use `__TARGET_ARCH_arm64` on arm64. The existing repository `.vimto.toml` selects root inside the guest and mounts cgroup v2. The test additionally requires vimto as guest PID 1, its private virtio control/stdio ports, and `bpf` in the active LSM list. Exporting a variable alone cannot authorize a host run. A VM missing root, BPF LSM, cgroup support, or the requested hooks **fails**, rather than quietly skipping or degrading to observe-only.

`KERNEL` accepts an absolute local kernel path or OCI reference (default `ghcr.io/cilium/ci-kernels:stable-selftests`). Set `VIMTO` to a custom binary path. KVM is optional (`VIMTO_DISABLE_KVM=1` uses emulation). No runner command installs host packages, invokes sudo, changes host LSM configuration, or starts the daemon outside the VM.

For systems with a small/memory-backed `/tmp`, put the OCI cache on persistent disk:

```sh
XDG_CACHE_HOME="$HOME/.cache/warmor-outcomes" bash tests/integration/run-outcomes.sh
```

The guest runs controlled executables in its private `/var/tmp` overlay, so a checkout under a mode-0700 host home directory does not require weakening host permissions. No host secret paths or service-account tokens are created or touched.

### Safe local validation without a VM

```sh
bash -n tests/e2e_enforcement_test.sh tests/integration/run-outcomes.sh tests/integration/run-vm.sh
go test -race -count=1 ./tests/integration
go test -tags integration -run 'Test(VMGuard|EPERMOracle|SIGKILLOracle|TimeoutCleanupIsNotTerminationProof)$' ./tests/integration
bash tests/integration/run-outcomes.sh --build-only
```

`--build-only` compiles the actual daemon, helper/outcome ELF, kernel-test ELF, and both WASM policies, and evaluates the policy cases in the production runtime (including the exported exec-domain eligibility). It never starts the daemon or loads BPF. Ordinary `go test ./...` includes only the nonprivileged oracle/workflow tests. A direct tagged outcome test without the explicit VM runner skips the privileged suite; **that skip is not a passing outcome gate**. Exact-identity kernel enforcement tests refuse execution outside vimto. The full runner additionally requires non-skipped kernel-test PASS records and a guest-generated success record written only after all daemon outcomes and cleanup pass. Shell pipelines use `pipefail`, test failures propagate, and there are no manual `((PASS++))` counters that terminate early under `set -e`.

## CI, evidence and limits

`.github/workflows/enforcement-outcomes.yml` is a dedicated gate, independent of the existing workflows. It regenerates BPF bindings from the tested revision with the v1 instruction baseline before building. The runner first loads/attaches the generated objects through the VM verifier and requires non-skipped exact-identity exec/connect `EPERM` tests, then executes the whole-daemon outcome suite in a fresh vimto VM. Both runs execute the exact prepared test binaries, not a later rebuild. Hashes identify the daemon, test binaries, validated WASM, all 22 embedded BPF objects, generated Go bindings, and C sources; the outcome guest verifies the manifest before enforcement. Logs, source policy YAML, build revision/toolchain information, guest kernel/LSM information, daemon process/capability status, markers, NDJSON events, metrics snapshots and hashes are retained in `tests/integration/artifacts/run.*`. Binaries and caches are not uploaded. A nonzero exit remains a failed job even when evidence is uploaded.

Host-side deadlines additionally bound vimto's kernel fetch, boot, transport and shutdown: 300 seconds for the verifier VM and 360 seconds for daemon outcomes, each with a 15-second hard-kill grace. Guest test timers remain 120/180 seconds. Both stdout and stderr and phase status are retained; a host deadline requests Go stacks and records process/disk/memory diagnostics. Deadline exits are failures, never retries, skips or outcome evidence. The CI kernel cache lives on runner disk outside the checkout shared with the VM, avoiding a checkout export containing the kernel root-overlay source. Run 43607514299 reached host preparation but was cancelled at the job limit with only kernel-cache progress and no guest test output; it supplied no whole-daemon prevention/termination evidence. Its full job cleanup log confirms QEMU had started, narrowing the stall to VM boot/transport before guest tests, not image download. The precise guest-side cause was not retained; moving the cache is isolation hardening, not a proven root-cause repair.

The cache is configured by a shell step using `$RUNNER_TEMP` and `$GITHUB_ENV`; the `runner` expression context is unavailable in job-level `env`. GNU timeout may return 124 or 137 after hard-kill escalation. The phase status labels a deadline only when that exit is accompanied by timeout's own signal diagnostic in the phase log (under the C locale). An arbitrary launcher exit 137 is still a failed phase, not deadline or termination proof. Run root `actionlint` when editing workflows, as YAML parsing alone does not validate Actions expression contexts.

Run 43611646970's bounded verifier phase retained vimto stacks waiting for QEMU exit and a control-RPC result, with no guest test output. Direct `vimto exec` inherited Actions' closed stdin pipe, unlike the green `vimto ... go test` LSM jobs whose test launcher supplies `/dev/null`. QEMU's stdio backend closes the virtio port on input EOF; vimto v0.4.0 substitutes a held-open pipe only for `/dev/null` (or nil stdin). Both VM phases now explicitly redirect launcher stdin from `/dev/null` to select that workaround. This does not affect the private pipes used to release the nonroot fixtures inside the guest. A regression passes an actual closed pipe to a fake launcher for both phases and requires `/dev/null` at its stdin; no enforcement or QEMU is run by this local test. Actual CI guest results are still required to confirm prevention and termination.

Run 43613283613 reached and passed all six verifier/errno tests and executed the daemon probes, but the suite remained **failed**: every daemon hung after SIGTERM at `Stopping enforcer...`. Tracepoint readers blocked indefinitely on idle rings, and the LSM reader's internal deadline loop kept retrying; platform Stop waited for those monitors before Close could interrupt them. Stop now closes only the readers before joining monitors, keeping hooks/maps until resource Close. A fake idle-monitor unit test covers ordering/idempotence, and the verifier phase additionally requires `TestLSM_StopReadersInterruptsIdleMonitors` against real VM rings. Clean daemon shutdown remains mandatory; the harness never treats its cleanup SIGKILL as successful shutdown or workload termination.

The nonroot termination gate assumes the daemon retains the ability to signal uid 65534 (normally `CAP_KILL`), alongside the capabilities needed to load/attach BPF. Root UID alone is insufficient evidence. PR #31's signaling/pidfd implementation is integrated from `origin/main`: trusted `KernelTimestampNS` must survive both sensor channels and the platform conversion, and the guest must have initial PID/time namespaces and usable procfs. The controlled file reader remains live for 100 ms after readiness before the trigger, clearing Linux's USER_HZ=100 process-start tick ambiguity without relaxing production identity checks. Its event must report an actual successful userspace enforcement attempt with no error, not kernel prevention. Capability absence, signal permission errors, identity refusals, pidfd failures, and cleanup kills remain failures, never skips or substitutes for actual SIGKILL and attributed enforcement.

This legacy `run-outcomes.sh` suite still does **not** itself prove atomic successful policy activation, map-write-failure rollback, no-gap switching, restart persistence, packet-level network prevention, or protection of operations outside the tested exec/file cases. Its reload test uses only today's supported SIGHUP/invalid-candidate APIs. Those generation-specific proofs are now carried by the separate whole-daemon generation gate below, which runs the real enforcer and kernel maps. Startup readiness here means the event loop/metrics are reachable and the exec default-deny domain has become active; it is not proof that startup had no enforcement gap.

`scripts/kind-e2e.sh` is a deployment/controller/**evaluation smoke test** on a shared host kernel. Ready pods, a loaded policy, Active CRs, events and deny counters demonstrate plumbing and policy evaluation, **not synchronous prevention or successful process termination**. Do not substitute its result for this VM outcome gate, or turn enforcement on in kind to obtain such proof. Lower-level `internal/ebpf` integration tests cover BPF loader/map behavior but likewise do not replace this whole-daemon test.

Local build/oracle success without a live VM run must be reported as **infrastructure-blocked for prevention/termination evidence**, not as an enforcement pass.

## Kernel-generation verifier and stress gate

`run-kernel-generations.sh` is the separate strict, non-skippable gate for the
opt-in kernel generation API. It requires real PASS results for every
`TestLSM_Generation*` fixture, the two event-loss regressions described below,
plus named legacy/integrity regressions. It runs a
prebuilt hashed binary only in a disposable vimto VM, requires BPF LSM and IMA,
and checks the requested actual kernel minor. Broad suite skips do not count.

Local compilation and oracle checks, **without host attachment or a VM**:

```sh
bash -n tests/integration/run-kernel-generations.sh tests/integration/run-vm.sh
go test -race -run '^(TestGenerationGate|TestVM)' ./tests/integration
bash tests/integration/run-kernel-generations.sh --build-only
```

The dedicated CI matrix runs on the built 6.1 and 6.18 IMA kernels and retains
logs, manifest and input hashes under `artifacts/generations.*`. Its shared
`run-vm.sh generations` phase replaces closed CI stdin with `/dev/null` and bounds
host cache/boot/transport/guest waits to 420 seconds, plus a 15-second hard-kill
grace for the whole launcher/QEMU process group. The guest's 180-second test
timeout is separate. `generations.log` captures both output streams and
`generations-status.txt` retains phase/deadline/exit and failure diagnostics,
including failures before guest startup; both are uploaded on failure too.
Offline fake-launcher tests cover closed stdin, failure propagation and stalled
startup with QUIT/KILL escalation. These do not execute a VM or enforcement.
The required-PASS/no-SKIP/duplicate-PASS oracle is unchanged. See
[`docs/design/kernel-generations.md`](../../docs/design/kernel-generations.md)
for concurrency and flush/retirement assertions. A build-only success is not
verifier/runtime evidence.

## Required event-loss and broad LSM hook gates

Two event-loss regressions are now named fixtures in the strict
`run-kernel-generations.sh` manifest, so a silent skip can no longer leave CI
green:

| Required test | What a non-skipped PASS proves |
| --- | --- |
| `TestLSM_EventLossIsCounted` | Under a 20k-open flood into a one-page ring, every probe open is either delivered to userspace or counted in `lsm_drops`. No operation is silently evaluated by nobody and accounted for by nobody. |
| `TestLSM_OnEventLossDeny` | With `--on-event-loss=deny` in enforce mode an exec whose event cannot be queued is refused with `EPERM`, while the default (`on-loss=log`) still allows it. Event loss therefore fails closed rather than allowing an unevaluated operation. |

`run-lsm-hooks.sh` adds a separate strict, non-skippable `lsm-hooks` VM phase
(reusing the `run-vm.sh` phase structure) for the broad hook tests that
previously ran with no oracle. These are now required gates:

| Required test | What a non-skipped PASS proves |
| --- | --- |
| `TestLSM_WASMFeedbackLoop` | A batch of WASM decisions is synced into the BPF policy map; kernel-matchable entries carry the correct action/audit bits and the file-only entry is correctly skipped. |
| `TestLSM_ExecBlocked` | A deny exec rule actually blocks execution of the configured binary. |
| `TestLSM_ConnectBlocked` | A deny endpoint rule actually blocks `connect(2)` to the configured address/port. |
| `TestLSM_BindBlocked` | A deny endpoint rule actually blocks `bind(2)` to the configured address/port. |
| `TestLSM_ListenBlocked` | A deny listen rule actually blocks `listen(2)` on the configured port after a successful bind. |
| `TestLSM_PtraceBlocked` | A deny ptrace rule actually blocks `PTRACE_ATTACH` to the named process. |
| `TestLSM_MountBlocked` | A deny mount rule actually blocks mounting the named filesystem type. |

Both gates use the **unchanged** strict oracle: exactly one non-skipped
`--- PASS:` per manifest fixture, rejection of any `--- SKIP`, `--- FAIL`,
`panic:` or no-tests line (including child/subtest skips), no duplicate PASS
lines, and a final `PASS`. They execute only a prepared, hashed `kernel.test`
binary in a disposable vimto VM with `WARMOR_REQUIRE_BPF_LSM=1`; an unavailable
LSM or incompatible BTF fails closed instead of skipping. The `lsm-hooks` phase
has a 300-second host deadline and a 120-second guest test timer, and its
`lsm-hooks.log`/status are retained on failure. AST-based gate tests scan the
integration sources so a renamed, removed or newly added hook fixture cannot
silently fall out of the manifest.

Safe local checks (no VM, no BPF attachment):

```sh
bash -n tests/integration/run-lsm-hooks.sh tests/integration/run-vm.sh
go test -race -count=1 -run '^TestLSMHooksGate' ./tests/integration
bash tests/integration/run-lsm-hooks.sh --build-only
```

A green CI run therefore proves, in addition to the existing gates, that event
loss is both counted and fail-closed and that the
exec/connect/bind/listen/ptrace/mount deny rules plus the WASM-to-BPF feedback
loop are exercised rather than skipped.

## Whole-daemon generation activation gate

`run-generation-daemon.sh` separately executes the actual daemon with
`--experimental-atomic-generations --require-lsm --lsm-enforce --default-deny`.
It is required after the kernel phase on both built 6.1.188 and 6.18.53 kernels.
Its compiled VM-only profile holds old work and injects named post-live durable/
pre-drain failures; normal builds have no fault-control flag. The guard checks
actual vimto PID 1/private ports before enabling the profile. The strict oracle
requires the parent and every child PASS, no skips, plus successful cleanup.

Safe local checks (no daemon or hooks):

```sh
bash -n tests/integration/run-generation-daemon.sh
go test -race -run '^TestGenerationDaemonGate' ./tests/integration
go test -race -tags 'integration generation_daemon_vm' -run '^TestProfile' ./internal/generationvm
bash tests/integration/run-generation-daemon.sh --build-only
```

Full VM invocation requires `KERNEL=/absolute/built/vmlinuz` and
`EXPECT_KERNEL_MINOR=6.1` (or `6.18`). It retains exact binaries/hashes, real Cargo
WASM, generation/scope/verdict evidence, markers, heartbeats/fault stages and
SIGTERM outcomes under `artifacts/generation-daemon.*`. It is not signed-mode or
supervised-Host combination proof. See
[`generation-daemon-vm.md`](../../docs/design/generation-daemon-vm.md) for exact
assertions, compile-profile boundaries and locally unexecuted VM evidence.

### New VM evidence: publication rollback, no gap, restart, second kernel

Four added child fixtures are required by the same strict non-skipped PASS
oracle (no SKIP, FAIL, panic, no-tests, duplicate PASS or missing child can
pass). The first three reuse the captured-verdict oracle and the real profile
seams; they are all compiled out of release binaries.

| Required fixture | What a non-skipped PASS proves | What it still does not prove |
| --- | --- | --- |
| `map-write-failure-keeps-old-generation-no-gap` | With generation 2 live and a real held captured exec, a named fault at the `activate` seam fails immediately before the kernel's single outer-map update. No `live-3.json` appears; a deny anchor whose verdict would change if the rejected generation went live returns EPERM on its **first** attempt throughout the fault window, and the captured verdict still belongs to generation 2 with matching kernel denial, scope and PID. | That a real BPF map write failed at the syscall boundary (the fault is injected at the seam immediately before it); that the kernel RCU grace period was itself interrupted; or any behavior after the fault is cleared and publication retried. |
| `clean-restart-first-denied-persists` | The normal (release) daemon is cleanly stopped with SIGTERM via `d.stop` (which waits with `awaitOutcomeDaemonExit` and refuses a harness kill), then relaunched with the **same immutable policy path**. The first eligible exec on **each** launch is EPERM with a fresh marker. | Crash, SIGKILL, power-loss or disk-corruption continuity. The on-disk boot revision is read on a graceful restart only. |
| Kernel matrix `6.1.188` (both `lsm-test.yml` and now `enforcement-outcomes.yml`) | The whole-daemon outcome suite runs on the oldest supported LTS kernel too, reusing the exact cached IMA kernel image built by `lsm-test.yml` (`actions/cache/restore`, key `ima-kernel-6.1.188-...`). | That the two kernels were tested concurrently or on different hardware; or that any unlisted kernel works. |

The fault seam is a no-op in every normal build: `internal/generationvm/profile.go`
and the daemon's `--generation-vm-control` flag require both `integration` and
`generation_daemon_vm` tags **and** real vimto PID 1 with private virtio ports.
Release binaries have neither the flag nor the fault field. No fixture uses a
host enforcing path, and the harness kill can never be reported as a clean
shutdown or an EPERM prevention.

**Remaining gaps after this sprint:** there is still no proof of physical
crash/power-loss continuity (unpinned maps and restart adoption are not
exercised), no multi-node/controller/fleet-at-scale proof (the fleet fixture is a
single in-guest client/server), no signed-mode or supervised-Host combination,
no packet-level network prevention, and no operations outside the tested
exec/file cases. Local oracle and compile success without a live non-skipped VM
run remains infrastructure-blocked evidence, not an enforcement pass.
