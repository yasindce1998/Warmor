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

The nonroot termination gate assumes the daemon retains the ability to signal uid 65534 (normally `CAP_KILL`), alongside the capabilities needed to load/attach BPF. Root UID alone is insufficient evidence. PR #31's signaling/pidfd implementation is integrated from `origin/main`: trusted `KernelTimestampNS` must survive both sensor channels and the platform conversion, and the guest must have initial PID/time namespaces and usable procfs. The controlled file reader remains live for 100 ms after readiness before the trigger, clearing Linux's USER_HZ=100 process-start tick ambiguity without relaxing production identity checks. Its event must report an actual successful userspace enforcement attempt with no error, not kernel prevention. Capability absence, signal permission errors, identity refusals, pidfd failures, and cleanup kills remain failures, never skips or substitutes for actual SIGKILL and attributed enforcement.

The suite does **not** yet prove atomic successful policy activation, map-write-failure rollback, no-gap switching, restart persistence, packet-level network prevention, or protection of operations outside the tested exec/file cases. The current reload test uses only today's supported SIGHUP/invalid-candidate APIs; kernel publication fault injection belongs with the activation implementation. Startup readiness here means the event loop/metrics are reachable and the exec default-deny domain has become active; it is not proof that startup had no enforcement gap.

`scripts/kind-e2e.sh` is a deployment/controller/**evaluation smoke test** on a shared host kernel. Ready pods, a loaded policy, Active CRs, events and deny counters demonstrate plumbing and policy evaluation, **not synchronous prevention or successful process termination**. Do not substitute its result for this VM outcome gate, or turn enforcement on in kind to obtain such proof. Lower-level `internal/ebpf` integration tests cover BPF loader/map behavior but likewise do not replace this whole-daemon test.

Local build/oracle success without a live VM run must be reported as **infrastructure-blocked for prevention/termination evidence**, not as an enforcement pass.
