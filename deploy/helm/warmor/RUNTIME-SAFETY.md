# Runtime safety and validation limits

The default chart is audit-only, with `cgroupFilter: auto`. It reports denies
without signaling or blocking. `auto` includes **every pod**, including Warmor,
the controller, kube-system and tenants. It is not per-workload isolation;
`WarmorPolicy.spec.selector` remains Pending. No CRI identity or protected-pod
exclusion model is implemented by this chart.

## Discovery and failure behavior

- Discover exact pod directory **and all descendant container cgroup IDs** every
  `daemon.cgroupReconcileInterval` (default 1s). New workloads may run before
  discovery. Explicit cgroup paths are exact IDs, not recursive selectors.
- Empty existing kubepods hierarchy means cover nobody, never the host. Missing
  hierarchy, unreadable cgroup v2 root, or initial filter-write failure prevents
  startup. Runtime discovery/write failures retain last accepted userspace scope
  and withdraw readiness. Never silently clear a filter on failure.
- Active kernel-scope sentinels are never removed during scoped updates. Add new
  IDs before removing old ones, so failed additions preserve previous coverage.
  Updates are not atomic across maps: errors can leave partial new coverage or
  obsolete IDs until retry. Desired and old+new transition sets must fit 1023
  exact IDs; capacity errors are explicit, not truncation or host-wide fallback.
- This is **not kernel-wide fail-closed admission**. New workloads can run before
  discovery and during discovery failure; readiness cannot prevent scheduling.
  Monitor `warmor_cgroup_reconciliations_total{result="error"}`,
  `warmor_cgroup_scope_ids`, and
  `warmor_cgroup_last_success_timestamp_seconds`.

The host cgroup v2 mount must expose the node hierarchy, not only the agent
subtree, and inode IDs must agree with `bpf_get_current_cgroup_id()` in the actual
runtime's PID/cgroup namespaces. `hostPaths.cgroup` selects the source,
`hostPaths.cgroupMount` its read-only container path (passed as `--cgroup-root`
to discovery and the container resolver). `hostPaths.kernel` mounts read-only at
`/sys/kernel` for BTF/LSM detection. hostPID exposes host `/proc`; duplicate host
proc/sys, writable bpffs and runtime-socket mounts are unnecessary and removed.

## Probes, API and networking

`/health` is HTTP process liveness, deliberately independent of policy/API
outages. `/ready` returns 503 without a running event loop and loaded policy,
when readers disconnect, when requested LSM enforcement is inactive, or when
discovery fails/goes stale. It is local active-policy readiness, **not** a
controller desired-generation acknowledgment. Retaining a last-good policy on a
failed reload may remain ready; applied-generation reporting is separate work.

The agent performs local discovery and reads projected ConfigMaps: it needs no
API RBAC or service account token. Controller RBAC remains separate. Metrics
Service selects only `component: daemon`. `daemon.metricsBindAddress` optionally
restricts bind IP; loopback prevents ordinary kubelet HTTP probes from succeeding.
hostNetwork NetworkPolicy enforcement is **CNI-dependent**, not proven by a
rendered policy. Unsupported admission webhook enablement is rejected.

## Explicit enforcement profile

`values-enforcement.yaml` is an example for disposable isolated nodes ONLY.
Disabling audit requires `daemon.confirmNodeWidePolicy=true`. Kernel enforcement
also requires `daemon.lsmEnforce=true,daemon.requireLSM=true`; unsupported kernels
fail startup. Contradictory audit/blocking settings are rejected. Clearing
`daemon.cgroupFilter` opts into host-wide events: do not validate this on a shared
host. Scope confirmation does not make a policy safe for Warmor/system workloads.

Current chart images are restricted to Linux amd64. Use `image.digest` and
`controller.image.digest` (`sha256:<64 lowercase hex>`) to override mutable tags;
the daemon's policy validator shares its pinned image. Controller writable cache
and temporary storage are bounded. The controller serves real process liveness,
recent-local-reconciliation readiness and metrics on port 9091 (separate pod
scrape annotations; the daemon Service does not select it). Reconcile failure or
staleness withdraws controller readiness; retaining a valid last-good publication
after an invalid desired edit can remain locally ready. This never proves node
application: CR `Applied` remains Unknown, with no asserted node count or
`lastApplied`. See the [controller contract](../../../../docs/design/warmorpolicy-controller.md#controller-probes-and-metrics).

## Empirical capability and real-node test matrix (not run here)

Use disposable VMs/nodes and a dedicated Kubernetes context, a restrictive test
policy whose deny marker occurs only in the test workload, and out-of-band
recovery. Kind shares the host kernel; a passing audit smoke test is not evidence
of safe hostPID signaling, cgroup namespace visibility, or LSM blocking.

1. Run `bash scripts/kubernetes-preflight.sh` on the node and in an
   agent-equivalent diagnostic image/security context (distroless has no shell).
   Compare effective caps, PID/cgroup/mount/user namespace identities, cgroup v2
   visibility, BTF/LSM/IMA. It is read-only and never attaches BPF.
2. Use the real audit pod context: drop ALL; add SYS_ADMIN/BPF/PERFMON, read-only
   root, no privilege escalation, actual seccomp/runtime. UID 10001 deny-marker
   workloads must survive, with no kernel block and no CAP_KILL. Record exact
   kernel/runtime/CNI/security-profile versions. SYS_ADMIN is broad even though
   KILL is absent; this is not a hostile-agent sandbox.
3. On modern kernels remove SYS_ADMIN, then BPF/PERFMON independently and verify
   startup and every advertised hook. Older kernels may need SYS_ADMIN as a
   compatibility fallback. NET_ADMIN was removed: current hooks do not configure
   networking. Do not claim a universal minimum without this matrix.
4. In explicit enforcement the chart adds **KILL only when audit is false**.
   Create a UID 10001 deny-marker pod AFTER startup. Verify target termination,
   repeat without KILL and assert permission failure is surfaced, not reported as
   a successful kill. Only use allowlisted test PIDs, never broadcast signals.
   Confirm unrelated pod/host sentinel processes survive.
5. On BPF-LSM nodes test each advertised hook. Distinguish first userspace
   detection from cached kernel EPERM/default-deny. Exercise new pods, container
   restart, deletion/recreation, exact child IDs, removed IDs, empty set, >1023
   capacity, inaccessible hierarchy and injected map errors. Readiness must fail
   on unhealthy required posture without liveness restarts. ID reuse/kernel
   decision generation and selector isolation need their separate runtime work.
6. Test CNI-specific metrics ingress, hostNetwork probes, containerd and CRI-O,
   node reboot, upgrade/uninstall and recovery. Preserve evidence. Unit/fake
   discovery/render tests do not satisfy this real enforcement acceptance gate.

## Make deployment policy contract

The root `deploy`/`deploy-audit` targets now compile selected YAML using
`warmor-compile` (Go + Rust toolchains), validate WASM, and mount that exact binary
through a content-addressed ConfigMap. `.wasm` input skips compilation but not
validation. The old ignored `--set-file policy.yaml=...` value is rejected.

```bash
# Local-only preview: compilation, validation, ConfigMap client dry-run + render.
make deploy-audit POLICY=examples/policies/kubernetes-hardening.yaml DRY_RUN=true
# Live commands require an explicit context; never use on existing shared nodes
# as an enforcement experiment.
make deploy-audit POLICY=my-policy.wasm KUBE_CONTEXT=dedicated-test-cluster
```

Dry-run output contains policy binaryData; treat it as policy material. Rendering
is validated before cluster writes. Live deploy resets previous Helm values to
avoid inherited enforcement flags on transition to audit; set required custom
values through the chart directly when that helper's narrow profile is
insufficient. `make deploy` additionally requires
`CONFIRM_NODE_WIDE_POLICY=true` and explicitly enables/requires LSM. Old ConfigMap
revisions are retained for rollback; prune only after verifying no current or
rollback revision references them. A failed upgrade may leave an unreferenced
ConfigMap but does not overwrite the previous policy artifact.
