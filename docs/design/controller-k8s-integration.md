# Controller / Kubernetes safety integration

This integration starts at `origin/main` commit `9ea4594`. After the controller
and Kubernetes tasks were combined, the coordinator requested incorporating the
newly merged PR #31 signaling/outcome changes at `origin/main` commit `1e49aa7`.
Activation work remains separate.
The persistent worktree is `.worktrees/controller-k8s-integration`, branch
`fix/k8s-controller-safety-integration`. No push, PR or merge into main is part of this work.

## Imported task commits (in order)

| Original | Integration cherry-pick | Purpose |
|---|---|---|
| `625c4ba` | `46a6f0e` | Compiler subprocess cancellation and failed-crate cleanup |
| `5c76e19` | `6d1c695` | Durable accepted-source journal and verified publication |
| `d68b86e` | `c4918df` | Controller restart/failure/identity tests |
| `7389eed` | `33444b5` | Publication-only status and recovery documentation |
| `ee96d4d` | `63ca5b3` | Immutable publication, snapshot privacy and scope tests |
| `a2bea94` | `52d4b42` | Exact pod cgroup reconciliation and local runtime readiness |
| `a7a29f0` | `7577fb9` | Validated chart posture and selected-policy binary deployment |
| `1da0e2c` | `5e6ae44` | Scope recovery and cluster-free deployment guard tests |

All eight apply without textual conflicts; original task branches remain intact.
Merge `e25546c` subsequently incorporates `1e49aa7`, also without textual
conflicts. This is a local merge into the integration branch, not a merge into
main or a remote publication.

The coordinator subsequently initiated a merge of `origin/main` at `78471f6`,
including PR #32 isolated streaming sinks, PR #30 dashboard HTTP safety and PR #34
canary analysis. Merge `1ffc00f` completes that merge. Its only textual conflict
was the daemon flag declaration block: both dashboard bind/auth flags and the
metrics/cgroup flags are retained. Dashboard literal-IP validation, token loading
and dedicated HTTP serving remain intact alongside scoped runtime options and
readiness. Use pinned base `78471f6` for the current integration delta, or a
three-dot merge-base diff if main advances again.

## Integration follow-ups

- Kind explicitly applies/establishes the additive CRD before controller upgrade
  and waits for both `phase=Published` and `Published=True`, never `Applied=True`.
  The aggregate audit-decision counter remains a smoke signal, not authenticated
  exact-digest node evidence.
- CRD migration contract tests check the serialized status field types, retained
  legacy fields/phases, condition string enum and status subresource. No live
  admission/pruning migration was run.
- A real cargo/WASM test serializes the accepted-source journal, restarts with an
  invalid update and unproven legacy application status, evaluates retained deny
  semantics, then recompiles with another source and checks that deny again.
- Real YAML and WASM deploy-helper tests validate exact artifact bytes and the
  content-addressed ConfigMap, mount reference, validator and daemon paths using
  kubectl **client** dry-run and Helm rendering. They evaluate the selected
  policy locally; they never deploy a DaemonSet.
- Controller port 9091 now serves real HTTP liveness, recent-successful-local-
  reconciliation readiness and private-registry metrics. The chart wires probes,
  pod scraping and ingress separately from daemon metrics. Reconcile failures,
  staleness and shutdown withdraw readiness. Successful last-good retention may
  remain locally ready while the desired CR stays invalid. No node-applied claim
  follows from a healthy controller.
- The daemon projection includes only `policy.wasm`, not accepted-source history.
- Workload review found the baseline treated `selector: {}` as an unscoped
  policy. Any non-nil selector now stays Pending (including empty object/labels/
  expressions); tests cover new sources making no contribution and restart
  retention of an old accepted unscoped generation without accepting the edit.
  This does not enable selector enforcement.
- All four Linux monitor loops retain raw `KernelTimestampNS` through delivery,
  alongside exact-scope filtering and reader-failure readiness withdrawal. Tests
  exercise process/file/network tracepoints and each LSM event kind via injected
  readers; missing timestamps remain zero and LSM denial/integrity/hook metadata
  remains intact. Enforcer construction tests cover both audit/learning posture
  and the combined cgroup root/reconciliation options. Strict pidfd verification
  and truthful attempted/refused/failed/successful outcomes from PR #31 remain.
- Independent Kubernetes review found wrapped `ENOENT` was misclassified by
  `os.IsNotExist` after `ResolveCgroupID` wrapped Statx errors. Discovery now uses
  `errors.Is(err, fs.ErrNotExist)`. A deterministic deletion between Walk's stat
  and the real resolver's Statx exercises the wrapped churn path; wrapped
  permission errors still fail discovery.

## Validation scope

Run with `GOMAXPROCS=2`, `GOFLAGS=-p=2`, `TMPDIR=/tmp/opencode` and
`WARMOR_REQUIRE_CARGO=1` for tests:

```text
go test -count=1 -p 2 ./...
go test -race -count=1 -p 2 ./...
go vet -p 2 ./...
bash -n scripts/kind-e2e.sh scripts/kubernetes-deploy.sh scripts/kubernetes-preflight.sh
helm lint deploy/helm/warmor --strict
helm lint deploy/helm/warmor --strict --set controller.enabled=true
helm lint deploy/helm/warmor --strict -f deploy/helm/warmor/values-enforcement.yaml
helm lint deploy/helm/warmor --strict --set controller.enabled=true -f deploy/helm/warmor/values-enforcement.yaml
```

Additional Helm templates include the CRD, controller/all-namespace confirmation,
and controller/enforcement profiles. Deployment tests exercise unsafe-value
rejection and default/controller/explicit-enforcement render contracts. The only
Helm lint advisory is the recommended chart icon.

Final settled-tree full tests, full race tests, vet, shell syntax and all four
strict Helm lint profiles passed after PR #31 integration and empty-selector
hardening, and were all rerun successfully after merge `1ffc00f` incorporated
main at `78471f6` (dashboard, streaming and canary safety). An earlier background race invocation overlapped the coordinator's
requested main merge and produced mixed-tree build failures; it is superseded
by the clean sequential full runs above, not counted as passing evidence.

No cluster was created/contacted and no live daemon/BPF/host enforcement was run.
The inherited signaling unit tests use only their own allowlisted child processes,
not arbitrary host processes or a running enforcement agent.
Real-node capability, namespace visibility, cgroup inode identity, readiness,
new-pod churn, CNI, PID signaling and LSM outcome gates remain unverified here.

## Coordinator handoff / unresolved work

- **Node acknowledgement:** no authenticated per-node exact-digest ack path;
  `Applied=Unknown`, no asserted `nodesApplied`/`lastApplied`, no active digest.
- **Signing:** mutable controller ConfigMaps are unsigned; SHA-256 is integrity,
  not writer authentication. A writer replacing content and checksums remains in
  the trust boundary. Durable accepted history depends on preserving/backing up
  the ConfigMap. Cache eviction and leader election remain open.
- **Scoping:** auto includes all discovered pods/descendants, including Warmor and
  system pods, and has discovery lag. Selectors are unsupported; a selector edit
  retains an old unscoped accepted generation until explicit deletion. Source
  namespacing is not workload isolation. Map updates are not atomic across maps.
- **Activation excluded:** re-test after combining that independently maintained
  branch, which overlaps `cmd/warmor-daemon/main.go` and
  `internal/enforcer/enforcer.go`. Signaling was included only after landing on
  main, as requested. Its overlapping enforcer/platform/LSM changes merged
  textually, then received combined monitor identity/scope/readiness regressions.
  Preserve both local readiness and exact activation/identity/outcome contracts
  when resolving any later activation merge.
- Independent owner review reported no new severe controller blockers, not an
  unconditional clean bill of health. The separate compilation-deadline
  limitation/documentation review remains coordinated by the main session.
