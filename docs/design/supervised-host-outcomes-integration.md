# PR53 supervised Host outcome gate integration

Persistent branch `test/supervised-host-outcomes-integration`, worktree
`.worktrees/supervised-host-outcomes-integration`, starts from PR53 **5ed1817**.
Only the reviewed packaging checkpoint **399f605** and held-load proof
**aaf328e** were cherry-picked (local commits **4ec17f9**, **a5e4711**).
The original commits/branches/worktrees remain frozen. No main merge, push,
release/tag or CI execution is performed here.

## Conflict resolution and inherited safety

- Preserve `checkSignedBackendCombination` before configuration/state/output/
  privilege/monitor/child setup and the existing enforcer/bootstrap guards.
  `--signed-assignments` + Host and/or atomic is still unsupported. Added CLI
  regression includes the full artifact-verification/helper-pin/load-deadline
  options to ensure the new option cannot bypass that refusal.
- **Artifact-signed fixtures are not signed deployment.** Both map modes use
  detached module signatures only, with explicit reviewed declaration digests;
  no assignment intent, agentstore publication or combined recovery is claimed.
- Preserve current main ce1/PR41 private VM recordings: use guest-local physical
  `/tmp/warmor-outcome-fixtures/recordings`, 0700, and real privatefile checks.
  Shared checkout files are evidence exports after daemon Wait, never live sinks.
  The helper remains at root-owned physical `/run/warmor-outcomes`; no symlink
  trust exception or ancestor chmod/chown is introduced.
- Retain canonical `policymeta.Source`/observed metadata, requested **and**
  initialized `platform.LSMBlocking()` posture, no parent runtime in Host mode,
  terminal-host cache refusal and old-host lease/Close ownership. No duplicate
  metadata interface/parser or loaded-hook-as-blocking inference is added.
- Release/archive and Docker helper bytes/pin metadata stay from the same source
  build as the daemon; no phase profile/environment is compiled into them.
  The VM pair explicitly uses `policyhost_phaseproof` and verifies embedded
  revision/toolchain/architecture/tag and the installed helper SHA-256.
- Phase receipts prove an attributed uncached ALLOW completes while the signed
  candidate is held **before compilation**, not during native SSA execution.
  Real compiler/init deadlines and eventual-LKG probes follow release. The real
  eventMu negative oracle in both map modes still rejects post-rejection ALLOW.
- New Host CI matrix pins **Go 1.26.11**, requires exact one PASS per selected
  verifier and outcome fixture, rejects any selected skip/failure, and retains
  failure evidence. There is no local/host fallback. Existing #41/#51 strict VM
  gates and PR53's Clang 18/21 BTF fix/authenticated LLVM provisioning are unchanged.

## Validation

Validation is one sequential pipeline, **Go 1.26.11**, `GOMAXPROCS=2`, `-p 2`,
Cargo required for compiler fixtures: full normal suite, then full race suite,
then normal/profile lint, tagged compile-only and Host build-only preparation.
Results/logs are recorded after completion; no broad-green result is inferred
from focused tests. Build-only never launches a daemon, VM or BPF program.

Actual legacy **and** atomic Host VM CI is still required after coordinator review
and PR53 gate append. No local VM/BPF attachment, Docker publication, native
arm64/container/bootstrap/update evidence or supported combined signed-deployment
Host/atomic transaction is supplied by this integration.
