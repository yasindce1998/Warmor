# Experimental supervised evaluator integration

Status: **off by default, Linux only, not production validated**. This branch
connects the reviewed policy-host and metadata APIs to the enforcer, including
generation slots. It does not attach any security hooks in its tests or change
the default in-process backend. The process boundary/resource limitations in
`supervised-policy-host.md` still apply: this is not a general OS sandbox, an RSS
quota, protection from a compromised trusted host executable, or protection from
daemon downtime.

Follow-ups: `supervised-evaluator-main.md` records the pinned PR40 main merge and
security fixes. `supervised-evaluator-shutdown.md` records the separately based
reader-close-before-join shutdown integration; earlier reviewed branches remain
unchanged.

The later current-main PR39/PR50 merge and usable opt-in configuration are
documented in `supervised-host-activation.md`, including private output boundaries
and the still-open whole-daemon Host VM gate.

## Configuration and trust

Explicit opt-in is `--experimental-supervised-policy-host`, with `--verify-key`,
an absolute `--policy-host` executable path, and lowercase
`--policy-host-sha256`. There is no PATH search, environment inheritance, shared
compilation cache, automatic fallback or worker respawn. The standalone command
must currently be built/installed separately; release packaging is follow-up.
The flags select an active backend, not an informational readiness label.

`--policy-declaration-digests` is an optional comma-separated, administrator-owned
attestation of exhaustive deterministic declarations for exact module digests.
It must not be populated from downloaded assignments, signature verification,
compiler display labels or worker readiness. Empty means **no decision cache,
kernel cache or static allowlist authorization**. Raw `Metadata()` observations
remain available but only `policymeta.Source`'s effective methods authorize
optimizations. PR41's shared **127-byte process path** limit applies to compiler,
runtime static tables and metadata, for both JSON and binary encoding. Transport
pattern/frame maxima do not enlarge the kernel identity contract.

## Preparation and ownership

`Evaluator` combines Evaluate, Close and canonical `policymeta.Source`. A
`policyBackend` owns the whole evaluator/pool/runtime or single child lifetime;
generation slots share the owner only for initial IDs 0/1. All teardown is
idempotent. Comparing pool pointers is deliberately not used: all supervised
pools are nil, while different hosts have different lifetimes.

The supervised startup path resolves an immutable revision pair, stages a
signature-verified byte snapshot, and waits for bounded child-observed metadata
before platform creation. Generation candidates read verified bytes once and
stage exactly that snapshot; readiness and static completeness checks precede
kernel Prepare. The parent never invokes WASM Decode, custom-section parsing,
validation, compilation or instantiation on this path. The enforcer binary still
imports the legacy runtime because that remains the default backend.

The existing generation commit model is unchanged: register evaluator, commit
kernel pointer, publish userspace, invoke the sole durable callback, fence ring
events and drain captured leases, then retire the old host. A failed durable
commit retains both owners and the original closure/revision. Retrying the same
candidate finishes recovery without another child or kernel Prepare. Failed
preparation only closes/reaps the candidate. Worker evaluation/IPC/limit failure
denies that event without caching the error; the failed host remains terminal.
Reaped hosts cannot serve prior userspace cached allows. Health checks are
snapshots, not atomic liveness proofs; separately authorized static/kernel rules
are not globally revoked merely because their evaluator child exits.
Only an explicit activation starts another host. Budgets are process-lifetime
budgets: request/CPU exhaustion requires operator-controlled activation, not a
hidden renewal loop.

## Signed assignment seam

`Options.ExpectedAssignment` and `ActivateAssignment` validate actual digest,
ABI and authenticated build claims using `Source.Metadata().MatchArtifact`,
including in host mode. They also check effective runtime posture and trusted
static eligibility when default-deny is required. They do **not** verify signed
deployment intent, target, expiry, anti-replay or clock health: that remains the
assignment/agentstore caller's responsibility. A detached artifact signature
does not establish compiler provenance or truthful dependency declarations.

`ExpectedAssignment` disables generic reload/activation. Assignment activation
requires an artifact verification key and exactly one durable callback.
**Signed-assignment + atomic-generation startup/activation is explicitly rejected**,
including supervised mode, until a shared commit/recovery model is tested. This
branch does not wire the separate signed-mode daemon/client. Its flags are not
silently emulated, nor is agentstore nested inside legacy fleet publication.
Detached artifact signatures with unsigned fleet generations remain supported.

The standalone `--validate-policy` command remains the legacy in-process
validator and explicitly rejects all supervised flags, so selecting supervised
mode cannot silently route validation through the parent runtime.

## Evidence and remaining gates

Unprivileged integration tests build the actual host command and substitute only
the platform/kernel publication boundary. They exercise captured old-host leases,
post-commit uncertain durability, exact retry ownership, bad signatures and
malformed candidates before Prepare, terminal worker timeout/noncached denial,
effective trusted static/cache methods, and actual child-observed ABI/build
assignment mismatches. A real compiler-heavy valid module must hit the parent's
load deadline while active-generation events continue; immediate next activation
checks killed-child reaping/capacity release. No sleeper/mock worker stands in
for compilation.

Whole-daemon supported-kernel VM evidence, release packaging, sustained resource
and event-loss tests, native non-Linux execution, restart/power-loss continuity,
and the combined signed/atomic commit model remain open. No host-wide enforcing
run or BPF feature/object change is claimed here. Validation commands/results
are recorded at the final checkpoint, not inferred from this test inventory.

### Local checkpoint validation

Code checkpoint `480d5d6`, Linux unprivileged, **Go 1.26.11**, `GOMAXPROCS=2`,
package parallelism **`-p 2`**:

- `go test -p 2 ./...`: pass.
- `go test -race -p 2 ./...`: pass.
- `go test -race -p 2 ./internal/enforcer -run 'TestSupervised|TestGeneration'
  -count=5`: pass, including real compiler-deadline and concurrent active work.
- `go vet -p 2 ./...`: pass.
- `golangci-lint v1.64.8 run --concurrency 2 --timeout 5m ./...`: pass. The lint
  executable itself was built with Go 1.27.2; analysis ran with Go 1.26.11 selected.
- `WARMOR_REQUIRE_CARGO=1 go test -p 2 ./internal/policyhost ./internal/wasm
  -run 'TestCompiled|TestReal.*(Compiler|Cargo)|TestGenerated' -count=1`: pass;
  actual compiler-generated metadata/decision parity tests did not skip.
- Windows amd64 enforcer and Darwin arm64 daemon test binaries cross-compiled
  successfully at `c1dc1dd`; no native non-Linux execution is claimed.
- `git diff --check`: pass. No BPF C/embedded object or `go.mod`/`go.sum` delta
  from generation base `22cc85e`. PR41 transport follow-up `0e3a2e` is not included;
  this integration makes no claim to its separate VM evidence.

Base is `22cc85e`. It contained no PR45 implementation; host base `de4065d`, lint
fix `f394546`, metadata `d68d0af`/`48d5c41`/`c7ff006`, FD fix `84a8176`, and signed
assignment/store dependency `d869cb5` were cherry-picked. The single real source
conflict in `internal/wasm/staticrules.go` retained PR41's 127-byte path/UTF-8 and
canonical endpoint validation while adopting canonical metadata types. Custom
duplicate exports now decline optimization under the reviewed metadata contract;
compiler-generated first-match deduplication is unchanged. Fleet sole-owner fix
`359c75c` is included as `db63155`, preserving standalone reload and rejecting
fleet local reload before the enforcer callback.

Logs: `/tmp/opencode/supervised-{full,race,focused-race,vet,lint,cargo,`
`cross-windows,cross-darwin}.log`. Early test failures caught fixture expectations
for the older 254-byte JSON allowance and duplicate-export deduplication; these
were corrected to assert the integrated conservative contract, not skipped.
No original branch/main edits, pushes, PR/merge actions, host-wide enforcing
tests, BPF regeneration or whole-daemon VM execution were performed.
