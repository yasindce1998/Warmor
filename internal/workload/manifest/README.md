# Selection manifest v1 (preparation only)

`internal/workload/manifest` implements the publication/composition boundary in
[`docs/design/workload-identity.md`](../../../docs/design/workload-identity.md).
Nothing imports this package into the controller or daemon. It neither enables
selectors nor reports Published/Applied, opens a socket, writes maps, or accesses
a cluster. Kernel/activation isolation remains a separate release gate.

## Publication contract

The JSON `Document` has an explicit positive publication generation, mandatory
workload baseline, namespace-local additions and **separate, mandatory** unknown
and positively-known-host handling. Each scope is either `audit-only` (no
enforcing generation) or `baseline` with its own dedicated source. There is no
implicit fallback to workload selection for either scope. Sources cannot be
reused across scope roles in v1; even identical policies need distinct accepted
source identities. A failed Pod lookup is never positive host evidence.

Each source pins namespace + immutable policy UID, accepted spec generation,
SHA-256 digest, exact byte size, media type and compiler-produced ABI (3 or 5).
The namespace is the **policy object's** namespace; UID is that object's UID,
not its display name or a Kubernetes Namespace object's UID. The existing
identity join exposes namespace names, not Namespace UIDs. Namespace recreation
and stale-policy retirement must be fenced by controller/identity snapshots;
this package does not invent Namespace UID evidence.

The manifest pins compiler `7`, composition `deny-first/v1`, and posture
`per-rule/v1`. Compiler 7 tightens static declarations to complete 127-byte paths
and canonical network endpoints without changing ABI 3/5 selection or deny-first
composition. Real compiled-WASM regression tests cover those boundaries and
namespace/audit/temporal behavior. Compiler-6 manifests must be regenerated;
future compiler changes still fail closed until explicitly reviewed, rather
than automatically accepting new code generation. `New` deep copies inputs;
`Decode` additionally rejects non-exact schema field names (including case
variants), unknown/duplicate JSON fields, excess depth,
invalid UTF-8, trailing JSON and oversized documents. Canonical JSON sorts
additions and selector set order. Its hash binds the complete document,
including generation, scope handling, selectors and source-local mode overrides.

`NewBundle` requires **exactly** the referenced artifacts, validates sizes and
SHA-256 bytes before parsing, and parses immutable copies into typed policies.
References are bundle-local digests: no paths, URLs, remote fetching, or mutable
tags are interpreted. v1 accepts effective YAML sources, **not arbitrary WASM**:
opaque first-match modules cannot be safely composed. Standalone compiled
source artifacts/digests from an existing controller therefore cannot simply be
substituted for these accepted-source references.

Limits are 256 KiB manifest JSON, 128 sources (all scopes), 1 MiB per source,
8 MiB total source/effective typed bytes, and 4096 total rules. Additional syntax
expansion limits preflight **all sources before any compiler parsing**: depth
32 per source, 65536 visited values and 8 MiB expanded scalar bytes shared across
the complete bundle, including repeated variable uses. YAML aliases and merge
keys (`<<`, including quoted/tagged keys) are deliberately unsupported at every
nesting level; compiler YAML merge semantics must not hide variables from
preflight. JSON schema keys require exact spelling, but labels and rule-mode
map keys remain case-sensitive user data (`app` and `App` are distinct).
Binary, custom and other non-policy YAML tags are rejected as well: decoding
them must not create variable references invisible to syntax preflight.
Preflight bounds source bytes and requires exactly one YAML document, decoding
both the first document and the EOF probe into `yaml.Node` only. Any second
document (including an empty document) or malformed trailing input is rejected
before expansion-budget traversal or compiler parsing; the EOF probe must never
decode into `any`, where trailing aliases could materialize unchecked values.
Single-document markers, comments and an explicit `...` end marker remain valid.
The bundle enforces these limits conservatively, including duplicate content
referenced by distinct sources. Resource-limited/asynchronous compilation and
node-local selected-set cache quotas are still integration responsibilities.

### Privacy and trust

Only digest references and provenance belong in the manifest. Accepted YAML can
contain sensitive operands and variables: publish it through access-controlled
artifact storage, **not** CR status, public ConfigMaps, telemetry, or logs. Do not
embed Secret values; secret resolution/delivery needs its own authorized
mechanism. This package does not read Secrets or resolve external values.
`NewBundle` retains resolved typed policies, not raw YAML or variable maps;
operands, reasons and generated Rust/WASM still contain policy data and require
the same care. Parser errors deliberately omit raw diagnostics/values.

Content hashes prove integrity only. There is no pretend signing key, signature
verification or trust flag. The controller/transport must authenticate the
publisher and enforce installation/RBAC ownership; the daemon must authenticate
that publication, enforce monotonic acceptance/rollback policy and atomically
retain the last accepted manifest on invalid replacement. This pure constructor
cannot prove authenticity, freshness, admission authorization or LKG lifecycle.

## Exact composition semantics

`SelectPod` requires both a corroborated immutable `workload.Identity` and
`Reason == Verified`. It returns every match, confined to that Pod's namespace.
An empty selector means all **verified Pods in its namespace**. `Matched()` is
false for a verified no-match selection, which still contains the mandatory
workload baseline. Unknown and host selection use different APIs, scopes,
digests and policy sources; neither evaluates selectors.

`Bundle.Compose` produces **one typed policy for one selection**. Compile it
once using `Generation.Build` (or a private `Generation.Policy` copy). Never
flatten namespace additions node-wide or combine independent module verdicts.
The existing ABI has no no-match verdict; an independent module's default allow
is indistinguishable from an explicit allow. Source-level composition avoids
needing that distinction at evaluation time.

The versioned rule order is:

1. Every enforcing deny (`action: deny`, mode empty/enforce).
2. Every audit deny (`action: deny`, `mode: audit`).
3. Every log rule.
4. Every allow rule.
5. The workload/scope baseline's explicit fallback action.

Order is stable inside a class: baseline first, then additions sorted by
namespace+UID, then original source rule order. This deliberately replaces
source first-match precedence with deny-first semantics, **including within a
single source**. An earlier source allow/log/audit rule cannot hide a later
enforcing deny. Audit denies remain nonblocking audit denies; they are not
upgraded to enforcing denies. When several rules match, the ABI reports only
the first winning rule, not a complete multi-rule audit trail.

Every source must explicitly declare default `allow` or `deny`; legacy omitted
defaults and default `log` are rejected. Additions must declare default `allow`
as a neutral no-rule-matched fallback: it is **not** an explicit allow rule and
is never merged over the baseline default. The effective default is the
baseline's. With a default-deny baseline, v1 permits **only enforcing-deny
additions**. Allow/log/audit additions are rejected because they could return a
nonblocking verdict before the baseline fallback deny. Baseline-local explicit
allow/audit/log rules are administrator-owned accepted behavior. More general
intersection/default-deny composition requires a reviewed compiler extension;
v1 does not approximate it with unsafe rule merging.

Variables are resolved independently by `compiler.Parse` for each source. Any
variable overrides must already be materialized in that source's accepted
artifact, hence covered by its digest. `Source.RuleModes` applies by exact
original rule name **only inside that namespace+UID**; unknown names fail.
Qualified compiled rule names include namespace/UID, preventing display-name
collisions. Explicit reasons are preserved byte-for-byte; implicit `Rule: NAME`
reasons are captured before qualification. Conditions, audit modes and temporal
constraints remain typed compiler inputs; maps of variables are never merged.

The selection digest binds manifest + scope + exact source set. A generation
content hash additionally binds compiler, exact resulting ABI, posture,
composition version and typed program hash. This is not the compiled WASM byte
digest, an activation epoch, or an active lease.

## Integration handoff (not implemented here)

1. Controller validates CR edits and preserves accepted LKG source generation;
   materializes source-local overrides into accepted private artifacts; validates
   a complete bundle; publishes authenticated immutable references plus manifest.
   Do not set selectors Applied or reuse this document's generation as an
   authenticated activation acknowledgement.
2. Daemon validates/authenticates a complete replacement before swapping it;
   classifies known-host positively, unknown separately; calls `SelectPod` only
   with fresh corroborated identity. Identity/selection epochs and event-time
   lifetime evidence must be fenced outside this package.
3. Compose and build each bounded selected set. Content-address **actual WASM
   bytes** separately and verify the module's actual ABI/exports using the daemon
   loader; `Generation.Build` only compiles. Bind that artifact to the generation
   content hash and atomically stage/activate it with kernel routing.
4. Route exact cgroup+lifetime+identity epoch to that generation. Do not install
   its default-deny/preload/dynamic results in host-wide state. Invalidate leases,
   caches and kernel entries on replacement/reassignment; bound selected-set
   cardinality and compilation work. Readiness must reflect actual activation.

Other agents own compiler/controller/activation/router changes. This package
changes none of those interfaces or their existing selector Pending behavior.

## Validation

```
GOMAXPROCS=2 go test -p 2 -race ./internal/workload/manifest
WARMOR_REQUIRE_CARGO=1 TMPDIR=/tmp/opencode GOMAXPROCS=2 \
  go test -p 2 -v ./internal/workload/manifest -run TestCargo
```

Real Cargo tests compile selected generations and run them through the real
WASM loader, pool and evaluator. They cover opposing namespaces, mandatory
baseline deny versus addition allow, verified no-match, dedicated unknown/host
policies, per-rule audit, temporal constraints and ABI 5 argv callbacks. These
are userspace preparation tests, **not real-node kernel isolation evidence**.

On 2026-11-14, the full `go test -p 2 ./...`, workload-package `go vet`, and
`WARMOR_REQUIRE_CARGO=1` race-enabled manifest tests passed. Repeated manifest
race runs passed with 94.5% statement coverage. Actual WASM `abi_version` exports
are checked against the declared resulting ABI, not only generated Rust text.
Default-deny tests also prove that a restrictive addition can deny a baseline
explicit allow while an unmatched event still receives the baseline default
deny. No cluster, runtime socket or privileged kernel test was used.

PR #46 security follow-up adds bounded regressions for merged-variable
amplification, shared pre-compiler expansion budgets, binary-tag references,
and case-variant JSON scope overrides at every schema layer. Four fuzz targets
exercise strict JSON, case variants, nested merges and repeated variables;
each passed a short bounded fuzz run. Full Go 1.26.11 tests, full-repo
golangci-lint, and workload race tests with required real Cargo also passed.
The large allocation specimens from review were not executed. These fixes
require independent re-review; passing tests alone does not close that gate.

The trailing-document follow-up adds bounded alias/merge/binary/deep/empty-tail
regressions and a fifth fuzz target. Tests assert that rejected streams do not
even charge the expansion budget and that `NewBundle` returns the preflight
framing error. A 10-second trailing-stream fuzz run passed, as did Go 1.26.11
full-repo lint and workload race tests with required real Cargo. No compiler
files were changed; this framing check protects bundles independently of any
separate compiler parser hardening. Independent re-review is still required.

## Compiler 7 compatibility regression coverage

Two compiler-7 compatibility changes are now integrated on main (`ce1d5ab`).
The original build-claim review at `98d2b90` compared against compiler-6 base
`2c415c9`: `codegen.go`, `fields.go`, `staticrules.go` and `temporal.go` were then
unchanged. PR #41 subsequently tightened `staticrules.go` to require complete,
valid UTF-8 paths of at most 127 bytes and canonical network endpoints. That
changes static kernel fast-path eligibility, not first-match WASM rule decisions,
audit-deny values, temporal conditions, input layout/callbacks or ABI selection.
`exactABI` still predicts 3, or 5 for argv/network operation callbacks; the
composition/posture semantics and versions remain unchanged.

The separate compiler-7 build change adds the `warmor.build.v1` custom section,
appended after Cargo compilation and before any artifact signing. It declares compiler
`warmor-yaml/7` and the typed policy's effective default action. The compiler
also gained cancellable build/toolchain execution and failed-build cleanup.
The parser's framing hardening rejects trailing documents before typed decoding;
the manifest already rejects these independently, along with aliases, merges
and non-policy tags. It does not extend the accepted manifest source language.

Only literal compiler `7` is accepted, and the runtime compiler must also equal
the pin. Old `6` and unknown/future versions remain rejected. Tests bind the
compiler into manifest, selection and compiled-generation content identities,
including hash-only reconstruction of the old contract; old cache identities
must not be reused even when source bytes and ABI are unchanged.

Every real Cargo manifest composition test reads the actual artifact section,
checks `warmor-yaml/7` and the effective default, calls the actual WASM ABI export,
and compares the loader's bytes/digest/ABI/build declarations via
`Pool.CheckAssignment`. An expectation of `warmor-yaml/6` must fail. These checks
run for opposing namespaces, unknown/host handling, default-deny restrictive
additions, baseline deny versus addition allow, and per-rule audit/temporal/ABI-5
cases. Build declarations alone are **not** publisher authentication or proof
of compiler provenance; no signatures, shared source authentication, controller
publication, activation or selector enforcement are enabled by this change.

PR #41's real Cargo static-boundary specimens remain intact: a complete
127-byte path and canonical IPv6 endpoint are eligible, while an overlong path
and noncanonical endpoint export no eligible static rules. All four now also
run through the same artifact-claim/actual-ABI/loader consistency checks. This
adds regression coverage to main's existing compiler-7 pin; it does not repeat
the production compatibility fix or alter static-identity behavior.

Before integration with PR #41, Go 1.26.11 validation passed with
`GOMAXPROCS=2`, `-p 2` and `WARMOR_REQUIRE_CARGO=1`: workload/compiler/policybuild/
WASM tests, their race suite, and the full repository suite; full-repo lint and
the exact Go 1.26.11 formatter also passed. An initial overlapping non-race WASM
run hit the existing 20 ms timeout-replacement test deadline under load; the
non-overlapping uncached affected-package rerun passed without test changes.
These results do not substitute for independent compatibility review.

After merging main `ce1d5ab`, the uncached focused workload/compiler/policybuild/
WASM tests with required real Cargo passed on Go 1.26.11 (`GOMAXPROCS=2`, `-p 2`),
as did full-repo lint. All focused race packages passed; WASM needed a standalone
uncached rerun after an initialization-budget deadline while lint was running.
No timeouts were weakened and no production behavior changed relative to main.
