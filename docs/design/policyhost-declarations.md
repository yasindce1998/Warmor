# Policy-host declarations: authenticated observations, explicit trust

Status: optional backend/API checkpoint on `feat/policyhost-declarations`, based
on PR45's frozen `f394546`. **No enforcer routing, generation activation, kernel
map writes or default backend changes.** PR45's process-boundary limitations
continue to apply.

## Contract

`internal/policymeta` is a runtime-free shared model. `policymeta.Source` is
implemented by both `*wasm.PolicyEvaluator` and `*policyhost.Host`; it exposes
`Metadata`, `FieldsRead`, temporal/container-age queries, process/network static
domains, decision-cache eligibility and Linux kernel-key dependency eligibility.
The existing `wasm.StaticDomain` name is an alias, so existing in-process method
signatures remain source-compatible. Legacy in-process fields/static methods
retain their trust semantics; new metadata/eligibility methods sanitize invalid
declarations. Combined evaluator lifecycle/interface wiring belongs to the
generation-activation integration, not this branch.

Wire protocol **2** requires `Ready{Control, Metadata}` instead of protocol 1's
bare ready control frame. Metadata has its own version (1), exact module SHA-256,
actual observed ABI export result (0 explicitly means absent), selected entrypoint
encoding (`binary` or `json`), exactly three ordered event records and two ordered
process/network domains. Missing, duplicate, unexpected, noncanonical or oversized
structured input is rejected; a protocol 1 worker cannot silently omit metadata.
The existing initialization/load deadline covers metadata construction and upload.
There is no parent WASM parsing or compilation; `go list -deps` tests enforce the
production parent's lack of `internal/wasm` and wazero dependencies. Runtime loads
in parity tests are test-only, not a fallback path.

The pinned executable is the trusted source of observations on a private inherited
pipe. The parent checks the module digest, versions, shape, count/length bounds,
exact field mask vocabulary and recomputed finite flags. This authenticates **who
observed which module**, not whether arbitrary guest exports tell the truth.
No standalone policy-supplied metadata document is accepted.

## Declaration trust and conservative defaults

An arbitrary module can lie about its dependencies, mutate private state between
events, or declare a static allowlist inconsistent with evaluation. Neither the
signature, actual ABI, valid field mask nor worker digest proves exhaustive,
deterministic declarations. Therefore `Config.TrustedDeclarationDigests` defaults
to empty and is an explicit administrator-owned attestation for at most 256 exact
module digests. It must come from an independently trusted compiler/build or
review process; **never populate it automatically from the candidate digest,
signature verification, or receipt of a ready frame**. Duplicate/malformed pins
are refused and configuration slices are copied.

Without that attestation, `Host.FieldsRead` returns `FieldsUnknown`, static domains
are ineligible, cache eligibility is false, and `TimeDependent` conservatively
returns true to disable legacy caches using that predicate. `Metadata` is a
defensive copy of raw observations, not an optimization authorization. With trust,
only structurally eligible flags/domains are exposed. An absent ABI is usable for
evaluation but never optimized; unsupported ABI values fail load/validation.
Unknown/future field bits become `FieldsUnknown` in worker observations and are
rejected if presented as finite metadata. Time/container-age inputs retain current
ABI 3+ semantics; temporal dependencies decline decision and kernel caching.

Kernel-key flags describe only dependency coverage by Linux exec full-path and
binary endpoint keys. They do not authorize global rules, kernel default deny,
hash-only maps, cache insertion, generation/scope reuse or other platforms.
Integrators must still enforce workload scope, platform capabilities, exact key
matching, full-table installation capacity, mode and generation atomicity. Dynamic
per-event kernel entries must obey the same exact-key requirements.

## Static rule validation and limits

- At most **4096 static entries total** across both domains; each individual
  guest table is bounded before allocation (1,064,961 bytes), and publication
  independently checks the combined count. This is below the legacy 65,536-entry
  map capacity, but not a promise of free capacity in any particular map.
- Paths/patterns are nonempty, valid UTF-8, NUL-free and at most 254 bytes.
  Process entries have port zero. Event labels must match their enclosing domain.
- Network entries require canonical unzoned IPv4/IPv6 text, not IPv4-mapped aliases
  or alternate textual spellings. Rewriting an alias would change guest string-eq
  semantics, so an unusable declaration declines the whole domain instead.
  Ports are uint16 including 0 and 65535, never interpreted as wildcards.
- Exact tuple keys `(event type, full pattern, port)` are retained. Duplicate full
  keys (even identical values) decline the whole guest domain or reject incoming
  metadata; action/audit differences never turn into last-writer-wins behavior.
  Distinct keys are not deduplicated by a lossy hash.
- Action is precisely allow=0 or deny=1; audit is a strict boolean. Log rules
  retain allow+audit; audit-mode denials retain deny+audit. Runtime global mode is
  not guessed or folded into the module metadata. Empty **eligible** domains mean
  deny-all misses, while ineligible domains must contain no rules.
- Static eligibility additionally requires finite fields fully covered by that
  domain's key. Unknown dependencies, invalid eligibility bytes, trailing data,
  overlong entries, duplicates and noncanonical endpoints never become incomplete
  allowlists. Worker observations decline unusable domains; malformed transport
  fails candidate readiness. Existing evaluation remains available when a guest
  optional declaration is unusable.

The metadata frame cap is **8 MiB**, accommodating worst-case JSON escaping of
4096 bounded patterns without allowing an unbounded parent allocation. Canonical
decoding rejects missing fields (including a missing ABI/flags record), duplicate
keys, unknown flags, and unknown metadata versions. Flags are independently
derived from the observed ABI/mask, not accepted as guest-provided authorization.
All API metadata/static-rule snapshots are defensive copies.

## Verification and remaining gates

Tests exercise malformed/missing/duplicate/oversized metadata, finite masks and
flags, future/absent ABI decline, exact key/endpoint/port bounds, count endpoints,
trust defaults and defensive copies. Actual Cargo-generated policies are signed,
loaded in the real worker, and compared with the in-process evaluator's observed
metadata and allow/deny/log/audit results. Tests cover compiler first-match
deduplication, ABI 3 static rules and ABI 5 args/invalid-UTF-8 behavior. Run with
`WARMOR_REQUIRE_CARGO=1` to make a missing Rust/wasm32 toolchain fail rather than
skip. No host security hooks or arbitrary process signals are installed.

This is not semantic verification of arbitrary WASM. The existing kernel branch's
collision-free exact identities and generation-atomic installation are still
required before enabling default-deny or kernel cache integration. Activation,
attestation provenance/configuration, global audit mode, retirement/drain,
packaging and fail-closed enforcement tests remain separate gates.
