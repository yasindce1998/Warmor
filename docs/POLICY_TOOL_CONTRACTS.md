# Policy tooling and replay contracts

## Learning is a proposal, not a security equivalence proof

`warmor-learn` emits compiler-valid `path` conditions and numeric ports. IPv6
endpoints are bracket-aware. Bind/listen observations become `network` rules
using their recorded **evaluator operation**; current Linux sensors may label the
hook bind/listen while still supplying operation `connect`. Legacy summaries use
that historical fallback and replay explicitly labels their evidence incomplete.

The learner intentionally generalizes exec/file observations to paths (not argv,
UID, flags, or operation), and network observations to endpoints/operations.
Review and narrow allow rules before deployment. Leading literal `$` values are
escaped and colliding/truncated generated rule names are made unique.

The CLI refuses mount/ptrace and unsupported hooks rather than emitting invalid
standalone YAML events or broadening them into ordinary process/file permissions.
It refuses empty policies, redacted/truncated evidence, incomplete target fields,
and paths over the compiler binary ABI's 128-byte width: an exact long-path allow
cannot currently match its own observation. No compiler or ABI changes are made.

## Recorded event schema version 2

New events have `schema_version: 2`. Existing top-level SIEM summary keys remain,
with an additional `policy_input` containing an owned snapshot of `api.Event` as
supplied to policy evaluation. This preserves argv, parent comm/PPID, typed file
operations/flags/mode, network operations/protocol/endpoints, hook identity,
cgroup and temporal metadata. Replay uses the snapshot, not the summary. The
snapshot timestamp remains authoritative even if a display timestamp was filled
in. Recording does not invent missing sensor metadata.

Missing/1 versions are legacy recordings: replay still estimates decisions, but
increments `incomplete_events` and warns about unavailable fields. Known missing
inputs are recorded in `input_issues`, e.g.:

```json
{"field":"process.args","state":"unknown"}
```

`unknown`, `truncated`, and `redacted` describe evidence limitations, not policy
values. Issues make replay report incomplete evidence; future schema versions
are rejected. Evaluation errors are counted separately in `evaluation_errors`
(and conservatively in denial totals). Reports with incomplete evidence/errors
never claim all prior decisions remain unchanged. Preserving input is not proof
of equivalent live enforcement.

**Sensitive data:** argv can contain passwords/tokens. Version 2 records argv by
default; protect event files, access, and retention. Redactors **must** remove
secrets from both `policy_input` and summary fields and append an `input_issues`
entry with `state: redacted` and the affected field path. Editing only the summary
leaves secrets in the authoritative snapshot. No automatic redaction CLI is added.

**Sensor/encoding limits:** the API does not supply capture-completeness or
truncation lengths, so the recorder cannot certify sensor completeness. Producers
that know capture was partial must add issues. JSON preserves Unicode but cannot
represent invalid UTF-8 path/argv bytes losslessly; the transform marks these
inputs incomplete before JSON replaces bytes. The learner refuses incomplete
target paths/endpoints. Replay/learning do not prove coverage of unobserved
behavior, workload identities, future events, or real kernel enforcement.

## Diff and merge

Files are validated with the real compiler parser before diff/merge loads them.
The editing-shaped YAML types retain variables/temporal blocks; they are not a
second validator. Merge CLI output is always compiler-validated; `--validate`
remains accepted and prints confirmation.

Diff reports effective defaults (omitted means `allow`), variable values including
addition/removal, relative first-match order of matched rules, and existing
action/mode/reason/temporal differences. A rule in “both” may use changed
variables; read policy-level changes too. This is structural comparison,
**not** a decision-equivalence theorem.

Merge's existing `union`, `intersection`, and `deny-wins` remain fingerprint-based
editing strategies, **not** Boolean composition of policy decisions. Overlap,
first-match order, defaults, variable collisions, audit modes, and temporal
windows still need review/replay. Compiler validation does not make composition
safe; this change does not expand the merge operators.

`TestRecordLearnCompileReplay` runs real event-store recording, learning,
validation, Rust/WASM compilation and replay (including IPv6, Unicode,
bind/listen, argv, operations and flags). Cargo/wasm32 absence normally skips it;
policy CI sets `WARMOR_REQUIRE_CARGO=1` to make missing tooling a failure.
