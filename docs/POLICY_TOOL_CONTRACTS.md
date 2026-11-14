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

**Sensitive data:** argv can contain passwords/tokens. Private file recordings
and the simulator event store retain argv for replay. Stdout and JSON webhook
exports omit the complete `policy_input` by default and mark it redacted;
programmatic callers must explicitly set `StdoutSink.IncludePolicyInput` or
`WebhookConfig.IncludePolicyInput` to export it. The daemon does not opt in.
Custom sinks receive the full event and must implement their own export controls.
SIEM summaries may themselves contain sensitive paths/reasons: these defaults
are not a general-purpose secret detector or comprehensive redactor.

On supported Unix platforms, file recordings are created as **0600** regardless
of a permissive umask. Existing owned, singly-linked regular files (including
recognized numeric rotation archives) are tightened before recording continues.
The event store creates directories **0700** and tightens an existing owned store
directory on initial open and daily reopen. Older daily recordings are checked
at startup and owned daily files are also tightened to 0600. Higher-level
directories are not chmodded; newly created ancestors are 0700. FileSink requires an existing
trusted parent directory; it never chmods a shared `/var/log` directory.
Untrusted/writable parent directories, symlink components/files, hard-linked
files, nonregular files, and files owned by another user are rejected. Reopening
and rotation use the same descriptor-relative no-follow checks; a failed reopen
does not continue writing via the old encoder. A platform without these private
file guarantees fails closed.
Operators using symlinked log paths must configure the physical directory path.
On macOS this includes system aliases such as `/var` and `/tmp`: use the
corresponding physical `/private/var` or `/private/tmp` recording path. Recording
does not call `EvalSymlinks` on user-supplied paths. Tests resolve only their
newly allocated temporary fixture root before constructing recording paths, so
native macOS temporary-directory aliases work without accepting symlinks planted
inside the fixture or weakening the production no-follow checks.
For concrete macOS commands and upgrading existing `/var/...` configurations,
see [private recording paths and migration](PLATFORM_MACOS.md#private-recording-paths-and-migration).
Rejected parent components report a physical-path configuration hint rather than
only the operating system's `not a directory`/symlink error; no path is followed
or retried with weaker checks as part of reporting that error.

On Windows, recordings support **fixed local NTFS volumes** with persistent ACLs.
New files/directories are created atomically with a protected DACL granting full
access only to the current token user SID. Existing recordings and private store
directories must already be owned by that user; their DACLs are replaced by handle
before appending. A foreign owner is never taken over, even when running elevated.
All path components are opened relative to validated directory handles, with
reparse points (including junctions), hard-linked/nonregular files, alternate data
streams, device/UNC paths, and unsafe Win32 aliases rejected. Ancestors must be
owned by the current user or trusted Windows system principals and must not grant
foreign principals replacement/deletion or ACL-changing rights. System-owned
parents may remain unchanged; files and private store leaves require the current
token user's ownership. Shared ancestors may grant child creation but the
recording's parent must not. Only a private store
leaf is tightened; higher-level directory ACLs are not changed. Rotation checks
the open file identity and uses a directory-relative handle rename that atomically
refuses an existing archive. Unsupported filesystems, security APIs, ACL forms or
untrusted layouts fail closed; choose a physical, owned local NTFS recording path.
Privileged administrator/backup access, like Unix root, is outside this boundary.
Native Windows CI runs owner/DACL, reparse/unsafe-path, file-sink rotation and
event-store replay tests; cross-compiling those tests is not runtime validation.

Tightening cannot revoke access via descriptors already opened by other users or
undo previous disclosure: treat credentials captured by older permissive logs as
potentially compromised and rotate them. Protect event access and retention.
Redactors **must** remove
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

Recorded `enforced`, `enforcement_attempted`, `enforcement_error`, `audit_only`,
and `kernel_enforced` describe the **historical action outcome**, independently
of `decision`. They survive private file/store recording unchanged. Replay
compares policy decisions only: a refused/failed termination or audit denial is
still a recorded deny, not evidence that the operation was actually prevented.
Replay never sends signals or changes the recorded outcome. Candidate decisions
do not predict whether a live termination would succeed.

Delivery uses independent bounded sink queues (see
[streaming reliability](streaming-reliability.md)). Workers share immutable events;
stdout/webhook redaction copies the summary rather than removing inputs from the
private recording worker's event. Webhook retries retain that already-redacted
copy, including the original action outcome and redaction marker. Retry failures
and counted delivery losses do not alter historical enforcement outcomes. Queue
drain/close preserves the same descriptor checks and 0600 recording permissions;
queue/retry/shutdown loss accounting remains best effort, not a durable audit-log
guarantee.

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
