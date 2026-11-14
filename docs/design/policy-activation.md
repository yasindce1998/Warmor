# Policy revision activation and recovery

Fleet identity is `(policy_id, version, wasm_hash)`, where `wasm_hash` is the
SHA-256 of the downloaded module. Moving between policies at the same version
is an update. The client checks the digest before the optional signature hook
and acknowledges only after `OnUpdate` returns success. That callback now returns
an error and must wait for actual activation and durable publication. A missing
callback cannot acknowledge a download. Heartbeats carry active ID/version/hash
and the latest poll/activation error, separately from desired assignment.

Conditional assignment requests include `if_policy_id`, `if_version`, and
`if_hash`. New servers return 304 only for the full identity and advertise
`X-Warmor-Revision-Identity: 1`. Legacy version-only clients get assignments
instead of an ambiguous 304, but must still upgrade their client-side comparison.
New clients retry legacy-server 304 responses with an unconditional request.

Registration uses `RegisterAgentChecked`, and revision heartbeats use the same
`mutateLocked` transaction boundary as fleet management changes. Neither path
discards persistence errors or falls back to an unchecked API. The default test
suite verifies acknowledgement restart recovery and persistence-failure rollback,
including registration errors. `NewStore` and `NewServer` without an injected
store remain ephemeral; production startup requires the persistent-store wiring
described in [POLICY_SERVER_STATE.md](../POLICY_SERVER_STATE.md).

## Server-managed disk layout

The daemon owns a writable compiled-WASM policy path in fleet mode. A `.yaml` or
`.yml` path is rejected before staging: restart would otherwise try to compile
downloaded WASM bytes as YAML. Do not simultaneously mount a read-only ConfigMap
there or use another writer. Downloads are staged in
`<policy>.revisions/revision-*/` with `module.wasm`, optional `module.wasm.sig`,
and assignment `metadata.json`. Files and directories are synced before
publication. `<policy>` and `<policy>.sig` become aliases through one `current`
revision pointer, switched by atomic rename. Enforcer signature readers resolve
the module pointer **once**, then read that immutable revision's sibling
signature. Independently opening the two public aliases is not a consistent
snapshot API while switching revisions.
For any symlinked policy path, the signature must live next to the resolved
module; an unrelated `<alias>.sig` alongside a module-only symlink is not used.

An existing legacy pair is first copied without changing its bytes, then
migrated to this layout. A fresh runtime/pool loads the staged candidate before
the restart pointer changes. Download, signature, staging-write, runtime-load,
kernel-preparation, and durable-publication failures are not acknowledged. The
previous userspace generation remains and subsequent polls retry. Unpublished
failed candidates are removed; interrupted staging is never selected on restart.
A crash after durable publication but before the evaluator swap restarts from
the already validated candidate, without having sent a success acknowledgement.
A failed durability barrier attempts pointer rollback and reports errors.

`<policy>.revisions/previous/module.wasm` retains the previous published pair.
For offline recovery, stop the daemon, inspect and validate that path with the
same verification key, atomically repoint `current` to the revision named by
`previous`, then restart. Preserve ownership/permissions and back up the revision
directory. Successfully published and crash-orphaned revisions are retained;
automatic bounded garbage collection is not implemented. Symlink and directory
fsync support are required. Unsupported filesystems/platforms fail activation
explicitly rather than falling back to two unrelated file replacements.

Fleet mode does not run a competing file watcher. A successful explicit SIGHUP
reload invalidates the client's remembered identity so the next poll reconciles
the fleet revision. Standalone watching hashes module/signature content instead
of increasing mtime and retries unchanged files after reload failure. External
standalone writers should still publish immutable pairs or use atomic directory
switching: this cannot make arbitrary concurrent two-file writes transactional.

## Evaluator lifetime and kernel limits

Reload and close are serialized. An event holds a shared drain barrier through
cache lookup, WASM evaluation, persistence, action and reporting. Activation
takes the exclusive barrier before kernel preparation/publication, swaps the
evaluator, resets cache dependencies, and only then admits new events. Old pools
and runtimes close after their events finish. Neither old cache-hit actions nor
old evaluated actions can cross a successful userspace activation; old events
cannot repopulate the new cache/map. Slow synchronous actions/sinks can delay
draining; this is not a new bounded-shutdown guarantee.
The process action keeps the original event identity and actual attempted,
succeeded, or refused outcome from the pidfd safety path; activation does not
reinterpret a deny decision as successful termination. Asynchronous sink delivery
may finish later; the barrier covers outcome creation and pipeline submission.

The kernel map is **not double-buffered or generation-addressed**. Default-deny
domains are unmarked before clearing/rebuilding, so kernel misses can allow
during this window even though userspace events are drained. Clear, preload and
mark failures return errors instead of reporting successful activation. Failure
attempts to rebuild previous static domains; dynamic kernel cache entries cannot
be restored transactionally. Rollback failure is explicitly reported as degraded
kernel enforcement. A usable previous disk/runtime revision is not a claim of
continuous protection or complete kernel restoration. Already queued kernel
events also lack a generation tag.

Generation-addressed kernel maps, require-default-deny semantics, readiness
integration, signed assignment/anti-replay metadata, compiler/ABI/effective-posture
identity, and privileged failure/soak verification remain follow-up work. No
protection is promised while the daemon is unavailable or during an unvalidated
host restart.
