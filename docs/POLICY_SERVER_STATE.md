# Durable policy-server state

Production `warmor-server` startup requires authenticated TLS and `--state-file`:

```sh
install -d -m 0700 /var/lib/warmor-server
WARMOR_JWT_SECRET="your-secret" warmor-server \
  --tls-cert server.crt --tls-key server.key \
  --state-file /var/lib/warmor-server/state.json \
  --policy-dir /srv/warmor-policies --verify-key policy-signing.pub
```

Prefer supplying the secret through the environment instead of process arguments.
`--ca-cert` additionally enables mTLS. `--insecure` is the explicit development
exception for plaintext or ephemeral state; configured authentication still
applies in that mode.

## Guarantees and boundaries

- A versioned checksummed snapshot contains immutable revision bytes/signatures,
  targeting and active versions, agent registrations/labels and heartbeats,
  rollouts, container bindings/owners, and bounded management history. Uploaded
  source files are not needed afterward. Opening with `--verify-key` re-verifies
  every retained revision.
- Every successful mutation writes a temporary file (mode 0600 on POSIX), syncs
  it, replaces the snapshot atomically, and syncs the directory. Windows uses write-through
  replacement. Promotion/abort and rollout state changes share one transaction.
  Failures before replacement restore in-memory state. A post-replacement sync
  failure has an indeterminate crash outcome: the request fails and subsequent
  mutations are refused until restart.
- A process lock (`state.json.lock`) rejects simultaneous writers. Keep the
  parent directory private on a local filesystem with reliable rename, sync, and
  advisory-lock semantics. Never unlink/replace the lock file while a server is
  running. This backend is not replicated/high-availability storage.
  On Windows, files inherit the parent directory's DACL; configure it to grant
  access only to the service identity, SYSTEM and administrators. POSIX mode bits
  are not a substitute for Windows ACLs. Native tests verify private DACL
  inheritance through snapshot replacement rather than interpreting mode bits.
- Corrupt/unsupported state fails startup, without resetting state. Checksums
  detect accidental corruption, not administrator modification or backup replay.
  Assignment authentication and anti-replay are separate protocol concerns (see
  [explicit opt-in signed deployment mode](SIGNED_POLICY_ASSIGNMENTS.md)). Drift
  data and canary counters are not retained; this does not enable auto-rollback.
- Runtime owners derive from the authenticated JWT subject or verified
  certificate identity, never JSON. Other runtimes cannot replace/delete an
  existing binding. Admins can manage any binding; updating preserves its owner.
  Container IDs are global within the store. Runtime identities must be stable.
- Priority ties resolve by ascending policy ID. Active rollouts block direct
  activation, active uploads, and policy deletion; staging remains allowed.

## Resource limits

Defaults: 256 MiB snapshot, 128 MiB retained WASM, 16 MiB/module, 1,024 policies,
128 revisions/policy, 10,000 agents, 4,096 rollouts, 10,000 bindings, and the latest
10,000 management audit entries. Labels allow 64 pairs (256-byte keys, 4,096-byte
values). A conservative metadata-encoding bound may reject state before the
snapshot reaches its exact byte limit. Runtime bind bodies are limited to 64 KiB.
Agent-reported active policy IDs, digests and activation errors are bounded to
256, 64 and 4,096 bytes respectively and included in snapshot-size accounting.
Retention limits reject mutations; they never silently evict revisions. Durable
heartbeats do not consume management-history entries.

`--state-max-bytes`, `--state-max-wasm-bytes`, and `--state-max-agents` adjust the
main deployment bounds; embedded users can configure every `StoreLimits` field.
This simple backend serializes the complete snapshot on each mutation, including
heartbeats. Benchmark your fleet/heartbeat rate; large fleets should use a future
database/journal backend.

## Backup and restore

Stop the server and copy `state.json` to protected backup storage. Atomic
replacement also allows a consistent read from a running server, but may omit
mutations committed after the file was opened. Do not copy temporary/lock files
as state. To restore, stop all writers, copy the backup to the state path with
mode 0600 on POSIX (a private DACL on Windows), and restart. Restore deliberately
restores that backup's active versions and rollout cohorts; it is not monotonic anti-replay. Corrupt state is
never automatically replaced by backup or empty state.

## Embedded API compatibility

`NewStore()` and `NewServer` without `ServerConfig.Store` remain ephemeral.
Inject `OpenStore(path, StoreOptions{VerifyKey: pub})` through `ServerConfig.Store`
and close it **after** server shutdown. Supply the key on open, not only later,
to validate restored modules. `RegisterAgentChecked` and `MarkStaleAgentsChecked`
report durability/limit errors; legacy `RegisterAgent` returns nil on failure,
and legacy `MarkStaleAgents` cannot report errors. Network handlers should use the
checked variants. Binary, signature, selector, label, and rollout getters now
return defensive copies.
