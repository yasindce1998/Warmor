# Kernel default-deny

Design for closing the biggest enforcement gap in Warmor's BPF-LSM path:
today the kernel only blocks operations whose deny decision was **already
synced** into the kernel policy map, and a policy-map **miss means allow**.

## The gap

Enforcement on a BPF-LSM node works like this:

1. An exec happens. The `lsm/bprm_check_security` hook looks the
   `{cgroup, full literal path bytes, exec}` key up in the policy map.
2. **Hit + DENY** → `-EPERM`. The operation never runs.
3. **Miss** → the event is emitted to userspace, the operation is
   **allowed through**, and the WASM evaluation result is synced into the
   map (via the tracepoint path) so *the next* execution of the same path
   is blocked in-kernel.

So the first execution of a disallowed binary always reaches userspace;
only repeats get kernel EPERM. Userspace enforcement (SIGKILL after the
tracepoint fires) is after the fact — the process already ran, however
briefly. For an allowlist-style security posture this is backwards: the
kernel should refuse what the policy does not allow, not allow what it
has not yet seen.

## Why "miss = deny" cannot just be flipped globally

1. **The map is populated lazily** from observed events. Flipping the
   default denies every path and endpoint nobody has executed yet — the
   node bricks.
2. **Not every decision is kernel-syncable.** Policies that read fields
   beyond the kernel key (uid, comm, args, …), glob rules, file events
   (the hook only sees the dentry basename) and temporal rules can never
   be complete in the map. Their misses must stay allows.
3. **A policy with `default_action: allow` wants miss = allow.** Flipping
   the kernel default would invert its semantics.

## Design: domain-scoped default-deny

The kernel denies a miss only for *domains* userspace has proven to be
complete allowlists. A domain is an `(event_type, cgroup)` pair — v1
marks the global domain (`cgroup_id = 0`) for **exec** and **connect**,
the two hooks whose kernel keys (exec path; remote addr+port) YAML rules
can target exactly.

### Kernel side

New shared map, consulted only on a policy-map miss:

```c
struct default_deny_key { __u64 cgroup_id; __u8 event_type; __u8 pad[7]; };
// value: __u8 audit — presence marks the domain; audit=1 means
// would-deny only (the operation is allowed through and userspace
// records the decision)
BPF_MAP_TYPE_HASH (NOT LRU — the marking must never be evicted)
```

Lookup mirrors the policy map: cgroup-specific key first, then the
global (`cgroup_id = 0`) key. Hook behaviour on a miss in a marked
domain:

- **enforce, not audit**: emit the event with `decision=1` (best effort
  — a full ring does not soften a known verdict) and return `-EPERM`.
  Fail closed: unlike an unknown miss, the verdict is known, so ring
  pressure cannot turn it into an allow.
- **audit (or enforcement disabled)**: emit as a normal miss
  (`decision=0`) and return `0`. Userspace re-evaluates through WASM —
  which, for an eligible policy, denies — and the audit path records the
  would-deny. This makes `--audit` a faithful rehearsal of
  default-deny.

In the exec hook, a filename that fills the read buffer (possibly
truncated) never consults the policy map today; under a marked domain it
falls into the miss path and is denied. That is deliberate: an
allowlisted path is never truncated (policy-derived exact rules are capped at 127
bytes), so a truncated name is not provably allowed.

Connects to unsupported families (AF_UNIX and others) return before the
map lookup and stay allowed; the connect domain covers AF_INET/AF_INET6
endpoints only.

### Userspace: proving a domain complete

The compiler analyses the policy at compile time. A domain is eligible
iff **every** rule for that event type is *exactly enumerable* and the
policy defaults to deny:

- `default_action: deny` — the policy is an allowlist; a WASM miss is a
  deny too, so kernel and userspace agree on misses.
- Every rule for the event type consists solely of `eq` conditions on
  the kernel key fields — for exec: `path`; for connect:
  `remote_addr` + `remote_port` (both required). No `glob`,
  `starts_with`, `contains`, `not`, `any_of`/`none_of`, no other fields,
  no temporal block, no `conditions.any`/`not` lists. (Deny rules that
  are globs would be *safe* — miss is already deny — but allowing them
  invites subtle rule-ordering mistakes, so v1 requires exactness of
  every rule in the domain.)
- The rule's pattern fits the complete-input contract (≤ 127 UTF-8 bytes
  for exec, no NUL bytes; canonical sensor-rendered IP for connect). This
  also respects the binary WASM ABI's 128-byte primary string: kernel
  preloads must not recognize a path the evaluator only sees as a prefix.
  Expanded, uppercase or IPv4-mapped IPv6 spellings that differ from
  `net.IP.String()` make the network domain ineligible rather than silently
  becoming a different string-equality rule.

For an eligible domain the compiler emits every rule (allow **and**
deny, preserving first-match order — duplicate keys keep the first rule,
matching the WASM's first-match semantics) into a static table the
compiled module exports:

```rust
warmor_static_rules(event_type: u32, buf: *mut u8, cap: u32) -> u32
```

The table is `[eligible u8]` followed by entries
`[action u8][audit u8][port u16][len u16][pattern bytes]` (port is 0 for
exec; host byte order for connect, as `SetEndpointRule` takes it). The
host calls it once with `cap=0` for the size, `malloc`s, reads, `free`s
— the same memory ABI `evaluate_event` uses. Hand-written Rust policies
can export the same function to opt in; a module without the export is
never marked.

`log` rules map to allow+audit; `mode: audit` deny rules map to
deny+audit — the same value encoding the policy map already uses.

### Preload order (crash- and reload-safe)

The marking is what flips miss→deny, so it goes in **last**:

1. `ClearDefaultDeny()` — unmark first, so misses allow while rebuilding
2. `Clear()` the policy map
3. `Put` every static entry (global cgroup)
4. mark the eligible domains

Between steps the worst state is today's behaviour (miss = allow); the
map is never "marked but empty" outside the preload window, and the
`default_deny` map is a plain HASH so the marking itself cannot be LRU
evicted. Entries in the LRU policy map *can* be evicted under pressure —
an evicted allow turns into a deny (fail closed, disruptive, visible in
the deny logs). Operators running default-deny should size the policy
map accordingly (`POLICY_MAP_MAX_ENTRIES`, 65536 by default).

### Wiring

- Daemon flag `--default-deny` (opt-in). Requires LSM enforcement to be
  active (`--lsm-enforce`); without BPF-LSM the flag logs that there is
  nothing to mark and the daemon runs as before. Learning mode never
  marks.
- Applied at startup and after every policy reload, from the *new*
  policy's static table.
- Metrics: `warmor_default_deny_active{event_type}` gauge (1 when
  marked) and the existing `warmor_ebpf_map_entries{map_name="policy_map"}`
  for preload size. A requested-but-ineligible domain logs why (e.g.
  "rule 'block-tmp' uses glob") and sets the gauge to 0.
- Helm: `daemon.defaultDeny` passes the flag.

## Out of scope (v1)

- Per-cgroup (per-container) domains — the key shape supports it; the
  policy model does not have per-container policies yet.
- bind/listen/ptrace/mount domains (their YAML event model maps to
  network/file keys the hooks do not cover).
- Deny-rule globs inside an eligible domain (see strictness note above).
- Failing daemon startup when the policy is ineligible (it logs and
  runs without kernel default-deny; userspace enforcement is unchanged).

## Exact identity contract and limitations

The Linux `policy_map` key is a 288-byte structured identity, not a 32-bit
FNV digest: cgroup ID, hook/event type, family, network-order port bytes,
16 address bytes, 256 literal path bytes, and zero padding. BPF compares
the entire key, so hash-table implementation collisions do not share
decisions. Cgroup-specific entries still precede global entries;
default-deny is a separate cgroup/event-type lookup on a miss.
Old 16-byte map layouts cannot be reused. Deploy BPF objects and userspace
together; external raw-map tooling must migrate its key ABI. The key alone
occupies 18 MiB at 65536 entries, before values and hash/LRU overhead;
recheck node memory budgets and performance before rollout.

- **Exec is literal pathname policy, not file identity policy.** The key
  is `bprm->filename`, without path cleaning, symlink/inode resolution or
  mount-namespace canonicalization. Relative paths, symlink spellings,
  rename/replacement, interpreter execution and the same pathname in
  different mount namespaces are not proven to name the same file.
  Decisions apply to the literal string within a cgroup (or globally for
  static rules); they do not attest file content. Integrity verification
  is separate. No new mount-namespace/workload isolation is implied.
- **Dynamic decisions require complete shared inputs.** Paths longer
  than 127 bytes, empty/NUL/invalid-UTF-8 paths, unknown cgroups, basename
  file events and non-connect network events are not synced. Low-level
  `SetRule` can explicitly key complete exec strings up to 254 bytes,
  but policy-derived static/dynamic entries use the shared stricter bound.
  Failed or full-buffer kernel path reads never hit allow entries;
  marked enforce domains deny them as misses. Sensors and legacy binary
  WASM still have bounded fields and **do not expose complete/truncated/
  unknown markers to policy code**. Skipping persistence does not make
  userspace's long-input evaluation complete; end-to-end input-schema
  migration remains necessary. Ineligible domains retain allow-on-miss.
- **Endpoints are address+port policy identities**, not socket or
  transport identities. Family and all address bytes are keyed; mapped
  IPv6 normalizes to IPv4 to match sensor `net.IP.String()` output.
  IPv6 zone/flow labels, protocol, image and other metadata are not key
  fields. Dynamic decisions depending on other fields cannot persist.
  Default-deny connect covers IPv4/IPv6 only, not Unix sockets.
- Mount and ptrace low-level keys hold the whole filesystem-type/task-comm
  field, not a target file/process lifetime. File-open never consults the
  map because it only sees a basename. `unix_watch` retains FNV solely to
  select **observation** events; it cannot install security decisions.
- `SetNetworkRule(hash, ...)` remains source-compatible but always returns
  `ErrNotKernelMatchable`; supply the canonical endpoint to
  `SetEndpointRule`. Legacy hash helpers are not identity constructors.

Unprivileged tests cover deliberate FNV32 path/endpoint collisions, scope,
embedded-object ABI layout, lengths and first-match exports. VM integration
tests assert successful allowed operations and **kernel EPERM** for
colliding denies, unknown default-deny keys and truncated paths. Run them
only in an isolated BPF-LSM VM. Compilation/unit success does not establish
kernel verifier acceptance or runtime enforcement on supported kernels.
