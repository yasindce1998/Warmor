# Warmor Performance

**Measured:** 2026-10-15, on one laptop (details below). Raw output of the runs
these tables come from is in [`docs/perf/2026-10-15/`](perf/2026-10-15/).

This page replaces the performance targets that earlier documents listed
without measurements. Where a target is still mentioned, it sits next to the
measurement and is labelled as a target.

## Summary

| Metric | Target (design, not a result) | Measured | Verdict |
|--------|-------------------------------|----------|---------|
| Userspace decision, cache hit | <100 µs P95 | P50 1.2–2.1 µs, P95 1.5–2.4 µs | Met |
| Userspace decision, cache miss (WASM evaluation) | <100 µs P95 | P95 79 µs (YAML policy), 90 µs (fixture), 148 µs (Rust `advanced` crate) | Met for YAML, **not** for the Rust crate |
| Decision cache hit rate, synthetic host workload | >90% | 95.4% with a compiled YAML policy; **0%** with any policy that does not declare the fields it reads | Met only for declared policies |
| Throughput (real event loop, one goroutine) | 100k events/s | 170k events/s (YAML policy); 26k (fixture) and 13k (Rust crate) | Met only for declared policies |
| Kernel fast path (BPF program on a policy_map hit) | <1 µs | 0.35 µs (connect), 0.78 µs (exec), kernel-measured program time | Met for the program itself, in a VM |
| Kernel cost when an event is sent to userspace | (none set) | about +24 µs per emitted event (connect, open; exec emits two) in this nested VM, almost all of it waking the ring-buffer reader | Not a fast path; every `open()` takes it |
| Memory (RSS) | <50 MB | 57 MB at 1k events/s up to 103 MB at maximum rate (YAML policy); 107–127 MB with undeclared policies | **Not met** |
| CPU | <5% | 11% of one core (0.8% of the 14-thread host) at 10k events/s with the YAML policy; 120% of one core with an undeclared policy | Depends on the policy; see table |

The single most important factor is whether the policy **declares the fields
it reads** (`warmor_fields_read`, which `warmor-compile` emits for every YAML
policy). Without it, every cache key contains the PID, so on a host where
processes are short-lived nearly every event is a WASM evaluation.

## Environment

| | |
|---|---|
| Machine | Laptop, Intel Core Ultra 5 135U (hybrid: P, E and LP-E cores), 14 logical CPUs, 7.5 GiB RAM visible |
| OS | Windows 11 + WSL2, kernel `6.18.33.2-microsoft-standard-WSL2` |
| Go | go1.26.6 linux/amd64, GOMAXPROCS=14, default GOGC |
| Commit | `25350a4` (userspace runs), kernel benchmarks from the same tree |
| Background load | **The machine was not idle.** 1-minute load average 5.9 before and 13.1 after the userspace run (other work, including a headless browser using ~9 cores at times). See caveats. |
| Kernel VM | vimto v0.4.0 + QEMU 8.2.2 + KVM, nested inside WSL2. Guest kernel 7.2.2 (`ghcr.io/cilium/ci-kernels:stable-selftests`), 2 vCPUs, `lsm=capability,selinux,bpf`, kvm-clock |

## How to reproduce

```sh
# Policies for the YAML and Rust-crate cases (both are skipped with a
# message if missing)
scripts/build-rust-policies.sh          # needs cargo + wasm32-unknown-unknown

make bench                              # userspace, ~20 min, writes bench-results/
make bench-kernel                       # kernel benchmarks in a vimto VM
make bench-kernel KERNEL=/abs/path/to/vmlinuz   # local kernel: ABSOLUTE path

scripts/bench-summary.py bench-results/*.txt    # medians over the repetitions
```

Single pieces:

```sh
go test -run '^$' -bench 'DecisionLatency' -benchtime 200000x -count 5 ./internal/enforcer/
go test -run '^$' -bench 'DecisionThroughputParallel' -benchtime 200000x -count 5 ./internal/enforcer/
go test -run '^$' -bench 'WorkloadStream' -benchtime 200000x -count 5 -v ./internal/enforcer/
WARMOR_BENCH_LOAD_SECONDS=10 go test -run '^$' \
    -bench '^BenchmarkSustainedLoad$/^yaml$/^rate=10000$' -benchtime 1x ./internal/enforcer/
go test -run '^$' -bench 'RecordExec' -benchtime 200000x ./internal/lineage/
vimto -kernel ghcr.io/cilium/ci-kernels:stable-selftests -- \
    go test -tags integration -run '^$' -bench Kernel -benchtime 3000x -count 10 ./internal/ebpf/
```

None of these run during a plain `go test ./...` (they are benchmarks; the
kernel ones also need the `integration` tag and root). CI runs `QUICK=1
scripts/bench.sh` only to catch benchmarks that crash; it does not check the
numbers.

## Methodology

### What is under test

All userspace benchmarks drive the real `Enforcer.handleEvent` (the function
the daemon's event loop calls for every event) on an `Enforcer` assembled the
same way `enforcer.New` assembles it, minus the kernel:

- real WASM runtime (wazero), policy instance pool and `PolicyEvaluator`;
- real decision cache: 10,000-entry LRU, 5-minute TTL, PID rule derived from
  the policy's fields-read declaration (`SetPIDRelevant`), exactly as `New`
  configures it;
- real lineage tracker, sandbox manager (default profiles), Prometheus metric
  updates;
- the logger at the daemon's default level (`info`), writing to `io.Discard`
  (so log formatting is included, terminal/file I/O is not);
- audit mode, so a deny never signals a real process with a synthetic PID
  (the decision path is otherwise identical);
- no kernel policy map, network filter or streaming sink (the daemon's
  defaults without `--lsm-enforce` or sinks).

Policies:

| Name | What | Fields-read declaration |
|------|------|-------------------------|
| `fixture` | `internal/wasm/testdata/allow_policy.wasm`, the test fixture | none (every key includes the PID) |
| `yaml` | `policies/yaml-example/policy.yaml`, compiled by the real compiler (cargo) | process: path, uid; file: path, uid, operation; network: uid, remote_port. No PID, so keys are PID-free |
| `rust-advanced` | `policies/advanced` crate built by `scripts/build-rust-policies.sh` | none |

### Latency

Each event is timed individually with `time.Now`/`time.Since` around
`handleEvent`, and the mean and nearest-rank P50/P95/P99/P99.9 of those
per-event durations are reported (Go's `ns/op` is a mean only). The timer pair
itself costs 53 ns at P50 (`BenchmarkTimerOverhead`) and is included in every
percentile.

- **hit**: the same exec event repeated (cache hit after the first).
- **miss**: execs of 32,768 distinct binaries by distinct PIDs, cycled. That is
  more than the cache holds, so with LRU every event misses (the benchmark
  reports a 0.0% hit rate to prove it) and the cost includes an LRU eviction.

### Throughput

Single goroutine: events per second over the latency loop. Parallel:
`b.RunParallel` with GOMAXPROCS goroutines and a pool of GOMAXPROCS WASM
instances. **The daemon does not do this today**: its event loop calls
`handleEvent` from one goroutine, so the parallel number is the capacity of
the evaluation path, not of the daemon as wired.

### Cache hit rate

A deterministic synthetic stream shaped like a busy host: short-lived
processes, each a new PID, exec one of 16 common binaries (Zipf-weighted),
open the dynamic loader's two files plus two binary-specific files, one in four
opens a uniquely named temp file, and one in five connects to one of four
service endpoints. 10,000 warm-up events, then 200,000 measured events (36,684
process, 155,964 file, 7,352 network). The hit rate is read from the real
cache's counters.

### Sustained load (memory and CPU)

`BenchmarkSustainedLoad` runs the daemon's real event loop goroutine
(`Enforcer.eventLoop`) fed through the same 1024-slot channel the platform
writes to. A generator produces the workload stream at a fixed rate (batches
every 5 ms) or unthrottled (`rate=0`). The lineage tracker starts full
(100,000 entries), which is the state of any daemon that has seen 100k
execs, since nothing removes entries on exit. After a 3 s warm-up it measures
for 10 s: process CPU time (`getrusage`, user+system) over wall time, RSS
(`/proc/self/status` VmRSS) sampled every 250 ms, and Go runtime memory
(`runtime/metrics`). Each configuration runs 3 times, each in its own process.

The generator runs in the same process. The `none` rows replace the enforcer
with a goroutine that discards events and measure the generator alone (about
19 MB RSS and 3–9% of one core at up to 50k events/s); subtract them to get
the enforcer's share.

### Kernel

`internal/ebpf/perf_integration_test.go`, run in the VM as root. For each
operation it measures, in one process and interleaved over 10 runs:

- `none`: no warmor programs attached;
- `lsm-hit`: all 7 LSM programs attached and the operation's policy_map entry
  is a global ALLOW;
- `lsm-miss`: no entry, so the program emits a ring-buffer event, drained by a
  reader goroutine like the daemon's. After each operation the benchmark waits
  (untimed) until the ring is empty, so every operation starts with an idle,
  caught-up reader;
- `lsm-miss-nowait`: the same without waiting, back to back;
- `progstats-hit/miss`: `lsm-hit`/`lsm-miss` with `BPF_STATS_RUN_TIME`
  enabled, reporting the kernel's own average run time of the operation's
  program (`prog-ns`). Stats collection adds a little to each run, so the
  syscall-level rows are measured without it;
- `lsm-miss+tp`: `lsm-miss` plus the three tracepoint monitors the daemon also
  loads (execve, openat, connect), all drained.

Each operation is timed individually; the tables use the median over the 10
runs of each run's P50 (`op-p50-ns`), which is much more stable in a VM than
the mean. Operations:

- **connect**: `connect()` of a UDP socket to `127.0.0.1:9` (no packet is
  sent, so the syscall is cheap and the hook's share is visible);
- **execve (ENOEXEC)**: `execve()` of a non-ELF file on tmpfs. The kernel
  opens it, sets up the bprm, runs `bprm_check_security` (and `file_open` on
  the binary) and fails with ENOEXEC: no fork, no child, no scheduler noise;
- **fork+exec**: fork, exec and wait for a 129-byte static ELF that only calls
  `exit(0)`, on tmpfs;
- **open**: `open()`+`close()` of a file on tmpfs.

## Results

All values are medians over the repetitions (5 for latency and hit rate, 3
for sustained load, 10 for kernel); ranges are in the raw files.

### Userspace decision latency (one goroutine)

| Policy | Case | Mean | P50 | P95 | P99 | P99.9 | Allocations |
|--------|------|------|-----|-----|-----|-------|-------------|
| fixture | hit | 2.5 µs | 2.1 µs | 2.4 µs | 6.9 µs | 42 µs | 160 B, 2 |
| fixture | miss | 56 µs | 40 µs | 90 µs | 232 µs | 3.2 ms | 37.8 KB, 58 |
| yaml | hit | 2.4 µs | 2.0 µs | 2.4 µs | 6.5 µs | 41 µs | 160 B, 2 |
| yaml | miss | 47 µs | 29 µs | 79 µs | 234 µs | 3.7 ms | 48.8 KB, 40 |
| rust-advanced | hit | 1.6 µs | 1.2 µs | 1.5 µs | 4.4 µs | 38 µs | 160 B, 2 |
| rust-advanced | miss | 99 µs | 76 µs | 148 µs | 453 µs | 4.3 ms | 37.8 KB, 58 |

The three hit rows execute identical code (no WASM call), so their spread
(1.2–2.1 µs at P50) is measurement noise on this loaded hybrid-core machine.
On a miss, most of the cost is outside the policy itself: a CPU profile of
`fixture/miss` shows about 38% of CPU time in the garbage collector, driven by
~38 KB of allocations per evaluation. An allocation profile attributes 89% of
those bytes to wazero creating a new call engine (with a fresh stack) on
every evaluation, because `evaluateJSON` (`internal/wasm/policy.go`) looks up
the exported functions with `ExportedFunction` per call. Looking them up once
per pooled instance looks like the largest available improvement; it is not
done here.

For comparison, an earlier single run (2,000–20,000 events) on the same
machine while it was less loaded measured P50 0.7 µs (hit) and 12 µs (miss)
for fixture and yaml: the numbers above are roughly 2× worse than a quiet
machine would give. They are kept because they come from the complete,
recorded run.

### Throughput

| Policy | Hit, 1 goroutine | Miss, 1 goroutine | Hit, 14 goroutines | Miss, 14 goroutines |
|--------|------------------|-------------------|--------------------|---------------------|
| fixture | 379k/s | 17.7k/s | 541k/s | 37k/s |
| yaml | 406k/s | 21.3k/s | 833k/s | 64k/s |
| rust-advanced | 612k/s | 10.1k/s | 914k/s | 50k/s |

Parallel hits scale poorly (1.4–2× on 14 threads): every event takes the
decision cache's single mutex, and every exec event the lineage tracker's.

### Cache hit rate (200,000-event synthetic stream)

| Policy | Overall | Process | File | Network | Per-event P50 / P95 / P99 |
|--------|---------|---------|------|---------|---------------------------|
| yaml (declared, PID-free keys) | **95.4%** | 100.0% | 94.1% | 99.4% | 2.1 / 18 / 68 µs |
| fixture (undeclared) | **0.0%** | 0.0% | 0.0% | 0.0% | 21 / 54 / 118 µs |
| rust-advanced (undeclared) | **0.0%** | 0.0% | 0.0% | 0.0% | 54 / 108 / 236 µs |

Why:

- The cache key (`internal/cache/cache.go`, `Key`) contains every field a
  policy can observe. The only field it may omit is the PID, and only for an
  event type whose policy has declared, through the exported
  `warmor_fields_read(event_type)` function, that it does not read the PID
  (`compiler.FieldBitPID`, `internal/compiler/fields.go`). `warmor-compile`
  emits that declaration for every YAML policy, listing exactly the fields its
  rules reference, so a YAML policy gets PID-free keys for every event type
  where no rule has a `pid` condition. A module without the export (the
  fixture, every Rust crate under `policies/` today) is treated as reading
  everything.
- With PID-free keys, the remaining misses in this stream are the first
  occurrence of each key and the unique temp-file names (one in four
  processes opens one; that is the 5.9% file miss rate).
- With PID in the key, each short-lived process starts with an empty set of
  keys and never repeats one, so nothing hits. This is not a property of the
  synthetic stream: any workload of short-lived processes behaves this way.
- Keys still include fields the policy does not read (uid, gid, comm, ...),
  so a declared policy could share entries more widely than it does; the key
  is only narrowed by the PID today.
- The stream runs in seconds, so the 5-minute TTL never expires an entry.
  Over real time, keys seen less than once per 5 minutes miss again.

### Sustained load: CPU and memory

The event loop is one goroutine; CPU above 100% of a core is the Go garbage
collector and runtime working in parallel. "Achieved" below the offered rate
means the loop could not keep up and the generator was blocked by the full
channel (in the daemon, the platform readers would block and the kernel ring
buffers would overflow).

| Policy | Offered rate | Achieved | CPU, % of one core | CPU, % of host (14 threads) | RSS median (max) | Go heap |
|--------|--------------|----------|--------------------|-----------------------------|------------------|---------|
| none (generator only) | 1k/s | 999/s | 3.2% | 0.2% | 18.6 MB (19.7) | 1.7 MB |
| none | 10k/s | 9,994/s | 4.8% | 0.3% | 20.0 MB (20.6) | 0.8 MB |
| none | 50k/s | 49,970/s | 8.7% | 0.6% | 20.2 MB (20.8) | 0.8 MB |
| yaml | 1k/s | 999/s | 6.6% | 0.5% | 57.2 MB (62.9) | 40.8 MB |
| yaml | 10k/s | 9,994/s | 15.9% | 1.1% | 81.0 MB (82.9) | 64.5 MB |
| yaml | 50k/s | 49,962/s | 54.6% | 3.9% | 98.0 MB (99.5) | 70.7 MB |
| yaml | unthrottled | **170k/s** | 202% | 14.4% | 103.1 MB (106.4) | 84.2 MB |
| fixture | 1k/s | 999/s | 17.1% | 1.2% | 106.8 MB (111.7) | 61.5 MB |
| fixture | 10k/s | 9,991/s | 124% | 8.9% | 120.4 MB (125.3) | 71.5 MB |
| fixture | 50k/s | 14,128/s | 210% | 15.0% | 126.9 MB (134.7) | 79.3 MB |
| fixture | unthrottled | **26k/s** | 277% | 19.8% | 121.8 MB (127.0) | 57.8 MB |
| rust-advanced | 1k/s | 999/s | 17.9% | 1.3% | 106.5 MB (111.9) | 78.2 MB |
| rust-advanced | 10k/s | 9,994/s | 122% | 8.7% | 119.5 MB (121.8) | 82.2 MB |
| rust-advanced | 50k/s | 13,887/s | 189% | 13.5% | 123.8 MB (128.6) | 70.3 MB |
| rust-advanced | unthrottled | **13k/s** | 182% | 13.0% | 122.5 MB (126.6) | 93.9 MB |

Net of the generator (subtract the `none` row): the YAML policy costs about
3% of one core at 1k events/s, 11% at 10k and 46% at 50k. With an undeclared
policy, 10k events/s already costs more than a full core.

On a less loaded run of the same configuration (3 s and 10 s, single runs) the
unthrottled YAML rate was 374k–412k events/s; 170k is the figure from the
recorded run.

Memory is above the 50 MB target in every configuration. Contributors: the
full lineage tracker (100,000 entries), one WASM instance per CPU (14), the
decision cache (10,000 entries), and the Go heap growing to about twice the
live heap between collections (default GOGC=100) under the allocation rate of
WASM evaluations. The harness itself accounts for about 19 MB (the `none`
rows: test binary plus generator); the daemon binary also loads eBPF objects
and serves HTTP, which this does not include.

### Lineage tracker (fixed while measuring)

`lineage.Tracker.RecordExec` evicted the oldest entry by scanning the whole
map once the tracker was full, and nothing ever removes entries, so every
exec of a new PID on a daemon that had seen 100,000 execs cost:

| | `BenchmarkRecordExec` (tracker full, new PID) |
|---|---|
| Before (`5c10c03`) | 3.76 ms per exec (single run, 2,000 iterations) |
| After (`c3d0a24`, FIFO list) | 0.49 µs on a quiet machine; 1.39 µs median of 5 in the recorded run |

Before the fix the unthrottled sustained-load rate with the YAML policy was
about 1.2k–1.4k events/s once the tracker filled; this was found by these
benchmarks.

### Kernel (vimto VM, nested virtualization)

Median of 10 runs of each run's P50; overhead is against `none`.

| Operation | none | lsm-hit | lsm-miss | lsm-miss-nowait | lsm-miss + tracepoints |
|-----------|------|---------|----------|-----------------|------------------------|
| connect (UDP) | 0.79 µs | 1.03 µs (+0.24) | 24.9 µs (+24.1) | 1.29 µs, **0.2 events/op delivered** | 53.3 µs (+52.5) |
| execve (ENOEXEC) | 12.3 µs | 47.0 µs (+34.7)¹ | 71.3 µs (+59.0) | 13.0 µs, 1.9 events/op | 116.5 µs (+104) |
| open + close | 1.77 µs | n/a² | 26.4 µs (+24.6) | 2.25 µs, **0.3 events/op delivered** | 64.5 µs (+62.7) |
| fork + exec + wait | 180 µs | 400 µs | 338 µs | 293 µs | 367 µs |

BPF program run time, measured by the kernel (`BPF_STATS_RUN_TIME`):

| Program | policy_map hit | miss (event emitted, reader idle) |
|---------|----------------|-----------------------------------|
| `lsm/socket_connect` | **0.35 µs** | 35.6 µs |
| `lsm/bprm_check_security` (execve ENOEXEC) | **0.78 µs** | 24.4 µs |
| `lsm/bprm_check_security` (fork+exec) | 2.1 µs | 27.8 µs |
| `lsm/file_open` | n/a² | 26.5 µs |

¹ An exec also opens the binary, and `file_open` has no hit path (²), so even
an exec whose policy_map entry hits emits one event.
² The `file_open` hook only sees the dentry basename, so file decisions are
never compiled into policy_map (see STATUS.md): every `open()` on the host
emits an event to userspace. There is no file fast path.

What this shows:

- **The fast path itself is cheap.** On a policy_map hit the program runs in
  0.35 µs (connect) to 0.78 µs (exec), and connect's syscall-level overhead is
  +0.24 µs. That supports the "<1 µs kernel fast path" target for the BPF
  program on a hit, in this VM. The cold fork+exec case measured 2.1 µs.
- **Sending an event is expensive here, and it is the wake-up.** A miss costs
  about +24 µs per operation when the reader is idle. In the `nowait` execve
  run, events are still emitted (1.9 per op) but the reader is usually behind,
  so no wake-up is needed, and the overhead drops to +0.7 µs. The cost is the
  ring buffer's reader wake-up (an irq_work self-IPI), which is very expensive
  under nested virtualization (WSL2 → KVM → guest). It will be much cheaper on
  bare metal; that was **not measured**.
- **Back to back, events are dropped.** Without waiting, one reader cannot
  keep up with connects or opens at ~1 µs each: only 20–30% of events reach
  userspace, the rest are lost when the ring is full. Those operations are
  allowed and never evaluated.
- **The tracepoint monitors double the miss cost**, because each emits to its
  own ring buffer and wakes its own reader.
- **fork+exec is below the noise.** Its spread between runs (median P50 from
  180 µs to 400 µs, `lsm-hit` slower than `lsm-miss`) is larger than any hook
  overhead; use the execve (ENOEXEC) row and the program run times instead.

## Caveats

- **One machine, not idle.** All numbers come from one laptop with a hybrid
  CPU (P and E cores; a goroutine's speed depends on which core it lands on)
  running other work during the runs (load average 6 to 13). Treat absolute
  values as indicative and ratios as more reliable. Quieter single runs were
  up to 2× faster; they are mentioned where relevant but not tabulated.
- **WSL2.** The userspace runs are in a WSL2 VM, the kernel runs in a KVM VM
  nested inside it. Kernel numbers are syscall-level overhead in a VM, not
  bare metal; the ring-buffer wake-up cost in particular is inflated by nested
  virtualization.
- **Synthetic load.** The workload stream is generated, not recorded from a
  real host. Hit rates depend on how often keys repeat; the 0% for undeclared
  policies does not, as long as processes are short-lived.
- **In-process harness.** The sustained-load generator shares the process
  (its cost is the `none` rows). The daemon's metrics HTTP server, eBPF
  loading and ring-buffer readers are not part of the userspace runs.
- **Audit mode, no kernel map.** Deny decisions are not acted on, and decisions
  are not synced to a kernel map in the userspace runs.
- **Not measured:** bare-metal kernel overhead, a real recorded workload,
  long-duration (hours) memory growth, the daemon binary's own RSS, and
  Windows/macOS.
