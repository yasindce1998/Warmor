# Warmor Performance

**Measured:** 2026-10-15, on one laptop (details below). Raw output of the runs
these tables come from is in [`docs/perf/2026-10-15/`](perf/2026-10-15/).

This page replaces the performance targets that earlier documents listed
without measurements. Where a target is still mentioned, it sits next to the
measurement and is labelled as a target.

## Summary

| Metric | Target (design, not a result) | Measured | Verdict |
|--------|-------------------------------|----------|---------|
| Userspace decision, cache hit | <100 µs P95 | P50 0.70–0.72 µs, P95 1.2–1.3 µs | Met |
| Userspace decision, cache miss (WASM evaluation) | <100 µs P95 | P95 32 µs (YAML policy), 38 µs (fixture), 55 µs (Rust `advanced` crate) | Met |
| Decision cache hit rate, synthetic host workload | >90% | 95.4% with a compiled YAML policy; **0%** with any policy that does not declare the fields it reads | Met only for declared policies |
| Throughput (real event loop, one goroutine) | 100k events/s | 175k events/s (YAML policy); 41k (fixture) and 24k (Rust crate) | Met only for declared policies |
| Kernel fast path (BPF program on a policy_map hit) | <1 µs | 0.07–0.11 µs (connect), 0.34–0.82 µs (exec) across two runs, kernel-measured program time | Met for the program itself, in a VM |
| Kernel cost when an event is sent to userspace | (none set) | 0.4–1.6 µs of program time per queued event; the reader is woken in batches, so a lone event can take up to 5 ms to reach userspace | Every `open()` takes it (no file fast path) |
| Memory (RSS) | <50 MB | 60 MB at 1k events/s up to 104 MB at maximum rate (YAML policy); 105–128 MB with undeclared policies | **Not met** |
| CPU | <5% | 11% of one core (0.8% of the 14-thread host) at 10k events/s with the YAML policy, net of the load generator; 83% of one core with the fixture; the Rust crate cannot sustain 10k events/s | Depends on the policy; see table |

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
| Commit | `4c39bd4` (this branch rebased onto `main` with the temporal-policies merge) for the userspace runs; kernel benchmarks from the same tree |
| Background load | Quiet machine: 1-minute load average 0.64 when the userspace run started. It was 7.53 when it ended; that is the harness itself (the parallel and sustained-load benchmarks keep up to 14 threads busy), not other work |
| Kernel VM | vimto v0.4.0 + QEMU 8.2.2 + KVM, nested inside WSL2. Guest kernel 7.2.2 (`ghcr.io/cilium/ci-kernels:stable-selftests`), 2 vCPUs, `lsm=capability,selinux,bpf`, kvm-clock |

## How to reproduce

```sh
# Policies for the YAML and Rust-crate cases (both are skipped with a
# message if missing)
scripts/build-rust-policies.sh          # needs cargo + wasm32-unknown-unknown

make bench                              # userspace, ~15 min, writes bench-results/
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
itself costs 19 ns at P50 (`BenchmarkTimerOverhead`) and is included in every
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
19–20 MB RSS and 3–7% of one core at up to 50k events/s); subtract them to get
the enforcer's share.

### Kernel

`internal/ebpf/perf_integration_test.go`, run in the VM as root. For each
operation it measures, in one process (programs are loaded once per
operation; with `-count 10` each configuration runs 10 times in a row):

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
for sustained load, 10 for kernel); ranges are in the raw files and are
printed by `scripts/bench-summary.py`.

### Userspace decision latency (one goroutine)

| Policy | Case | Mean | P50 | P95 | P99 | P99.9 | Allocations |
|--------|------|------|-----|-----|-----|-------|-------------|
| fixture | hit | 0.87 µs | 0.70 µs | 1.27 µs | 1.85 µs | 19 µs | 160 B, 2 |
| fixture | miss | 20.0 µs | 14.6 µs | 38.5 µs | 89 µs | 333 µs | 38.0 KB, 59 |
| yaml | hit | 0.84 µs | 0.71 µs | 1.19 µs | 1.72 µs | 17 µs | 160 B, 2 |
| yaml | miss | 17.0 µs | 11.9 µs | 31.9 µs | 81 µs | 336 µs | 49.0 KB, 41 |
| rust-advanced | hit | 0.87 µs | 0.72 µs | 1.22 µs | 2.34 µs | 14 µs | 160 B, 2 |
| rust-advanced | miss | 31.1 µs | 25.4 µs | 55.0 µs | 115 µs | 402 µs | 38.0 KB, 59 |

The three hit rows execute identical code (no WASM call), and agree within
0.02 µs at P50. On a miss, most of the cost is outside the policy itself: a CPU
profile of `fixture/miss` (taken on this machine before the rebase; the
allocation counts are unchanged) shows about 38% of CPU time in the garbage
collector, driven by ~38 KB of allocations per evaluation. An allocation
profile attributes 89% of those bytes to wazero creating a new call engine
(with a fresh stack) on every evaluation, because `evaluateJSON`
(`internal/wasm/policy.go`) looks up the exported functions with
`ExportedFunction` per call. Looking them up once per pooled instance looks
like the largest available improvement; it is not done here.

### Throughput

| Policy | Hit, 1 goroutine | Miss, 1 goroutine | Hit, 14 goroutines | Miss, 14 goroutines |
|--------|------------------|-------------------|--------------------|---------------------|
| fixture | 1.09M/s | 49.7k/s | 1.14M/s | 79k/s |
| yaml | 1.13M/s | 58.5k/s | 1.03M/s | 85k/s |
| rust-advanced | 1.10M/s | 32.1k/s | 1.14M/s | 71k/s |

Parallel hits do not scale at all (about 1× on 14 threads): every event takes
the decision cache's single mutex, and every exec event the lineage tracker's.
Parallel misses scale 1.5–2.2×.

### Cache hit rate (200,000-event synthetic stream)

| Policy | Overall | Process | File | Network | Per-event P50 / P95 / P99 |
|--------|---------|---------|------|---------|---------------------------|
| yaml (declared, PID-free keys) | **95.4%** | 100.0% | 94.1% | 99.4% | 0.73 / 6.2 / 15.5 µs |
| fixture (undeclared) | **0.0%** | 0.0% | 0.0% | 0.0% | 15.2 / 39.6 / 81.7 µs |
| rust-advanced (undeclared) | **0.0%** | 0.0% | 0.0% | 0.0% | 19.9 / 46.8 / 99.7 µs |

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
| none (generator only) | 1k/s | 999/s | 3.4% | 0.2% | 18.5 MB (19.8) | 1.9 MB |
| none | 10k/s | 9,994/s | 3.8% | 0.3% | 19.8 MB (20.1) | 2.8 MB |
| none | 50k/s | 49,969/s | 6.5% | 0.5% | 20.1 MB (20.7) | 2.9 MB |
| none | unthrottled | 4.13M/s | 178% | 12.7% | 20.8 MB (21.5) | 1.2 MB |
| yaml | 1k/s | 999/s | 5.0% | 0.4% | 59.5 MB (63.2) | 41.8 MB |
| yaml | 10k/s | 9,993/s | 14.5% | 1.0% | 81.4 MB (83.8) | 62.0 MB |
| yaml | 50k/s | 49,970/s | 55.2% | 3.9% | 99.1 MB (102.5) | 81.3 MB |
| yaml | unthrottled | **175k/s** | 201% | 14.3% | 103.9 MB (106.5) | 67.4 MB |
| fixture | 1k/s | 999/s | 15.0% | 1.1% | 105.1 MB (109.7) | 80.8 MB |
| fixture | 10k/s | 9,994/s | 86.7% | 6.2% | 118.1 MB (120.6) | 87.0 MB |
| fixture | 50k/s | 42,934/s | 286% | 20.4% | 127.8 MB (129.2) | 94.0 MB |
| fixture | unthrottled | **41k/s** | 287% | 20.5% | 127.3 MB (132.1) | 58.9 MB |
| rust-advanced | 1k/s | 999/s | 20.1% | 1.4% | 106.8 MB (112.0) | 60.1 MB |
| rust-advanced | 10k/s | **9,202/s** | 189% | 13.5% | 121.0 MB (124.6) | 87.3 MB |
| rust-advanced | 50k/s | 10,416/s | 198% | 14.1% | 124.4 MB (129.6) | 83.2 MB |
| rust-advanced | unthrottled | **24k/s** | 246% | 17.6% | 121.6 MB (126.4) | 79.5 MB |

Net of the generator (subtract the `none` row): the YAML policy costs about
2% of one core at 1k events/s, 11% at 10k and 49% at 50k. The fixture costs
83% of one core at 10k events/s. The Rust crate did not keep up with 10k
events/s offered (9.2k achieved), yet reached 24k unthrottled; its 50k/s runs
varied from 10.3k to 24.3k achieved (median 10.4k). These files do not explain
that gap between paced and unthrottled runs; treat the paced Rust-crate rows
as unreliable.

Memory is above the 50 MB target in every configuration. Contributors: the
full lineage tracker (100,000 entries), one WASM instance per CPU (14), the
decision cache (10,000 entries), and the Go heap growing to about twice the
live heap between collections (default GOGC=100) under the allocation rate of
WASM evaluations. The harness itself accounts for about 19–20 MB (the `none`
rows: test binary plus generator); the daemon binary also loads eBPF objects
and serves HTTP, which this does not include.

### Lineage tracker (fixed while measuring)

`lineage.Tracker.RecordExec` evicted the oldest entry by scanning the whole
map once the tracker was full, and nothing ever removes entries, so every
exec of a new PID on a daemon that had seen 100,000 execs cost:

| | `BenchmarkRecordExec` (tracker full, new PID) |
|---|---|
| Before the fix | 3.76 ms per exec (single run, 2,000 iterations, on the pre-rebase branch) |
| After (FIFO list) | 0.59 µs per exec (median of 5, range 0.49–0.64 µs) |

Before the fix the unthrottled sustained-load rate with the YAML policy was
about 1.2k–1.4k events/s once the tracker filled (pre-rebase single runs);
this was found by these benchmarks.

### Kernel (vimto VM, nested virtualization)

Median of 10 runs of each run's P50; overhead is against `none`. Raw output:
`docs/perf/2026-10-16/kernel.txt` (current), `docs/perf/2026-10-15/kernel.txt`
(before batched wake-ups).

**Back-to-back operations (`lsm-miss-nowait`): cost to the process and events
delivered.** This is the burst case, where one reader has to keep up:

| Operation | none | Before: per-event wake-up | Now: batched wake-up |
|-----------|------|---------------------------|----------------------|
| connect (UDP) | 0.38 µs | 0.54 µs, **0.2 events/op delivered** | 0.59 µs, **1.0 events/op delivered** |
| open + close | 0.67 µs | 2.02 µs, **0.5 events/op delivered** | 0.99 µs (+0.33), **1.0 events/op delivered** |
| execve (ENOEXEC) | 4.66 µs | 6.89 µs, 1.9 of 2 events/op | 5.48 µs (+0.82), 2.0 of 2 events/op |
| fork + exec + wait | 45.7 µs | 118.7 µs | 65.8 µs (+20.1) |

**One operation at a time, waiting for its event to reach userspace
(`lsm-miss`).** This measures delivery latency, not the cost to the process:

| Operation | Before | Now |
|-----------|--------|-----|
| connect, open | 13–21 µs | 0.45–0.95 µs to the syscall, then up to 5 ms until the reader polls |
| execve (ENOEXEC) / fork + exec + wait | 31.4 / 80.1 µs | 29.1 / 134.8 µs |

With batching, the kernel no longer wakes the reader for every event: it wakes
it once 64 KiB are queued or for a denial, and the reader otherwise polls every
5 ms. So the syscall returns sooner (no per-event wake-up), but a lone event can
reach userspace up to 5 ms later. The exec rows in the second table pay that
wait (an exec emits an event for the binary's open), which is why they look
slower; the process itself is not slower (first table, and the program times
below). Denials still wake the reader at once.

BPF program run time, measured by the kernel (`BPF_STATS_RUN_TIME`):

| Program | policy_map hit | miss (event queued) |
|---------|----------------|---------------------|
| `lsm/socket_connect` | **0.07 µs** | 0.61 µs (was 11.7 µs) |
| `lsm/bprm_check_security` (execve ENOEXEC) | **0.82 µs**³ | 1.06 µs (was 13.3 µs) |
| `lsm/bprm_check_security` (fork+exec) | 1.17 µs³ | 1.63 µs (was 12.7 µs) |
| `lsm/file_open` | n/a² | 0.42 µs (was 20.0 µs) |

² The `file_open` hook only sees the dentry basename, so file decisions are
never compiled into policy_map (see STATUS.md): every `open()` on the host
emits an event to userspace. There is no file fast path.
³ Higher than the earlier run's 0.34 / 0.50 µs. The hit path is unchanged by
batching, so this is most likely run-to-run noise in the nested VM, but it was
not investigated further.

What this shows:

- **The fast path is cheap.** A policy_map hit costs 0.07 µs (connect) to about
  1 µs (exec) of program time.
- **Sending an event is now cheap too.** Queueing without a wake-up costs
  0.4–1.6 µs of program time, down from 12–20 µs, because the expensive part
  was the per-event reader wake-up (an irq_work self-IPI, very expensive under
  nested virtualization).
- **Bursts no longer lose events.** Back to back, connects and opens deliver
  1.0 events per operation (were 0.2 and 0.5). Under a sustained flood beyond
  what the reader can drain, events can still be dropped, but every drop is
  counted (`warmor_lsm_events_dropped_total`, alerted), and with
  `--on-event-loss=deny` an unknown exec or connect is refused rather than
  allowed unevaluated. A VM test checks that every operation is either
  delivered or counted.
- **Trade-off: event latency.** A lone event can take up to 5 ms to reach
  userspace. This affects how soon an after-the-fact deny (SIGKILL) or an
  escape alert happens, not kernel-map decisions or denials.
- **The tracepoint monitors still wake their reader per event** and add
  +22–30 µs per miss; they were not changed.

## Caveats

- **One machine.** All numbers come from one laptop with a hybrid CPU (P and E
  cores; a goroutine's speed depends on which core it lands on). The machine
  was otherwise idle (load average 0.64 at the start); the parallel and
  sustained-load benchmarks themselves keep many threads busy, which is why
  the load average was 7.53 at the end. An earlier run while other work was
  using most of the cores measured roughly 2–3× slower latencies. Treat
  absolute values as indicative of this machine only.
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
