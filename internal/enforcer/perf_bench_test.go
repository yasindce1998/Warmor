package enforcer

// Performance harness for the userspace decision path (docs/PERFORMANCE.md).
//
// Everything here is a Benchmark, so a plain `go test ./...` never runs it.
// Run it with `make bench`, or directly:
//
//	go test -run '^$' -bench . -benchtime 200000x ./internal/enforcer/
//
// Every benchmark drives the real Enforcer.handleEvent with a real WASM
// evaluator, a real decision cache (10k entries, 5 min TTL, PID rule derived
// from the policy's fields-read declaration, exactly as New sets it up) and
// a logger at the daemon's default level ("info") writing to io.Discard.
// There is no kernel policy map, network filter or streaming sink (the
// daemon's defaults without -lsm-enforce or sinks).
//
// Policies:
//   - fixture: internal/wasm/testdata/allow_policy.wasm (binary ABI, no
//     fields-read declaration, so every cache key includes the PID).
//   - yaml: policies/yaml-example/policy.yaml compiled by the real compiler
//     (cargo). Skipped with a message when cargo is not installed.
//   - rust-advanced: the policies/advanced crate (JSON ABI, no declaration).
//     Skipped unless scripts/build-rust-policies.sh has been run.

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/lineage"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// benchPolicy is a policy the harness can load.
type benchPolicy struct {
	name string
	path string
	yaml bool
}

var (
	benchYAMLPolicy  = filepath.Join("..", "..", "policies", "yaml-example", "policy.yaml")
	benchCratePolicy = filepath.Join("..", "..", "policies", "advanced", "target", "wasm32-unknown-unknown", "release", "warmor_policy_advanced.wasm")
)

// benchPolicies returns the policies available on this machine, logging why
// any are skipped.
func benchPolicies(b *testing.B) []benchPolicy {
	b.Helper()
	logEnvironmentOnce(b)
	ps := []benchPolicy{{name: "fixture", path: testPolicyPath}}
	if _, err := exec.LookPath("cargo"); err != nil {
		b.Logf("SKIP yaml policy: cargo not found (needed to compile %s)", benchYAMLPolicy)
	} else {
		ps = append(ps, benchPolicy{name: "yaml", path: benchYAMLPolicy, yaml: true})
	}
	if _, err := os.Stat(benchCratePolicy); err != nil {
		b.Logf("SKIP rust-advanced policy: %s not built (run scripts/build-rust-policies.sh)", benchCratePolicy)
	} else {
		ps = append(ps, benchPolicy{name: "rust-advanced", path: benchCratePolicy})
	}
	return ps
}

// benchCacheDir holds compiled YAML policies across benchmark runs, so only
// the first run pays for cargo.
func benchCacheDir() string { return filepath.Join(os.TempDir(), "warmor-bench-cache") }

// silenceStdLog discards the standard logger (ActionHandler logs audit and
// log decisions with log.Printf) for the duration of the benchmark.
func silenceStdLog(b *testing.B) {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(prev) })
}

// newBenchEnforcer builds an Enforcer the way New does (minus the platform
// and kernel map): same cache size, TTL and PID rule, info-level logger.
// Audit mode is on so a deny never signals a real process with a synthetic
// PID; the decision path is otherwise identical.
func newBenchEnforcer(b *testing.B, p benchPolicy, poolSize int) *Enforcer {
	b.Helper()
	ctx := context.Background()
	silenceStdLog(b)

	rt, err := wasm.NewRuntime(ctx, wasm.RuntimeConfig{CacheDir: benchCacheDir(), PoolSize: poolSize})
	if err != nil {
		b.Fatalf("NewRuntime: %v", err)
	}
	if p.yaml {
		start := time.Now()
		err = rt.LoadPolicyFromYAML(ctx, p.path)
		if d := time.Since(start); d > 2*time.Second {
			b.Logf("compiled %s in %v", p.path, d.Round(time.Millisecond))
		}
	} else {
		err = rt.LoadPolicy(ctx, p.path)
	}
	if err != nil {
		rt.Close(ctx)
		b.Fatalf("load policy %s: %v", p.path, err)
	}
	pool, err := wasm.NewPool(ctx, rt, poolSize)
	if err != nil {
		rt.Close(ctx)
		b.Fatalf("NewPool: %v", err)
	}
	evaluator := wasm.NewPolicyEvaluator(pool, "bench-host")
	dc := cache.NewDecisionCache(10000, 5*time.Minute)
	dc.SetPIDRelevant(pidRelevance(evaluator))

	ectx, cancel := context.WithCancel(ctx)
	e := &Enforcer{
		platform:       &fakePlatform{},
		wasmRuntime:    rt,
		evaluator:      evaluator,
		pool:           pool,
		cache:          dc,
		actionHandler:  NewActionHandler(true),
		logger:         logging.NewLoggerWithWriter("info", io.Discard),
		metricsServer:  metrics.NewServer(-1),
		lineageTracker: lineage.NewTracker(lineage.TrackerConfig{}),
		sandbox:        NewSandboxManager(DefaultProfiles()...),
		policyPath:     p.path,
		policyID:       policyID(p.path),
		auditMode:      true,
		ctx:            ectx,
		cancel:         cancel,
	}
	b.Cleanup(func() {
		cancel()
		e.wg.Wait()
		pool.Close(context.Background())
		rt.Close(context.Background())
	})
	return e
}

// ---- synthetic events ----

func benchExec(pid, uid uint32, path string) *api.Event {
	comm := filepath.Base(path)
	if len(comm) > 15 {
		comm = comm[:15]
	}
	base := api.BaseEvent{Type: api.EventTypeProcess, PID: pid, UID: uid, GID: uid, Comm: comm}
	return &api.Event{
		Type: api.EventTypeProcess, PID: pid, UID: uid, GID: uid, Comm: comm, Filename: path,
		Process: &api.ProcessEvent{BaseEvent: base, Filename: path},
	}
}

func benchOpen(pid, uid uint32, comm, path string, flags uint32) *api.Event {
	base := api.BaseEvent{Type: api.EventTypeFile, PID: pid, UID: uid, GID: uid, Comm: comm}
	return &api.Event{
		Type: api.EventTypeFile, PID: pid, UID: uid, GID: uid, Comm: comm, Filename: path,
		File: &api.FileEvent{BaseEvent: base, Operation: "open", Path: path, Flags: flags},
	}
}

func benchConnect(pid, uid uint32, comm, addr string, port uint16) *api.Event {
	base := api.BaseEvent{Type: api.EventTypeNetwork, PID: pid, UID: uid, GID: uid, Comm: comm}
	return &api.Event{
		Type: api.EventTypeNetwork, PID: pid, UID: uid, GID: uid, Comm: comm,
		Network: &api.NetworkEvent{BaseEvent: base, Operation: "connect", Protocol: "tcp", RemoteAddr: addr, RemotePort: port},
	}
}

// missRingSize exceeds the decision cache capacity (10000), so cycling
// through it with an LRU cache misses on every event.
const missRingSize = 1 << 15

// missEvents are execs of distinct binaries by distinct PIDs.
func missEvents() []*api.Event {
	evs := make([]*api.Event, missRingSize)
	for i := range evs {
		evs[i] = benchExec(uint32(100000+i), 1000, fmt.Sprintf("/opt/app/bin/tool-%05d", i))
	}
	return evs
}

// workloadStream generates a deterministic event stream shaped like a busy
// host: short-lived processes (each a new PID) exec one of a small set of
// binaries (Zipf-weighted), open the usual loader files plus a couple of
// binary-specific ones, sometimes a unique temp file, and sometimes connect
// to one of a few service endpoints.
type workloadStream struct {
	rng     *rand.Rand
	zipf    *rand.Zipf
	nextPID uint32
	queue   []*api.Event
}

var (
	streamBinaries = []string{
		"/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/bin/sh", "/usr/bin/sed",
		"/usr/bin/date", "/usr/bin/python3", "/usr/bin/git", "/usr/bin/env", "/usr/bin/sleep",
		"/usr/bin/awk", "/usr/bin/head", "/usr/bin/curl", "/usr/bin/ssh", "/usr/local/bin/app",
		"/usr/bin/tar",
	}
	streamCommonFiles = []string{"/etc/ld.so.cache", "/lib/x86_64-linux-gnu/libc.so.6"}
	streamExtraFiles  = []string{
		"/etc/passwd", "/etc/nsswitch.conf", "/usr/lib/locale/locale-archive", "/etc/hosts",
		"/etc/resolv.conf", "/proc/self/status", "/etc/ssl/certs/ca-certificates.crt", "/home/app/.config/app.yaml",
	}
	streamEndpoints = []struct {
		addr string
		port uint16
	}{{"10.0.0.10", 443}, {"10.0.0.11", 5432}, {"10.0.0.12", 6379}, {"169.254.169.254", 80}}
)

func newWorkloadStream(seed uint64) *workloadStream {
	rng := rand.New(rand.NewPCG(seed, 0x5eed))
	return &workloadStream{
		rng:     rng,
		zipf:    rand.NewZipf(rng, 1.2, 1, uint64(len(streamBinaries)-1)),
		nextPID: 20000,
	}
}

// next returns the next event of the stream.
func (s *workloadStream) next() *api.Event {
	if len(s.queue) == 0 {
		s.spawn()
	}
	ev := s.queue[0]
	s.queue = s.queue[1:]
	return ev
}

// spawn queues the events of one short-lived process.
func (s *workloadStream) spawn() {
	pid := s.nextPID
	s.nextPID++
	uid := uint32(1000)
	if s.rng.IntN(10) == 0 {
		uid = 0
	}
	bi := int(s.zipf.Uint64())
	bin := streamBinaries[bi]
	exe := benchExec(pid, uid, bin)
	comm := exe.Comm
	s.queue = append(s.queue, exe)
	const oRdonlyCloexec = 0x80000
	for _, f := range streamCommonFiles {
		s.queue = append(s.queue, benchOpen(pid, uid, comm, f, oRdonlyCloexec))
	}
	// Each binary reads the same two extra files every run.
	for j := range 2 {
		f := streamExtraFiles[(bi+j)%len(streamExtraFiles)]
		s.queue = append(s.queue, benchOpen(pid, uid, comm, f, oRdonlyCloexec))
	}
	// One process in four opens a uniquely named temp file.
	if s.rng.IntN(4) == 0 {
		s.queue = append(s.queue, benchOpen(pid, uid, comm, fmt.Sprintf("/tmp/tmp.%08x", s.rng.Uint32()), 0x241))
	}
	// One in five connects to a service.
	if s.rng.IntN(5) == 0 {
		ep := streamEndpoints[s.rng.IntN(len(streamEndpoints))]
		s.queue = append(s.queue, benchConnect(pid, uid, comm, ep.addr, ep.port))
	}
}

// ---- latency reporting ----

// reportLatencies reports the mean and nearest-rank percentiles of per-event
// durations as custom benchmark metrics (ns). Go's ns/op is a mean only.
func reportLatencies(b *testing.B, d []time.Duration) {
	b.Helper()
	if len(d) == 0 {
		return
	}
	s := slices.Clone(d)
	slices.Sort(s)
	var sum time.Duration
	for _, v := range s {
		sum += v
	}
	pct := func(q float64) float64 {
		i := int(math.Ceil(q*float64(len(s)))) - 1
		return float64(s[max(i, 0)].Nanoseconds())
	}
	b.ReportMetric(float64(sum.Nanoseconds())/float64(len(s)), "mean-ns")
	b.ReportMetric(pct(0.50), "p50-ns")
	b.ReportMetric(pct(0.95), "p95-ns")
	b.ReportMetric(pct(0.99), "p99-ns")
	b.ReportMetric(pct(0.999), "p99.9-ns")
}

func reportThroughput(b *testing.B, n int) {
	if sec := b.Elapsed().Seconds(); sec > 0 {
		b.ReportMetric(float64(n)/sec, "events/s")
	}
}

func reportHitRate(b *testing.B, before, after cache.CacheStats) {
	hits := after.TotalHits - before.TotalHits
	total := hits + after.Misses - before.Misses
	if total > 0 {
		b.ReportMetric(100*float64(hits)/float64(total), "hit-%")
	}
}

// BenchmarkTimerOverhead measures the cost of the time.Now pair wrapped
// around each event by the latency benchmarks (included in their
// percentiles).
func BenchmarkTimerOverhead(b *testing.B) {
	lat := make([]time.Duration, b.N)
	b.ResetTimer()
	for i := range b.N {
		t0 := time.Now()
		lat[i] = time.Since(t0)
	}
	b.StopTimer()
	reportLatencies(b, lat)
}

// BenchmarkDecisionLatency measures handleEvent end to end, one goroutine,
// per event: a decision-cache hit (the same exec event repeated) and a miss
// (distinct execs, each evaluated by the WASM policy).
func BenchmarkDecisionLatency(b *testing.B) {
	for _, p := range benchPolicies(b) {
		b.Run(p.name+"/hit", func(b *testing.B) {
			e := newBenchEnforcer(b, p, 1)
			ev := benchExec(4242, 1000, "/usr/bin/ls")
			e.handleEvent(ev) // populate the cache
			lat := make([]time.Duration, b.N)
			before := e.cache.Stats()
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				t0 := time.Now()
				e.handleEvent(ev)
				lat[i] = time.Since(t0)
			}
			b.StopTimer()
			reportLatencies(b, lat)
			reportThroughput(b, b.N)
			reportHitRate(b, before, e.cache.Stats())
		})
		b.Run(p.name+"/miss", func(b *testing.B) {
			e := newBenchEnforcer(b, p, 1)
			evs := missEvents()
			for _, ev := range evs[:1000] { // warm the WASM instance
				e.handleEvent(ev)
			}
			lat := make([]time.Duration, b.N)
			before := e.cache.Stats()
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				ev := evs[(i+1000)%len(evs)]
				t0 := time.Now()
				e.handleEvent(ev)
				lat[i] = time.Since(t0)
			}
			b.StopTimer()
			reportLatencies(b, lat)
			reportThroughput(b, b.N)
			reportHitRate(b, before, e.cache.Stats())
		})
	}
}

// BenchmarkDecisionThroughputParallel calls handleEvent from GOMAXPROCS
// goroutines against a pool of GOMAXPROCS WASM instances. Note the daemon's
// event loop calls handleEvent from a single goroutine, so this is the
// capacity of the evaluation path, not of the daemon as wired today.
func BenchmarkDecisionThroughputParallel(b *testing.B) {
	procs := runtime.GOMAXPROCS(0)
	for _, p := range benchPolicies(b) {
		b.Run(p.name+"/hit", func(b *testing.B) {
			e := newBenchEnforcer(b, p, procs)
			ev := benchExec(4242, 1000, "/usr/bin/ls")
			e.handleEvent(ev)
			before := e.cache.Stats()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					e.handleEvent(ev)
				}
			})
			b.StopTimer()
			reportThroughput(b, b.N)
			reportHitRate(b, before, e.cache.Stats())
		})
		b.Run(p.name+"/miss", func(b *testing.B) {
			e := newBenchEnforcer(b, p, procs)
			evs := missEvents()
			var next atomic.Uint64
			before := e.cache.Stats()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					e.handleEvent(evs[next.Add(1)%missRingSize])
				}
			})
			b.StopTimer()
			reportThroughput(b, b.N)
			reportHitRate(b, before, e.cache.Stats())
		})
	}
}

// BenchmarkWorkloadStream feeds the synthetic workload stream through
// handleEvent and reports the decision-cache hit rate (overall and per event
// type) and the per-event latency distribution of the mixed stream. Run it
// with a fixed iteration count (e.g. -benchtime 200000x) so the hit rate is
// for a known stream length; the first 10000 events warm the cache and are
// not counted.
func BenchmarkWorkloadStream(b *testing.B) {
	const warmup = 10000
	for _, p := range benchPolicies(b) {
		b.Run(p.name, func(b *testing.B) {
			e := newBenchEnforcer(b, p, 1)
			for t := api.EventTypeProcess; t <= api.EventTypeNetwork && b.N > 1; t++ {
				pidFree := e.evaluator.FieldsRead(t)&compiler.FieldBitPID == 0
				b.Logf("%s: %s fields read %v, pid-free cache key: %v",
					p.name, t, compiler.FieldNames(e.evaluator.FieldsRead(t)), pidFree)
			}
			s := newWorkloadStream(1)
			for range warmup {
				e.handleEvent(s.next())
			}
			evs := make([]*api.Event, b.N)
			for i := range evs {
				evs[i] = s.next()
			}
			lat := make([]time.Duration, b.N)
			hit := make([]bool, b.N)
			before := e.cache.Stats()
			b.ResetTimer()
			for i, ev := range evs {
				prev := e.cache.Stats().TotalHits
				t0 := time.Now()
				e.handleEvent(ev)
				lat[i] = time.Since(t0)
				hit[i] = e.cache.Stats().TotalHits != prev
			}
			b.StopTimer()
			reportLatencies(b, lat)
			reportHitRate(b, before, e.cache.Stats())
			var n, h [3]int
			for i, ev := range evs {
				t := ev.GetType()
				n[t]++
				if hit[i] {
					h[t]++
				}
			}
			for t, unit := range []string{"proc-hit-%", "file-hit-%", "net-hit-%"} {
				if n[t] > 0 {
					b.ReportMetric(100*float64(h[t])/float64(n[t]), unit)
				}
			}
			if b.N == 1 {
				return
			}
			b.Logf("%s: %d events (%d process, %d file, %d network); hits %d/%d/%d",
				p.name, len(evs), n[0], n[1], n[2], h[0], h[1], h[2])
		})
	}
}

// statsOnce guards a one-off log line per process.
var statsOnce sync.Once

// logEnvironmentOnce logs Go and machine details once per run, so a pasted
// benchmark log carries its environment.
func logEnvironmentOnce(b *testing.B) {
	statsOnce.Do(func() {
		b.Logf("go %s %s/%s GOMAXPROCS=%d NumCPU=%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), runtime.NumCPU())
	})
}
