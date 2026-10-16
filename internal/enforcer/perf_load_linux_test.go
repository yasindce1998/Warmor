//go:build linux

package enforcer

import (
	"bufio"
	"os"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// BenchmarkSustainedLoad drives the real event loop (Enforcer.eventLoop, the
// goroutine the daemon runs) with the synthetic workload stream at a fixed
// rate and samples process RSS (/proc/self/status VmRSS), process CPU time
// (getrusage, user+system) and Go runtime memory. b.N is ignored: run with
// -benchtime 1x. The load runs for WARMOR_BENCH_LOAD_SECONDS (default 10)
// after a 3 s warm-up that is not measured.
//
// Sub-benchmarks are <policy>/rate=<events/s>; rate=0 means unthrottled
// (the maximum the single event loop sustains). The "none" policy replaces
// the enforcer with a goroutine that discards events: it measures the cost of
// the load generator itself, which runs in the same process and is included
// in every CPU figure.
//
// RSS is per process and Go rarely returns memory to the OS, so run each
// sub-benchmark in its own process (scripts/bench.sh does).
func BenchmarkSustainedLoad(b *testing.B) {
	rates := []int{1000, 10000, 50000, 0}
	policies := append([]benchPolicy{{name: "none"}}, benchPolicies(b)...)
	for _, p := range policies {
		for _, rate := range rates {
			b.Run(p.name+"/rate="+strconv.Itoa(rate), func(b *testing.B) {
				runSustainedLoad(b, p, rate)
			})
		}
	}
}

// lineageCapacity is lineage.TrackerConfig's default MaxSize.
const lineageCapacity = 100000

func loadSeconds() time.Duration {
	if v, err := strconv.Atoi(os.Getenv("WARMOR_BENCH_LOAD_SECONDS")); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return 10 * time.Second
}

func runSustainedLoad(b *testing.B, p benchPolicy, rate int) {
	const warmup = 3 * time.Second
	measure := loadSeconds()

	ch := make(chan *api.Event, 1024)
	var stop func()
	if p.name == "none" {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range ch { //nolint:revive // drain only
			}
		}()
		stop = func() { close(ch); <-done }
	} else {
		e := newBenchEnforcer(b, p, runtime.NumCPU())
		// A long-running daemon's lineage tracker is full: nothing calls
		// RecordExit, so it holds the last 100000 execs. Start from that
		// state instead of an empty tracker, or a 10 s run would understate
		// steady-state memory.
		for i := range lineageCapacity {
			e.lineageTracker.RecordExec(uint32(5_000_000+i), 1, 1000, 1000,
				strings.Clone("prefill"), strings.Clone("/usr/bin/prefill"))
		}
		e.eventChan = ch
		e.wg.Add(1)
		go e.eventLoop()
		stop = func() { e.cancel(); e.wg.Wait() }
	}

	stream := newWorkloadStream(1)
	produce := func(d time.Duration) int {
		start := time.Now()
		sent := 0
		for {
			el := time.Since(start)
			if el >= d {
				return sent
			}
			target := int(el.Seconds() * float64(rate))
			if rate == 0 {
				target = sent + 256
			}
			for sent < target {
				ch <- stream.next()
				sent++
			}
			if rate != 0 {
				time.Sleep(5 * time.Millisecond) // batches of rate/200 events
			}
		}
	}

	produce(warmup)

	samples := []int64{}
	sampleDone := make(chan struct{})
	sampleStop := make(chan struct{})
	go func() {
		defer close(sampleDone)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-sampleStop:
				return
			case <-t.C:
				if rss, ok := vmRSS(); ok {
					samples = append(samples, rss)
				}
			}
		}
	}()

	cpu0 := cpuTime()
	wall0 := time.Now()
	b.ResetTimer()
	sent := produce(measure)
	b.StopTimer()
	wall := time.Since(wall0)
	cpu := cpuTime() - cpu0
	close(sampleStop)
	<-sampleDone

	gomem := readGoMemory()
	stop()

	if len(samples) == 0 {
		b.Fatal("no RSS samples")
	}
	slices.Sort(samples)
	b.ReportMetric(float64(sent)/wall.Seconds(), "events/s")
	b.ReportMetric(100*cpu.Seconds()/wall.Seconds(), "cpu-%core")
	b.ReportMetric(100*cpu.Seconds()/wall.Seconds()/float64(runtime.NumCPU()), "cpu-%host")
	b.ReportMetric(float64(samples[len(samples)/2])/(1<<20), "rss-median-MiB")
	b.ReportMetric(float64(samples[len(samples)-1])/(1<<20), "rss-max-MiB")
	b.ReportMetric(float64(gomem.total)/(1<<20), "go-total-MiB")
	b.ReportMetric(float64(gomem.heapLive)/(1<<20), "go-heap-MiB")
}

// vmRSS returns this process's resident set size in bytes.
func vmRSS() (int64, bool) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		return kb * 1024, err == nil
	}
	return 0, false
}

// cpuTime is the process's user+system CPU time.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

type goMemory struct{ total, heapLive uint64 }

// readGoMemory reads the Go runtime's view of memory mapped (total) and
// live heap objects.
func readGoMemory() goMemory {
	s := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
	}
	metrics.Read(s)
	var m goMemory
	if s[0].Value.Kind() == metrics.KindUint64 {
		m.total = s[0].Value.Uint64()
	}
	if s[1].Value.Kind() == metrics.KindUint64 {
		m.heapLive = s[1].Value.Uint64()
	}
	return m
}
