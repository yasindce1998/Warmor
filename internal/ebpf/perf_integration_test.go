//go:build integration

package ebpf

// Kernel fast-path benchmarks (docs/PERFORMANCE.md). They need root and a
// BPF-LSM kernel, so they run in a vimto VM (make bench-kernel):
//
//	vimto -kernel ghcr.io/cilium/ci-kernels:stable-selftests -- \
//	    go test -tags integration -run '^$' -bench Kernel -benchtime 3000x -count 10 ./internal/ebpf/
//
// Each top-level benchmark measures, in this order and in one process:
//
//	none             no warmor programs attached
//	lsm-hit          all LSM programs attached, the operation's policy_map
//	                 entry is a global ALLOW (cgroup lookup misses, global
//	                 lookup hits; this hook emits no ringbuf event)
//	lsm-miss         LSM programs attached, no policy_map entry (the program
//	                 emits a ringbuf event, drained by a reader goroutine as
//	                 in the daemon)
//	lsm-miss-nowait  lsm-miss without waiting for the reader between ops
//	progstats-*      lsm-hit / lsm-miss again with BPF_STATS_RUN_TIME
//	                 enabled, reporting the kernel's own average run time of
//	                 the operation's program (prog-ns)
//	lsm-miss+tp      lsm-miss plus the tracepoint monitors the daemon also
//	                 loads (sys_enter_execve/openat/connect), all drained
//
// The difference between a configuration's op-p50-ns and none's is the
// syscall-level overhead. Programs are loaded once per top-level benchmark;
// with -count N, the testing package runs each configuration N times in a
// row (it does not interleave them).

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// tinyELF returns a static x86-64 executable that only calls exit(0).
func tinyELF() []byte {
	const base = 0x400000
	code := []byte{
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
		0x31, 0xff, // xor edi, edi
		0x0f, 0x05, // syscall
	}
	hdrSize := binary.Size(elf.Header64{}) + binary.Size(elf.Prog64{})
	total := uint64(hdrSize + len(code))
	var buf bytes.Buffer
	h := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Entry: base + uint64(hdrSize), Phoff: uint64(binary.Size(elf.Header64{})),
		Ehsize: uint16(binary.Size(elf.Header64{})), Phentsize: uint16(binary.Size(elf.Prog64{})), Phnum: 1,
	}
	copy(h.Ident[:], elf.ELFMAG)
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	p := elf.Prog64{
		Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X),
		Vaddr: base, Paddr: base, Filesz: total, Memsz: total, Align: 0x1000,
	}
	_ = binary.Write(&buf, binary.LittleEndian, h)
	_ = binary.Write(&buf, binary.LittleEndian, p)
	buf.Write(code)
	return buf.Bytes()
}

// tinyBinary writes tinyELF to a tmpfs (the vimto root is 9p, whose exec
// cost would swamp the hook) and returns its path.
func tinyBinary(b *testing.B) string {
	b.Helper()
	if runtime.GOARCH != "amd64" {
		b.Skip("tiny exec binary is x86-64 only")
	}
	dir := b.TempDir()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=1m"); err != nil {
		b.Logf("tmpfs mount failed (%v); exec'ing from %s", err, dir)
	} else {
		b.Cleanup(func() { _ = syscall.Unmount(dir, 0) })
	}
	path := filepath.Join(dir, "exit0")
	if err := os.WriteFile(path, tinyELF(), 0o755); err != nil {
		b.Fatal(err)
	}
	return path
}

func execOnce(b *testing.B, path string) {
	pid, err := syscall.ForkExec(path, []string{path}, &syscall.ProcAttr{})
	if err != nil {
		b.Fatalf("exec %s: %v", path, err)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		b.Fatalf("wait: %v", err)
	}
	if ws.ExitStatus() != 0 {
		b.Fatalf("%s exited %d", path, ws.ExitStatus())
	}
}

// drainer reads ring buffers until they are closed, as the daemon's
// platform monitors do, and counts the events.
type drainer struct {
	wg     sync.WaitGroup
	events atomic.Uint64
}

func (d *drainer) drain(read func() (*Event, error)) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			if _, err := read(); errors.Is(err, ringbuf.ErrClosed) {
				return
			} else if err == nil {
				d.events.Add(1)
			}
		}
	}()
}

func requireKernelBench(b *testing.B) {
	b.Helper()
	if os.Geteuid() != 0 {
		b.Skip("requires root (run in a VM: make bench-kernel)")
	}
	if !IsLSMSupported() {
		b.Skip("kernel does not have BPF LSM enabled")
	}
}

func loadLSMForBench(b *testing.B) *LSMLoader {
	b.Helper()
	l, err := LoadLSM()
	if err != nil || l == nil {
		b.Fatalf("LoadLSM: %v", err)
	}
	if err := l.SetEnforceMode(true); err != nil {
		b.Fatalf("SetEnforceMode: %v", err)
	}
	return l
}

// kernelBench runs op under every configuration. setHit installs the
// policy_map entry that makes op an ALLOW hit.
//
// Every op is timed individually (op-mean-ns, op-p50-ns). With programs
// attached, the benchmark then waits, untimed, until the ring buffers are
// empty, so each op starts with an idle, caught-up consumer and every miss
// really emits (and wakes the reader). Go's ns/op includes that wait and is
// not the number to use. lsm-miss-nowait skips the wait: back to back, the
// ring can fill faster than one reader drains it, and then events are
// dropped (events/op shows it).
func kernelBench(b *testing.B, op func(b *testing.B), setHit func(*PolicyMapManager) error, prog func(*LSMLoader) *ciliumebpf.Program) {
	var rings []*ringbuf.Reader
	run := func(name string, d *drainer, stats func() (float64, bool), wait bool) {
		b.Run(name, func(b *testing.B) {
			drained := func() {
				if !wait {
					return
				}
				for _, r := range rings {
					for r.AvailableBytes() > 0 {
						runtime.Gosched()
					}
				}
			}
			var ev0 uint64
			if d != nil {
				ev0 = d.events.Load()
			}
			op(b) // warm up
			drained()
			lat := make([]time.Duration, b.N)
			b.ResetTimer()
			for i := range b.N {
				t0 := time.Now()
				op(b)
				lat[i] = time.Since(t0)
				drained()
			}
			b.StopTimer()
			slices.Sort(lat)
			var sum time.Duration
			for _, v := range lat {
				sum += v
			}
			b.ReportMetric(float64(sum.Nanoseconds())/float64(len(lat)), "op-mean-ns")
			b.ReportMetric(float64(lat[len(lat)/2].Nanoseconds()), "op-p50-ns")
			if d != nil {
				b.ReportMetric(float64(d.events.Load()-ev0)/float64(b.N+1), "events/op")
			}
			if stats != nil {
				if ns, ok := stats(); ok {
					b.ReportMetric(ns, "prog-ns")
				}
			}
		})
	}

	run("none", nil, nil, false)

	l := loadLSMForBench(b)
	rings = []*ringbuf.Reader{l.lsmReader}
	d := &drainer{}
	d.drain(l.ReadLSMEvent)
	defer func() { l.Close(); d.wg.Wait() }()
	pm := l.PolicyMap()

	if setHit != nil {
		if err := setHit(pm); err != nil {
			b.Fatalf("install allow rule: %v", err)
		}
		run("lsm-hit", d, nil, true)
		if err := pm.Clear(); err != nil {
			b.Fatal(err)
		}
	}
	run("lsm-miss", d, nil, true)
	run("lsm-miss-nowait", d, nil, false)

	// Kernel-measured program run time. Stats collection itself adds a
	// little time per run, which is why the configurations above run
	// without it.
	if closer, err := ciliumebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME)); err != nil {
		b.Logf("BPF_STATS_RUN_TIME unavailable: %v", err)
	} else {
		p := prog(l)
		var t0, n0 uint64
		snap := func() {
			if st, err := p.Stats(); err == nil {
				t0, n0 = uint64(st.Runtime.Nanoseconds()), st.RunCount
			}
		}
		perRun := func() (float64, bool) {
			st, err := p.Stats()
			if err != nil || st.RunCount <= n0 {
				return 0, false
			}
			return float64(uint64(st.Runtime.Nanoseconds())-t0) / float64(st.RunCount-n0), true
		}
		if setHit != nil {
			if err := setHit(pm); err != nil {
				b.Fatal(err)
			}
			snap()
			run("progstats-hit", d, perRun, true)
			if err := pm.Clear(); err != nil {
				b.Fatal(err)
			}
		}
		snap()
		run("progstats-miss", d, perRun, true)
		closer.Close()
	}

	tp, err := Load()
	if err != nil || tp == nil {
		b.Logf("tracepoint monitors unavailable: %v", err)
		return
	}
	td := &drainer{}
	td.drain(tp.ReadProcessEvent)
	td.drain(tp.ReadFileEvent)
	td.drain(tp.ReadNetworkEvent)
	rings = append(rings, tp.processReader, tp.fileReader, tp.networkReader)
	run("lsm-miss+tp", d, nil, true)
	rings = rings[:1]
	tp.Close()
	td.wg.Wait()
}

// BenchmarkKernelExec measures fork+exec+exit+wait of a static binary that
// only calls exit(0).
func BenchmarkKernelExec(b *testing.B) {
	requireKernelBench(b)
	path := tinyBinary(b)
	kernelBench(b,
		func(b *testing.B) { execOnce(b, path) },
		func(pm *PolicyMapManager) error { return pm.SetRule(0, EventTypeExec, path, ActionAllow, false) },
		func(l *LSMLoader) *ciliumebpf.Program { return l.execObjs.LsmExecCheck },
	)
}

// BenchmarkKernelExecveENOEXEC measures an execve() that the kernel runs
// through open, bprm setup and the bprm_check_security hook and then fails
// with ENOEXEC (the file is not a valid executable). There is no fork, child
// or wait, so this isolates the exec hook from scheduler noise far better
// than BenchmarkKernelExec.
func BenchmarkKernelExecveENOEXEC(b *testing.B) {
	requireKernelBench(b)
	dir := filepath.Dir(tinyBinary(b))
	path := filepath.Join(dir, "not-an-elf")
	if err := os.WriteFile(path, make([]byte, 64), 0o755); err != nil {
		b.Fatal(err)
	}
	argv := []string{path}
	kernelBench(b,
		func(b *testing.B) {
			if err := syscall.Exec(path, argv, nil); !errors.Is(err, syscall.ENOEXEC) {
				b.Fatalf("execve %s: %v, want ENOEXEC", path, err)
			}
		},
		func(pm *PolicyMapManager) error { return pm.SetRule(0, EventTypeExec, path, ActionAllow, false) },
		func(l *LSMLoader) *ciliumebpf.Program { return l.execObjs.LsmExecCheck },
	)
}

// BenchmarkKernelOpen measures open()+close() of a file on tmpfs. The
// file_open hook has no fast path (the kernel only sees the basename, so
// file decisions are never compiled into policy_map): every open emits an
// event, so there is no lsm-hit configuration.
func BenchmarkKernelOpen(b *testing.B) {
	requireKernelBench(b)
	path := tinyBinary(b)
	kernelBench(b,
		func(b *testing.B) {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				b.Fatalf("open: %v", err)
			}
			unix.Close(fd)
		},
		nil,
		func(l *LSMLoader) *ciliumebpf.Program { return l.fileObjs.LsmFileCheck },
	)
}

// BenchmarkKernelConnect measures connect() of a UDP socket to a loopback
// address (no packets are sent, so the syscall is cheap and the hook's
// share of it is visible). The same socket is re-connected each time.
func BenchmarkKernelConnect(b *testing.B) {
	requireKernelBench(b)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
	kernelBench(b,
		func(b *testing.B) {
			if err := unix.Connect(fd, sa); err != nil {
				b.Fatalf("connect: %v", err)
			}
		},
		func(pm *PolicyMapManager) error {
			return pm.SetEndpointRule(0, EventTypeNetwork, "127.0.0.1", 9, ActionAllow, false)
		},
		func(l *LSMLoader) *ciliumebpf.Program { return l.connectObjs.LsmConnectCheck },
	)
}
