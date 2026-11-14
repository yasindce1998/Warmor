//go:build linux && integration

package ebpf

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

func TestLSM_GenerationVMRequirements(t *testing.T) {
	if os.Getenv("WARMOR_GENERATION_VM_GATE") != "1" {
		t.Skip("dedicated strict generation VM gate only")
	}
	if os.Getenv("WARMOR_REQUIRE_BPF_LSM") != "1" || os.Getenv("WARMOR_REQUIRE_IMA") != "1" {
		t.Fatal("strict generation gate must disallow BTF/LSM/IMA skips")
	}
	_, _ = identityTestLoader(t) // proves VM identity, root, BTF load and all policy hooks
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	minor := os.Getenv("WARMOR_EXPECT_KERNEL_MINOR")
	if minor == "" || !strings.HasPrefix(strings.TrimSpace(string(release)), minor+".") {
		t.Fatalf("kernel release %q is not requested %q", strings.TrimSpace(string(release)), minor)
	}
	if ok, err := imaAvailable(); err != nil || !ok {
		t.Fatalf("strict gate requires IMA in kernel BTF: available=%v error=%v", ok, err)
	}
	t.Logf("private vimto VM, required BPF-LSM/IMA, actual kernel=%s", strings.TrimSpace(string(release)))
}

// All helpers in this file are used only after identityTestLoader has proved
// the private disposable vimto VM. No environment variable authorizes a host.
type generationTrafficEvents struct {
	mu       sync.Mutex
	events   []Event
	err      error
	barriers chan int
	done     chan struct{}
}

type generationTrafficAttempt struct {
	blocked    bool
	start, end time.Time
}

func collectGenerationTraffic(l *LSMLoader) *generationTrafficEvents {
	c := &generationTrafficEvents{barriers: make(chan int, 1), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			e, err := l.ReadLSMEvent()
			c.mu.Lock()
			if errors.Is(err, ringbuf.ErrFlushed) {
				n := len(c.events)
				c.mu.Unlock()
				c.barriers <- n
				continue
			}
			if err != nil {
				c.err = err
				c.mu.Unlock()
				return
			}
			if e.Hook == "connect" && e.RemoteAddr == "127.0.0.1" && e.RemotePort >= 42100 && e.RemotePort < 42104 {
				if len(c.events) >= 20000 {
					c.err = errors.New("generation traffic event bound exceeded")
					c.mu.Unlock()
					return
				}
				c.events = append(c.events, *e)
			}
			c.mu.Unlock()
		}
	}()
	return c
}

func waitGenerationTraffic(t *testing.T, c *generationTrafficEvents, condition func([]Event) bool) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		c.mu.Lock()
		ok, err := condition(c.events), c.err
		c.mu.Unlock()
		if err != nil {
			t.Fatalf("traffic reader: %v", err)
		}
		if ok {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("generation traffic progress timed out")
		case <-tick.C:
		}
	}
}

func flushGenerationTraffic(t *testing.T, l *LSMLoader, c *generationTrafficEvents) int {
	t.Helper()
	if err := l.FlushLSMEvents(); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-c.barriers:
		return n
	case <-c.done:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		t.Fatalf("traffic reader ended before flush: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("flush under live traffic timed out")
	}
	return 0
}

func TestLSM_GenerationConcurrentVerdictsFlushAndRetire(t *testing.T) {
	l, cgid := identityTestLoader(t)
	m := l.PolicyGenerations()
	spec := func(id uint64) GenerationSpec {
		s := GenerationSpec{DefaultDeny: []GenerationDomain{{EventType: EventTypeNetwork, Mode: DefaultDenyModeDeny}}}
		for worker := 0; worker < 4; worker++ {
			// Alternate which endpoints are exact audited allows and which
			// are denied on a miss. Both generations must remain complete.
			if (uint64(worker)+id)%2 == 0 {
				s.Rules = append(s.Rules, GenerationRule{CgroupID: cgid, EventType: EventTypeNetwork,
					Address: "127.0.0.1", Port: uint16(42100 + worker), Action: ActionAllow, Audit: true})
			}
		}
		return s
	}
	if err := m.Prepare(1, spec(1)); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	c := collectGenerationTraffic(l)
	var stopOnce sync.Once
	stop := make(chan struct{})
	var workers sync.WaitGroup
	var completed atomic.Uint64
	var results [4][]generationTrafficAttempt
	workerErrors := make(chan error, 4)
	stopWorkers := func() { stopOnce.Do(func() { close(stop); workers.Wait() }) }
	t.Cleanup(func() {
		stopWorkers()
		if err := l.lsmReader.Close(); err != nil {
			t.Error(err)
		}
		<-c.done
	})
	flushGenerationTraffic(t, l, c)
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	for worker := range results {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			tick := time.NewTicker(2 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
				if err != nil {
					workerErrors <- err
					return
				}
				// UDP connect has no peer/listener dependency: success or
				// kernel EPERM, never a TCP timeout/refusal used as an allow.
				start := time.Now()
				err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: 42100 + worker, Addr: [4]byte{127, 0, 0, 1}})
				end := time.Now()
				closeErr := syscall.Close(fd)
				if closeErr != nil {
					workerErrors <- closeErr
					return
				}
				if err != nil && !errors.Is(err, syscall.EPERM) {
					workerErrors <- err
					return
				}
				results[worker] = append(results[worker], generationTrafficAttempt{errors.Is(err, syscall.EPERM), start, end})
				completed.Add(1)
				if len(results[worker]) >= 4500 {
					workerErrors <- errors.New("producer bound exceeded")
					return
				}
			}
		}(worker)
	}
	seenAll := func(id uint64) func([]Event) bool {
		return func(events []Event) bool {
			var seen [4]int
			for _, e := range events {
				if e.PolicyGeneration == id {
					seen[e.RemotePort-42100]++
				}
			}
			for _, count := range seen {
				if count < 4 {
					return false
				}
			}
			return true
		}
	}
	waitGenerationTraffic(t, c, seenAll(1))
	type retiredBarrier struct {
		id    uint64
		index int
	}
	var retired []retiredBarrier
	type publicationWindow struct{ start, end time.Time }
	var publications []publicationWindow
	for id := uint64(2); id <= 6; id++ {
		beforeBuild := completed.Load()
		if err := m.Prepare(id, spec(id)); err != nil {
			t.Fatal(err)
		}
		oldFD := m.active.mapFD
		start := time.Now()
		if err := m.Activate(id); err != nil {
			t.Fatal(err)
		}
		publications = append(publications, publicationWindow{start, time.Now()})
		waitGenerationTraffic(t, c, seenAll(id))
		if m.retiring == nil || m.retiring.mapFD != oldFD {
			t.Fatal("old FD released before acknowledgement")
		}
		if err := m.Prepare(id+1, spec(id+1)); !errors.Is(err, ErrGenerationBusy) {
			t.Fatalf("third buffer admitted: %v", err)
		}
		barrier := flushGenerationTraffic(t, l, c)
		beforeRetire := completed.Load()
		if beforeRetire <= beforeBuild {
			t.Fatal("no producers ran across candidate publication")
		}
		if err := m.AcknowledgeDrain(id - 1); err != nil {
			t.Fatal(err)
		}
		if m.retiring != nil || oldFD.(interface{ FD() int }).FD() != -1 {
			t.Fatal("retired generation FD was not actually closed")
		}
		retired = append(retired, retiredBarrier{id - 1, barrier})
		waitGenerationTraffic(t, c, func([]Event) bool { return completed.Load() >= beforeRetire+16 })
		t.Logf("generation=%d flush-index=%d completions build=%d retire=%d after=%d", id, barrier, beforeBuild, beforeRetire, completed.Load())
	}
	stopWorkers()
	flushGenerationTraffic(t, l, c)
	select {
	case err := <-workerErrors:
		t.Fatal(err)
	default:
	}
	c.mu.Lock()
	events := append([]Event(nil), c.events...)
	c.mu.Unlock()
	var actual [4][]Event
	for _, e := range events {
		worker := int(e.RemotePort - 42100)
		if e.CgroupID != cgid || e.PolicyGeneration < 1 || e.PolicyGeneration > 6 {
			t.Fatalf("invalid traffic scope/generation: %+v", e)
		}
		wantBlocked := (uint64(worker)+e.PolicyGeneration)%2 != 0
		if e.KernelDenied != wantBlocked {
			t.Fatalf("mixed snapshot generation/verdict: %+v wantBlocked=%v", e, wantBlocked)
		}
		actual[worker] = append(actual[worker], e)
	}
	overlapped := 0
	for worker := range results {
		// Each worker has only one outstanding syscall. Its ring submits
		// precede syscall return, so per-endpoint order pairs exact attempts
		// even while all other producers and the pointer switch race.
		if len(actual[worker]) != len(results[worker]) {
			t.Fatalf("worker %d lost/duplicate events: %d syscalls, %d events", worker, len(results[worker]), len(actual[worker]))
		}
		for i, attempt := range results[worker] {
			if actual[worker][i].KernelDenied != attempt.blocked {
				t.Fatalf("worker %d attempt %d syscall blocked=%v event=%+v", worker, i, attempt.blocked, actual[worker][i])
			}
			for _, publication := range publications {
				if attempt.start.Before(publication.end) && attempt.end.After(publication.start) {
					overlapped++
				}
			}
		}
	}
	if overlapped == 0 {
		t.Fatal("no syscall invocation overlapped an activation; insufficient concurrent evidence")
	}
	t.Logf("paired %d syscall/event verdicts; %d connect invocations overlapped pointer publication", len(events), overlapped)
	for _, barrier := range retired {
		for _, e := range events[barrier.index:] {
			if e.PolicyGeneration <= barrier.id {
				t.Fatalf("old generation after flush/retire %d: %+v", barrier.id, e)
			}
		}
	}
	drops, err := l.EventDrops()
	if err != nil {
		t.Fatal(err)
	}
	if drops["connect"] != 0 {
		t.Fatalf("stress verdict evidence lost: %+v", drops)
	}
}

func TestLSM_GenerationFlushQueuedOldNoWakeup(t *testing.T) {
	l, cgid := identityTestLoader(t)
	m := l.PolicyGenerations()
	rule := GenerationRule{CgroupID: cgid, EventType: EventTypeNetwork, Address: "127.0.0.1", Port: 42100, Action: ActionAllow, Audit: true}
	if err := m.Prepare(1, GenerationSpec{Rules: []GenerationRule{rule}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	// Drain loader-time observation events first. No traffic producer has run;
	// after this boundary the reader stays idle until AFTER the pointer switch.
	if err := l.FlushLSMEvents(); err != nil {
		t.Fatal(err)
	}
	initialTimer := time.AfterFunc(10*time.Second, func() { _ = l.lsmReader.Close() })
	defer initialTimer.Stop()
	for {
		_, err := l.ReadLSMEvent()
		if errors.Is(err, ringbuf.ErrFlushed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	initialTimer.Stop()
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	const queued = 7 // 7 * 424 (record+header) < 64KiB wakeup threshold
	for i := 0; i < queued; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: 42100, Addr: [4]byte{127, 0, 0, 1}})
		closeErr := syscall.Close(fd)
		if err != nil || closeErr != nil {
			t.Fatalf("queue audited allow: connect=%v close=%v", err, closeErr)
		}
	}
	// No reader ran during production. Inspect producer/consumer distance: the queued allows
	// must all take BPF_RB_NO_WAKEUP, not an accidental forced denial wakeup.
	if available := l.lsmReader.AvailableBytes(); available < queued*424 || available >= 64*1024 {
		t.Fatalf("NO_WAKEUP precondition: queued bytes=%d", available)
	}
	if err := m.Prepare(2, GenerationSpec{DefaultDeny: []GenerationDomain{{EventType: EventTypeNetwork, Mode: DefaultDenyModeDeny}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(2); err != nil {
		t.Fatal(err)
	}
	if err := l.FlushLSMEvents(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(10*time.Second, func() { _ = l.lsmReader.Close() })
	defer timer.Stop()
	count := 0
	for {
		e, err := l.ReadLSMEvent()
		if errors.Is(err, ringbuf.ErrFlushed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Hook == "connect" {
			if e.PolicyGeneration != 1 || e.KernelDenied || e.RemotePort != 42100 {
				t.Fatalf("queued old event relabelled or verdict changed: %+v", e)
			}
			count++
		}
	}
	if count != queued {
		t.Fatalf("flush lost queued NO_WAKEUP events: got %d want %d", count, queued)
	}
	if err := m.AcknowledgeDrain(1); err != nil {
		t.Fatal(err)
	}
	t.Logf("drained %d old-generation NO_WAKEUP events after switching to generation 2", count)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: 42100, Addr: [4]byte{127, 0, 0, 1}})
	closeErr := syscall.Close(fd)
	if !errors.Is(err, syscall.EPERM) || closeErr != nil {
		t.Fatalf("post-retire generation-2 connect=%v close=%v", err, closeErr)
	}
	for {
		e, err := l.ReadLSMEvent()
		if err != nil {
			t.Fatal(err)
		}
		if e.Hook == "connect" {
			if e.PolicyGeneration != 2 || !e.KernelDenied || e.RemotePort != 42100 {
				t.Fatalf("post-retire generation/verdict drift: %+v", e)
			}
			break
		}
	}
}

func TestLSM_GenerationIntegrityCoexistence(t *testing.T) {
	// The dedicated strict IMA gate MUST run this, not accept a skip. Broad
	// non-IMA kernel suites are not evidence for the coexistence assertion.
	if os.Getenv("WARMOR_REQUIRE_IMA") != "1" {
		t.Skip("requires strict IMA generation gate")
	}
	l, _ := identityTestLoader(t)
	dir, err := os.MkdirTemp("/tmp", "warmor-gen-ima-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(dir); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=8m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(dir, syscall.MNT_DETACH); err != nil {
			t.Error(err)
		}
	})
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	good, bad := filepath.Join(dir, "good"), filepath.Join(dir, "bad")
	if err := os.WriteFile(good, bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, append(bin, 0), 0755); err != nil {
		t.Fatal(err)
	}
	if err := l.EnableIntegrity([]Digest{digestOf(t, good)}, IntegrityEnforce); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.SetIntegrityMode(IntegrityOff); err != nil {
			t.Error(err)
		}
	})
	pm := l.PolicyMap()
	for _, path := range []string{good, bad} {
		if err := pm.SetRule(0, EventTypeExec, path, ActionAllow, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := pm.SetDefaultDeny(EventTypeExec, DefaultDenyModeDeny); err != nil {
		t.Fatal(err)
	}
	check := func(path string, denied bool) {
		t.Helper()
		err := exec.Command(path).Run()
		if (denied && !errors.Is(err, syscall.EPERM)) || (!denied && err != nil) {
			t.Fatalf("integrity/policy exec %s denied=%v: %v", path, denied, err)
		}
	}
	check(good, false)
	check(bad, true)
	m := l.PolicyGenerations()
	for id := uint64(1); id <= 2; id++ {
		rules := []GenerationRule{{EventType: EventTypeExec, Pattern: good, Action: ActionAllow, Audit: true}, {EventType: EventTypeExec, Pattern: bad, Action: ActionAllow, Audit: true}}
		if id == 2 {
			rules[0].Action, rules[0].Audit = ActionDeny, false
		}
		if err := m.Prepare(id, GenerationSpec{Rules: rules, DefaultDeny: []GenerationDomain{{EventType: EventTypeExec, Mode: DefaultDenyModeDeny}}}); err != nil {
			t.Fatal(err)
		}
		if err := m.Activate(id); err != nil {
			t.Fatal(err)
		}
		check(good, id == 2)
		check(bad, true) // exact policy allow never bypasses the integrity LSM
		if err := l.FlushLSMEvents(); err != nil {
			t.Fatal(err)
		}
		timer := time.AfterFunc(10*time.Second, func() { _ = l.lsmReader.Close() })
		defer timer.Stop()
		seenPolicy, seenIntegrity := false, false
		for {
			e, err := l.ReadLSMEvent()
			if errors.Is(err, ringbuf.ErrFlushed) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.IntegrityViolation && e.Filename == bad {
				if e.PolicyGeneration != 0 || !e.KernelDenied {
					t.Fatalf("integrity event ABI drift: %+v", e)
				}
				seenIntegrity = true
			}
			if !e.IntegrityViolation && e.Hook == "exec" && e.Filename == good && e.PolicyGeneration == id {
				if e.KernelDenied != (id == 2) {
					t.Fatalf("generation/integrity verdict drift: %+v", e)
				}
				seenPolicy = true
			}
		}
		timer.Stop()
		if !seenPolicy || !seenIntegrity {
			t.Fatalf("missing coexisting policy/integrity events generation=%d policy=%v integrity=%v", id, seenPolicy, seenIntegrity)
		}
		if err := m.AcknowledgeDrain(id - 1); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := l.IntegrityStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hashed == 0 || stats.Denied < 3 || stats.HashErrors != 0 || stats.LastHashAlgo != 4 {
		t.Fatalf("IMA not actually exercised successfully: %+v", stats)
	}
}
