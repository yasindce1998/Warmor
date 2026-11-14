//go:build linux && integration

package ebpf

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/yasindce1998/warmor/pkg/api"
)

// These attach enforcing hooks ONLY after identityTestLoader proves the
// disposable vimto VM. Do not run against a host, including with sudo.
// CI runs them on both the regular kernels and the built Linux 6.1 LTS kernel.
func TestLSM_GenerationPrepareSwitchRetireExec(t *testing.T) {
	l, cgid := identityTestLoader(t)
	dir, err := os.MkdirTemp("/tmp", "warmor-gen-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	a, b := collidingExecPaths(t, dir)
	unknown := filepath.Join(dir, "unknown")
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a, b, unknown} {
		if err := os.WriteFile(path, bin, 0755); err != nil {
			t.Fatal(err)
		}
	}
	pm := l.PolicyMap()
	if err := pm.SetRule(0, EventTypeExec, a, ActionAllow, false); err != nil {
		t.Fatal(err)
	}
	if err := pm.SetDefaultDeny(EventTypeExec, DefaultDenyModeDeny); err != nil {
		t.Fatal(err)
	}
	assertExec := func(path string, blocked bool) {
		t.Helper()
		err := exec.Command(path).Run()
		if (blocked && !errors.Is(err, syscall.EPERM)) || (!blocked && err != nil) {
			t.Fatalf("exec %s = %v, blocked=%v", path, err, blocked)
		}
	}
	assertExec(a, false)
	assertExec(unknown, true)
	m := l.PolicyGenerations()
	first := GenerationSpec{
		Rules: []GenerationRule{
			{EventType: EventTypeExec, Pattern: a, Action: ActionAllow},
			{EventType: EventTypeExec, Pattern: b, Action: ActionDeny, Audit: true},
			{CgroupID: cgid + 1, EventType: EventTypeExec, Pattern: a, Action: ActionDeny},
		},
		DefaultDeny: []GenerationDomain{{EventType: EventTypeExec, Mode: DefaultDenyModeDeny}},
	}
	if err := m.Prepare(1, first); err != nil {
		t.Fatal(err)
	}
	// A fully prepared candidate must not soften the legacy default-deny.
	assertExec(unknown, true)
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	assertExec(a, false)
	assertExec(b, false) // audited deny is NOT a kernel refusal, even on collision
	assertExec(unknown, true)
	readGeneration := func(path string, generation uint64, blocked bool) {
		t.Helper()
		// Bound missing-event failures without a goroutine left reading a
		// closed loader. ReadLSMEvent normally retries its short deadlines.
		timer := time.AfterFunc(5*time.Second, func() { _ = l.lsmReader.Close() })
		defer timer.Stop()
		for {
			event, err := l.ReadLSMEvent()
			if err != nil {
				t.Fatalf("read generation event: %v", err)
			}
			if event.Hook == "exec" && event.Filename == path && event.PolicyGeneration == generation {
				if event.KernelDenied != blocked {
					t.Fatalf("generation audit/refusal drift: %+v", event)
				}
				return
			}
		}
	}
	readGeneration(b, 1, false)
	drain := func() {
		t.Helper()
		if err := l.FlushLSMEvents(); err != nil {
			t.Fatal(err)
		}
		timer := time.AfterFunc(5*time.Second, func() { _ = l.lsmReader.Close() })
		defer timer.Stop()
		for {
			_, err := l.ReadLSMEvent()
			if errors.Is(err, ringbuf.ErrFlushed) {
				return
			}
			if err != nil {
				t.Fatalf("drain generation events: %v", err)
			}
		}
	}
	// This fixture has no evaluator workers; the production integration must
	// additionally wait for their old-generation references before acknowledging.
	drain()
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	oldFD := m.active.mapFD
	second := GenerationSpec{
		Rules:       []GenerationRule{{CgroupID: cgid, EventType: EventTypeExec, Pattern: a, Action: ActionDeny}},
		DefaultDeny: first.DefaultDeny,
	}
	if err := m.Prepare(2, second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		assertExec(unknown, true)
		assertExec(a, false)
	}
	if err := m.Activate(2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		assertExec(unknown, true)
		assertExec(a, true)
		assertExec(b, true)
	}
	readGeneration(a, 2, true)
	if err := m.SyncEvent(1, &api.Event{Type: api.EventTypeProcess, CgroupID: cgid, Filename: a}, ActionAllow, false); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	assertExec(a, true)
	if m.retiring == nil || m.retiring.mapFD != oldFD {
		t.Fatal("old map not retained")
	}
	if err := m.Prepare(3, first); !errors.Is(err, ErrGenerationBusy) {
		t.Fatal(err)
	}
	drain()
	if err := m.AcknowledgeDrain(1); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(3, first); err != nil {
		t.Fatal(err)
	}
	if err := m.Abort(3); err != nil {
		t.Fatal(err)
	}
	assertExec(a, true)
}

func TestLSM_GenerationEndpointCollisionAndDynamicScope(t *testing.T) {
	l, cgid := identityTestLoader(t)
	for _, addr := range []string{"127.1.156.58:8644", "127.1.248.57:24525"} {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ln.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	m := l.PolicyGenerations()
	if err := m.Prepare(1, GenerationSpec{
		Rules:       []GenerationRule{{EventType: EventTypeNetwork, Address: "127.1.156.58", Port: 8644, Action: ActionAllow}},
		DefaultDeny: []GenerationDomain{{EventType: EventTypeNetwork, Mode: DefaultDenyModeDeny}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	dial := func(addr string, blocked bool) {
		t.Helper()
		conn, err := net.DialTimeout("tcp4", addr, time.Second)
		if conn != nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		if (blocked && !errors.Is(err, syscall.EPERM)) || (!blocked && err != nil) {
			t.Fatalf("connect %s = %v, blocked=%v", addr, err, blocked)
		}
	}
	dial("127.1.156.58:8644", false)
	dial("127.1.248.57:24525", true)
	event := &api.Event{Type: api.EventTypeNetwork, Hook: "connect", CgroupID: cgid + 1,
		Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "127.1.248.57", RemotePort: 24525}}
	if err := m.SyncEvent(1, event, ActionAllow, false); err != nil {
		t.Fatal(err)
	}
	dial("127.1.248.57:24525", true) // another cgroup's decision must not allow us
	event.CgroupID = cgid
	if err := m.SyncEvent(1, event, ActionAllow, false); err != nil {
		t.Fatal(err)
	}
	dial("127.1.248.57:24525", false)
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(2, GenerationSpec{DefaultDeny: []GenerationDomain{{EventType: EventTypeNetwork, Mode: DefaultDenyModeDeny}}}); err != nil {
		t.Fatal(err)
	}
	dial("127.1.156.58:8644", false)
	if err := m.Activate(2); err != nil {
		t.Fatal(err)
	}
	dial("127.1.156.58:8644", true)
	dial("127.1.248.57:24525", true)
	if err := m.SyncEvent(1, event, ActionAllow, false); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	dial("127.1.248.57:24525", true)
}
