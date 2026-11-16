//go:build linux && integration

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/yasindce1998/warmor/internal/compiler"
)

// These tests attach enforcing hooks. Run ONLY in an isolated LSM CI VM,
// never against an operator's host. No daemon is started.
func identityTestLoader(t *testing.T) (*LSMLoader, uint64) {
	t.Helper()
	// An opt-in alone must never authorize these enforcing tests on a host.
	// The existing lower-level CI also runs inside vimto.
	init, err := os.Readlink("/proc/1/exe")
	if err != nil || filepath.Base(init) != "vimto" {
		t.Fatal("exact-identity enforcement tests require the disposable vimto VM")
	}
	ports, err := filepath.Glob("/sys/class/virtio-ports/*/name")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, path := range ports {
		name, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seen[strings.TrimSpace(string(name))] = true
	}
	if !seen["ctrl"] || !seen["stdio"] {
		t.Fatal("exact-identity enforcement tests require vimto private control/stdio ports")
	}
	requireRoot(t)
	requireLSM(t)
	cgid, err := GetPIDCgroupID(uint32(os.Getpid()))
	if err != nil || cgid == 0 {
		t.Fatalf("resolve test scope: %d %v", cgid, err)
	}
	l := loadLSMOrSkip(t)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("close identity test loader: %v", err)
		}
	})
	if err := l.SetCgroupFilter([]uint64{cgid}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetEnforceMode(true); err != nil {
		t.Fatal(err)
	}
	return l, cgid
}

func TestLSM_StopReadersInterruptsIdleMonitors(t *testing.T) {
	l, _ := identityTestLoader(t) // Requires the disposable VM before loading.
	tp, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tp.Close(); err != nil {
			t.Errorf("close idle tracepoint loader: %v", err)
		}
	})
	// No current task can produce events in this reserved test-only scope.
	if err := tp.SetCgroupFilter([]uint64{^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetCgroupFilter([]uint64{^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 4)
	for _, read := range []func() (*Event, error){tp.ReadProcessEvent, tp.ReadFileEvent, tp.ReadNetworkEvent, l.ReadLSMEvent} {
		go func() {
			for {
				if _, err := read(); err != nil {
					results <- err
					return
				}
			}
		}()
	}
	// Let pending startup events drain; idle reads must not return themselves.
	select {
	case err := <-results:
		t.Fatalf("reader returned before stop: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := tp.StopReaders(); err != nil {
		t.Fatal(err)
	}
	if err := l.StopReaders(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ringbuf.ErrClosed) {
				t.Fatalf("stopped read: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("idle reader was not interrupted")
		}
	}
	// StopReaders must not close the policy maps or detach enforcement.
	if _, err := l.PolicyMap().Stats(); err != nil {
		t.Fatalf("StopReaders closed policy resources: %v", err)
	}
}

func TestLSM_ExactExecCollisionFirstMatchDefaultDenyAndScope(t *testing.T) {
	l, cgid := identityTestLoader(t)
	// FNV collisions depend on the entire prefix. A bounded birthday search
	// over sequential filenames can be injective for a random temp directory,
	// even across a million candidates. Reuse the proven full literal paths
	// from the unprivileged identity tests instead: no search or seed assumption.
	// The VM guard above MUST precede this fixed-path creation. Exclusive Mkdir
	// refuses preexisting contents; never reuse, overwrite or clean an old dir.
	a, b := collisionPathA, collisionPathB
	if err := validateExecCollisionPaths(a, b); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(a)
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatalf("create exclusive disposable-VM collision fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove identity fixture: %v", err)
		}
	})
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(filepath.Dir(a), "unknown")
	for _, p := range []string{a, b, unknown} {
		if err := os.WriteFile(p, bin, 0755); err != nil {
			t.Fatal(err)
		}
	}
	p, err := compiler.Parse([]byte(fmt.Sprintf(`name: collision
version: 1
default_action: deny
rules:
  - name: first
    event: process
    conditions:
      all:
        - path: %q
    action: allow
  - name: colliding-deny
    event: process
    conditions:
      all:
        - path: %q
    action: deny
  - name: shadowed
    event: process
    conditions:
      all:
        - path: %q
    action: deny
`, a, b, a)))
	if err != nil {
		t.Fatal(err)
	}
	rules, why := compiler.StaticRules(p)
	if len(why) != 0 || len(rules) != 2 {
		t.Fatalf("static rules: %+v %v", rules, why)
	}
	pm := l.PolicyMap()
	for _, r := range rules {
		if err := pm.SetRule(0, EventTypeExec, r.Pattern, r.Action, r.Audit); err != nil {
			t.Fatal(err)
		}
	}
	if err := pm.defaultDenyMap.Put(DefaultDenyKey{CgroupID: cgid, EventType: EventTypeExec}, uint8(DefaultDenyModeDeny)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pm.ClearDefaultDeny(); err != nil {
			t.Errorf("clear default-deny fixture: %v", err)
		}
	})
	for i := 0; i < 2; i++ {
		if err := exec.Command(a).Run(); err != nil {
			t.Fatalf("first-match allow failed: %v", err)
		}
		for _, p := range []string{b, unknown} {
			if err := exec.Command(p).Run(); !errors.Is(err, syscall.EPERM) {
				t.Fatalf("exec %s = %v, want kernel EPERM", p, err)
			}
		}
	}
	if err := pm.SetRule(cgid+1, EventTypeExec, a, ActionDeny, false); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(a).Run(); err != nil {
		t.Fatalf("other scope leaked: %v", err)
	}
	if err := pm.SetRule(cgid, EventTypeExec, a, ActionDeny, false); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(a).Run(); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("scoped deny = %v", err)
	}
	if err := pm.DeleteRule(cgid, EventTypeExec, a); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(a).Run(); err != nil {
		t.Fatalf("global fallback failed: %v", err)
	}
}

func TestLSM_ExactAuditDeniesAreNotKernelRefusals(t *testing.T) {
	l, cgid := identityTestLoader(t)
	dir, err := os.MkdirTemp("/tmp", "warmor-audit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove audit fixture: %v", err)
		}
	})
	path := filepath.Join(dir, "audited")
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bin, 0755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		enforce, audit bool
	}{{true, true}, {false, false}, {true, false}} {
		if err := l.SetEnforceMode(tc.enforce); err != nil {
			t.Fatal(err)
		}
		if err := l.PolicyMap().SetRule(cgid, EventTypeExec, path, ActionDeny, tc.audit); err != nil {
			t.Fatal(err)
		}
		blocked := tc.enforce && !tc.audit
		err := exec.Command(path).Run()
		if (blocked && !errors.Is(err, syscall.EPERM)) || (!blocked && err != nil) {
			t.Fatalf("enforce=%v audit=%v exec=%v", tc.enforce, tc.audit, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if time.Now().After(deadline) {
				t.Fatal("missing exact audit/refusal event")
			}
			event, err := l.ReadLSMEvent()
			if err != nil {
				continue
			}
			if event.Hook != "exec" || event.Filename != path {
				continue
			}
			if event.KernelDenied != blocked || event.KernelTimestampNS == 0 {
				t.Fatalf("audit must not masquerade as actual kernel refusal: %+v", event)
			}
			break
		}
	}
}

func TestLSM_ExactEndpointCollisionDefaultDeny(t *testing.T) {
	l, cgid := identityTestLoader(t)
	a, b := "127.1.156.58:8644", "127.1.248.57:24525"
	if HashPattern(string([]byte{127, 1, 156, 58, 33, 196})) != HashPattern(string([]byte{127, 1, 248, 57, 95, 205})) {
		t.Fatal("fixture does not collide")
	}
	for _, addr := range []string{a, b} {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ln.Close(); err != nil {
				t.Errorf("close collision listener: %v", err)
			}
		})
	}
	pm := l.PolicyMap()
	if err := pm.SetEndpointRule(0, EventTypeNetwork, "127.1.156.58", 8644, ActionAllow, false); err != nil {
		t.Fatal(err)
	}
	if err := pm.SetEndpointRule(0, EventTypeNetwork, "127.1.248.57", 24525, ActionDeny, false); err != nil {
		t.Fatal(err)
	}
	if err := pm.defaultDenyMap.Put(DefaultDenyKey{CgroupID: cgid, EventType: EventTypeNetwork}, uint8(DefaultDenyModeDeny)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pm.ClearDefaultDeny(); err != nil {
			t.Errorf("clear endpoint default-deny fixture: %v", err)
		}
	})
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp4", a, time.Second)
		if err != nil {
			t.Fatalf("colliding allow failed: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		for _, addr := range []string{b, "127.1.156.58:8645"} {
			conn, err := net.DialTimeout("tcp4", addr, time.Second)
			if conn != nil {
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}
			if !errors.Is(err, syscall.EPERM) {
				t.Fatalf("connect %s = %v, want kernel EPERM", addr, err)
			}
		}
	}
}

func TestLSM_TruncatedExecCannotHitExactAllow(t *testing.T) {
	l, cgid := identityTestLoader(t)
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 100))
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, strings.Repeat("x", 255-len(dir)-1))
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bin, 0755); err != nil {
		t.Fatal(err)
	}
	pm := l.PolicyMap()
	// Even raw-map entries must not bypass the hook's full-buffer guard.
	key := PolicyKey{CgroupID: cgid, EventType: EventTypeExec}
	copy(key.Path[:], path)
	if err := pm.policyMap.Put(key, PolicyValue{Action: ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if err := pm.defaultDenyMap.Put(DefaultDenyKey{CgroupID: cgid, EventType: EventTypeExec}, uint8(DefaultDenyModeDeny)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pm.ClearDefaultDeny(); err != nil {
			t.Errorf("clear truncated-path default-deny fixture: %v", err)
		}
	})
	if err := exec.Command(path).Run(); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("truncated exec = %v, want EPERM", err)
	}
}

func TestLSM_ExactIPv6AndMappedEndpointIdentities(t *testing.T) {
	l, _ := identityTestLoader(t)
	pm := l.PolicyMap()
	for _, tc := range []struct {
		name, network, bind, policyAddr string
		addr                            [16]byte
	}{
		{"ipv6", "tcp6", "[::1]:0", "::1", [16]byte{15: 1}},
		{"mapped-ipv4", "tcp4", "127.0.0.1:0", "127.0.0.1", [16]byte{10: 255, 11: 255, 12: 127, 15: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen(tc.network, tc.bind)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := ln.Close(); err != nil {
					t.Errorf("close endpoint listener: %v", err)
				}
			})
			addr, ok := ln.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatalf("endpoint listener has unexpected address type %T", ln.Addr())
			}
			port := uint16(addr.Port)
			connect := func(length uintptr) error {
				// Force sockaddr_in6, including for mapped IPv4; net.Dial
				// would otherwise select an IPv4 socket automatically.
				fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
				if err != nil {
					return err
				}
				defer func() {
					if err := syscall.Close(fd); err != nil {
						t.Errorf("close IPv6 test socket: %v", err)
					}
				}()
				var address [28]byte
				binary.NativeEndian.PutUint16(address[:2], syscall.AF_INET6)
				binary.BigEndian.PutUint16(address[2:4], port)
				copy(address[8:24], tc.addr[:])
				_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address[0])), length)
				if errno != 0 {
					return errno
				}
				return nil
			}
			if err := pm.SetEndpointRule(0, EventTypeNetwork, tc.policyAddr, port, ActionDeny, false); err != nil {
				t.Fatal(err)
			}
			for _, length := range []uintptr{24, 28} {
				if err := connect(length); !errors.Is(err, syscall.EPERM) {
					t.Fatalf("IPv6 length %d exact deny = %v, want kernel EPERM", length, err)
				}
			}
			if err := pm.SetEndpointRule(0, EventTypeNetwork, tc.policyAddr, port, ActionAllow, false); err != nil {
				t.Fatal(err)
			}
			if err := connect(28); err != nil {
				t.Fatalf("IPv6 exact allow = %v", err)
			}
		})
	}
}
