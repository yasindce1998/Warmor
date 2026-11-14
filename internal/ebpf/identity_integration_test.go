//go:build linux && integration

package ebpf

import (
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

	"github.com/yasindce1998/warmor/internal/compiler"
)

// These tests attach enforcing hooks. Run ONLY in an isolated LSM CI VM,
// never against an operator's host. No daemon is started.
func identityTestLoader(t *testing.T) (*LSMLoader, uint64) {
	t.Helper()
	requireRoot(t)
	requireLSM(t)
	cgid, err := GetPIDCgroupID(uint32(os.Getpid()))
	if err != nil || cgid == 0 {
		t.Fatalf("resolve test scope: %d %v", cgid, err)
	}
	l := loadLSMOrSkip(t)
	t.Cleanup(func() { l.Close() })
	if err := l.SetCgroupFilter([]uint64{cgid}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetEnforceMode(true); err != nil {
		t.Fatal(err)
	}
	return l, cgid
}

// Prepending arbitrary bytes to a known FNV collision need not preserve it;
// search after the actual temp-dir prefix instead.
func collidingExecPaths(t *testing.T, dir string) (string, string) {
	t.Helper()
	seen := make(map[uint32]string)
	for i := 0; i < 1000000; i++ {
		p := filepath.Join(dir, fmt.Sprintf("collision-%08x", i))
		h := HashPattern(p)
		if prior, ok := seen[h]; ok && prior != p {
			return prior, p
		}
		seen[h] = p
	}
	t.Fatal("could not find test collision")
	return "", ""
}

func TestLSM_ExactExecCollisionFirstMatchDefaultDenyAndScope(t *testing.T) {
	l, cgid := identityTestLoader(t)
	a, b := collidingExecPaths(t, t.TempDir())
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
	t.Cleanup(func() { pm.ClearDefaultDeny() })
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
		defer ln.Close()
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
	t.Cleanup(func() { pm.ClearDefaultDeny() })
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp4", a, time.Second)
		if err != nil {
			t.Fatalf("colliding allow failed: %v", err)
		}
		conn.Close()
		for _, addr := range []string{b, "127.1.156.58:8645"} {
			conn, err := net.DialTimeout("tcp4", addr, time.Second)
			if conn != nil {
				conn.Close()
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
	t.Cleanup(func() { pm.ClearDefaultDeny() })
	if err := exec.Command(path).Run(); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("truncated exec = %v, want EPERM", err)
	}
}
