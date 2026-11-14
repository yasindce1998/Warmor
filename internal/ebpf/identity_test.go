//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/pkg/api"
)

const (
	collisionPathA = "/opt/warmor/collision-000079bb"
	collisionPathB = "/opt/warmor/collision-00044848"
)

func mustStringKey(t *testing.T, scope uint64, typ uint8, path string) PolicyKey {
	t.Helper()
	k, err := stringPolicyKey(scope, typ, path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestExactKeysSeparateDeliberateFNV32Collisions(t *testing.T) {
	if HashPattern(collisionPathA) != HashPattern(collisionPathB) {
		t.Fatal("fixture must collide under old key")
	}
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	for _, scope := range []uint64{0, 42, 43} {
		if err := m.SetRule(scope, EventTypeExec, collisionPathA, ActionAllow, false); err != nil {
			t.Fatal(err)
		}
		if err := m.SetRule(scope, EventTypeExec, collisionPathB, ActionDeny, true); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			path          string
			action, audit uint8
		}{{collisionPathA, ActionAllow, 0}, {collisionPathB, ActionDeny, 1}} {
			if v := b.entries[mustStringKey(t, scope, EventTypeExec, tc.path)]; v.Action != tc.action || v.Audit != tc.audit {
				t.Fatalf("scope %d path %s: %+v", scope, tc.path, v)
			}
		}
	}
	if len(b.entries) != 6 {
		t.Fatal("collision or scope alias")
	}
	if err := m.DeleteRule(42, EventTypeExec, collisionPathA); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.entries[mustStringKey(t, 42, EventTypeExec, collisionPathB)]; !ok {
		t.Fatal("deleting one collision removed the other")
	}

	// Actual colliding FNV32 sockaddr address+port byte sequences.
	a, z := []byte{127, 1, 156, 58, 33, 196}, []byte{127, 1, 248, 57, 95, 205}
	if HashPattern(string(a)) != HashPattern(string(z)) {
		t.Fatal("endpoint fixture must collide")
	}
	ka, err := endpointPolicyKey(42, EventTypeNetwork, "127.1.156.58", 8644)
	if err != nil {
		t.Fatal(err)
	}
	kz, err := endpointPolicyKey(42, EventTypeNetwork, "127.1.248.57", 24525)
	if err != nil {
		t.Fatal(err)
	}
	if ka == kz {
		t.Fatal("endpoint identities alias")
	}
	for _, scope := range []uint64{0, 42, 43} {
		for _, typ := range []uint8{EventTypeNetwork, EventTypeBind} {
			if err := m.SetEndpointRule(scope, typ, "127.1.156.58", 8644, ActionAllow, false); err != nil {
				t.Fatal(err)
			}
			if err := m.SetEndpointRule(scope, typ, "127.1.248.57", 24525, ActionDeny, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if b.entries[ka].Action != ActionAllow || b.entries[kz].Action != ActionDeny || len(b.entries) != 17 {
		t.Fatal("endpoint scope/hook/collision alias")
	}
}

func TestPolicyKeyLayoutMatchesEveryEmbeddedLSMObject(t *testing.T) {
	if binary.Size(PolicyKey{}) != 288 || unsafe.Sizeof(PolicyKey{}) != 288 || binary.Size(PolicyValue{}) != 8 {
		t.Fatal("Go map ABI size")
	}
	// bpf2go includes a leading zero-sized structs.HostLayout marker.
	a, b := reflect.TypeOf(PolicyKey{}), reflect.TypeOf(lsm_execPolicyKey{})
	if a.NumField()+1 != b.NumField() {
		t.Fatal("C/Go field count mismatch")
	}
	for i := 0; i < a.NumField(); i++ {
		if a.Field(i).Offset != b.Field(i+1).Offset || a.Field(i).Type.Size() != b.Field(i+1).Type.Size() {
			t.Fatalf("C/Go field %d layout mismatch", i)
		}
	}
	for name, load := range map[string]func() (*ebpf.CollectionSpec, error){
		"exec": loadLsm_exec, "file": loadLsm_file, "connect": loadLsm_connect, "bind": loadLsm_bind,
		"listen": loadLsm_listen, "mount": loadLsm_mount, "ptrace": loadLsm_ptrace, "integrity": loadLsm_integrity,
	} {
		spec, err := load()
		if err != nil {
			t.Fatal(err)
		}
		m := spec.Maps["policy_map"]
		if m == nil || m.KeySize != 288 || m.ValueSize != 8 {
			t.Fatalf("%s stale map ABI: %+v", name, m)
		}
	}
}

func TestPolicyKeyMarshalBinary(t *testing.T) {
	k := mustStringKey(t, 0x0102030405060708, EventTypeExec, "/opt/café/run")
	k.Pad = [4]byte{1, 2, 3, 4}
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 288 || binary.NativeEndian.Uint64(b[:8]) != k.CgroupID || b[8] != k.EventType ||
		!bytes.Equal(b[28:284], k.Path[:]) || !bytes.Equal(b[284:], make([]byte, 4)) {
		t.Fatalf("key bytes: %x", b)
	}
	for _, tc := range []struct {
		addr   string
		family byte
		raw    []byte
	}{
		{"192.168.1.20", 2, []byte{192, 168, 1, 20}},
		{"2001:db8::1", 10, []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	} {
		k, err := endpointPolicyKey(1, EventTypeBind, tc.addr, 0x1234)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := k.MarshalBinary()
		if b[9] != tc.family || !bytes.Equal(b[10:12], []byte{0x12, 0x34}) || !bytes.Equal(b[12:12+len(tc.raw)], tc.raw) {
			t.Fatalf("endpoint wire bytes: %x", b)
		}
	}
}

func TestStringIdentityBoundsAndLiteralSemantics(t *testing.T) {
	for _, tc := range []struct {
		typ uint8
		max int
	}{{EventTypeExec, 254}, {EventTypeMount, 62}, {EventTypePtrace, 15}} {
		p := strings.Repeat("x", tc.max)
		k := mustStringKey(t, 2, tc.typ, p)
		if string(k.Path[:tc.max]) != p || k.Path[tc.max] != 0 {
			t.Fatal("not full zero-terminated identity")
		}
		if _, err := stringPolicyKey(2, tc.typ, p+"x"); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatal("accepted truncation")
		}
	}
	for _, p := range []string{"", "/bin/sh\x00evil", "/bin/\xff"} {
		if _, err := stringPolicyKey(1, EventTypeExec, p); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("accepted %q", p)
		}
	}
	for _, typ := range []uint8{EventTypeFile, EventTypeNetwork, EventTypeBind, EventTypeListen, 255} {
		if _, err := stringPolicyKey(1, typ, "/bin/sh"); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatal("accepted unsupported string key")
		}
	}
	if mustStringKey(t, 1, EventTypeExec, "/a/../b") == mustStringKey(t, 1, EventTypeExec, "/b") {
		t.Fatal("paths were cleaned")
	}
}

func TestRejectUnsafeAndUnavailableWrites(t *testing.T) {
	m := NewPolicyMapManager(nil)
	if err := m.SetNetworkRule(1, 123, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatal(err)
	}
	for _, addr := range []string{"bogus", "2001:0db8::1", "2001:DB8::1", "::ffff:192.0.2.1", "fe80::1%eth0"} {
		if err := m.SetEndpointRule(1, EventTypeNetwork, addr, 80, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	if err := m.SetRule(1, EventTypeExec, "/bin/sh", 99, false); err == nil {
		t.Fatal("accepted invalid action")
	}
	if err := m.SetRule(1, EventTypeExec, "/bin/sh", ActionAllow, false); err == nil {
		t.Fatal("unloaded map write succeeded")
	}
	if err := m.DeleteRule(1, EventTypeExec, "/bin/sh"); err == nil {
		t.Fatal("unloaded map delete succeeded")
	}
	if err := m.SyncFromWASM([]CachedDecision{{CgroupID: 42, EventType: EventTypeFile, Pattern: "/etc/shadow", Action: ActionDeny}}); err != nil {
		t.Fatal(err)
	}
}

func TestSyncEventRequiresCompleteScopedIdentity(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	for _, n := range []int{128, 254, 255, 256, 300} {
		e := &api.Event{CgroupID: 42, Filename: strings.Repeat("a", n)}
		if err := m.SyncEvent(e, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("len %d: %v", n, err)
		}
	}
	for _, e := range []*api.Event{
		nil, {Filename: "/bin/sh"}, {CgroupID: 42, Filename: "sleep", Hook: "ptrace"},
		{Type: api.EventTypeNetwork, CgroupID: 42, Network: &api.NetworkEvent{Operation: "bind", RemoteAddr: "127.0.0.1", RemotePort: 80}},
		{Type: api.EventTypeFile, CgroupID: 42, Filename: "/etc/shadow"},
	} {
		if err := m.SyncEvent(e, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("accepted incomplete input: %v", err)
		}
	}
	if len(b.entries) != 0 {
		t.Fatal("unsafe inputs modified map")
	}
	e := &api.Event{CgroupID: 42, Filename: strings.Repeat("a", kernelmap.MaxPolicyPathBytes)}
	if err := m.SyncEvent(e, ActionAllow, false); err != nil {
		t.Fatal(err)
	}
	e = &api.Event{Type: api.EventTypeNetwork, CgroupID: 42, Network: &api.NetworkEvent{Operation: "connect", RemoteAddr: "::1", RemotePort: 443}}
	if err := m.SyncEvent(e, ActionDeny, false); err != nil {
		t.Fatal(err)
	}
	if len(b.entries) != 2 {
		t.Fatal("complete decisions not persisted")
	}
}

func TestSyncFromWASMUsesExactKeys(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	if err := m.SyncFromWASM([]CachedDecision{
		{CgroupID: 42, EventType: EventTypeExec, Pattern: collisionPathA, Action: ActionAllow},
		{CgroupID: 42, EventType: EventTypeExec, Pattern: collisionPathB, Action: ActionDeny},
		{CgroupID: 42, EventType: EventTypeFile, Pattern: "/etc/shadow", Action: ActionDeny},
		{CgroupID: 0, EventType: EventTypeExec, Pattern: "/unknown-scope", Action: ActionAllow},
		{CgroupID: 42, EventType: EventTypeExec, Pattern: strings.Repeat("a", 128), Action: ActionAllow},
	}); err != nil {
		t.Fatal(err)
	}
	if len(b.entries) != 2 {
		t.Fatal("unsafe batch decisions persisted or collisions aliased")
	}
}

func TestHashPatternUnixWatchVectors(t *testing.T) {
	if HashPattern("") != 2166136261 || HashPattern("hello") != 0x4f9f2cab {
		t.Fatal("unix watch hash changed")
	}
}

func TestExactEndpointKeySeparatesFamilyPortAndAddressTail(t *testing.T) {
	base, err := endpointPolicyKey(42, EventTypeNetwork, "2001:db8::1", 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		port uint16
	}{
		{"2001:db8::2", 443}, {"2001:db8:1::1", 443},
		{"2001:db8::1", 444}, {"32.1.13.184", 443},
	} {
		key, err := endpointPolicyKey(42, EventTypeNetwork, tc.addr, tc.port)
		if err != nil {
			t.Fatal(err)
		}
		if key == base {
			t.Fatalf("endpoint alias: %+v", tc)
		}
	}
}
