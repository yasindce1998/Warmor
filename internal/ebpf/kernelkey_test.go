//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/kernelmap"
	"github.com/yasindce1998/warmor/pkg/api"
)

// TestKernelKeyPathBoundary pins the shared exact-path identity limit at the
// kernel-map write API: 127 bytes are accepted verbatim, 128 and 254 are
// refused with ErrNotKernelMatchable rather than silently truncated into a key
// a raw writer could use to allow a path WASM only saw as a truncated prefix.
func TestKernelKeyPathBoundary(t *testing.T) {
	const limit = kernelmap.MaxPolicyPathBytes // 127
	atLimit := strings.Repeat("p", limit)

	k, err := stringPolicyKey(42, EventTypeExec, atLimit)
	if err != nil {
		t.Fatalf("len %d must be accepted: %v", limit, err)
	}
	if string(k.Path[:limit]) != atLimit || k.Path[limit] != 0 {
		t.Fatal("127-byte key must be the full, zero-terminated identity")
	}

	for _, n := range []int{128, 254} {
		if _, err := stringPolicyKey(42, EventTypeExec, strings.Repeat("q", n)); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("len %d: got %v, want ErrNotKernelMatchable", n, err)
		}
	}
}

// TestKernelKeyLengthLimitAppliesToAllStringDomains covers every policy-
// decision domain keyed by a string (exec, mount, ptrace). Mount and ptrace are
// bounded even tighter by their sensor buffers, but must also never admit a
// pattern beyond the shared 127-byte identity limit.
func TestKernelKeyLengthLimitAppliesToAllStringDomains(t *testing.T) {
	for _, typ := range []uint8{EventTypeExec, EventTypeMount, EventTypePtrace} {
		if _, err := stringPolicyKey(42, typ, strings.Repeat("z", 254)); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("event type %d accepted a 254-byte pattern", typ)
		}
	}
}

// TestSetRuleRejectsOverlongPathWithoutTruncation checks the public kernel-map
// write API directly: a 127-byte path is stored in full, while an over-long
// path is refused without installing a truncated prefix key.
func TestSetRuleRejectsOverlongPathWithoutTruncation(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	const limit = kernelmap.MaxPolicyPathBytes

	atLimit := strings.Repeat("a", limit)
	if err := m.SetRule(0, EventTypeExec, atLimit, ActionAllow, false); err != nil {
		t.Fatalf("127-byte rule must be accepted: %v", err)
	}
	if len(b.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(b.entries))
	}

	// 254 bytes of a distinct character: its first 127 bytes are NOT the
	// legitimate entry above, so a truncated-key regression is detectable.
	overlong := strings.Repeat("c", 254)
	if err := m.SetRule(0, EventTypeExec, overlong, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("SetRule(254-byte path) = %v, want ErrNotKernelMatchable", err)
	}
	if len(b.entries) != 1 {
		t.Fatalf("over-long rule installed %d extra entries", len(b.entries)-1)
	}
	if _, ok := b.entries[mustStringKey(t, 0, EventTypeExec, overlong[:limit])]; ok {
		t.Fatal("a truncated 127-byte prefix key was installed")
	}
	if v := b.entries[mustStringKey(t, 0, EventTypeExec, atLimit)]; v.Action != ActionAllow {
		t.Fatal("the legitimate 127-byte entry was disturbed")
	}
}

// preloadExecAllowlist models the enforcer's default-deny preload sequence:
// write every global-domain static rule first, and only mark the domain
// default-deny after all writes succeed. It uses only PolicyMapManager APIs.
func preloadExecAllowlist(t *testing.T, m *PolicyMapManager, patterns []string) error {
	t.Helper()
	for _, p := range patterns {
		if err := m.SetRule(0, EventTypeExec, p, ActionAllow, false); err != nil {
			return err
		}
	}
	return m.SetDefaultDeny(EventTypeExec, DefaultDenyModeDeny)
}

// TestDefaultDenyPreloadRejectsOverlongRule verifies the complete-allowlist
// property: an over-long rule aborts preload, so neither a truncated allow key
// nor the default-deny marking (which would deny its misses) is installed.
func TestDefaultDenyPreloadRejectsOverlongRule(t *testing.T) {
	b := newFakeBackend()
	dd := &fakeDefaultDenyBackend{}
	m := &PolicyMapManager{policyMap: b, defaultDenyMap: dd}

	valid := strings.Repeat("v", kernelmap.MaxPolicyPathBytes)
	overlong := strings.Repeat("o", 254)

	if err := preloadExecAllowlist(t, m, []string{valid, overlong}); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("preload err = %v, want ErrNotKernelMatchable", err)
	}
	if _, ok := b.entries[mustStringKey(t, 0, EventTypeExec, overlong[:kernelmap.MaxPolicyPathBytes])]; ok {
		t.Fatal("preload installed a truncated key for the over-long rule")
	}
	if _, marked := dd.entries[DefaultDenyKey{EventType: EventTypeExec}]; marked {
		t.Fatal("domain was marked default-deny despite a rejected rule")
	}
}

// TestSyncFromWASMSkipsOverlongRuleWithoutTruncatedKey covers the batch
// preload path: an over-long pattern is skipped, with no truncated key left in
// the map. Userspace WASM evaluation of the full path is unaffected.
func TestSyncFromWASMSkipsOverlongRuleWithoutTruncatedKey(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}
	overlong := strings.Repeat("s", 254)

	if err := m.SyncFromWASM([]CachedDecision{{
		CgroupID: 42, EventType: EventTypeExec, Pattern: overlong, Action: ActionAllow,
	}}); err != nil {
		t.Fatal(err)
	}
	if len(b.entries) != 0 {
		t.Fatalf("SyncFromWASM installed %d entries for an over-long rule", len(b.entries))
	}
	if _, ok := b.entries[mustStringKey(t, 42, EventTypeExec, overlong[:kernelmap.MaxPolicyPathBytes])]; ok {
		t.Fatal("SyncFromWASM installed a truncated prefix key")
	}
}

// TestListenPolicyKeyWireBytes pins the exact 288-byte layout of the listen
// key against lsm_listen.bpf.c: only cgroup_id, EVENT_TYPE_LISTEN, the raw
// skc_family and the big-endian port are set. The address, path and pad bytes
// are never populated by the kernel hook and must stay zero.
func TestListenPolicyKeyWireBytes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		family     uint8
		port       uint16
		wantFamily byte
		wantPort   []byte
	}{
		{"v4", 2, 8080, 2, []byte{0x1f, 0x90}},  // 8080 = 0x1f90
		{"v6", 10, 443, 10, []byte{0x01, 0xbb}}, // 443 = 0x01bb
		{"v4 edge", 2, 0x1234, 2, []byte{0x12, 0x34}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := listenPolicyKey(0x0102030405060708, tc.family, tc.port)
			b, err := k.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != 288 {
				t.Fatalf("key length = %d, want 288", len(b))
			}
			if binary.NativeEndian.Uint64(b[:8]) != 0x0102030405060708 {
				t.Fatalf("cgroup bytes = %x", b[:8])
			}
			if b[8] != EventTypeListen {
				t.Fatalf("event_type = %d, want %d", b[8], EventTypeListen)
			}
			if b[9] != tc.wantFamily {
				t.Fatalf("family = %d, want %d", b[9], tc.wantFamily)
			}
			if !bytes.Equal(b[10:12], tc.wantPort) {
				t.Fatalf("port bytes = %x, want %x", b[10:12], tc.wantPort)
			}
			// address[16] + path[256] + pad[4] = 276 zero bytes.
			if tail := b[12:]; !bytes.Equal(tail, make([]byte, len(tail))) {
				t.Fatalf("listen key tail (address/path/pad) is not zero: %x", tail)
			}
		})
	}
}

// TestConnectBindKeysRemainByteIdentical guards the requirement that adding
// listen support does not perturb the existing connect/bind endpoint keys:
// family, big-endian port and the canonical address bytes are unchanged for
// both EVENT_TYPE_NETWORK and EVENT_TYPE_BIND.
func TestConnectBindKeysRemainByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		addr   string
		family byte
		raw    []byte
	}{
		{"192.168.1.20", 2, []byte{192, 168, 1, 20}},
		{"2001:db8::1", 10, []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	} {
		for _, typ := range []uint8{EventTypeNetwork, EventTypeBind} {
			k, err := endpointPolicyKey(1, typ, tc.addr, 0x1234)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := k.MarshalBinary()
			if b[8] != typ || b[9] != tc.family ||
				!bytes.Equal(b[10:12], []byte{0x12, 0x34}) ||
				!bytes.Equal(b[12:12+len(tc.raw)], tc.raw) {
				t.Fatalf("domain %d %s wire bytes changed: %x", typ, tc.addr, b)
			}
			// Every byte past the address must still be zero for an endpoint key.
			if tail := b[12+len(tc.raw):]; !bytes.Equal(tail, make([]byte, len(tail))) {
				t.Fatalf("domain %d %s nonzero tail: %x", typ, tc.addr, tail)
			}
		}
	}
}

// TestMountPolicyKeyWireBytes pins the exact 288-byte mount key against
// lsm_mount.bpf.c: only cgroup_id, EVENT_TYPE_MOUNT and the fstype bytes in
// path[0..len] are set; family/port/address and the rest of path and pad stay
// zero. There is no source/target field: dev_name is aux-only in the hook.
func TestMountPolicyKeyWireBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fstype string
	}{
		{"ext4", "ext4"},
		{"proc", "proc"},
		{"max", strings.Repeat("f", maxMountPatternLen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := mountPolicyKey(0x0102030405060708, tc.fstype)
			if err != nil {
				t.Fatal(err)
			}
			b, err := k.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != 288 {
				t.Fatalf("key length = %d, want 288", len(b))
			}
			if binary.NativeEndian.Uint64(b[:8]) != 0x0102030405060708 {
				t.Fatalf("cgroup bytes = %x", b[:8])
			}
			if b[8] != EventTypeMount {
				t.Fatalf("event_type = %d, want %d", b[8], EventTypeMount)
			}
			if !bytes.Equal(b[28:28+len(tc.fstype)], []byte(tc.fstype)) {
				t.Fatalf("fstype bytes = %x, want %q", b[28:28+len(tc.fstype)], tc.fstype)
			}
			// family/port/address are never set by the mount hook.
			if !bytes.Equal(b[9:28], make([]byte, 19)) {
				t.Fatalf("family/port/address nonzero: %x", b[9:28])
			}
			// The rest of path (after the fstype) and the pad stay zero.
			if tail := b[28+len(tc.fstype):]; !bytes.Equal(tail, make([]byte, len(tail))) {
				t.Fatalf("mount key tail is not zero: %x", tail)
			}
		})
	}
}

// TestMountKeySeparateFromFileOpenDomain checks the two file-kind hooks stay
// distinct: an LSM mount event is keyed in EVENT_TYPE_MOUNT, while a plain
// file_open event (same Kind=File, different Hook) has no exact kernel key and
// is refused. A fstype deny can never leak into the file_open domain.
func TestMountKeySeparateFromFileOpenDomain(t *testing.T) {
	mount := &api.Event{
		Type: api.EventTypeFile, CgroupID: 42, LSMEvent: true, Hook: "mount",
		Filename: "tmpfs", File: &api.FileEvent{Path: "tmpfs"},
	}
	km, err := eventPolicyKey(mount)
	if err != nil {
		t.Fatal(err)
	}
	if km.EventType != EventTypeMount || km.EventType == EventTypeFile {
		t.Fatalf("mount event type = %d, want EVENT_TYPE_MOUNT", km.EventType)
	}
	if got := string(km.Path[:5]); got != "tmpfs" {
		t.Fatalf("mount key fstype = %q, want tmpfs", got)
	}
	// A file_open event with the same Path must not become a kernel key at all.
	fileOpen := &api.Event{
		Type: api.EventTypeFile, CgroupID: 42, LSMEvent: true, Hook: "file",
		Filename: "tmpfs", File: &api.FileEvent{Path: "tmpfs"},
	}
	if _, err := eventPolicyKey(fileOpen); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("file_open event was keyed: %v", err)
	}
	fileOpen.Hook = ""
	if _, err := eventPolicyKey(fileOpen); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("empty-hook file event was keyed: %v", err)
	}
}

// TestMountOverlongFstypeRejectedWithoutTruncatedKey verifies a >=64-byte
// fstype (which lsm_mount would treat as truncated and skip) is refused by the
// public write path, leaving no truncated key that BPF could never match.
func TestMountOverlongFstypeRejectedWithoutTruncatedKey(t *testing.T) {
	b := newFakeBackend()
	m := &PolicyMapManager{policyMap: b}

	// A 62-byte fstype is the longest accepted identity.
	fstype := strings.Repeat("x", maxMountPatternLen)
	mount := &api.Event{
		Type: api.EventTypeFile, CgroupID: 42, LSMEvent: true, Hook: "mount",
		File: &api.FileEvent{Path: fstype},
	}
	if err := m.SyncEvent(mount, ActionDeny, false); err != nil {
		t.Fatalf("%d-byte fstype must be accepted: %v", maxMountPatternLen, err)
	}
	if len(b.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(b.entries))
	}

	// 63/64/128 bytes are all refused, with no truncated prefix installed.
	for _, n := range []int{63, 64, 128} {
		long := strings.Repeat("y", n)
		ev := &api.Event{
			Type: api.EventTypeFile, CgroupID: 42, LSMEvent: true, Hook: "mount",
			File: &api.FileEvent{Path: long},
		}
		if err := m.SyncEvent(ev, ActionDeny, false); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("%d-byte fstype: got %v, want ErrNotKernelMatchable", n, err)
		}
	}
	if len(b.entries) != 1 {
		t.Fatalf("overlong fstypes installed %d extra entries", len(b.entries)-1)
	}
	if _, ok := b.entries[mustMountKey(t, 42, strings.Repeat("y", maxMountPatternLen))]; ok {
		t.Fatal("a truncated mount fstype prefix key was installed")
	}
	if v := b.entries[mustMountKey(t, 42, fstype)]; v.Action != ActionDeny {
		t.Fatal("the legitimate mount entry was disturbed")
	}
}

func mustMountKey(t *testing.T, scope uint64, fstype string) PolicyKey {
	t.Helper()
	k, err := mountPolicyKey(scope, fstype)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestPtracePolicyKeyWireBytes pins the exact 288-byte layout that
// lsm_ptrace.bpf.c looks up: cgroup_id is the TARGET's cgroup (not the
// tracer's), event_type is EVENT_TYPE_PTRACE, path holds the target's comm
// and every unused byte is zero. This is the key a DENY feedback writes.
func TestPtracePolicyKeyWireBytes(t *testing.T) {
	const targetCGID = uint64(0x0102030405060708)
	k, err := ptracePolicyKey(targetCGID, "sleep")
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 288 {
		t.Fatalf("key length = %d, want 288", len(b))
	}
	if got := binary.NativeEndian.Uint64(b[:8]); got != targetCGID {
		t.Fatalf("cgroup bytes = %x, want target cgroup %x", got, targetCGID)
	}
	if b[8] != EventTypePtrace {
		t.Fatalf("event_type = %d, want %d", b[8], EventTypePtrace)
	}
	if !bytes.Equal(b[28:28+5], []byte("sleep")) || b[33] != 0 {
		t.Fatalf("target comm bytes = %q, want zero-terminated sleep", b[28:40])
	}
	// family, port, address, the rest of path and pad are all unused.
	if tail := b[9:28]; !bytes.Equal(tail, make([]byte, len(tail))) {
		t.Fatalf("nonzero key prefix before path: %x", tail)
	}
	if tail := b[33:]; !bytes.Equal(tail, make([]byte, len(tail))) {
		t.Fatalf("nonzero key tail after comm: %x", tail)
	}

	// The BPF side writes the same bytes: target cgroup in cgroup_id, the
	// 16-byte comm buffer at the start of path. A Go key with a 15-byte comm
	// (TASK_COMM_LEN 16 minus NUL) must match that buffer byte-for-byte.
	var commBuf [16]byte
	copy(commBuf[:], "sleep")
	if !bytes.Equal(b[28:44], commBuf[:]) {
		t.Fatalf("comm buffer mismatch: %x vs %x", b[28:44], commBuf)
	}

	// Domain separation: the same comm and cgroup in the exec domain, or a
	// different target cgroup in the ptrace domain, must produce different
	// keys. Otherwise a deny could be applied to another domain/container.
	execKey, err := stringPolicyKey(targetCGID, EventTypeExec, "sleep")
	if err != nil {
		t.Fatal(err)
	}
	if k == execKey {
		t.Fatal("ptrace key aliased the exec domain for the same comm/cgroup")
	}
	other, err := ptracePolicyKey(targetCGID+1, "sleep")
	if err != nil {
		t.Fatal(err)
	}
	if k == other {
		t.Fatal("target cgroup does not distinguish two same-comm targets")
	}
	otherComm, err := ptracePolicyKey(targetCGID, "sshd")
	if err != nil {
		t.Fatal(err)
	}
	if k == otherComm {
		t.Fatal("target comm does not distinguish two same-cgroup targets")
	}

	// A zero target cgroup would be a wildcard deny over every container.
	if _, err := ptracePolicyKey(0, "sleep"); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("zero target cgroup: %v", err)
	}
	for _, comm := range []string{"", "a\x00b", strings.Repeat("x", 16)} {
		if _, err := ptracePolicyKey(targetCGID, comm); !errors.Is(err, ErrNotKernelMatchable) {
			t.Fatalf("comm %q: %v", comm, err)
		}
	}
}

// TestEventPolicyKeyPtraceUsesTargetIdentity checks the dynamic write-back
// path: a ptrace PROCESS LSM event is keyed by the target identity from the
// event (TargetCgroupID from aux_id, Filename/Process.Filename from the
// sensor's comm buffer), never by the tracer's cgroup or comm.
func TestEventPolicyKeyPtraceUsesTargetIdentity(t *testing.T) {
	newPtrace := func() *api.Event {
		return &api.Event{
			Type: api.EventTypeProcess, CgroupID: 99, Comm: "tracer",
			LSMEvent: true, Hook: "ptrace", Filename: "sleep", TargetCgroupID: 4242,
			Process: &api.ProcessEvent{Filename: "sleep"},
		}
	}
	got, err := eventPolicyKey(newPtrace())
	if err != nil {
		t.Fatal(err)
	}
	want, err := ptracePolicyKey(4242, "sleep")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ptrace key = %+v, want target-scoped %+v", got, want)
	}
	if got.CgroupID == 99 {
		t.Fatal("ptrace key used the tracer cgroup instead of the target cgroup")
	}

	// Without a target cgroup the identity is incomplete: it would be a
	// wildcard over all containers, so it is refused.
	e := newPtrace()
	e.TargetCgroupID = 0
	if _, err := eventPolicyKey(e); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatalf("missing target cgroup: %v", err)
	}

	// An exec PROCESS event with the same comm stays in the exec domain.
	exec := newPtrace()
	exec.Hook = "exec"
	exec.TargetCgroupID = 0
	exec.Filename = "/bin/sleep"
	exec.Process.Filename = "/bin/sleep"
	ek, err := eventPolicyKey(exec)
	if err != nil {
		t.Fatal(err)
	}
	if ek.EventType != EventTypeExec || ek == got {
		t.Fatalf("exec key = %+v, want EVENT_TYPE_EXEC distinct from ptrace", ek)
	}
}

// TestPtraceKernelKeySoundness pins the fields the enforcer may rely on for
// ptrace write-back: target comm ("path") and target cgroup ("cgroup_id").
// Anything else the policy reads — uid, ppid, the tracer comm, or temporal
// context — cannot be reproduced by that key and must be refused.
func TestPtraceKernelKeySoundness(t *testing.T) {
	m := &PolicyMapManager{}
	ev := &api.Event{
		Type: api.EventTypeProcess, CgroupID: 99, LSMEvent: true,
		Hook: "ptrace", Filename: "sleep", TargetCgroupID: 4242,
	}
	keyFields := m.KernelKeyFieldsForEvent(ev)
	want := []string{"path", "cgroup_id"}
	if !reflect.DeepEqual(keyFields, want) {
		t.Fatalf("ptrace key fields = %v, want %v", keyFields, want)
	}
	covered := compiler.FieldMask(keyFields...)
	for _, tc := range []struct {
		name   string
		fields uint32
		want   bool
	}{
		{"target identity only", covered, true},
		{"constant decision", 0, true},
		{"target comm only", compiler.FieldBitPath, true},
		{"uid", covered | compiler.FieldBitUID, false},
		{"ppid", covered | compiler.FieldBitPPID, false},
		{"tracer comm", covered | compiler.FieldBitComm, false},
		{"args", covered | compiler.FieldBitArgs, false},
		{"wall clock", covered | compiler.FieldBitTime, false},
		{"container age", covered | compiler.FieldBitContainerAge, false},
		{"undeclared", compiler.FieldsUnknown, false},
	} {
		got := tc.fields&^covered == 0 && tc.fields != compiler.FieldsUnknown
		if got != tc.want {
			t.Errorf("%s: determined=%v, want %v", tc.name, got, tc.want)
		}
	}
}
