//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/yasindce1998/warmor/pkg/api"
)

type fakeGenerationMap struct {
	entries   map[PolicyKey]generationValue
	putErr    error
	failAfter int
	closeErr  error
	closes    int
}

func (f *fakeGenerationMap) Put(key, value any) error {
	if f.putErr != nil && len(f.entries) >= f.failAfter {
		return f.putErr
	}
	f.entries[key.(PolicyKey)] = value.(generationValue)
	return nil
}

func (f *fakeGenerationMap) Close() error {
	f.closes++
	return f.closeErr
}

type fakeGenerationBackend struct {
	maps                                         []*fakeGenerationMap
	active                                       *fakeGenerationMap
	createErr, populateErr, closeErr, publishErr error
	failAfter                                    int
	publications                                 int
}

func (f *fakeGenerationBackend) create() (generationMap, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	m := &fakeGenerationMap{entries: make(map[PolicyKey]generationValue), putErr: f.populateErr, closeErr: f.closeErr, failAfter: f.failAfter}
	f.maps = append(f.maps, m)
	return m, nil
}

func (f *fakeGenerationBackend) publish(m generationMap) error {
	if f.publishErr != nil {
		return f.publishErr
	}
	f.active = m.(*fakeGenerationMap)
	f.publications++
	return nil
}

func generationFixture() GenerationSpec {
	return GenerationSpec{
		Rules: []GenerationRule{
			{EventType: EventTypeExec, Pattern: collisionPathA, Action: ActionAllow, Audit: true},
			{EventType: EventTypeExec, Pattern: collisionPathB, Action: ActionDeny},
			{CgroupID: 43, EventType: EventTypeExec, Pattern: collisionPathA, Action: ActionDeny, Audit: true},
			{EventType: EventTypeNetwork, Address: "127.1.156.58", Port: 8644, Action: ActionAllow},
			{EventType: EventTypeNetwork, Address: "127.1.248.57", Port: 24525, Action: ActionDeny, Audit: true},
		},
		DefaultDeny: []GenerationDomain{
			{EventType: EventTypeExec, Mode: DefaultDenyModeDeny},
			{CgroupID: 43, EventType: EventTypeExec, Mode: DefaultDenyModeAudit},
			{EventType: EventTypeNetwork, Mode: DefaultDenyModeDeny},
		},
	}
}

// modelGenerationLookup mirrors the hook's single-inner-pointer exact/scoped
// lookup. Real verifier/verdict tests live in policy_generation_integration_test.
func modelGenerationLookup(inner *fakeGenerationMap, key PolicyKey) (PolicyValue, uint8) {
	if v, ok := inner.entries[key]; ok {
		return v.Policy, 0
	}
	scope := key.CgroupID
	key.CgroupID = 0
	if v, ok := inner.entries[key]; ok {
		return v.Policy, 0
	}
	if v, ok := inner.entries[generationMarker(scope, key.EventType)]; ok {
		return PolicyValue{}, v.Policy.Action
	}
	return PolicyValue{}, inner.entries[generationMarker(0, key.EventType)].Policy.Action
}

func TestGenerationPreparePublishDrainAndRetire(t *testing.T) {
	b := &fakeGenerationBackend{}
	m := &GenerationManager{backend: b}
	if err := m.Prepare(1, generationFixture()); err != nil {
		t.Fatal(err)
	}
	if b.active != nil || b.publications != 0 {
		t.Fatal("Prepare changed active policy")
	}
	old := b.maps[0]
	if len(old.entries) != 9 || old.entries[generationMarker(0, generationIDEvent)].Generation != 1 {
		t.Fatal("incomplete candidate")
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(2, GenerationSpec{}); !errors.Is(err, ErrGenerationBusy) {
		t.Fatalf("legacy drain was not required: %v", err)
	}
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(2, GenerationSpec{DefaultDeny: generationFixture().DefaultDeny}); err != nil {
		t.Fatal(err)
	}
	key := mustStringKey(t, 42, EventTypeExec, collisionPathA)
	if v, dd := modelGenerationLookup(b.active, key); v.Action != ActionAllow || v.Audit != 1 || dd != 0 {
		t.Fatal("candidate leaked before switch")
	}
	if err := m.Activate(2); err != nil {
		t.Fatal(err)
	}
	if old.closes != 0 || len(old.entries) != 9 {
		t.Fatal("old generation cleared before drain")
	}
	if _, dd := modelGenerationLookup(b.active, key); dd != DefaultDenyModeDeny {
		t.Fatal("allowlist/default-deny not published together")
	}
	// An already-running hook's old pointer still resolves the complete old map.
	if v, dd := modelGenerationLookup(old, key); v.Audit != 1 || dd != 0 {
		t.Fatal("old snapshot mutated")
	}
	if err := m.Prepare(3, GenerationSpec{}); !errors.Is(err, ErrGenerationBusy) {
		t.Fatal(err)
	}
	if err := m.AcknowledgeDrain(999); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	boom := errors.New("close failed")
	old.closeErr = boom
	if err := m.AcknowledgeDrain(1); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := m.Prepare(3, GenerationSpec{}); !errors.Is(err, ErrGenerationBusy) {
		t.Fatal(err)
	}
	old.closeErr = nil
	if err := m.AcknowledgeDrain(1); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(3, GenerationSpec{}); err != nil {
		t.Fatal(err)
	}
	if len(old.entries) != 9 {
		t.Fatal("retirement deleted entries instead of releasing FD")
	}
	if err := m.Abort(3); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(4, GenerationSpec{}); err == nil {
		t.Fatal("closed manager accepted candidate")
	}
}

func TestGenerationFailuresLeaveActiveIntactAndBoundCleanup(t *testing.T) {
	boom := errors.New("injected failure")
	b := &fakeGenerationBackend{}
	m := &GenerationManager{backend: b}
	if err := m.Prepare(1, generationFixture()); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	old := b.active
	b.createErr = boom
	if err := m.Prepare(2, GenerationSpec{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	b.createErr = nil
	b.populateErr, b.closeErr = boom, boom
	if err := m.Prepare(3, GenerationSpec{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if b.active != old || len(old.entries) != 9 {
		t.Fatal("failed build touched active policy")
	}
	if err := m.Activate(3); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("partially populated candidate activated")
	}
	if err := m.Prepare(4, GenerationSpec{}); !errors.Is(err, ErrGenerationBusy) {
		t.Fatal("cleanup leak exceeded double buffer")
	}
	b.maps[1].closeErr = nil
	if err := m.Abort(3); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(3, GenerationSpec{}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("reused aborted ID")
	}
	b.populateErr, b.closeErr = nil, nil
	if err := m.Prepare(4, generationFixture()); err != nil {
		t.Fatal(err)
	}
	b.publishErr = boom
	if err := m.Activate(4); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if b.active != old || m.active.id != 1 || m.candidate.id != 4 {
		t.Fatal("failed pointer swap altered ownership")
	}
	b.publishErr = nil
	if err := m.Activate(4); err != nil {
		t.Fatal(err)
	}
	if b.publications != 2 {
		t.Fatal("unexpected publication count")
	}
}

func TestGenerationRejectsInvalidAndOversizedCandidatesBeforeAllocation(t *testing.T) {
	rule := GenerationRule{EventType: EventTypeExec, Pattern: "/bin/true", Action: ActionAllow}
	for name, spec := range map[string]GenerationSpec{
		"rule capacity":         {Rules: make([]GenerationRule, GenerationMaxEntries)},
		"domain capacity":       {DefaultDeny: make([]GenerationDomain, GenerationMaxDomains+1)},
		"duplicate rules":       {Rules: []GenerationRule{rule, rule}},
		"invalid action":        {Rules: []GenerationRule{{EventType: EventTypeExec, Pattern: "/bin/true", Action: 9}}},
		"file identity":         {Rules: []GenerationRule{{EventType: EventTypeFile, Pattern: "basename"}}},
		"unsupported domain":    {DefaultDeny: []GenerationDomain{{EventType: EventTypeBind, Mode: DefaultDenyModeDeny}}},
		"invalid mode":          {DefaultDeny: []GenerationDomain{{EventType: EventTypeExec, Mode: 0}}},
		"duplicate domains":     {DefaultDeny: []GenerationDomain{{EventType: EventTypeExec, Mode: 1}, {EventType: EventTypeExec, Mode: 2}}},
		"noncanonical endpoint": {Rules: []GenerationRule{{EventType: EventTypeNetwork, Address: "0:0:0:0:0:0:0:1"}}},
		"ambiguous identity":    {Rules: []GenerationRule{{EventType: EventTypeExec, Pattern: "/bin/true", Address: "127.0.0.1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			b := &fakeGenerationBackend{}
			m := &GenerationManager{backend: b}
			if err := m.Prepare(1, spec); err == nil {
				t.Fatal("accepted invalid candidate")
			}
			if len(b.maps) != 0 || b.active != nil {
				t.Fatal("validation allocated/published a map")
			}
		})
	}
}

func TestGenerationPartialCandidateCleanedAndCapacityBoundary(t *testing.T) {
	boom := errors.New("partial population failure")
	b := &fakeGenerationBackend{populateErr: boom, failAfter: 2}
	m := &GenerationManager{backend: b}
	if err := m.Prepare(1, generationFixture()); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if len(b.maps) != 1 || len(b.maps[0].entries) != 2 || b.maps[0].closes != 1 || m.candidate != nil || b.active != nil {
		t.Fatal("partially built candidate was not closed without publishing")
	}
	if err := m.Prepare(1, GenerationSpec{}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("failed candidate ID reused")
	}
	b.populateErr = nil
	spec := GenerationSpec{Rules: make([]GenerationRule, GenerationMaxEntries-2),
		DefaultDeny: []GenerationDomain{{EventType: EventTypeExec, Mode: DefaultDenyModeDeny}}}
	for i := range spec.Rules {
		// Same exact operation in distinct explicit scopes: marker capacity
		// counts, and there is no multiplying by an unbounded cgroup list.
		spec.Rules[i] = GenerationRule{CgroupID: uint64(i + 1), EventType: EventTypeExec, Pattern: "/bin/true", Action: ActionAllow}
	}
	if err := m.Prepare(2, spec); err != nil {
		t.Fatal(err)
	}
	if len(b.maps[1].entries) != GenerationMaxEntries {
		t.Fatal("full candidate did not include all rules and markers")
	}
	if err := m.Abort(2); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(3, GenerationSpec{Rules: append(spec.Rules, spec.Rules[0]), DefaultDeny: spec.DefaultDeny}); err == nil {
		t.Fatal("rule capacity ignored reserved marker space")
	}
	if len(b.maps) != 2 {
		t.Fatal("oversized candidate allocated another map")
	}
}

func TestGenerationZeroAndReusedIDsAndUnloadedFlush(t *testing.T) {
	b := &fakeGenerationBackend{}
	m := &GenerationManager{backend: b}
	if err := m.Prepare(0, GenerationSpec{}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	if err := m.Prepare(^uint64(0), GenerationSpec{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Abort(^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(1, GenerationSpec{}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("generation ID wrapped")
	}
	if err := (&LSMLoader{}).FlushLSMEvents(); err == nil {
		t.Fatal("unloaded reader claimed a drain barrier")
	}
}

func TestGenerationExactCollisionScopeAndAudit(t *testing.T) {
	b := &fakeGenerationBackend{}
	m := &GenerationManager{backend: b}
	if err := m.Prepare(1, generationFixture()); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		scope         uint64
		path          string
		action, audit uint8
	}{
		{42, collisionPathA, ActionAllow, 1}, {42, collisionPathB, ActionDeny, 0},
		{43, collisionPathA, ActionDeny, 1},
	} {
		v, dd := modelGenerationLookup(b.active, mustStringKey(t, tc.scope, EventTypeExec, tc.path))
		if v.Action != tc.action || v.Audit != tc.audit || dd != 0 {
			t.Fatalf("collision/scope/audit: %+v %d", v, dd)
		}
	}
	if _, dd := modelGenerationLookup(b.active, mustStringKey(t, 43, EventTypeExec, "/unknown")); dd != DefaultDenyModeAudit {
		t.Fatal("scoped audit marker lost")
	}
	for _, tc := range []struct {
		addr          string
		port          uint16
		action, audit uint8
	}{
		{"127.1.156.58", 8644, ActionAllow, 0}, {"127.1.248.57", 24525, ActionDeny, 1},
	} {
		key, err := endpointPolicyKey(42, EventTypeNetwork, tc.addr, tc.port)
		if err != nil {
			t.Fatal(err)
		}
		v, dd := modelGenerationLookup(b.active, key)
		if v.Action != tc.action || v.Audit != tc.audit || dd != 0 {
			t.Fatal("endpoint collision")
		}
	}
}

func TestGenerationDynamicWritebackFencedAcrossSwitch(t *testing.T) {
	b := &fakeGenerationBackend{}
	m := &GenerationManager{backend: b}
	event := &api.Event{Type: api.EventTypeProcess, CgroupID: 42, Filename: "/bin/dynamic"}
	if err := m.Prepare(1, GenerationSpec{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(1); err != nil {
		t.Fatal(err)
	}
	if err := m.AcknowledgeDrain(0); err != nil {
		t.Fatal(err)
	}
	if err := m.SyncEvent(1, event, ActionAllow, true); err != nil {
		t.Fatal(err)
	}
	old := b.active
	if err := m.Prepare(2, GenerationSpec{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Activate(2); err != nil {
		t.Fatal(err)
	}
	if err := m.SyncEvent(1, event, ActionAllow, false); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal(err)
	}
	if len(b.active.entries) != 1 || len(old.entries) != 2 {
		t.Fatal("old decision copied to new generation")
	}
	event.CgroupID = 0
	if err := m.SyncEvent(2, event, ActionAllow, false); !errors.Is(err, ErrNotKernelMatchable) {
		t.Fatal(err)
	}
	event.CgroupID = 43
	if err := m.SyncEvent(2, event, 99, false); err == nil {
		t.Fatal("invalid action accepted")
	}
	boom := errors.New("map full")
	b.active.putErr = boom
	if err := m.SyncEvent(2, event, ActionAllow, false); !errors.Is(err, boom) {
		t.Fatal("capacity failure hidden")
	}
}

func TestGenerationConcurrentPrepareHasOneWinner(t *testing.T) {
	b := &fakeGenerationBackend{}
	m := &GenerationManager{backend: b}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id uint64) { defer wg.Done(); _ = m.Prepare(id, GenerationSpec{}) }(uint64(i + 1))
	}
	wg.Wait()
	if len(b.maps) != 1 || m.candidate == nil {
		t.Fatal("parallel candidates violated memory bound")
	}
}

func TestGenerationEmbeddedMapABIAndSharing(t *testing.T) {
	if binary.Size(generationValue{}) != 16 {
		t.Fatal("generation value ABI drift")
	}
	want := generationMapSpec()
	for name, load := range map[string]func() (*ebpf.CollectionSpec, error){
		"exec": loadLsm_exec, "file": loadLsm_file, "connect": loadLsm_connect, "bind": loadLsm_bind,
		"listen": loadLsm_listen, "ptrace": loadLsm_ptrace, "mount": loadLsm_mount, "integrity": loadLsm_integrity,
	} {
		spec, err := load()
		if err != nil {
			t.Fatal(err)
		}
		outer := spec.Maps["active_generation"]
		if outer == nil || outer.Type != ebpf.ArrayOfMaps || outer.MaxEntries != 1 || outer.KeySize != 4 || len(outer.Contents) != 0 {
			t.Fatalf("%s not empty atomic pointer: %+v", name, outer)
		}
		inner := outer.InnerMap
		if inner == nil || inner.Type != want.Type || inner.KeySize != want.KeySize || inner.ValueSize != want.ValueSize || inner.MaxEntries != want.MaxEntries || inner.Flags != want.Flags {
			t.Fatalf("%s mismatched inner template: %+v", name, inner)
		}
	}
	// No kernel map is needed to ensure the loader shares the new pointer.
	marker := &ebpf.Map{}
	l := &LSMLoader{execObjs: &lsm_execObjects{lsm_execMaps: lsm_execMaps{ActiveGeneration: marker}}}
	if l.sharedMaps()["active_generation"] != marker {
		t.Fatal("hook-private active pointer")
	}
	if l.PolicyGenerations() != l.PolicyGenerations() {
		t.Fatal("multiple generation writers")
	}
	if !reflect.DeepEqual(l.PolicyGenerations().backend, kernelGenerationBackend{marker}) {
		t.Fatal("wrong active pointer backend")
	}
}
