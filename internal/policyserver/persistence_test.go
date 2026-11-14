package policyserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T, path string, opts StoreOptions) *Store {
	t.Helper()
	s, err := OpenStore(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestDurableStoreRestartPreservesRevisionsCohortsAndAudit(t *testing.T) {
	dir := t.TempDir()
	preparePrivateSnapshotDir(t, dir)
	path := filepath.Join(dir, "state.json")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := StoreOptions{VerifyKey: pub}
	s := openTestStore(t, path, opts)
	w := writeWASM(t, dir, "policy.wasm", "one")
	sig1 := ed25519.Sign(priv, []byte("one"))
	sig2 := ed25519.Sign(priv, []byte("two"))
	if err := s.CreateSignedPolicy(&Policy{ID: "p", Priority: 9, Selector: map[string]string{"tier": "web"}}, w, sig1); err != nil {
		t.Fatal(err)
	}
	writeWASM(t, dir, "policy.wasm", "two")
	if err := s.AddVersion("p", w, sig2, false); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{"tier": "web"}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "node", Labels: labels}); err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat("node", 1); err != nil {
		t.Fatal(err)
	}
	rm := NewRolloutManager(s)
	if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "p", Percentage: 31}); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]*PolicyAssignment)
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("node-%d", i)
		want[id] = rm.ResolvePolicy(id, labels)
	}
	before := s.snapshotLocked()
	s.Close()
	if err := os.Remove(w); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path, opts)
	rm = NewRolloutManager(s)
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(s.snapshotLocked())
	if !bytes.Equal(a, b) {
		t.Fatal("restored management state differs")
	}
	for id, expected := range want {
		if got := rm.ResolvePolicy(id, labels); !reflect.DeepEqual(got, expected) {
			t.Fatalf("cohort changed for %s: %+v -> %+v", id, expected, got)
		}
	}
	for n, expected := range map[int64]struct {
		data string
		sig  []byte
	}{1: {"one", sig1}, 2: {"two", sig2}} {
		data, sig, ok := s.GetSignedWASM("p", n)
		if !ok || string(data) != expected.data || !bytes.Equal(sig, expected.sig) {
			t.Fatalf("revision %d not restored", n)
		}
	}
	assertPrivateSnapshot(t, path)
}

func TestDurableStoreRestoreBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := openTestStore(t, path, StoreOptions{})
	if err := s.CreatePolicy(&Policy{ID: "p"}, writeWASM(t, dir, "p.wasm", "one")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restore.json")
	if err := os.WriteFile(restoredPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	restored := openTestStore(t, restoredPath, StoreOptions{})
	if got, ok := restored.GetWASM("p"); !ok || string(got) != "one" {
		t.Fatal("backup not servable")
	}
}

func TestDurableRolloutTransitionsAreAtomic(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(fmt.Sprintf("abort=%v", abort), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			s := openTestStore(t, path, StoreOptions{})
			if err := s.CreatePolicy(&Policy{ID: "p"}, writeWASM(t, dir, "one.wasm", "one")); err != nil {
				t.Fatal(err)
			}
			if err := s.StagePolicy("p", writeWASM(t, dir, "two.wasm", "two")); err != nil {
				t.Fatal(err)
			}
			rm := NewRolloutManager(s)
			if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "p", Percentage: 40}); err != nil {
				t.Fatal(err)
			}
			if err := rm.UpdatePercentage("r", 61); err != nil {
				t.Fatal(err)
			}
			audit := s.ListAudit()
			s.backend.path = filepath.Join(dir, "missing", "state.json")
			transition := func() error {
				if abort {
					return rm.AbortRollout("r")
				}
				return rm.CompleteRollout("r")
			}
			if err := transition(); !errors.Is(err, ErrStatePersistence) {
				t.Fatalf("wanted persistence failure, got %v", err)
			}
			r, _ := rm.GetRollout("r")
			p, _ := s.GetPolicy("p")
			if r.Status != "active" || r.Percentage != 61 || p.ActiveVersion != 1 || !reflect.DeepEqual(audit, s.ListAudit()) {
				t.Fatal("failed transition leaked into memory")
			}
			s.backend.path = path
			s.Close()
			s = openTestStore(t, path, StoreOptions{})
			rm = NewRolloutManager(s)
			r, _ = rm.GetRollout("r")
			p, _ = s.GetPolicy("p")
			if r.Status != "active" || r.Percentage != 61 || p.ActiveVersion != 1 {
				t.Fatal("disk saw failed transition")
			}
			if err := transition(); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s = openTestStore(t, path, StoreOptions{})
			rm = NewRolloutManager(s)
			r, _ = rm.GetRollout("r")
			p, _ = s.GetPolicy("p")
			status, version := "completed", int64(2)
			if abort {
				status, version = "aborted", 1
			}
			if r.Status != status || r.CompletedAt == nil || p.ActiveVersion != version {
				t.Fatalf("transition not restored: %+v %+v", r, p)
			}
		})
	}
}

func rewriteSnapshot(t *testing.T, data []byte, change func(*storeSnapshot)) []byte {
	t.Helper()
	var e snapshotEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	var d storeSnapshot
	if err := json.Unmarshal(e.State, &d); err != nil {
		t.Fatal(err)
	}
	change(&d)
	e.State, _ = json.Marshal(d)
	h := sha256.Sum256(e.State)
	e.SHA256 = hex.EncodeToString(h[:])
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDurableStoreRejectsCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := openTestStore(t, path, StoreOptions{})
	if err := s.CreatePolicy(&Policy{ID: "p"}, writeWASM(t, dir, "p.wasm", "one")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty": {}, "truncated": valid[:len(valid)/2], "trailing": append(bytes.Clone(valid), []byte(" {}")...),
		"checksum":         bytes.Replace(valid, []byte(`"sequence":1`), []byte(`"sequence":2`), 1),
		"format":           bytes.Replace(valid, []byte(`"format":1`), []byte(`"format":2`), 1),
		"digest":           rewriteSnapshot(t, valid, func(d *storeSnapshot) { d.Versions["p"][1].Data = []byte("changed") }),
		"missing revision": rewriteSnapshot(t, valid, func(d *storeSnapshot) { delete(d.Versions["p"], 1) }),
		"bad reference":    rewriteSnapshot(t, valid, func(d *storeSnapshot) { d.Policies["p"].ActiveVersion = 7 }),
		"bad signature":    rewriteSnapshot(t, valid, func(d *storeSnapshot) { d.Versions["p"][1].Signature = []byte("bad") }),
		"null policy":      rewriteSnapshot(t, valid, func(d *storeSnapshot) { d.Policies["p"] = nil }),
		"null revision":    rewriteSnapshot(t, valid, func(d *storeSnapshot) { d.Versions["p"][2] = nil }),
		"missing agents":   rewriteSnapshot(t, valid, func(d *storeSnapshot) { d.Agents = nil }),
		"conflicting rollouts": rewriteSnapshot(t, valid, func(d *storeSnapshot) {
			for _, id := range []string{"a", "b"} {
				d.Rollouts[id] = &RolloutState{Rollout: Rollout{ID: id, PolicyID: "p", TargetVersion: 1, Status: "active"}, BaseVersion: 1}
			}
		}),
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenStore(path, StoreOptions{}); err == nil {
				opened.Close()
				t.Fatal("corruption accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, corrupt) {
				t.Fatal("corrupt state overwritten")
			}
			if err := os.WriteFile(path, valid, 0600); err != nil {
				t.Fatal(err)
			}
			good, err := OpenStore(path, StoreOptions{})
			if err != nil {
				t.Fatal(err)
			}
			good.Close()
		})
	}
}

func TestDurableStoreReverifiesSignatures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := openTestStore(t, path, StoreOptions{VerifyKey: pub})
	if err := s.CreateSignedPolicy(&Policy{ID: "p"}, writeWASM(t, dir, "p.wasm", "one"), ed25519.Sign(priv, []byte("one"))); err != nil {
		t.Fatal(err)
	}
	s.Close()
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if opened, err := OpenStore(path, StoreOptions{VerifyKey: wrong}); err == nil {
		opened.Close()
		t.Fatal("wrong signing key accepted")
	}
	data, _ := os.ReadFile(path)
	data = rewriteSnapshot(t, data, func(d *storeSnapshot) { d.Versions["p"][1].Signature = make([]byte, ed25519.SignatureSize) })
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenStore(path, StoreOptions{VerifyKey: pub}); err == nil {
		opened.Close()
		t.Fatal("forged signature accepted")
	}
}

func TestDurableStoreWriterConflictAndClosedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := openTestStore(t, path, StoreOptions{})
	if other, err := OpenStore(path, StoreOptions{}); err == nil {
		other.Close()
		t.Fatal("second writer accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(path), alias); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenStore(filepath.Join(alias, "state.json"), StoreOptions{}); err == nil {
		other.Close()
		t.Fatal("aliased second writer accepted")
	}
	s.Close()
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "a"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed store mutation: %v", err)
	}
	openTestStore(t, path, StoreOptions{})
}

func TestStoreLimitsRejectWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := openTestStore(t, path, StoreOptions{Limits: StoreLimits{MaxPolicies: 1, MaxAgents: 1, MaxVersionsPerPolicy: 2, MaxAuditEntries: 3}})
	w := writeWASM(t, dir, "p.wasm", "one")
	if err := s.CreatePolicy(&Policy{ID: "p"}, w); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePolicy(&Policy{ID: "other"}, w); !errors.Is(err, ErrStateLimit) {
		t.Fatalf("policy limit: %v", err)
	}
	if err := s.StagePolicy("p", w); err != nil {
		t.Fatal(err)
	}
	if err := s.StagePolicy("p", w); !errors.Is(err, ErrStateLimit) {
		t.Fatalf("version limit: %v", err)
	}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAgentChecked(&RegisterRequest{ID: "b"}); !errors.Is(err, ErrStateLimit) {
		t.Fatalf("agent limit: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := s.SetActiveVersion("p", 1); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.ListAudit(); len(got) != 3 || got[2].Sequence-got[0].Sequence != 2 {
		t.Fatal("unbounded audit")
	}
	s.Close()
	s = openTestStore(t, path, StoreOptions{})
	p, _ := s.GetPolicy("p")
	if len(s.ListPolicies()) != 1 || len(s.ListAgents()) != 1 || p.Version != 2 || len(s.ListAudit()) != 3 {
		t.Fatal("rejected mutation persisted")
	}
}

func TestStoreSnapshotAndBinaryLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits StoreLimits
	}{
		{"snapshot", StoreLimits{MaxSnapshotBytes: 2048}},
		{"binary", StoreLimits{MaxWASMBytes: 4}},
		{"retained", StoreLimits{MaxRetainedWASMBytes: 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := openTestStore(t, filepath.Join(dir, "state.json"), StoreOptions{Limits: tc.limits})
			p := &Policy{ID: "p"}
			w := writeWASM(t, dir, "p.wasm", string(bytes.Repeat([]byte("x"), 4096)))
			if err := s.CreatePolicy(p, w); err == nil {
				t.Fatal("oversized policy accepted")
			}
			if len(s.ListPolicies()) != 0 || len(s.ListAudit()) != 0 || p.Version != 0 {
				t.Fatal("failed create leaked mutation")
			}
		})
	}
}

func TestStoreImmutabilityAndDeterministicPriorityTies(t *testing.T) {
	s := NewStore()
	dir := t.TempDir()
	w := writeWASM(t, dir, "p.wasm", "one")
	for _, id := range []string{"z", "a", "m"} {
		p := &Policy{ID: id, Priority: 10, Selector: map[string]string{"x": "1"}}
		if err := s.CreatePolicy(p, w); err != nil {
			t.Fatal(err)
		}
		p.Selector["x"] = "attacker"
	}
	for i := 0; i < 200; i++ {
		p := s.MatchPolicy(map[string]string{"x": "1"})
		if p == nil || p.ID != "a" {
			t.Fatalf("unstable tie: %+v", p)
		}
		p.Selector["x"] = "changed"
	}
	p, _ := s.GetPolicy("a")
	p.Selector["x"] = "changed"
	list := s.ListPolicies()
	list[0].Selector["x"] = "changed"
	data, _ := s.GetWASM("a")
	data[0] = 'X'
	if got, _ := s.GetWASMVersion("a", 1); string(got) != "one" {
		t.Fatal("binary mutated")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s.SetVerifyKey(pub)
	sig := ed25519.Sign(priv, []byte("one"))
	if err := s.AddVersion("a", w, sig, false); err != nil {
		t.Fatal(err)
	}
	data, returnedSig, _ := s.GetSignedWASM("a", 2)
	data[0] = 'X'
	returnedSig[0] ^= 1
	sig[0] ^= 1
	data, returnedSig, _ = s.GetSignedWASM("a", 2)
	if !ed25519.Verify(pub, data, returnedSig) {
		t.Fatal("signed revision mutated")
	}
	labels := map[string]string{"x": "1"}
	a := s.RegisterAgent(&RegisterRequest{ID: "node", Labels: labels})
	labels["x"] = "changed"
	a.Labels["x"] = "changed"
	a, _ = s.GetAgent("node")
	a.Labels["x"] = "changed"
	agents := s.ListAgents()
	agents[0].Labels["x"] = "changed"
	a, _ = s.GetAgent("node")
	if a.Labels["x"] != "1" {
		t.Fatal("agent labels escaped")
	}
}

func TestRolloutConflictsAndConcurrentReaders(t *testing.T) {
	s, rm, w := setupRolloutTest(t)
	if _, err := rm.CreateRollout(RolloutConfig{ID: "r", PolicyID: "web-policy", Percentage: 10}); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func() error{
		"delete":   func() error { return s.DeletePolicy("web-policy") },
		"activate": func() error { return s.SetActiveVersion("web-policy", 2) },
		"update":   func() error { return s.UpdatePolicy("web-policy", w) },
	} {
		if err := fn(); err == nil {
			t.Errorf("%s must conflict with rollout", name)
		}
	}
	if err := s.StagePolicy("web-policy", w); err != nil {
		t.Fatal(err)
	}
	other := NewRolloutManager(s)
	if _, err := other.CreateRollout(RolloutConfig{ID: "other", PolicyID: "web-policy"}); err == nil {
		t.Fatal("second manager bypassed conflict")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rm.ShouldUseNewVersion("r", "a")
				rm.ResolvePolicy("a", map[string]string{"tier": "web"})
				rm.ListRollouts()
			}
		}()
	}
	for i := 0; i < 99; i++ {
		if err := rm.UpdatePercentage("r", i); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err := rm.CompleteRollout("r"); err != nil {
		t.Fatal(err)
	}
	r, _ := rm.GetRollout("r")
	*r.CompletedAt = time.Time{}
	again, _ := rm.GetRollout("r")
	if again.CompletedAt.IsZero() {
		t.Fatal("completion time escaped")
	}
}
