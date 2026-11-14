package agentstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto/assignment"
)

type signer struct {
	private ed25519.PrivateKey
	trust   assignment.Trust
	opts    assignment.VerifyOptions
	base    assignment.Deployment
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := assignment.Deployment{Format: assignment.Format, KeyID: "assignment-key", Target: assignment.Target{Scope: "tenant/prod", Audience: "agent-1"},
		Policy: assignment.Policy{ID: "policy", Version: 1, SHA256: assignment.Digest([]byte("module")), ABI: 5, Compiler: "compiler-build-1",
			Posture: assignment.Posture{Mode: "enforce", DefaultAction: "deny", RequireDefaultDeny: true}},
		Sequence: 1, IssuedAt: 1800000000, ExpiresAt: 1800003600}
	return &signer{private: private, trust: assignment.Trust{d.KeyID: assignment.Key{Public: pub, Target: d.Target, CanRollback: true}}, base: d,
		opts: assignment.VerifyOptions{Target: d.Target, Clock: assignment.Clock{Trusted: true, Now: time.Unix(d.IssuedAt+1, 0)},
			SupportedABIs: []uint32{5}, AllowedCompilers: []string{d.Policy.Compiler}, MaxLifetime: time.Hour}}
}

func (k *signer) verify(t *testing.T, d assignment.Deployment) assignment.Verified {
	t.Helper()
	return k.verifyModule(t, d, []byte("module"))
}

func (k *signer) verifyModule(t *testing.T, d assignment.Deployment, module []byte) assignment.Verified {
	t.Helper()
	e, err := assignment.Sign(k.private, d)
	if err != nil {
		t.Fatal(err)
	}
	v, err := assignment.Verify(e, module, k.trust, k.opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func create(t *testing.T, k *signer) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "assignment.json")
	s, err := Create(path, k.base.Target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func snapshot(t *testing.T, s *Store) State {
	t.Helper()
	st, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func commit(t *testing.T, s *Store, k *signer, d assignment.Deployment) {
	t.Helper()
	if err := s.Commit(k.verify(t, d), fmt.Sprintf("revision-%d", d.Sequence), k.opts.Clock); err != nil {
		t.Fatal(err)
	}
}

func reopen(t *testing.T, s *Store, path string, target assignment.Target) *Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestDurableSequenceRestartAndNoReset(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	d := k.base
	commit(t, s, k, d)
	before := snapshot(t, s)
	s = reopen(t, s, path, d.Target)
	if after := snapshot(t, s); !reflect.DeepEqual(before, after) {
		t.Fatalf("state changed across restart: %+v", after)
	}
	if err := s.Commit(k.verify(t, d), "revision-replay", k.opts.Clock); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	d.Sequence = 2
	commit(t, s, k, d) // same exact policy, renewed authorization
	d.Sequence = 1
	if err := s.Commit(k.verify(t, d), "revision-old", k.opts.Clock); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	if _, err := Create(path, d.Target); err == nil {
		t.Fatal("enrollment reset live state")
	}
	st := snapshot(t, s)
	st.Policies[d.Policy.ID] = assignment.Policy{}
	st.Active.Envelope[0] = 'x'
	if snapshot(t, s).Policies[d.Policy.ID] != d.Policy {
		t.Fatal("state exposed mutable map")
	}
	if _, err := assignment.Decode(snapshot(t, s).Active.Envelope); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackAuthorizedFreshSequenceExactSourceAndPersistentVersionFloor(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	v1 := k.base
	commit(t, s, k, v1)
	v3 := v1
	v3.Sequence = 2
	v3.Policy.Version = 3
	commit(t, s, k, v3)
	rb := v1
	rb.Sequence = 3
	if err := s.Commit(k.verify(t, rb), "revision-no-authorization", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	rb.Rollback = &assignment.Rollback{FromSequence: v3.Sequence, From: v3.Policy, Reason: "incident-123 approved restore"}
	wrong := rb
	r := *rb.Rollback
	r.FromSequence = 1
	wrong.Rollback = &r
	if err := s.Commit(k.verify(t, wrong), "revision-wrong-seq", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	r = *rb.Rollback
	r.From.Version = 2
	wrong.Rollback = &r
	if err := s.Commit(k.verify(t, wrong), "revision-wrong-source", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	commit(t, s, k, rb)
	st := snapshot(t, s)
	if st.HighWater != 3 || st.Policies[v1.Policy.ID].Version != 3 {
		t.Fatal("rollback lowered high-water", st)
	}
	s = reopen(t, s, path, rb.Target)
	if err := s.Commit(k.verify(t, rb), "revision-rollback-replay", k.opts.Clock); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	// A normal deploy at version 2 is still a rollback from the historical 3,
	// even though the currently active version after recovery is only 1.
	v2 := v1
	v2.Sequence = 4
	v2.Policy.Version = 2
	if err := s.Commit(k.verify(t, v2), "revision-bypass-floor", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	v2.Rollback = &assignment.Rollback{FromSequence: rb.Sequence, From: rb.Policy, Reason: "approved intermediate fix"}
	commit(t, s, k, v2)
	// Old rollback authorization cannot be grafted onto a new sequence, even
	// if a signer re-signs it, because its exact current source no longer matches.
	rb.Sequence = 5
	if err := s.Commit(k.verify(t, rb), "revision-stale-authorization", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	v4 := v1
	v4.Sequence = 5
	v4.Policy.Version = 4
	commit(t, s, k, v4)
	if snapshot(t, s).Policies[v1.Policy.ID].Version != 4 {
		t.Fatal("forward progress impossible after rollback")
	}
}

func TestRollbackHistorySurvivesPolicySwitchAndSignerRotation(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	d := k.base
	d.Policy.Version = 8
	commit(t, s, k, d)
	other := d
	other.Sequence++
	other.Policy.ID = "replacement"
	other.Policy.Version = 1
	commit(t, s, k, other)
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k.private = private
	k.trust = assignment.Trust{"rotated-key": assignment.Key{Public: pub, Target: d.Target, CanRollback: true}}
	d.KeyID = "rotated-key"
	d.Sequence = 3
	d.Policy.Version = 7
	s = reopen(t, s, path, d.Target)
	if err := s.Commit(k.verify(t, d), "revision-key-reset-attempt", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	d.Rollback = &assignment.Rollback{FromSequence: other.Sequence, From: other.Policy, Reason: "approved switch back"}
	commit(t, s, k, d)
	if snapshot(t, s).HighWater != 3 || snapshot(t, s).Policies[d.Policy.ID].Version != 8 {
		t.Fatal("rotation reset replay state")
	}
}

func TestPostureAndSameVersionEquivocationNeedRollback(t *testing.T) {
	for _, change := range []struct {
		name string
		f    func(*assignment.Policy)
	}{
		{"audit", func(p *assignment.Policy) { p.Posture.Mode = "audit"; p.Posture.RequireDefaultDeny = false }},
		{"allow", func(p *assignment.Policy) { p.Posture.DefaultAction = "allow"; p.Posture.RequireDefaultDeny = false }},
		{"optional kernel deny", func(p *assignment.Policy) { p.Posture.RequireDefaultDeny = false }},
		{"compiler at same version", func(p *assignment.Policy) { p.Compiler = "compiler-build-2" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			k := newSigner(t)
			k.opts.AllowedCompilers = append(k.opts.AllowedCompilers, "compiler-build-2")
			s, _ := create(t, k)
			d := k.base
			commit(t, s, k, d)
			next := d
			next.Sequence++
			change.f(&next.Policy)
			if err := s.Commit(k.verify(t, next), "revision-unsigned-downgrade", k.opts.Clock); !errors.Is(err, ErrRollback) {
				t.Fatal(err)
			}
			next.Rollback = &assignment.Rollback{FromSequence: d.Sequence, From: d.Policy, Reason: "explicit authorized relaxation"}
			commit(t, s, k, next)
		})
	}
	// A fresh policy ID or higher version does not conceal weaker posture.
	k := newSigner(t)
	s, _ := create(t, k)
	d := k.base
	commit(t, s, k, d)
	next := d
	next.Sequence++
	next.Policy.ID = "new-id"
	next.Policy.Version = 100
	next.Policy.Posture.RequireDefaultDeny = false
	if err := s.Commit(k.verify(t, next), "revision-new-id-bypass", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
}

func TestCommitClockAndExpiry(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	d := k.base
	commit(t, s, k, d)
	s = reopen(t, s, path, d.Target)
	d.Sequence++
	for name, clock := range map[string]assignment.Clock{
		"unknown": {Now: k.opts.Clock.Now}, "expired": {Now: time.Unix(d.ExpiresAt, 0), Trusted: true},
		"backwards": {Now: k.opts.Clock.Now.Add(-time.Second), Trusted: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.Commit(k.verify(t, d), "revision-clock", clock); err == nil {
				t.Fatal("bad clock accepted")
			}
		})
	}
	// Even a newly verified token cannot bypass the durable last clock.
	k.opts.Clock.Now = k.opts.Clock.Now.Add(-time.Second)
	if err := s.Commit(k.verify(t, d), "revision-clock-regression", k.opts.Clock); !errors.Is(err, assignment.ErrClock) {
		t.Fatal(err)
	}
	if snapshot(t, s).HighWater != 1 {
		t.Fatal("failed commit consumed sequence")
	}
}

func TestDurableActivationPublicationFaults(t *testing.T) {
	for _, stage := range []string{"file-sync", "before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			k := newSigner(t)
			s, path := create(t, k)
			d := k.base
			commit(t, s, k, d)
			old := snapshot(t, s)
			d.Sequence++
			d.Policy.Version++
			failure := errors.New("injected storage failure")
			switch stage {
			case "file-sync":
				s.fileSync = func(*os.File) error { return failure }
			case "before-rename":
				s.publish = func(string, string) (bool, error) { return false, failure }
			case "after-rename":
				s.publish = func(from, to string) (bool, error) {
					if err := os.Rename(from, to); err != nil {
						return false, err
					}
					return true, failure
				}
			}
			err := s.Commit(k.verify(t, d), "revision-candidate", k.opts.Clock)
			if err == nil {
				t.Fatal("failed publication acknowledged")
			}
			if stage == "after-rename" {
				if !errors.Is(err, ErrIndeterminate) {
					t.Fatal(err)
				}
				if _, err := s.Snapshot(); !errors.Is(err, ErrIndeterminate) {
					t.Fatal("uncertain state exposed", err)
				}
				if err := s.Commit(k.verify(t, d), "revision-retry", k.opts.Clock); !errors.Is(err, ErrIndeterminate) {
					t.Fatal("poisoned writer accepted commit", err)
				}
			} else {
				if after := snapshot(t, s); !reflect.DeepEqual(old, after) {
					t.Fatal("failed write mutated memory")
				}
			}
			s = reopen(t, s, path, d.Target)
			after := snapshot(t, s)
			if stage == "after-rename" {
				if after.HighWater != d.Sequence || after.Active.Revision != "revision-candidate" {
					t.Fatal("recovery split pointer from marks")
				}
				if err := s.Commit(k.verify(t, d), "revision-replay", k.opts.Clock); !errors.Is(err, ErrReplay) {
					t.Fatal(err)
				}
			} else {
				if !reflect.DeepEqual(old, after) {
					t.Fatal("unpublished state survived restart")
				}
				commit(t, s, k, d) // no sequence consumed; retry is legitimate
			}
		})
	}
}

func TestMissingCorruptWrongTargetAndConcurrentWriterFailClosed(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	if _, err := Open(path, k.base.Target); err == nil {
		t.Fatal("second writer opened")
	}
	commit(t, s, k, k.base)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wrong := k.base.Target
	wrong.Audience = "agent-2"
	if _, err := Open(path, wrong); !errors.Is(err, ErrState) {
		t.Fatal("wrong target", err)
	}
	for _, bad := range [][]byte{[]byte("broken"), append(bytes.Clone(data), '\n'), bytes.Replace(data, []byte(`"high_water":1`), []byte(`"high_water":0`), 1)} {
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, k.base.Target); !errors.Is(err, ErrState) {
			t.Fatal("corrupt state accepted", err)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, bad) {
			t.Fatal("corrupt state overwritten")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, k.base.Target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing replay state reset", err)
	}
}

func TestSemanticCorruptionWithValidChecksum(t *testing.T) {
	for _, change := range []struct {
		name string
		f    func(*State)
	}{
		{"format", func(s *State) { s.Format++ }}, {"high-water", func(s *State) { s.HighWater++ }},
		{"clock", func(s *State) { s.LastClock = 0 }}, {"missing-history", func(s *State) { clear(s.Policies) }},
		{"unsafe-pointer", func(s *State) { s.Active.Revision = "../escape" }},
		{"no-active", func(s *State) { s.Active = nil }},
		{"history-lowered", func(s *State) { p := s.Policies["policy"]; p.Version = 0; s.Policies["policy"] = p }},
	} {
		t.Run(change.name, func(t *testing.T) {
			k := newSigner(t)
			s, path := create(t, k)
			commit(t, s, k, k.base)
			st := snapshot(t, s)
			change.f(&st)
			payload, _ := json.Marshal(st)
			wire, _ := json.Marshal(disk{SHA256: assignment.Digest(payload), State: payload})
			_ = s.Close()
			if err := os.WriteFile(path, wire, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, k.base.Target); !errors.Is(err, ErrState) {
				t.Fatal(err)
			}
		})
	}
}

func TestUnsafeReferencesAudienceAndZeroVerification(t *testing.T) {
	k := newSigner(t)
	s, _ := create(t, k)
	if err := s.Commit(assignment.Verified{}, "revision-zero", k.opts.Clock); !errors.Is(err, assignment.ErrInvalid) {
		t.Fatal(err)
	}
	for _, revision := range []string{"", ".", "..", "revision-../foo", "/revision-abs", "revision-a/b", `revision-a\b`, "revision-", strings.Repeat("x", 129)} {
		if err := s.Commit(k.verify(t, k.base), revision, k.opts.Clock); !errors.Is(err, ErrState) {
			t.Fatalf("%q: %v", revision, err)
		}
	}
	other := newSigner(t)
	other.base.Target.Audience = "another-agent"
	other.opts.Target = other.base.Target
	key := other.trust[other.base.KeyID]
	key.Target = other.base.Target
	other.trust[other.base.KeyID] = key
	if err := s.Commit(other.verify(t, other.base), "revision-wrong-agent", other.opts.Clock); !errors.Is(err, assignment.ErrAudience) {
		t.Fatal(err)
	}
	rb := k.base
	rb.Rollback = &assignment.Rollback{FromSequence: 1, From: rb.Policy, Reason: "no active revision"}
	rb.Sequence = 2
	if err := s.Commit(k.verify(t, rb), "revision-empty-rollback", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
}

func TestConcurrentReplayOnlyOneCommitAndSequenceExhaustion(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	d := k.base
	v := k.verify(t, d)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { results <- s.Commit(v, "revision-concurrent", k.opts.Clock) })
	}
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrReplay) {
			t.Fatal(err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d concurrent commits succeeded", succeeded)
	}
	d.Sequence = math.MaxUint64
	commit(t, s, k, d)
	s = reopen(t, s, path, d.Target)
	if err := s.Commit(k.verify(t, d), "revision-max-replay", k.opts.Clock); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	if snapshot(t, s).HighWater != math.MaxUint64 {
		t.Fatal("sequence wrapped")
	}
}

func TestCloseAndHistoryBound(t *testing.T) {
	k := newSigner(t)
	s, _ := create(t, k)
	for i := range maxPolicies {
		p := k.base.Policy
		p.ID = fmt.Sprintf("policy-%d", i)
		s.state.Policies[p.ID] = p
	}
	if err := s.Commit(k.verify(t, k.base), "revision-full", k.opts.Clock); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if len(s.state.Policies) != maxPolicies {
		t.Fatal("history silently evicted")
	}
	_ = s.Close()
	if _, err := s.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Commit(k.verify(t, k.base), "revision-closed", k.opts.Clock); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessExitAfterDurableCommit(t *testing.T) {
	// The child exits without Close/defer, simulating the crash window after
	// publication and before evaluator swap/acknowledgement. The kernel releases
	// the process lock, and a fresh process must recover marks and pointer together.
	if os.Getenv("WARMOR_ASSIGNMENT_CRASH_HELPER") == "1" {
		target := assignment.Target{Scope: "tenant/prod", Audience: "agent-1"}
		s, err := Open(os.Getenv("WARMOR_ASSIGNMENT_CRASH_STATE"), target)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := base64.StdEncoding.DecodeString(os.Getenv("WARMOR_ASSIGNMENT_CRASH_ENVELOPE"))
		if err != nil {
			t.Fatal(err)
		}
		e, err := assignment.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := base64.StdEncoding.DecodeString(os.Getenv("WARMOR_ASSIGNMENT_CRASH_PUBLIC"))
		if err != nil {
			t.Fatal(err)
		}
		clock := assignment.Clock{Now: time.Unix(e.Deployment.IssuedAt+1, 0), Trusted: true}
		v, err := assignment.Verify(e, []byte("module"), assignment.Trust{e.Deployment.KeyID: assignment.Key{Public: pub, Target: target}},
			assignment.VerifyOptions{Target: target, Clock: clock, SupportedABIs: []uint32{5}, AllowedCompilers: []string{e.Deployment.Policy.Compiler}, MaxLifetime: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Commit(v, "revision-crash-window", clock); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	k := newSigner(t)
	s, path := create(t, k)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	e, err := assignment.Sign(k.private, k.base)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := assignment.Encode(e)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessExitAfterDurableCommit$")
	cmd.Env = append(os.Environ(), "WARMOR_ASSIGNMENT_CRASH_HELPER=1", "WARMOR_ASSIGNMENT_CRASH_STATE="+path,
		"WARMOR_ASSIGNMENT_CRASH_ENVELOPE="+base64.StdEncoding.EncodeToString(wire),
		"WARMOR_ASSIGNMENT_CRASH_PUBLIC="+base64.StdEncoding.EncodeToString(k.trust[k.base.KeyID].Public))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v\n%s", err, out)
	}
	s = reopen(t, s, path, k.base.Target)
	st := snapshot(t, s)
	if st.HighWater != 1 || st.Active.Revision != "revision-crash-window" {
		t.Fatalf("torn recovered commit: %+v", st)
	}
	if err := s.Commit(k.verify(t, k.base), "revision-replayed-after-crash", k.opts.Clock); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
}

func TestDifferentArtifactRollbackDoesNotPermitOldSignatureOrDigestEquivocation(t *testing.T) {
	k := newSigner(t)
	s, path := create(t, k)
	v1 := k.base
	commit(t, s, k, v1)
	v2 := v1
	v2.Policy.Version = 2
	v2.Sequence = 2
	newModule := []byte("newer exact artifact bytes")
	v2.Policy.SHA256 = assignment.Digest(newModule)
	if err := s.Commit(k.verifyModule(t, v2, newModule), "revision-new-artifact", k.opts.Clock); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, s, path, v1.Target)
	// Old, still-unexpired and correctly signed deployment is not a rollback
	// authorization. Relabeling its sequence would invalidate its signature.
	if err := s.Commit(k.verify(t, v1), "revision-replayed-old-artifact", k.opts.Clock); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	// Re-signing old bytes with the latest version and a fresh deployment
	// sequence is same-version equivocation, not ordinary forward deployment.
	equivocation := v1
	equivocation.Sequence = 3
	equivocation.Policy.Version = 2
	if err := s.Commit(k.verify(t, equivocation), "revision-digest-equivocation", k.opts.Clock); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	rb := v1
	rb.Sequence = 3
	rb.Rollback = &assignment.Rollback{FromSequence: v2.Sequence, From: v2.Policy, Reason: "approved exact artifact recovery"}
	commit(t, s, k, rb)
	s = reopen(t, s, path, v1.Target)
	st := snapshot(t, s)
	e, err := assignment.Decode(st.Active.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if e.Deployment.Policy.SHA256 != v1.Policy.SHA256 || st.Policies[v1.Policy.ID].SHA256 != v2.Policy.SHA256 || st.HighWater != 3 {
		t.Fatal("rollback lost exact historical/current identities")
	}
}
