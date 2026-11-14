//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func TestGenerationPendingRevisionRetainedAndSamePathRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	writeFile(t, path, "old")
	var candidate string
	calls := 0
	hook := policyUpdateHandler(path, nil, func(p string, commit func() error) error {
		calls++
		if calls == 1 {
			candidate = p
			return errors.Join(enforcer.ErrActivationPending, errors.New("fsync"))
		}
		if p != candidate {
			t.Fatal("uncertain commit retried with different immutable revision")
		}
		return commit()
	})
	a := &policyserver.PolicyAssignment{PolicyID: "p", Version: 2, WASMHash: "digest"}
	if err := hook(a, []byte("new")); !errors.Is(err, enforcer.ErrActivationPending) {
		t.Fatalf("pending acknowledged: %v", err)
	}
	if _, err := os.Stat(candidate); err != nil {
		t.Fatalf("live candidate discarded: %v", err)
	}
	if err := hook(a, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" || calls != 2 {
		t.Fatalf("recovery failed: %s %v calls=%d", got, err, calls)
	}
}

func TestGenerationChangedAssignmentResolvesPendingFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	writeFile(t, path, "old")
	calls := 0
	var pending string
	hook := policyUpdateHandler(path, nil, func(p string, commit func() error) error {
		calls++
		if calls == 1 {
			pending = p
			return enforcer.ErrActivationPending
		}
		if calls == 2 && p != pending {
			t.Fatal("new assignment abandoned unresolved live commit")
		}
		if calls == 3 && p == pending {
			t.Fatal("old recovery acknowledged as new assignment")
		}
		return commit()
	})
	if err := hook(&policyserver.PolicyAssignment{PolicyID: "p", Version: 1}, []byte("first")); !errors.Is(err, enforcer.ErrActivationPending) {
		t.Fatal(err)
	}
	if err := hook(&policyserver.PolicyAssignment{PolicyID: "p", Version: 2}, []byte("second")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" || calls != 3 {
		t.Fatalf("wrong assignment acknowledged: %s %v calls=%d", data, err, calls)
	}
}

func TestGenerationRepeatedCommitPreservesPreviousRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	writeFile(t, path, "old")
	r, err := stagePolicyRevision(path, &policyserver.PolicyAssignment{}, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.commit(); err != nil {
		t.Fatal(err)
	}
	if err := r.commit(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path+".revisions", "previous", "module.wasm"))
	if err != nil || string(data) != "old" {
		t.Fatalf("retry destroyed previous recovery pointer: %s %v", data, err)
	}
}
