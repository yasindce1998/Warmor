package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func TestPolicyUpdateFailureKeepsDurableRevision(t *testing.T) {
	for _, failure := range []string{"load", "write", "commit"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.wasm")
			old := readFixture(t)
			sk, _ := crypto.GenerateSigningKey()
			writeFile(t, path, string(old))
			writeFile(t, path+".sig", string(sk.SignPolicyFile(old)))
			next := []byte("not a wasm module")
			a := &policyserver.PolicyAssignment{PolicyID: "p", Version: 2, Signature: sk.Sign(next)}
			if failure == "write" {
				writeFile(t, path+".revisions", "not a directory")
			}
			calls := 0
			hook := policyUpdateHandler(path, func(candidate string, commit func() error) error {
				calls++
				if failure == "load" {
					_, err := enforcer.ValidatePolicy(context.Background(), candidate, sk.Public)
					return err
				}
				return errors.New("injected commit/full disk failure")
			})
			if err := hook(a, next); err == nil {
				t.Fatal("failed activation reported success")
			}
			if failure == "write" && calls != 0 {
				t.Fatal("activation attempted after staging failure")
			}
			got, err := enforcer.ReadVerifiedPolicy(path, sk.Public)
			if err != nil || !bytes.Equal(got, old) {
				t.Fatalf("previous disk pair lost: %v", err)
			}
		})
	}
}

func TestPolicyRevisionInterruptedStageAndPreviousRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	sk, _ := crypto.GenerateSigningKey()
	old, next := []byte("old"), []byte("next")
	writeFile(t, path, string(old))
	writeFile(t, path+".sig", string(sk.SignPolicyFile(old)))
	r, err := stagePolicyRevision(path, &policyserver.PolicyAssignment{PolicyID: "p", Version: 2, Signature: sk.Sign(next)}, next)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := enforcer.ReadVerifiedPolicy(path, sk.Public); err != nil || !bytes.Equal(got, old) {
		t.Fatalf("staging changed active pair: %q %v", got, err)
	}
	if err := r.commit(); err != nil {
		t.Fatal(err)
	}
	if got, err := enforcer.ReadVerifiedPolicy(path, sk.Public); err != nil || !bytes.Equal(got, next) {
		t.Fatalf("committed pair invalid: %q %v", got, err)
	}
	previous := filepath.Join(path+".revisions", "previous", "module.wasm")
	if got, err := enforcer.ReadVerifiedPolicy(previous, sk.Public); err != nil || !bytes.Equal(got, old) {
		t.Fatalf("last-known-good lost: %q %v", got, err)
	}
}

func TestPolicyRevisionConcurrentPairConsistency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	sk, _ := crypto.GenerateSigningKey()
	first, second := []byte("first"), []byte("second")
	if err := writeDownloadedPolicy(path, &policyserver.PolicyAssignment{Signature: sk.Sign(first)}, first); err != nil {
		t.Fatal(err)
	}
	r, err := stagePolicyRevision(path, &policyserver.PolicyAssignment{Signature: sk.Sign(second)}, second)
	if err != nil {
		t.Fatal(err)
	}
	firstDir, err := os.Readlink(filepath.Join(r.root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			got, err := enforcer.ReadVerifiedPolicy(path, sk.Public)
			if err != nil || (!bytes.Equal(got, first) && !bytes.Equal(got, second)) {
				t.Errorf("mixed revision pair: %q %v", got, err)
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		target := firstDir
		if i%2 == 0 {
			target = filepath.Base(r.dir)
		}
		if err := replacePolicyLink(filepath.Join(r.root, "current"), target); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
}

func TestPolicyRevisionPointerWriteFailurePreservesCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := writeDownloadedPolicy(path, &policyserver.PolicyAssignment{}, []byte("old")); err != nil {
		t.Fatal(err)
	}
	r, err := stagePolicyRevision(path, &policyserver.PolicyAssignment{}, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(r.root, "previous")
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(previous, "block-rename"), "injected pointer write failure")
	if err := r.commit(); err == nil {
		t.Fatal("pointer write failure acknowledged")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "old" {
		t.Fatalf("failed publication changed active revision: %q %v", got, err)
	}
}
