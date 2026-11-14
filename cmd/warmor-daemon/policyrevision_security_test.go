//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
	"github.com/yasindce1998/warmor/internal/wasm/wasmtest"
)

func requireSignedStartupPair(t *testing.T, path string, sk *crypto.SigningKey, want []byte) {
	t.Helper()
	if got, err := enforcer.ReadVerifiedPolicy(path, sk.Public); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("previous signed startup pair changed: %q %v", got, err)
	}
	if res, err := enforcer.ValidatePolicy(context.Background(), path, sk.Public); err != nil || !res.Loaded || !res.SignatureVerified {
		t.Fatalf("signed startup pair is not loadable: %+v %v", res, err)
	}
}

func TestPolicyRevisionLegacySymlinkPreservesActualSignedPair(t *testing.T) {
	for _, failure := range []string{"interrupted-stage", "load", "publication"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "actual.wasm")
			path := filepath.Join(dir, "policy.wasm")
			sk, err := crypto.GenerateSigningKey()
			if err != nil {
				t.Fatal(err)
			}
			old := readFixture(t)
			writeFile(t, target, string(old))
			writeFile(t, target+".sig", string(sk.SignPolicyFile(old)))
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			// A signature beside the module-only symlink is unrelated. Exercise
			// both its absence and a present-but-wrong signature.
			if failure == "publication" {
				writeFile(t, path+".sig", string(sk.SignPolicyFile([]byte("wrong module"))))
			}
			requireSignedStartupPair(t, path, sk, old)
			next := wasmtest.ConstPolicy(0, &[3]uint32{})
			if failure == "load" {
				next = []byte("invalid WASM")
			}
			a := &policyserver.PolicyAssignment{PolicyID: "p", Version: 2, Signature: sk.Sign(next)}
			stager := policyRevisionStager{verifyKey: sk.Public}
			if failure == "interrupted-stage" {
				r, err := stager.stage(path, a, next)
				if err != nil {
					t.Fatal(err)
				}
				defer r.discard()
				// No candidate activation/commit, as after interruption.
			} else {
				hook := stager.updateHandler(path, func(candidate string, commit func() error) error {
					if _, err := enforcer.ValidatePolicy(context.Background(), candidate, sk.Public); err != nil {
						return err
					}
					previous := filepath.Join(path+".revisions", "previous")
					if err := os.Mkdir(previous, 0o700); err != nil {
						return err
					}
					writeFile(t, filepath.Join(previous, "block-rename"), "injected publication failure")
					return commit()
				})
				if err := hook(a, next); err == nil {
					t.Fatal("failed activation acknowledged")
				}
			}
			requireSignedStartupPair(t, path, sk, old)
			requireSignedStartupPair(t, target, sk, old)
		})
	}
}

func TestPolicyRevisionMigrationValidatesBeforeReplacingAliases(t *testing.T) {
	dir := t.TempDir()
	target, path := filepath.Join(dir, "actual.wasm"), filepath.Join(dir, "policy.wasm")
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	old := readFixture(t)
	writeFile(t, target, string(old))
	writeFile(t, target+".sig", string(sk.SignPolicyFile(old)))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	stager := policyRevisionStager{verifyKey: wrongKey.Public}
	if r, err := stager.stage(path, &policyserver.PolicyAssignment{}, old); err == nil {
		r.discard()
		t.Fatal("migration published a pair that did not verify against the configured key")
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("validation failure replaced original module alias: %q %v", got, err)
	}
	if _, err := os.Lstat(path + ".sig"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validation failure changed original signature alias: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(path+".revisions", "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unverified migration acquired the startup pointer: %v", err)
	}
	requireSignedStartupPair(t, path, sk, old)
	// Also reject an invalid recovery pointer left before alias replacement.
	// It must not override the still-valid original symlink on the next poll.
	legacy, err := stager.create(path+".revisions", &policyserver.PolicyAssignment{}, old, wrongKey.SignPolicyFile(old))
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.commit(); err != nil {
		t.Fatal(err)
	}
	stager.verifyKey = sk.Public
	if r, err := stager.stage(path, &policyserver.PolicyAssignment{}, old); err == nil {
		r.discard()
		t.Fatal("migration resumed an invalid signed recovery pair")
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("invalid recovery replaced original module alias: %q %v", got, err)
	}
	requireSignedStartupPair(t, path, sk, old)
}

func TestPolicyRevisionRetriesFailedAliasParentSyncBeforeAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.wasm")
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	old := readFixture(t)
	writeFile(t, path, string(old))
	writeFile(t, path+".sig", string(sk.SignPolicyFile(old)))
	next := wasmtest.ConstPolicy(0, &[3]uint32{})
	a := &policyserver.PolicyAssignment{PolicyID: "p", Version: 2, Signature: sk.Sign(next)}
	parentSyncs, activations, acknowledgements := 0, 0, 0
	syncFailure := errors.New("injected alias parent fsync failure")
	syncDir := func(p string) error {
		if p == dir {
			parentSyncs++
			if parentSyncs <= 2 {
				return syncFailure
			}
		}
		return syncPolicyDir(p)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		// A fresh stager models losing in-memory migration state on restart.
		hook := (policyRevisionStager{verifyKey: sk.Public, dirSync: syncDir}).updateHandler(path, func(candidate string, commit func() error) error {
			activations++
			if _, err := enforcer.ValidatePolicy(context.Background(), candidate, sk.Public); err != nil {
				return err
			}
			return commit()
		})
		err := hook(a, next)
		if err == nil {
			acknowledgements++
		}
		if parentSyncs != attempt {
			t.Fatalf("attempt %d skipped outstanding alias-parent barrier: calls=%d", attempt, parentSyncs)
		}
		if attempt <= 2 {
			if !errors.Is(err, syncFailure) || activations != 0 || acknowledgements != 0 {
				t.Fatalf("failed durability barrier acknowledged/activated: err=%v activations=%d acknowledgements=%d", err, activations, acknowledgements)
			}
			moduleAlias := filepath.Join(path+".revisions", "current", "module.wasm")
			for alias, want := range map[string]string{path: moduleAlias, path + ".sig": moduleAlias + ".sig"} {
				if got, err := os.Readlink(alias); err != nil || got != want {
					t.Fatalf("failure was not after alias replacement: %s -> %q %v", alias, got, err)
				}
			}
			requireSignedStartupPair(t, path, sk, old)
		} else if err != nil || activations != 1 || acknowledgements != 1 {
			t.Fatalf("recovered barrier did not allow exact retry: err=%v activations=%d acknowledgements=%d", err, activations, acknowledgements)
		}
	}
	requireSignedStartupPair(t, path, sk, next)
	requireSignedStartupPair(t, filepath.Join(path+".revisions", "previous", "module.wasm"), sk, old)
}
