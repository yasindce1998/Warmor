package main

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func TestWindowsFleetPublicationFailsBeforeMutation(t *testing.T) {
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	old := readFixture(t)
	for _, existing := range []bool{true, false} {
		name := "fresh"
		if existing {
			name = "signed-local"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.wasm")
			if existing {
				writeFile(t, path, string(old))
				writeFile(t, path+".sig", string(sk.SignPolicyFile(old)))
			}
			a := &policyserver.PolicyAssignment{PolicyID: "p", Version: 2, Signature: sk.Sign(old)}
			activations, syncs := 0, 0
			stager := policyRevisionStager{verifyKey: sk.Public, dirSync: func(string) error { syncs++; return nil }}
			hook := stager.updateHandler(path, func(string, func() error) error { activations++; return nil })
			for attempt := 0; attempt < 2; attempt++ {
				if err := hook(a, old); !errors.Is(err, errPolicyRevisionUnsupported) {
					t.Fatalf("unsupported publication acknowledged: %v", err)
				}
			}
			if err := writeDownloadedPolicy(path, a, old); !errors.Is(err, errPolicyRevisionUnsupported) {
				t.Fatalf("direct publisher bypassed platform gate: %v", err)
			}
			if activations != 0 || syncs != 0 {
				t.Fatalf("unsupported publisher performed activation/filesystem operations: activations=%d syncs=%d", activations, syncs)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !existing {
				if len(entries) != 0 {
					t.Fatalf("unsupported publisher mutated fresh policy directory: %v", entries)
				}
				return
			}
			if len(entries) != 2 {
				t.Fatalf("unsupported publisher created aliases/revisions: %v", entries)
			}
			if got, err := enforcer.ReadVerifiedPolicy(path, sk.Public); err != nil || !bytes.Equal(got, old) {
				t.Fatalf("unsupported fleet update changed signed local pair: %v", err)
			}
			if res, err := enforcer.ValidatePolicy(context.Background(), path, sk.Public); err != nil || !res.Loaded || !res.SignatureVerified {
				t.Fatalf("local signed startup no longer works: %+v %v", res, err)
			}
		})
	}
}

func TestWindowsFleetClientReportsFailureWithoutSuccessAcknowledgement(t *testing.T) {
	ctx := context.Background()
	srv := policyserver.NewServer(policyserver.ServerConfig{Insecure: true})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	data := readFixture(t)
	module := writeFile(t, filepath.Join(t.TempDir(), "upload.wasm"), string(data))
	if err := srv.Store().CreateSignedPolicy(&policyserver.Policy{ID: "p"}, module, sk.SignPolicyFile(data)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.wasm")
	updates := make(chan error, 4)
	activate := policyUpdateHandler(path, sk.Public, func(string, func() error) error {
		t.Error("unsupported fleet client reached activation")
		return nil
	})
	c, err := newPolicyClient(policyClientConfig{ServerURL: ts.URL, AgentID: "windows-agent", Verify: verifyDownload(sk.Public)}, func(a *policyserver.PolicyAssignment, b []byte) error {
		err := activate(a, b)
		select {
		case updates <- err:
		default:
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	pollCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); c.PollLoop(pollCtx, 10*time.Millisecond) }()
	defer func() { cancel(); <-done }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-updates:
			if !errors.Is(err, errPolicyRevisionUnsupported) {
				t.Fatalf("unsupported client update returned success: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("unsupported client update was not retried")
		}
	}
	// The callback notification precedes the poll's error bookkeeping. Keep
	// polling alive and wait for an error heartbeat, rather than racing its
	// completion or replacing the last error with cancellation of a new poll.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := c.SendHeartbeat(ctx); err != nil {
			t.Fatal(err)
		}
		a, ok := srv.Store().GetAgent("windows-agent")
		if !ok || a.PolicyID != "" || a.PolicyVersion != 0 || a.PolicyHash != "" {
			t.Fatalf("unsupported activation produced a success acknowledgement: %+v", a)
		}
		if strings.Contains(a.ActivationError, "unsupported on Windows") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unsupported activation not reported in heartbeat: %+v", a)
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Lstat(path + ".revisions"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported client changed restart layout: %v", err)
	}
}

func TestWindowsDaemonRejectsFleetBeforeStartupSideEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "policy.wasm")
	r := runChild(t, nil, "--server", "http://127.0.0.1:1", "--policy", path, "--policy-fallback", wasmFixture)
	if r.code != 1 || !strings.Contains(r.stderr, "unsupported on Windows") {
		t.Fatalf("daemon did not reject unsupported fleet configuration: code=%d stderr=%s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported startup seeded fallback or changed policy directory: %v", err)
	}
	if strings.Contains(r.stderr, "WASM-Powered") || strings.Contains(r.stderr, "platform monitor") {
		t.Fatalf("unsupported startup reached platform initialization: %s", r.stderr)
	}
}

// Keep the existing portable signature semantics explicit on the unsupported
// publication platform: verifying bytes is not the same as activating them.
func TestWindowsVerifyDownloadRejectsInvalidSignatures(t *testing.T) {
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	good := readFixture(t)
	if err := verifyDownload(sk.Public)(&policyserver.PolicyAssignment{Signature: sk.Sign(good)}, good); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownload(sk.Public)(&policyserver.PolicyAssignment{}, good); !errors.Is(err, crypto.ErrPolicyUnsigned) {
		t.Fatalf("unsigned download accepted: %v", err)
	}
	if err := verifyDownload(sk.Public)(&policyserver.PolicyAssignment{Signature: sk.Sign([]byte("different"))}, good); !errors.Is(err, crypto.ErrPolicySignatureInvalid) {
		t.Fatalf("bad signature accepted: %v", err)
	}
}
