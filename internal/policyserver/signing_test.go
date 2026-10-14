package policyserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/crypto"
)

func testSigningKey(t *testing.T) *crypto.SigningKey {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

// writeSigned writes a WASM file and its detached .sig into dir.
func writeSigned(t *testing.T, sk *crypto.SigningKey, dir, name, content string) string {
	t.Helper()
	p := writeWASM(t, dir, name, content)
	if err := os.WriteFile(crypto.PolicySignaturePath(p), sk.SignPolicyFile([]byte(content)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func adminDo(t *testing.T, ts *httptest.Server, method, path, body string) (int, Policy) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, bytes.NewBufferString(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var p Policy
	_ = json.NewDecoder(resp.Body).Decode(&p)
	return resp.StatusCode, p
}

func getWASM(t *testing.T, ts *httptest.Server, query string) (int, string, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/v1/policy/wasm?" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header.Get(SignatureHeader)
}

func TestSignedPolicyUploadAndServe(t *testing.T) {
	sk := testSigningKey(t)
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// v1: pre-signed upload via the .sig file next to the module.
	writeSigned(t, sk, srv.policyDir, "v1.wasm", "one")
	status, p := adminDo(t, ts, http.MethodPost, "/api/v1/admin/policies", `{"id":"p","wasm_path":"v1.wasm"}`)
	if status != http.StatusCreated || !p.Signed {
		t.Fatalf("create: status %d, policy %+v", status, p)
	}

	// v2: unsigned upload is accepted (no server verify key) and served
	// without a signature header.
	writeWASM(t, srv.policyDir, "v2.wasm", "two")
	status, p = adminDo(t, ts, http.MethodPut, "/api/v1/admin/policies/p", `{"wasm_path":"v2.wasm"}`)
	if status != http.StatusOK || p.Signed {
		t.Fatalf("unsigned update: status %d, policy %+v", status, p)
	}

	// v3: signature supplied inline in the request.
	writeWASM(t, srv.policyDir, "v3.wasm", "three")
	inline := strings.TrimSpace(string(sk.SignPolicyFile([]byte("three"))))
	status, p = adminDo(t, ts, http.MethodPut, "/api/v1/admin/policies/p", `{"wasm_path":"v3.wasm","signature":"`+inline+`"}`)
	if status != http.StatusOK || !p.Signed || p.Version != 3 {
		t.Fatalf("inline-signed update: status %d, policy %+v", status, p)
	}

	for _, tc := range []struct {
		version, body string
		signed        bool
	}{{"1", "one", true}, {"2", "two", false}, {"3", "three", true}} {
		status, body, hdr := getWASM(t, ts, "policy_id=p&version="+tc.version)
		if status != http.StatusOK || body != tc.body {
			t.Fatalf("v%s: got %d %q", tc.version, status, body)
		}
		if !tc.signed {
			if hdr != "" {
				t.Errorf("v%s: unexpected signature header %q", tc.version, hdr)
			}
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(hdr)
		if err != nil {
			t.Fatalf("v%s: bad signature header %q: %v", tc.version, hdr, err)
		}
		if err := crypto.VerifyPolicySignature(sk.Public, []byte(body), sig); err != nil {
			t.Errorf("v%s: served signature does not verify: %v", tc.version, err)
		}
	}

	// A malformed signature is rejected even without a server verify key.
	writeWASM(t, srv.policyDir, "v4.wasm", "four")
	if status, _ := adminDo(t, ts, http.MethodPut, "/api/v1/admin/policies/p", `{"wasm_path":"v4.wasm","signature":"bm9wZQ=="}`); status != http.StatusBadRequest {
		t.Errorf("malformed inline signature: status %d, want 400", status)
	}
}

func TestServerVerifyKeyRequiresSignedUploads(t *testing.T) {
	sk := testSigningKey(t)
	other := testSigningKey(t)
	srv := NewServer(ServerConfig{Addr: ":0", Insecure: true, PolicyDir: t.TempDir(), VerifyKey: sk.Public})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	writeWASM(t, srv.policyDir, "unsigned.wasm", "u")
	if status, _ := adminDo(t, ts, http.MethodPost, "/api/v1/admin/policies", `{"id":"p","wasm_path":"unsigned.wasm"}`); status != http.StatusUnprocessableEntity {
		t.Errorf("unsigned upload: status %d, want 422", status)
	}
	writeSigned(t, other, srv.policyDir, "wrongkey.wasm", "w")
	if status, _ := adminDo(t, ts, http.MethodPost, "/api/v1/admin/policies", `{"id":"p","wasm_path":"wrongkey.wasm"}`); status != http.StatusUnprocessableEntity {
		t.Errorf("wrong-key upload: status %d, want 422", status)
	}
	if _, ok := srv.Store().GetPolicy("p"); ok {
		t.Fatal("rejected upload created a policy")
	}

	writeSigned(t, sk, srv.policyDir, "good.wasm", "g")
	if status, p := adminDo(t, ts, http.MethodPost, "/api/v1/admin/policies", `{"id":"p","wasm_path":"good.wasm"}`); status != http.StatusCreated || !p.Signed {
		t.Fatalf("signed upload: status %d, policy %+v", status, p)
	}

	// A tampered module (signature no longer matches) cannot be added as a
	// new version; the stored version is unchanged.
	path := writeSigned(t, sk, srv.policyDir, "v2.wasm", "two")
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status, _ := adminDo(t, ts, http.MethodPut, "/api/v1/admin/policies/p", `{"wasm_path":"v2.wasm"}`); status != http.StatusUnprocessableEntity {
		t.Errorf("tampered update: status %d, want 422", status)
	}
	if p, _ := srv.Store().GetPolicy("p"); p.Version != 1 {
		t.Errorf("version = %d after rejected update, want 1", p.Version)
	}

	// Store-level API enforces the key too.
	if err := srv.Store().UpdatePolicy("p", writeWASM(t, t.TempDir(), "x.wasm", "x")); !errors.Is(err, crypto.ErrPolicyUnsigned) {
		t.Errorf("unsigned store update: %v", err)
	}
}

// The detached signature is looked up inside the policy directory only: a
// .sig symlink pointing outside it is refused rather than followed.
func TestUploadSignatureConfinedToPolicyDir(t *testing.T) {
	sk := testSigningKey(t)
	srv, ts := setupTestServer(t)
	defer ts.Close()

	writeWASM(t, srv.policyDir, "p.wasm", "data")
	outside := filepath.Join(t.TempDir(), "evil.sig")
	if err := os.WriteFile(outside, sk.SignPolicyFile([]byte("data")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(srv.policyDir, "p.wasm.sig")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if status, _ := adminDo(t, ts, http.MethodPost, "/api/v1/admin/policies", `{"id":"p","wasm_path":"p.wasm"}`); status != http.StatusBadRequest {
		t.Errorf("out-of-dir signature: status %d, want 400", status)
	}
}

func TestClientVerifyHook(t *testing.T) {
	sk := testSigningKey(t)
	srv, ts := setupTestServer(t)
	defer ts.Close()
	if err := srv.Store().CreateSignedPolicy(&Policy{ID: "p"}, writeWASM(t, t.TempDir(), "p.wasm", "data"), sk.SignPolicyFile([]byte("data"))); err != nil {
		t.Fatal(err)
	}

	var gotSig []byte
	reject := true
	rec := newUpdateRecorder()
	c := NewClient(ClientConfig{
		ServerURL: ts.URL, AgentID: "a", OnUpdate: rec.onUpdate,
		Verify: func(a *PolicyAssignment, data []byte) error {
			gotSig = a.Signature
			if reject {
				return errors.New("rejected")
			}
			return crypto.VerifyPolicySignature(sk.Public, data, a.Signature)
		},
	})
	ctx := context.Background()
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}

	c.poll(ctx)
	if rec.count() != 0 {
		t.Fatal("OnUpdate called for a rejected policy")
	}
	if c.policyVersion != 0 {
		t.Fatalf("version advanced to %d after rejection", c.policyVersion)
	}
	if len(gotSig) != 64 {
		t.Fatalf("signature not passed to Verify: %x", gotSig)
	}

	// The rejected version is retried on the next poll.
	reject = false
	c.poll(ctx)
	if rec.count() != 1 || c.policyVersion != 1 {
		t.Fatalf("accepted policy not applied: updates=%d version=%d", rec.count(), c.policyVersion)
	}
}
