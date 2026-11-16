package policyserver

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/pkg/controlplane/conformance"
)

// TestReferenceServerConformance proves that the published agent contract is
// executable against the in-tree server. The same suite is intended to be run
// by hosted control planes (warmor-saas) from their own tests.
func TestReferenceServerConformance(t *testing.T) {
	srv := NewServer(ServerConfig{Addr: ":0", Insecure: true, PolicyDir: t.TempDir()})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wasmPath := filepath.Join(t.TempDir(), "conformance.wasm")
	if err := os.WriteFile(wasmPath, []byte("\x00asm\x01\x00\x00\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Policy{ID: "conformance-policy", Name: "Conformance policy"}
	if err := srv.Store().CreatePolicy(p, wasmPath); err != nil {
		t.Fatal(err)
	}

	conformance.Run(t, conformance.Config{
		BaseURL:  ts.URL,
		AgentID:  "conformance-agent",
		PolicyID: p.ID,
	})
}
