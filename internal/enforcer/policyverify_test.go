package enforcer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/metrics"
)

// signedFixture copies the WASM fixture into a temp dir, optionally writing
// a detached signature next to it, and returns the policy path.
func signedFixture(t *testing.T, sk *crypto.SigningKey) string {
	t.Helper()
	data, err := os.ReadFile(testPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.wasm")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if sk != nil {
		if err := os.WriteFile(crypto.PolicySignaturePath(path), sk.SignPolicyFile(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func newKey(t *testing.T) *crypto.SigningKey {
	t.Helper()
	sk, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestReloadPolicy_VerifyKey(t *testing.T) {
	isolateCacheDir(t)
	sk := newKey(t)
	path := signedFixture(t, sk)

	e, _ := newTestEnforcer(t, testEnforcerOpts{})
	e.policyPath = path
	e.verifyKey = sk.Public

	if err := e.ReloadPolicy(); err != nil {
		t.Fatalf("signed policy rejected: %v", err)
	}

	failures := func() float64 {
		var m dto.Metric
		if err := metrics.PolicySignatureFailures.WithLabelValues(metrics.PolicySourceFile).Write(&m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}

	// Tampered module: reload is refused and the active pool stays in place.
	before := failures()
	pool := e.pool
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(data, 0), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.ReloadPolicy(); !errors.Is(err, crypto.ErrPolicySignatureInvalid) {
		t.Fatalf("tampered policy: err = %v, want ErrPolicySignatureInvalid", err)
	}
	if e.pool != pool {
		t.Error("active policy replaced after a failed verification")
	}
	if got := failures(); got != before+1 {
		t.Errorf("signature failure metric = %v, want %v", got, before+1)
	}

	// Missing signature.
	if err := os.Remove(crypto.PolicySignaturePath(path)); err != nil {
		t.Fatal(err)
	}
	if err := e.ReloadPolicy(); !errors.Is(err, crypto.ErrPolicyUnsigned) {
		t.Fatalf("unsigned policy: err = %v, want ErrPolicyUnsigned", err)
	}

	// Signed by a different key.
	path = signedFixture(t, newKey(t))
	e.policyPath = path
	if err := e.ReloadPolicy(); !errors.Is(err, crypto.ErrPolicySignatureInvalid) {
		t.Fatalf("wrong key: err = %v, want ErrPolicySignatureInvalid", err)
	}
	if e.pool != pool {
		t.Error("active policy replaced after a failed verification")
	}
}

func TestReadVerifiedPolicy_RefusesYAML(t *testing.T) {
	sk := newKey(t)
	if _, err := ReadVerifiedPolicy("policy.yaml", sk.Public); err == nil || !strings.Contains(err.Error(), "compiled .wasm") {
		t.Fatalf("YAML policy with verify key: err = %v", err)
	}
}

func TestValidatePolicy(t *testing.T) {
	ctx := context.Background()
	sk := newKey(t)

	t.Run("wasm", func(t *testing.T) {
		res, err := ValidatePolicy(ctx, testPolicyPath, nil)
		if err != nil {
			t.Fatalf("ValidatePolicy: %v", err)
		}
		if !res.Loaded || res.SignatureVerified || res.Kind != "wasm" {
			t.Errorf("result = %+v", res)
		}
	})

	t.Run("signed", func(t *testing.T) {
		res, err := ValidatePolicy(ctx, signedFixture(t, sk), sk.Public)
		if err != nil {
			t.Fatalf("ValidatePolicy: %v", err)
		}
		if !res.Loaded || !res.SignatureVerified {
			t.Errorf("result = %+v", res)
		}
	})

	t.Run("unsigned with key", func(t *testing.T) {
		if _, err := ValidatePolicy(ctx, signedFixture(t, nil), sk.Public); !errors.Is(err, crypto.ErrPolicyUnsigned) {
			t.Errorf("err = %v, want ErrPolicyUnsigned", err)
		}
	})

	t.Run("not wasm", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.wasm")
		if err := os.WriteFile(path, []byte("not a module"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidatePolicy(ctx, path, nil); err == nil {
			t.Error("garbage module accepted")
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := ValidatePolicy(ctx, filepath.Join(t.TempDir(), "nope.wasm"), nil); err == nil {
			t.Error("missing file accepted")
		}
	})

	t.Run("yaml schema only", func(t *testing.T) {
		res, err := ValidatePolicy(ctx, filepath.Join("..", "..", "policies", "yaml-example", "policy.yaml"), nil)
		if err != nil {
			t.Fatalf("ValidatePolicy: %v", err)
		}
		if res.Kind != "yaml" || res.Loaded {
			t.Errorf("result = %+v", res)
		}
	})

	t.Run("yaml with precompiled wasm", func(t *testing.T) {
		dir := t.TempDir()
		src, _ := os.ReadFile(filepath.Join("..", "..", "policies", "yaml-example", "policy.yaml"))
		wasmData, _ := os.ReadFile(testPolicyPath)
		yamlPath := filepath.Join(dir, "policy.yaml")
		_ = os.WriteFile(yamlPath, src, 0o644)
		_ = os.WriteFile(filepath.Join(dir, "policy.wasm"), wasmData, 0o644)
		res, err := ValidatePolicy(ctx, yamlPath, nil)
		if err != nil {
			t.Fatalf("ValidatePolicy: %v", err)
		}
		if !res.Loaded || res.WASMPath != filepath.Join(dir, "policy.wasm") {
			t.Errorf("result = %+v", res)
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		_ = os.WriteFile(path, []byte("name: x\nrules:\n  - event: bogus\n"), 0o644)
		if _, err := ValidatePolicy(ctx, path, nil); err == nil {
			t.Error("invalid YAML accepted")
		}
	})
}
