package nodereceipt_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/nodereceipt"
	"github.com/yasindce1998/warmor/internal/nodereceipt/receipttest"
)

func TestCurrentContradictionWithdrawsOnlyAfterSessionSequenceAndFreshness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*nodereceipt.Receipt)
	}{
		{"different-digest", func(r *nodereceipt.Receipt) { r.Active.Digest = nodereceipt.Digest([]byte("other")) }},
		{"different-abi", func(r *nodereceipt.Receipt) { r.Active.ABI++ }},
		{"different-posture", func(r *nodereceipt.Receipt) { r.Active.Posture.Audit = !r.Active.Posture.Audit }},
		{"unacknowledged", func(r *nodereceipt.Receipt) { r.Active = nodereceipt.Activation{} }},
		{"different-manifest", func(r *nodereceipt.Receipt) { r.Manifest.PublicationEpoch = nodereceipt.Digest([]byte("other")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			good := f.register(t, strings.Repeat("a", 64))
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", good, nil); code != 204 {
				t.Fatal(code)
			}
			f.all(t, true)
			bad := good
			bad.Sequence++
			tc.change(&bad)
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", bad, nil); code != 409 {
				t.Fatal(code)
			}
			f.all(t, false)
			// The contradiction consumed its sequence. Neither the old positive
			// nor another positive using the negative's sequence may revive it.
			good.Sequence = bad.Sequence
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", good, nil); code != 409 {
				t.Fatal(code)
			}
			f.all(t, false)
			good.Sequence++
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", good, nil); code != 204 {
				t.Fatal(code)
			}
			f.all(t, true)
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", bad, nil); code != 409 {
				t.Fatal(code)
			}
			f.all(t, true) // stale contradiction cannot revoke newer evidence
			negative := good
			negative.Withdrawn = true
			negative.Sequence++
			if code := f.post(t, "/v1/node-receipts", "unreviewed-token", negative, nil); code != 401 {
				t.Fatal(code)
			}
			f.all(t, true)
			for _, stale := range []nodereceipt.Receipt{
				func() nodereceipt.Receipt { r := negative; r.Sequence = good.Sequence; return r }(),
				func() nodereceipt.Receipt { r := negative; r.Challenge = strings.Repeat("f", 64); return r }(),
				func() nodereceipt.Receipt { r := negative; r.BootEpoch = strings.Repeat("f", 64); return r }(),
				func() nodereceipt.Receipt { r := negative; r.MeasuredAt = time.Now().Add(-2 * time.Minute); return r }(),
				func() nodereceipt.Receipt { r := negative; r.MeasuredAt = time.Now().Add(time.Minute); return r }(),
			} {
				if code := f.post(t, "/v1/node-receipts", "bound-token-a", stale, nil); code != 409 {
					t.Fatal(code)
				}
				f.all(t, true)
			}
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", negative, nil); code != 204 {
				t.Fatal(code)
			}
			f.all(t, false)
			newBoot := f.register(t, strings.Repeat("b", 64))
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", newBoot, nil); code != 204 {
				t.Fatal(code)
			}
			negative.Sequence += 100
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", negative, nil); code != 409 {
				t.Fatal(code)
			}
			f.all(t, true) // old registration cannot withdraw a new session
		})
	}
}

func TestWithdrawalDoesNotRequireDesiredReadAndDesiredFailureConsumesSequence(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(fmt.Sprintf("withdraw=%t", withdraw), func(t *testing.T) {
			f := setup(t)
			failDesired := false
			cfg := receipttest.Config(f.k, func(context.Context) (nodereceipt.Manifest, error) {
				if failDesired {
					return nodereceipt.Manifest{}, errors.New("desired unavailable")
				}
				return f.m, nil
			})
			var err error
			f.s, err = nodereceipt.NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			f.http.Close()
			f.http = httptest.NewTLSServer(f.s.Handler())
			defer f.http.Close()
			r := f.register(t, strings.Repeat("a", 64))
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 204 {
				t.Fatal(code)
			}
			f.all(t, true)
			failDesired = true
			r.Sequence++
			r.Withdrawn = withdraw
			want := 503
			if withdraw {
				want = 204
			}
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != want {
				t.Fatal(code)
			}
			failDesired = false
			f.all(t, false)
			r.Withdrawn = false
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 409 {
				t.Fatal("sequence not consumed", code)
			}
			f.all(t, false)
			r.Sequence++
			if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 204 {
				t.Fatal(code)
			}
			f.all(t, true)
		})
	}
}

func TestPublicationEpochPreventsReceiptResurrectionWithoutIntermediateAggregation(t *testing.T) {
	f := setup(t)
	a := f.m
	r := f.register(t, strings.Repeat("a", 64))
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 204 {
		t.Fatal(code)
	}
	f.all(t, true)
	// Publisher durably changes A->B->A, with no registration, receipt or
	// aggregation during B. Only the nonreusable epoch changes in final A.
	f.m.PublicationEpoch = nodereceipt.Digest([]byte("publication-b"))
	f.m.Digest = nodereceipt.Digest([]byte("b"))
	f.m = a
	f.m.PublicationEpoch = nodereceipt.Digest([]byte("publication-a-again"))
	f.all(t, false)
	r.Sequence++
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 409 {
		t.Fatal(code)
	}
	f.all(t, false)
	fresh := f.register(t, strings.Repeat("b", 64))
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", fresh, nil); code != 204 {
		t.Fatal(code)
	}
	f.all(t, true)
	r.Sequence += 100
	r.Withdrawn = true
	if code := f.post(t, "/v1/node-receipts", "bound-token-a", r, nil); code != 409 {
		t.Fatal(code)
	}
	f.all(t, true)
}

func TestClientWithdrawsOnLocalActivationOrManifestFailures(t *testing.T) {
	for _, failure := range []string{"active-error", "active-drift", "manifest-missing", "manifest-invalid", "manifest-mismatch"} {
		t.Run(failure, func(t *testing.T) {
			f := setup(t)
			dir := t.TempDir()
			path, token := filepath.Join(dir, "manifest"), filepath.Join(dir, "token")
			write := func(p string, b []byte) {
				t.Helper()
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			b, _ := json.Marshal(f.m)
			write(path, b)
			write(token, []byte("bound-token-a"))
			active := nodereceipt.Activation{Digest: f.m.Digest, ABI: f.m.ABI, Posture: f.m.Posture, ActivatedAt: time.Now().Add(-time.Second)}
			var activeErr error
			c, err := nodereceipt.NewClient(nodereceipt.ClientConfig{URL: f.http.URL, TLS: receipttest.Trust(f.http), TokenPath: token, ManifestPath: path, Active: func() (nodereceipt.Activation, error) { return active, activeErr }})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Report(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.all(t, true)
			switch failure {
			case "active-error":
				activeErr = errors.New("local activation not acknowledged")
			case "active-drift":
				active.Digest = nodereceipt.Digest([]byte("active-b"))
			case "manifest-missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "manifest-invalid":
				write(path, []byte("invalid"))
			case "manifest-mismatch":
				other := f.m
				other.PublicationEpoch = nodereceipt.Digest([]byte("other"))
				data, _ := json.Marshal(other)
				write(path, data)
			}
			if err := c.Report(context.Background()); err == nil {
				t.Fatal("local failure acknowledged")
			}
			f.all(t, false)
			activeErr = nil
			active.Digest = f.m.Digest
			write(path, b)
			if err := c.Report(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.all(t, true)
			// Once the network is unavailable withdrawal is unconfirmed, not
			// instantaneous: the still-stored receipt is explicitly expiry-bound.
			f.http.Close()
			activeErr = errors.New("local readiness lost")
			if err := c.Report(context.Background()); err == nil || !strings.Contains(err.Error(), "expiry bound only") {
				t.Fatalf("missing honest withdrawal bound: %v", err)
			}
			f.all(t, true)
			result, err := f.s.Aggregate(context.Background(), f.m)
			if err != nil || result.ExpiresAt.IsZero() || result.ExpiresAt.After(time.Now().Add(time.Minute)) {
				t.Fatalf("unbounded offline evidence: %+v %v", result, err)
			}
		})
	}
}
