package enforcer

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/pkg/api"
)

// earlyDenyCase drives a userspace deny path that does not go through WASM
// evaluation. Each case returns a fresh event on every call.
type earlyDenyCase struct {
	name  string
	setup func(t *testing.T, e *Enforcer) func() *api.Event
}

func earlyDenyCases() []earlyDenyCase {
	return []earlyDenyCase{
		{
			name: "netfilter",
			setup: func(t *testing.T, e *Enforcer) func() *api.Event {
				nf, err := NewNetFilter(NetFilterConfig{BlockCIDRs: []string{"10.0.0.0/8"}})
				if err != nil {
					t.Fatal(err)
				}
				e.netFilter = nf
				return func() *api.Event {
					return &api.Event{PID: 0, Type: api.EventTypeNetwork,
						Network: &api.NetworkEvent{RemoteAddr: "10.0.0.1"}}
				}
			},
		},
		{
			name: "sandbox",
			setup: func(t *testing.T, e *Enforcer) func() *api.Event {
				if err := e.sandbox.ApplySandbox(0, "network-deny"); err != nil {
					t.Fatal(err)
				}
				return func() *api.Event {
					return &api.Event{PID: 0, Type: api.EventTypeNetwork,
						Network: &api.NetworkEvent{RemoteAddr: "8.8.8.8"}}
				}
			},
		},
		{
			name: "escape",
			setup: func(t *testing.T, e *Enforcer) func() *api.Event {
				withEscape(t, e, EscapeDeny)
				return func() *api.Event { return nsenterEvent(0) }
			},
		},
	}
}

// Every userspace deny path must agree on stats, the audit-denied Prometheus
// counter and telemetry, whether it enforces or downgrades to an audit.
func TestEarlyDenyPaths_ReportConsistentOutcome(t *testing.T) {
	for _, tc := range earlyDenyCases() {
		t.Run(tc.name+"/enforce", func(t *testing.T) {
			e, _ := newTestEnforcer(t, testEnforcerOpts{})
			attachTestTelemetry(t, e)
			newEvent := tc.setup(t, e)
			before := testutil.ToFloat64(metrics.AuditDeniedTotal)

			for range 2 {
				e.handleEvent(newEvent())
			}

			if got := e.GetStats(); got.Denied != 2 {
				t.Fatalf("stats = %+v, want 2 denies", got)
			}
			if s := e.telemetry.Snapshot(); s.Total != 2 || s.Denied != 2 || s.Excluded != 0 {
				t.Fatalf("telemetry = %+v, want 2 counted denies", s)
			}
			if delta := testutil.ToFloat64(metrics.AuditDeniedTotal) - before; delta != 0 {
				t.Fatalf("warmor_audit_denied_total delta = %v, want 0 for enforced denies", delta)
			}
		})

		t.Run(tc.name+"/audit", func(t *testing.T) {
			e, _ := newTestEnforcer(t, testEnforcerOpts{audit: true})
			attachTestTelemetry(t, e)
			newEvent := tc.setup(t, e)
			before := testutil.ToFloat64(metrics.AuditDeniedTotal)

			for range 2 {
				e.handleEvent(newEvent())
			}

			if got := e.GetStats(); got.AuditDenied != 2 || got.Denied != 0 {
				t.Fatalf("stats = %+v, want 2 audit denies", got)
			}
			if s := e.telemetry.Snapshot(); s.Total != 0 || s.Excluded != 2 || s.Denied != 0 {
				t.Fatalf("telemetry = %+v, want 2 excluded audit denies", s)
			}
			if delta := testutil.ToFloat64(metrics.AuditDeniedTotal) - before; delta != 2 {
				t.Fatalf("warmor_audit_denied_total delta = %v, want 2", delta)
			}
		})
	}
}

func TestCachedDeny_ReportsEveryDeny(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "enforce"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			e, _ := newTestEnforcer(t, testEnforcerOpts{audit: audit})
			attachTestTelemetry(t, e)
			event := &api.Event{PID: 0, UID: 0, Comm: "bash", Filename: "/bin/bash"}
			before := testutil.ToFloat64(metrics.AuditDeniedTotal)

			e.handleEvent(event) // miss
			e.handleEvent(event) // hit: must still report the cached deny

			stats := e.GetStats()
			if stats.CacheHits != 1 {
				t.Fatalf("stats = %+v, want one cache hit", stats)
			}
			s := e.telemetry.Snapshot()
			wantDelta := float64(0)
			if audit {
				if stats.AuditDenied != 2 || s.Excluded != 2 || s.Total != 0 {
					t.Fatalf("audit stats = %+v, telemetry = %+v, want 2 excluded audit denies", stats, s)
				}
				wantDelta = 2
			} else if stats.Denied != 2 || s.Denied != 2 || s.Total != 2 {
				t.Fatalf("stats = %+v, telemetry = %+v, want 2 counted denies (miss and hit)", stats, s)
			}
			if delta := testutil.ToFloat64(metrics.AuditDeniedTotal) - before; delta != wantDelta {
				t.Fatalf("warmor_audit_denied_total delta = %v, want %v", delta, wantDelta)
			}
		})
	}
}

// CacheMisses must count real cache lookups, not be derived from decision
// totals: an early deny never consults the cache and must not be a miss.
func TestGetStats_CacheMissesExcludesEarlyDenies(t *testing.T) {
	e, _ := newTestEnforcer(t, testEnforcerOpts{netFilter: &NetFilterConfig{BlockCIDRs: []string{"10.0.0.0/8"}}})
	blocked := &api.Event{PID: 0, Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{RemoteAddr: "10.0.0.1"}}
	allowed := &api.Event{PID: 0, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"}
	before := testutil.ToFloat64(metrics.CacheMissesTotal)

	e.handleEvent(blocked) // early deny, no cache lookup
	e.handleEvent(allowed) // one real miss

	stats := e.GetStats()
	if stats.Denied != 1 || stats.Allowed != 1 {
		t.Fatalf("stats = %+v, want one deny and one allow", stats)
	}
	if stats.CacheMisses != 1 {
		t.Fatalf("CacheMisses = %d, want 1 (early deny is not a miss)", stats.CacheMisses)
	}
	if delta := testutil.ToFloat64(metrics.CacheMissesTotal) - before; delta != 1 {
		t.Fatalf("warmor_cache_misses_total delta = %v, want 1", delta)
	}
}
