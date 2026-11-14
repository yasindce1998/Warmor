package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/crypto/assignment"
	"github.com/yasindce1998/warmor/internal/telemetry"
)

func TestSignedTelemetryDisabledWithoutWeakeningDeploymentAcknowledgements(t *testing.T) {
	artifact, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	fleetPath := filepath.Join(t.TempDir(), "fleet.json")
	fleet := openTestStore(t, fleetPath, StoreOptions{VerifyKey: artifact.Public})
	// Deliberately collide signed policy identity/artifacts with a real legacy
	// rollout. Equal IDs/hashes are not signed assignment/cohort authorization.
	dir := filepath.Dir(fleetPath)
	if err := fleet.CreateSignedPolicy(&Policy{ID: "p"}, writeWASM(t, dir, "base.wasm", "module-1"), artifact.Sign([]byte("module-1"))); err != nil {
		t.Fatal(err)
	}
	if err := fleet.AddVersion("p", writeWASM(t, dir, "target.wasm", "module-2"), artifact.Sign([]byte("module-2")), false); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRolloutManager(fleet).CreateRollout(RolloutConfig{ID: "r", PolicyID: "p", Percentage: 50}); err != nil {
		t.Fatal(err)
	}
	store, err := NewTelemetryStore(testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	target := assignment.Target{Scope: "tenant/prod", Audience: "signed-node"}
	trust := assignment.Trust{"deployment": {Public: signer.Public, Target: target, CanRollback: true}}
	server := NewServer(ServerConfig{Store: fleet, JWTSecret: testJWTSecret, AssignmentTrust: trust, Telemetry: store})
	var requests atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if strings.HasPrefix(r.URL.Path, "/api/v1/deployment") && (r.Header.Get(telemetryEpochHeader) != "" || r.Header.Get(telemetrySessionHeader) != "") {
			t.Error("signed poll carried legacy telemetry lease")
		}
		server.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()
	request := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	now := time.Now().Unix()
	base := assignment.Deployment{Format: 1, KeyID: "deployment", Target: target, Sequence: 1, IssuedAt: now - 1, ExpiresAt: now + 60,
		Policy: assignment.Policy{ID: "p", Version: 2, SHA256: assignment.Digest([]byte("module-2")), ABI: 1, Compiler: "reviewed", Posture: assignment.Posture{Mode: "enforce", DefaultAction: "allow"}}}
	bundle := func(d assignment.Deployment, module string) assignment.Bundle {
		t.Helper()
		d.Policy.SHA256 = assignment.Digest([]byte(module))
		e, err := assignment.Sign(signer.Private, d)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := assignment.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		return assignment.Bundle{Envelope: wire, WASM: []byte(module), ArtifactSignature: artifact.Sign([]byte(module))}
	}
	publish := func(b assignment.Bundle) {
		t.Helper()
		wire, err := MarshalDeploymentBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		if w := request(http.MethodPost, "/api/v1/admin/deployments", telemetryToken(t, RoleAdmin, "admin"), wire); w.Code != http.StatusCreated {
			t.Fatalf("signed publish: %d %s", w.Code, w.Body.String())
		}
	}
	collector := &telemetry.Collector{}
	lease := telemetry.Session{Epoch: "old-epoch", SessionID: "old-session"}
	if err := collector.SetSession(lease); err != nil {
		t.Fatal(err)
	}
	prepared, err := collector.Prepare(telemetry.Assignment{Session: lease, AssignmentRevision: 1}, telemetry.Revision{PolicyID: "p", PolicyVersion: 2, PolicyHash: base.Policy.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	collector.Replace(prepared)
	updates := 0
	fail := false
	client := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: target.Audience, Token: telemetryToken(t, RoleAgent, target.Audience), SignedAssignments: true, Telemetry: collector,
		Verify: func(a *PolicyAssignment, module []byte) error {
			e, err := assignment.Decode(a.Envelope)
			if err != nil {
				return err
			}
			_, err = assignment.Verify(e, module, trust, assignment.VerifyOptions{Target: target, Clock: assignment.Clock{Now: time.Now(), Trusted: true}, SupportedABIs: []uint32{1}, AllowedCompilers: []string{"reviewed"}, MaxLifetime: time.Hour})
			return err
		}, OnUpdate: func(a *PolicyAssignment, _ []byte) error {
			if a.Telemetry != nil {
				t.Fatal("signed callback received unsigned telemetry assignment")
			}
			updates++
			if fail {
				return errors.New("durable activation refused")
			}
			return nil
		}})
	ctx := context.Background()
	if collector.Snapshot() != nil || client.telemetry != nil {
		t.Fatal("signed client retained collector")
	}
	if err := client.Register(ctx); err != nil {
		t.Fatal(err)
	}
	legacyPoll := httptest.NewRequest(http.MethodGet, "/api/v1/policy?agent_id="+target.Audience, nil)
	legacyPoll.Header.Set("Authorization", "Bearer "+client.token)
	legacyPoll.Header.Set(telemetryEpochHeader, lease.Epoch)
	legacyPoll.Header.Set(telemetrySessionHeader, lease.SessionID)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, legacyPoll)
	var legacyAssignment PolicyAssignment
	if err := json.Unmarshal(w.Body.Bytes(), &legacyAssignment); err != nil || w.Code != http.StatusOK || legacyAssignment.Telemetry != nil {
		t.Fatalf("signed relay attached unsigned rollout domain: %d %s %v", w.Code, w.Body.String(), err)
	}
	before := requests.Load()
	if err := client.AuthorizeTelemetry(ctx); err == nil || requests.Load() != before {
		t.Fatal("signed client attempted telemetry session negotiation")
	}
	checkAck := func(b assignment.Bundle, activationError bool) {
		t.Helper()
		if err := client.SendHeartbeat(ctx); err != nil {
			t.Fatal(err)
		}
		e, err := assignment.Decode(b.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := fleet.GetAgent(target.Audience)
		if a.DeploymentSequence != e.Deployment.Sequence || a.EnvelopeHash != assignment.Digest(b.Envelope) || a.PolicyID != e.Deployment.Policy.ID || a.PolicyVersion != int64(e.Deployment.Policy.Version) || (a.ActivationError != "") != activationError {
			t.Fatalf("signed ack changed: %+v", a)
		}
		if len(store.state.Sources) != 0 || len(store.state.Rollouts) != 0 {
			t.Fatal("signed source fabricated legacy telemetry domain")
		}
	}
	initial := bundle(base, "module-2")
	publish(initial)
	// Removing public trust cannot reinterpret retained signed relay state as
	// unsigned telemetry eligibility; neither report nor lease may be revived.
	withoutTrust := NewServer(ServerConfig{Store: fleet, JWTSecret: testJWTSecret, Telemetry: store})
	for _, path := range []string{"/api/v1/telemetry/session", "/api/v1/admin/telemetry?rollout_id=r"} {
		method, token := http.MethodPost, client.token
		if strings.Contains(path, "admin") {
			method, token = http.MethodGet, telemetryToken(t, RoleAdmin, "admin")
		}
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		withoutTrust.Handler().ServeHTTP(w, r)
		if !strings.Contains(w.Body.String(), signedTelemetryUnsupported) {
			t.Fatalf("retained deployment became legacy telemetry: %d %s", w.Code, w.Body.String())
		}
	}
	if err := client.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	checkAck(initial, false)
	base.Sequence++ // identical artifact, fresh signed authorization must activate
	renewal := bundle(base, "module-2")
	publish(renewal)
	if err := client.Poll(ctx); err != nil || updates != 2 {
		t.Fatalf("renewal skipped: %d %v", updates, err)
	}
	checkAck(renewal, false)
	if err := client.Poll(ctx); err != nil || updates != 2 {
		t.Fatal("conditional signed poll reactivated unchanged deployment", err)
	}
	base.Sequence++
	previous, _ := assignment.Decode(renewal.Envelope)
	base.Rollback = &assignment.Rollback{FromSequence: 2, From: previous.Deployment.Policy, Reason: "approved restore"}
	base.Policy.Version = 1
	rollback := bundle(base, "module-1")
	publish(rollback)
	fail = true
	if err := client.Poll(ctx); err == nil {
		t.Fatal("failed activation reported success")
	}
	checkAck(renewal, true)
	fail = false
	if err := client.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	checkAck(rollback, false)
	// Withdrawn authority is an error, not a legacy fallback or new ack.
	fleet.mu.Lock()
	delete(fleet.deployments, target.Audience)
	fleet.mu.Unlock()
	if err := client.Poll(ctx); err == nil {
		t.Fatal("missing signed deployment silently fell back")
	}
	checkAck(rollback, true)
	// Neither another agent nor admin can authorize a telemetry incarnation.
	for _, role := range []string{RoleAgent, RoleAdmin} {
		w := request(http.MethodPost, "/api/v1/telemetry/session", telemetryToken(t, role, target.Audience), nil)
		if (role == RoleAgent && w.Code != http.StatusConflict) || (role == RoleAdmin && w.Code != http.StatusForbidden) {
			t.Fatalf("signed session admission: %s %d %s", role, w.Code, w.Body.String())
		}
	}
	body, _ := json.Marshal(HeartbeatRequest{AgentID: target.Audience, PolicyID: client.policyID, PolicyVersion: client.policyVersion, PolicyHash: client.policyHash, DeploymentSequence: client.deploymentSequence, EnvelopeHash: client.envelopeHash, Telemetry: &prepared})
	if w := request(http.MethodPost, "/api/v1/heartbeat", telemetryToken(t, RoleAgent, "other-node"), body); w.Code != http.StatusForbidden {
		t.Fatal("cross-source heartbeat accepted", w.Code)
	}
	if w := request(http.MethodPost, "/api/v1/heartbeat", client.token, body); w.Code != http.StatusConflict {
		t.Fatal("signed heartbeat contributed legacy evidence", w.Code)
	}
	if w := request(http.MethodGet, "/api/v1/admin/telemetry?rollout_id=r", telemetryToken(t, RoleAdmin, "admin"), nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), signedTelemetryUnsupported) || !strings.Contains(w.Body.String(), `"report_only":true`) {
		t.Fatalf("signed report not explicitly pending: %d %s", w.Code, w.Body.String())
	}
	if err := fleet.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, fleetPath, StoreOptions{VerifyKey: artifact.Public})
	a, _ := reopened.GetAgent(target.Audience)
	if a.DeploymentSequence != client.deploymentSequence || a.EnvelopeHash != client.envelopeHash {
		t.Fatal("telemetry rejection undid durable signed acknowledgement")
	}
	rollout, _ := NewRolloutManager(reopened).GetRollout("r")
	if rollout.Status != "active" {
		t.Fatal("signed telemetry report performed rollout action")
	}
}

func TestLegacyTelemetryRejectsSignedAssignmentFields(t *testing.T) {
	for _, field := range []string{"envelope", "sequence"} {
		t.Run(field, func(t *testing.T) {
			a := PolicyAssignment{PolicyID: "p", Version: 1, WASMHash: strings.Repeat("a", 64)}
			if field == "envelope" {
				a.Envelope = []byte("unauthorized")
			} else {
				a.DeploymentSequence = 1
			}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, a) }))
			defer ts.Close()
			called := false
			client := NewClient(ClientConfig{ServerURL: ts.URL, AgentID: "agent", Telemetry: &telemetry.Collector{}, OnUpdate: func(*PolicyAssignment, []byte) error { called = true; return nil }})
			if err := client.Poll(context.Background()); err == nil || called {
				t.Fatal("signed fields reached unverified legacy activation")
			}
		})
	}
}

func TestSignedAcknowledgementInvalidatesLegacyEvidenceAndPoisonsOnFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalidate", true: "poison"}[fail], func(t *testing.T) {
			store, err := NewTelemetryStore(testTelemetryConfig())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			store.clock = func() time.Time { return now }
			if err := store.ConfigureGeneration("r", "g"); err != nil {
				t.Fatal(err)
			}
			snapshot, ack := telemetryTestSource(t, store, now, "agent", true)
			if _, err := store.ingest("agent", ack, snapshot); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Second)
			ack.LastHeartbeat = now
			snapshot.Sequence++
			snapshot.Total = 10
			if _, err := store.ingest("agent", ack, snapshot); err != nil || store.Report("r").Canary.Total != 10 {
				t.Fatal("fixture did not retain legacy contribution", err)
			}
			if fail {
				store.persist = func([]byte) error { return errors.New("disk full") }
			}
			err = store.observeAcknowledgement(HeartbeatRequest{AgentID: ack.ID, PolicyID: ack.PolicyID, PolicyVersion: ack.PolicyVersion, PolicyHash: ack.PolicyHash, DeploymentSequence: 1, EnvelopeHash: strings.Repeat("b", 64)})
			if (err != nil) != fail || (fail && store.fault == nil) || (!fail && !store.state.Sources[ack.ID].Suspended) {
				t.Fatal("signed ack retained legacy evidence without invalidation/poison", err)
			}
			if report := store.Report("r"); report.Canary.Total != 0 || report.Verdict != "pending" {
				t.Fatalf("signed acknowledgement kept legacy contribution reportable: %+v", report)
			}
			ack.DeploymentSequence = 1
			if _, err := store.ingest(ack.ID, ack, snapshot); !errors.Is(err, ErrTelemetryFence) {
				t.Fatal("signed ack satisfied legacy eligibility", err)
			}
		})
	}
}

func TestSignedTelemetryReportSuppressesRetainedLegacyHealth(t *testing.T) {
	store, err := NewTelemetryStore(testTelemetryConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	store.clock = func() time.Time { return now }
	if err := store.ConfigureGeneration("r", "g"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"baseline", "canary"} {
		snapshot, ack := telemetryTestSource(t, store, now, id, id == "canary")
		if _, err := store.ingest(id, ack, snapshot); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		ack.LastHeartbeat = now
		snapshot.Sequence++
		snapshot.Total = 10
		if _, err := store.ingest(id, ack, snapshot); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Second)
	if store.Report("r").Verdict != "healthy" {
		t.Fatal("fixture did not retain healthy legacy evidence")
	}
	server := NewServer(ServerConfig{JWTSecret: testJWTSecret, Telemetry: store, AssignmentTrust: assignment.Trust{"configured": {}}})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/telemetry?rollout_id=r", nil)
	r.Header.Set("Authorization", "Bearer "+telemetryToken(t, RoleAdmin, "admin"))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	var report TelemetryReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || w.Code != http.StatusOK || report.Verdict != "pending" || report.Reason != signedTelemetryUnsupported || !report.ReportOnly || report.Baseline.Total != 0 || report.Canary.Total != 0 || report.ObservedFor != 0 {
		t.Fatalf("signed relay exposed legacy health: %d %s %v", w.Code, w.Body.String(), err)
	}
}
