package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

func TestDriftHeartbeatOmitsUnidentifiedFingerprints(t *testing.T) {
	collector := drift.NewFingerprintCollector(time.Minute)
	collector.Record("local", "", "exec:bash")
	for _, tc := range []struct {
		name            string
		fp              *drift.BehaviorFingerprint
		wantFingerprint bool
	}{
		{"nothing observed", nil, false},
		{"host aggregate", collector.Snapshot("local"), false},
		{"blank identity", &drift.BehaviorFingerprint{ImageHash: " \t"}, false},
		{"future workload identity", &drift.BehaviorFingerprint{AgentID: "local", ImageHash: "sha256:real-workload-image", Vectors: map[string]float64{"exec:bash": 1}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan map[string]json.RawMessage, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/heartbeat" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				requests <- body
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("{}"))
			}))
			defer server.Close()
			t.Setenv(serverTokenEnv, "")
			client, err := newPolicyClient(policyClientConfig{
				ServerURL: server.URL, AgentID: "authenticated-agent",
				Fingerprint: identifiedDriftFingerprint(func() *drift.BehaviorFingerprint { return tc.fp }),
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.SendHeartbeat(context.Background()); err != nil {
				t.Fatal(err)
			}
			body := <-requests
			_, present := body["fingerprint"]
			if present != tc.wantFingerprint {
				t.Fatalf("fingerprint present = %v, want %v: %s", present, tc.wantFingerprint, body["fingerprint"])
			}
			if tc.wantFingerprint {
				var fp drift.BehaviorFingerprint
				if err := json.Unmarshal(body["fingerprint"], &fp); err != nil {
					t.Fatal(err)
				}
				if fp.ImageHash != tc.fp.ImageHash || fp.AgentID != "authenticated-agent" {
					t.Fatalf("identity changed incorrectly: %+v", fp)
				}
				if tc.fp.AgentID != "local" {
					t.Fatal("client mutated source snapshot")
				}
			}
		})
	}
	if identifiedDriftFingerprint(nil) != nil {
		t.Fatal("nil source should disable callback")
	}
}

func TestLocalDriftDoesNotBreakRealServerHeartbeat(t *testing.T) {
	_, server := startPolicyServer(t, policyserver.ServerConfig{Insecure: true}, false)
	t.Setenv(serverTokenEnv, "")
	collector := drift.NewFingerprintCollector(time.Minute)
	collector.Record("local", "", "exec:bash")
	client, err := newPolicyClient(policyClientConfig{
		ServerURL: server.URL, AgentID: "host-agent",
		Fingerprint: identifiedDriftFingerprint(func() *drift.BehaviorFingerprint { return collector.Snapshot("local") }),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.SendHeartbeat(context.Background()); err != nil {
		t.Fatalf("unidentified local observation broke heartbeat: %v", err)
	}
}
