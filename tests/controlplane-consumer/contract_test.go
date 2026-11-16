package consumer

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/warmor/pkg/controlplane"
	"github.com/yasindce1998/warmor/pkg/controlplane/conformance"
)

// Compile-time reference to the conformance suite: a hosted control plane
// must be able to import it from its own tests.
var _ = conformance.Run

func TestExternalContractUsage(t *testing.T) {
	// All wire types, including the ones whose canonical definitions live in
	// internal packages, must be nameable from a different Go module.
	req := controlplane.HeartbeatRequest{
		AgentID: "external-agent",
		Fingerprint: &controlplane.BehaviorFingerprint{
			AgentID: "external-agent",
			Vectors: map[string]float64{"file": 2},
		},
		Telemetry: &controlplane.TelemetrySnapshot{Sequence: 1},
	}
	assignment := controlplane.PolicyAssignment{
		PolicyID:  "external-policy",
		Version:   1,
		WASMHash:  "00",
		Telemetry: &controlplane.TelemetryAssignment{},
	}
	register := controlplane.RegisterRequest{ID: req.AgentID}
	agent := controlplane.Agent{ID: req.AgentID, Status: controlplane.AgentStatusActive}
	rollout := controlplane.Rollout{ID: "r", PolicyID: assignment.PolicyID}

	body, err := json.Marshal(struct {
		Heartbeat  controlplane.HeartbeatRequest
		Assignment controlplane.PolicyAssignment
		Register   controlplane.RegisterRequest
		Agent      controlplane.Agent
		Rollout    controlplane.Rollout
	}{req, assignment, register, agent, rollout})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("empty JSON")
	}
	if controlplane.RouteRegister != "/api/v1/register" ||
		controlplane.HeaderPolicySignature == "" ||
		controlplane.HeaderSignedAssignment == "" ||
		controlplane.MaxWASMDownloadSize <= 0 {
		t.Fatal("contract constants missing")
	}
}
