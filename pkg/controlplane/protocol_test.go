package controlplane

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestProtocolVersion(t *testing.T) {
	if ProtocolVersionString != strconv.Itoa(ProtocolVersion) {
		t.Fatalf("ProtocolVersionString = %q, want %d", ProtocolVersionString, ProtocolVersion)
	}
}

func TestRoutesShareAPIPrefix(t *testing.T) {
	routes := []string{
		RouteRegister, RouteHeartbeat, RoutePolicy, RoutePolicyWASM, RouteDeployment,
		RouteTelemetrySession, RouteContainersBind, RouteContainersPrefix,
		RouteAdminTelemetry, RouteAdminPolicies, RouteAdminPolicyPrefix,
		RouteAdminDeployments, RouteAdminAgents, RouteAdminRollouts,
		RouteAdminRolloutPrefix, RouteAdminDrift,
	}
	for _, route := range routes {
		if !strings.HasPrefix(route, APIPrefix+"/") {
			t.Errorf("route %q does not start with %q", route, APIPrefix)
		}
	}
}

func TestHeartbeatWireTypesRoundTrip(t *testing.T) {
	in := HeartbeatRequest{
		AgentID:       "node-1",
		PolicyID:      "p",
		PolicyVersion: 7,
		Fingerprint: &BehaviorFingerprint{
			AgentID: "node-1",
			Vectors: map[string]float64{"process": 1.5},
		},
		Telemetry: &TelemetrySnapshot{Sequence: 3},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out HeartbeatRequest
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.AgentID != in.AgentID || out.PolicyVersion != in.PolicyVersion {
		t.Fatalf("round-trip lost heartbeat identity: %+v", out)
	}
	if out.Fingerprint == nil || out.Fingerprint.Vectors["process"] != 1.5 {
		t.Fatalf("round-trip lost fingerprint: %+v", out.Fingerprint)
	}
	if out.Telemetry == nil || out.Telemetry.Sequence != 3 {
		t.Fatalf("round-trip lost telemetry: %+v", out.Telemetry)
	}
}
