package policyserver

import (
	"errors"
	"net/http"

	"github.com/yasindce1998/warmor/internal/drift"
)

// Bounds on agent-supplied fingerprints: they are untrusted input that
// lives in server memory (and drives anomaly reports), so a runaway or
// hostile agent must not be able to grow it without bound.
const (
	// MaxFingerprintPatterns bounds the distinct behavior patterns
	// (event-type+comm pairs) one agent may report.
	MaxFingerprintPatterns = 10_000
	// MaxFingerprintImageKeyLen bounds the grouping key length.
	MaxFingerprintImageKeyLen = 256
)

// validateFingerprint rejects fingerprints that are oversized or missing
// the fields the fleet comparison keys on.
func validateFingerprint(fp *drift.BehaviorFingerprint) error {
	if fp.ImageHash == "" {
		return errors.New("fingerprint image_hash is required")
	}
	if len(fp.ImageHash) > MaxFingerprintImageKeyLen {
		return errors.New("fingerprint image_hash too long")
	}
	if len(fp.Vectors) > MaxFingerprintPatterns {
		return errors.New("fingerprint has too many patterns")
	}
	return nil
}

// driftStatusResponse is the admin drift view: per-image fleet status and
// every anomaly currently detected across the fleet.
type driftStatusResponse struct {
	Images    []drift.FleetStatus  `json:"images"`
	Anomalies []drift.DriftAnomaly `json:"anomalies"`
}

// handleAdminDrift reports fleet drift state.
// GET /api/v1/admin/drift — per-image fleet status and all anomalies.
// GET /api/v1/admin/drift?agent_id=<id> — only that agent's anomalies.
func (s *Server) handleAdminDrift(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := driftStatusResponse{
		Images:    s.drift.Status(),
		Anomalies: []drift.DriftAnomaly{},
	}
	agentID := r.URL.Query().Get("agent_id")
	for _, image := range s.drift.Images() {
		for _, a := range s.drift.Anomalies(image) {
			if agentID == "" || a.AgentID == agentID {
				resp.Anomalies = append(resp.Anomalies, a)
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
