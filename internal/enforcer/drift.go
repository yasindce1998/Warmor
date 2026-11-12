package enforcer

import (
	"time"

	"github.com/yasindce1998/warmor/internal/drift"
	"github.com/yasindce1998/warmor/internal/streaming"
)

// driftCollectorKey identifies this daemon's counters inside the
// FingerprintCollector. The fingerprint's real agent ID is stamped by the
// policy server client when it is shipped in a heartbeat.
const driftCollectorKey = "local"

// newDriftCollector returns the behavioral fingerprint collector for
// fleet drift detection (--drift) and its pipeline enricher. The enricher
// records one counter per "event_type:comm" pair (e.g. "exec:bash"), the
// granularity the server-side z-score comparison runs on: bounded
// cardinality (task comms) but fine enough to notice one node suddenly
// spawning shells or mining tools.
func newDriftCollector() (*drift.FingerprintCollector, streaming.Enricher) {
	fc := drift.NewFingerprintCollector(10 * time.Minute)
	record := func(ev *streaming.SecurityEvent) {
		if ev.Comm != "" {
			fc.Record(driftCollectorKey, "", ev.EventType+":"+ev.Comm)
		}
	}
	return fc, eventObserver{record}
}

// DriftFingerprint returns this daemon's current behavioral fingerprint,
// or nil when drift collection is disabled or nothing has been observed.
// The caller (the policy server client) fills in AgentID and ImageHash.
func (e *Enforcer) DriftFingerprint() *drift.BehaviorFingerprint {
	if e.driftCollector == nil {
		return nil
	}
	return e.driftCollector.Snapshot(driftCollectorKey)
}
