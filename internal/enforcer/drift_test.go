package enforcer

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestDriftCollector_RecordsPatterns(t *testing.T) {
	fc, enricher := newDriftCollector()

	enrich := func(eventType, comm string) {
		enricher.Enrich(&streaming.SecurityEvent{
			EventType: eventType,
			Comm:      comm,
			Timestamp: time.Now(),
		})
	}
	enrich("exec", "bash")
	enrich("exec", "bash")
	enrich("network", "curl")
	enrich("exec", "") // no comm: skipped

	e := &Enforcer{driftCollector: fc}
	fp := e.DriftFingerprint()
	if fp == nil {
		t.Fatal("DriftFingerprint = nil, want a snapshot")
	}
	bash, ok := fp.Vectors["exec:bash"]
	if !ok || bash <= 0 {
		t.Errorf("exec:bash rate = %v (present: %v), want > 0", bash, ok)
	}
	curl := fp.Vectors["network:curl"]
	if curl <= 0 {
		t.Fatalf("network:curl rate = %v, want > 0", curl)
	}
	// Both counters share the same elapsed window, so their ratio is the
	// count ratio regardless of the elapsed time.
	if got, want := bash/curl, 2.0; got < want*0.99 || got > want*1.01 {
		t.Errorf("bash/curl rate ratio = %v, want ~2", got)
	}
	if _, ok := fp.Vectors["exec:"]; ok {
		t.Error(`pattern "exec:" recorded for an event with no comm`)
	}
}

func TestDriftFingerprint_DisabledIsNil(t *testing.T) {
	var e Enforcer
	if fp := e.DriftFingerprint(); fp != nil {
		t.Errorf("DriftFingerprint = %+v, want nil when drift is off", fp)
	}
}
