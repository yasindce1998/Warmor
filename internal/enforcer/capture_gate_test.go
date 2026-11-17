package enforcer

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/lineage"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/pkg/api"
)

// gateSource is a minimal Evaluator whose only meaningful surface is its
// fields-read declaration. It stands in for a policy that declared it needs
// complete capture for specific fields.
type gateSource struct {
	fields    [3]uint32
	evaluated int
}

func (s *gateSource) FieldsRead(t api.EventType) uint32 {
	if t < api.EventTypeProcess || t > api.EventTypeNetwork {
		return policymeta.FieldsUnknown
	}
	return s.fields[t]
}
func (s *gateSource) Metadata() policymeta.Module                 { return policymeta.Module{} }
func (s *gateSource) TimeDependent(api.EventType) bool            { return false }
func (s *gateSource) ReadsContainerAge(api.EventType) bool        { return false }
func (s *gateSource) StaticRulesProcess() policymeta.StaticDomain { return policymeta.StaticDomain{} }
func (s *gateSource) StaticRulesNetwork() policymeta.StaticDomain { return policymeta.StaticDomain{} }
func (s *gateSource) DecisionCacheEligible(api.EventType) bool    { return false }
func (s *gateSource) LinuxKernelCacheEligible(api.EventType) bool { return false }
func (s *gateSource) Evaluate(context.Context, *api.Event) (*api.ActionResult, error) {
	s.evaluated++
	return &api.ActionResult{Action: api.ActionAllow, Reason: "evaluated", Timestamp: time.Now()}, nil
}
func (s *gateSource) Close(context.Context) error { return nil }

func gateDeclaration(fields ...uint32) [3]uint32 {
	var out [3]uint32
	copy(out[:], fields)
	return out
}

func TestCaptureQualityGate(t *testing.T) {
	declaresPPID := gateDeclaration(uint32(compiler.FieldBitPPID|compiler.FieldBitRequireCompleteCapture), 0, 0)
	trusted := func() *api.Event {
		return &api.Event{PID: 0, KernelTimestampNS: 1, PPID: 0, ParentComm: "bash", CgroupID: 9}
	}

	t.Run("deny on missing required field", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "deny"}
		verdict, logOnly := e.captureQualityGate(trusted(), &gateSource{fields: declaresPPID})
		if verdict == nil || verdict.Action != api.ActionDeny || verdict.Audit || logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want fail-closed deny", verdict, logOnly)
		}
	})

	t.Run("allow when present", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "deny"}
		event := trusted()
		event.PPID = 100
		verdict, logOnly := e.captureQualityGate(event, &gateSource{fields: declaresPPID})
		if verdict != nil || logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want no gate", verdict, logOnly)
		}
	})

	t.Run("truncation telemetry gates even for a declared path", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "deny"}
		event := trusted()
		event.TruncatedFields = []string{"filename"}
		fields := gateDeclaration(uint32(compiler.FieldBitPath|compiler.FieldBitRequireCompleteCapture), 0, 0)
		verdict, logOnly := e.captureQualityGate(event, &gateSource{fields: fields})
		if verdict == nil || verdict.Action != api.ActionDeny || logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want deny on truncated path", verdict, logOnly)
		}
	})

	t.Run("replay event is not falsely incomplete", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "deny"}
		event := &api.Event{PID: 0, PPID: 0, ParentComm: "", CgroupID: 0} // no KernelTimestampNS
		verdict, logOnly := e.captureQualityGate(event, &gateSource{fields: declaresPPID})
		if verdict != nil || logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want no gate for replay", verdict, logOnly)
		}
	})

	t.Run("no declaration means no gate", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "deny"}
		noFields := gateDeclaration()                        // no declaration at all
		noRequire := gateDeclaration(compiler.FieldBitPPID)  // no require-complete bit
		unknown := gateDeclaration(policymeta.FieldsUnknown) // undeclared policy
		for _, fields := range [][3]uint32{noFields, noRequire, unknown} {
			verdict, logOnly := e.captureQualityGate(trusted(), &gateSource{fields: fields})
			if verdict != nil || logOnly {
				t.Fatalf("fields %v gated an undeclaring policy", fields)
			}
		}
	})

	t.Run("audit mode records a would-deny", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "audit"}
		verdict, logOnly := e.captureQualityGate(trusted(), &gateSource{fields: declaresPPID})
		if verdict == nil || verdict.Action != api.ActionDeny || !verdict.Audit || logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want audited would-deny", verdict, logOnly)
		}
	})

	t.Run("log mode logs only", func(t *testing.T) {
		e := &Enforcer{onIncompleteInput: "log"}
		verdict, logOnly := e.captureQualityGate(trusted(), &gateSource{fields: declaresPPID})
		if verdict != nil || !logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want log-only", verdict, logOnly)
		}
	})

	t.Run("empty mode defaults to log", func(t *testing.T) {
		e := &Enforcer{}
		verdict, logOnly := e.captureQualityGate(trusted(), &gateSource{fields: declaresPPID})
		if verdict != nil || !logOnly {
			t.Fatalf("verdict = %+v, logOnly = %v, want default log-only", verdict, logOnly)
		}
	})
}

func newGateEnforcer(t *testing.T, mode string, source *gateSource) *Enforcer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Enforcer{
		evaluator:         source,
		cache:             cache.NewDecisionCache(100, time.Minute),
		actionHandler:     NewActionHandler(false),
		logger:            logging.NewLoggerWithWriter("error", io.Discard),
		metricsServer:     metrics.NewServer(-1),
		lineageTracker:    lineage.NewTracker(lineage.TrackerConfig{}),
		onIncompleteInput: mode,
		ctx:               ctx,
		cancel:            cancel,
	}
}

func TestHandleEvent_CaptureQualityGate(t *testing.T) {
	declaresPPID := gateDeclaration(uint32(compiler.FieldBitPPID|compiler.FieldBitRequireCompleteCapture), 0, 0)

	t.Run("deny replaces the verdict before evaluation or caching", func(t *testing.T) {
		source := &gateSource{fields: declaresPPID}
		e := newGateEnforcer(t, "deny", source)
		e.handleEvent(&api.Event{PID: 0, KernelTimestampNS: 1, PPID: 0, ParentComm: "bash", CgroupID: 9, Filename: "/bin/x"})
		if stats := e.GetStats(); stats.Denied != 1 || stats.Allowed != 0 {
			t.Fatalf("stats = %+v, want exactly one deny", stats)
		}
		if source.evaluated != 0 {
			t.Fatalf("policy evaluated %d times; gate must fail closed first", source.evaluated)
		}
		if size := e.cache.Stats().Size; size != 0 {
			t.Fatalf("gate verdict cached (%d entries); it is event-specific", size)
		}
	})

	t.Run("present field falls through to normal evaluation", func(t *testing.T) {
		source := &gateSource{fields: declaresPPID}
		e := newGateEnforcer(t, "deny", source)
		e.handleEvent(&api.Event{PID: 0, KernelTimestampNS: 1, PPID: 55, ParentComm: "bash", CgroupID: 9, Filename: "/bin/x"})
		if source.evaluated != 1 {
			t.Fatalf("policy evaluated %d times, want 1", source.evaluated)
		}
		if stats := e.GetStats(); stats.Allowed != 1 {
			t.Fatalf("stats = %+v, want one allow", stats)
		}
	})

	t.Run("audit mode does not enforce", func(t *testing.T) {
		source := &gateSource{fields: declaresPPID}
		e := newGateEnforcer(t, "audit", source)
		e.handleEvent(&api.Event{PID: 4242, KernelTimestampNS: 1, PPID: 0, ParentComm: "bash", CgroupID: 9, Filename: "/bin/x"})
		if source.evaluated != 0 {
			t.Fatalf("policy evaluated %d times; gate must short-circuit", source.evaluated)
		}
		if stats := e.GetStats(); stats.AuditDenied != 1 || stats.Denied != 0 {
			t.Fatalf("stats = %+v, want audit-denied only", stats)
		}
	})
}
