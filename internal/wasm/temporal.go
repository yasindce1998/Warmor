package wasm

import (
	"time"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/pkg/api"
)

// TemporalABIVersion is the first policy ABI version whose modules are sent
// temporal context: the event's wall clock and container age (binary ABI
// offsets 245 and 249, JSON keys wall_clock_unix and container_age_ms).
//
// Modules declaring an older version, or none, never see either value, so
// their decisions are a function of the event fields alone and stay
// cacheable exactly as before. Only a module that opted in can make a
// decision that depends on time.
const TemporalABIVersion uint32 = 3

// TemporalFields is the fields-read mask of the temporal inputs.
const TemporalFields = compiler.FieldBitTime | compiler.FieldBitContainerAge

// temporalInputs returns the temporal context sent to ABI >= 3 policies:
// the event's wall clock as UTC Unix seconds and the container's age at the
// event in milliseconds, each 0 when unknown.
//
// The wall clock is the event's own Timestamp (when the operation was
// observed), not the time of evaluation, so a recorded event replays with
// the decision it was made with and tests control time through the event;
// PolicyEvaluator stamps events that have no timestamp. The age is
// Timestamp - ContainerStart. A known age is at least 1ms: a start slightly
// after the event (clock tick rounding) still means "just started". A start
// more than a second after the event means the clocks disagree, and the age
// is reported unknown.
func temporalInputs(event *api.Event) (wallUnix int64, ageMs uint64) {
	ts := event.Timestamp
	if ts.IsZero() || ts.Unix() <= 0 {
		return 0, 0
	}
	wallUnix = ts.Unix()
	if start := event.ContainerStart; !start.IsZero() {
		switch d := ts.Sub(start); {
		case d < -time.Second:
		case d < time.Millisecond:
			ageMs = 1
		default:
			ageMs = uint64(d.Milliseconds())
		}
	}
	return wallUnix, ageMs
}

// Temporal reports whether the pool's module is sent temporal context
// (declared ABI version >= TemporalABIVersion).
func (p *Pool) Temporal() bool { return p.temporal }

// TimeDependent reports whether the policy's decision for events of type t
// may depend on the wall clock or container age: the module is sent them
// and its fields-read declaration does not rule them out (an undeclared
// module may read anything). Such decisions must not be cached or
// compiled into the kernel map, since the same event can be decided
// differently a moment later.
func (p *Pool) TimeDependent(t api.EventType) bool {
	return p.temporal && p.FieldsRead(t)&TemporalFields != 0
}

// TimeDependent reports the evaluator's policy time dependence; see
// Pool.TimeDependent. A nil evaluator is conservatively time dependent.
func (e *PolicyEvaluator) TimeDependent(t api.EventType) bool {
	if e == nil || e.pool == nil {
		return true
	}
	return e.pool.TimeDependent(t)
}

// ReadsContainerAge reports whether the policy's decision for events of type
// t may depend on the container age, i.e. whether it is worth resolving the
// event's container start before evaluation.
func (e *PolicyEvaluator) ReadsContainerAge(t api.EventType) bool {
	if e == nil || e.pool == nil || !e.pool.temporal {
		return false
	}
	return e.pool.FieldsRead(t)&compiler.FieldBitContainerAge != 0
}
