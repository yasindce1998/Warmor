package wasm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// DefaultEvalTimeout bounds a single policy evaluation unless overridden
// with SetTimeout.
const DefaultEvalTimeout = 50 * time.Millisecond

// ErrEvaluationTimeout is returned (wrapped) when a policy evaluation did not
// finish within the evaluator's deadline. Callers must treat it like any
// evaluation error: fail closed, and do not cache the result.
var ErrEvaluationTimeout = errors.New("policy evaluation timed out")

// PolicyEvaluator handles policy evaluation with an instance pool.
type PolicyEvaluator struct {
	pool     *Pool
	hostname string
	timeout  time.Duration
	// now stamps events that carry no Timestamp, so a temporal policy
	// never sees an unknown wall clock for them.
	now func() time.Time
}

// NewPolicyEvaluator creates a new pool-backed policy evaluator with the
// DefaultEvalTimeout per-evaluation deadline.
func NewPolicyEvaluator(pool *Pool, hostname string) *PolicyEvaluator {
	return &PolicyEvaluator{
		pool:     pool,
		hostname: hostname,
		timeout:  DefaultEvalTimeout,
		now:      time.Now,
	}
}

// SetTimeout sets the per-evaluation deadline (including waiting for a pool
// instance). A non-positive d restores DefaultEvalTimeout; evaluations are
// never unbounded, since a looping policy would otherwise hang the caller.
func (e *PolicyEvaluator) SetTimeout(d time.Duration) {
	if d <= 0 {
		d = DefaultEvalTimeout
	}
	e.timeout = d
}

// Timeout returns the per-evaluation deadline.
func (e *PolicyEvaluator) Timeout() time.Duration { return e.timeout }

// ActionAuditDeny is the WASM ABI value for per-rule audit mode denials.
const ActionAuditDeny api.Action = 3

// Evaluate runs policy evaluation using an instance from the pool.
func (e *PolicyEvaluator) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
	start := time.Now()

	if event.Timestamp.IsZero() {
		// The policy's wall clock is the event's time (see
		// temporalInputs); stamp a copy rather than the caller's event.
		stamped := *event
		stamped.Timestamp = e.now()
		event = &stamped
	}

	timeout := e.timeout
	if timeout <= 0 {
		timeout = DefaultEvalTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	policy, err := e.pool.Get(ctx)
	if err != nil {
		return nil, e.wrapErr(ctx, fmt.Errorf("get policy from pool: %w", err))
	}

	action, err := policy.Evaluate(ctx, event)
	if err != nil {
		// The instance may be closed (deadline: wazero closes it to abort
		// the call) or left in an inconsistent state by a trap: never reuse
		// it. A replacement failure only shrinks the pool.
		_ = e.pool.Replace(policy)
		return nil, e.wrapErr(ctx, err)
	}

	// Map AUDIT_DENY from WASM to ActionDeny + Audit flag
	audit := false
	if action == ActionAuditDeny {
		action = api.ActionDeny
		audit = true
	}

	// Extract matched rule reason from WASM if available
	reason := policy.GetMatchedRule(ctx)
	if ctx.Err() != nil {
		// The deadline hit inside get_last_matched_rule, which closed the
		// instance. Fail closed like any other timed-out evaluation.
		_ = e.pool.Replace(policy)
		return nil, e.wrapErr(ctx, ctx.Err())
	}
	e.pool.Put(policy)
	if reason == "" {
		reason = e.buildReason(action, event)
	}

	result := &api.ActionResult{
		Action:    action,
		Reason:    reason,
		Timestamp: start,
		Cached:    false,
		Latency:   time.Since(start),
		Audit:     audit,
	}

	return result, nil
}

// wrapErr marks errors caused by the evaluation deadline with
// ErrEvaluationTimeout.
func (e *PolicyEvaluator) wrapErr(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w after %v: %v", ErrEvaluationTimeout, e.timeout, err)
	}
	return err
}

func (e *PolicyEvaluator) buildReason(action api.Action, event *api.Event) string {
	switch action {
	case api.ActionAllow:
		return "Policy allows execution"
	case api.ActionDeny:
		return fmt.Sprintf("Policy denies: %s by UID %d", event.Filename, event.UID)
	case api.ActionLog:
		return "Policy requires logging"
	default:
		return "Unknown action"
	}
}

// Close closes the underlying pool.
func (e *PolicyEvaluator) Close(ctx context.Context) error {
	return e.pool.Close(ctx)
}
