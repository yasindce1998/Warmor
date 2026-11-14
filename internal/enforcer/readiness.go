package enforcer

import "fmt"

// Ready reports a local active policy/capture posture, not controller desired
// generation acknowledgment or a gate on scheduling other workloads.
func (e *Enforcer) Ready() error {
	if !e.processing.Load() {
		return fmt.Errorf("event loop is not running")
	}
	if err := e.ctx.Err(); err != nil {
		return err
	}
	e.evaluatorMu.RLock()
	defer e.evaluatorMu.RUnlock()
	if e.evaluator == nil {
		return fmt.Errorf("no active policy")
	}
	if host, ok := e.evaluator.(*hostEvaluator); ok {
		if !host.Alive() {
			return fmt.Errorf("active policy host stopped")
		}
	} else if e.pool == nil {
		return fmt.Errorf("no active policy pool")
	}
	if p, ok := e.platform.(interface{ Ready() error }); ok {
		return p.Ready()
	}
	return nil
}
