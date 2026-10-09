package enforcer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestActionHandler_AuditMode_DowngradesDeny(t *testing.T) {
	handler := NewActionHandler(true)

	event := &api.Event{
		PID:       1234,
		UID:       1000,
		GID:       1000,
		Comm:      "test",
		Filename:  "/tmp/malicious",
		Timestamp: time.Now(),
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "execution from temp dir",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if !result.Audit {
		t.Error("expected result.Audit to be true in audit mode")
	}

	stats := handler.GetStats()
	if stats.AuditDenied != 1 {
		t.Errorf("expected AuditDenied=1, got %d", stats.AuditDenied)
	}
	if stats.Denied != 0 {
		t.Errorf("expected Denied=0 in audit mode, got %d", stats.Denied)
	}
}

func TestActionHandler_AuditMode_AllowPassesThrough(t *testing.T) {
	handler := NewActionHandler(true)

	event := &api.Event{
		PID:  1234,
		UID:  0,
		Comm: "systemd",
	}

	result := &api.ActionResult{
		Action:    api.ActionAllow,
		Reason:    "allowed",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if result.Audit {
		t.Error("expected result.Audit to be false for allow actions")
	}

	stats := handler.GetStats()
	if stats.Allowed != 1 {
		t.Errorf("expected Allowed=1, got %d", stats.Allowed)
	}
}

func TestActionHandler_NoAudit_DenyNotDowngraded(t *testing.T) {
	handler := NewActionHandler(false)

	// PID 0 skips terminateProcess; a real PID here would SIGKILL whatever
	// host process owns it. The kill path is covered in actions_linux_test.go.
	event := &api.Event{
		PID:      0,
		UID:      1000,
		Comm:     "nc",
		Filename: "/usr/bin/nc",
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "blocked network tool",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if result.Audit {
		t.Error("expected result.Audit to be false when audit mode is off")
	}

	stats := handler.GetStats()
	if stats.Denied != 1 {
		t.Errorf("expected Denied=1, got %d", stats.Denied)
	}
	if stats.AuditDenied != 0 {
		t.Errorf("expected AuditDenied=0, got %d", stats.AuditDenied)
	}
}

func TestActionHandler_PerRuleAudit(t *testing.T) {
	handler := NewActionHandler(false)

	event := &api.Event{
		PID:      1234,
		UID:      1000,
		Comm:     "test",
		Filename: "/tmp/script.sh",
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "temp dir execution",
		Timestamp: time.Now(),
		Audit:     true, // per-rule audit set by WASM evaluator
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if !result.Audit {
		t.Error("expected result.Audit to remain true for per-rule audit")
	}

	stats := handler.GetStats()
	if stats.AuditDenied != 1 {
		t.Errorf("expected AuditDenied=1, got %d", stats.AuditDenied)
	}
	if stats.Denied != 0 {
		t.Errorf("expected Denied=0 for audit deny, got %d", stats.Denied)
	}
}

func TestActionHandler_LogAction(t *testing.T) {
	handler := NewActionHandler(false)

	result := &api.ActionResult{Action: api.ActionLog, Reason: "log it"}
	if err := handler.Enforce(context.Background(), &api.Event{PID: 0, Comm: "python"}, result); err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	stats := handler.GetStats()
	if stats.Logged != 1 || stats.Allowed != 0 || stats.Denied != 0 || stats.AuditDenied != 0 {
		t.Errorf("unexpected stats for log action: %+v", stats)
	}
	if result.Audit {
		t.Error("log action must not set Audit")
	}
}

func TestActionHandler_UnknownActionReturnsError(t *testing.T) {
	handler := NewActionHandler(false)

	err := handler.Enforce(context.Background(), &api.Event{PID: 0}, &api.ActionResult{Action: api.Action(42)})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}

	stats := handler.GetStats()
	if stats.Allowed+stats.Denied+stats.Logged+stats.AuditDenied != 0 {
		t.Errorf("unknown action must not be counted, got %+v", stats)
	}
}

func TestActionHandler_DenyPIDZeroIsNoop(t *testing.T) {
	handler := NewActionHandler(false)

	// PID 0 must never be signalled (kill(0, ...) would target our own
	// process group).
	err := handler.Enforce(context.Background(), &api.Event{PID: 0}, &api.ActionResult{Action: api.ActionDeny})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if got := handler.GetStats().Denied; got != 1 {
		t.Errorf("Denied = %d, want 1", got)
	}
}

func TestActionHandler_ConcurrentStats(t *testing.T) {
	handler := NewActionHandler(true)
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = handler.Enforce(ctx, &api.Event{PID: 0}, &api.ActionResult{Action: api.ActionAllow})
		}()
		go func() {
			defer wg.Done()
			_ = handler.Enforce(ctx, &api.Event{PID: 99}, &api.ActionResult{Action: api.ActionDeny})
		}()
		go func() {
			defer wg.Done()
			_ = handler.Enforce(ctx, &api.Event{PID: 0}, &api.ActionResult{Action: api.ActionLog})
		}()
	}
	wg.Wait()

	stats := handler.GetStats()
	if stats.Allowed != 50 || stats.AuditDenied != 50 || stats.Logged != 100 || stats.Denied != 0 {
		t.Errorf("unexpected concurrent stats: %+v", stats)
	}
}
