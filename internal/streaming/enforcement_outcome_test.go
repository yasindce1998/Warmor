package streaming

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestFromAPIEventReportsActualEnforcementOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result api.ActionResult
		kernel bool
	}{
		{"refused identity", api.ActionResult{Action: api.ActionDeny, EnforcementError: "identity unavailable"}, false},
		{"failed syscall", api.ActionResult{Action: api.ActionDeny, EnforcementAttempted: true, EnforcementError: "permission denied"}, false},
		{"accepted termination", api.ActionResult{Action: api.ActionDeny, EnforcementAttempted: true, Enforced: true}, false},
		{"kernel prevented", api.ActionResult{Action: api.ActionDeny, Enforced: true}, true},
		{"audit", api.ActionResult{Action: api.ActionDeny, Audit: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FromAPIEvent(&api.Event{KernelDenied: tc.kernel}, &tc.result)
			if got.Enforced != tc.result.Enforced || got.EnforcementAttempted != tc.result.EnforcementAttempted || got.EnforcementError != tc.result.EnforcementError || got.KernelEnforced != tc.kernel {
				t.Fatalf("outcome = %+v", got)
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if tc.result.EnforcementError != "" && !strings.Contains(string(data), `"enforcement_error"`) {
				t.Fatalf("missing error in serialized event: %s", data)
			}
		})
	}
}
