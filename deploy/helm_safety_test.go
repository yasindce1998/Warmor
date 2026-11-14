package deploy_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestHelmDefaultsToAudit(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is unavailable")
	}
	for _, tc := range []struct {
		name  string
		args  []string
		audit bool
	}{
		{"default", nil, true},
		{"controller", []string{"--set", "controller.enabled=true"}, true},
		{"explicit enforcement", []string{"--set", "daemon.auditMode=false", "--set", "daemon.lsmEnforce=true"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"template", "safety", "helm/warmor"}, tc.args...)
			out, err := exec.Command("helm", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm: %v\n%s", err, out)
			}
			if got := strings.Contains(string(out), `- "-audit"`); got != tc.audit {
				t.Fatalf("rendered audit = %v, want %v", got, tc.audit)
			}
		})
	}
}
