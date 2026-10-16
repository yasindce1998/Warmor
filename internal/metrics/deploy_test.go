package metrics

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestDeployReferencesOnlyExportedMetrics fails when a dashboard or alert
// under deploy/ queries a warmor_* metric this package does not export, so
// panels and alerts cannot silently go blank again.
func TestDeployReferencesOnlyExportedMetrics(t *testing.T) {
	// Make every vector emit a series so Gather lists it.
	RecordEvent("ALLOW")
	RecordCacheHit()
	RecordCacheMiss()
	RecordLatency(1)
	UpdateCacheSize(1)
	SetPolicyInfo("p", "v")
	RecordProcessingError()
	RecordAuditDenied()
	RecordLSMDecision("exec", "deny")
	RecordPolicyLoad("p", nil)
	RecordHeartbeat("a", nil)
	RecordRegistration(nil)
	RecordWASMExec("p", 0.001, errors.New("x"), true)
	RecordEventProcessed("PROCESS")
	RecordEventDropped()
	SetMapEntries("policy_map", 1)
	SetEBPFLoaderStatus(true)
	RecordPolicyMapSync(SyncSynced)
	RecordLSMEventsDropped("exec", 0)

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	exported := map[string]bool{}
	for _, f := range families {
		exported[f.GetName()] = true
	}

	root := filepath.Join("..", "..", "deploy")
	files := []string{
		filepath.Join(root, "prometheus", "alerts.yml"),
		filepath.Join(root, "grafana", "warmor-dashboard.json"),
		filepath.Join(root, "helm", "warmor", "templates", "prometheusrule.yaml"),
		filepath.Join(root, "helm", "warmor", "templates", "grafana-dashboard.yaml"),
	}
	re := regexp.MustCompile(`warmor_[a-z0-9_]+`)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range re.FindAllString(string(data), -1) {
			base := name
			for _, suf := range []string{"_bucket", "_sum", "_count"} {
				base = strings.TrimSuffix(base, suf)
			}
			if !exported[base] {
				t.Errorf("%s references %s, which is not exported", f, name)
			}
		}
	}
}
