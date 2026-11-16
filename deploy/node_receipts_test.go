package deploy_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestNodeReceiptsDisabledByDefaultAndTrustGated(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm unavailable")
	}
	for _, doc := range renderChart(t, "controller.enabled=true") {
		encoded, _ := json.Marshal(doc)
		for _, forbidden := range []string{"tokenreviews", "receipt-token", "receipts-https", "--node-receipts"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("disabled receipts grant/mount/serve %s", forbidden)
			}
		}
	}
	for _, set := range []string{"controller.nodeReceipts.enabled=true", "controller.enabled=true,controller.nodeReceipts.enabled=true"} {
		if out, err := exec.Command("helm", "template", "invalid", "helm/warmor", "--set", set).CombinedOutput(); err == nil {
			t.Fatalf("untrusted receipts enabled:\n%s", out)
		}
	}
}

func TestNodeReceiptsLeastPrivilegeAndBoundTokenWiring(t *testing.T) {
	docs := renderChart(t, "controller.enabled=true", "controller.nodeReceipts.enabled=true", "controller.nodeReceipts.audience=warmor-receipts", "controller.nodeReceipts.tlsSecretName=receipt-tls", "controller.nodeReceipts.caConfigMapName=receipt-ca", "controller.nodeReceipts.requiredNodes[0]=node-a")
	reviewGrant, daemon, controller, service := false, false, false, false
	for _, doc := range docs {
		name, _ := object(doc, "metadata")["name"].(string)
		switch doc["kind"] {
		case "ClusterRole":
			if !strings.HasSuffix(name, "-node-receipts") {
				continue
			}
			rules := contractValue[[]interface{}](t, "receipt cluster rules", doc["rules"])
			if len(rules) != 2 {
				t.Fatal("unexpected cluster grant", rules)
			}
			for _, rule := range rules {
				r := contractValue[map[string]interface{}](t, "rule", rule)
				resources := fmtArgs(t, contractValue[[]interface{}](t, "resources", r["resources"]))
				verbs := fmtArgs(t, contractValue[[]interface{}](t, "verbs", r["verbs"]))
				if resources == "tokenreviews" && verbs == "create" {
					reviewGrant = true
				} else if resources == "nodes" && verbs == "get" && fmtArgs(t, contractValue[[]interface{}](t, "resourceNames", r["resourceNames"])) == "node-a" {
				} else {
					t.Fatalf("excess cluster permission %+v", r)
				}
			}
		case "ClusterRoleBinding":
			if object(doc, "roleRef")["name"] == "cluster-admin" || object(doc, "roleRef")["name"] == "system:auth-delegator" {
				t.Fatal("blanket auth delegation")
			}
		case "DaemonSet":
			spec := object(doc, "spec", "template", "spec")
			if spec["automountServiceAccountToken"] != false {
				t.Fatal("default API token mounted")
			}
			volumes := contractValue[[]interface{}](t, "daemon volumes", spec["volumes"])
			for _, raw := range volumes {
				v := contractValue[map[string]interface{}](t, "volume", raw)
				if v["name"] != "receipt-token" {
					continue
				}
				sources := contractValue[[]interface{}](t, "token projection", object(v, "projected")["sources"])
				projection := object(contractValue[map[string]interface{}](t, "projection", sources[0]), "serviceAccountToken")
				if projection["audience"] != "warmor-receipts" || projection["expirationSeconds"] != 600 {
					t.Fatal(projection)
				}
				daemon = true
			}
		case "Deployment":
			containers := contractValue[[]interface{}](t, "controller containers", object(doc, "spec", "template", "spec")["containers"])
			args := fmtArgs(t, contractValue[[]interface{}](t, "args", contractValue[map[string]interface{}](t, "container", containers[0])["args"]))
			for _, required := range []string{"--node-receipts", "--receipts-required-nodes=node-a", "--receipts-audience=warmor-receipts", "--receipts-tls-cert="} {
				if !strings.Contains(args, required) {
					t.Fatal("missing", required)
				}
			}
			controller = true
		case "Service":
			if strings.HasSuffix(name, "-controller-receipts") {
				if object(doc, "spec", "selector")["component"] != "controller" {
					t.Fatal("receipt service selects wrong pods")
				}
				service = true
			}
		}
	}
	if !reviewGrant || !daemon || !controller || !service {
		t.Fatalf("incomplete opt-in wiring review=%t daemon=%t controller=%t service=%t", reviewGrant, daemon, controller, service)
	}
}
