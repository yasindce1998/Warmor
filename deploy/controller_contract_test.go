package deploy_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/controller"
	"gopkg.in/yaml.v3"
)

func contractValue[T any](t *testing.T, field string, raw interface{}) T {
	t.Helper()
	value, ok := raw.(T)
	if !ok {
		t.Fatalf("%s has unexpected type %T", field, raw)
	}
	return value
}

func TestCRDMigrationPreservesPublicationStatusWireShape(t *testing.T) {
	raw, err := os.ReadFile("helm/warmor/crds/warmorpolicy-crd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd map[string]interface{}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	versions := contractValue[[]interface{}](t, "spec.versions", object(crd, "spec")["versions"])
	if len(versions) != 1 {
		t.Fatalf("expected one CRD version, got %d", len(versions))
	}
	version := contractValue[map[string]interface{}](t, "spec.versions[0]", versions[0])
	if version["name"] != "v1alpha1" || version["served"] != true || version["storage"] != true {
		t.Fatal("migration unexpectedly changed served/storage version")
	}
	if _, ok := object(version, "subresources")["status"]; !ok {
		t.Fatal("missing status subresource")
	}
	status := object(version, "schema", "openAPIV3Schema", "properties", "status")
	fields := object(status, "properties")
	// Every status JSON field must survive Kubernetes schema pruning with
	// the right primitive/collection type; old application fields stay readable.
	typ := reflect.TypeFor[controller.WarmorPolicyStatus]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		want := "string"
		switch field.Type.Kind() {
		case reflect.Int, reflect.Int64:
			want = "integer"
		case reflect.Slice:
			want = "array"
		}
		if object(fields, name)["type"] != want {
			t.Fatalf("status.%s schema = %+v, want type %s", name, fields[name], want)
		}
		if _, exists := object(fields, name)["default"]; exists {
			t.Fatalf("status.%s must not fabricate default success/application state", name)
		}
	}
	for _, name := range []string{"observedGeneration", "acceptedGeneration"} {
		if object(fields, name)["format"] != "int64" {
			t.Fatalf("%s must be int64", name)
		}
	}
	for _, name := range []string{"lastPublished", "lastApplied"} {
		if object(fields, name)["format"] != "date-time" {
			t.Fatalf("%s must retain date-time format", name)
		}
	}
	phase, _ := json.Marshal(object(fields, "phase")["enum"])
	for _, name := range []string{"Pending", "Active", "Published", "Error"} {
		if !bytes.Contains(phase, []byte(`"`+name+`"`)) {
			t.Fatalf("migration lost phase %s: %s", name, phase)
		}
	}
	conditions := object(fields, "conditions", "items", "properties")
	for _, name := range []string{"type", "status", "reason", "message", "lastTransitionTime"} {
		if object(conditions, name)["type"] != "string" {
			t.Fatalf("condition.%s is missing or not a string", name)
		}
	}
	if got, _ := json.Marshal(object(conditions, "status")["enum"]); string(got) != `["True","False","Unknown"]` {
		t.Fatalf("condition status enum must be strings, not YAML booleans: %s", got)
	}
}

func TestKindWaitsForPublicationNotLegacyOrFabricatedApplication(t *testing.T) {
	raw, err := os.ReadFile("../scripts/kind-e2e.sh")
	if err != nil {
		t.Fatal(err)
	}
	lf := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, fixture := range []struct {
		name, script string
	}{
		{"LF", lf},
		{"CRLF", strings.ReplaceAll(lf, "\n", "\r\n")},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			checkKindPublicationWaitContract(t, fixture.script)
		})
	}
}

func checkKindPublicationWaitContract(t *testing.T, script string) {
	t.Helper()
	// Git's Windows checkout may use CRLF. Normalize before locating the
	// function boundary and executing its snippet with bash; otherwise the
	// closing brace is not found and carriage returns become shell tokens.
	script = strings.ReplaceAll(script, "\r\n", "\n")
	start := strings.Index(script, "cr_is_published() {")
	if start < 0 {
		t.Fatal("missing publication predicate")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("missing publication predicate end")
	}
	predicate := script[start : start+end+3]
	for _, tc := range []struct {
		phase, condition string
		ok               bool
	}{{"Published", "True", true}, {"Active", "True", false}, {"Published", "False", false}, {"Published", "Unknown", false}, {"Published", "", false}, {"Error", "True", false}} {
		cmd := exec.Command("bash", "-c", `
kubectl() {
  case "$*" in
    *status.phase*) echo "$PHASE" ;;
    *Published*) echo "$PUBLISHED_CONDITION" ;;
    *Applied*) echo True ;; # must never substitute for publication
    *) exit 99 ;;
  esac
}
`+predicate+"\ncr_is_published")
		cmd.Env = append(os.Environ(), "PHASE="+tc.phase, "PUBLISHED_CONDITION="+tc.condition)
		if out, err := cmd.CombinedOutput(); (err == nil) != tc.ok {
			t.Fatalf("phase=%s Published=%s: err=%v %s", tc.phase, tc.condition, err, out)
		}
	}
	apply := strings.Index(script, "apply -f deploy/helm/warmor/crds/warmorpolicy-crd.yaml")
	upgrade := strings.Index(script, "helm upgrade")
	if apply < 0 || upgrade < apply || !strings.Contains(script[apply:upgrade], "--for=condition=Established") {
		t.Fatal("kind upgrade must explicitly migrate and establish the CRD first")
	}
}

func TestHelmControllerProbesAndPolicyProjectionContract(t *testing.T) {
	var foundController, foundDaemon, foundNetwork bool
	for _, doc := range renderChart(t, "controller.enabled=true", "networkPolicy.enabled=true") {
		spec := object(doc, "spec", "template", "spec")
		switch doc["kind"] {
		case "Deployment":
			foundController = true
			if docSpec := object(doc, "spec"); docSpec["replicas"] != 1 || object(docSpec, "strategy")["type"] != "Recreate" {
				t.Fatal("controller must remain one writer")
			}
			containers := contractValue[[]interface{}](t, "controller containers", spec["containers"])
			if len(containers) != 1 {
				t.Fatalf("expected one controller container, got %d", len(containers))
			}
			c := contractValue[map[string]interface{}](t, "controller container", containers[0])
			if !strings.Contains(fmtArgs(t, contractValue[[]interface{}](t, "controller args", c["args"])), "--metrics-address :9091") {
				t.Fatal("missing controller listener argument")
			}
			for _, probe := range []string{"startupProbe", "livenessProbe", "readinessProbe"} {
				want := "/health"
				if probe == "readinessProbe" {
					want = "/ready"
				}
				get := object(c, probe, "httpGet")
				if get["path"] != want || get["port"] != "controller-http" {
					t.Fatalf("%s = %+v", probe, get)
				}
			}
		case "DaemonSet":
			foundDaemon = true
			containers := contractValue[[]interface{}](t, "daemon containers", spec["containers"])
			if len(containers) != 1 {
				t.Fatalf("expected one daemon container, got %d", len(containers))
			}
			c := contractValue[map[string]interface{}](t, "daemon container", containers[0])
			if !strings.Contains(fmtArgs(t, contractValue[[]interface{}](t, "daemon args", c["args"])), "-policy /etc/warmor/policy.d/policy.wasm") {
				t.Fatal("controller binaryData key does not reach daemon policy path")
			}
			found := false
			for _, item := range contractValue[[]interface{}](t, "daemon volumes", spec["volumes"]) {
				v := contractValue[map[string]interface{}](t, "daemon volume", item)
				if v["name"] == "effective-policy" {
					cm := object(v, "configMap")
					found = cm["name"] == "safety-warmor-effective-policy" && cm["optional"] == true
					// Do not project accepted-sources.json into the daemon. It
					// contains policy source history, not executable input.
					items := contractValue[[]interface{}](t, "policy ConfigMap items", cm["items"])
					if len(items) != 1 {
						t.Fatalf("expected one projected policy key, got %d", len(items))
					}
					projection := contractValue[map[string]interface{}](t, "policy ConfigMap item", items[0])
					if projection["key"] != controller.PolicyDataKey || projection["path"] != "policy.wasm" {
						t.Fatal("daemon must project only the compiled policy key")
					}
				}
			}
			if !found {
				t.Fatal("missing effective policy ConfigMap")
			}
		case "NetworkPolicy":
			if object(doc, "spec", "podSelector", "matchLabels")["component"] == "controller" {
				foundNetwork = true
				ingress := contractValue[[]interface{}](t, "controller ingress", object(doc, "spec")["ingress"])
				if len(ingress) != 1 {
					t.Fatalf("expected one controller ingress rule, got %d", len(ingress))
				}
				rule := contractValue[map[string]interface{}](t, "controller ingress rule", ingress[0])
				ports := contractValue[[]interface{}](t, "controller ingress ports", rule["ports"])
				if len(ports) != 1 {
					t.Fatalf("expected one controller ingress port, got %d", len(ports))
				}
				port := contractValue[map[string]interface{}](t, "controller ingress port", ports[0])
				if port["port"] != 9091 {
					t.Fatal("controller metrics ingress port differs from listener")
				}
			}
		}
	}
	if !foundController || !foundDaemon || !foundNetwork {
		t.Fatal("missing controller, daemon or controller network policy")
	}
}
