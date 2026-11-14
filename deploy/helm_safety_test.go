package deploy_test

import (
	"bytes"
	"errors"
	"gopkg.in/yaml.v3"
	"io"
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
		{"explicit enforcement", []string{"--set", "daemon.auditMode=false,daemon.lsmEnforce=true,daemon.requireLSM=true,daemon.confirmNodeWidePolicy=true"}, false},
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

func renderChart(t *testing.T, sets ...string) []map[string]interface{} {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm unavailable")
	}
	args := []string{"template", "safety", "helm/warmor"}
	for _, set := range sets {
		args = append(args, "--set", set)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm: %v\n%s", err, out)
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	var docs []map[string]interface{}
	for {
		var doc map[string]interface{}
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}
func object(m map[string]interface{}, path ...string) map[string]interface{} {
	for _, key := range path {
		m, _ = m[key].(map[string]interface{})
	}
	return m
}
func fmtArgs(t *testing.T, args []interface{}) string {
	t.Helper()
	var out []string
	for _, a := range args {
		out = append(out, contractValue[string](t, "argument", a))
	}
	return strings.Join(out, " ")
}
func TestHelmScopedRuntimeAndMetrics(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, enforcing := range []bool{false, true} {
		sets := []string{"controller.enabled=true", "image.digest=" + digest, "controller.image.digest=" + digest, "hostPaths.cgroup=/node/cgroups", "hostPaths.cgroupMount=/host/cgroups"}
		if enforcing {
			sets = append(sets, "daemon.auditMode=false,daemon.lsmEnforce=true,daemon.requireLSM=true,daemon.confirmNodeWidePolicy=true")
		}
		for _, doc := range renderChart(t, sets...) {
			switch doc["kind"] {
			case "Service":
				if object(doc, "spec", "selector")["component"] != "daemon" {
					t.Fatal("metrics selects controller")
				}
			case "DaemonSet", "Deployment":
				spec := object(doc, "spec", "template", "spec")
				nodes := object(spec, "nodeSelector")
				if nodes["kubernetes.io/os"] != "linux" || nodes["kubernetes.io/arch"] != "amd64" {
					t.Fatal(nodes)
				}
				for _, item := range contractValue[[]interface{}](t, "containers", spec["containers"]) {
					c := contractValue[map[string]interface{}](t, "container", item)
					if !strings.HasSuffix(contractValue[string](t, "container image", c["image"]), "@"+digest) {
						t.Fatal(c["image"])
					}
					if doc["kind"] != "DaemonSet" {
						continue
					}
					if spec["automountServiceAccountToken"] != false {
						t.Fatal("agent gets API token")
					}
					text := fmtArgs(t, contractValue[[]interface{}](t, "container args", c["args"]))
					if !strings.Contains(text, "-cgroup-filter auto") || !strings.Contains(text, "-cgroup-root /host/cgroups") {
						t.Fatal(text)
					}
					caps := fmtArgs(t, contractValue[[]interface{}](t, "container capabilities", object(c, "securityContext", "capabilities")["add"]))
					if strings.Contains(caps, "KILL") != enforcing || strings.Contains(caps, "NET_ADMIN") {
						t.Fatal(caps)
					}
					mounted := false
					for _, item := range contractValue[[]interface{}](t, "container volumeMounts", c["volumeMounts"]) {
						m := contractValue[map[string]interface{}](t, "volume mount", item)
						if m["name"] == "host-cgroup" {
							mounted = m["mountPath"] == "/host/cgroups" && m["readOnly"] == true
						}
					}
					if !mounted {
						t.Fatal("discovery path differs from mount")
					}
				}
			}
		}
	}
}
func TestHelmNoUnusedAgentRBACAndDigestValidator(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	for _, doc := range renderChart(t, "image.digest="+digest) {
		if strings.Contains(contractValue[string](t, "kind", doc["kind"]), "Role") {
			t.Fatal("unused agent API permissions")
		}
		if doc["kind"] == "DaemonSet" {
			for _, item := range contractValue[[]interface{}](t, "initContainers", object(doc, "spec", "template", "spec")["initContainers"]) {
				if contractValue[map[string]interface{}](t, "init container", item)["image"] != "ghcr.io/yasindce1998/warmor@"+digest {
					t.Fatal("validator not pinned")
				}
			}
		}
	}
}
func TestHelmRejectsUnsafeAndInvalidValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm unavailable")
	}
	for _, set := range []string{
		"daemon.auditMode=false", "daemon.auditMode=false,daemon.confirmNodeWidePolicy=true,daemon.lsmEnforce=true",
		"daemon.lsmEnforce=true", "daemon.defaultDeny=true", "webhook.enabled=true", "image.digest=sha256:nope",
		"daemon.metricsPort=65536", "daemon.auditMode=not-a-bool", "daemon.cgroupReconcileInterval=0s",
		"daemon.cgroupFilter=autoo", "daemon.unusedOption=true", "policy.yaml=ignored",
		"controller.enabled=true,policy.existingConfigMap=external", "controller.watchAllNamespaces=true",
		"nodeSelector.kubernetes\\.io/os=windows", "nodeSelector.kubernetes\\.io/arch=arm64", "hostPaths.cgroupMount=relative",
	} {
		t.Run(set, func(t *testing.T) {
			out, err := exec.Command("helm", "template", "invalid", "helm/warmor", "--set", set).CombinedOutput()
			if err == nil {
				t.Fatalf("accepted %s\n%s", set, out)
			}
		})
	}
}

func TestHelmRenderedAgentArgumentsExist(t *testing.T) {
	flags := daemonFlags(t)
	for _, doc := range renderChart(t) {
		if doc["kind"] != "DaemonSet" {
			continue
		}
		spec := object(doc, "spec", "template", "spec")
		for _, kind := range []string{"containers", "initContainers"} {
			for _, item := range contractValue[[]interface{}](t, kind, spec[kind]) {
				c := contractValue[map[string]interface{}](t, kind+" entry", item)
				for _, value := range contractValue[[]interface{}](t, kind+" args", c["args"]) {
					arg := contractValue[string](t, "argument", value)
					if !strings.HasPrefix(arg, "-") {
						continue
					}
					name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
					if !flags[name] {
						t.Fatalf("rendered unknown daemon argument: %q", arg)
					}
				}
			}
		}
	}
}
