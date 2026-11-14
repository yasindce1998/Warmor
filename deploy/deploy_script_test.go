package deploy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/compiler"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
	"gopkg.in/yaml.v3"
)

// Cluster commands reject everything except a local ConfigMap client dry-run.
// Real Helm still validates the binary mount reference and posture.
func TestMakeDeploymentUsesSelectedBinaryWithoutClusterAccess(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm unavailable")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("kubectl", `#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == create\ configmap* && "$*" == *--dry-run=client* ]] || { echo "unexpected cluster access: $*" >&2; exit 91; }
echo "kubectl $*" >> "$CALL_LOG"
echo "apiVersion: v1"
echo "kind: ConfigMap"
echo "metadata: {name: $3}"
echo "binaryData: {policy.wasm: AGFzbQ==}"
`)
	write("compile", `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -o && -f "$3" ]] || exit 92
echo "compile $3" >> "$CALL_LOG"
cp "$FIXTURE" "$2"
`)
	write("validator", `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == --validate-policy ]] || exit 93
cmp "$FIXTURE" "$2"
echo validate >> "$CALL_LOG"
`)
	policy := write("selected policy.yaml", "name: selected\nversion: 1\ndefault_action: allow\n")
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CALL_LOG="+log, "FIXTURE="+filepath.Join(root, "internal/wasm/testdata/allow_policy.wasm"), "WARMOR_COMPILE="+filepath.Join(dir, "compile"), "WARMOR_DAEMON="+filepath.Join(dir, "validator"))
	for _, mode := range []string{"audit", "enforce"} {
		target := "deploy"
		if mode == "audit" {
			target += "-audit"
		}
		cmd := exec.Command("make", "--no-print-directory", target, "POLICY="+policy, "DRY_RUN=true", "CONFIRM_NODE_WIDE_POLICY=true")
		cmd.Dir = root
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make %s: %v\n%s", mode, err, out)
		}
		text := string(out)
		if !strings.Contains(text, "name: warmor-policy-") || !strings.Contains(text, "binaryData:") || !strings.Contains(text, "--validate-policy") {
			t.Fatal(text)
		}
		if strings.Contains(text, `- "-audit"`) != (mode == "audit") {
			t.Fatal("wrong audit posture")
		}
		if strings.Contains(text, `- "-lsm-enforce"`) != (mode == "enforce") || strings.Contains(text, `- "-require-lsm"`) != (mode == "enforce") {
			t.Fatal("kernel posture omitted")
		}
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "compile "+policy) != 2 || strings.Count(string(calls), "validate\n") != 2 || strings.Count(string(calls), "kubectl create configmap") != 2 {
		t.Fatalf("policy not compiled/validated: %s", calls)
	}
}

// Real compilation, daemon validation, kubectl client dry-run and Helm render.
// An empty kubeconfig and DRY_RUN=true keep this entirely cluster-free.
func TestDeployRealPolicyConfigMapMatchesValidatedMountedBinary(t *testing.T) {
	for _, tool := range []string{"helm", "kubectl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
	if !compiler.CargoAvailable() {
		if os.Getenv("WARMOR_REQUIRE_CARGO") == "1" {
			t.Fatal("cargo/wasm32 required")
		}
		t.Skip("cargo/wasm32 unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(t.TempDir(), "selected policy.yaml")
	if err := os.WriteFile(selected, []byte(`name: deploy-contract
version: 7
default_action: allow
rules:
- name: marker
  event: process
  action: deny
  conditions: {all: [{path: {eq: /var/tmp/deploy-contract-marker}}]}
`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{selected, filepath.Join(root, "internal/wasm/testdata/allow_policy.wasm")} {
		t.Run(filepath.Ext(input), func(t *testing.T) {
			cmd := exec.Command("bash", "scripts/kubernetes-deploy.sh", "--mode", "audit", "--policy", input)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "DRY_RUN=true", "KUBECONFIG=/dev/null", "NAMESPACE=contract-test", "RELEASE=contract", "WARMOR_COMPILE=", "WARMOR_DAEMON=")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("local deploy: %v\n%s", err, &stderr)
			}
			decoder := yaml.NewDecoder(bytes.NewReader(out))
			var cm struct {
				Kind       string            `yaml:"kind"`
				Metadata   map[string]string `yaml:"metadata"`
				BinaryData map[string]string `yaml:"binaryData"`
				Data       map[string]string `yaml:"data"`
			}
			if err := decoder.Decode(&cm); err != nil {
				t.Fatal(err)
			}
			artifact, err := base64.StdEncoding.DecodeString(cm.BinaryData["policy.wasm"])
			if err != nil || len(artifact) == 0 || cm.Kind != "ConfigMap" || len(cm.Data) != 0 || cm.Metadata["namespace"] != "contract-test" {
				t.Fatalf("invalid binary ConfigMap: %+v, %v", cm, err)
			}
			digest := fmt.Sprintf("%x", sha256.Sum256(artifact))
			if cm.Metadata["name"] != "contract-policy-"+digest[:16] || !strings.Contains(stderr.String(), "sha256:"+digest) {
				t.Fatal("ConfigMap reference does not identify exact validated bytes")
			}
			if filepath.Ext(input) == ".wasm" {
				original, err := os.ReadFile(input)
				if err != nil || !bytes.Equal(artifact, original) {
					t.Fatal("selected WASM bytes were replaced")
				}
			}
			found := false
			for {
				var doc map[string]interface{}
				if err := decoder.Decode(&doc); errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if doc["kind"] != "DaemonSet" {
					continue
				}
				found = true
				spec := object(doc, "spec", "template", "spec")
				policyVolume := false
				for _, v := range contractValue[[]interface{}](t, "daemon volumes", spec["volumes"]) {
					volume := contractValue[map[string]interface{}](t, "daemon volume", v)
					if volume["name"] == "policy" {
						policyVolume = object(volume, "configMap")["name"] == cm.Metadata["name"]
					}
				}
				if !policyVolume {
					t.Fatal("DaemonSet does not mount selected ConfigMap")
				}
				for _, kind := range []string{"initContainers", "containers"} {
					containers := contractValue[[]interface{}](t, kind, spec[kind])
					if len(containers) != 1 {
						t.Fatalf("expected one %s entry, got %d", kind, len(containers))
					}
					c := contractValue[map[string]interface{}](t, kind+" entry", containers[0])
					if !strings.Contains(fmtArgs(t, contractValue[[]interface{}](t, kind+" args", c["args"])), "/etc/warmor/policy.wasm") {
						t.Fatalf("%s consumes a different policy", kind)
					}
					mounts := contractValue[[]interface{}](t, kind+" volumeMounts", c["volumeMounts"])
					if len(mounts) == 0 {
						t.Fatalf("%s has no volume mounts", kind)
					}
					mount := contractValue[map[string]interface{}](t, kind+" policy mount", mounts[0])
					if mount["name"] != "policy" || mount["mountPath"] != "/etc/warmor" || mount["readOnly"] != true {
						t.Fatalf("%s does not use selected binary read-only: %+v", kind, mount)
					}
				}
			}
			if !found {
				t.Fatal("missing DaemonSet")
			}
			ctx := context.Background()
			runtime, err := wasm.NewRuntime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close(ctx)
			if err := runtime.LoadPolicyBytes(ctx, artifact); err != nil {
				t.Fatal(err)
			}
			policy, err := wasm.NewPolicy(ctx, runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer policy.Close(ctx)
			want := api.ActionAllow
			if input == selected {
				want = api.ActionDeny
			}
			if action, err := policy.Evaluate(ctx, &api.Event{Process: &api.ProcessEvent{Filename: "/var/tmp/deploy-contract-marker"}}); err != nil || action != want {
				t.Fatalf("mounted binary has wrong semantics: action=%v err=%v want=%v", action, err, want)
			}
		})
	}
}
func TestDeployScriptRejectsUnsafeRequestsBeforeTools(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args, env []string
		message   string
	}{
		{[]string{"--mode", "enforce", "--policy", "deploy/default-policy.yaml"}, []string{"DRY_RUN=true", "CONFIRM_NODE_WIDE_POLICY=false"}, "CONFIRM_NODE_WIDE_POLICY"},
		{[]string{"--mode", "audit", "--policy", "deploy/default-policy.yaml"}, []string{"DRY_RUN=false", "KUBE_CONTEXT="}, "explicit KUBE_CONTEXT"},
		{[]string{"--mode", "audit", "--policy", "missing.yaml"}, []string{"DRY_RUN=true"}, "existing file"},
	} {
		cmd := exec.Command("bash", append([]string{"scripts/kubernetes-deploy.sh"}, tc.args...)...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), tc.env...)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), tc.message) {
			t.Fatalf("err=%v output=%s", err, out)
		}
	}
}

func TestDeployCompileOrValidationFailureCannotReachClusterTools(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// The helper may check command presence but must not invoke these after
	// a compiler or validator error, even when a live context was specified.
	marker := filepath.Join(dir, "cluster-called")
	for _, tool := range []string{"helm", "kubectl"} {
		write(tool, "#!/bin/sh\ntouch \"$CLUSTER_MARKER\"\nexit 95\n")
	}
	compiler := write("compile", "#!/bin/sh\nif [ \"$FAIL_AT\" = compile ]; then exit 96; fi\ncp \"$FIXTURE\" \"$2\"\n")
	validator := write("validate", "#!/bin/sh\nexit 97\n")
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"compile", "validate"} {
		cmd := exec.Command("bash", "scripts/kubernetes-deploy.sh", "--mode", "audit", "--policy", "deploy/default-policy.yaml")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "DRY_RUN=false", "KUBE_CONTEXT=must-never-be-used", "CLUSTER_MARKER="+marker,
			"FAIL_AT="+failure, "WARMOR_COMPILE="+compiler, "WARMOR_DAEMON="+validator, "FIXTURE="+filepath.Join(root, "internal/wasm/testdata/allow_policy.wasm"))
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("accepted failed %s: %s", failure, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%s failure reached cluster tooling", failure)
		}
	}
}
