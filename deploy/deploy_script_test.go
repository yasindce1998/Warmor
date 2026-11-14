package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
