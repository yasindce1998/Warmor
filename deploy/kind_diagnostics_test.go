package deploy_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestKindInstallFailureCollectsDiagnosticsBeforeCleanup(t *testing.T) {
	rawScript, err := os.ReadFile("../scripts/kind-e2e.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, storageBlocked := range []bool{false, true} {
		name := "artifact"
		if storageBlocked {
			name = "storage-failure"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			callsPath := filepath.Join(dir, "calls")
			diagnosticsDir := filepath.Join(dir, "diagnostics")
			scriptPath := filepath.Join(dir, "kind-e2e.sh")
			// Match the LF script executed by hosted Linux CI even when the
			// portable Go test itself runs in a Windows CRLF checkout.
			if err := os.WriteFile(scriptPath, []byte(strings.ReplaceAll(string(rawScript), "\r\n", "\n")), 0600); err != nil {
				t.Fatal(err)
			}
			if storageBlocked {
				if err := os.WriteFile(diagnosticsDir, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Shell functions intercept EVERY cluster/container tool, including
			// the cleanup trap. No live Docker, kind, Helm or kubectl is used.
			cmd := exec.Command("bash", "-c", `
docker() { echo "unexpected docker $*" >> "$TEST_CALLS"; return 99; }
curl() { echo "unexpected curl $*" >> "$TEST_CALLS"; return 99; }
kind() {
  echo "kind $*" >> "$TEST_CALLS"
  case "$*" in delete*) return 38 ;; esac
}
helm() {
  echo "helm $*" >> "$TEST_CALLS"
  echo "injected Helm install readiness failure" >&2
  return 37
}
kubectl() {
  echo "kubectl $*" >> "$TEST_CALLS"
  echo "synthetic bounded pod diagnostic" >&2
  return 52 # even failed reads must not stop subsequent diagnostics/cleanup
}
source "$TEST_SCRIPT"
`)
			cmd.Env = append(os.Environ(), "WARMOR_IMAGE=warmor:fixture", "TEST_CALLS="+filepath.ToSlash(callsPath),
				"TEST_SCRIPT="+filepath.ToSlash(scriptPath), "WARMOR_E2E_DIAGNOSTICS_DIR="+filepath.ToSlash(diagnosticsDir))
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 37 {
				t.Fatalf("must preserve Helm's original exit code despite diagnostics/deletion failures: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "injected Helm install readiness failure") || !strings.Contains(string(out), "synthetic bounded pod diagnostic") {
				t.Fatalf("failure output lost diagnostics: %s", out)
			}
			raw, err := os.ReadFile(callsPath)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.ReplaceAll(string(raw), "\r\n", "\n")
			if !strings.HasSuffix(calls, "kind delete cluster --name warmor-e2e\n") {
				t.Fatalf("cleanup did not run last: %s", calls)
			}
			if strings.Contains(calls, "unexpected") || strings.Count(calls, "helm install ") != 1 || strings.Contains(calls, "helm upgrade ") {
				t.Fatalf("unexpected work after install failure: %s", calls)
			}
			for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
				if strings.HasPrefix(line, "kubectl ") && !strings.HasPrefix(line, "kubectl --context kind-warmor-e2e --request-timeout=10s ") {
					t.Fatalf("diagnostic read lacks isolated context/deadline: %s", line)
				}
			}
			for _, want := range []string{"get nodes -o wide", "get daemonsets,deployments,pods -o wide", "describe pods", "get events"} {
				if !strings.Contains(calls, want) {
					t.Fatalf("missing %s after Helm failure: %s", want, calls)
				}
			}
			for _, container := range []string{"validate-policy", "warmor", "controller"} {
				component := "daemon"
				if container == "controller" {
					component = "controller"
				}
				for _, suffix := range []string{" --tail=100", " --previous --tail=100"} {
					if !strings.Contains(calls, "-l app.kubernetes.io/instance=warmor-e2e,component="+component+" -c "+container+suffix) {
						t.Fatalf("missing current/previous bounded %s logs: %s", container, calls)
					}
				}
			}
			if !storageBlocked {
				artifact, err := os.ReadFile(filepath.Join(diagnosticsDir, "diagnostics.log"))
				if err != nil || !strings.Contains(string(artifact), "synthetic bounded pod diagnostic") {
					t.Fatalf("missing artifact: %v %s", err, artifact)
				}
			}
		})
	}
}
