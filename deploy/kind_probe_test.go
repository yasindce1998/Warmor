package deploy_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestKindNonRootAuditProbeHasWritableMarkerAndExecutesIt(t *testing.T) {
	raw, err := os.ReadFile("../scripts/kind-e2e.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(string(raw), "\r\n", "\n")
	start := strings.Index(script, `kubectl "${KCTX[@]}" run "$PROBE" --image=busybox:1.37`)
	end := strings.Index(script, "# The counter family only exists")
	if start < 0 || end < start {
		t.Fatal("missing audit probe setup")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.sh")
	overridesPath := filepath.Join(dir, "overrides.json")
	setup := script[start:end]
	for _, failSetup := range []string{"false", "true"} {
		cmd := exec.Command("bash", "-c", `
set -euo pipefail
KCTX=(--context kind-fixture)
PROBE=warmor-audit-probe
kubectl() {
  [[ "$1" == --context && "$2" == kind-fixture ]] || return 90
  shift 2
  case "$1" in
    run)
      for arg in "$@"; do
        case "$arg" in --overrides=*) printf '%s' "${arg#--overrides=}" > "$TEST_OVERRIDES" ;; esac
      done ;;
    wait) return 0 ;;
    exec)
      [[ "$FAIL_SETUP" != true ]] || return 73
      shift 3 # exec <pod> --; run the real marker setup shell, not kubectl
      "$@" ;;
    *) return 91 ;;
  esac
}
`+setup+"\n\"$MARKER\"\n")
		cmd.Env = append(os.Environ(), "MARKER="+filepath.ToSlash(marker), "TEST_OVERRIDES="+filepath.ToSlash(overridesPath), "FAIL_SETUP="+failSetup)
		out, err := cmd.CombinedOutput()
		if failSetup == "true" {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("marker preparation failure must stop before evaluation retries: %v %s", err, out)
			}
		} else if err != nil {
			t.Fatalf("marker preparation/execution: %v %s", err, out)
		}
	}
	rawOverrides, err := os.ReadFile(overridesPath)
	if err != nil {
		t.Fatal(err)
	}
	var overrides map[string]interface{}
	if err := json.Unmarshal(rawOverrides, &overrides); err != nil {
		t.Fatal(err)
	}
	spec := object(overrides, "spec")
	security := object(spec, "securityContext")
	if security["runAsUser"] != float64(10001) || security["runAsGroup"] != float64(10001) || security["fsGroup"] != float64(10001) || security["runAsNonRoot"] != true {
		t.Fatalf("probe lost non-root writable-volume posture: %+v", security)
	}
	containers := contractValue[[]interface{}](t, "probe containers", spec["containers"])
	if len(containers) != 1 {
		t.Fatal("expected one probe container")
	}
	c := contractValue[map[string]interface{}](t, "probe container", containers[0])
	if c["name"] != "warmor-audit-probe" || c["image"] != "busybox:1.37" {
		t.Fatal("kubectl merge override does not identify the actual probe container")
	}
	mounts := contractValue[[]interface{}](t, "probe mounts", c["volumeMounts"])
	if len(mounts) != 1 {
		t.Fatal("expected marker volume mount")
	}
	mount := contractValue[map[string]interface{}](t, "marker mount", mounts[0])
	volumes := contractValue[[]interface{}](t, "probe volumes", spec["volumes"])
	if len(volumes) != 1 {
		t.Fatal("expected marker volume")
	}
	volume := contractValue[map[string]interface{}](t, "marker volume", volumes[0])
	if mount["mountPath"] != "/var/tmp" || mount["name"] != volume["name"] || volume["emptyDir"] == nil || volume["hostPath"] != nil {
		t.Fatalf("CR-only marker path must use pod-local writable storage: mount=%+v volume=%+v", mount, volume)
	}
	probeStart := strings.Index(script, "policy_audit_observed() {")
	if probeStart < 0 {
		t.Fatal("missing audit predicate")
	}
	probeEnd := strings.Index(script[probeStart:], "\n}\n")
	if probeEnd < 0 {
		t.Fatal("missing audit predicate end")
	}
	predicate := script[probeStart : probeStart+probeEnd+3]
	for _, tc := range []struct {
		count, path string
		ok          bool
	}{{"0", marker, false}, {"1", marker, true}, {"1", filepath.Join(dir, "missing-marker"), false}} {
		cmd := exec.Command("bash", "-c", `
KCTX=(--context kind-fixture)
PROBE=warmor-audit-probe
BEFORE_DENIES=0
kubectl() { shift 5; "$@"; }
deny_count() { echo "$COUNT"; }
`+predicate+"\npolicy_audit_observed")
		cmd.Env = append(os.Environ(), "MARKER="+filepath.ToSlash(tc.path), "COUNT="+tc.count)
		if out, err := cmd.CombinedOutput(); (err == nil) != tc.ok {
			t.Fatalf("audit predicate must execute marker AND require counter movement (count=%s path=%s): %v %s", tc.count, tc.path, err, out)
		}
	}
}
