package main

// Test harness for exercising main() of this command.
//
// Paths that terminate via os.Exit / log.Fatal are run in a re-executed copy
// of the test binary via runChild (TestMain intercepts the child and calls
// main() with the requested args).

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const childArgsEnv = "WARMOR_CMD_TEST_CHILD_ARGS"

func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv(childArgsEnv); ok {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			fmt.Fprintf(os.Stderr, "bad %s: %v\n", childArgsEnv, err)
			os.Exit(97)
		}
		os.Args = append([]string{"warmor-server"}, args...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type childResult struct {
	stdout, stderr string
	code           int
}

// runChild re-executes the test binary so that main() runs with args in a
// separate process; use it for paths that call os.Exit or log.Fatal.
func runChild(t *testing.T, extraEnv []string, args ...string) childResult {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	enc, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), childArgsEnv+"="+string(enc), "GOCOVERDIR="+t.TempDir())
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run child: %v", err)
		}
		code = ee.ExitCode()
	}
	return childResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// resetFlags restores every non-testing flag on flag.CommandLine to its
// default so consecutive in-process runs don't leak values.
func resetFlags() {
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "test.") {
			return
		}
		_ = f.Value.Set(f.DefValue)
	})
}

func assertContains(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s missing %q:\n%s", label, w, got)
		}
	}
}
