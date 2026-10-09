package main

// Test harness for exercising main() of this command.
//
// Paths that return normally from main() are run in-process via runMain so
// they count towards coverage. Paths that terminate via os.Exit / log.Fatal
// are run in a re-executed copy of the test binary via runChild (TestMain
// intercepts the child and calls main() with the requested args).

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const childArgsEnv = "WARMOR_CMD_TEST_CHILD_ARGS"

// mainUsesLocalFlags reports whether main() defines its flags locally (and
// therefore needs a fresh flag.CommandLine per invocation) as opposed to
// package-level flag vars (which must instead be reset to their defaults).
const mainUsesLocalFlags = false

func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv(childArgsEnv); ok {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			fmt.Fprintf(os.Stderr, "bad %s: %v\n", childArgsEnv, err)
			os.Exit(97)
		}
		os.Args = append([]string{"warmor-compile"}, args...)
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

// runMain invokes main() in-process with args, capturing stdout, stderr and
// the standard logger. stdin, if non-empty, is fed to os.Stdin. The caller
// must only use it for paths where main() returns normally.
func runMain(t *testing.T, stdin string, args ...string) (stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()

	outF, err := os.Create(dir + "/stdout")
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.Create(dir + "/stderr")
	if err != nil {
		t.Fatal(err)
	}
	var inF *os.File
	if stdin != "" {
		if err := os.WriteFile(dir+"/stdin", []byte(stdin), 0o600); err != nil {
			t.Fatal(err)
		}
		if inF, err = os.Open(dir + "/stdin"); err != nil {
			t.Fatal(err)
		}
	}

	oldArgs, oldOut, oldErr, oldIn := os.Args, os.Stdout, os.Stderr, os.Stdin
	oldCmdLine, oldUsage := flag.CommandLine, flag.Usage
	oldLogFlags := log.Flags()

	os.Args = append([]string{"warmor-compile"}, args...)
	os.Stdout, os.Stderr = outF, errF
	if inF != nil {
		os.Stdin = inF
	}
	log.SetOutput(errF)
	if mainUsesLocalFlags {
		flag.CommandLine = flag.NewFlagSet("warmor-compile", flag.ContinueOnError)
	} else {
		resetFlags()
	}

	defer func() {
		os.Args, os.Stdout, os.Stderr, os.Stdin = oldArgs, oldOut, oldErr, oldIn
		flag.CommandLine, flag.Usage = oldCmdLine, oldUsage
		log.SetOutput(os.Stderr)
		log.SetFlags(oldLogFlags)
		outF.Close()
		errF.Close()
		if inF != nil {
			inF.Close()
		}
	}()

	main()

	o, _ := os.ReadFile(dir + "/stdout")
	e, _ := os.ReadFile(dir + "/stderr")
	return string(o), string(e)
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

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertContains(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s missing %q:\n%s", label, w, got)
		}
	}
}
