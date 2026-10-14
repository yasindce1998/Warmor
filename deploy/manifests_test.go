// Package deploy_test checks the plain Kubernetes manifests against the
// binaries they run, so flags and env vars cannot silently drift.
package deploy_test

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// daemonFlags returns the flag names registered by cmd/warmor-daemon, found
// by scanning its sources for flag.<Type>("name", ...) calls.
func daemonFlags(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "cmd", "warmor-daemon", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if name, err := strconv.Unquote(lit.Value); err == nil {
					flags[name] = true
				}
			}
			return true
		})
	}
	if len(flags) < 5 {
		t.Fatalf("found only %d daemon flags; scanner is broken", len(flags))
	}
	return flags
}

type container struct {
	Name  string   `yaml:"name"`
	Image string   `yaml:"image"`
	Args  []string `yaml:"args"`
	Env   []struct {
		Name string `yaml:"name"`
	} `yaml:"env"`
}

func TestDaemonSetMatchesDaemonFlags(t *testing.T) {
	flags := daemonFlags(t)
	// Env vars the daemon itself reads (cmd/warmor-daemon serverTokenEnv).
	daemonEnv := map[string]bool{"WARMOR_SERVER_TOKEN": true}

	data, err := os.ReadFile(filepath.Join("kubernetes", "warmor-daemonset.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	found := false
	for {
		var doc struct {
			Kind string `yaml:"kind"`
			Spec struct {
				Template struct {
					Spec struct {
						Containers []container `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("invalid YAML: %v", err)
		}
		if doc.Kind != "DaemonSet" {
			continue
		}
		for _, c := range doc.Spec.Template.Spec.Containers {
			found = true
			if len(c.Args) == 0 {
				t.Errorf("container %s has no args; the daemon is configured only by flags", c.Name)
			}
			expand := regexp.MustCompile(`\$\(([A-Za-z_][A-Za-z0-9_]*)\)`)
			expanded := map[string]bool{}
			for _, a := range c.Args {
				for _, m := range expand.FindAllStringSubmatch(a, -1) {
					expanded[m[1]] = true
				}
				if !strings.HasPrefix(a, "-") {
					continue
				}
				name := strings.TrimLeft(a, "-")
				if i := strings.IndexByte(name, '='); i >= 0 {
					name = name[:i]
				}
				if !flags[name] {
					t.Errorf("container %s: arg %q is not a warmor-daemon flag", c.Name, a)
				}
			}
			for _, e := range c.Env {
				if !daemonEnv[e.Name] && !expanded[e.Name] {
					t.Errorf("container %s: env %s is neither read by the daemon nor used in args", c.Name, e.Name)
				}
			}
		}
	}
	if !found {
		t.Fatal("no DaemonSet container found")
	}
}
