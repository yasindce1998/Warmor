package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spdxSBOM = `{
  "spdxVersion": "SPDX-2.3",
  "name": "nginx-alpine",
  "packages": [
    {"name": "nginx", "versionInfo": "1.25.3-r1", "primaryPackagePurpose": "APPLICATION"},
    {"name": "musl", "versionInfo": "1.2.4-r2", "primaryPackagePurpose": "LIBRARY"}
  ]
}`

const cyclonedxSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {"component": {"type": "container", "name": "nginx", "version": "1.25-alpine"}},
  "components": [
    {"type": "application", "name": "nginx", "version": "1.25.3-r1"},
    {"type": "library", "name": "musl", "version": "1.2.4-r2"}
  ]
}`

const apkInstalled = `P:nginx
V:1.25.3-r1
F:usr/sbin
R:nginx
F:usr/share/nginx
R:index.html

P:musl
V:1.2.4-r2
F:lib
R:ld-musl-x86_64.so.1
F:usr/lib
R:libm.so

`

// apkRootFS builds a minimal Alpine-style rootfs with an APK database.
func apkRootFS(t *testing.T) string {
	t.Helper()
	rootfs := t.TempDir()
	db := filepath.Join(rootfs, "lib", "apk", "db")
	if err := os.MkdirAll(db, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(db, "installed"), apkInstalled)
	return rootfs
}

func TestSBOM_SPDXBinaryLevelToStdout(t *testing.T) {
	sbom := writeFile(t, filepath.Join(t.TempDir(), "sbom.json"), spdxSBOM)
	stdout, stderr := runMain(t, "", "-rootfs", apkRootFS(t), sbom)

	assertContains(t, "stderr", stderr,
		"Parsing SBOM: "+sbom+" (format: auto)",
		"Name: nginx-alpine, Packages: 2",
		"level: binary")
	assertContains(t, "policy", stdout,
		"name: nginx-alpine-sbom-policy",
		"default_action: deny",
		"/usr/sbin/nginx",
		"/usr/bin/python3") // interpreters included by default
	if strings.Contains(stdout, "libm.so") {
		t.Errorf("binary level should exclude libraries:\n%s", stdout)
	}
}

func TestSBOM_CycloneDXAllLevelToFile(t *testing.T) {
	dir := t.TempDir()
	sbom := writeFile(t, filepath.Join(dir, "bom.json"), cyclonedxSBOM)
	outPath := filepath.Join(dir, "policy.yaml")
	stdout, stderr := runMain(t, "",
		"-format", "cyclonedx",
		"-level", "all",
		"-rootfs", apkRootFS(t),
		"-name", "my-policy",
		"-description", "hand written",
		"-include-interpreters=false",
		"-o", outPath,
		sbom)
	if stdout != "" {
		t.Errorf("stdout should be empty with -o, got %q", stdout)
	}
	assertContains(t, "stderr", stderr, "Policy written to: "+outPath)
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	assertContains(t, "policy", s, "name: my-policy", "hand written", "/usr/sbin/nginx", "libm.so")
	if strings.Contains(s, "python3") {
		t.Errorf("interpreters should be excluded:\n%s", s)
	}
}

func TestSBOM_Errors(t *testing.T) {
	dir := t.TempDir()
	sbom := writeFile(t, filepath.Join(dir, "sbom.json"), spdxSBOM)
	garbage := writeFile(t, filepath.Join(dir, "garbage.json"), `{"hello": "world"}`)
	rootfs := apkRootFS(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no input", nil, "SBOM file path required"},
		{"bad level", []string{"-level", "kernel", sbom}, "--level must be binary, library, or all"},
		{"missing sbom", []string{"-rootfs", rootfs, filepath.Join(dir, "nope.json")}, "Error parsing SBOM"},
		{"unknown format", []string{"-rootfs", rootfs, garbage}, "Error parsing SBOM"},
		{"no package db", []string{"-rootfs", t.TempDir(), sbom}, "Error resolving packages"},
		{"unwritable output", []string{"-rootfs", rootfs, "-o", filepath.Join(dir, "x", "y", "p.yaml"), sbom}, "Error writing output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runChild(t, nil, tt.args...)
			if r.code != 1 {
				t.Errorf("exit = %d, want 1 (stderr: %s)", r.code, r.stderr)
			}
			assertContains(t, "stderr", r.stderr, tt.want)
		})
	}
}

func TestSBOM_Version(t *testing.T) {
	r := runChild(t, nil, "-version")
	if r.code != 0 {
		t.Fatalf("exit = %d", r.code)
	}
	assertContains(t, "stdout", r.stdout, "warmor-sbom-policy ")
}
