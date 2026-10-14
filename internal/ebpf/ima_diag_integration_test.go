//go:build integration

package ebpf

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strings"
	"testing"
)

// TestIMA_Environment logs what the integrity tests depend on, so a failure
// in CI says why: whether IMA is built in, whether securityfs exposes it, and
// whether an IMA policy is active.
func TestIMA_Environment(t *testing.T) {
	requireRoot(t)
	if f, err := os.Open("/proc/config.gz"); err == nil {
		zr, err := gzip.NewReader(f)
		if err == nil {
			cfg, _ := io.ReadAll(zr)
			for _, line := range bytes.Split(cfg, []byte("\n")) {
				if bytes.Contains(line, []byte("CONFIG_IMA")) || bytes.Contains(line, []byte("CONFIG_INTEGRITY")) {
					t.Logf("kconfig: %s", line)
				}
			}
		}
		f.Close()
	} else {
		t.Logf("no /proc/config.gz: %v", err)
	}
	if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		t.Logf("active LSMs: %s", strings.TrimSpace(string(lsm)))
	}
	ok, err := imaAvailable()
	t.Logf("IMA in kernel BTF: %v (err %v)", ok, err)
}
