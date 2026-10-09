//go:build linux

package platform

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestConfigConvertsToLinuxConfig(t *testing.T) {
	cfg := Config{
		CgroupFilter: []string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b"},
		LSMEnforce:   true,
		RequireLSM:   true,
		SkipLSM:      false,
	}
	lc := LinuxConfig(cfg)
	if len(lc.CgroupFilter) != 2 || lc.CgroupFilter[1] != "/sys/fs/cgroup/b" {
		t.Errorf("CgroupFilter not preserved: %v", lc.CgroupFilter)
	}
	if !lc.LSMEnforce || !lc.RequireLSM || lc.SkipLSM {
		t.Errorf("flags not preserved: %+v", lc)
	}
}

func TestNewPassesConfigThrough(t *testing.T) {
	cfg := Config{CgroupFilter: []string{"auto"}, LSMEnforce: true, SkipLSM: true}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lp, ok := p.(*LinuxPlatform)
	if !ok {
		t.Fatalf("New returned %T, want *LinuxPlatform", p)
	}
	if lp.config.LSMEnforce != true || lp.config.SkipLSM != true || lp.config.RequireLSM {
		t.Errorf("config not passed through: %+v", lp.config)
	}
	if len(lp.config.CgroupFilter) != 1 || lp.config.CgroupFilter[0] != "auto" {
		t.Errorf("cgroup filter not passed through: %v", lp.config.CgroupFilter)
	}
}

func TestCurrent(t *testing.T) {
	p, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "linux" {
		t.Errorf("Name = %q, want linux", p.Name())
	}
	lp := p.(*LinuxPlatform)
	if lp.config.LSMEnforce || lp.config.RequireLSM || lp.config.SkipLSM || lp.config.CgroupFilter != nil {
		t.Errorf("Current should use zero config, got %+v", lp.config)
	}
}

func TestCapabilitiesBeforeLoad(t *testing.T) {
	p, _ := NewLinuxPlatform(LinuxConfig{LSMEnforce: true})
	caps := p.Capabilities()
	want := Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true,
		LSMEnforcement:    false, // LSM not loaded yet
	}
	if caps != want {
		t.Errorf("Capabilities = %+v, want %+v", caps, want)
	}
}

func TestCapabilitiesReflectLSMState(t *testing.T) {
	p := &LinuxPlatform{stopChan: make(chan struct{}), lsmEnabled: true}
	if !p.Capabilities().LSMEnforcement {
		t.Error("LSMEnforcement should be true when lsmEnabled")
	}
}

func TestPolicyMapNilWithoutLSM(t *testing.T) {
	p, _ := NewLinuxPlatform(LinuxConfig{})
	if pm := p.PolicyMap(); pm != nil {
		t.Errorf("PolicyMap = %v, want nil before LSM load", pm)
	}
}

func TestStartBeforeLoad(t *testing.T) {
	p, _ := NewLinuxPlatform(LinuxConfig{})
	ch := make(chan *api.Event, 1)
	err := p.Start(context.Background(), ch)
	if err == nil || !strings.Contains(err.Error(), "not loaded") {
		t.Fatalf("expected 'not loaded' error, got %v", err)
	}
}

func TestStopWithoutStart(t *testing.T) {
	p, _ := NewLinuxPlatform(LinuxConfig{})
	done := make(chan error, 1)
	go func() { done <- p.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung without Start")
	}
}

func TestCloseWithoutLoad(t *testing.T) {
	p, _ := NewLinuxPlatform(LinuxConfig{})
	if err := p.Close(); err != nil {
		t.Errorf("Close on unloaded platform: %v", err)
	}
	// Close is safe to call repeatedly when nothing was loaded.
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestLogSecurityPosture(t *testing.T) {
	cases := []struct {
		name       string
		lsmEnabled bool
		enforce    bool
		want       string
	}{
		{"enforce", true, true, "kernel enforcement ACTIVE"},
		{"audit", true, false, "AUDIT-ONLY"},
		{"observe", false, false, "OBSERVE-ONLY"},
		{"observe-enforce-requested", false, true, "OBSERVE-ONLY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &LinuxPlatform{lsmEnabled: tc.lsmEnabled, config: LinuxConfig{LSMEnforce: tc.enforce}}
			out := captureStdout(t, p.logSecurityPosture)
			if !strings.Contains(out, tc.want) {
				t.Errorf("posture output %q does not contain %q", out, tc.want)
			}
		})
	}
}

// TestLoadFailsWithoutPrivileges exercises Load's error path. Loading eBPF
// programs requires CAP_BPF/CAP_SYS_ADMIN, so as an unprivileged user Load
// must fail cleanly and leave the platform in an unloaded state.
func TestLoadFailsWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; Load would attach real eBPF programs")
	}
	for _, cfg := range []LinuxConfig{
		{},
		{SkipLSM: true},
		{RequireLSM: true, LSMEnforce: true},
		{CgroupFilter: []string{"auto"}},
	} {
		p, _ := NewLinuxPlatform(cfg)
		err := p.Load(context.Background())
		if err == nil {
			_ = p.Close()
			t.Skip("eBPF load succeeded (process has BPF capabilities); skipping unprivileged test")
		}
		if !strings.Contains(err.Error(), "load eBPF") {
			t.Errorf("cfg %+v: error %q missing 'load eBPF' prefix", cfg, err)
		}
		if p.Capabilities().LSMEnforcement {
			t.Errorf("cfg %+v: LSMEnforcement true after failed Load", cfg)
		}
		if p.PolicyMap() != nil {
			t.Errorf("cfg %+v: PolicyMap non-nil after failed Load", cfg)
		}
		if err := p.Start(context.Background(), make(chan *api.Event)); err == nil {
			t.Errorf("cfg %+v: Start succeeded after failed Load", cfg)
		}
		if err := p.Close(); err != nil {
			t.Errorf("cfg %+v: Close after failed Load: %v", cfg, err)
		}
	}
}

func TestPlatformInterfaceSatisfied(t *testing.T) {
	var _ Platform = (*LinuxPlatform)(nil)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	return string(buf[:n])
}
