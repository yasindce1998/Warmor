package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// --- certs ---

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	return cert
}

func TestCertsModel_GenerateCA(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	m := newCertsModel()
	cmd := m.Update(runeKey("g"))
	if cmd == nil {
		t.Fatal("'g' should return generate cmd")
	}
	msg := cmd()
	gen, ok := msg.(certGenMsg)
	if !ok {
		t.Fatalf("generateCA returned %T (%v)", msg, msg)
	}
	m.Update(gen)
	if v := m.View(); !strings.Contains(v, "ca.crt, ca.key") || !strings.Contains(v, "agent.crt") {
		t.Errorf("view after gen = %q", v)
	}

	out := filepath.Join(dir, "warmor-certs")
	for _, f := range []string{"ca.crt", "ca.key", "server.crt", "server.key", "agent.crt", "agent.key"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}

	ca := readCert(t, filepath.Join(out, "ca.crt"))
	if !ca.IsCA || ca.Subject.CommonName != "warmor-ca" {
		t.Errorf("CA cert: IsCA=%v CN=%q", ca.IsCA, ca.Subject.CommonName)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	srv := readCert(t, filepath.Join(out, "server.crt"))
	if srv.Subject.CommonName != "warmor-server" {
		t.Errorf("server CN = %q", srv.Subject.CommonName)
	}
	if err := srv.VerifyHostname("localhost"); err != nil {
		t.Errorf("server cert should be valid for localhost: %v", err)
	}
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("server cert not signed by CA: %v", err)
	}

	agent := readCert(t, filepath.Join(out, "agent.crt"))
	if agent.Subject.CommonName != "warmor-agent" {
		t.Errorf("agent CN = %q", agent.Subject.CommonName)
	}
	if _, err := agent.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("agent cert not signed by CA: %v", err)
	}
}

func TestCertsModel_GenerateSigningKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	m := newCertsModel()
	cmd := m.Update(runeKey("s"))
	if cmd == nil {
		t.Fatal("'s' should return generate cmd")
	}
	msg := cmd()
	gen, ok := msg.(certGenMsg)
	if !ok {
		t.Fatalf("generateSigningKey returned %T (%v)", msg, msg)
	}
	if !strings.Contains(gen.message, "signing.key") {
		t.Errorf("message = %q", gen.message)
	}
	for _, f := range []string{"signing.key", "signing.pub"} {
		data, err := os.ReadFile(filepath.Join(dir, "warmor-certs", f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if b, _ := pem.Decode(data); b == nil {
			t.Errorf("%s is not PEM", f)
		}
	}
}

func TestCertsModel_OutputDirUnwritable(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// A regular file where the output directory should be makes MkdirAll fail.
	if err := os.WriteFile(filepath.Join(dir, "warmor-certs"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newCertsModel()
	for name, fn := range map[string]func() tea.Msg{"ca": m.generateCA, "signing": m.generateSigningKey} {
		msg := fn()
		em, ok := msg.(errMsg)
		if !ok {
			t.Fatalf("%s: got %T, want errMsg", name, msg)
		}
		m.Update(em)
		if !strings.Contains(m.View(), "Error:") {
			t.Errorf("%s: view should show error: %q", name, m.View())
		}
	}
}

func TestCertsModel_ViewAndNavigation(t *testing.T) {
	m := newCertsModel()
	v := m.View()
	for _, want := range []string{"Certificate & Key Management", "> [g] Generate CA", "  [s] Generate policy signing", "Press g or s", "./warmor-certs/"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	m.Update(runeKey("j"))
	m.Update(runeKey("j"))
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want 1", m.cursor)
	}
	if !strings.Contains(m.View(), "> [s]") {
		t.Errorf("cursor should be on [s]:\n%s", m.View())
	}
	m.Update(runeKey("k"))
	m.Update(runeKey("k"))
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}

	// Init clears previous state.
	m.Update(errMsg{errors.New("old")})
	if m.Init() != nil {
		t.Error("certs Init should return nil")
	}
	if m.err != nil || m.message != "" {
		t.Error("Init should reset message and err")
	}
	if m.Update(runeKey("x")) != nil {
		t.Error("unbound key should return nil")
	}
}

// --- app ---

func TestApp_TabNavigation(t *testing.T) {
	fs := newFakeServer(t, fixtures{})
	a := newApp(fs.URL, "")

	if a.Init() == nil {
		t.Error("app Init should return dashboard fetch cmd")
	}

	order := []view{viewAgents, viewPolicies, viewRollouts, viewCerts, viewDashboard}
	for _, want := range order {
		_, _ = a.Update(tea.KeyMsg{Type: tea.KeyTab})
		if a.currentView != want {
			t.Fatalf("after tab: view = %d, want %d", a.currentView, want)
		}
	}
	// shift+tab wraps backwards.
	_, _ = a.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	if a.currentView != viewCerts {
		t.Errorf("shift+tab from dashboard = %d, want certs", a.currentView)
	}
	_, _ = a.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	if a.currentView != viewRollouts {
		t.Errorf("shift+tab = %d, want rollouts", a.currentView)
	}
}

func TestApp_NumberKeysAndViews(t *testing.T) {
	fs := newFakeServer(t, fixtures{
		agents:   []agentInfo{{ID: "agent-x", Status: "online"}},
		policies: []policyInfo{{ID: "pol-x", Version: 2}},
		rollouts: []rolloutInfo{{ID: "roll-x", Status: "active", Percentage: 40}},
	})
	a := newApp(fs.URL, "tok")

	cases := []struct {
		key      string
		view     view
		contains string
	}{
		{"2", viewAgents, "agent-x"},
		{"3", viewPolicies, "pol-x"},
		{"4", viewRollouts, "roll-x"},
		{"5", viewCerts, "Certificate & Key Management"},
		{"1", viewDashboard, "Cluster Overview"},
	}
	for _, c := range cases {
		_, cmd := a.Update(runeKey(c.key))
		if a.currentView != c.view {
			t.Fatalf("key %s: view = %d, want %d", c.key, a.currentView, c.view)
		}
		// Deliver the fetch result (certs has none) back through the app.
		if cmd != nil {
			_, _ = a.Update(cmd())
		}
		v := a.View()
		if !strings.Contains(v, c.contains) {
			t.Errorf("key %s: view missing %q:\n%s", c.key, c.contains, v)
		}
		if !strings.Contains(v, "warmor") || !strings.Contains(v, "tab/shift+tab: navigate") {
			t.Errorf("key %s: missing header/footer:\n%s", c.key, v)
		}
	}
}

func TestApp_QuitAndWindowSize(t *testing.T) {
	a := newApp("http://unused", "")

	_, _ = a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if a.width != 120 || a.height != 40 {
		t.Errorf("size = %dx%d", a.width, a.height)
	}

	for _, k := range []tea.KeyMsg{runeKey("q"), {Type: tea.KeyCtrlC}} {
		_, cmd := a.Update(k)
		if cmd == nil {
			t.Fatalf("%v: expected quit cmd", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%v: cmd did not produce QuitMsg", k)
		}
	}
}

func TestApp_RoutesMessagesToCurrentView(t *testing.T) {
	a := newApp("http://unused", "")
	a.currentView = viewPolicies
	_, _ = a.Update(policiesMsg{{ID: "only-policies"}})
	if len(a.policies.policies) != 1 {
		t.Error("policiesMsg should reach policies model")
	}
	// Non-current views do not receive messages.
	_, _ = a.Update(agentsMsg{{ID: "ignored"}})
	if len(a.agents.agents) != 0 {
		t.Error("agentsMsg should not reach agents model while on policies view")
	}
	for _, v := range []view{viewDashboard, viewAgents, viewPolicies, viewRollouts, viewCerts} {
		a.currentView = v
		if a.initCurrentView() == nil && v != viewCerts {
			t.Errorf("initCurrentView(%d) returned nil", v)
		}
		_, _ = a.Update(errMsg{errors.New("e")})
	}
	a.currentView = view(99)
	if a.initCurrentView() != nil {
		t.Error("unknown view should return nil cmd")
	}
}

func TestApp_RenderTabsHighlightsCurrent(t *testing.T) {
	a := newApp("http://unused", "")
	tabs := a.renderTabs()
	for _, want := range []string{"1:Dashboard", "2:Agents", "3:Policies", "4:Rollouts", "5:Certs"} {
		if !strings.Contains(tabs, want) {
			t.Errorf("tabs missing %q: %q", want, tabs)
		}
	}
}
