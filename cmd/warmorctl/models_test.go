package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func runeKey(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// --- renderProgressBar ---

func TestRenderProgressBar(t *testing.T) {
	tests := []struct {
		pct, width    int
		filled, total int
	}{
		{0, 20, 0, 20},
		{50, 20, 10, 20},
		{100, 20, 20, 20},
		{150, 20, 20, 20}, // clamped
		{-10, 20, 0, 20},  // clamped; used to panic in strings.Repeat
		{33, 10, 3, 10},   // integer truncation
		{99, 10, 9, 10},
		{100, 0, 0, 0},
	}
	for _, tt := range tests {
		bar := renderProgressBar(tt.pct, tt.width)
		if got := strings.Count(bar, "█"); got != tt.filled {
			t.Errorf("renderProgressBar(%d,%d) filled = %d, want %d", tt.pct, tt.width, got, tt.filled)
		}
		if got := len([]rune(bar)); got != tt.total {
			t.Errorf("renderProgressBar(%d,%d) width = %d, want %d", tt.pct, tt.width, got, tt.total)
		}
	}
}

// --- dashboard ---

func TestDashboardModel_FetchAllAndView(t *testing.T) {
	agents := make([]agentInfo, 12)
	for i := range agents {
		agents[i] = agentInfo{ID: "agent-" + string(rune('a'+i)), Hostname: "host", Status: "offline", PolicyVersion: int64(i)}
	}
	agents[0].Status = "online"
	agents[1].Status = "online"
	fs := newFakeServer(t, fixtures{
		agents:   agents,
		policies: []policyInfo{{ID: "p1", Version: 1}, {ID: "p2", Version: 3}},
		rollouts: []rolloutInfo{
			{ID: "r1", Status: "active"},
			{ID: "r2", Status: "in_progress"},
			{ID: "r3", Status: "completed"},
		},
	})

	m := newDashboardModel(fs.URL, "tok")
	cmd := m.Init()
	if !m.loading {
		t.Error("Init should set loading")
	}
	if !strings.Contains(m.View(), "Loading dashboard") {
		t.Errorf("loading view = %q", m.View())
	}

	msg := cmd()
	data, ok := msg.(dashboardDataMsg)
	if !ok {
		t.Fatalf("fetchAll returned %T (%v), want dashboardDataMsg", msg, msg)
	}
	if got := fs.paths(); len(got) != 3 {
		t.Errorf("expected 3 API calls, got %v", got)
	}
	if fs.auth() != "Bearer tok" {
		t.Errorf("auth header = %q", fs.auth())
	}

	if m.Update(data) != nil {
		t.Error("Update(data) should return nil cmd")
	}
	if m.loading || m.err != nil {
		t.Errorf("after data: loading=%v err=%v", m.loading, m.err)
	}

	v := m.View()
	for _, want := range []string{
		"Cluster Overview",
		"2 online / 12 total",
		"Policies: 2 registered",
		"Rollouts: 2 active",
		"Recent Agents",
		"agent-a",
		"agent-j", // 10th agent shown
	} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	// Only the first 10 agents are listed.
	if strings.Contains(v, "agent-k") || strings.Contains(v, "agent-l") {
		t.Errorf("view should truncate to 10 agents:\n%s", v)
	}
}

func TestDashboardModel_EmptyAndErrors(t *testing.T) {
	m := newDashboardModel("http://unused", "")
	m.Update(dashboardDataMsg{})
	if v := m.View(); !strings.Contains(v, "No agents registered") || !strings.Contains(v, "0 online / 0 total") {
		t.Errorf("empty view = %q", v)
	}

	m.Update(errMsg{errors.New("kaboom")})
	if v := m.View(); !strings.Contains(v, "Error: kaboom") {
		t.Errorf("error view = %q", v)
	}
	if m.loading {
		t.Error("errMsg should clear loading")
	}

	if cmd := m.Update(runeKey("r")); cmd == nil || !m.loading {
		t.Error("'r' should trigger refresh")
	}
	if cmd := m.Update(runeKey("x")); cmd != nil {
		t.Error("unbound key should return nil")
	}
}

func TestDashboardModel_FetchErrorEachEndpoint(t *testing.T) {
	for _, path := range []string{"/api/v1/admin/agents", "/api/v1/admin/policies", "/api/v1/admin/rollouts"} {
		t.Run(path, func(t *testing.T) {
			fs := newFakeServer(t, fixtures{failPath: path})
			m := newDashboardModel(fs.URL, "")
			msg := m.fetchAll()
			em, ok := msg.(errMsg)
			if !ok {
				t.Fatalf("got %T, want errMsg", msg)
			}
			if !strings.Contains(em.err.Error(), "HTTP 500") {
				t.Errorf("err = %v", em.err)
			}
		})
	}
}

// --- agents ---

func TestAgentsModel_FetchViewNavigate(t *testing.T) {
	fs := newFakeServer(t, fixtures{agents: []agentInfo{
		{ID: "a1", Hostname: "web-1", Status: "online", PolicyVersion: 4,
			Labels: map[string]string{"env": "prod"}, LastHeartbeat: time.Now().Add(-5 * time.Second)},
		{ID: "a2", Hostname: "web-2", Status: "stale"},
	}})
	m := newAgentsModel(fs.URL, "")
	cmd := m.Init()
	if !strings.Contains(m.View(), "Loading agents") {
		t.Errorf("loading view = %q", m.View())
	}
	msg := cmd()
	if _, ok := msg.(agentsMsg); !ok {
		t.Fatalf("fetch returned %T", msg)
	}
	m.Update(msg)

	v := m.View()
	for _, want := range []string{"Agents (2)", "web-1", "web-2", "v4", "env=prod", "never", " ago", "online", "stale", "j/k: navigate"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	if !strings.Contains(v, "> a1") {
		t.Errorf("cursor should be on a1:\n%s", v)
	}

	// Cursor navigation is bounded.
	m.Update(runeKey("k"))
	if m.cursor != 0 {
		t.Errorf("cursor = %d after k at top", m.cursor)
	}
	m.Update(runeKey("j"))
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.cursor != 1 {
		t.Errorf("cursor = %d, want clamped to 1", m.cursor)
	}
	if !strings.Contains(m.View(), "> a2") {
		t.Errorf("cursor should be on a2:\n%s", m.View())
	}
	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.cursor != 0 {
		t.Errorf("cursor = %d after up", m.cursor)
	}

	if cmd := m.Update(runeKey("r")); cmd == nil || !m.loading {
		t.Error("'r' should refresh")
	}
}

// TestAgentsModel_LabelsSorted is a regression test: labels used to render in
// Go's random map order, reshuffling on every redraw.
func TestAgentsModel_LabelsSorted(t *testing.T) {
	m := newAgentsModel("http://unused", "")
	m.Update(agentsMsg{{ID: "a1", Labels: map[string]string{
		"zone": "z1", "app": "web", "env": "prod", "tier": "front", "region": "eu", "owner": "ops",
	}}})
	want := "app=web env=prod owner=ops region=eu tier=front zone=z1"
	for i := 0; i < 20; i++ {
		if v := m.View(); !strings.Contains(v, want) {
			t.Fatalf("labels not sorted, want %q in:\n%s", want, v)
		}
	}
}

func TestAgentsModel_EmptyAndError(t *testing.T) {
	m := newAgentsModel("http://unused", "")
	m.Update(agentsMsg(nil))
	if v := m.View(); !strings.Contains(v, "No agents registered") || !strings.Contains(v, "Agents (0)") {
		t.Errorf("empty view = %q", v)
	}
	m.Update(errMsg{errors.New("nope")})
	if !strings.Contains(m.View(), "Error: nope") {
		t.Errorf("error view = %q", m.View())
	}
	// A subsequent successful load clears the error.
	m.Update(agentsMsg{{ID: "x"}})
	if m.err != nil {
		t.Error("agentsMsg should clear err")
	}
}

func TestAgentsModel_FetchError(t *testing.T) {
	fs := newFakeServer(t, fixtures{failPath: "/api/v1/admin/agents"})
	m := newAgentsModel(fs.URL, "")
	if _, ok := m.fetch().(errMsg); !ok {
		t.Fatal("expected errMsg")
	}
}

// --- policies ---

func TestPoliciesModel_FetchViewNavigate(t *testing.T) {
	fs := newFakeServer(t, fixtures{policies: []policyInfo{{ID: "base", Version: 1}, {ID: "strict", Version: 9}}})
	m := newPoliciesModel(fs.URL, "")
	cmd := m.Init()
	if !strings.Contains(m.View(), "Loading policies") {
		t.Errorf("loading view = %q", m.View())
	}
	m.Update(cmd())
	v := m.View()
	for _, want := range []string{"Policies (2)", "base", "strict", "v1", "v9", "> base"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	m.Update(runeKey("j"))
	m.Update(runeKey("j"))
	if m.cursor != 1 {
		t.Errorf("cursor = %d", m.cursor)
	}
	m.Update(runeKey("k"))
	m.Update(runeKey("k"))
	if m.cursor != 0 {
		t.Errorf("cursor = %d", m.cursor)
	}
	if cmd := m.Update(runeKey("r")); cmd == nil {
		t.Error("'r' should refresh")
	}
}

func TestPoliciesModel_EmptyErrorAndFetchError(t *testing.T) {
	m := newPoliciesModel("http://unused", "")
	m.Update(policiesMsg(nil))
	if !strings.Contains(m.View(), "No policies registered") {
		t.Errorf("empty view = %q", m.View())
	}
	m.Update(errMsg{errors.New("bad")})
	if !strings.Contains(m.View(), "Error: bad") {
		t.Errorf("error view = %q", m.View())
	}

	fs := newFakeServer(t, fixtures{failPath: "/api/v1/admin/policies"})
	m2 := newPoliciesModel(fs.URL, "")
	if _, ok := m2.fetch().(errMsg); !ok {
		t.Fatal("expected errMsg")
	}
}

// --- rollouts ---

func TestRolloutsModel_FetchViewNavigate(t *testing.T) {
	fs := newFakeServer(t, fixtures{rollouts: []rolloutInfo{
		{ID: "r-active", PolicyID: "p1", Status: "active", Percentage: 50},
		{ID: "r-prog", PolicyID: "p1", Status: "in_progress", Percentage: 10},
		{ID: "r-done", PolicyID: "p2", Status: "completed", Percentage: 100},
		{ID: "r-abort", PolicyID: "p3", Status: "aborted", Percentage: 0},
		{ID: "r-pending", PolicyID: "p4", Status: "pending", Percentage: 0},
	}})
	m := newRolloutsModel(fs.URL, "")
	cmd := m.Init()
	if !strings.Contains(m.View(), "Loading rollouts") {
		t.Errorf("loading view = %q", m.View())
	}
	m.Update(cmd())
	v := m.View()
	for _, want := range []string{"Rollouts (5)", "r-active", "r-done", "aborted", "pending", " 50%", "100%", "> r-active"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	for i := 0; i < 10; i++ {
		m.Update(runeKey("j"))
	}
	if m.cursor != 4 {
		t.Errorf("cursor = %d, want 4", m.cursor)
	}
	for i := 0; i < 10; i++ {
		m.Update(tea.KeyMsg{Type: tea.KeyUp})
	}
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}
	if cmd := m.Update(runeKey("r")); cmd == nil {
		t.Error("'r' should refresh")
	}
}

// TestRolloutsModel_NegativePercentage is a regression test: a negative
// percentage from the server used to panic the TUI in renderProgressBar.
func TestRolloutsModel_NegativePercentage(t *testing.T) {
	m := newRolloutsModel("http://unused", "")
	m.Update(rolloutsMsg{{ID: "r-bad", PolicyID: "p1", Status: "active", Percentage: -5}})
	if v := m.View(); !strings.Contains(v, "r-bad") {
		t.Errorf("view missing rollout:\n%s", v)
	}
}

func TestRolloutsModel_EmptyErrorAndFetchError(t *testing.T) {
	m := newRolloutsModel("http://unused", "")
	m.Update(rolloutsMsg(nil))
	if !strings.Contains(m.View(), "No rollouts configured") {
		t.Errorf("empty view = %q", m.View())
	}
	m.Update(errMsg{errors.New("bad")})
	if !strings.Contains(m.View(), "Error: bad") {
		t.Errorf("error view = %q", m.View())
	}

	fs := newFakeServer(t, fixtures{failPath: "/api/v1/admin/rollouts"})
	m2 := newRolloutsModel(fs.URL, "")
	if _, ok := m2.fetch().(errMsg); !ok {
		t.Fatal("expected errMsg")
	}
}
