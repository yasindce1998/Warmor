package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type agentsModel struct {
	api     *apiClient
	agents  []agentInfo
	loading bool
	err     error
	cursor  int
}

type agentsMsg []agentInfo

func newAgentsModel(serverURL, token string) *agentsModel {
	return &agentsModel{
		api: newAPIClient(serverURL, token),
	}
}

func (m *agentsModel) Init() tea.Cmd {
	m.loading = true
	return m.fetch
}

func (m *agentsModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case agentsMsg:
		m.agents = msg
		m.loading = false
		m.err = nil
	case errMsg:
		m.err = msg.err
		m.loading = false
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			return m.Init()
		case "j", "down":
			if m.cursor < len(m.agents)-1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		}
	}
	return nil
}

func (m *agentsModel) View() string {
	if m.loading {
		return dimStyle.Render("Loading agents...")
	}
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Error: %v", m.err))
	}

	var sb strings.Builder
	sb.WriteString(headerStyle.Render(fmt.Sprintf("Agents (%d)", len(m.agents))))
	sb.WriteString("\n\n")

	if len(m.agents) == 0 {
		sb.WriteString(dimStyle.Render("  No agents registered"))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  %-22s %-16s %-8s %-8s %-20s %s\n",
		dimStyle.Render("ID"),
		dimStyle.Render("HOSTNAME"),
		dimStyle.Render("STATUS"),
		dimStyle.Render("VER"),
		dimStyle.Render("LAST HEARTBEAT"),
		dimStyle.Render("LABELS")))

	for i, a := range m.agents {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}

		status := a.Status
		if status == "online" {
			status = successStyle.Render("online")
		} else {
			status = errorStyle.Render(status)
		}

		hb := "never"
		if !a.LastHeartbeat.IsZero() {
			hb = time.Since(a.LastHeartbeat).Truncate(time.Second).String() + " ago"
		}

		// Sort keys so labels don't reshuffle on every redraw.
		labels := ""
		for _, k := range slices.Sorted(maps.Keys(a.Labels)) {
			labels += k + "=" + a.Labels[k] + " "
		}

		sb.WriteString(fmt.Sprintf("%s%-20s %-16s %-8s v%-7d %-20s %s\n",
			prefix, a.ID, a.Hostname, status, a.PolicyVersion, hb, dimStyle.Render(labels)))
	}

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  j/k: navigate | r: refresh"))

	return sb.String()
}

func (m *agentsModel) fetch() tea.Msg {
	var agents []agentInfo
	if err := m.api.get("/api/v1/admin/agents", &agents); err != nil {
		return errMsg{err}
	}
	return agentsMsg(agents)
}
