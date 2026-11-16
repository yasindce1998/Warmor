package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type dashboardModel struct {
	api      *apiClient
	agents   []agentInfo
	policies []policyInfo
	rollouts []rolloutInfo
	loading  bool
	err      error
}

type dashboardDataMsg struct {
	agents   []agentInfo
	policies []policyInfo
	rollouts []rolloutInfo
}

type errMsg struct{ err error }

func newDashboardModel(serverURL, token string) *dashboardModel {
	return &dashboardModel{
		api: newAPIClient(serverURL, token),
	}
}

func (m *dashboardModel) Init() tea.Cmd {
	m.loading = true
	return m.fetchAll
}

func (m *dashboardModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case dashboardDataMsg:
		m.agents = msg.agents
		m.policies = msg.policies
		m.rollouts = msg.rollouts
		m.loading = false
		m.err = nil
	case errMsg:
		m.err = msg.err
		m.loading = false
	case tea.KeyMsg:
		if msg.String() == "r" {
			return m.Init()
		}
	}
	return nil
}

func (m *dashboardModel) View() string {
	if m.loading {
		return dimStyle.Render("Loading dashboard...")
	}
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Error: %v", m.err))
	}

	var sb strings.Builder

	sb.WriteString(headerStyle.Render("Cluster Overview"))
	sb.WriteString("\n\n")

	// Agent summary
	online := 0
	for _, a := range m.agents {
		if a.Status == "online" {
			online++
		}
	}
	sb.WriteString(fmt.Sprintf("  Agents:   %s / %d total\n",
		successStyle.Render(fmt.Sprintf("%d online", online)),
		len(m.agents)))

	sb.WriteString(fmt.Sprintf("  Policies: %d registered\n", len(m.policies)))

	activeRollouts := 0
	for _, r := range m.rollouts {
		if r.Status == "active" || r.Status == "in_progress" {
			activeRollouts++
		}
	}
	sb.WriteString(fmt.Sprintf("  Rollouts: %d active\n", activeRollouts))

	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render("Recent Agents"))
	sb.WriteString("\n\n")

	if len(m.agents) == 0 {
		sb.WriteString(dimStyle.Render("  No agents registered"))
	} else {
		sb.WriteString(fmt.Sprintf("  %-20s %-15s %-10s %s\n",
			dimStyle.Render("ID"), dimStyle.Render("HOSTNAME"), dimStyle.Render("STATUS"), dimStyle.Render("POLICY VER")))
		limit := len(m.agents)
		if limit > 10 {
			limit = 10
		}
		for _, a := range m.agents[:limit] {
			status := a.Status
			if status == "online" {
				status = successStyle.Render(status)
			} else {
				status = errorStyle.Render(status)
			}
			sb.WriteString(fmt.Sprintf("  %-20s %-15s %-10s v%d\n",
				a.ID, a.Hostname, status, a.PolicyVersion))
		}
	}

	return sb.String()
}

func (m *dashboardModel) fetchAll() tea.Msg {
	var agents []agentInfo
	var policies []policyInfo
	var rollouts []rolloutInfo

	if err := m.api.get(routeAdminAgents, &agents); err != nil {
		return errMsg{err}
	}
	if err := m.api.get(routeAdminPolicies, &policies); err != nil {
		return errMsg{err}
	}
	if err := m.api.get(routeAdminRollouts, &rollouts); err != nil {
		return errMsg{err}
	}

	return dashboardDataMsg{
		agents:   agents,
		policies: policies,
		rollouts: rollouts,
	}
}
