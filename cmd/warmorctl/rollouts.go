package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type rolloutsModel struct {
	api      *apiClient
	rollouts []rolloutInfo
	loading  bool
	err      error
	cursor   int
}

type rolloutsMsg []rolloutInfo

func newRolloutsModel(serverURL, token string) *rolloutsModel {
	return &rolloutsModel{
		api: newAPIClient(serverURL, token),
	}
}

func (m *rolloutsModel) Init() tea.Cmd {
	m.loading = true
	return m.fetch
}

func (m *rolloutsModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case rolloutsMsg:
		m.rollouts = msg
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
			if m.cursor < len(m.rollouts)-1 {
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

func (m *rolloutsModel) View() string {
	if m.loading {
		return dimStyle.Render("Loading rollouts...")
	}
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Error: %v", m.err))
	}

	var sb strings.Builder
	sb.WriteString(headerStyle.Render(fmt.Sprintf("Rollouts (%d)", len(m.rollouts))))
	sb.WriteString("\n\n")

	if len(m.rollouts) == 0 {
		sb.WriteString(dimStyle.Render("  No rollouts configured"))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  %-20s %-20s %-12s %s\n",
		dimStyle.Render("ID"),
		dimStyle.Render("POLICY"),
		dimStyle.Render("STATUS"),
		dimStyle.Render("PROGRESS")))

	for i, r := range m.rollouts {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}

		status := r.Status
		switch status {
		case "active", "in_progress":
			status = successStyle.Render(status)
		case "completed":
			status = dimStyle.Render(status)
		case "aborted":
			status = errorStyle.Render(status)
		}

		bar := renderProgressBar(r.Percentage, 20)
		sb.WriteString(fmt.Sprintf("%s%-20s %-20s %-12s %s %d%%\n",
			prefix, r.ID, r.PolicyID, status, bar, r.Percentage))
	}

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  j/k: navigate | r: refresh"))

	return sb.String()
}

func (m *rolloutsModel) fetch() tea.Msg {
	var rollouts []rolloutInfo
	if err := m.api.get("/api/v1/admin/rollouts", &rollouts); err != nil {
		return errMsg{err}
	}
	return rolloutsMsg(rollouts)
}

func renderProgressBar(pct, width int) string {
	// Clamp so a bad percentage from the server can't make Repeat panic.
	pct = max(0, min(pct, 100))
	filled := pct * width / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}
