package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type policiesModel struct {
	api      *apiClient
	policies []policyInfo
	loading  bool
	err      error
	cursor   int
}

type policiesMsg []policyInfo

func newPoliciesModel(serverURL, token string) *policiesModel {
	return &policiesModel{
		api: newAPIClient(serverURL, token),
	}
}

func (m *policiesModel) Init() tea.Cmd {
	m.loading = true
	return m.fetch
}

func (m *policiesModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case policiesMsg:
		m.policies = msg
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
			if m.cursor < len(m.policies)-1 {
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

func (m *policiesModel) View() string {
	if m.loading {
		return dimStyle.Render("Loading policies...")
	}
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Error: %v", m.err))
	}

	var sb strings.Builder
	sb.WriteString(headerStyle.Render(fmt.Sprintf("Policies (%d)", len(m.policies))))
	sb.WriteString("\n\n")

	if len(m.policies) == 0 {
		sb.WriteString(dimStyle.Render("  No policies registered"))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  %-30s %s\n",
		dimStyle.Render("ID"), dimStyle.Render("VERSION")))

	for i, p := range m.policies {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		sb.WriteString(fmt.Sprintf("%s%-30s v%d\n", prefix, p.ID, p.Version))
	}

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  j/k: navigate | r: refresh"))

	return sb.String()
}

func (m *policiesModel) fetch() tea.Msg {
	var policies []policyInfo
	if err := m.api.get(routeAdminPolicies, &policies); err != nil {
		return errMsg{err}
	}
	return policiesMsg(policies)
}
