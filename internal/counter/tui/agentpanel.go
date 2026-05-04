// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

func (m *Model) RenderAgentPanel(width, height int) string {
	if m.activeAgent == nil {
		return m.renderWaitingForAgent(width, height)
	}

	return m.renderActiveAgent(width, height)
}

func (m *Model) renderWaitingForAgent(width, height int) string {
	contentHeight := height
	if contentHeight < 1 {
		contentHeight = 1
	}

	var lines []string
	lines = append(lines,
		" "+panelTitleStyle.Render("Agent Status"),
	)

	if len(m.sessions) > 0 {
		lastSession := m.sessions[len(m.sessions)-1]
		ago := time.Since(lastSession.LastSeen)
		lines = append(lines,
			mutedColor.Render("  Last seen: ")+truncate(lastSession.AgentID, max(width-15, 12)),
			mutedColor.Render("  Connected back: ")+formatDuration(ago)+" ago",
		)
	} else {
		lines = append(lines,
			mutedColor.Render("  Waiting for agent callback"),
			mutedColor.Render("  Deploy brisket to a CI runner to begin"),
		)
	}
	if len(lines) > contentHeight {
		lines = lines[:contentHeight]
	}
	for len(lines) < contentHeight {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func (m *Model) renderActiveAgent(width, height int) string {
	contentHeight := height
	if contentHeight < 1 {
		contentHeight = 1
	}
	agent := m.activeAgent

	var lines []string
	lines = append(lines, " "+panelTitleStyle.Render("Agent Status"))

	statusText, remaining, countdown := m.activeAgentStatus()
	lines = append(lines,
		mutedColor.Render("  Agent: ")+truncate(agent.ID, max(width-22, 12))+" | "+renderAgentStatus(statusText, remaining, countdown),
		m.renderAgentProvenanceLine(agent, width),
		mutedColor.Render("  Connected back: ")+m.renderAgentConnectedBack(agent),
	)
	if agent.Mode == agentModeResident {
		lines = append(lines, m.renderResidentWatchLines(agent, width)...)
	}

	if len(lines) > contentHeight {
		lines = lines[:contentHeight]
	}
	for len(lines) < contentHeight {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderResidentWatchLines(agent *AgentState, width int) []string {
	status := agent.ResidentWatchStatus
	if status == "" {
		status = "watching"
	}
	lines := []string{mutedColor.Render("  Watch: ") + status}
	if agent.ResidentSignalSource != "" {
		lines = append(lines, mutedColor.Render("  Signal: ")+truncate(agent.ResidentSignalSource, max(width-10, 8)))
	}
	if agent.ResidentLastObserved.IsZero() {
		lines = append(lines, mutedColor.Render("  Last job: none observed"))
	} else {
		job := strings.TrimSpace(strings.Join([]string{
			agent.ResidentLastRepository,
			agent.ResidentLastWorkflow,
			agent.ResidentLastJob,
		}, " "))
		if job == "" {
			job = "unknown"
		}
		lines = append(lines, mutedColor.Render("  Last job: ")+truncate(job, max(width-12, 8)))
	}
	if !agent.ResidentLastHarvested.IsZero() {
		label := agent.ResidentLastHarvested.Format(time.RFC3339)
		if agent.ResidentLastConfidence != "" {
			label += " " + agent.ResidentLastConfidence
		}
		lines = append(lines, mutedColor.Render("  Harvest: ")+truncate(label, max(width-11, 8)))
	}
	if agent.ResidentLastHarvestError != "" {
		lines = append(lines, errorColor.Render("  Harvest failed: ")+truncate(agent.ResidentLastHarvestError, max(width-18, 8)))
	}
	return lines
}

func (m Model) activeAgentStatus() (string, time.Duration, bool) {
	remaining := time.Until(m.jobDeadline)
	switch m.activeAgentMode() {
	case agentModeResident:
		return "✓ Resident foothold online", remaining, false
	case agentModeDwell:
		switch {
		case m.jobDeadline.IsZero():
			return "✓ Dwell active", remaining, false
		case remaining <= 0:
			return "✓ Dwell complete", remaining, false
		default:
			return fmt.Sprintf("⏱ %s remaining", formatCountdown(remaining)), remaining, true
		}
	default:
		switch {
		case !m.jobDeadline.IsZero() && remaining > 0:
			return fmt.Sprintf("⏱ %s remaining", formatCountdown(remaining)), remaining, true
		default:
			return "✓ Express complete", remaining, false
		}
	}
}

func (m Model) activeAgentMode() string {
	if m.activeAgent == nil {
		return ""
	}
	mode := strings.TrimSpace(m.activeAgent.Mode)
	if mode != "" {
		return mode
	}
	if m.dwellMode {
		return agentModeDwell
	}
	return agentModeExpress
}

func formatCountdown(d time.Duration) string {
	if d <= 0 {
		return "EXPIRED"
	}

	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60

	if minutes > 0 {
		return fmt.Sprintf("%d:%02d", minutes, seconds)
	}
	return fmt.Sprintf("0:%02d", seconds)
}

func renderAgentStatus(statusText string, remaining time.Duration, countdown bool) string {
	if !countdown {
		return successColor.Render(statusText)
	}
	countdownStyle := successColor
	if remaining < 2*time.Minute {
		countdownStyle = warningColor
	}
	if remaining < 30*time.Second {
		countdownStyle = errorColor
	}
	return countdownStyle.Render(statusText)
}

func (m Model) renderAgentProvenanceLine(agent *AgentState, width int) string {
	plainParts := make([]string, 0, 3)
	if agent.Repo != "" {
		plainParts = append(plainParts, agent.Repo)
	}
	if agent.Workflow != "" {
		plainParts = append(plainParts, agent.Workflow)
	}
	if agent.Job != "" {
		plainParts = append(plainParts, agent.Job)
	}
	if len(plainParts) == 0 {
		return mutedColor.Render("  Repo: unknown")
	}

	prefix := mutedColor.Render("  Repo: ")
	plainLine := strings.Join(plainParts, " → ")
	if lipgloss.Width(plainLine)+8 > width {
		return prefix + truncateVisual(plainLine, max(width-8, 12))
	}

	renderedParts := make([]string, 0, len(plainParts))
	if agent.Repo != "" {
		renderedParts = append(renderedParts, hyperlinkOrText(GitHubRepoURL(agent.Repo), agent.Repo))
	}
	if agent.Workflow != "" {
		renderedParts = append(renderedParts, hyperlinkOrText(GitHubFileURL(agent.Repo, agent.Workflow), agent.Workflow))
	}
	if agent.Job != "" {
		renderedParts = append(renderedParts, agent.Job)
	}
	return prefix + strings.Join(renderedParts, " → ")
}

func (m Model) renderAgentConnectedBack(agent *AgentState) string {
	if agent == nil || agent.StartTime.IsZero() {
		return "unknown"
	}
	return agent.StartTime.Local().Format("15:04:05")
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
