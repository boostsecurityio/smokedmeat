// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"image"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/ultraviolet/layout"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func (m *Model) renderCallbacksOverlay(background string, height int) string {
	modalWidth := m.width * 82 / 100
	if modalWidth < 72 {
		modalWidth = m.width - 6
	}
	if modalWidth > 108 {
		modalWidth = 108
	}
	modalHeight := height - 4
	if modalHeight > 24 {
		modalHeight = 24
	}
	if modalHeight < 14 {
		modalHeight = 14
	}

	modal := m.buildCallbacksModal(modalWidth, modalHeight)
	return compositeCenter(modal, dimBackground(background), m.width, height)
}

func (m *Model) buildCallbacksModal(width, height int) string {
	if width < 40 {
		width = 40
	}
	if height < 10 {
		height = 10
	}

	frame := lipgloss.NewStyle().
		Width(width-2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(0, 1)

	innerWidth := width - 6
	bodyHeight := height - 4
	if bodyHeight < 6 {
		bodyHeight = 6
	}

	area := image.Rect(0, 0, innerWidth-1, bodyHeight)
	leftArea, rightArea := layout.SplitHorizontal(area, layout.Fixed(max(26, innerWidth/3)))
	leftWidth := max(leftArea.Dx(), 24)
	rightWidth := max(rightArea.Dx(), 24)

	title := modalTitleStyle.Width(innerWidth).Render(padRight(" IMPLANTS", innerWidth))
	leftLines := m.buildCallbackListLines(leftWidth, bodyHeight)
	rightLines := m.buildCallbackDetailLines(rightWidth, bodyHeight)

	content := make([]string, 0, bodyHeight)
	for i := 0; i < bodyHeight; i++ {
		left := ""
		if i < len(leftLines) {
			left = leftLines[i]
		}
		right := ""
		if i < len(rightLines) {
			right = rightLines[i]
		}
		content = append(content, padRight(left, leftWidth)+" "+padRight(right, rightWidth))
	}

	hints := helpKeyStyle.Render("j/k") + helpDescStyle.Render(":select ") +
		helpKeyStyle.Render("Enter") + helpDescStyle.Render(":attach ")
	if callback := m.selectedCallback(); callback != nil {
		if m.callbackIsResidentFoothold(callback) {
			hints += helpKeyStyle.Render("c") + helpDescStyle.Render(":copy handle ") +
				helpKeyStyle.Render("t") + helpDescStyle.Render(":retrigger ")
		} else {
			hints += helpKeyStyle.Render("e") + helpDescStyle.Render(":express ") +
				helpKeyStyle.Render("d") + helpDescStyle.Render(":default dwell ") +
				helpKeyStyle.Render("n") + helpDescStyle.Render(":next dwell ") +
				helpKeyStyle.Render("x") + helpDescStyle.Render(":clear ")
		}
	}
	hints += helpKeyStyle.Render("r") + helpDescStyle.Render(":revoke ") +
		helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close")

	lines := []string{title, ""}
	lines = append(lines, content...)
	lines = append(lines, "", padRight(hints, innerWidth))
	for len(lines) < height-2 {
		lines = append(lines, strings.Repeat(" ", innerWidth))
	}

	return frame.Render(strings.Join(lines, "\n"))
}

func (m *Model) buildCallbackListLines(width, height int) []string {
	lines := []string{mutedColor.Render(padRight("Persistent implants", width))}
	if len(m.callbacks) == 0 {
		lines = append(lines, padRight("No persistent implants registered.", width))
		for len(lines) < height {
			lines = append(lines, strings.Repeat(" ", width))
		}
		return lines
	}

	for i, callback := range m.callbacks {
		prefix := "  "
		if m.callbackModal != nil && i == m.callbackModal.Cursor {
			prefix = "> "
		}
		label := truncate(callbackListLabel(callback), max(width-2, 8))
		line := prefix + label
		if callback.RevokedAt != nil {
			line = mutedColor.Render(line)
		} else if callback.NextMode != "" {
			line = warningColor.Render(line)
		}
		lines = append(lines, padRight(line, width))
		if len(lines) == height {
			break
		}
	}
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return lines
}

func (m *Model) buildCallbackDetailLines(width, height int) []string {
	callback := m.selectedCallback()
	if callback == nil {
		lines := []string{mutedColor.Render(padRight("No callback selected", width))}
		for len(lines) < height {
			lines = append(lines, strings.Repeat(" ", width))
		}
		return lines
	}

	metadata := callback.Metadata
	repo := metadata["repository"]
	workflow := metadata["workflow"]
	job := metadata["job"]
	state := callback.DefaultMode
	if state == "" {
		state = "express"
	}
	if callback.RevokedAt != nil {
		state = "revoked"
	} else if callback.NextMode != "" {
		state += " -> next " + callback.NextMode
	}

	if m.callbackIsResidentFoothold(callback) {
		lines := []string{
			padRight(lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(truncate(callbackDetailLabel(*callback), width)), width),
			padRight("ID: "+truncate(callback.ID, max(width-4, 8)), width),
			padRight("Repo: "+truncate(orFallback(repo, "unknown"), max(width-6, 8)), width),
			padRight("Workflow: "+truncate(orFallback(workflow, "unknown"), max(width-10, 8)), width),
			padRight("Job: "+truncate(orFallback(job, "unknown"), max(width-5, 8)), width),
		}
		if branch := callbackMetadataValue(callback, runnerTargetMetadataBranchKey); branch != "" {
			lines = append(lines, padRight("Branch: "+truncate(branch, max(width-8, 8)), width))
		}
		if route := callbackMetadataValue(callback, runnerTargetMetadataRouteKey); route != "" {
			lines = append(lines, padRight("Route: "+truncate(route, max(width-7, 8)), width))
		}
		watchStatus := callbackMetadataValue(callback, "resident_watch_status")
		if watchStatus == "" {
			watchStatus = "watching"
		}
		watchLine := "Watch: " + watchStatus
		if confidence := callbackMetadataValue(callback, "resident_confidence"); confidence != "" {
			watchLine += " " + confidence
		}
		lines = append(lines, padRight(truncate(watchLine, width), width))
		if lastJob := residentCallbackLastJob(callback); lastJob != "" {
			lines = append(lines, padRight("Last job: "+truncate(lastJob, max(width-10, 8)), width))
		}
		if lastHarvest := callbackMetadataValue(callback, "resident_last_harvested_at"); lastHarvest != "" {
			lines = append(lines, padRight("Last harvest: "+truncate(lastHarvest, max(width-14, 8)), width))
		}
		status := "offline"
		if callback.RevokedAt != nil {
			status = "revoked"
		} else if m.liveSessionForCallback(callback) != nil {
			status = "online"
		}
		retryPolicy := callbackMetadataValue(callback, runnerTargetMetadataRetryKey)
		if retryPolicy == "" {
			retryPolicy = "infinite"
		}
		lastSeen := "never"
		if live := m.liveSessionForCallback(callback); live != nil {
			lastSeen = live.LastSeen.Format(time.RFC3339)
		} else if callback.CallbackAt != nil {
			lastSeen = callback.CallbackAt.Format(time.RFC3339)
		}
		lines = append(lines,
			padRight("Foothold: resident runner", width),
			padRight("Status: "+status, width),
			padRight("Retry: "+retryPolicy, width),
			padRight("Last seen: "+truncate(lastSeen, max(width-10, 8)), width),
			padRight("Last agent: "+truncate(orFallback(callback.LastAgentID, "none"), max(width-12, 8)), width),
			padRight("Recovery: c copies handle, t copies retrigger recipe", width),
			"",
			padRight(mutedColor.Render("Recent agents"), width),
		)
		for _, link := range m.callbackAgents[callback.ID] {
			status := m.callbackAgentStatus(link.AgentID)
			line := fmt.Sprintf("%s  %s  %s", truncate(link.AgentID, 12), status, link.Mode)
			if link.Hostname != "" {
				line += "  " + truncate(link.Hostname, 16)
			}
			lines = append(lines, padRight(truncate(line, width), width))
			if len(lines) == height {
				break
			}
		}
		for len(lines) < height {
			lines = append(lines, strings.Repeat(" ", width))
		}
		return lines
	}

	lines := []string{
		padRight(lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(truncate(callbackDetailLabel(*callback), width)), width),
		padRight("ID: "+truncate(callback.ID, max(width-4, 8)), width),
		padRight("Repo: "+truncate(orFallback(repo, "unknown"), max(width-6, 8)), width),
		padRight("Workflow: "+truncate(orFallback(workflow, "unknown"), max(width-10, 8)), width),
		padRight("Job: "+truncate(orFallback(job, "unknown"), max(width-5, 8)), width),
		padRight("State: "+state, width),
		padRight("Dwell: "+orFallback(callback.DwellTime, "not configured"), width),
		padRight(fmt.Sprintf("Hits: %d", callback.CallbackCount), width),
		padRight("Last agent: "+truncate(orFallback(callback.LastAgentID, "none"), max(width-12, 8)), width),
		"",
		padRight(mutedColor.Render("Recent agents"), width),
	}

	for _, link := range m.callbackAgents[callback.ID] {
		status := m.callbackAgentStatus(link.AgentID)
		line := fmt.Sprintf("%s  %s  %s", truncate(link.AgentID, 12), status, link.Mode)
		if link.SecretHits > 0 {
			line += fmt.Sprintf("  %d secrets", link.SecretHits)
		}
		if link.Hostname != "" {
			line += "  " + truncate(link.Hostname, 16)
		}
		lines = append(lines, padRight(truncate(line, width), width))
		if len(lines) == height {
			break
		}
	}

	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", width))
	}
	return lines
}

func residentCallbackLastJob(callback *counter.CallbackPayload) string {
	parts := []string{
		callbackMetadataValue(callback, "resident_last_repository"),
		callbackMetadataValue(callback, "resident_last_workflow"),
		callbackMetadataValue(callback, "resident_last_job"),
	}
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	if len(filtered) == 0 {
		return ""
	}
	if runID := callbackMetadataValue(callback, "resident_last_run_id"); runID != "" {
		filtered = append(filtered, "#"+runID)
	}
	return strings.Join(filtered, " ")
}

func callbackListLabel(callback counter.CallbackPayload) string {
	if label := callback.Metadata["callback_label"]; label != "" {
		return label
	}
	if workflow := callback.Metadata["workflow"]; workflow != "" {
		return workflow
	}
	return callback.ID
}

func callbackDetailLabel(callback counter.CallbackPayload) string {
	if label := callback.Metadata["callback_label"]; label != "" {
		return label
	}
	if repo := callback.Metadata["repository"]; repo != "" {
		return repo
	}
	return callback.ID
}

func (m Model) callbackAgentStatus(agentID string) string {
	for _, session := range m.sessions {
		if session.AgentID != agentID {
			continue
		}
		if session.IsOnline || time.Since(session.LastSeen) < 2*time.Minute {
			return "active"
		}
		return "stale"
	}
	return "seen"
}

func orFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
