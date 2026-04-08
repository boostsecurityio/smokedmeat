// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

var orderSubcommands = []string{
	"exec",
	"env",
	"recon",
	"cloud-query",
	"oidc",
	"transfer",
	"upload",
	"download",
}

var orderSubcommandHints = map[string]string{
	"exec":        "exec <cmd>",
	"env":         "env",
	"recon":       "recon",
	"cloud-query": "cloud-query <provider> <query-type>",
	"oidc":        "oidc pivot <provider> [args...] | oidc audience=<value>",
	"transfer":    "transfer <upload|download|list> <path> [base64_data]",
	"upload":      "upload <remote_path> <base64_data>",
	"download":    "download <path>",
}

func orderUsage() string {
	return "order <" + strings.Join(orderSubcommands, "|") + "> [args...]"
}

func (m Model) executeCommand() (result tea.Model, cmd tea.Cmd) {
	commandText := strings.TrimSpace(m.input.Value())
	if commandText == "" {
		return m, nil
	}

	m.history = append(m.history, commandText)
	m.historyIndex = -1

	m.input.SetValue("")
	m.completionHint = ""

	m.AddOutput("info", "> "+maskCommandToken(commandText))
	activityBefore := m.activityLog.Len()
	defer func() {
		rm, ok := result.(Model)
		if !ok {
			return
		}
		rm.maybeExpandActivityLogAfterCommand(activityBefore)
		result = rm
	}()

	parts := strings.Fields(commandText)
	if len(parts) == 0 {
		return m, nil
	}

	switch parts[0] {
	case "help", "?":
		m.prevView = m.view
		m.prevFocus = m.focus
		m.view = ViewHelp
		return m, nil
	case "implants", "callbacks":
		return m, m.openCallbacksModal()
	case "sessions", "ls":
		m.showSessions()
	case "select":
		if len(parts) > 1 {
			m.selectSession(parts[1])
		} else {
			m.AddOutput("error", "Usage: select <agent_id>")
		}
	case "status":
		m.showStatus()
	case "clear":
		m.output = []OutputLine{}
		if m.activityLog != nil {
			m.activityLog.Clear()
		}
	case "license":
		m.prevView = m.view
		m.prevFocus = m.focus
		m.view = ViewLicense
		return m, nil
	case "exit", "quit":
		m.cleanupCloudSession()
		m.cleanupSSHSession()
		m.quitting = true
		return m, tea.Quit

	case "set":
		if len(parts) < 2 {
			m.AddOutput("error", "Usage: set <token|target|kitchen|activity-log> [value]")
			return m, nil
		}
		if parts[1] == "token" {
			return m.handleTokenCommand(parts[2:])
		}
		if len(parts) < 3 {
			m.showSetUsage(parts[1])
			return m, nil
		}
		return m.handleSetCommand(parts[1], strings.Join(parts[2:], " "))

	case "payload":
		ctxName := ""
		if len(parts) > 1 {
			ctxName = parts[1]
		}
		return m.handlePayloadCommand(ctxName)

	case "order":
		if len(parts) < 2 {
			m.AddOutput("error", "Usage: "+orderUsage())
			m.AddOutput("info", "Examples: order exec whoami | order env | order recon")
			if m.SelectedSession() == nil {
				m.AddOutput("error", "No session selected")
				m.AddOutput("info", "Use 'sessions' then 'select <agent_id>' before sending agent orders")
			}
			return m, nil
		}
		if m.SelectedSession() == nil {
			m.AddOutput("error", "No session selected")
			m.AddOutput("info", "Use 'sessions' then 'select <agent_id>' before sending agent orders")
			return m, nil
		}
		if !m.connected {
			m.AddOutput("error", "Not connected to Kitchen")
			return m, nil
		}
		m.AddOutput("info", "Sending order to "+m.SelectedSession().AgentID+"...")
		return m, m.sendOrder(parts[1], parts[2:])

	case "exploit":
		target := strings.TrimSpace(strings.TrimPrefix(commandText, parts[0]))
		cmd, err := m.openSelectedVulnerabilityWizard(target)
		if err != nil {
			m.AddOutput("error", err.Error())
			var analyzeOnlyErr analyzeOnlyFindingError
			if !errors.As(err, &analyzeOnlyErr) {
				m.AddOutput("info", "Usage: exploit [vuln-id or query]")
			}
			return m, nil
		}
		return m, cmd

	case "analyze", "scan":
		if len(parts) > 1 && parts[1] == "pivots" {
			return m.handleAnalyzePivotsCommand()
		}
		return m.handleAnalyzeCommand()

	case "deep-analyze":
		return m.handleDeepAnalyzeCommand()

	case "purge":
		return m.handlePurgeCommand(parts[1:])

	case "vulns":
		m.showVulnerabilities()

	case "menu":
		m.showLightRyeMenu()

	case "graph":
		m.handleGraphCommand()

	case "cloud":
		return m.executeCloudCommand(parts[1:])

	case "ssh":
		return m.executeSSHCommand(parts[1:])

	case "pivot":
		if len(parts) < 2 {
			m.AddOutput("error", "Usage: pivot <github|app|ssh|aws|gcp|azure> [target]")
			m.AddOutput("info", "  pivot github              - List accessible repos")
			m.AddOutput("info", "  pivot github org          - List repos in org")
			m.AddOutput("info", "  pivot github org/repo     - Find dispatchable workflows")
			m.AddOutput("info", "  pivot app [app_id]        - Exchange PEM for installation token")
			m.AddOutput("info", "  pivot ssh                 - Confirm SSH access for the current target")
			m.AddOutput("info", "  pivot ssh org:<owner>     - Confirm SSH access across known repos in an org")
			m.AddOutput("info", "  pivot ssh repo:<owner/repo> - Confirm SSH access for one repo")
			m.AddOutput("info", "  pivot aws|gcp|azure       - OIDC pivot (requires agent)")
			return m, nil
		}

		var pivotType PivotType
		provider := parts[1]
		switch provider {
		case "github":
			pivotType = PivotTypeGitHubToken
		case "app":
			pivotType = PivotTypeGitHubApp
		case "ssh":
			pivotType = PivotTypeSSHKey
		case "aws", "gcp", "azure":
			pivotType = PivotTypeCloudOIDC
		default:
			m.AddOutput("error", "Unknown pivot target: "+provider)
			m.AddOutput("info", "Try: pivot github | pivot app | pivot ssh | pivot aws | pivot gcp | pivot azure")
			return m, nil
		}

		if pivotType == PivotTypeCloudOIDC {
			if !m.dwellMode || (!m.jobDeadline.IsZero() && time.Now().After(m.jobDeadline)) {
				m.AddOutput("warning", "Agent session expired — cloud pivot requires Dwell mode")
				m.AddOutput("info", "Re-deploy with dwell: press 'd' in Step 3/3 of the wizard")
				return m, nil
			}
		}

		target := strings.TrimSpace(strings.Join(parts[2:], " "))

		if pivotType == PivotTypeCloudOIDC {
			m.AddOutput("info", fmt.Sprintf("Initiating %s pivot...", provider))
			return m, m.executePivot(pivotType, provider)
		}
		switch pivotType {
		case PivotTypeGitHubToken:
			if secret := m.selectedLootPivotToken(); secret != nil {
				m.preparePivotToken(*secret)
				m.AddOutput("info", fmt.Sprintf("Using Loot token %s", secret.Name))
				m.AddOutput("info", "Initiating github pivot...")
				return m, m.executePivotWithSecret(*secret, target)
			}
			m.AddOutput("info", "Initiating github pivot...")
			return m, m.executePivot(pivotType, target)
		case PivotTypeGitHubApp:
			keySecret, appID, err := m.resolveGitHubAppPivot(target)
			if err != nil {
				m.AddOutput("error", fmt.Sprintf("Pivot failed: %v", err))
				return m, nil
			}
			m.AddOutput("info", fmt.Sprintf("Using GitHub App key %s (App ID %s)", keySecret.Name, appID))
			m.AddOutput("info", "Initiating app pivot...")
			return m, m.executePivot(pivotType, appID)
		case PivotTypeSSHKey:
			secret, err := m.resolveLootDrivenSecret("SSH private keys", func(secret CollectedSecret) bool {
				return secret.CanUseAsSSHKey()
			})
			if err != nil {
				m.AddOutput("error", fmt.Sprintf("Pivot failed: %v", err))
				return m, nil
			}
			return m.startSSHPivot(secret, target)
		default:
			m.AddOutput("info", fmt.Sprintf("Initiating %s pivot...", provider))
			return m, m.executePivot(pivotType, target)
		}

	case "use":
		if len(parts) < 2 {
			m.AddOutput("error", "Usage: use <vuln-id>")
			return m, nil
		}
		m.selectVulnerability(parts[1])

	default:
		if suggestion, ok := suggestLocalCommand(parts[0]); ok {
			m.AddOutput("error", "Unknown command: "+parts[0])
			m.AddOutput("info", "Did you mean: "+suggestion)
			return m, nil
		}
		m.AddOutput("error", "Unknown command: "+parts[0])
		if m.SelectedSession() != nil {
			m.AddOutput("info", "Use 'order exec <cmd>' for agent shell commands, or 'help' for local commands")
		} else {
			m.AddOutput("info", "Type 'help' for local commands")
		}
	}

	return m, nil
}

func (m *Model) showSetUsage(key string) {
	switch key {
	case "target":
		m.AddOutput("error", "Usage: set target <org:owner|repo:owner/repo>")
		m.AddOutput("info", "Examples: set target org:acme | set target repo:acme/api")
	case "kitchen":
		m.AddOutput("error", "Usage: set kitchen <http://host:port>")
	case "activity-log", "activity":
		m.AddOutput("error", "Usage: set activity-log autoexpand on|off")
	default:
		m.AddOutput("error", "Usage: set <token|target|kitchen|activity-log> <value>")
	}
}

func suggestLocalCommand(input string) (string, bool) {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return "", false
	}

	best := ""
	bestDistance := 0
	for _, candidate := range localCommandNames {
		if candidate == input {
			return "", false
		}
		distance := damerauLevenshteinDistance(input, candidate)
		if distance > maxCommandSuggestionDistance(candidate) {
			continue
		}
		if best == "" || distance < bestDistance || (distance == bestDistance && candidate < best) {
			best = candidate
			bestDistance = distance
		}
	}

	if best == "" {
		return "", false
	}
	return best, true
}

func maxCommandSuggestionDistance(command string) int {
	if len(command) <= 5 {
		return 1
	}
	return 2
}

func damerauLevenshteinDistance(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return len(b)
	}
	if b == "" {
		return len(a)
	}

	prevPrev := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)

	for j := range len(b) + 1 {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}

			deletion := prev[j] + 1
			insertion := curr[j-1] + 1
			substitution := prev[j-1] + cost

			curr[j] = minInt(deletion, insertion, substitution)

			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				curr[j] = minInt(curr[j], prevPrev[j-2]+1)
			}
		}
		copy(prevPrev, prev)
		copy(prev, curr)
	}

	return prev[len(b)]
}

func minInt(values ...int) int {
	best := values[0]
	for _, value := range values[1:] {
		if value < best {
			best = value
		}
	}
	return best
}

var localCommandNames = []string{
	"analyze",
	"callbacks",
	"clear",
	"cloud",
	"deep-analyze",
	"exit",
	"exploit",
	"graph",
	"help",
	"implants",
	"license",
	"ls",
	"menu",
	"order",
	"payload",
	"pivot",
	"purge",
	"quit",
	"scan",
	"select",
	"sessions",
	"set",
	"ssh",
	"status",
	"use",
	"vulns",
}

func (m *Model) showStatus() {
	if m.tokenInfo != nil {
		m.activityLog.Add(IconSuccess, fmt.Sprintf("Token: %s (%s)", m.tokenInfo.MaskedValue(), m.tokenInfo.Type.ShortType()))
	} else {
		m.activityLog.Add(IconWarning, "Token: not set (use 'set token')")
	}

	if target := m.currentTargetSpec(); target != "" {
		m.activityLog.Add(IconSuccess, "Target: "+target)
	} else {
		m.activityLog.Add(IconWarning, "Target: not set (use 'set target')")
	}

	if m.connected {
		m.activityLog.Add(IconSuccess, "Kitchen: connected")
	} else {
		m.activityLog.Add(IconWarning, "Kitchen: disconnected")
	}
}

func (m *Model) showSessions() {
	if len(m.sessions) == 0 {
		m.activityLog.Add(IconWarning, "No sessions connected")
		return
	}

	for _, s := range m.sessions {
		icon := IconAgent
		if !s.IsOnline {
			icon = IconWarning
		}
		m.activityLog.Add(icon, fmt.Sprintf("%s (%s/%s)", s.AgentID[:8], s.OS, s.Arch))
	}
}

func (m *Model) selectSession(agentID string) {
	for i, s := range m.sessions {
		if s.AgentID == agentID || strings.HasPrefix(s.AgentID, agentID) {
			m.selectedIndex = i
			m.AddOutput("success", "Selected session: "+s.AgentID)
			return
		}
	}
	m.AddOutput("error", "Session not found: "+agentID)
}
