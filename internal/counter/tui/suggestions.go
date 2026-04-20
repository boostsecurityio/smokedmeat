// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func (m *Model) RenderSuggestions(width, height int) string {
	focused := m.paneFocus == PaneFocusMenu && !m.view.IsModal() && m.focus != FocusInput
	var lines []string
	lines = append(lines, " "+panelTitleStyle.Render("The Menu"), "")

	count := len(m.suggestions)
	if count > 5 {
		count = 5
	}
	if m.menuCursor >= count {
		m.menuCursor = count - 1
	}
	if m.menuCursor < 0 {
		m.menuCursor = 0
	}

	if count == 0 {
		lines = append(lines, mutedColor.Render("  No orders ready."), "")
		if m.phase == PhaseSetup || m.phase == PhaseRecon {
			lines = append(lines,
				mutedColor.Render("  Run 'analyze' to"),
				mutedColor.Render("  find entry points."),
			)
		}
	} else {
		type menuItem struct {
			index int
			lines []string
		}
		var items []menuItem
		for i := 0; i < count; i++ {
			numKey := fmt.Sprintf("[%d]", i+1)
			itemLines := m.renderMenuItemLines(numKey, m.suggestions[i], width, focused && i == m.menuCursor)
			items = append(items, menuItem{index: i, lines: itemLines})
		}

		availLines := height - 2 - 1
		startItem := m.menuScrollPos
		if m.menuCursor < startItem {
			startItem = m.menuCursor
		}

		usedLines := 0
		endItem := startItem
		for endItem < len(items) {
			needed := len(items[endItem].lines) + 1
			if usedLines+needed > availLines && endItem > startItem {
				break
			}
			usedLines += needed
			endItem++
		}

		if m.menuCursor >= endItem {
			endItem = m.menuCursor + 1
			usedLines = 0
			for i := endItem - 1; i >= 0; i-- {
				needed := len(items[i].lines) + 1
				if usedLines+needed > availLines && i < endItem-1 {
					startItem = i + 1
					break
				}
				usedLines += needed
				startItem = i
			}
		}
		m.menuScrollPos = startItem

		for i := startItem; i < endItem; i++ {
			lines = append(lines, items[i].lines...)
			lines = append(lines, "")
		}

		totalContentLines := 3
		for _, item := range items {
			totalContentLines += len(item.lines) + 1
		}
		scrollOffsetLines := 0
		for i := 0; i < startItem; i++ {
			scrollOffsetLines += len(items[i].lines) + 1
		}

		if len(lines) > height-1 {
			lines = lines[:height-1]
		}
		for len(lines) < height-1 {
			lines = append(lines, "")
		}
		lines = append(lines, mutedColor.Render("  Press 1-5 to order"))

		scroll := ScrollInfo{TotalLines: totalContentLines, ViewportSize: height, ScrollOffset: scrollOffsetLines}
		return strings.Join(applyScrollIndicator(lines, height, focused, nil, scroll), "\n")
	}

	if len(lines) > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}

	return strings.Join(applyFocusIndicatorAndPad(lines, height, focused), "\n")
}

func (m *Model) renderMenuItemLines(numKey string, suggestion SuggestedAction, width int, selected bool) []string {
	if suggestion.VulnIndex >= 0 && suggestion.VulnIndex < len(m.vulnerabilities) {
		vuln := m.vulnerabilities[suggestion.VulnIndex]
		itemLines := m.renderVulnMenuItem(numKey, vuln, width)
		if selected {
			itemLines[0] = treeSelectedStyle.Render("  " + numKey + " " + m.vulnFirstLineText(vuln))
		}
		return itemLines
	}
	if selected {
		return []string{treeSelectedStyle.Render("  " + numKey + " " + suggestion.Label)}
	}
	lines := []string{secondaryColorStyle.Render("  "+numKey) + " " + suggestion.Label}
	if suggestion.Description != "" {
		lines = append(lines, mutedColor.Render("      "+suggestion.Description))
	}
	return lines
}

func (m *Model) vulnFirstLineText(vuln Vulnerability) string {
	var icon, class string
	switch vuln.RuleID {
	case "injection":
		icon = "💉"
		class = vulnLabel(vuln.Context, vuln.Trigger)
	case "untrusted_checkout_exec":
		icon = "🪝"
		class = "Pwn Request"
		t := vuln.LOTPTool
		if t == "" {
			t = vuln.LOTPAction
		}
		if t != "" {
			class += " (" + t + ")"
		}
	default:
		icon = "⚠"
		class = formatRuleID(vuln.RuleID)
	}
	return icon + " " + class
}

func (m *Model) renderVulnMenuItem(numKey string, vuln Vulnerability, width int) []string {
	var icon, class string
	switch vuln.RuleID {
	case "injection":
		icon = "💉"
		class = vulnLabel(vuln.Context, vuln.Trigger)
	case "untrusted_checkout_exec":
		icon = "🪝"
		class = "Pwn Request"
		t := vuln.LOTPTool
		if t == "" {
			t = vuln.LOTPAction
		}
		if t != "" {
			class += " (" + t + ")"
		}
	default:
		icon = "⚠"
		class = formatRuleID(vuln.RuleID)
	}

	availWidth := width - 8
	repoURL := GitHubRepoURL(vuln.Repository)
	locationURL := GitHubFileLineURL(vuln.Repository, vuln.Workflow, vuln.Line)

	line1 := secondaryColorStyle.Render("  "+numKey) + " " + icon + " " + warningColor.Render(class)

	repoDisplay := truncateVisual(vuln.Repository, availWidth)
	line2 := mutedColor.Render("      ") + hyperlinkOrText(repoURL, repoDisplay)

	locDisplay := formatSmartLocation(vuln.Workflow, vuln.Job, vuln.Line, availWidth)
	line3 := mutedColor.Render("      ") + hyperlinkOrText(locationURL, locDisplay)

	result := []string{line1, line2, line3}
	if len(vuln.LOTPTargets) > 0 {
		result = append(result, renderMenuTargetLines(vuln.Repository, vuln.LOTPTargets, availWidth)...)
	}
	return result
}

func renderMenuTargetLines(repo string, targets []string, availWidth int) []string {
	var lines []string
	for _, target := range targets {
		label := truncateVisual(target, availWidth-8)
		line := mutedColor.Render("      target: ") + hyperlinkOrText(GitHubFileURL(repo, target), label)
		lines = append(lines, line)
	}
	return lines
}

func formatSmartLocation(workflow, job string, line, maxWidth int) string {
	full := fmt.Sprintf("%s→%s:%d", workflow, job, line)
	if lipgloss.Width(full) <= maxWidth {
		return full
	}

	base := filepath.Base(workflow)
	abbrev := fmt.Sprintf("%s→%s:%d", base, job, line)
	if lipgloss.Width(abbrev) <= maxWidth {
		return abbrev
	}

	minimal := fmt.Sprintf("→%s:%d", job, line)
	if lipgloss.Width(minimal) <= maxWidth {
		return minimal
	}

	return truncateVisual(minimal, maxWidth)
}

func (m *Model) GenerateSuggestions() {
	m.suggestions = []SuggestedAction{}

	if m.phase.HasActiveAgent() {
		m.generateAgentActiveSuggestions()
	} else {
		m.generateIdleSuggestions()
	}

	sort.Slice(m.suggestions, func(i, j int) bool {
		return m.suggestions[i].Priority < m.suggestions[j].Priority
	})

	if len(m.suggestions) > 5 {
		m.suggestions = m.suggestions[:5]
	}
}

func (m *Model) generateAgentActiveSuggestions() {
	seenCommands := make(map[string]bool)

	for _, secret := range m.sessionLoot {
		recs := credentialRecommendations(secret, len(m.knownEntities))
		for _, rec := range recs {
			if rec.Command == "" || seenCommands[rec.Command] {
				continue
			}
			seenCommands[rec.Command] = true
			m.suggestions = append(m.suggestions, SuggestedAction{
				Label:       rec.Label,
				Description: rec.Description,
				Command:     rec.Command,
				Priority:    rec.Priority,
			})
		}
	}

	for _, secret := range m.sessionLoot {
		if !secret.IsEphemeral() && secret.Name != "" {
			cmd := "exfil " + secret.Name
			if seenCommands[cmd] {
				continue
			}
			seenCommands[cmd] = true
			m.suggestions = append(m.suggestions, SuggestedAction{
				Label:       "Exfil " + secret.Name,
				Description: "Persistent secret, high value",
				Command:     cmd,
				Priority:    10,
			})
		}
	}

	if m.pantry != nil && m.dwellMode {
		for _, p := range m.detectOIDCProviders() {
			cmd := "pivot " + p.Provider
			if seenCommands[cmd] {
				continue
			}
			seenCommands[cmd] = true
			m.suggestions = append(m.suggestions, SuggestedAction{
				Label:       p.Label,
				Description: p.Description,
				Command:     cmd,
				Priority:    0,
			})
		}
	}

	m.suggestions = append(m.suggestions, SuggestedAction{
		Label:       "Run recon",
		Description: "Discover more secrets and context",
		Command:     "recon",
		Priority:    20,
	})
}

type oidcProvider struct {
	Provider    string
	Label       string
	Description string
}

func (m *Model) detectOIDCProviders() []oidcProvider {
	var providers []oidcProvider

	for _, token := range m.pantry.GetAssetsByType(pantry.AssetToken) {
		tokenType, _ := token.Properties["token_type"].(string)

		switch tokenType {
		case "gcp_oidc":
			projectID, _ := token.Properties["project_id"].(string)
			if projectID == "" {
				projectID = m.runnerVars["CLOUDSDK_CORE_PROJECT"]
			}
			label := "OIDC \u2192 GCP"
			if projectID != "" {
				resolved := m.resolveRefs(projectID)
				if resolved != projectID {
					projectID = resolved
				}
				label += " (" + projectID + ")"
			}
			sa, _ := token.Properties["service_account"].(string)
			desc := "Workload identity federation"
			if sa != "" {
				resolved := m.resolveRefs(sa)
				if resolved != sa {
					sa = resolved
				}
				desc = sa
			}
			providers = append(providers, oidcProvider{Provider: "gcp", Label: label, Description: desc})

		case "aws_oidc":
			roleArn, _ := token.Properties["role_arn"].(string)
			label := "OIDC \u2192 AWS"
			if roleArn != "" {
				resolved := m.resolveRefs(roleArn)
				if resolved != roleArn {
					roleArn = resolved
				}
				if parts := strings.SplitN(roleArn, "/", 2); len(parts) == 2 {
					label += " (" + parts[1] + ")"
				}
			}
			region, _ := token.Properties["region"].(string)
			desc := "GitHub OIDC → AssumeRoleWithWebIdentity"
			if region != "" {
				desc += " [" + m.resolveRefs(region) + "]"
			}
			providers = append(providers, oidcProvider{Provider: "aws", Label: label, Description: desc})

		case "azure_oidc":
			subID, _ := token.Properties["subscription_id"].(string)
			label := "OIDC \u2192 Azure"
			if subID != "" {
				resolved := m.resolveRefs(subID)
				if resolved != subID {
					subID = resolved
				}
				if len(subID) > 12 {
					subID = subID[:12] + "\u2026"
				}
				label += " (" + subID + ")"
			}
			tenantID, _ := token.Properties["tenant_id"].(string)
			desc := "Federated identity credential"
			if tenantID != "" {
				desc = "tenant:" + m.resolveRefs(tenantID)
			}
			providers = append(providers, oidcProvider{Provider: "azure", Label: label, Description: desc})
		}
	}

	return providers
}

func (m *Model) generateIdleSuggestions() {
	if len(m.vulnerabilities) > 0 {
		ranked := m.rankVulnerabilities()
		count := 0
		for _, vulnIdx := range ranked {
			if count >= 5 {
				break
			}
			vuln := m.vulnerabilities[vulnIdx]

			if !vulnerabilitySupportsExploit(&vuln) {
				continue
			}

			label := vuln.Title
			if label == "" {
				label = formatRuleID(vuln.RuleID)
			}
			if label == "" {
				label = "injection"
			}

			description := vuln.Repository
			if vulnNeedsDispatch(vuln) {
				if m.hasDispatchCredential() {
					description += " | dispatch ready"
				} else {
					description += " | needs pivot"
				}
			}

			m.suggestions = append(m.suggestions, SuggestedAction{
				Label:       label,
				Description: description,
				Command:     "use " + vuln.ID,
				Priority:    count + 1,
				VulnIndex:   vulnIdx,
			})
			count++
		}
		if count > 0 {
			return
		}
	}

	// No vulnerabilities - guide through setup
	if m.tokenInfo == nil {
		m.suggestions = append(m.suggestions, SuggestedAction{
			Label:       "Set GitHub token",
			Description: "Required for analysis and operations",
			Command:     "set token",
			Priority:    1,
			VulnIndex:   -1,
		})
		return
	}

	if m.pantry == nil || m.pantry.Size() == 0 {
		m.suggestions = append(m.suggestions, SuggestedAction{
			Label:       "Analyze target",
			Description: "Scan for CI/CD vulnerabilities",
			Command:     "analyze",
			Priority:    1,
			VulnIndex:   -1,
		})
	}

	if (m.pantry == nil || m.pantry.Size() == 0) && len(m.pivotTargets) == 0 {
		return
	}

	// Have pantry but no vulns - suggest report if we have loot
	if len(m.lootStash) > 0 {
		m.suggestions = append(m.suggestions, SuggestedAction{
			Label:       "Generate report",
			Description: "Document attack paths and loot",
			Command:     "report",
			Priority:    5,
			VulnIndex:   -1,
		})
	}

	// Suggest viewing attack graph in browser when pantry has data
	if m.pantry != nil && m.pantry.Size() > 0 && m.connected {
		m.suggestions = append(m.suggestions, SuggestedAction{
			Label:       "View attack graph",
			Description: "Open interactive graph in browser",
			Command:     "graph",
			Priority:    6,
			VulnIndex:   -1,
		})
	}
}

func (m *Model) ExecuteSuggestion(index int) string {
	if index < 0 || index >= len(m.suggestions) {
		return ""
	}
	return m.suggestions[index].Command
}

func (m *Model) MenuCursorUp() {
	if m.menuCursor > 0 {
		m.menuCursor--
	}
}

func (m *Model) MenuCursorDown() {
	if m.menuCursor < len(m.suggestions)-1 {
		m.menuCursor++
	}
}

func (m *Model) rankVulnerabilities() []int {
	type scoredVuln struct {
		index       int
		workflowKey string
		score       int
	}

	workflowScores := m.computeWorkflowLootScores()

	scored := make([]scoredVuln, len(m.vulnerabilities))
	for i, vuln := range m.vulnerabilities {
		workflowKey := vuln.Workflow
		if workflowKey == "" {
			workflowKey = vuln.Repository + "\x00" + vuln.RuleID
		}

		score := workflowScores[vuln.Workflow]

		if score == 0 {
			score = 1
		}
		score += m.vulnerabilitySuggestionScore(vuln)
		if vulnNeedsDispatch(vuln) && !m.hasDispatchCredential() {
			score = -10000
		}

		scored[i] = scoredVuln{
			index:       i,
			workflowKey: workflowKey,
			score:       score,
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		if scored[i].workflowKey != scored[j].workflowKey {
			return scored[i].workflowKey < scored[j].workflowKey
		}
		return vulnerabilitySortKey(m.vulnerabilities[scored[i].index]) < vulnerabilitySortKey(m.vulnerabilities[scored[j].index])
	})

	seen := make(map[string]bool)
	workflowCounts := make(map[string]int)
	var result []int
	for _, sv := range scored {
		vuln := m.vulnerabilities[sv.index]
		dedupKey := vulnSuggestionDedupKey(vuln)
		if seen[dedupKey] {
			continue
		}
		if workflowCounts[sv.workflowKey] >= 2 {
			continue
		}
		seen[dedupKey] = true
		workflowCounts[sv.workflowKey]++
		result = append(result, sv.index)
	}
	return result
}

func (m *Model) vulnerabilitySuggestionScore(vuln Vulnerability) int {
	score := 0

	target := strings.TrimSpace(m.target)
	switch m.targetType {
	case "repo":
		if target != "" && vuln.Repository == target {
			score += 1000
		}
	case "org":
		if target != "" && (vuln.Repository == target || strings.HasPrefix(vuln.Repository, target+"/")) {
			score += 100
		}
	}

	switch {
	case vulnNeedsDispatch(vuln):
		if m.hasDispatchCredential() {
			score += 350
		} else {
			score -= 250
		}
	case vulnHasTrigger(vuln, "issue_comment"):
		score += 140
	case vulnHasTrigger(vuln, "issues"):
		score += 110
	case vulnHasTrigger(vuln, "pull_request_target"):
		score += 90
	case vulnHasTrigger(vuln, "push"):
		score -= 150
	}

	if vuln.Context == "issue_comment" {
		score += 25
	}

	return score
}

func vulnSuggestionDedupKey(vuln Vulnerability) string {
	trigger := strings.TrimSpace(vuln.Trigger)
	if trigger == "" {
		trigger = vuln.Context
	}
	group := strings.TrimSpace(vuln.Job)
	if group == "" {
		group = strings.TrimSpace(vuln.Step)
	}
	if group == "" {
		group = strings.TrimSpace(vuln.Context)
	}
	return strings.Join([]string{vuln.Repository, vuln.Workflow, trigger, group, vuln.RuleID}, "\x00")
}

func vulnNeedsDispatch(vuln Vulnerability) bool {
	if vuln.Context == "workflow_dispatch" || vuln.Context == "workflow_dispatch_input" {
		return true
	}
	return vulnHasTrigger(vuln, "workflow_dispatch")
}

func vulnHasTrigger(vuln Vulnerability, trigger string) bool {
	if strings.TrimSpace(vuln.Context) == trigger {
		return true
	}
	for _, candidate := range strings.Split(vuln.Trigger, ",") {
		if strings.TrimSpace(candidate) == trigger {
			return true
		}
	}
	return false
}

func (m *Model) computeWorkflowLootScores() map[string]int {
	scores := make(map[string]int)

	if m.pantry == nil {
		return scores
	}

	workflows := m.pantry.GetAssetsByType(pantry.AssetWorkflow)
	for _, wf := range workflows {
		path, _ := wf.Properties["path"].(string)
		if path == "" {
			continue
		}

		if !strings.HasPrefix(path, ".github/workflows/") {
			continue
		}

		score := 0

		if hasOIDC, _ := wf.Properties["has_oidc"].(bool); hasOIDC {
			score += 150
		}
		if hasWrite, _ := wf.Properties["has_write"].(bool); hasWrite {
			score += 50
		}
		if selfHosted, _ := wf.Properties["self_hosted"].(bool); selfHosted {
			score += 200
		}

		neighbors, err := m.pantry.GetNeighbors(wf.ID, 1)
		if err != nil {
			scores[path] = score
			continue
		}

		secretCount := 0
		for _, neighbor := range neighbors {
			switch neighbor.Type {
			case pantry.AssetSecret:
				secretCount++
				name := neighbor.Name
				if isHighValueSecret(name) {
					score += 50
				} else {
					score += 10
				}
			case pantry.AssetToken:
				tokenType, _ := neighbor.Properties["token_type"].(string)
				if tokenType == "oidc" {
					score += 100
				}
			}
		}

		if secretCount > 0 {
			score += secretCount * 20
		}

		for _, v := range m.vulnerabilities {
			if v.Workflow == path {
				switch {
				case strings.Contains(v.Trigger, "issue_comment"):
					score += 100
				case strings.Contains(v.Trigger, "issues"):
					score += 80
				case strings.Contains(v.Trigger, "pull_request_target"):
					score += 60
				case v.Trigger == "workflow_dispatch":
					if m.hasDispatchCredential() {
						score += 150
					} else {
						score -= 600
					}
				case v.Trigger == "push":
					score -= 150
				}
				break
			}
		}

		if m.pantry != nil {
			for _, v := range m.vulnerabilities {
				if v.Workflow == path {
					chain, err := m.pantry.TraceKillChain(v.ID)
					if err == nil {
						score += chain.CredentialCount() * 30
						score += chain.CloudPivotCount() * 50
					}
					break
				}
			}
		}

		scores[path] = score
	}

	return scores
}

func isHighValueSecret(name string) bool {
	highValue := []string{
		"AWS_", "GCP_", "AZURE_", "NPM_TOKEN", "PYPI_", "DOCKER_",
		"GITHUB_APP", "SLACK_", "SIGNING_KEY", "DEPLOY_KEY", "SSH_",
		"API_KEY", "SECRET_KEY", "PRIVATE_KEY", "_PAT",
	}
	upper := strings.ToUpper(name)
	for _, prefix := range highValue {
		if strings.Contains(upper, prefix) {
			return true
		}
	}
	return false
}

// formatRuleID converts poutine rule IDs to readable labels
func formatRuleID(ruleID string) string {
	switch ruleID {
	case "injection":
		return "Injection"
	case "untrusted_checkout_exec":
		return "Untrusted Checkout"
	case "dangerous_action":
		return "Dangerous Action"
	case "pr_approval_bypass":
		return "PR Approval Bypass"
	case "artifact_poisoning":
		return "Artifact Poisoning"
	case "debug_enabled":
		return "Debug Enabled"
	case "known_vulnerability":
		return "Known Vuln"
	default:
		if ruleID != "" {
			// Title case the rule ID (simple ASCII-safe version)
			words := strings.Split(ruleID, "_")
			for i, w := range words {
				if w != "" {
					words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
				}
			}
			return strings.Join(words, " ")
		}
		return ""
	}
}
