// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

func (m *Model) RenderAttackTree(width, height int) string {
	if m.treeRoot == nil || len(m.treeNodes) == 0 {
		return m.renderEmptyTree(width, height)
	}

	menuMap := m.buildMenuNumberMap()
	focused := m.paneFocus == PaneFocusFindings && !m.view.IsModal() && m.focus != FocusInput

	var lines []string
	selectedLines := make(map[int]bool)
	for i, node := range m.treeNodes {
		isSelected := i == m.treeCursor
		menuNum := menuMap[node.ID]
		line := m.renderTreeNode(node, width-2, isSelected && focused, menuNum)
		if isSelected && focused {
			selectedLines[len(lines)] = true
		}
		lines = append(lines, line)

		if isSelected && node.Type == TreeNodeVuln {
			detailLines := m.renderVulnDetails(node, width-2)
			lines = append(lines, detailLines...)
		}
	}

	totalLines := len(lines)

	start := 0
	if len(lines) > height {
		cursorLine := m.findCursorLine(lines)
		if cursorLine >= height-2 {
			start = cursorLine - height + 3
		}
		end := start + height
		if end > len(lines) {
			end = len(lines)
			start = end - height
			if start < 0 {
				start = 0
			}
		}
		lines = lines[start:end]
	}

	if len(lines) > height {
		lines = lines[:height]
	}

	visibleSelected := make(map[int]bool)
	for idx := range selectedLines {
		if idx >= start && idx < start+len(lines) {
			visibleSelected[idx-start] = true
		}
	}

	scroll := ScrollInfo{TotalLines: totalLines, ViewportSize: height, ScrollOffset: start}
	return strings.Join(applyScrollIndicator(lines, height, focused, visibleSelected, scroll), "\n")
}

func (m *Model) buildMenuNumberMap() map[string]int {
	menuMap := make(map[string]int)
	for i, suggestion := range m.suggestions {
		if i >= 5 {
			break
		}
		if suggestion.VulnIndex >= 0 && suggestion.VulnIndex < len(m.vulnerabilities) {
			vuln := m.vulnerabilities[suggestion.VulnIndex]
			for _, node := range m.treeNodes {
				if node.Type != TreeNodeVuln {
					continue
				}
				if m.nodeMatchesVuln(node, vuln) {
					menuMap[node.ID] = i + 1
					break
				}
			}
		}
	}
	return menuMap
}

func (m *Model) nodeMatchesVuln(node *TreeNode, vuln Vulnerability) bool {
	repo := m.treeNodeRepo(node)
	path, _ := node.Properties["path"].(string)
	line, _ := node.Properties["line"].(int)
	if line == 0 {
		if lineFloat, ok := node.Properties["line"].(float64); ok {
			line = int(lineFloat)
		}
	}
	ruleID, _ := node.Properties["rule_id"].(string)
	if ruleID == "" {
		ruleID = node.RuleID
	}
	job := nodeStringProperty(node, "job")
	context := nodeStringProperty(node, "context")
	expression := nodeStringProperty(node, "expression")

	if repo != "" && vuln.Repository != repo {
		return false
	}
	if path != "" && vuln.Workflow != path {
		return false
	}
	if line > 0 && vuln.Line != line {
		return false
	}
	if ruleID != "" && vuln.RuleID != ruleID {
		return false
	}
	if job != "" && vuln.Job != "" && vuln.Job != job {
		return false
	}
	if context != "" && vuln.Context != "" && vuln.Context != context {
		return false
	}
	if expression != "" && vuln.Expression != "" && vuln.Expression != expression {
		return false
	}
	return true
}

func (m *Model) vulnerabilityIndexForNode(node *TreeNode) int {
	if node == nil || node.Type != TreeNodeVuln {
		return -1
	}
	for i := range m.vulnerabilities {
		if m.vulnerabilities[i].ID == node.ID || m.nodeMatchesVuln(node, m.vulnerabilities[i]) {
			return i
		}
	}
	return -1
}

func (m *Model) findCursorLine(lines []string) int {
	lineIdx := 0
	for i := 0; i < m.treeCursor && i < len(m.treeNodes); i++ {
		lineIdx++
		node := m.treeNodes[i]
		if i == m.treeCursor && node.Type == TreeNodeVuln {
			lineIdx += 3
		}
	}
	return lineIdx
}

func (m *Model) renderTreeNode(node *TreeNode, width int, selected bool, menuNum int) string {
	indent := strings.Repeat("  ", node.Depth)

	var expandIcon string
	if node.HasChildren() {
		if node.Expanded {
			expandIcon = "▼ "
		} else {
			expandIcon = "▶ "
		}
	} else {
		expandIcon = "  "
	}

	stateIcon := node.State.Icon() + " "

	menuTag := ""
	if menuNum > 0 {
		menuTag = fmt.Sprintf("[%d] ", menuNum)
	}

	label := node.Label
	typeTag := " [" + node.Type.String() + "]"

	if node.Type == TreeNodeRepo && node.State == TreeStateHighValue {
		label = "🔒 " + label
		typeTag = " [PRIVATE REPO]"
	}

	// Format vuln labels like the Menu for consistency
	if node.Type == TreeNodeVuln {
		label = m.formatVulnLabel(node)
	}

	childSummary := ""
	if node.Type == TreeNodeJob && !node.Expanded && len(node.Children) > 0 {
		childSummary = collapsedJobSummary(node.Children)
	}

	maxLabelWidth := width - lipgloss.Width(indent) - lipgloss.Width(expandIcon) - lipgloss.Width(stateIcon) - lipgloss.Width(menuTag) - lipgloss.Width(typeTag) - lipgloss.Width(childSummary)
	if maxLabelWidth < 10 {
		maxLabelWidth = 10
	}
	label = truncateVisual(label, maxLabelWidth)
	labelDisplay := m.renderTreeNodeLabel(node, label)

	prefix := indent + expandIcon + stateIcon
	contentDisplay := labelDisplay + typeTag

	if selected {
		line := prefix + menuTag + contentDisplay + childSummary
		return treeSelectedStyle.Render(line)
	}

	nodeStyle := m.getTreeNodeStyle(node)
	if menuNum > 0 {
		menuStyle := secondaryColorStyle.Bold(true)
		return nodeStyle.Render(prefix) + menuStyle.Render(menuTag) + nodeStyle.Render(contentDisplay) + mutedColor.Render(childSummary)
	}

	return nodeStyle.Render(prefix+contentDisplay) + mutedColor.Render(childSummary)
}

func (m *Model) renderTreeNodeLabel(node *TreeNode, label string) string {
	return hyperlinkOrText(m.treeNodeURL(node), label)
}

func (m *Model) treeNodeURL(node *TreeNode) string {
	if node == nil {
		return ""
	}
	switch node.Type {
	case TreeNodeOrg:
		return GitHubOrgURL(m.treeNodeOrg(node))
	case TreeNodeRepo:
		return GitHubRepoURL(m.treeNodeRepo(node))
	case TreeNodeWorkflow:
		repo := m.treeNodeRepo(node)
		if repo == "" {
			return ""
		}
		return GitHubFileURL(repo, node.Label)
	case TreeNodeVuln:
		repo := m.treeNodeRepo(node)
		path := nodeStringProperty(node, "path")
		if path == "" {
			path = nearestTreePath(node, TreeNodeWorkflow)
		}
		return GitHubFileLineURL(repo, path, nodeIntProperty(node, "line"))
	default:
		return ""
	}
}

func (m *Model) treeNodeOrg(node *TreeNode) string {
	if node == nil {
		return ""
	}
	if node.Type == TreeNodeOrg {
		return node.Label
	}
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Type == TreeNodeOrg {
			return current.Label
		}
	}
	if org := nodeStringProperty(node, "org"); org != "" {
		return org
	}
	return ""
}

func (m *Model) treeNodeRepo(node *TreeNode) string {
	if node == nil {
		return ""
	}
	for current := node; current != nil; current = current.Parent {
		if current.Type != TreeNodeRepo {
			continue
		}
		if strings.Contains(current.Label, "/") {
			return current.Label
		}
		if org := m.treeNodeOrg(current); org != "" {
			return org + "/" + current.Label
		}
		if idx := strings.Index(current.ID, ":"); idx >= 0 && idx+1 < len(current.ID) {
			return current.ID[idx+1:]
		}
	}
	if repoID := nodeStringProperty(node, "repo_id"); repoID != "" {
		if idx := strings.Index(repoID, ":"); idx >= 0 && idx+1 < len(repoID) {
			return repoID[idx+1:]
		}
	}
	return ""
}

func (m *Model) getTreeNodeStyle(node *TreeNode) lipgloss.Style {
	switch node.Type {
	case TreeNodeOrg:
		return treeOrgStyle
	case TreeNodeRepo:
		if node.State == TreeStateHighValue {
			return treePrivateRepoStyle
		}
		return treeRepoStyle
	case TreeNodeWorkflow:
		return treeWorkflowStyle
	case TreeNodeJob:
		return treeJobStyle
	case TreeNodeSecret:
		if node.State == TreeStateEphemeral {
			return treeEphemeralStyle
		}
		return treeSecretStyle
	case TreeNodeVuln:
		return treeVulnStyle
	case TreeNodeCloud:
		return treeCloudStyle
	case TreeNodeAgent:
		return treeAgentStyle
	case TreeNodeToken:
		return treeEphemeralStyle
	default:
		return lipgloss.NewStyle()
	}
}

func (m *Model) renderVulnDetails(node *TreeNode, width int) []string {
	indent := strings.Repeat("  ", node.Depth+1)
	var lines []string

	vuln := m.vulnerabilityForNode(node)
	if vuln == nil {
		return lines
	}

	detailStyle := mutedColor
	valueStyle := lipgloss.NewStyle().Foreground(fgDimColor)

	var metaParts []string
	if vuln.Line > 0 {
		metaParts = append(metaParts, valueStyle.Render(fmt.Sprintf("L%d", vuln.Line)))
	}
	if vuln.RuleID != "" {
		metaParts = append(metaParts, mutedColor.Render(vuln.RuleID))
	}
	if len(metaParts) > 0 {
		lines = append(lines, detailStyle.Render(indent+"├─ ")+strings.Join(metaParts, " • "))
	}

	if vuln.Trigger != "" {
		triggerStyle := valueStyle
		if vuln.Trigger == "pull_request_target" || vuln.Trigger == "issue_comment" {
			triggerStyle = warningColor
		}
		lines = append(lines, detailStyle.Render(indent+"├─ Trigger: ")+triggerStyle.Render(vuln.Trigger))
	}

	if vuln.Context != "" {
		lines = append(lines, detailStyle.Render(indent+"├─ Context: ")+valueStyle.Render(vuln.Context))
	}

	lotpDisplay := vuln.LOTPTool
	if lotpDisplay == "" {
		lotpDisplay = vuln.LOTPAction
	}
	if lotpDisplay != "" {
		toolLine := lotpDisplay
		if len(vuln.LOTPTargets) > 0 {
			toolLine += " → " + strings.Join(vuln.LOTPTargets, ", ")
		}
		lines = append(lines, detailStyle.Render(indent+"├─ LOTP: ")+valueStyle.Render(toolLine))
	}

	if vuln.Expression != "" {
		expr := vuln.Expression
		maxExprLen := width - len(indent) - 6
		if len(expr) > maxExprLen {
			expr = expr[:maxExprLen-3] + "..."
		}
		lines = append(lines, detailStyle.Render(indent+"└─ ")+warningColor.Render(expr))
	} else if len(lines) > 0 {
		lastIdx := len(lines) - 1
		lines[lastIdx] = strings.Replace(lines[lastIdx], "├─", "└─", 1)
	}

	return lines
}

func (m *Model) formatVulnLabel(node *TreeNode) string {
	ruleID := node.RuleID
	if ruleID == "" {
		if r, ok := node.Properties["rule_id"].(string); ok {
			ruleID = r
		}
	}

	vuln := m.vulnerabilityForNode(node)
	ctx, _ := node.Properties["context"].(string)
	trigger, _ := node.Properties["trigger"].(string)
	if vuln != nil {
		if ctx == "" {
			ctx = vuln.Context
		}
		if trigger == "" {
			trigger = vuln.Trigger
		}
	}

	switch ruleID {
	case "injection":
		label := vulnLabel(ctx, trigger)
		if trigger == "workflow_dispatch" && !m.hasDispatchCredential() {
			label += " (needs pivot)"
		}
		return label
	case "untrusted_checkout_exec":
		label := "Pwn Request"
		if vuln != nil && (vuln.LOTPTool != "" || vuln.LOTPAction != "") {
			t := vuln.LOTPTool
			if t == "" {
				t = vuln.LOTPAction
			}
			label += " (" + t + ")"
		}
		return label
	case "dangerous_action":
		return "Dangerous Action"
	case "default_permissions":
		return "Default Permissions"
	case "known_vulnerability":
		return "Known Vulnerability"
	case "pr_approval_bypass":
		return "PR Approval Bypass"
	case "actions_artifact":
		return "Artifact Poisoning"
	default:
		return formatRuleID(ruleID)
	}
}

func (m *Model) vulnerabilityForNode(node *TreeNode) *Vulnerability {
	index := m.vulnerabilityIndexForNode(node)
	if index >= 0 {
		return &m.vulnerabilities[index]
	}
	return nil
}

func hasActionsWriteToken(secrets []CollectedSecret) bool {
	for _, s := range secrets {
		if secretHasActionsWrite(s) {
			return true
		}
	}
	return false
}

func collapsedJobSummary(children []*TreeNode) string {
	vulns, secrets := 0, 0
	var tokenParts []string
	for _, child := range children {
		switch child.Type {
		case TreeNodeVuln:
			vulns++
		case TreeNodeSecret:
			secrets++
		case TreeNodeToken:
			writeScopes := tokenWriteScopes(child)
			if len(writeScopes) > 0 {
				tokenParts = append(tokenParts, child.Label+" on: "+strings.Join(writeScopes, ", "))
			}
		}
	}
	var parts []string
	if vulns == 1 {
		parts = append(parts, "1 vuln")
	} else if vulns > 1 {
		parts = append(parts, fmt.Sprintf("%d vulns", vulns))
	}
	if secrets == 1 {
		parts = append(parts, "1 secret")
	} else if secrets > 1 {
		parts = append(parts, fmt.Sprintf("%d secrets", secrets))
	}
	parts = append(parts, tokenParts...)
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func tokenWriteScopes(node *TreeNode) []string {
	if node.Properties == nil {
		return nil
	}
	var scopes []string
	switch v := node.Properties["scopes"].(type) {
	case []string:
		scopes = v
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				scopes = append(scopes, s)
			}
		}
	}
	if len(scopes) == 0 {
		return nil
	}
	var writeScopes []string
	for _, s := range scopes {
		if strings.HasSuffix(s, ":write") {
			name := strings.TrimSuffix(s, ":write")
			writeScopes = append(writeScopes, name)
		}
	}
	return writeScopes
}

func (m *Model) renderEmptyTree(width, height int) string {
	lines := []string{
		"",
		mutedColor.Render("  No attack graph data yet."),
		"",
		mutedColor.Render("  To populate the graph:"),
		mutedColor.Render("    • Run 'analyze <org>' to scan for vulnerabilities"),
		mutedColor.Render("    • Deploy an agent to discover secrets"),
		mutedColor.Render("    • Connect to Kitchen for live data"),
	}

	focused := m.paneFocus == PaneFocusFindings && !m.view.IsModal() && m.focus != FocusInput
	return strings.Join(applyFocusIndicatorAndPad(lines, height, focused), "\n")
}
