// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

type OmniboxResultKind string

const (
	OmniboxResultOrg              OmniboxResultKind = "org"
	OmniboxResultRepo             OmniboxResultKind = "repo"
	OmniboxResultDispatchWorkflow OmniboxResultKind = "dispatch_workflow"
	OmniboxResultWorkflow         OmniboxResultKind = "workflow"
	OmniboxResultRunner           OmniboxResultKind = "runner"
	OmniboxResultVuln             OmniboxResultKind = "vuln"
	OmniboxResultLoot             OmniboxResultKind = "loot"
)

var omniboxEmptyOrder = []OmniboxResultKind{
	OmniboxResultOrg,
	OmniboxResultRepo,
	OmniboxResultDispatchWorkflow,
	OmniboxResultWorkflow,
	OmniboxResultRunner,
	OmniboxResultVuln,
	OmniboxResultLoot,
}

type OmniboxResult struct {
	Kind       OmniboxResultKind
	Label      string
	Detail     string
	SearchText string
	NodeID     string
	TargetSpec string
	VulnID     string
	Order      int
}

type OmniboxState struct {
	input   textinput.Model
	results []OmniboxResult
	cursor  int
}

func newOmniboxState(width int) *OmniboxState {
	input := textinput.New()
	input.Focus()
	input.CharLimit = 200
	if width > 24 {
		input.SetWidth(width - 24)
	} else {
		input.SetWidth(width)
	}
	input.Placeholder = "Search repos, loot, workflows, vulns"
	return &OmniboxState{input: input}
}

func (m *Model) openOmnibox() {
	m.prevView = m.view
	m.prevFocus = m.focus
	m.view = ViewOmnibox
	m.omnibox = newOmniboxState(m.width)
	m.refreshOmniboxResults()
}

func (m *Model) closeOmnibox() {
	m.view = m.prevView
	m.focus = m.prevFocus
	m.omnibox = nil
	m.updateFocus()
}

func (m *Model) refreshOmniboxResults() {
	if m.omnibox == nil {
		return
	}
	m.omnibox.results = m.searchOmnibox(m.omnibox.input.Value())
	if len(m.omnibox.results) == 0 {
		m.omnibox.cursor = 0
		return
	}
	if m.omnibox.cursor >= len(m.omnibox.results) {
		m.omnibox.cursor = len(m.omnibox.results) - 1
	}
	if m.omnibox.cursor < 0 {
		m.omnibox.cursor = 0
	}
}

func (m *Model) searchOmnibox(query string) []OmniboxResult {
	items := m.buildOmniboxIndex()
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return m.defaultOmniboxResults(items)
	}

	type rankedResult struct {
		OmniboxResult
		score int
	}

	tokens := strings.Fields(query)
	ranked := make([]rankedResult, 0, len(items))
	for _, item := range items {
		score, ok := scoreOmniboxResult(item, tokens)
		if ok {
			ranked = append(ranked, rankedResult{OmniboxResult: item, score: score})
		}
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].score > ranked[j].score
	})

	results := make([]OmniboxResult, 0, min(len(ranked), 5))
	for i := 0; i < len(ranked) && i < 5; i++ {
		results = append(results, ranked[i].OmniboxResult)
	}
	return results
}

func (m *Model) defaultOmniboxResults(items []OmniboxResult) []OmniboxResult {
	buckets := make(map[OmniboxResultKind][]OmniboxResult, len(omniboxEmptyOrder))
	for _, item := range items {
		buckets[item.Kind] = append(buckets[item.Kind], item)
	}

	vulnMenuOrder := m.omniboxVulnMenuOrder()
	for _, kind := range omniboxEmptyOrder {
		sortOmniboxBucket(buckets[kind], kind, vulnMenuOrder)
	}

	limit := min(len(items), 5)
	selected := make([]OmniboxResult, 0, limit)
	next := make(map[OmniboxResultKind]int, len(omniboxEmptyOrder))

	for len(selected) < limit {
		added := false
		for _, kind := range omniboxEmptyOrder {
			bucket := buckets[kind]
			idx := next[kind]
			if idx >= len(bucket) {
				continue
			}
			selected = append(selected, bucket[idx])
			next[kind] = idx + 1
			added = true
			if len(selected) == limit {
				break
			}
		}
		if !added {
			break
		}
	}

	results := make([]OmniboxResult, 0, limit)
	for _, kind := range omniboxEmptyOrder {
		for _, item := range selected {
			if item.Kind == kind {
				results = append(results, item)
			}
		}
	}

	return results
}

func (m *Model) omniboxVulnMenuOrder() map[string]int {
	order := make(map[string]int)
	position := 0
	for _, suggestion := range m.suggestions {
		if suggestion.VulnIndex < 0 || suggestion.VulnIndex >= len(m.vulnerabilities) {
			continue
		}
		vulnID := m.vulnerabilities[suggestion.VulnIndex].ID
		if _, exists := order[vulnID]; exists {
			continue
		}
		order[vulnID] = position
		position++
	}
	return order
}

func sortOmniboxBucket(bucket []OmniboxResult, kind OmniboxResultKind, vulnMenuOrder map[string]int) {
	sort.SliceStable(bucket, func(i, j int) bool {
		if kind == OmniboxResultVuln {
			rankI := len(vulnMenuOrder) + bucket[i].Order
			rankJ := len(vulnMenuOrder) + bucket[j].Order
			if rank, ok := vulnMenuOrder[bucket[i].VulnID]; ok {
				rankI = rank
			}
			if rank, ok := vulnMenuOrder[bucket[j].VulnID]; ok {
				rankJ = rank
			}
			if rankI != rankJ {
				return rankI < rankJ
			}
		}

		labelI := strings.ToLower(bucket[i].Label)
		labelJ := strings.ToLower(bucket[j].Label)
		if labelI != labelJ {
			return labelI < labelJ
		}

		detailI := strings.ToLower(bucket[i].Detail)
		detailJ := strings.ToLower(bucket[j].Detail)
		if detailI != detailJ {
			return detailI < detailJ
		}

		return bucket[i].Order < bucket[j].Order
	})
}

func scoreOmniboxResult(item OmniboxResult, tokens []string) (int, bool) {
	label := strings.ToLower(item.Label)
	detail := strings.ToLower(item.Detail)
	searchText := strings.ToLower(item.SearchText)
	score := 0

	for _, token := range tokens {
		switch {
		case label == token:
			score += 120
		case strings.HasPrefix(label, token):
			score += 90
		case strings.Contains(label, token):
			score += 70
		case strings.HasPrefix(detail, token):
			score += 45
		case strings.Contains(detail, token):
			score += 35
		case strings.Contains(searchText, token):
			score += 20
		default:
			return 0, false
		}
	}

	return score, true
}

func (m *Model) buildOmniboxIndex() []OmniboxResult {
	var items []OmniboxResult
	order := 0

	appendItem := func(item OmniboxResult) {
		item.Order = order
		order++
		items = append(items, item)
	}

	appendTreeNode := func(node *TreeNode) {
		switch node.Type {
		case TreeNodeOrg:
			appendItem(OmniboxResult{
				Kind:       OmniboxResultOrg,
				Label:      node.Label,
				Detail:     "organization",
				SearchText: strings.ToLower(node.Label + " organization"),
				NodeID:     node.ID,
				TargetSpec: "org:" + node.Label,
			})
		case TreeNodeRepo:
			repoPath := treeSearchPath(node)
			appendItem(OmniboxResult{
				Kind:       OmniboxResultRepo,
				Label:      repoPath,
				Detail:     repoDetail(node),
				SearchText: strings.ToLower(repoPath + " " + repoDetail(node)),
				NodeID:     node.ID,
				TargetSpec: "repo:" + repoPath,
			})
		case TreeNodeWorkflow:
			repoPath := nearestTreePath(node, TreeNodeRepo)
			kind := OmniboxResultWorkflow
			detail := repoPath
			searchText := node.Label + " " + repoPath
			if workflowNodeDispatchable(node) {
				kind = OmniboxResultDispatchWorkflow
				detailParts := []string{"workflow_dispatch", "x:exploit"}
				if repoPath != "" {
					detailParts = append([]string{repoPath}, detailParts...)
				}
				detail = strings.Join(detailParts, " | ")
				searchText += " dispatch dispatchable workflow_dispatch x exploit"
			}
			appendItem(OmniboxResult{
				Kind:       kind,
				Label:      node.Label,
				Detail:     detail,
				SearchText: strings.ToLower(searchText),
				NodeID:     node.ID,
			})
		case TreeNodeSelfHostedRunner:
			repoPath := nearestTreePath(node, TreeNodeRepo)
			detail := runnerTargetDetail(node)
			appendItem(OmniboxResult{
				Kind:       OmniboxResultRunner,
				Label:      "[SH-RUNNER] " + node.Label,
				Detail:     detail,
				SearchText: strings.ToLower("sh-runner shrunner self-hosted runner " + node.Label + " " + repoPath + " " + detail),
				NodeID:     node.ID,
				TargetSpec: "repo:" + repoPath,
			})
		case TreeNodeVuln:
			appendItem(OmniboxResult{
				Kind:       OmniboxResultVuln,
				Label:      omniboxVulnLabel(node),
				Detail:     vulnDetail(node),
				SearchText: strings.ToLower(omniboxVulnLabel(node) + " " + vulnDetail(node) + " " + node.Label),
				NodeID:     node.ID,
				VulnID:     node.ID,
			})
		}
	}

	if m.treeRoot != nil {
		traverseTree(m.treeRoot, appendTreeNode)
	}

	if m.lootTreeRoot == nil && (len(m.lootStash) > 0 || len(m.sessionLoot) > 0) {
		m.RebuildLootTree()
	}
	if m.lootTreeRoot != nil {
		traverseTree(m.lootTreeRoot, func(node *TreeNode) {
			secret := m.getLootSecret(node)
			if secret == nil {
				return
			}
			detail := lootResultDetail(*secret)
			appendItem(OmniboxResult{
				Kind:       OmniboxResultLoot,
				Label:      secret.Name,
				Detail:     detail,
				SearchText: strings.ToLower(secret.Name + " " + detail + " " + secret.Repository + " " + secret.Workflow + " " + secret.Job),
				NodeID:     node.ID,
			})
		})
	}

	return items
}

func traverseTree(node *TreeNode, fn func(*TreeNode)) {
	if node == nil {
		return
	}
	if node.ID != "root" {
		fn(node)
	}
	for _, child := range node.Children {
		traverseTree(child, fn)
	}
}

func treeSearchPath(node *TreeNode) string {
	var parts []string
	for current := node; current != nil && current.ID != "root"; current = current.Parent {
		if current.Type == TreeNodeOrg || current.Type == TreeNodeRepo {
			parts = append([]string{current.Label}, parts...)
		}
	}
	return strings.Join(parts, "/")
}

func nearestTreePath(node *TreeNode, targetType TreeNodeType) string {
	for current := node; current != nil; current = current.Parent {
		if current.Type == targetType {
			if targetType == TreeNodeRepo {
				return treeSearchPath(current)
			}
			return current.Label
		}
	}
	return ""
}

func repoDetail(node *TreeNode) string {
	detail := "repository"
	if node.State == TreeStateHighValue {
		detail = "private repository"
	}
	return detail
}

func runnerTargetDetail(node *TreeNode) string {
	var parts []string
	if repo := nearestTreePath(node, TreeNodeRepo); repo != "" {
		parts = append(parts, repo)
	}
	if labels := nodeStringSliceProperty(node, "label_set"); len(labels) > 0 {
		parts = append(parts, strings.Join(labels, ", "))
	}
	if workflows := nodeStringSliceProperty(node, "observed_workflow_paths"); len(workflows) > 0 {
		parts = append(parts, strings.Join(workflows, ", "))
	}
	if len(parts) == 0 {
		return "self-hosted runner target"
	}
	return strings.Join(parts, " -> ")
}

func vulnDetail(node *TreeNode) string {
	var parts []string
	if repo := nearestTreePath(node, TreeNodeRepo); repo != "" {
		parts = append(parts, repo)
	}
	if workflow := nearestTreePath(node, TreeNodeWorkflow); workflow != "" {
		parts = append(parts, workflow)
	}
	if job := nearestTreePath(node, TreeNodeJob); job != "" {
		parts = append(parts, job)
	}
	if ctx := nodeStringProperty(node, "context"); ctx != "" {
		parts = append(parts, ctx)
	} else if ruleID := node.RuleID; ruleID != "" {
		parts = append(parts, ruleID)
	}
	return strings.Join(parts, " -> ")
}

func omniboxVulnLabel(node *TreeNode) string {
	if line := nodeIntProperty(node, "line"); line > 0 {
		return fmt.Sprintf("%s · L%d", node.Label, line)
	}
	if ctx := nodeStringProperty(node, "context"); ctx != "" {
		return node.Label + " · " + ctx
	}
	if node.RuleID != "" {
		return node.Label + " · " + node.RuleID
	}
	return node.Label
}

func nodeStringProperty(node *TreeNode, key string) string {
	if node == nil || node.Properties == nil || key == "" {
		return ""
	}
	value, ok := node.Properties[key]
	if !ok {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func nodeIntProperty(node *TreeNode, key string) int {
	if node == nil || node.Properties == nil || key == "" {
		return 0
	}
	value, ok := node.Properties[key]
	if !ok {
		return 0
	}
	switch n := value.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return 0
	}
}

func lootResultDetail(secret CollectedSecret) string {
	var parts []string
	if secret.Repository != "" {
		parts = append(parts, secret.Repository)
	}
	if secret.Workflow != "" {
		parts = append(parts, secret.Workflow)
	}
	if secret.Job != "" {
		parts = append(parts, secret.Job)
	}
	if len(parts) == 0 {
		return "loot"
	}
	return "from " + strings.Join(parts, " -> ")
}

func (m Model) handleOmniboxKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.omnibox == nil {
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc":
		m.closeOmnibox()
		return m, nil
	case "up":
		if m.omnibox.cursor > 0 {
			m.omnibox.cursor--
		}
		return m, nil
	case "down":
		if m.omnibox.cursor < len(m.omnibox.results)-1 {
			m.omnibox.cursor++
		}
		return m, nil
	case "enter":
		return m.applyOmniboxSelection()
	}

	var cmd tea.Cmd
	m.omnibox.input, cmd = m.omnibox.input.Update(msg)
	m.refreshOmniboxResults()
	return m, cmd
}

func (m Model) applyOmniboxSelection() (tea.Model, tea.Cmd) {
	if m.omnibox == nil || len(m.omnibox.results) == 0 {
		m.closeOmnibox()
		return m, nil
	}

	result := m.omnibox.results[m.omnibox.cursor]
	m.closeOmnibox()

	switch result.Kind {
	case OmniboxResultLoot:
		m.focusPane(PaneFocusLoot)
		m.LootTreeSelectByID(result.NodeID)
		return m, nil
	case OmniboxResultOrg, OmniboxResultRepo:
		updated, cmd := m.handleSetCommand("target", result.TargetSpec)
		if next, ok := updated.(Model); ok {
			m = next
		}
		m.focusPane(PaneFocusFindings)
		m.TreeSelectByID(result.NodeID)
		return m, cmd
	case OmniboxResultDispatchWorkflow, OmniboxResultWorkflow, OmniboxResultRunner:
		m.focusPane(PaneFocusFindings)
		m.TreeSelectByID(result.NodeID)
		return m, nil
	case OmniboxResultVuln:
		m.focusOmniboxResultVulnerability(result)
		return m, nil
	default:
		return m, nil
	}
}

func (m *Model) focusOmniboxResultVulnerability(result OmniboxResult) bool {
	if result.VulnID == "" && result.NodeID == "" {
		return false
	}

	found := false
	if result.VulnID != "" {
		for i := range m.vulnerabilities {
			if m.vulnerabilities[i].ID != result.VulnID {
				continue
			}
			m.selectedVuln = i
			found = true
			break
		}
	}

	treeSelected := false
	if result.NodeID != "" {
		treeSelected = m.TreeSelectByID(result.NodeID)
	}
	if !treeSelected && result.VulnID != "" {
		treeSelected = m.TreeSelectByID(result.VulnID)
	}

	if menuIdx := m.menuSuggestionIndexForVuln(result.VulnID); menuIdx >= 0 {
		m.menuCursor = menuIdx
		m.view = ViewFindings
		m.focusPane(PaneFocusMenu)
		return true
	}

	if treeSelected {
		m.view = ViewFindings
		m.focusPane(PaneFocusFindings)
		return true
	}

	return found
}

func (m *Model) focusOmniboxVulnerability(vulnID string) bool {
	return m.focusOmniboxResultVulnerability(OmniboxResult{VulnID: vulnID, NodeID: vulnID})
}

func (m Model) menuSuggestionIndexForVuln(vulnID string) int {
	for i, suggestion := range m.suggestions {
		if suggestion.VulnIndex < 0 || suggestion.VulnIndex >= len(m.vulnerabilities) {
			continue
		}
		if m.vulnerabilities[suggestion.VulnIndex].ID == vulnID {
			return i
		}
	}
	return -1
}

func omniboxKindLabel(kind OmniboxResultKind) string {
	switch kind {
	case OmniboxResultOrg:
		return "ORG"
	case OmniboxResultRepo:
		return "REPO"
	case OmniboxResultDispatchWorkflow:
		return "DISPATCH"
	case OmniboxResultWorkflow:
		return "WORK"
	case OmniboxResultRunner:
		return "SH-RUN"
	case OmniboxResultVuln:
		return "VULN"
	case OmniboxResultLoot:
		return "LOOT"
	default:
		return strings.ToUpper(string(kind))
	}
}

func (m Model) handleOmniboxPaste(msg tea.PasteMsg) (tea.Model, tea.Cmd) {
	if m.omnibox == nil {
		return m, nil
	}
	var cmd tea.Cmd
	m.omnibox.input, cmd = m.omnibox.input.Update(msg)
	m.refreshOmniboxResults()
	return m, cmd
}

func (m *Model) paneShortcut(code rune) bool {
	switch code {
	case tea.KeyF1:
		m.focusPane(PaneFocusFindings)
	case tea.KeyF2:
		m.focusPane(PaneFocusMenu)
	case tea.KeyF3:
		m.focusPane(PaneFocusLoot)
	case tea.KeyF4:
		m.focusPane(PaneFocusActivity)
	case tea.KeyF5:
		m.focusInputPane()
	default:
		return false
	}
	m.flashFocusedPane()
	return true
}

func (m *Model) flashFocusedPane() {
	pane := "findings"
	switch m.paneFocus {
	case PaneFocusMenu:
		pane = "menu"
	case PaneFocusLoot:
		pane = "loot"
	case PaneFocusActivity:
		pane = "activity"
	}
	if m.focus == FocusInput {
		pane = "input"
	}
	m.flashMessage = fmt.Sprintf("Focused %s pane", pane)
	m.flashUntil = time.Now().Add(1500 * time.Millisecond)
}
