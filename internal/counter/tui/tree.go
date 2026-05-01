// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"sort"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type TreeNodeType int

const (
	TreeNodeOrg TreeNodeType = iota
	TreeNodeRepo
	TreeNodeWorkflow
	TreeNodeSelfHostedRunner
	TreeNodeJob
	TreeNodeSecret
	TreeNodeVuln
	TreeNodeCloud
	TreeNodeAgent
	TreeNodeToken
)

func (t TreeNodeType) String() string {
	switch t {
	case TreeNodeOrg:
		return "ORG"
	case TreeNodeRepo:
		return "REPO"
	case TreeNodeWorkflow:
		return "WORKFLOW"
	case TreeNodeSelfHostedRunner:
		return "SH-RUNNER"
	case TreeNodeJob:
		return "JOB"
	case TreeNodeSecret:
		return "SECRET"
	case TreeNodeVuln:
		return "VULN"
	case TreeNodeCloud:
		return "CLOUD"
	case TreeNodeAgent:
		return "AGENT"
	case TreeNodeToken:
		return "TOKEN"
	default:
		return "UNKNOWN"
	}
}

type TreeNodeState int

const (
	TreeStateNew TreeNodeState = iota
	TreeStateReachable
	TreeStateActive
	TreeStateAchieved
	TreeStateDeadEnd
	TreeStateHighValue
	TreeStateEphemeral
	TreeStateEntry
)

func (s TreeNodeState) Icon() string {
	switch s {
	case TreeStateEntry:
		return "◉"
	case TreeStateActive:
		return "●"
	case TreeStateAchieved:
		return "★"
	case TreeStateEphemeral:
		return "⏱"
	case TreeStateReachable:
		return "◌"
	case TreeStateDeadEnd:
		return "✗"
	case TreeStateHighValue:
		return "★"
	default:
		return "○"
	}
}

type TreeNode struct {
	ID         string
	Label      string
	Type       TreeNodeType
	State      TreeNodeState
	Children   []*TreeNode
	Parent     *TreeNode
	Expanded   bool
	Depth      int
	Properties map[string]interface{}
	RuleID     string
}

func (n *TreeNode) Toggle() {
	n.Expanded = !n.Expanded
}

func (n *TreeNode) IsLeaf() bool {
	return len(n.Children) == 0
}

func (n *TreeNode) HasChildren() bool {
	return len(n.Children) > 0
}

func BuildTreeFromPantry(p *pantry.Pantry) *TreeNode {
	if p == nil || p.Size() == 0 {
		return nil
	}

	root := &TreeNode{
		ID:       "root",
		Label:    "Attack Graph",
		Type:     TreeNodeOrg,
		State:    TreeStateNew,
		Expanded: true,
		Depth:    -1,
	}

	orgs := p.GetAssetsByType(pantry.AssetOrganization)
	repos := p.GetAssetsByType(pantry.AssetRepository)
	workflows := p.GetAssetsByType(pantry.AssetWorkflow)
	runnerTargets := p.GetAssetsByType(pantry.AssetSelfHostedRunner)
	jobs := p.GetAssetsByType(pantry.AssetJob)
	secrets := p.GetAssetsByType(pantry.AssetSecret)
	vulns := p.GetAssetsByType(pantry.AssetVulnerability)
	agents := p.GetAssetsByType(pantry.AssetAgent)
	tokens := p.GetAssetsByType(pantry.AssetToken)
	clouds := p.GetAssetsByType(pantry.AssetCloud)

	edges := p.AllRelationships()

	childMap := make(map[string][]string)
	for _, e := range edges {
		childMap[e.From] = append(childMap[e.From], e.To)
	}

	// Build org nodes from actual Organization assets
	orgNodes := make(map[string]*TreeNode)
	for _, org := range orgs {
		orgNode := &TreeNode{
			ID:       org.ID,
			Label:    org.Name,
			Type:     TreeNodeOrg,
			State:    TreeStateNew,
			Expanded: true,
			Depth:    0,
			Parent:   root,
		}
		orgNodes[org.ID] = orgNode
		root.Children = append(root.Children, orgNode)
	}

	// Build repo nodes and link to org via relationships
	repoNodes := make(map[string]*TreeNode)
	for _, repo := range repos {
		node := assetToTreeNode(repo, 1)
		node.Expanded = true
		repoNodes[repo.ID] = node

		// Find parent org via relationships
		var parentOrg *TreeNode
		for orgID, children := range childMap {
			for _, childID := range children {
				if childID == repo.ID {
					if org, ok := orgNodes[orgID]; ok {
						parentOrg = org
						break
					}
				}
			}
			if parentOrg != nil {
				break
			}
		}

		if parentOrg != nil {
			node.Parent = parentOrg
			parentOrg.Children = append(parentOrg.Children, node)
		} else {
			node.Parent = root
			node.Depth = 0
			root.Children = append(root.Children, node)
		}
	}

	workflowNodes := make(map[string]*TreeNode)
	for _, wf := range workflows {
		path, _ := wf.GetProperty("path")
		pathStr, _ := path.(string)
		if pathStr != "" && !strings.HasPrefix(pathStr, ".github/workflows/") {
			continue
		}

		node := assetToTreeNode(wf, 2)
		node.Expanded = true
		workflowNodes[wf.ID] = node

		parentID, _ := wf.GetProperty("repo_id")
		if parentStr, ok := parentID.(string); ok {
			if parent, exists := repoNodes[parentStr]; exists {
				node.Parent = parent
				parent.Children = append(parent.Children, node)
				continue
			}
		}

		for repoID := range repoNodes {
			if strings.HasPrefix(wf.ID, repoID+":workflow:") {
				node.Parent = repoNodes[repoID]
				repoNodes[repoID].Children = append(repoNodes[repoID].Children, node)
				break
			}
		}

		if node.Parent == nil {
			node.Parent = root
			root.Children = append(root.Children, node)
		}
	}

	runnerTargetNodes := make(map[string]*TreeNode)
	for _, target := range runnerTargets {
		node := assetToTreeNode(target, 2)
		node.Expanded = false
		runnerTargetNodes[target.ID] = node

		parentID, _ := target.GetProperty("repo_id")
		if parentStr, ok := parentID.(string); ok {
			if parent, exists := repoNodes[parentStr]; exists {
				node.Parent = parent
				parent.Children = append(parent.Children, node)
				continue
			}
		}

		node.Parent = root
		root.Children = append(root.Children, node)
	}

	jobNodes := make(map[string]*TreeNode)
	for _, job := range jobs {
		node := assetToTreeNode(job, 3)
		node.Type = TreeNodeJob
		node.Expanded = false // Collapsed by default, expand via The Menu
		jobNodes[job.ID] = node

		attached := false
		for wfID, children := range childMap {
			for _, childID := range children {
				if childID == job.ID {
					if wfNode, exists := workflowNodes[wfID]; exists {
						node.Parent = wfNode
						wfNode.Children = append(wfNode.Children, node)
						attached = true
						break
					}
				}
			}
			if attached {
				break
			}
		}

		if !attached {
			node.Parent = root
			root.Children = append(root.Children, node)
		}
	}

	for _, secret := range secrets {
		node := assetToTreeNode(secret, 4)
		if secret.Name == "GITHUB_TOKEN" || secret.Name == "ACTIONS_RUNTIME_TOKEN" {
			node.State = TreeStateEphemeral
		}

		attached := false
		for parentID, children := range childMap {
			for _, childID := range children {
				if childID == secret.ID {
					if jobNode, exists := jobNodes[parentID]; exists {
						node.Parent = jobNode
						jobNode.Children = append(jobNode.Children, node)
						attached = true
						break
					}
					if wfNode, exists := workflowNodes[parentID]; exists {
						node.Parent = wfNode
						wfNode.Children = append(wfNode.Children, node)
						attached = true
						break
					}
					if repoNode, exists := repoNodes[parentID]; exists {
						node.Parent = repoNode
						repoNode.Children = append(repoNode.Children, node)
						attached = true
						break
					}
				}
			}
			if attached {
				break
			}
		}

		if !attached {
			node.Parent = root
			root.Children = append(root.Children, node)
		}
	}

	for _, vuln := range vulns {
		if pantry.IsSelfHostedRunnerAnalyzeOnlyRule(vuln.RuleID) {
			continue
		}
		node := assetToTreeNode(vuln, 4)

		attached := false
		for parentID, children := range childMap {
			for _, childID := range children {
				if childID == vuln.ID {
					if jobNode, exists := jobNodes[parentID]; exists {
						node.Parent = jobNode
						jobNode.Children = append(jobNode.Children, node)
						attached = true
						break
					}
					if wfNode, exists := workflowNodes[parentID]; exists {
						node.Parent = wfNode
						wfNode.Children = append(wfNode.Children, node)
						attached = true
						break
					}
				}
			}
			if attached {
				break
			}
		}

		if !attached {
			for repoID, children := range childMap {
				for _, childID := range children {
					if childID == vuln.ID {
						if repoNode, exists := repoNodes[repoID]; exists {
							node.Parent = repoNode
							repoNode.Children = append(repoNode.Children, node)
							attached = true
							break
						}
					}
				}
				if attached {
					break
				}
			}
		}

		if !attached {
			node.Parent = root
			root.Children = append(root.Children, node)
		}
	}

	cloudNodes := make(map[string]*TreeNode)
	for _, cloud := range clouds {
		node := assetToTreeNode(cloud, 1)
		cloudNodes[cloud.ID] = node

		parent, attached := findParentNode(cloud.ID, childMap, jobNodes, workflowNodes)
		if attached {
			node.Parent = parent
			node.Depth = parent.Depth + 1
			parent.Children = append(parent.Children, node)
			continue
		}

		node.Parent = root
		root.Children = append(root.Children, node)
	}

	for _, token := range tokens {
		node := assetToTreeNode(token, 4)
		node.State = TreeStateEphemeral

		parent, attached := findParentNode(token.ID, childMap, jobNodes, workflowNodes, cloudNodes)
		if attached {
			node.Parent = parent
			if parent.Type == TreeNodeCloud {
				node.Depth = parent.Depth + 1
			}
			parent.Children = append(parent.Children, node)
			continue
		}

		node.Parent = root
		root.Children = append(root.Children, node)
	}

	for _, agent := range agents {
		node := assetToTreeNode(agent, 0)
		node.State = TreeStateEntry
		node.Parent = root
		root.Children = append(root.Children, node)
	}

	sortChildren(root)

	return root
}

func assetToTreeNode(a pantry.Asset, depth int) *TreeNode {
	node := &TreeNode{
		ID:         a.ID,
		Label:      a.Name,
		Depth:      depth,
		Expanded:   false,
		Children:   []*TreeNode{},
		Properties: a.Properties,
		RuleID:     a.RuleID,
	}

	switch a.Type {
	case pantry.AssetRepository:
		node.Type = TreeNodeRepo
	case pantry.AssetWorkflow:
		node.Type = TreeNodeWorkflow
		if path, ok := a.Properties["path"].(string); ok && path != "" {
			node.Label = path
		}
	case pantry.AssetSelfHostedRunner:
		node.Type = TreeNodeSelfHostedRunner
		if display, ok := a.Properties["label_display"].(string); ok && display != "" {
			node.Label = display
		}
	case pantry.AssetJob:
		node.Type = TreeNodeJob
		if displayName, ok := a.Properties["display_name"].(string); ok && displayName != "" {
			node.Label = a.Name + " (" + displayName + ")"
		}
	case pantry.AssetSecret:
		node.Type = TreeNodeSecret
	case pantry.AssetVulnerability:
		node.Type = TreeNodeVuln
		if title, ok := a.Properties["title"].(string); ok && title != "" {
			node.Label = title
		}
	case pantry.AssetCloud:
		node.Type = TreeNodeCloud
	case pantry.AssetAgent:
		node.Type = TreeNodeAgent
	case pantry.AssetToken:
		node.Type = TreeNodeToken
		if scopes := a.StringSliceProperty("scopes"); len(scopes) > 0 {
			switch a.Name {
			case "oidc":
				node.Label = "OIDC (" + strings.Join(scopes, ",") + ")"
			case "github_token":
				node.Label = "GITHUB_TOKEN (" + strings.Join(scopes, ",") + ")"
			}
		}
	default:
		node.Type = TreeNodeRepo
	}

	switch a.State {
	case pantry.StateNew:
		node.State = TreeStateNew
	case pantry.StateValidated:
		node.State = TreeStateReachable
	case pantry.StateExploited:
		node.State = TreeStateAchieved
	case pantry.StateDeadEnd:
		node.State = TreeStateDeadEnd
	case pantry.StateHighValue:
		node.State = TreeStateHighValue
	default:
		node.State = TreeStateNew
	}

	return node
}

func sortChildren(node *TreeNode) {
	if node == nil || len(node.Children) == 0 {
		return
	}

	sort.Slice(node.Children, func(i, j int) bool {
		ti, tj := node.Children[i].Type, node.Children[j].Type
		// Within jobs: Vulns first, then Secrets (alpha), then Tokens
		if node.Type == TreeNodeJob {
			orderI := jobChildOrder(ti)
			orderJ := jobChildOrder(tj)
			if orderI != orderJ {
				return orderI < orderJ
			}
			if node.Children[i].Label != node.Children[j].Label {
				return node.Children[i].Label < node.Children[j].Label
			}
			return node.Children[i].ID < node.Children[j].ID
		}
		// Default: sort by type, then label
		if ti != tj {
			return ti < tj
		}
		if node.Children[i].Label != node.Children[j].Label {
			return node.Children[i].Label < node.Children[j].Label
		}
		return node.Children[i].ID < node.Children[j].ID
	})

	for _, child := range node.Children {
		sortChildren(child)
	}
}

func jobChildOrder(t TreeNodeType) int {
	switch t {
	case TreeNodeVuln:
		return 0 // Vulns first
	case TreeNodeSecret:
		return 1 // Secrets second (alpha sorted)
	case TreeNodeToken:
		return 2 // Tokens last
	default:
		return 3
	}
}

func FlattenTree(root *TreeNode) []*TreeNode {
	if root == nil {
		return nil
	}

	var result []*TreeNode
	flattenRecursive(root, &result)
	return result
}

func flattenRecursive(node *TreeNode, result *[]*TreeNode) {
	if node.ID != "root" {
		*result = append(*result, node)
	}

	if node.Expanded {
		for _, child := range node.Children {
			flattenRecursive(child, result)
		}
	}
}

func (m *Model) RebuildTree() {
	m.treeRepoCount = treeRepoCount(m.pantry)
	m.treeVisibleRepoCount = m.treeRepoCount
	m.treeFilterFallback = false

	if m.treeFiltered {
		m.treeRoot = m.buildFilteredTree()
	} else {
		m.treeRoot = BuildTreeFromPantry(m.pantry)
	}
	m.applyPrivateRepoOverlay(m.treeRoot)
	m.expandJobsWithMenuVulns()
	m.treeNodes = FlattenTree(m.treeRoot)
	if m.treeCursor >= len(m.treeNodes) {
		m.treeCursor = 0
	}
}

func (m *Model) applyPrivateRepoOverlay(node *TreeNode) {
	if node == nil {
		return
	}
	if node.Type == TreeNodeRepo && node.State != TreeStateHighValue {
		if m.isRepoPrivate(node.ID, node.Properties) {
			node.State = TreeStateHighValue
		}
	}
	for _, child := range node.Children {
		m.applyPrivateRepoOverlay(child)
	}
}

func (m *Model) isRepoPrivate(assetID string, props map[string]interface{}) bool {
	if private, ok := props["private"]; ok {
		if p, isBool := private.(bool); isBool && p {
			return true
		}
	}
	if idx := strings.Index(assetID, ":"); idx >= 0 {
		if entity, ok := m.knownEntities["repo:"+assetID[idx+1:]]; ok && entity.IsPrivate {
			return true
		}
	}
	return false
}

func (m *Model) expandJobsWithMenuVulns() {
	if m.treeRoot == nil {
		return
	}
	if len(m.vulnerabilities) == 0 {
		return
	}
	menuVulns := make([]Vulnerability, 0, 5)
	for i, suggestion := range m.suggestions {
		if i >= 5 {
			break
		}
		if suggestion.VulnIndex >= 0 && suggestion.VulnIndex < len(m.vulnerabilities) {
			menuVulns = append(menuVulns, m.vulnerabilities[suggestion.VulnIndex])
		}
	}
	if len(menuVulns) == 0 {
		return
	}
	m.expandParentsOfMenuVulns(m.treeRoot, menuVulns)
}

func (m *Model) expandParentsOfMenuVulns(node *TreeNode, menuVulns []Vulnerability) bool {
	if node == nil {
		return false
	}
	hasVuln := false
	if node.Type == TreeNodeVuln {
		for _, vuln := range menuVulns {
			if m.nodeMatchesVuln(node, vuln) {
				hasVuln = true
				break
			}
		}
	}
	for _, child := range node.Children {
		if m.expandParentsOfMenuVulns(child, menuVulns) {
			hasVuln = true
		}
	}
	if hasVuln && node.Type == TreeNodeJob {
		node.Expanded = true
	}
	return hasVuln
}

func (m *Model) buildFilteredTree() *TreeNode {
	if m.pantry == nil || m.pantry.Size() == 0 {
		m.treeVisibleRepoCount = 0
		return nil
	}

	filteredPantry := m.pantry.VulnBearingSubgraph()
	if filteredPantry.Size() == 0 {
		m.treeVisibleRepoCount = m.treeRepoCount
		m.treeFilterFallback = true
		return BuildTreeFromPantry(m.pantry)
	}

	m.treeVisibleRepoCount = treeRepoCount(filteredPantry)
	root := BuildTreeFromPantry(filteredPantry)
	if root != nil {
		root.Label = "Relevant Attack Graph"
	}
	return root
}

func treeRepoCount(p *pantry.Pantry) int {
	if p == nil {
		return 0
	}
	return len(p.GetAssetsByType(pantry.AssetRepository))
}

func findParentNode(childID string, childMap map[string][]string, parentGroups ...map[string]*TreeNode) (*TreeNode, bool) {
	for parentID, children := range childMap {
		if !treeChildAttached(children, childID) {
			continue
		}
		for _, group := range parentGroups {
			if parent, exists := group[parentID]; exists {
				return parent, true
			}
		}
	}
	return nil, false
}

func treeChildAttached(children []string, childID string) bool {
	for _, id := range children {
		if id == childID {
			return true
		}
	}
	return false
}

func (m *Model) ReflattenTree() {
	m.treeNodes = FlattenTree(m.treeRoot)
	if m.treeCursor >= len(m.treeNodes) {
		m.treeCursor = len(m.treeNodes) - 1
	}
	if m.treeCursor < 0 {
		m.treeCursor = 0
	}
}

func (m *Model) SelectedTreeNode() *TreeNode {
	if m.treeCursor >= 0 && m.treeCursor < len(m.treeNodes) {
		return m.treeNodes[m.treeCursor]
	}
	return nil
}

func (m *Model) ToggleTreeFilter() {
	m.treeFiltered = !m.treeFiltered
	m.RebuildTree()
}
