// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestCollapsedJobSummary(t *testing.T) {
	tests := []struct {
		name     string
		children []*TreeNode
		want     string
	}{
		{
			"empty children",
			[]*TreeNode{},
			"",
		},
		{
			"single vuln",
			[]*TreeNode{{Type: TreeNodeVuln}},
			" (1 vuln)",
		},
		{
			"multiple vulns",
			[]*TreeNode{{Type: TreeNodeVuln}, {Type: TreeNodeVuln}, {Type: TreeNodeVuln}},
			" (3 vulns)",
		},
		{
			"single secret",
			[]*TreeNode{{Type: TreeNodeSecret}},
			" (1 secret)",
		},
		{
			"multiple secrets",
			[]*TreeNode{{Type: TreeNodeSecret}, {Type: TreeNodeSecret}},
			" (2 secrets)",
		},
		{
			"vuln and secret",
			[]*TreeNode{{Type: TreeNodeVuln}, {Type: TreeNodeSecret}},
			" (1 vuln, 1 secret)",
		},
		{
			"token with write scopes",
			[]*TreeNode{
				{
					Type:  TreeNodeToken,
					Label: "GITHUB_TOKEN",
					Properties: map[string]interface{}{
						"scopes": []string{"contents:write", "actions:write", "metadata:read"},
					},
				},
			},
			" (GITHUB_TOKEN on: contents, actions)",
		},
		{
			"token with no write scopes omitted",
			[]*TreeNode{
				{
					Type:  TreeNodeToken,
					Label: "GITHUB_TOKEN",
					Properties: map[string]interface{}{
						"scopes": []string{"contents:read", "metadata:read"},
					},
				},
			},
			"",
		},
		{
			"mixed vulns secrets and write token",
			[]*TreeNode{
				{Type: TreeNodeVuln},
				{Type: TreeNodeVuln},
				{Type: TreeNodeSecret},
				{
					Type:  TreeNodeToken,
					Label: "GITHUB_TOKEN",
					Properties: map[string]interface{}{
						"scopes": []string{"contents:write"},
					},
				},
			},
			" (2 vulns, 1 secret, GITHUB_TOKEN on: contents)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collapsedJobSummary(tt.children)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatVulnLabel_RequiresPivot(t *testing.T) {
	tests := []struct {
		name             string
		trigger          string
		loot             []CollectedSecret
		sessionLoot      []CollectedSecret
		tokenPermissions map[string]string
		contains         string
		excludes         string
	}{
		{
			name:     "workflow_dispatch without loot shows requires pivot",
			trigger:  "workflow_dispatch",
			contains: "(needs pivot)",
		},
		{
			name:    "workflow_dispatch with actions:write loot hides annotation",
			trigger: "workflow_dispatch",
			loot: []CollectedSecret{{
				Name:   "GITHUB_TOKEN",
				Value:  "ghs_abc123",
				Scopes: []string{"actions:write"},
			}},
			excludes: "(needs pivot)",
		},
		{
			name:    "workflow_dispatch with classic PAT hides annotation",
			trigger: "workflow_dispatch",
			loot: []CollectedSecret{{
				Name:  "MY_PAT",
				Value: "ghp_abc123",
			}},
			excludes: "(needs pivot)",
		},
		{
			name:    "workflow_dispatch with active session token hides annotation",
			trigger: "workflow_dispatch",
			sessionLoot: []CollectedSecret{{
				Name:      "GITHUB_TOKEN",
				Value:     "ghs_abc123",
				Ephemeral: true,
				Type:      "github_token",
			}},
			tokenPermissions: map[string]string{"actions": "write"},
			excludes:         "(needs pivot)",
		},
		{
			name:     "non-dispatch trigger never shows annotation",
			trigger:  "issue_comment",
			excludes: "(needs pivot)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel(Config{})
			m.jobDeadline = time.Now().Add(2 * time.Minute)
			m.lootStash = tt.loot
			m.sessionLoot = tt.sessionLoot
			m.tokenPermissions = tt.tokenPermissions
			m.vulnerabilities = []Vulnerability{{
				ID:      "V001",
				RuleID:  "injection",
				Context: "bash_run",
				Trigger: tt.trigger,
			}}
			node := &TreeNode{
				ID:     "V001",
				Type:   TreeNodeVuln,
				RuleID: "injection",
			}
			label := m.formatVulnLabel(node)
			if tt.contains != "" {
				assert.Contains(t, label, tt.contains)
			}
			if tt.excludes != "" {
				assert.NotContains(t, label, tt.excludes)
			}
		})
	}
}

func TestHasActionsWriteToken(t *testing.T) {
	tests := []struct {
		name    string
		secrets []CollectedSecret
		want    bool
	}{
		{"empty", nil, false},
		{"no matching scopes", []CollectedSecret{{Scopes: []string{"contents:read"}}}, false},
		{"actions:write scope", []CollectedSecret{{Scopes: []string{"actions:write"}}}, true},
		{"classic PAT (ghp_ prefix)", []CollectedSecret{{Value: "ghp_abc123"}}, true},
		{"non-matching PAT prefix", []CollectedSecret{{Value: "ghs_abc123"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasActionsWriteToken(tt.secrets))
		})
	}
}

func TestVulnerabilityForNode_UsesRepoToDisambiguateMatches(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{ID: "V001", Repository: "acme/one", Workflow: ".github/workflows/ci.yml", Job: "build", Line: 12, RuleID: "injection", Context: "issue_body"},
		{ID: "V002", Repository: "acme/two", Workflow: ".github/workflows/ci.yml", Job: "build", Line: 12, RuleID: "injection", Context: "issue_body"},
	}

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/two", Type: TreeNodeRepo, Label: "acme/two", Expanded: true, Parent: root}
	node := &TreeNode{
		ID:     "vuln:injection:.github/workflows/ci.yml:12",
		Type:   TreeNodeVuln,
		RuleID: "injection",
		Parent: repo,
		Properties: map[string]interface{}{
			"path":    ".github/workflows/ci.yml",
			"line":    12,
			"context": "issue_body",
			"job":     "build",
		},
	}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{node}

	vuln := m.vulnerabilityForNode(node)

	require.NotNil(t, vuln)
	assert.Equal(t, "V002", vuln.ID)
}

func TestTokenWriteScopes(t *testing.T) {
	tests := []struct {
		name string
		node *TreeNode
		want []string
	}{
		{"nil properties", &TreeNode{}, nil},
		{
			"no scopes key",
			&TreeNode{Properties: map[string]interface{}{}},
			nil,
		},
		{
			"read-only scopes",
			&TreeNode{Properties: map[string]interface{}{
				"scopes": []string{"contents:read", "metadata:read"},
			}},
			nil,
		},
		{
			"mixed scopes",
			&TreeNode{Properties: map[string]interface{}{
				"scopes": []string{"contents:write", "metadata:read", "actions:write"},
			}},
			[]string{"contents", "actions"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenWriteScopes(tt.node)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestRenderTreeNode_AddsGitHubHyperlinks(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg}
	repo := &TreeNode{ID: "github:whooli/xyz", Label: "xyz", Type: TreeNodeRepo, Parent: org}
	workflow := &TreeNode{ID: "github:whooli/xyz:workflow:.github/workflows/ci.yml", Label: ".github/workflows/ci.yml", Type: TreeNodeWorkflow, Parent: repo}

	orgLine := m.renderTreeNode(org, 80, false, 0)
	repoLine := m.renderTreeNode(repo, 80, false, 0)
	workflowLine := m.renderTreeNode(workflow, 100, false, 0)

	require.Contains(t, orgLine, "https://github.com/whooli")
	require.Contains(t, repoLine, "https://github.com/whooli/xyz")
	require.Contains(t, workflowLine, "https://github.com/whooli/xyz/blob/HEAD/.github/workflows/ci.yml")
}

func TestRenderTreeNode_MarksDispatchableWorkflowAction(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	repo := &TreeNode{ID: "github:whooli/xyz", Label: "xyz", Type: TreeNodeRepo}
	workflow := &TreeNode{
		ID:     "github:whooli/xyz:workflow:.github/workflows/deploy.yml",
		Label:  ".github/workflows/deploy.yml",
		Type:   TreeNodeWorkflow,
		Parent: repo,
		Properties: map[string]interface{}{
			"event_triggers": []string{"push", "workflow_dispatch"},
		},
	}
	normal := &TreeNode{
		ID:     "github:whooli/xyz:workflow:.github/workflows/ci.yml",
		Label:  ".github/workflows/ci.yml",
		Type:   TreeNodeWorkflow,
		Parent: repo,
		Properties: map[string]interface{}{
			"event_triggers": []string{"push"},
		},
	}

	dispatchLine := stripANSI(m.renderTreeNode(workflow, 100, false, 0))
	normalLine := stripANSI(m.renderTreeNode(normal, 100, false, 0))

	assert.Contains(t, dispatchLine, "[WORKFLOW - DISPATCHABLE]")
	assert.Contains(t, normalLine, "[WORKFLOW]")
	assert.NotContains(t, normalLine, "DISPATCHABLE")
}

func TestRenderVulnDetails_FallsBackToPathLineMatch(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{{
		ID:         "V001",
		Repository: "acme/api",
		Workflow:   ".github/workflows/deploy.yml",
		Job:        "deploy",
		Line:       27,
		RuleID:     "injection",
		Context:    "bash_run",
		Trigger:    "workflow_dispatch",
		Expression: "${{ github.event.inputs.payload }}",
	}}

	node := &TreeNode{
		ID:     "vuln:injection:.github/workflows/deploy.yml:27",
		Type:   TreeNodeVuln,
		Depth:  2,
		RuleID: "injection",
		Properties: map[string]interface{}{
			"path": ".github/workflows/deploy.yml",
			"line": 27,
		},
	}

	lines := m.renderVulnDetails(node, 120)

	require.NotEmpty(t, lines)
	assert.Contains(t, strings.Join(lines, "\n"), "Trigger:")
	assert.Contains(t, strings.Join(lines, "\n"), "workflow_dispatch")
}

func TestRenderAttackTree_ShowsFilteredBannerWithRepoCounts(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	org := pantry.NewOrganization("acme", "github")
	repo := pantry.NewRepository("acme", "api", "github")
	repoOther := pantry.NewRepository("acme", "docs", "github")
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/deploy.yml")
	workflowOther := pantry.NewWorkflow(repoOther.ID, ".github/workflows/lint.yml")
	vuln := pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/deploy.yml", 12)

	for _, asset := range []pantry.Asset{org, repo, repoOther, workflow, workflowOther, vuln} {
		require.NoError(t, m.pantry.AddAsset(asset))
	}

	require.NoError(t, m.pantry.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(org.ID, repoOther.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repoOther.ID, workflowOther.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(workflow.ID, vuln.ID, pantry.VulnerableTo("injection", "critical")))

	m.treeFiltered = true
	m.RebuildTree()

	rendered := m.RenderAttackTree(100, 8)

	assert.Contains(t, rendered, "FILTERED TREE")
	assert.Contains(t, rendered, "ON - showing 1 of 2 repos linked to vulnerabilities")
	assert.Contains(t, rendered, "Press f for the full tree")
}

func TestRenderAttackTree_ShowsFilterBannerWhenFullTreeIsVisible(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	org := pantry.NewOrganization("acme", "github")
	repo := pantry.NewRepository("acme", "api", "github")
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/deploy.yml")

	for _, asset := range []pantry.Asset{org, repo, workflow} {
		require.NoError(t, m.pantry.AddAsset(asset))
	}

	require.NoError(t, m.pantry.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))

	m.RebuildTree()

	rendered := m.RenderAttackTree(100, 8)

	assert.Contains(t, rendered, "FILTERED TREE")
	assert.Contains(t, rendered, "OFF - showing all 1 repo")
	assert.Contains(t, rendered, "Press f to show only repos with vulnerabilities")
}
