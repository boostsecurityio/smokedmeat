// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectedSourceTargetFromVulnerabilityNode(t *testing.T) {
	repo := &TreeNode{ID: "github:acme/api", Label: "api", Type: TreeNodeRepo, Properties: map[string]interface{}{}, Parent: &TreeNode{Label: "acme", Type: TreeNodeOrg}}
	workflow := &TreeNode{ID: "wf", Label: ".github/workflows/ci.yml", Type: TreeNodeWorkflow, Properties: map[string]interface{}{"path": ".github/workflows/ci.yml"}, Parent: repo}
	vuln := &TreeNode{ID: "V001", Label: "Injection", Type: TreeNodeVuln, Properties: map[string]interface{}{"path": ".github/workflows/ci.yml", "line": 7}, Parent: workflow}

	m := NewModel(Config{
		SessionID:         "sess-1",
		KitchenURL:        "http://kitchen.local",
		KitchenBrowserURL: "http://127.0.0.1:8080",
		AuthToken:         "jwt-token",
	})
	m.treeNodes = []*TreeNode{vuln}
	m.treeCursor = 0
	m.vulnerabilities = []Vulnerability{{
		ID:         "V001",
		Repository: "acme/api",
		Workflow:   ".github/workflows/ci.yml",
		Line:       7,
		RuleID:     "injection",
	}}

	target, err := m.selectedSourceTarget()
	require.NoError(t, err)
	assert.Equal(t, "acme", target.Owner)
	assert.Equal(t, "api", target.Repo)
	assert.Equal(t, ".github/workflows/ci.yml", target.Path)
	assert.Equal(t, 7, target.Line)
	assert.Contains(t, target.ViewerURL, "/viewer/github.com/acme/api/blob/HEAD/.github/workflows/ci.yml")
	assert.NotContains(t, target.ViewerURL, "token=")
	assert.NotContains(t, target.ViewerURL, "session_id=")
	assert.Contains(t, target.ViewerURL, "#L7")
}

func TestSelectedSourceBrowserURLFromOrgAndRepoNodes(t *testing.T) {
	m := NewModel(Config{
		SessionID:         "sess-1",
		KitchenBrowserURL: "http://127.0.0.1:8080",
		AuthToken:         "jwt-token",
	})
	root := &TreeNode{ID: "root", Label: "Attack Graph", Type: TreeNodeOrg}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/xyz", Label: "xyz", Type: TreeNodeRepo, Parent: org}

	orgURL, err := m.selectedSourceBrowserURL(org)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/viewer/github.com/whooli", orgURL)
	assert.True(t, m.sourceViewerAvailableForNode(org))

	repoURL, err := m.selectedSourceBrowserURL(repo)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/viewer/github.com/whooli/xyz", repoURL)
	assert.True(t, m.sourceViewerAvailableForNode(repo))
	assert.False(t, m.sourceViewerAvailableForNode(root))
}

func TestSelectedSourceBrowserURLFromWorkflowAndVulnerabilityNodes(t *testing.T) {
	repo := &TreeNode{ID: "github:acme/api", Label: "api", Type: TreeNodeRepo, Properties: map[string]interface{}{}, Parent: &TreeNode{Label: "acme", Type: TreeNodeOrg}}
	workflow := &TreeNode{ID: "wf", Label: ".github/workflows/ci.yml", Type: TreeNodeWorkflow, Properties: map[string]interface{}{"path": ".github/workflows/ci.yml", "default_branch": "main"}, Parent: repo}
	vuln := &TreeNode{ID: "V001", Label: "Injection", Type: TreeNodeVuln, Properties: map[string]interface{}{"line": 7}, Parent: workflow}

	m := NewModel(Config{
		SessionID:         "sess-1",
		KitchenBrowserURL: "http://127.0.0.1:8080",
		AuthToken:         "jwt-token",
	})
	m.vulnerabilities = []Vulnerability{{
		ID:         "V001",
		Repository: "acme/api",
		Workflow:   ".github/workflows/ci.yml",
		Line:       7,
		RuleID:     "injection",
	}}

	workflowURL, err := m.selectedSourceBrowserURL(workflow)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/viewer/github.com/acme/api/blob/main/.github/workflows/ci.yml#L1", workflowURL)

	vulnURL, err := m.selectedSourceBrowserURL(vuln)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080/viewer/github.com/acme/api/blob/HEAD/.github/workflows/ci.yml#L7", vulnURL)
	assert.True(t, m.sourceViewerAvailableForNode(workflow))
	assert.True(t, m.sourceViewerAvailableForNode(vuln))
}

func TestSourceViewerAvailableForNodeRequiresResolvableSource(t *testing.T) {
	m := NewModel(Config{
		SessionID:         "sess-1",
		KitchenBrowserURL: "http://127.0.0.1:8080",
		AuthToken:         "jwt-token",
	})
	repo := &TreeNode{ID: "github:acme/api", Label: "api", Type: TreeNodeRepo, Parent: &TreeNode{Label: "acme", Type: TreeNodeOrg}}
	workflow := &TreeNode{ID: "wf", Label: ".github/workflows/ci.yml", Type: TreeNodeWorkflow, Properties: map[string]interface{}{"path": ".github/workflows/ci.yml"}, Parent: repo}
	badWorkflow := &TreeNode{ID: "bad-wf", Label: "", Type: TreeNodeWorkflow, Parent: &TreeNode{Label: "api", Type: TreeNodeRepo}}
	vuln := &TreeNode{ID: "V001", Label: "Injection", Type: TreeNodeVuln, Parent: workflow}
	m.vulnerabilities = []Vulnerability{{
		ID:         "V001",
		Repository: "acme/api",
		Workflow:   ".github/workflows/ci.yml",
		Line:       7,
		RuleID:     "injection",
	}}

	assert.True(t, m.sourceViewerAvailableForNode(workflow))
	assert.True(t, m.sourceViewerAvailableForNode(vuln))
	assert.False(t, m.sourceViewerAvailableForNode(badWorkflow))

	withoutVulns := m
	withoutVulns.vulnerabilities = nil
	assert.False(t, withoutVulns.sourceViewerAvailableForNode(vuln))

	badRepo := m
	badRepo.vulnerabilities = []Vulnerability{{
		ID:         "bad-repo-vuln",
		Repository: "api",
		Workflow:   ".github/workflows/ci.yml",
	}}
	assert.False(t, badRepo.sourceViewerAvailableForNode(&TreeNode{ID: "bad-repo-vuln", Type: TreeNodeVuln, Parent: workflow}))
}

func TestBrowserSessionURLWrapsViewerAndGraphURLs(t *testing.T) {
	m := NewModel(Config{
		SessionID:         "sess-1",
		KitchenBrowserURL: "http://127.0.0.1:8080",
		AuthToken:         "jwt-token",
	})

	fileURL := "http://127.0.0.1:8080/viewer/github.com/acme/api/blob/HEAD/.github/workflows/ci.yml#L7"
	assert.Equal(t,
		"http://127.0.0.1:8080/browser/session?token=jwt-token&session_id=sess-1&next=%2Fviewer%2Fgithub.com%2Facme%2Fapi%2Fblob%2FHEAD%2F.github%2Fworkflows%2Fci.yml%23L7",
		m.browserSessionURL(fileURL),
	)

	assert.Equal(t,
		"http://127.0.0.1:8080/browser/session?token=jwt-token&session_id=sess-1&next=%2Fgraph",
		m.browserSessionURL("http://127.0.0.1:8080/graph"),
	)
}
