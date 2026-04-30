// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOmniboxKindLabel(t *testing.T) {
	assert.Equal(t, "ORG", omniboxKindLabel(OmniboxResultOrg))
	assert.Equal(t, "REPO", omniboxKindLabel(OmniboxResultRepo))
	assert.Equal(t, "WORK", omniboxKindLabel(OmniboxResultWorkflow))
	assert.Equal(t, "SH-RUN", omniboxKindLabel(OmniboxResultRunner))
	assert.Equal(t, "VULN", omniboxKindLabel(OmniboxResultVuln))
	assert.Equal(t, "LOOT", omniboxKindLabel(OmniboxResultLoot))
}

func TestModel_SearchOmnibox_ReturnsRepoAndLootMatches(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.treeRoot = &TreeNode{ID: "root", Expanded: true}

	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: true, Parent: m.treeRoot}
	repo := &TreeNode{ID: "repo:whooli/banana", Label: "banana", Type: TreeNodeRepo, Parent: org}
	org.Children = []*TreeNode{repo}
	m.treeRoot.Children = []*TreeNode{org}
	m.ReflattenTree()

	m.lootStash = []CollectedSecret{{
		Name:        "banana",
		Value:       "secret",
		Repository:  "whooli/xyz",
		Workflow:    ".github/workflows/test.yml",
		Job:         "build",
		CollectedAt: time.Now(),
	}}
	m.RebuildLootTree()

	results := m.searchOmnibox("banana")
	require.Len(t, results, 2)
	assert.ElementsMatch(t, []OmniboxResultKind{results[0].Kind, results[1].Kind}, []OmniboxResultKind{OmniboxResultRepo, OmniboxResultLoot})
	assert.ElementsMatch(t, []string{results[0].Label, results[1].Label}, []string{"whooli/banana", "banana"})
}

func TestModel_SearchOmnibox_ReturnsSelfHostedRunnerMatches(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/newcleus-core-v3", Label: "newcleus-core-v3", Type: TreeNodeRepo, Expanded: true, Parent: org}
	runner := &TreeNode{
		ID:     "runner:linux-x64",
		Label:  "linux-x64",
		Type:   TreeNodeSelfHostedRunner,
		Parent: repo,
		Properties: map[string]interface{}{
			"label_set":               []string{"self-hosted", "linux", "x64"},
			"observed_workflow_paths": []string{".github/workflows/build.yml"},
		},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{runner}
	m.treeRoot = root
	m.ReflattenTree()

	results := m.searchOmnibox("shrunner linux")

	require.Len(t, results, 1)
	assert.Equal(t, OmniboxResultRunner, results[0].Kind)
	assert.Equal(t, "[SH-RUNNER] linux-x64", results[0].Label)
	assert.Equal(t, runner.ID, results[0].NodeID)
	assert.Contains(t, results[0].Detail, "whooli/newcleus-core-v3")
}

func TestModel_SearchOmnibox_EmptyQueryBalancesKinds(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/xyz", Label: "xyz", Type: TreeNodeRepo, Expanded: true, Parent: org}
	workflow := &TreeNode{ID: "wf:auto-labeler", Label: ".github/workflows/auto-labeler.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	job := &TreeNode{ID: "job:whooli-triage", Label: "whooli-triage", Type: TreeNodeJob, Expanded: true, Parent: workflow}
	vuln := &TreeNode{
		ID:         "V001",
		Label:      "Bash injection",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 20, "context": "issue_body"},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflow}
	workflow.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()

	m.vulnerabilities = []Vulnerability{{ID: "V001"}}
	m.suggestions = []SuggestedAction{{VulnIndex: 0}}
	m.lootStash = []CollectedSecret{{
		Name:        "DEPLOY_KEY",
		Value:       "secret",
		Repository:  "whooli/xyz",
		Workflow:    "README.md",
		CollectedAt: time.Now(),
	}}
	m.RebuildLootTree()

	results := m.searchOmnibox("")

	require.Len(t, results, 5)
	assert.Equal(t, []OmniboxResultKind{
		OmniboxResultOrg,
		OmniboxResultRepo,
		OmniboxResultWorkflow,
		OmniboxResultVuln,
		OmniboxResultLoot,
	}, []OmniboxResultKind{
		results[0].Kind,
		results[1].Kind,
		results[2].Kind,
		results[3].Kind,
		results[4].Kind,
	})
}

func TestModel_SearchOmnibox_EmptyQueryRefillsBucketsInOrder(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	root := &TreeNode{ID: "root", Expanded: true}
	orgA := &TreeNode{ID: "org:alpha", Label: "alpha", Type: TreeNodeOrg, Expanded: true, Parent: root}
	orgB := &TreeNode{ID: "org:zeta", Label: "zeta", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:alpha/app", Label: "app", Type: TreeNodeRepo, Expanded: true, Parent: orgA}
	job := &TreeNode{ID: "job:build", Label: "build", Type: TreeNodeJob, Expanded: true}
	vulnA := &TreeNode{
		ID:         "V001",
		Label:      "Injection A",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 10, "context": "issue_body"},
	}
	vulnB := &TreeNode{
		ID:         "V002",
		Label:      "Injection B",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 20, "context": "issue_body"},
	}
	root.Children = []*TreeNode{orgB, orgA}
	orgA.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{job}
	job.Parent = repo
	job.Children = []*TreeNode{vulnA, vulnB}
	m.treeRoot = root
	m.ReflattenTree()

	m.vulnerabilities = []Vulnerability{{ID: "V001"}, {ID: "V002"}}
	m.suggestions = []SuggestedAction{{VulnIndex: 1}, {VulnIndex: 0}}
	m.lootStash = []CollectedSecret{
		{Name: "BETA", Value: "b", CollectedAt: time.Now()},
		{Name: "ALPHA", Value: "a", CollectedAt: time.Now()},
	}
	m.RebuildLootTree()

	results := m.searchOmnibox("")

	require.Len(t, results, 5)
	assert.Equal(t, []string{"alpha", "zeta", "alpha/app", "Injection B · L20", "ALPHA"}, []string{
		results[0].Label,
		results[1].Label,
		results[2].Label,
		results[3].Label,
		results[4].Label,
	})
}

func TestModel_SearchOmnibox_EmptyQueryUsesSecondWorkflowWhenLootMissing(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/xyz", Label: "xyz", Type: TreeNodeRepo, Expanded: true, Parent: org}
	workflowA := &TreeNode{ID: "wf:auto-labeler", Label: ".github/workflows/auto-labeler.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	workflowB := &TreeNode{ID: "wf:community-build", Label: ".github/workflows/community-build.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	job := &TreeNode{ID: "job:analyze", Label: "analyze (Weissman Score Analysis)", Type: TreeNodeJob, Expanded: true, Parent: workflowA}
	vuln := &TreeNode{
		ID:         "V001",
		Label:      "Injection with Arbitrary External Contributor Input",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 30, "context": "comment_body"},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflowA, workflowB}
	workflowA.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()

	m.vulnerabilities = []Vulnerability{{ID: "V001"}}
	m.suggestions = []SuggestedAction{{VulnIndex: 0}}

	results := m.searchOmnibox("")

	require.Len(t, results, 5)
	assert.Equal(t, []OmniboxResultKind{
		OmniboxResultOrg,
		OmniboxResultRepo,
		OmniboxResultWorkflow,
		OmniboxResultWorkflow,
		OmniboxResultVuln,
	}, []OmniboxResultKind{
		results[0].Kind,
		results[1].Kind,
		results[2].Kind,
		results[3].Kind,
		results[4].Kind,
	})
	assert.Equal(t, []string{
		"whooli",
		"whooli/xyz",
		".github/workflows/auto-labeler.yml",
		".github/workflows/community-build.yml",
		"Injection with Arbitrary External Contributor Input · L30",
	}, []string{
		results[0].Label,
		results[1].Label,
		results[2].Label,
		results[3].Label,
		results[4].Label,
	})
}

func TestModel_SearchOmnibox_DisambiguatesSameTitleVulns(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/xyz", Label: "xyz", Type: TreeNodeRepo, Expanded: true, Parent: org}
	workflow := &TreeNode{ID: "wf:auto-labeler", Label: ".github/workflows/auto-labeler.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	job := &TreeNode{ID: "job:whooli-triage", Label: "whooli-triage", Type: TreeNodeJob, Expanded: true, Parent: workflow}
	vuln1 := &TreeNode{
		ID:         "V001",
		Label:      "Bash injection",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 20, "context": "issue_body"},
	}
	vuln2 := &TreeNode{
		ID:         "V002",
		Label:      "Bash injection",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 35, "context": "issue_body"},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflow}
	workflow.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln1, vuln2}
	m.treeRoot = root
	m.ReflattenTree()

	results := m.searchOmnibox("bash injection")

	require.Len(t, results, 2)
	assert.Equal(t, OmniboxResultVuln, results[0].Kind)
	assert.Equal(t, OmniboxResultVuln, results[1].Kind)
	assert.ElementsMatch(t, []string{results[0].Label, results[1].Label}, []string{"Bash injection · L20", "Bash injection · L35"})
	assert.Contains(t, results[0].Detail, "whooli/xyz")
	assert.Contains(t, results[0].Detail, "whooli-triage")
	assert.Contains(t, results[0].Detail, "issue_body")
}

func TestModel_ApplyOmniboxSelection_SelectsLootPane(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.phase = PhaseRecon
	m.view = ViewAgent
	m.focus = FocusInput
	m.lootStash = []CollectedSecret{{
		Name:        "DEPLOY_KEY",
		Value:       "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
		Type:        "private_key",
		Repository:  "whooli/infrastructure-definitions",
		Workflow:    "README.md",
		CollectedAt: time.Now(),
	}}
	m.RebuildLootTree()

	var nodeID string
	for _, node := range m.lootTreeNodes {
		if secret := m.getLootSecret(node); secret != nil && secret.Name == "DEPLOY_KEY" {
			nodeID = node.ID
			break
		}
	}
	require.NotEmpty(t, nodeID)

	m.openOmnibox()
	m.omnibox.results = []OmniboxResult{{
		Kind:   OmniboxResultLoot,
		Label:  "DEPLOY_KEY",
		NodeID: nodeID,
	}}

	result, cmd := m.applyOmniboxSelection()
	model := result.(Model)

	require.Nil(t, cmd)
	assert.Equal(t, ViewAgent, model.view)
	assert.Equal(t, PaneFocusLoot, model.paneFocus)
	require.NotNil(t, model.SelectedLootSecret())
	assert.Equal(t, "DEPLOY_KEY", model.SelectedLootSecret().Name)
}

func TestModel_ApplyOmniboxSelection_SelectsRepoAndUpdatesTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.focus = FocusInput

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/newcleus-core-v3", Label: "newcleus-core-v3", Type: TreeNodeRepo, Parent: org}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	m.treeRoot = root
	m.ReflattenTree()

	m.openOmnibox()
	m.omnibox.results = []OmniboxResult{{
		Kind:       OmniboxResultRepo,
		Label:      "whooli/newcleus-core-v3",
		NodeID:     repo.ID,
		TargetSpec: "repo:whooli/newcleus-core-v3",
	}}

	result, cmd := m.applyOmniboxSelection()
	model := result.(Model)

	require.Nil(t, cmd)
	assert.Equal(t, ViewFindings, model.view)
	assert.Equal(t, PaneFocusFindings, model.paneFocus)
	assert.Equal(t, "whooli/newcleus-core-v3", model.target)
	require.NotNil(t, model.SelectedTreeNode())
	assert.Equal(t, repo.ID, model.SelectedTreeNode().ID)
}

func TestTreeSelectByID_ExpandsCollapsedAncestors(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{{
		ID:         "V001",
		Repository: "whooli/infra",
		Workflow:   ".github/workflows/deploy.yml",
		Job:        "deploy",
		Line:       42,
		RuleID:     "injection",
		Context:    "issue_body",
	}}

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Label: "whooli", Type: TreeNodeOrg, Expanded: false, Parent: root}
	repo := &TreeNode{ID: "repo:whooli/infra", Label: "infra", Type: TreeNodeRepo, Expanded: false, Parent: org}
	vuln := &TreeNode{
		ID:     "vuln:injection:.github/workflows/deploy.yml:42:abc123",
		Label:  "Bash injection",
		Type:   TreeNodeVuln,
		Parent: repo,
		Properties: map[string]interface{}{
			"path":    ".github/workflows/deploy.yml",
			"line":    42,
			"job":     "deploy",
			"context": "issue_body",
		},
		RuleID: "injection",
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{vuln}

	m.treeRoot = root
	m.ReflattenTree()

	require.True(t, m.TreeSelectByID("V001"))
	require.NotNil(t, m.SelectedTreeNode())
	assert.Equal(t, vuln.ID, m.SelectedTreeNode().ID)
	assert.True(t, org.Expanded)
	assert.True(t, repo.Expanded)
}

func TestLootTreeSelectByID_ExpandsCollapsedAncestors(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{{
		Name:        "DEPLOY_KEY",
		Value:       "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
		Type:        "private_key",
		Repository:  "whooli/infra",
		Workflow:    "README.md",
		CollectedAt: time.Now(),
	}}
	m.RebuildLootTree()

	var nodeID string
	for _, node := range m.lootTreeNodes {
		if secret := m.getLootSecret(node); secret != nil && secret.Name == "DEPLOY_KEY" {
			nodeID = node.ID
			break
		}
	}
	require.NotEmpty(t, nodeID)
	require.GreaterOrEqual(t, len(m.lootTreeNodes), 3)
	m.lootTreeRoot.Children[0].Expanded = false
	m.ReflattenLootTree()

	require.True(t, m.LootTreeSelectByID(nodeID))
	require.NotNil(t, m.SelectedLootSecret())
	assert.Equal(t, "DEPLOY_KEY", m.SelectedLootSecret().Name)
	assert.True(t, m.lootTreeRoot.Children[0].Expanded)
}

func TestFocusOmniboxVulnerability_PrefersMenuWhenSuggestionExists(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{ID: "V004", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/internal-sync.yml", Job: "archive-feedback", Context: "workflow_dispatch_input"},
	}
	m.suggestions = []SuggestedAction{{VulnIndex: 0}}

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:acme", Label: "acme", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:acme/xyz", Label: "xyz", Type: TreeNodeRepo, Expanded: true, Parent: org}
	workflow := &TreeNode{ID: "wf:dispatch", Label: ".github/workflows/internal-sync.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	job := &TreeNode{ID: "job:archive-feedback", Label: "archive-feedback", Type: TreeNodeJob, Expanded: true, Parent: workflow}
	vuln := &TreeNode{
		ID:         "V004",
		Label:      "Bash injection",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 22, "context": "workflow_dispatch_input"},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflow}
	workflow.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()

	require.True(t, m.focusOmniboxVulnerability("V004"))
	require.NotNil(t, m.SelectedTreeNode())
	assert.Equal(t, "V004", m.SelectedTreeNode().ID)
	assert.Equal(t, PaneFocusMenu, m.paneFocus)
	assert.Equal(t, 0, m.menuCursor)
}

func TestFocusOmniboxVulnerability_FallsBackToTreeWhenNotInMenu(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{ID: "V001", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/comment.yml", Job: "triage", Context: "issue_body"},
	}

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:acme", Label: "acme", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:acme/xyz", Label: "xyz", Type: TreeNodeRepo, Expanded: true, Parent: org}
	workflow := &TreeNode{ID: "wf:comment", Label: ".github/workflows/comment.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	job := &TreeNode{ID: "job:triage", Label: "triage", Type: TreeNodeJob, Expanded: true, Parent: workflow}
	vuln := &TreeNode{
		ID:         "V001",
		Label:      "Bash injection",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 12, "context": "issue_body"},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflow}
	workflow.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()

	require.True(t, m.focusOmniboxVulnerability("V001"))
	require.NotNil(t, m.SelectedTreeNode())
	assert.Equal(t, "V001", m.SelectedTreeNode().ID)
	assert.Equal(t, PaneFocusFindings, m.paneFocus)
}

func TestModel_ApplyOmniboxSelection_SelectsVulnByNodeIDFallback(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.view = ViewFindings

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:acme", Label: "acme", Type: TreeNodeOrg, Expanded: true, Parent: root}
	repo := &TreeNode{ID: "repo:acme/xyz", Label: "xyz", Type: TreeNodeRepo, Expanded: true, Parent: org}
	workflow := &TreeNode{ID: "wf:comment", Label: ".github/workflows/comment.yml", Type: TreeNodeWorkflow, Expanded: true, Parent: repo}
	job := &TreeNode{ID: "job:triage", Label: "triage", Type: TreeNodeJob, Expanded: true, Parent: workflow}
	vuln := &TreeNode{
		ID:         "node:vuln:comment",
		Label:      "Bash injection",
		Type:       TreeNodeVuln,
		Parent:     job,
		RuleID:     "injection",
		Properties: map[string]interface{}{"line": 12, "context": "issue_body"},
	}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflow}
	workflow.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()
	m.vulnerabilities = []Vulnerability{{ID: "V001", Repository: "acme/xyz", Workflow: ".github/workflows/comment.yml", Job: "triage", Context: "issue_body"}}

	m.openOmnibox()
	m.omnibox.results = []OmniboxResult{{
		Kind:   OmniboxResultVuln,
		Label:  "Bash injection",
		NodeID: vuln.ID,
		VulnID: "V001",
	}}

	result, cmd := m.applyOmniboxSelection()
	model := result.(Model)

	require.Nil(t, cmd)
	require.NotNil(t, model.SelectedTreeNode())
	assert.Equal(t, vuln.ID, model.SelectedTreeNode().ID)
	assert.Equal(t, PaneFocusFindings, model.paneFocus)
}
