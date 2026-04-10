// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestTreeNodeType_String(t *testing.T) {
	tests := []struct {
		nodeType TreeNodeType
		want     string
	}{
		{TreeNodeOrg, "ORG"},
		{TreeNodeRepo, "REPO"},
		{TreeNodeWorkflow, "WORKFLOW"},
		{TreeNodeJob, "JOB"},
		{TreeNodeVuln, "VULN"},
		{TreeNodeSecret, "SECRET"},
		{TreeNodeToken, "TOKEN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.nodeType.String())
		})
	}
}

func TestTreeNodeState_Values(t *testing.T) {
	// Verify states are distinct
	states := []TreeNodeState{
		TreeStateNew, TreeStateReachable, TreeStateAchieved,
		TreeStateHighValue, TreeStateDeadEnd,
	}
	seen := make(map[TreeNodeState]bool)
	for _, s := range states {
		assert.False(t, seen[s], "State should be unique")
		seen[s] = true
	}
}

func TestModel_TreeCursorDown(t *testing.T) {
	m := NewModel(Config{})
	m.treeNodes = []*TreeNode{
		{ID: "1", Label: "Node 1"},
		{ID: "2", Label: "Node 2"},
		{ID: "3", Label: "Node 3"},
	}
	m.treeCursor = 0

	m.TreeCursorDown()
	assert.Equal(t, 1, m.treeCursor)

	m.TreeCursorDown()
	assert.Equal(t, 2, m.treeCursor)

	// Should wrap to first
	m.TreeCursorDown()
	assert.Equal(t, 0, m.treeCursor)
}

func TestModel_TreeCursorUp(t *testing.T) {
	m := NewModel(Config{})
	m.treeNodes = []*TreeNode{
		{ID: "1", Label: "Node 1"},
		{ID: "2", Label: "Node 2"},
	}
	m.treeCursor = 1

	m.TreeCursorUp()
	assert.Equal(t, 0, m.treeCursor)

	// Should wrap to last
	m.TreeCursorUp()
	assert.Equal(t, 1, m.treeCursor)
}

func TestModel_TreeToggleExpand(t *testing.T) {
	m := NewModel(Config{})
	node := &TreeNode{
		ID:       "1",
		Label:    "Node",
		Expanded: false,
		Children: []*TreeNode{{ID: "child"}},
	}
	m.treeNodes = []*TreeNode{node}
	m.treeCursor = 0

	m.TreeToggleExpand()
	// Note: TreeToggleExpand may rebuild tree, check the node was expanded
}

func TestModel_RebuildTree_WithRepoAndWorkflow(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	// Add a repo
	repo := pantry.Asset{
		ID:   "repo:test/app",
		Name: "test/app",
		Type: pantry.AssetRepository,
	}
	err := m.pantry.AddAsset(repo)
	require.NoError(t, err)

	// Add a workflow
	wf := pantry.Asset{
		ID:   "wf:ci.yml",
		Name: "ci.yml",
		Type: pantry.AssetWorkflow,
	}
	wf.SetProperty("path", ".github/workflows/ci.yml")
	err = m.pantry.AddAsset(wf)
	require.NoError(t, err)

	// Link them
	err = m.pantry.AddRelationship(repo.ID, wf.ID, pantry.Contains())
	require.NoError(t, err)

	m.RebuildTree()

	assert.NotNil(t, m.treeRoot)
	assert.Greater(t, len(m.treeNodes), 0)
}

func TestFlattenTree(t *testing.T) {
	root := &TreeNode{
		ID:       "root",
		Expanded: true,
		Children: []*TreeNode{
			{ID: "child1", Expanded: false},
			{
				ID:       "child2",
				Expanded: true,
				Children: []*TreeNode{
					{ID: "grandchild"},
				},
			},
		},
	}

	flat := FlattenTree(root)

	// Root is skipped (ID="root"), so: 2 children + 1 grandchild (since child2 is expanded)
	assert.Len(t, flat, 3)
}

func TestFlattenTree_Nil(t *testing.T) {
	flat := FlattenTree(nil)
	assert.Empty(t, flat)
}

func TestFlattenTree_CollapsedChildren(t *testing.T) {
	root := &TreeNode{
		ID:       "root",
		Expanded: true,
		Children: []*TreeNode{
			{
				ID:       "child",
				Expanded: false,
				Children: []*TreeNode{
					{ID: "hidden"},
				},
			},
		},
	}

	flat := FlattenTree(root)

	// Root is skipped (ID="root"), child is visible, hidden grandchild is not (collapsed parent)
	assert.Len(t, flat, 1)
	assert.Equal(t, "child", flat[0].ID)
}

func TestModel_BuildTreeFromPantry_Empty(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	m.RebuildTree()

	assert.Nil(t, m.treeRoot)
	assert.Empty(t, m.treeNodes)
}

func TestModel_RebuildTree_AppliesPrivateRepoOverlay(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pantry = pantry.New()

	repo := pantry.NewRepository("acme", "secret-infra", "github")
	require.NoError(t, m.pantry.AddAsset(repo))

	m.knownEntities = map[string]*KnownEntity{
		"repo:acme/secret-infra": {
			ID:         "repo:acme/secret-infra",
			EntityType: "repo",
			Name:       "acme/secret-infra",
			IsPrivate:  true,
		},
	}

	m.RebuildTree()

	require.NotNil(t, m.treeRoot)
	require.Len(t, m.treeRoot.Children, 1)
	repoNode := m.treeRoot.Children[0]
	assert.Equal(t, "secret-infra", repoNode.Label, "label should be just repo name")
	assert.Equal(t, "github:acme/secret-infra", repoNode.ID, "ID should be provider:org/repo")
	assert.Equal(t, TreeStateHighValue, repoNode.State, "repo with IsPrivate in knownEntities should be marked HighValue")
}

func TestModel_SelectedTreeNode_Empty(t *testing.T) {
	m := NewModel(Config{})

	node := m.SelectedTreeNode()

	assert.Nil(t, node)
}

func TestModel_SelectedTreeNode_Valid(t *testing.T) {
	m := NewModel(Config{})
	expected := &TreeNode{ID: "test", Label: "Test Node"}
	m.treeNodes = []*TreeNode{expected}
	m.treeCursor = 0

	node := m.SelectedTreeNode()

	assert.Equal(t, expected, node)
}

func TestModel_TreeExpandAll(t *testing.T) {
	m := NewModel(Config{})
	m.treeRoot = &TreeNode{
		ID:       "root",
		Expanded: false,
		Children: []*TreeNode{
			{ID: "child", Expanded: false},
		},
	}

	m.TreeExpandAll()

	assert.True(t, m.treeRoot.Expanded)
	assert.True(t, m.treeRoot.Children[0].Expanded)
}

func TestModel_TreeCollapseAll(t *testing.T) {
	m := NewModel(Config{})
	m.treeRoot = &TreeNode{
		ID:       "root",
		Expanded: true,
		Children: []*TreeNode{
			{ID: "child", Expanded: true},
		},
	}

	m.TreeCollapseAll()

	// Root stays expanded, children collapse
	assert.True(t, m.treeRoot.Expanded)
	assert.False(t, m.treeRoot.Children[0].Expanded)
}

func TestBuildTreeFromPantry_OrgAsRoot(t *testing.T) {
	p := pantry.New()

	// Create org -> repo -> workflow hierarchy
	org := pantry.NewOrganization("whooli", "github")
	require.NoError(t, p.AddAsset(org))

	repo := pantry.NewRepository("whooli", "xyz", "github")
	require.NoError(t, p.AddAsset(repo))

	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	require.NoError(t, p.AddAsset(workflow))

	// Add relationships
	require.NoError(t, p.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))

	// Build tree
	root := BuildTreeFromPantry(p)

	// Verify structure
	require.NotNil(t, root, "Root should not be nil")
	require.Len(t, root.Children, 1, "Root should have 1 child (the org)")

	orgNode := root.Children[0]
	assert.Equal(t, TreeNodeOrg, orgNode.Type, "First child should be org")
	assert.Equal(t, "whooli", orgNode.Label, "Org label should be org name")
	assert.Equal(t, org.ID, orgNode.ID, "Org ID should match")

	require.Len(t, orgNode.Children, 1, "Org should have 1 child (the repo)")
	repoNode := orgNode.Children[0]
	assert.Equal(t, TreeNodeRepo, repoNode.Type, "Org's child should be repo")
	assert.Equal(t, repo.ID, repoNode.ID, "Repo ID should match")

	require.Len(t, repoNode.Children, 1, "Repo should have 1 child (the workflow)")
	wfNode := repoNode.Children[0]
	assert.Equal(t, TreeNodeWorkflow, wfNode.Type, "Repo's child should be workflow")
}

func TestBuildTreeFromPantry_OrgAsRoot_AfterJSONRoundTrip(t *testing.T) {
	// This test simulates what happens when Counter loads from Kitchen
	p := pantry.New()

	// Create org -> repo -> workflow hierarchy
	org := pantry.NewOrganization("whooli", "github")
	require.NoError(t, p.AddAsset(org))

	repo := pantry.NewRepository("whooli", "xyz", "github")
	require.NoError(t, p.AddAsset(repo))

	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	require.NoError(t, p.AddAsset(workflow))

	// Add relationships
	require.NoError(t, p.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))

	// Simulate Kitchen -> Counter transfer via JSON
	data, err := p.MarshalJSON()
	require.NoError(t, err)

	p2 := pantry.New()
	require.NoError(t, p2.UnmarshalJSON(data))

	// Debug: check what assets we have
	orgs := p2.GetAssetsByType(pantry.AssetOrganization)
	t.Logf("Orgs after JSON roundtrip: %d", len(orgs))
	for _, o := range orgs {
		t.Logf("  Org: ID=%s Name=%s Type=%s", o.ID, o.Name, o.Type)
	}

	repos := p2.GetAssetsByType(pantry.AssetRepository)
	t.Logf("Repos after JSON roundtrip: %d", len(repos))
	for _, r := range repos {
		t.Logf("  Repo: ID=%s Name=%s Type=%s", r.ID, r.Name, r.Type)
	}

	edges := p2.AllRelationships()
	t.Logf("Edges after JSON roundtrip: %d", len(edges))
	for _, e := range edges {
		t.Logf("  Edge: %s -> %s (type=%s)", e.From, e.To, e.Relationship.Type)
	}

	// Build tree from loaded pantry
	root := BuildTreeFromPantry(p2)

	// Verify structure
	require.NotNil(t, root, "Root should not be nil")
	t.Logf("Root children: %d", len(root.Children))
	for i, c := range root.Children {
		t.Logf("  Child %d: ID=%s Label=%s Type=%s", i, c.ID, c.Label, c.Type)
	}

	require.Len(t, root.Children, 1, "Root should have 1 child (the org)")

	orgNode := root.Children[0]
	assert.Equal(t, TreeNodeOrg, orgNode.Type, "First child should be org")
}

func TestBuildTreeFromPantry_OrgAsRoot_WithLocalImport(t *testing.T) {
	// This simulates Counter flow:
	// 1. Load pantry from Kitchen (with org)
	// 2. Import analysis locally (adds more assets)
	// 3. Build tree - org should still be root

	// Step 1: Create "Kitchen" pantry with org->repo->workflow
	kitchenPantry := pantry.New()
	org := pantry.NewOrganization("whooli", "github")
	require.NoError(t, kitchenPantry.AddAsset(org))
	repo := pantry.NewRepository("whooli", "xyz", "github")
	require.NoError(t, kitchenPantry.AddAsset(repo))
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	require.NoError(t, kitchenPantry.AddAsset(workflow))
	require.NoError(t, kitchenPantry.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, kitchenPantry.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))

	// Simulate JSON transfer from Kitchen to Counter
	data, err := kitchenPantry.MarshalJSON()
	require.NoError(t, err)

	counterPantry := pantry.New()
	require.NoError(t, counterPantry.UnmarshalJSON(data))

	// Step 2: "Import" a vulnerability locally (like Counter's importAnalysisToPantry does)
	vuln := pantry.NewVulnerability("injection", "pkg:github/whooli/xyz", ".github/workflows/ci.yml", 42)
	require.NoError(t, counterPantry.AddAsset(vuln))
	require.NoError(t, counterPantry.AddRelationship(workflow.ID, vuln.ID, pantry.VulnerableTo("injection", "critical")))

	// Step 3: Build tree
	root := BuildTreeFromPantry(counterPantry)

	// Verify org is still root
	require.NotNil(t, root)
	t.Logf("Root children after local import: %d", len(root.Children))
	for i, c := range root.Children {
		t.Logf("  Child %d: ID=%s Label=%s Type=%s", i, c.ID, c.Label, c.Type)
	}

	require.Len(t, root.Children, 1, "Root should have 1 child (the org)")
	assert.Equal(t, TreeNodeOrg, root.Children[0].Type)
	assert.Equal(t, "whooli", root.Children[0].Label)
}

func TestRebuildTree_PrivateRepoPantryProperty(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pantry = pantry.New()

	org := pantry.NewOrganization("whooli", "github")
	require.NoError(t, m.pantry.AddAsset(org))

	repo := pantry.NewRepository("whooli", "secret-repo", "github")
	repo.SetProperty("private", true)
	require.NoError(t, m.pantry.AddAsset(repo))

	require.NoError(t, m.pantry.AddRelationship(org.ID, repo.ID, pantry.Contains()))

	m.RebuildTree()

	require.NotNil(t, m.treeRoot)
	require.Len(t, m.treeRoot.Children, 1)
	orgNode := m.treeRoot.Children[0]
	require.Len(t, orgNode.Children, 1)
	repoNode := orgNode.Children[0]
	assert.Equal(t, TreeStateHighValue, repoNode.State, "private repo should have HighValue state")
}

func TestRebuildTree_PublicRepoNotHighValue(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pantry = pantry.New()

	repo := pantry.NewRepository("whooli", "public-repo", "github")
	require.NoError(t, m.pantry.AddAsset(repo))

	m.RebuildTree()

	require.NotNil(t, m.treeRoot)
	require.Len(t, m.treeRoot.Children, 1)
	repoNode := m.treeRoot.Children[0]
	assert.NotEqual(t, TreeStateHighValue, repoNode.State, "public repo should not have HighValue state")
}

func TestBuildFilteredTree_CreatesOrgFromRepoProperty(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	// Create org -> repo -> workflow hierarchy
	org := pantry.NewOrganization("whooli", "github")
	require.NoError(t, m.pantry.AddAsset(org))

	repo := pantry.NewRepository("whooli", "xyz", "github")
	require.NoError(t, m.pantry.AddAsset(repo))

	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	require.NoError(t, m.pantry.AddAsset(workflow))

	require.NoError(t, m.pantry.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))

	// Add a vulnerability to make the workflow a "top path"
	vuln := pantry.NewVulnerability("injection", "pkg:github/whooli/xyz", ".github/workflows/ci.yml", 42)
	require.NoError(t, m.pantry.AddAsset(vuln))
	require.NoError(t, m.pantry.AddRelationship(workflow.ID, vuln.ID, pantry.VulnerableTo("injection", "critical")))

	// Add vulnerability to model for suggestions
	m.vulnerabilities = []Vulnerability{{
		ID:       "V001",
		RuleID:   "injection",
		Severity: "critical",
		Workflow: ".github/workflows/ci.yml",
	}}
	m.GenerateSuggestions()

	// Build filtered tree (default is treeFiltered=true)
	m.treeFiltered = true
	m.RebuildTree()

	// Verify org node is created
	require.NotNil(t, m.treeRoot, "Tree root should not be nil")
	t.Logf("Root children: %d", len(m.treeRoot.Children))
	for i, c := range m.treeRoot.Children {
		t.Logf("  Child %d: ID=%s Label=%s Type=%s", i, c.ID, c.Label, c.Type)
	}

	require.Len(t, m.treeRoot.Children, 1, "Root should have 1 child (the org)")
	orgNode := m.treeRoot.Children[0]
	assert.Equal(t, TreeNodeOrg, orgNode.Type, "First child should be org")
	assert.Equal(t, "whooli", orgNode.Label, "Org label should be org name")
}

func TestBuildFilteredTree_HidesIrrelevantRepoAndWorkflow(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	org := pantry.NewOrganization("acme", "github")
	repo := pantry.NewRepository("acme", "api", "github")
	repoOther := pantry.NewRepository("acme", "docs", "github")
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/deploy.yml")
	workflowSibling := pantry.NewWorkflow(repo.ID, ".github/workflows/test.yml")
	workflowOther := pantry.NewWorkflow(repoOther.ID, ".github/workflows/lint.yml")
	job := pantry.NewJob(workflow.ID, "deploy")
	secret := pantry.NewSecret("AWS_KEY", job.ID, "github")
	token := pantry.NewToken("github_token", job.ID, []string{"contents:write"})
	cloud := pantry.NewCloud("aws", "oidc_trust", "arn:aws:iam::123456789012:role/deploy")
	vuln := pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/deploy.yml", 12)

	for _, asset := range []pantry.Asset{org, repo, repoOther, workflow, workflowSibling, workflowOther, job, secret, token, cloud, vuln} {
		require.NoError(t, m.pantry.AddAsset(asset))
	}

	require.NoError(t, m.pantry.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(org.ID, repoOther.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repo.ID, workflowSibling.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(repoOther.ID, workflowOther.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(workflow.ID, job.ID, pantry.Contains()))
	require.NoError(t, m.pantry.AddRelationship(workflow.ID, vuln.ID, pantry.VulnerableTo("injection", "critical")))
	require.NoError(t, m.pantry.AddRelationship(job.ID, secret.ID, pantry.Exposes("deploy", "")))
	require.NoError(t, m.pantry.AddRelationship(job.ID, token.ID, pantry.Exposes("deploy", "")))
	require.NoError(t, m.pantry.AddRelationship(job.ID, cloud.ID, pantry.Exposes("deploy", "")))

	m.treeFiltered = true
	m.RebuildTree()

	require.NotNil(t, m.treeRoot)
	assert.True(t, treeHasNodeID(m.treeRoot, org.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, repo.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, workflow.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, job.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, secret.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, token.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, cloud.ID))
	assert.True(t, treeHasNodeID(m.treeRoot, vuln.ID))
	assert.False(t, treeHasNodeID(m.treeRoot, workflowSibling.ID))
	assert.False(t, treeHasNodeID(m.treeRoot, repoOther.ID))
	assert.False(t, treeHasNodeID(m.treeRoot, workflowOther.ID))
}

func treeHasNodeID(root *TreeNode, nodeID string) bool {
	if root == nil {
		return false
	}
	if root.ID == nodeID {
		return true
	}
	for _, child := range root.Children {
		if treeHasNodeID(child, nodeID) {
			return true
		}
	}
	return false
}
