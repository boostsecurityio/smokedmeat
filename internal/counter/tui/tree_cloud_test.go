// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type oidcTrustTreeFixture struct {
	workflowPath string
	jobID        string
	cloudID      string
	tokenID      string
	vulnID       string
}

func TestBuildTreeFromPantry_AttachesOIDCTrustCloudUnderJob(t *testing.T) {
	p, fx := newOIDCTrustTreeFixture(t)

	root := BuildTreeFromPantry(p)
	require.NotNil(t, root)

	jobNode := findTreeNodeByID(root, fx.jobID)
	require.NotNil(t, jobNode)

	cloudNode := findTreeNodeByID(root, fx.cloudID)
	require.NotNil(t, cloudNode)
	assert.Equal(t, fx.jobID, cloudNode.Parent.ID)

	tokenNode := findTreeNodeByID(root, fx.tokenID)
	require.NotNil(t, tokenNode)
	assert.Equal(t, fx.cloudID, tokenNode.Parent.ID)

	assert.Equal(t, 1, countTreeNodesByID(root, fx.cloudID))
	assert.Equal(t, 1, countTreeNodesByID(root, fx.tokenID))
	assertRootDoesNotContainID(t, root, fx.cloudID)
	assertRootDoesNotContainID(t, root, fx.tokenID)
}

func TestBuildFilteredTree_KeepsOIDCTrustCloudPath(t *testing.T) {
	p, fx := newOIDCTrustTreeFixture(t)

	m := NewModel(Config{})
	m.pantry = p
	m.vulnerabilities = []Vulnerability{{
		ID:       fx.vulnID,
		Workflow: fx.workflowPath,
	}}
	m.suggestions = []SuggestedAction{{
		VulnIndex: 0,
	}}

	root := m.buildFilteredTree()
	require.NotNil(t, root)

	jobNode := findTreeNodeByID(root, fx.jobID)
	require.NotNil(t, jobNode)

	cloudNode := findTreeNodeByID(root, fx.cloudID)
	require.NotNil(t, cloudNode)
	assert.Equal(t, fx.jobID, cloudNode.Parent.ID)

	tokenNode := findTreeNodeByID(root, fx.tokenID)
	require.NotNil(t, tokenNode)
	assert.Equal(t, fx.cloudID, tokenNode.Parent.ID)

	assert.Equal(t, 1, countTreeNodesByID(root, fx.cloudID))
	assert.Equal(t, 1, countTreeNodesByID(root, fx.tokenID))
	assertRootDoesNotContainID(t, root, fx.cloudID)
	assertRootDoesNotContainID(t, root, fx.tokenID)
}

func newOIDCTrustTreeFixture(t *testing.T) (*pantry.Pantry, oidcTrustTreeFixture) {
	t.Helper()

	p := pantry.New()

	org := pantry.NewOrganization("whooli", "github")
	repo := pantry.NewRepository("whooli", "infrastructure-definitions", "github")
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/deploy.yml")
	job := pantry.NewJob(workflow.ID, "deploy")
	vuln := pantry.NewVulnerability("injection", "pkg:github/whooli/infrastructure-definitions", ".github/workflows/deploy.yml", 42)
	cloud := pantry.NewCloud("gcp", "oidc_trust", "sa@whooli.iam.gserviceaccount.com")
	token := pantry.NewToken("gcp_oidc", cloud.ID, []string{"iam.serviceAccounts.getAccessToken"})
	token.SetProperty("provider", "gcp")

	require.NoError(t, p.AddAsset(org))
	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(workflow))
	require.NoError(t, p.AddAsset(job))
	require.NoError(t, p.AddAsset(vuln))
	require.NoError(t, p.AddAsset(cloud))
	require.NoError(t, p.AddAsset(token))

	require.NoError(t, p.AddRelationship(org.ID, repo.ID, pantry.Contains()))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))
	require.NoError(t, p.AddRelationship(workflow.ID, job.ID, pantry.Contains()))
	require.NoError(t, p.AddRelationship(job.ID, vuln.ID, pantry.VulnerableTo("injection", "critical")))
	require.NoError(t, p.AddRelationship(job.ID, cloud.ID, pantry.Exposes("deploy", "")))
	require.NoError(t, p.AddRelationship(cloud.ID, token.ID, pantry.Contains()))

	return p, oidcTrustTreeFixture{
		workflowPath: ".github/workflows/deploy.yml",
		jobID:        job.ID,
		cloudID:      cloud.ID,
		tokenID:      token.ID,
		vulnID:       vuln.ID,
	}
}

func findTreeNodeByID(node *TreeNode, id string) *TreeNode {
	if node == nil {
		return nil
	}
	if node.ID == id {
		return node
	}
	for _, child := range node.Children {
		if found := findTreeNodeByID(child, id); found != nil {
			return found
		}
	}
	return nil
}

func countTreeNodesByID(node *TreeNode, id string) int {
	if node == nil {
		return 0
	}
	count := 0
	if node.ID == id {
		count++
	}
	for _, child := range node.Children {
		count += countTreeNodesByID(child, id)
	}
	return count
}

func assertRootDoesNotContainID(t *testing.T, root *TreeNode, id string) {
	t.Helper()
	for _, child := range root.Children {
		assert.NotEqual(t, id, child.ID)
	}
}
