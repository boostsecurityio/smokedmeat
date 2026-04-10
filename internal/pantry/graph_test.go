// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPantry_New(t *testing.T) {
	p := New()
	assert.NotNil(t, p)
	assert.Equal(t, 0, p.Size())
	assert.Equal(t, 0, p.EdgeCount())
}

func TestPantry_AddAsset(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	err := p.AddAsset(repo)
	require.NoError(t, err)

	assert.Equal(t, 1, p.Size())
	assert.True(t, p.HasAsset(repo.ID))
}

func TestPantry_AddAsset_Update(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	err := p.AddAsset(repo)
	require.NoError(t, err)

	// Update the same asset
	repo.State = StateValidated
	err = p.AddAsset(repo)
	require.NoError(t, err)

	// Should still be only one asset
	assert.Equal(t, 1, p.Size())

	// State should be updated
	retrieved, err := p.GetAsset(repo.ID)
	require.NoError(t, err)
	assert.Equal(t, StateValidated, retrieved.State)
}

func TestPantry_GetAsset(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	_ = p.AddAsset(repo)

	retrieved, err := p.GetAsset(repo.ID)
	require.NoError(t, err)
	assert.Equal(t, repo.ID, retrieved.ID)
	assert.Equal(t, repo.Name, retrieved.Name)
	assert.Equal(t, AssetRepository, retrieved.Type)
}

func TestPantry_GetAsset_NotFound(t *testing.T) {
	p := New()

	_, err := p.GetAsset("nonexistent")
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestPantry_HasAsset(t *testing.T) {
	p := New()

	assert.False(t, p.HasAsset("nonexistent"))

	repo := NewRepository("acme", "api", "github")
	_ = p.AddAsset(repo)

	assert.True(t, p.HasAsset(repo.ID))
}

func TestPantry_AddRelationship(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)

	err := p.AddRelationship(repo.ID, workflow.ID, Contains())
	require.NoError(t, err)

	assert.Equal(t, 1, p.EdgeCount())
}

func TestPantry_AddRelationship_SourceNotFound(t *testing.T) {
	p := New()

	workflow := NewWorkflow("repo", ".github/workflows/ci.yml")
	_ = p.AddAsset(workflow)

	err := p.AddRelationship("nonexistent", workflow.ID, Contains())
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestPantry_AddRelationship_TargetNotFound(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	_ = p.AddAsset(repo)

	err := p.AddRelationship(repo.ID, "nonexistent", Contains())
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestPantry_GetAssetsByType(t *testing.T) {
	p := New()

	repo1 := NewRepository("acme", "api", "github")
	repo2 := NewRepository("acme", "web", "github")
	workflow := NewWorkflow(repo1.ID, ".github/workflows/ci.yml")

	_ = p.AddAsset(repo1)
	_ = p.AddAsset(repo2)
	_ = p.AddAsset(workflow)

	repos := p.GetAssetsByType(AssetRepository)
	assert.Len(t, repos, 2)

	workflows := p.GetAssetsByType(AssetWorkflow)
	assert.Len(t, workflows, 1)

	secrets := p.GetAssetsByType(AssetSecret)
	assert.Nil(t, secrets)
}

func TestPantry_AllAssets(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("AWS_KEY", "org", "github")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddAsset(secret)

	all := p.AllAssets()
	assert.Len(t, all, 3)
}

func TestPantry_AllRelationships(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("AWS_KEY", "org", "github")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddAsset(secret)

	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())
	_ = p.AddRelationship(workflow.ID, secret.ID, Exposes("deploy", "step1"))

	edges := p.AllRelationships()
	assert.Len(t, edges, 2)

	// Verify edge data
	var foundContains, foundExposes bool
	for _, e := range edges {
		if e.Relationship.Type == RelContains {
			foundContains = true
			assert.Equal(t, repo.ID, e.From)
			assert.Equal(t, workflow.ID, e.To)
		}
		if e.Relationship.Type == RelExposes {
			foundExposes = true
			assert.Equal(t, workflow.ID, e.From)
			assert.Equal(t, secret.ID, e.To)
			assert.Equal(t, "deploy", e.Relationship.Properties["job"])
		}
	}
	assert.True(t, foundContains)
	assert.True(t, foundExposes)
}

func TestPantry_VulnBearingSubgraph_HidesIrrelevantRepoAndWorkflow(t *testing.T) {
	p := New()

	org := NewOrganization("acme", "github")
	repo := NewRepository("acme", "api", "github")
	repoOther := NewRepository("acme", "docs", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/deploy.yml")
	workflowSibling := NewWorkflow(repo.ID, ".github/workflows/test.yml")
	workflowOther := NewWorkflow(repoOther.ID, ".github/workflows/lint.yml")
	job := NewJob(workflow.ID, "deploy")
	secret := NewSecret("AWS_KEY", job.ID, "github")
	token := NewToken("github_token", job.ID, []string{"contents:write"})
	cloud := NewCloud("aws", "oidc_trust", "arn:aws:iam::123456789012:role/deploy")
	vuln := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/deploy.yml", 12)

	for _, asset := range []Asset{org, repo, repoOther, workflow, workflowSibling, workflowOther, job, secret, token, cloud, vuln} {
		require.NoError(t, p.AddAsset(asset))
	}

	require.NoError(t, p.AddRelationship(org.ID, repo.ID, Contains()))
	require.NoError(t, p.AddRelationship(org.ID, repoOther.ID, Contains()))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, Contains()))
	require.NoError(t, p.AddRelationship(repo.ID, workflowSibling.ID, Contains()))
	require.NoError(t, p.AddRelationship(repoOther.ID, workflowOther.ID, Contains()))
	require.NoError(t, p.AddRelationship(workflow.ID, job.ID, Contains()))
	require.NoError(t, p.AddRelationship(workflow.ID, vuln.ID, VulnerableTo("injection", "critical")))
	require.NoError(t, p.AddRelationship(job.ID, secret.ID, Exposes("deploy", "")))
	require.NoError(t, p.AddRelationship(job.ID, token.ID, Exposes("deploy", "")))
	require.NoError(t, p.AddRelationship(job.ID, cloud.ID, Exposes("deploy", "")))

	filtered := p.VulnBearingSubgraph()

	assert.True(t, filtered.HasAsset(org.ID))
	assert.True(t, filtered.HasAsset(repo.ID))
	assert.True(t, filtered.HasAsset(workflow.ID))
	assert.True(t, filtered.HasAsset(job.ID))
	assert.True(t, filtered.HasAsset(secret.ID))
	assert.True(t, filtered.HasAsset(token.ID))
	assert.True(t, filtered.HasAsset(cloud.ID))
	assert.True(t, filtered.HasAsset(vuln.ID))
	assert.False(t, filtered.HasAsset(workflowSibling.ID))
	assert.False(t, filtered.HasAsset(repoOther.ID))
	assert.False(t, filtered.HasAsset(workflowOther.ID))
}

func TestPantry_VulnBearingSubgraph_NoVulnerabilities(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")

	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(workflow))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, Contains()))

	filtered := p.VulnBearingSubgraph()

	assert.Equal(t, 0, filtered.Size())
	assert.Equal(t, 0, filtered.EdgeCount())
}

func TestPantry_GetNeighbors(t *testing.T) {
	p := New()

	// Create a graph: repo -> workflow -> secret
	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("AWS_KEY", "org", "github")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddAsset(secret)

	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())
	_ = p.AddRelationship(workflow.ID, secret.ID, Exposes("", ""))

	// 0 hops = just the source
	neighbors, err := p.GetNeighbors(repo.ID, 0)
	require.NoError(t, err)
	assert.Len(t, neighbors, 1)
	assert.Equal(t, repo.ID, neighbors[0].ID)

	// 1 hop = source + direct neighbors
	neighbors, err = p.GetNeighbors(repo.ID, 1)
	require.NoError(t, err)
	assert.Len(t, neighbors, 2) // repo + workflow

	// 2 hops = all three
	neighbors, err = p.GetNeighbors(repo.ID, 2)
	require.NoError(t, err)
	assert.Len(t, neighbors, 3) // repo + workflow + secret
}

func TestPantry_GetNeighbors_NotFound(t *testing.T) {
	p := New()

	_, err := p.GetNeighbors("nonexistent", 1)
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestPantry_UpdateAssetState(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	_ = p.AddAsset(repo)

	err := p.UpdateAssetState(repo.ID, StateExploited)
	require.NoError(t, err)

	retrieved, _ := p.GetAsset(repo.ID)
	assert.Equal(t, StateExploited, retrieved.State)
}

func TestPantry_UpdateAssetState_NotFound(t *testing.T) {
	p := New()

	err := p.UpdateAssetState("nonexistent", StateExploited)
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestPantry_FindVulnerabilities(t *testing.T) {
	p := New()

	vuln1 := NewVulnerability("injection", "pkg:github/acme/api", "ci.yml", 10)
	vuln2 := NewVulnerability("debug_enabled", "pkg:github/acme/api", "ci.yml", 20)
	repo := NewRepository("acme", "api", "github")

	_ = p.AddAsset(vuln1)
	_ = p.AddAsset(vuln2)
	_ = p.AddAsset(repo)

	vulns := p.FindVulnerabilities()
	assert.Len(t, vulns, 2)
}

func TestPantry_FindSecrets(t *testing.T) {
	p := New()

	secret1 := NewSecret("AWS_KEY", "org", "github")
	secret2 := NewSecret("NPM_TOKEN", "repo", "github")
	repo := NewRepository("acme", "api", "github")

	_ = p.AddAsset(secret1)
	_ = p.AddAsset(secret2)
	_ = p.AddAsset(repo)

	secrets := p.FindSecrets()
	assert.Len(t, secrets, 2)
}

func TestPantry_FindHighValueTargets(t *testing.T) {
	p := New()

	secret := NewSecret("AWS_KEY", "org", "github") // Secrets are high value by default
	repo := NewRepository("acme", "api", "github")

	_ = p.AddAsset(secret)
	_ = p.AddAsset(repo)

	targets := p.FindHighValueTargets()
	assert.Len(t, targets, 1)
	assert.Equal(t, secret.ID, targets[0].ID)
}

func TestPantry_GetAttackPaths(t *testing.T) {
	p := New()

	// Create a graph: repo -> workflow -> secret
	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("AWS_KEY", "org", "github")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddAsset(secret)

	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())
	_ = p.AddRelationship(workflow.ID, secret.ID, Exposes("", ""))

	// Find paths from repo to secrets
	paths := p.GetAttackPaths(repo.ID, []AssetType{AssetSecret})
	assert.Len(t, paths, 1)
	assert.Len(t, paths[0], 3) // repo -> workflow -> secret
}

func TestPantry_GetAttackPaths_NoPath(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	secret := NewSecret("AWS_KEY", "org", "github")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(secret)
	// No edge connecting them

	paths := p.GetAttackPaths(repo.ID, []AssetType{AssetSecret})
	assert.Len(t, paths, 0)
}

func TestPantry_GetAttackPaths_NonexistentSource(t *testing.T) {
	p := New()

	paths := p.GetAttackPaths("nonexistent", []AssetType{AssetSecret})
	assert.Nil(t, paths)
}

func TestPantry_Clear(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())

	assert.Equal(t, 2, p.Size())
	assert.Equal(t, 1, p.EdgeCount())

	p.Clear()

	assert.Equal(t, 0, p.Size())
	assert.Equal(t, 0, p.EdgeCount())
}

func TestPantry_Size(t *testing.T) {
	p := New()
	assert.Equal(t, 0, p.Size())

	_ = p.AddAsset(NewRepository("acme", "api", "github"))
	assert.Equal(t, 1, p.Size())

	_ = p.AddAsset(NewRepository("acme", "web", "github"))
	assert.Equal(t, 2, p.Size())
}

func TestPantry_EdgeCount(t *testing.T) {
	p := New()
	assert.Equal(t, 0, p.EdgeCount())

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())

	assert.Equal(t, 1, p.EdgeCount())
}

func TestPantry_RemoveAsset(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	_ = p.AddAsset(repo)
	assert.Equal(t, 1, p.Size())

	err := p.RemoveAsset(repo.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, p.Size())
	assert.False(t, p.HasAsset(repo.ID))
}

func TestPantry_RemoveAsset_RemovesEdges(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	secret := NewSecret("AWS_KEY", "org", "github")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddAsset(secret)
	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())
	_ = p.AddRelationship(workflow.ID, secret.ID, Exposes("", ""))

	assert.Equal(t, 2, p.EdgeCount())

	err := p.RemoveAsset(workflow.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, p.Size())
	assert.Equal(t, 0, p.EdgeCount())
}

func TestPantry_RemoveAsset_NotFound(t *testing.T) {
	p := New()

	err := p.RemoveAsset("nonexistent")
	assert.ErrorIs(t, err, ErrAssetNotFound)
}

func TestPantry_RemoveRelationship(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)
	_ = p.AddRelationship(repo.ID, workflow.ID, Contains())

	assert.Equal(t, 1, p.EdgeCount())

	err := p.RemoveRelationship(repo.ID, workflow.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, p.EdgeCount())
	assert.Equal(t, 2, p.Size())
}

func TestPantry_RemoveRelationship_NotFound(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")

	_ = p.AddAsset(repo)
	_ = p.AddAsset(workflow)

	err := p.RemoveRelationship(repo.ID, workflow.ID)
	assert.Error(t, err)
}

func TestPantry_AddAsset_PreservesProperties(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	repo.SetProperty("private", true)
	repo.SetProperty("discovered_by", "install-token")
	require.NoError(t, p.AddAsset(repo))

	retrieved, err := p.GetAsset(repo.ID)
	require.NoError(t, err)
	assert.Equal(t, true, retrieved.Properties["private"])

	updated := NewRepository("acme", "api", "github")
	updated.State = StateValidated
	updated.SetProperty("discovered_by", "analysis")
	require.NoError(t, p.AddAsset(updated))

	assert.Equal(t, 1, p.Size())

	final, err := p.GetAsset(repo.ID)
	require.NoError(t, err)
	assert.Equal(t, StateValidated, final.State, "State should be updated")
	assert.Equal(t, true, final.Properties["private"], "Old property should be preserved")
	assert.Equal(t, "analysis", final.Properties["discovered_by"], "New property should override old")
}

func TestPantry_AddAsset_PropertyChangeNotifiesObserver(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	require.NoError(t, p.AddAsset(repo))

	var updatedAssets []Asset
	obs := &testObserver{
		onUpdated: func(a Asset, _ AssetState) { updatedAssets = append(updatedAssets, a) },
	}
	p.AddObserver(obs)

	updated := NewRepository("acme", "api", "github")
	updated.SetProperty("private", true)
	require.NoError(t, p.AddAsset(updated))

	require.Len(t, updatedAssets, 1, "property change should fire OnAssetUpdated")
	assert.Equal(t, true, updatedAssets[0].Properties["private"])
}

func TestPantry_AddAsset_NoPropertyChangeNoNotification(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	require.NoError(t, p.AddAsset(repo))

	var updateCount int
	obs := &testObserver{
		onUpdated: func(_ Asset, _ AssetState) { updateCount++ },
	}
	p.AddObserver(obs)

	same := NewRepository("acme", "api", "github")
	require.NoError(t, p.AddAsset(same))

	assert.Equal(t, 0, updateCount, "identical re-add should not fire observer")
}

func TestPantry_AddAsset_SlicePropertyNoPanic(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	repo.SetProperty("permissions", []interface{}{"read", "write"})
	require.NoError(t, p.AddAsset(repo))

	updated := NewRepository("acme", "api", "github")
	updated.SetProperty("private", true)
	require.NoError(t, p.AddAsset(updated))

	final, err := p.GetAsset(repo.ID)
	require.NoError(t, err)
	assert.Equal(t, true, final.Properties["private"])
	assert.Equal(t, []interface{}{"read", "write"}, final.Properties["permissions"])
}

type testObserver struct {
	onAdded   func(Asset)
	onUpdated func(Asset, AssetState)
}

func (o *testObserver) OnAssetAdded(a Asset) {
	if o.onAdded != nil {
		o.onAdded(a)
	}
}
func (o *testObserver) OnAssetUpdated(a Asset, old AssetState) {
	if o.onUpdated != nil {
		o.onUpdated(a, old)
	}
}
func (o *testObserver) OnRelationshipAdded(_, _ string, _ Relationship) {}
func (o *testObserver) OnAssetRemoved(_ string)                         {}
func (o *testObserver) OnRelationshipRemoved(_, _ string)               {}

func TestPantry_JSON_OrganizationRoundTrip(t *testing.T) {
	p := New()

	org := NewOrganization("whooli", "github")
	_ = p.AddAsset(org)

	repo := NewRepository("whooli", "xyz", "github")
	_ = p.AddAsset(repo)

	_ = p.AddRelationship(org.ID, repo.ID, Contains())

	assert.Equal(t, 2, p.Size())
	assert.Equal(t, 1, len(p.GetAssetsByType(AssetOrganization)))
	assert.Equal(t, 1, len(p.GetAssetsByType(AssetRepository)))
	assert.Equal(t, 1, p.EdgeCount())

	// Serialize
	data, err := p.MarshalJSON()
	require.NoError(t, err)

	// Deserialize into new pantry
	p2 := New()
	err = p2.UnmarshalJSON(data)
	require.NoError(t, err)

	// Verify all data survived round-trip
	assert.Equal(t, 2, p2.Size())
	orgs := p2.GetAssetsByType(AssetOrganization)
	require.Len(t, orgs, 1, "Should have 1 organization after JSON round-trip")
	assert.Equal(t, "whooli", orgs[0].Name)
	assert.Equal(t, AssetOrganization, orgs[0].Type)

	repos := p2.GetAssetsByType(AssetRepository)
	require.Len(t, repos, 1)
	assert.Equal(t, "xyz", repos[0].Name)

	assert.Equal(t, 1, p2.EdgeCount())
}
