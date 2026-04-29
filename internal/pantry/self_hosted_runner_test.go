// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncObservedSelfHostedRunnerTargets(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/pr.yml")
	job := NewJob(workflow.ID, "build")
	job.SetProperty("self_hosted", true)
	job.SetProperty("runs_on", NormalizeSelfHostedRunnerLabels([]string{"linux", "self-hosted", "x64"}))

	vuln := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/pr.yml", 12)
	vuln.SetProperty("job", "build")
	vuln.SetProperty("context", "issue_body")
	SetVulnerabilityExploitSupport(&vuln)

	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(workflow))
	require.NoError(t, p.AddAsset(job))
	require.NoError(t, p.AddAsset(vuln))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, Contains()))
	require.NoError(t, p.AddRelationship(workflow.ID, job.ID, Contains()))
	require.NoError(t, p.AddRelationship(job.ID, vuln.ID, VulnerableTo(vuln.RuleID, vuln.Severity)))

	created := SyncObservedSelfHostedRunnerTargets(p)
	assert.Equal(t, 1, created)

	targets := p.GetAssetsByType(AssetSelfHostedRunner)
	require.Len(t, targets, 1)

	target := targets[0]
	assert.Equal(t, StateValidated, target.State)
	assert.Equal(t, []string{"self-hosted", "linux", "x64"}, target.StringSliceProperty("label_set"))
	assert.Equal(t, []string{"build"}, target.StringSliceProperty("observed_job_names"))
	assert.Equal(t, []string{".github/workflows/pr.yml"}, target.StringSliceProperty("observed_workflow_paths"))

	edges := p.AllRelationships()
	assert.Contains(t, edges, Edge{From: repo.ID, To: target.ID, Relationship: Contains()})
	assert.Contains(t, edges, Edge{From: workflow.ID, To: target.ID, Relationship: ObservedOn()})
	assert.Contains(t, edges, Edge{From: job.ID, To: target.ID, Relationship: ObservedOn()})
}

func TestSyncObservedSelfHostedRunnerTargets_SplitsDynamicLabels(t *testing.T) {
	p := New()

	repo := NewRepository("acme", "api", "github")
	workflow := NewWorkflow(repo.ID, ".github/workflows/pr.yml")
	job := NewJob(workflow.ID, "build")
	job.SetProperty("self_hosted", true)
	job.SetProperty("runs_on", NormalizeSelfHostedRunnerLabels([]string{
		"self-hosted",
		"linux",
		"x64",
		"${{ needs.bootstrap.outputs.runner_label }}",
	}))

	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(workflow))
	require.NoError(t, p.AddAsset(job))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, Contains()))
	require.NoError(t, p.AddRelationship(workflow.ID, job.ID, Contains()))

	created := SyncObservedSelfHostedRunnerTargets(p)
	assert.Equal(t, 1, created)

	targets := p.GetAssetsByType(AssetSelfHostedRunner)
	require.Len(t, targets, 1)

	target := targets[0]
	assert.Equal(t, "linux-x64 +dynamic", target.Name)
	assert.Equal(t, []string{"self-hosted", "linux", "x64"}, target.StringSliceProperty("label_set"))
	assert.Equal(t, []string{"${{ needs.bootstrap.outputs.runner_label }}"}, target.StringSliceProperty("dynamic_label_set"))
	assert.Equal(t, []string{"self-hosted", "${{ needs.bootstrap.outputs.runner_label }}", "linux", "x64"}, target.StringSliceProperty("observed_label_set"))
}
