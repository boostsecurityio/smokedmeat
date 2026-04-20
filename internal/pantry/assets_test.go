// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAsset(t *testing.T) {
	asset := NewAsset("test-id", AssetRepository, "test-name")

	assert.Equal(t, "test-id", asset.ID)
	assert.Equal(t, AssetRepository, asset.Type)
	assert.Equal(t, "test-name", asset.Name)
	assert.Equal(t, StateNew, asset.State)
	assert.Equal(t, "recon", asset.DiscoveredBy)
	assert.NotNil(t, asset.Properties)
	assert.False(t, asset.DiscoveredAt.IsZero())
}

func TestNewRepository(t *testing.T) {
	repo := NewRepository("acme", "api", "github")

	assert.Equal(t, "github:acme/api", repo.ID)
	assert.Equal(t, "api", repo.Name)
	assert.Equal(t, AssetRepository, repo.Type)
	assert.Equal(t, "github", repo.Provider)
	assert.Equal(t, "acme", repo.Properties["org"])
	assert.Equal(t, "api", repo.Properties["repo"])
}

func TestNewRepository_GitLab(t *testing.T) {
	repo := NewRepository("mygroup", "myproject", "gitlab")

	assert.Equal(t, "gitlab:mygroup/myproject", repo.ID)
	assert.Equal(t, "gitlab", repo.Provider)
}

func TestNewWorkflow(t *testing.T) {
	repoID := "github:acme/api"
	workflow := NewWorkflow(repoID, ".github/workflows/ci.yml")

	assert.Equal(t, "github:acme/api:workflow:.github/workflows/ci.yml", workflow.ID)
	assert.Equal(t, "ci.yml", workflow.Name)
	assert.Equal(t, AssetWorkflow, workflow.Type)
	assert.Equal(t, ".github/workflows/ci.yml", workflow.Properties["path"])
	assert.Equal(t, repoID, workflow.Properties["repo_id"])
}

func TestNewWorkflow_NestedPath(t *testing.T) {
	workflow := NewWorkflow("repo", "workflows/nested/build.yml")

	assert.Equal(t, "build.yml", workflow.Name)
	assert.Equal(t, "workflows/nested/build.yml", workflow.Properties["path"])
}

func TestNewJob(t *testing.T) {
	workflowID := "github:acme/api:workflow:ci.yml"
	job := NewJob(workflowID, "build")

	assert.Equal(t, "github:acme/api:workflow:ci.yml:job:build", job.ID)
	assert.Equal(t, "build", job.Name)
	assert.Equal(t, AssetJob, job.Type)
	assert.Equal(t, workflowID, job.Properties["workflow_id"])
}

func TestNewSecret(t *testing.T) {
	secret := NewSecret("AWS_ACCESS_KEY", "org", "github")

	assert.Equal(t, "github:secret:org:AWS_ACCESS_KEY", secret.ID)
	assert.Equal(t, "AWS_ACCESS_KEY", secret.Name)
	assert.Equal(t, AssetSecret, secret.Type)
	assert.Equal(t, "github", secret.Provider)
	assert.Equal(t, "org", secret.Properties["scope"])
	assert.Equal(t, StateHighValue, secret.State) // Secrets are always high value
}

func TestNewToken(t *testing.T) {
	token := NewToken("GITHUB_TOKEN", "acme/api", []string{"contents:write", "issues:read"})

	assert.Equal(t, "token:GITHUB_TOKEN:acme/api", token.ID)
	assert.Equal(t, "GITHUB_TOKEN", token.Name)
	assert.Equal(t, AssetToken, token.Type)
	assert.Equal(t, "GITHUB_TOKEN", token.Properties["token_type"])
	assert.Equal(t, "acme/api", token.Properties["scope"])
	assert.Equal(t, []string{"contents:write", "issues:read"}, token.Properties["scopes"])
}

func TestNewCloud(t *testing.T) {
	cloud := NewCloud("aws", "s3", "prod-bucket")

	assert.Equal(t, "aws:s3:prod-bucket", cloud.ID)
	assert.Equal(t, "s3/prod-bucket", cloud.Name)
	assert.Equal(t, AssetCloud, cloud.Type)
	assert.Equal(t, "aws", cloud.Provider)
	assert.Equal(t, "s3", cloud.Properties["resource_type"])
	assert.Equal(t, "prod-bucket", cloud.Properties["identifier"])
}

func TestNewAgent(t *testing.T) {
	agent := NewAgent("agent-123", "runner-1", "linux")

	assert.Equal(t, "agent:agent-123", agent.ID)
	assert.Equal(t, "runner-1", agent.Name)
	assert.Equal(t, AssetAgent, agent.Type)
	assert.Equal(t, "agent-123", agent.Properties["agent_id"])
	assert.Equal(t, "runner-1", agent.Properties["hostname"])
	assert.Equal(t, "linux", agent.Properties["platform"])
}

func TestNewVulnerability(t *testing.T) {
	vuln := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 42)

	assert.Equal(t, "vuln:injection:.github/workflows/ci.yml:42", vuln.ID)
	assert.Equal(t, "injection", vuln.Name)
	assert.Equal(t, AssetVulnerability, vuln.Type)
	assert.Equal(t, "injection", vuln.RuleID)
	assert.Equal(t, "pkg:github/acme/api", vuln.Purl)
	assert.Equal(t, ".github/workflows/ci.yml", vuln.Properties["path"])
	assert.Equal(t, 42, vuln.Properties["line"])
	assert.Equal(t, "critical", vuln.Severity) // injection is critical
	_, hasSupported := vuln.Properties["exploit_supported"]
	assert.False(t, hasSupported)
	_, hasReason := vuln.Properties["exploit_support_reason"]
	assert.False(t, hasReason)
}

func TestNewVulnerability_WithDiscriminator(t *testing.T) {
	first := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 42, "issue_body")
	second := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 42, "issue_title")
	third := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 42, "issue", "body")

	assert.NotEqual(t, first.ID, second.ID)
	assert.Contains(t, first.ID, "vuln:injection:.github/workflows/ci.yml:42:")
	assert.Contains(t, second.ID, "vuln:injection:.github/workflows/ci.yml:42:")
	assert.NotEqual(t, first.ID, third.ID)
}

func TestNewVulnerability_SetsAnalyzeOnlyMetadata(t *testing.T) {
	vuln := NewVulnerability("pr_runs_on_self_hosted", "pkg:github/acme/api", ".github/workflows/pr.yml", 19)
	SetVulnerabilityExploitSupport(&vuln)

	assert.Equal(t, false, vuln.Properties["exploit_supported"])
	assert.Equal(t, "Self-hosted runner findings are analyze-only in v0.1.0. Exploit actions are not supported yet.", vuln.Properties["exploit_support_reason"])
}

func TestNewVulnerability_WorkflowDispatchIsExploitable(t *testing.T) {
	vuln := NewVulnerability("workflow_dispatch", "pkg:github/acme/api", ".github/workflows/deploy.yml", 0)
	SetVulnerabilityExploitSupport(&vuln)

	assert.Equal(t, true, vuln.Properties["exploit_supported"])
	_, hasReason := vuln.Properties["exploit_support_reason"]
	assert.False(t, hasReason)
}

func TestSetVulnerabilityExploitSupport_QuotedHeredocIsAnalyzeOnly(t *testing.T) {
	vuln := NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 42)
	vuln.SetProperty("bash_context", "bash_heredoc_quoted")

	SetVulnerabilityExploitSupport(&vuln)

	assert.Equal(t, false, vuln.Properties["exploit_supported"])
	assert.Equal(t, "Quoted heredoc bodies do not evaluate shell substitutions.", vuln.Properties["exploit_support_reason"])
}

func TestClassifyRuleSeverity(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"untrusted_checkout_exec", "critical"},
		{"injection", "critical"},
		{"pr_runs_on_self_hosted", "critical"},
		{"debug_enabled", "high"},
		{"unverified_script_exec", "high"},
		{"known_vulnerability_in_runner", "high"},
		{"excessive_permissions", "high"},
		{"unknown_rule", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			assert.Equal(t, tt.expected, classifyRuleSeverity(tt.ruleID))
		})
	}
}

func TestAsset_SetState(t *testing.T) {
	asset := NewAsset("test", AssetRepository, "test")
	assert.Equal(t, StateNew, asset.State)

	asset.SetState(StateExploited)
	assert.Equal(t, StateExploited, asset.State)
}

func TestAsset_SetDiscoveredBy(t *testing.T) {
	asset := NewAsset("test", AssetRepository, "test")
	assert.Equal(t, "recon", asset.DiscoveredBy)

	asset.SetDiscoveredBy("agent-123")
	assert.Equal(t, "agent-123", asset.DiscoveredBy)
}

func TestAsset_SetProperty(t *testing.T) {
	asset := NewAsset("test", AssetRepository, "test")

	asset.SetProperty("custom_key", "custom_value")
	assert.Equal(t, "custom_value", asset.Properties["custom_key"])

	asset.SetProperty("numeric", 42)
	assert.Equal(t, 42, asset.Properties["numeric"])
}

func TestAsset_GetProperty(t *testing.T) {
	asset := NewAsset("test", AssetRepository, "test")
	asset.SetProperty("key", "value")

	val, ok := asset.GetProperty("key")
	assert.True(t, ok)
	assert.Equal(t, "value", val)

	val, ok = asset.GetProperty("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestAsset_GetProperty_NilProperties(t *testing.T) {
	asset := Asset{ID: "test"}

	val, ok := asset.GetProperty("key")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestAsset_SetProperty_NilProperties(t *testing.T) {
	asset := Asset{ID: "test"}

	// Should not panic
	asset.SetProperty("key", "value")
	assert.Equal(t, "value", asset.Properties["key"])
}
