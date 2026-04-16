// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"context"
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
)

// =============================================================================
// AnalysisResult Tests
// =============================================================================

func TestAnalysisResult_Fields(t *testing.T) {
	result := AnalysisResult{
		Success:          true,
		Target:           "acme/api",
		TargetType:       "repo",
		Repository:       "acme/api",
		ReposAnalyzed:    1,
		TotalFindings:    5,
		CriticalFindings: 1,
		HighFindings:     2,
		MediumFindings:   1,
		LowFindings:      1,
		Findings: []Finding{
			{ID: "V001", Severity: "critical"},
		},
		Errors: []string{"partial failure"},
	}

	assert.True(t, result.Success)
	assert.Equal(t, "acme/api", result.Target)
	assert.Equal(t, "repo", result.TargetType)
	assert.Equal(t, "acme/api", result.Repository)
	assert.Equal(t, 1, result.ReposAnalyzed)
	assert.Equal(t, 5, result.TotalFindings)
	assert.Equal(t, 1, result.CriticalFindings)
	assert.Equal(t, 2, result.HighFindings)
	assert.Equal(t, 1, result.MediumFindings)
	assert.Equal(t, 1, result.LowFindings)
	assert.Len(t, result.Findings, 1)
	assert.Len(t, result.Errors, 1)
}

func TestAnalysisResult_Empty(t *testing.T) {
	result := AnalysisResult{}

	assert.False(t, result.Success)
	assert.Empty(t, result.Target)
	assert.Empty(t, result.Findings)
	assert.Empty(t, result.Errors)
	assert.Equal(t, 0, result.TotalFindings)
}

// =============================================================================
// Finding Tests
// =============================================================================

func TestFinding_AllFields(t *testing.T) {
	finding := Finding{
		ID:          "V001",
		Repository:  "acme/api",
		Workflow:    ".github/workflows/ci.yml",
		Line:        42,
		Job:         "build",
		Step:        "Run tests",
		RuleID:      "injection",
		Title:       "Command Injection",
		Description: "Untrusted input in run step",
		Severity:    "critical",
		Details:     "uses ${{ github.event.pull_request.title }}",
		Context:     "pr_title",
		Trigger:     "pull_request",
		Expression:  "${{ github.event.pull_request.title }}",
		Fingerprint: "abc123",
	}

	assert.Equal(t, "V001", finding.ID)
	assert.Equal(t, "acme/api", finding.Repository)
	assert.Equal(t, ".github/workflows/ci.yml", finding.Workflow)
	assert.Equal(t, 42, finding.Line)
	assert.Equal(t, "build", finding.Job)
	assert.Equal(t, "Run tests", finding.Step)
	assert.Equal(t, "injection", finding.RuleID)
	assert.Equal(t, "Command Injection", finding.Title)
	assert.Equal(t, "Untrusted input in run step", finding.Description)
	assert.Equal(t, "critical", finding.Severity)
	assert.Equal(t, "uses ${{ github.event.pull_request.title }}", finding.Details)
	assert.Equal(t, "pr_title", finding.Context)
	assert.Equal(t, "pull_request", finding.Trigger)
	assert.Equal(t, "${{ github.event.pull_request.title }}", finding.Expression)
	assert.Equal(t, "abc123", finding.Fingerprint)
}

// =============================================================================
// determineContext Tests
// =============================================================================

func TestDetermineContext_GithubScript(t *testing.T) {
	tests := []struct {
		name     string
		details  string
		expected string
	}{
		{"actions/github-script", "uses actions/github-script@v6", "github_script"},
		{"github.event with script", "github.event.issue.body in script block", "github_script"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := results.FindingMeta{Details: tt.details}
			assert.Equal(t, tt.expected, determineContext("", meta))
		})
	}
}

func TestDetermineContext_GitBranch(t *testing.T) {
	tests := []struct {
		name     string
		details  string
		expected string
	}{
		{"github.head_ref", "uses github.head_ref in checkout", "git_branch"},
		{"branch keyword", "branch name from PR", "git_branch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := results.FindingMeta{Details: tt.details}
			assert.Equal(t, tt.expected, determineContext("", meta))
		})
	}
}

func TestDetermineContext_PRTitle(t *testing.T) {
	tests := []struct {
		name     string
		details  string
		expected string
	}{
		{"pull_request.title", "uses pull_request.title in run", "pr_title"},
		{"pr title", "pr title used in command", "pr_title"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := results.FindingMeta{Details: tt.details}
			assert.Equal(t, tt.expected, determineContext("", meta))
		})
	}
}

func TestDetermineContext_PRBody(t *testing.T) {
	tests := []struct {
		name     string
		details  string
		expected string
	}{
		{"pull_request.body", "uses pull_request.body in run", "pr_body"},
		{"pr body", "pr body passed to script", "pr_body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := results.FindingMeta{Details: tt.details}
			assert.Equal(t, tt.expected, determineContext("", meta))
		})
	}
}

func TestDetermineContext_IssueTitle(t *testing.T) {
	meta := results.FindingMeta{Details: "uses issue.title in automation"}
	assert.Equal(t, "issue_title", determineContext("", meta))
}

func TestDetermineContext_IssueBody(t *testing.T) {
	meta := results.FindingMeta{Details: "issue.body content is parsed"}
	assert.Equal(t, "issue_body", determineContext("", meta))
}

func TestDetermineContext_CommentBody(t *testing.T) {
	tests := []struct {
		name    string
		details string
	}{
		{"github.event.comment.body", "Sources: github.event.comment.body"},
		{"comment.body pattern", "uses comment.body in automation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := results.FindingMeta{Details: tt.details}
			assert.Equal(t, "comment_body", determineContext("", meta))
		})
	}
}

func TestDetermineContext_CommitMessage(t *testing.T) {
	meta := results.FindingMeta{Details: "commit message used in build"}
	assert.Equal(t, "commit_message", determineContext("", meta))
}

func TestDetermineContext_DefaultInjection(t *testing.T) {
	meta := results.FindingMeta{Details: "some generic details"}
	assert.Equal(t, "bash_run", determineContext("injection", meta))
}

func TestDetermineContext_Unknown(t *testing.T) {
	meta := results.FindingMeta{Details: "some generic details"}
	assert.Equal(t, "unknown", determineContext("other_rule", meta))
}

func TestDetermineContext_CaseInsensitive(t *testing.T) {
	meta := results.FindingMeta{Details: "GITHUB.HEAD_REF used here"}
	assert.Equal(t, "git_branch", determineContext("", meta))
}

// =============================================================================
// convertFindings Tests
// =============================================================================

func TestConvertFindings_Empty(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	convertFindings(result, nil)

	assert.Empty(t, result.Findings)
	assert.Equal(t, 0, result.TotalFindings)
}

func TestConvertFindings_EmptyPackageList(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	convertFindings(result, []*models.PackageInsights{})

	assert.Empty(t, result.Findings)
	assert.Equal(t, 0, result.TotalFindings)
}

func TestConvertFindings_NilPackage(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	convertFindings(result, []*models.PackageInsights{nil})

	assert.Empty(t, result.Findings)
}

func TestConvertFindings_PackageWithNoFindings(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{},
		},
	}
	convertFindings(result, []*models.PackageInsights{pkg})

	assert.Empty(t, result.Findings)
}

func TestConvertFindings_SingleFinding(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{
					RuleId: "injection",
					Meta: results.FindingMeta{
						Path:    ".github/workflows/ci.yml",
						Line:    42,
						Job:     "build",
						Step:    "test",
						Details: "uses ${{ github.event.pull_request.title }}",
					},
				},
			},
			Rules: map[string]results.Rule{
				"injection": {
					Title:       "Command Injection",
					Description: "Untrusted input in run step",
					Level:       "error",
				},
			},
		},
	}

	convertFindings(result, []*models.PackageInsights{pkg})

	require.Len(t, result.Findings, 1)
	assert.Equal(t, "V001", result.Findings[0].ID)
	assert.Equal(t, "acme/api", result.Findings[0].Repository)
	assert.Equal(t, ".github/workflows/ci.yml", result.Findings[0].Workflow)
	assert.Equal(t, 42, result.Findings[0].Line)
	assert.Equal(t, "build", result.Findings[0].Job)
	assert.Equal(t, "test", result.Findings[0].Step)
	assert.Equal(t, "injection", result.Findings[0].RuleID)
	assert.Equal(t, "Command Injection", result.Findings[0].Title)
	assert.Equal(t, "critical", result.Findings[0].Severity)
	assert.Equal(t, "pr_title", result.Findings[0].Context)
	assert.Equal(t, "${{ github.event.pull_request.title }}", result.Findings[0].Expression)
	assert.Equal(t, 1, result.TotalFindings)
	assert.Equal(t, 1, result.CriticalFindings)
}

func TestConvertFindings_MultipleSeverities(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{RuleId: "rule1", Meta: results.FindingMeta{}},
				{RuleId: "rule2", Meta: results.FindingMeta{}},
				{RuleId: "rule3", Meta: results.FindingMeta{}},
				{RuleId: "rule4", Meta: results.FindingMeta{}},
			},
			Rules: map[string]results.Rule{
				"rule1": {Level: "error"},   // critical
				"rule2": {Level: "warning"}, // high
				"rule3": {Level: "note"},    // medium
				"rule4": {Level: "info"},    // low
			},
		},
	}

	convertFindings(result, []*models.PackageInsights{pkg})

	assert.Equal(t, 4, result.TotalFindings)
	assert.Equal(t, 1, result.CriticalFindings)
	assert.Equal(t, 1, result.HighFindings)
	assert.Equal(t, 1, result.MediumFindings)
	assert.Equal(t, 1, result.LowFindings)
}

func TestConvertFindings_IDGeneration(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{RuleId: "r1", Meta: results.FindingMeta{}},
				{RuleId: "r2", Meta: results.FindingMeta{}},
				{RuleId: "r3", Meta: results.FindingMeta{}},
			},
			Rules: map[string]results.Rule{},
		},
	}

	convertFindings(result, []*models.PackageInsights{pkg})

	assert.Equal(t, "V001", result.Findings[0].ID)
	assert.Equal(t, "V002", result.Findings[1].ID)
	assert.Equal(t, "V003", result.Findings[2].ID)
}

func TestConvertFindings_PopulatesAnalyzedRepos(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	packages := []*models.PackageInsights{
		{
			Purl: "pkg:github/acme/api",
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{
					{RuleId: "r1", Meta: results.FindingMeta{}},
				},
				Rules: map[string]results.Rule{},
			},
		},
		{
			Purl: "pkg:github/acme/frontend",
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{},
				Rules:    map[string]results.Rule{},
			},
		},
		{
			Purl: "pkg:github/acme/api",
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{},
				Rules:    map[string]results.Rule{},
			},
		},
	}

	convertFindings(result, packages)

	assert.Len(t, result.AnalyzedRepos, 2, "should deduplicate repos")
	assert.Contains(t, result.AnalyzedRepos, "acme/api")
	assert.Contains(t, result.AnalyzedRepos, "acme/frontend")
}

func TestConvertFindings_AnalyzedReposEmpty(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	convertFindings(result, []*models.PackageInsights{nil})

	assert.Empty(t, result.AnalyzedRepos)
}

func TestConvertFindings_MultiplePackages(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	packages := []*models.PackageInsights{
		{
			Purl: "pkg:github/acme/api",
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{
					{RuleId: "r1", Meta: results.FindingMeta{}},
				},
				Rules: map[string]results.Rule{},
			},
		},
		{
			Purl: "pkg:github/acme/frontend",
			FindingsResults: results.FindingsResult{
				Findings: []results.Finding{
					{RuleId: "r2", Meta: results.FindingMeta{}},
				},
				Rules: map[string]results.Rule{},
			},
		},
	}

	convertFindings(result, packages)

	require.Len(t, result.Findings, 2)
	assert.Equal(t, "acme/api", result.Findings[0].Repository)
	assert.Equal(t, "acme/frontend", result.Findings[1].Repository)
	assert.Equal(t, "V001", result.Findings[0].ID)
	assert.Equal(t, "V002", result.Findings[1].ID)
}

func TestConvertFindings_MissingRule(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/api",
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{RuleId: "unknown_rule", Meta: results.FindingMeta{}},
			},
			Rules: map[string]results.Rule{}, // Empty rules map
		},
	}

	convertFindings(result, []*models.PackageInsights{pkg})

	require.Len(t, result.Findings, 1)
	assert.Empty(t, result.Findings[0].Title)
	assert.Empty(t, result.Findings[0].Description)
	assert.Empty(t, result.Findings[0].Severity) // No severity when rule not found
}

func TestBuildWorkflowVictimIndex_CollectsEachWorkflowOnce(t *testing.T) {
	pkg := &models.PackageInsights{
		SourceGitRepoPath: "/tmp/acme-api",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{Path: ".github/workflows/build.yml"},
			{Path: ".github/workflows/deploy.yml"},
			{Path: "README.md"},
		},
	}

	calls := make(map[string]int)
	byPath, repoVictims := buildWorkflowVictimIndex(pkg, "acme/api", func(repository, root string, workflow models.GithubActionsWorkflow) []cachepoison.VictimCandidate {
		assert.Equal(t, "acme/api", repository)
		assert.Equal(t, "/tmp/acme-api", root)
		calls[workflow.Path]++
		return []cachepoison.VictimCandidate{{
			ID:         workflow.Path,
			Repository: repository,
			Workflow:   workflow.Path,
		}}
	})

	require.Len(t, byPath, 2)
	assert.Len(t, repoVictims, 2)
	assert.Equal(t, 1, calls[".github/workflows/build.yml"])
	assert.Equal(t, 1, calls[".github/workflows/deploy.yml"])
	assert.Zero(t, calls["README.md"])
}

func TestConvertFindings_SetupGoVersionFileVictimStaysReadyWithoutRepoPath(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl:              "pkg:github/whooli/infrastructure-definitions",
		SourceGitRepoPath: "",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/benchmark-bot.yml",
				Events: models.GithubActionsEvents{
					{Name: "issue_comment"},
				},
			},
			{
				Path: ".github/workflows/deploy.yml",
				Events: models.GithubActionsEvents{
					{Name: "workflow_dispatch"},
				},
				Jobs: models.GithubActionsJobs{
					{
						ID: "sync",
						Steps: models.GithubActionsSteps{
							{
								Uses: "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
							},
							{
								Uses: "actions/setup-go@v5",
								With: models.GithubActionsWith{
									{Name: "go-version-file", Value: "go.mod"},
								},
							},
						},
					},
				},
			},
		},
		FindingsResults: results.FindingsResult{
			Findings: []results.Finding{
				{
					RuleId: "injection",
					Meta: results.FindingMeta{
						Path:             ".github/workflows/benchmark-bot.yml",
						EventTriggers:    []string{"issue_comment"},
						InjectionSources: []string{"github.event.comment.body"},
					},
				},
			},
			Rules: map[string]results.Rule{
				"injection": {
					Title: "Command Injection",
					Level: "high",
				},
			},
		},
	}

	convertFindings(result, []*models.PackageInsights{pkg})

	require.Len(t, result.Findings, 1)
	require.Len(t, result.Findings[0].CachePoisonVictims, 1)

	victim := result.Findings[0].CachePoisonVictims[0]
	assert.Equal(t, ".github/workflows/deploy.yml", victim.Workflow)
	assert.True(t, victim.Ready)
	assert.Equal(t, "ready", victim.Readiness)
	assert.Equal(t, cachepoison.StrategySetupGo, victim.Strategy)
	assert.Empty(t, victim.VersionSpec)
	assert.Equal(t, "go.mod", victim.VersionFilePath)
}

// =============================================================================
// NoopFormatter Tests
// =============================================================================

func TestNoopFormatter_Format(t *testing.T) {
	f := &NoopFormatter{}
	err := f.Format(context.Background(), nil)
	assert.NoError(t, err)
}

func TestNoopFormatter_FormatWithPath(t *testing.T) {
	f := &NoopFormatter{}
	err := f.FormatWithPath(context.Background(), nil, nil)
	assert.NoError(t, err)
}

// =============================================================================
// extractTrigger Additional Tests
// =============================================================================

func TestExtractTrigger_IssueComment(t *testing.T) {
	assert.Equal(t, "issue_comment", extractTrigger([]string{"issue_comment"}))
}

func TestExtractTrigger_WorkflowDispatch(t *testing.T) {
	assert.Equal(t, "workflow_dispatch", extractTrigger([]string{"workflow_dispatch"}))
}

func TestExtractTrigger_MultipleTriggers(t *testing.T) {
	assert.Equal(t, "pull_request_target, issues", extractTrigger([]string{"pull_request_target", "issues"}))
}

// =============================================================================
// extractExpression Additional Tests
// =============================================================================

func TestExtractExpression_Nested(t *testing.T) {
	expr := extractExpression("echo ${{ format('{0}', github.actor) }}")
	assert.Equal(t, "${{ format('{0}', github.actor) }}", expr)
}

func TestExtractExpression_Empty(t *testing.T) {
	expr := extractExpression("")
	assert.Empty(t, expr)
}

// =============================================================================
// extractRepoFromPurl Additional Tests
// =============================================================================

func TestExtractRepoFromPurl_ComplexVersion(t *testing.T) {
	assert.Equal(t, "org/repo", extractRepoFromPurl("pkg:github/org/repo@v1.2.3-beta.1"))
}

func TestExtractRepoFromPurl_MultipleSlashes(t *testing.T) {
	// GitHub doesn't allow this, but test edge case
	assert.Equal(t, "org/repo/sub", extractRepoFromPurl("pkg:github/org/repo/sub"))
}

func TestExtractRepoFromPurl_EmptyString(t *testing.T) {
	assert.Equal(t, "", extractRepoFromPurl(""))
}

// =============================================================================
// Cloud Action Detection Tests
// =============================================================================

func TestDetectCloudAction_AWS(t *testing.T) {
	action := detectCloudAction(
		"aws-actions/configure-aws-credentials@v4",
		[]models.GithubActionsEnv{
			{Name: "role-to-assume", Value: "arn:aws:iam::123456789:role/my-role"},
			{Name: "aws-region", Value: "us-east-1"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, CloudProviderAWS, action.Provider)
	assert.Equal(t, "aws-actions/configure-aws-credentials", action.Action)
	assert.Equal(t, "v4", action.Version)
	assert.Equal(t, "arn:aws:iam::123456789:role/my-role", action.Inputs["role-to-assume"])
	assert.Equal(t, "us-east-1", action.Inputs["aws-region"])
}

func TestDetectCloudAction_GCP(t *testing.T) {
	action := detectCloudAction(
		"google-github-actions/auth@v2",
		[]models.GithubActionsEnv{
			{Name: "workload_identity_provider", Value: "projects/123/locations/global/workloadIdentityPools/pool/providers/provider"},
			{Name: "service_account", Value: "sa@project.iam.gserviceaccount.com"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, CloudProviderGCP, action.Provider)
	assert.Equal(t, "google-github-actions/auth", action.Action)
	assert.Equal(t, "v2", action.Version)
	assert.Contains(t, action.Inputs["workload_identity_provider"], "workloadIdentityPools")
	assert.Contains(t, action.Inputs["service_account"], "@project.iam.gserviceaccount.com")
}

func TestDetectCloudAction_Azure(t *testing.T) {
	action := detectCloudAction(
		"azure/login@v1",
		[]models.GithubActionsEnv{
			{Name: "client-id", Value: "00000000-0000-0000-0000-000000000001"},
			{Name: "tenant-id", Value: "00000000-0000-0000-0000-000000000002"},
			{Name: "subscription-id", Value: "00000000-0000-0000-0000-000000000003"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, CloudProviderAzure, action.Provider)
	assert.Equal(t, "azure/login", action.Action)
	assert.Equal(t, "v1", action.Version)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", action.Inputs["client-id"])
	assert.Equal(t, "00000000-0000-0000-0000-000000000002", action.Inputs["tenant-id"])
}

func TestDetectCloudAction_UnknownAction(t *testing.T) {
	action := detectCloudAction(
		"actions/checkout@v4",
		[]models.GithubActionsEnv{
			{Name: "ref", Value: "main"},
		},
	)

	assert.Nil(t, action)
}

func TestDetectCloudAction_EmptyUses(t *testing.T) {
	action := detectCloudAction("", nil)
	assert.Nil(t, action)
}

func TestDetectCloudAction_NoVersion(t *testing.T) {
	action := detectCloudAction(
		"aws-actions/configure-aws-credentials",
		[]models.GithubActionsEnv{
			{Name: "role-to-assume", Value: "arn:aws:iam::123456789:role/my-role"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, CloudProviderAWS, action.Provider)
	assert.Equal(t, "aws-actions/configure-aws-credentials", action.Action)
	assert.Empty(t, action.Version)
}

func TestDetectCloudAction_PartialInputs(t *testing.T) {
	action := detectCloudAction(
		"aws-actions/configure-aws-credentials@v4",
		[]models.GithubActionsEnv{
			{Name: "role-to-assume", Value: "arn:aws:iam::123456789:role/my-role"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, "arn:aws:iam::123456789:role/my-role", action.Inputs["role-to-assume"])
	_, hasRegion := action.Inputs["aws-region"]
	assert.False(t, hasRegion)
}

func TestDetectCloudAction_EmptyInputValue(t *testing.T) {
	action := detectCloudAction(
		"aws-actions/configure-aws-credentials@v4",
		[]models.GithubActionsEnv{
			{Name: "role-to-assume", Value: ""},
			{Name: "aws-region", Value: "us-west-2"},
		},
	)

	require.NotNil(t, action)
	_, hasRole := action.Inputs["role-to-assume"]
	assert.False(t, hasRole, "Empty value should not be captured")
	assert.Equal(t, "us-west-2", action.Inputs["aws-region"])
}

func TestParseActionReference(t *testing.T) {
	tests := []struct {
		uses            string
		expectedAction  string
		expectedVersion string
	}{
		{"aws-actions/configure-aws-credentials@v4", "aws-actions/configure-aws-credentials", "v4"},
		{"google-github-actions/auth@v2.1.0", "google-github-actions/auth", "v2.1.0"},
		{"azure/login@main", "azure/login", "main"},
		{"actions/checkout", "actions/checkout", ""},
		{"owner/repo@refs/heads/feature", "owner/repo", "refs/heads/feature"},
	}

	for _, tt := range tests {
		t.Run(tt.uses, func(t *testing.T) {
			action, version := parseActionReference(tt.uses)
			assert.Equal(t, tt.expectedAction, action)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

// =============================================================================
// extractSecretsFromString Tests
// =============================================================================

func TestExtractSecretsFromString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty string", "", nil},
		{"no secrets", "echo hello world", nil},
		{"single secret", "${{ secrets.MY_TOKEN }}", []string{"MY_TOKEN"}},
		{"multiple secrets", "secrets.FOO and secrets.BAR", []string{"FOO", "BAR"}},
		{"github token excluded", "secrets.GITHUB_TOKEN", nil},
		{"mixed with github token", "secrets.DEPLOY_KEY and secrets.GITHUB_TOKEN", []string{"DEPLOY_KEY"}},
		{"secret at end of string", "use secrets.KEY", []string{"KEY"}},
		{"secrets with underscores", "secrets.MY_DEPLOY_KEY_2", []string{"MY_DEPLOY_KEY_2"}},
		{"secret with no name", "secrets.", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretSet := make(map[string]struct{})
			extractSecretsFromString(tt.input, secretSet)

			if tt.expected == nil {
				assert.Empty(t, secretSet)
			} else {
				assert.Len(t, secretSet, len(tt.expected))
				for _, exp := range tt.expected {
					_, ok := secretSet[exp]
					assert.True(t, ok, "expected secret %q not found", exp)
				}
			}
		})
	}
}

// =============================================================================
// determineContextFromSources Tests
// =============================================================================

func TestDetermineContextFromSources(t *testing.T) {
	tests := []struct {
		name     string
		sources  []string
		expected string
	}{
		{"empty sources", nil, "unknown"},
		{"workflow dispatch input", []string{"github.event.inputs.name"}, "workflow_dispatch_input"},
		{"head ref", []string{"github.head_ref"}, "git_branch"},
		{"pr head ref", []string{"github.event.pull_request.head.ref"}, "git_branch"},
		{"pr title", []string{"github.event.pull_request.title"}, "pr_title"},
		{"pr body", []string{"github.event.pull_request.body"}, "pr_body"},
		{"issue title", []string{"github.event.issue.title"}, "issue_title"},
		{"issue body", []string{"github.event.issue.body"}, "issue_body"},
		{"comment body", []string{"github.event.comment.body"}, "comment_body"},
		{"commit message", []string{"github.event.commits[0].message"}, "commit_message"},
		{"unknown source", []string{"github.actor"}, "bash_run"},
		{"uses first source only", []string{"github.event.issue.title", "github.head_ref"}, "issue_title"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, determineContextFromSources(tt.sources))
		})
	}
}

// =============================================================================
// App Action Detection Tests
// =============================================================================

func TestDetectAppAction_Official(t *testing.T) {
	action := detectAppAction(
		"actions/create-github-app-token@v2",
		[]models.GithubActionsEnv{
			{Name: "private-key", Value: "${{ secrets.WHOOLI_BOT_APP_PRIVATE_KEY }}"},
			{Name: "app-id", Value: "${{ secrets.WHOOLI_BOT_APP_ID }}"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, "actions/create-github-app-token", action.Action)
	assert.Equal(t, "v2", action.Version)
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", action.PrivateKey)
	assert.Equal(t, "WHOOLI_BOT_APP_ID", action.AppID)
}

func TestDetectAppAction_Tibdex(t *testing.T) {
	action := detectAppAction(
		"tibdex/github-app-token@v2",
		[]models.GithubActionsEnv{
			{Name: "private_key", Value: "${{ secrets.MY_PEM }}"},
			{Name: "app_id", Value: "${{ secrets.MY_APP_ID }}"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, "tibdex/github-app-token", action.Action)
	assert.Equal(t, "v2", action.Version)
	assert.Equal(t, "MY_PEM", action.PrivateKey)
	assert.Equal(t, "MY_APP_ID", action.AppID)
}

func TestDetectAppAction_PeterMurray(t *testing.T) {
	action := detectAppAction(
		"peter-murray/workflow-application-token-action@v4",
		[]models.GithubActionsEnv{
			{Name: "application_private_key", Value: "${{ secrets.BANANA }}"},
			{Name: "application_id", Value: "${{ secrets.BANANA_ID }}"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, "peter-murray/workflow-application-token-action", action.Action)
	assert.Equal(t, "v4", action.Version)
	assert.Equal(t, "BANANA", action.PrivateKey)
	assert.Equal(t, "BANANA_ID", action.AppID)
}

func TestDetectAppAction_UnknownAction(t *testing.T) {
	action := detectAppAction(
		"actions/checkout@v4",
		[]models.GithubActionsEnv{
			{Name: "ref", Value: "main"},
		},
	)
	assert.Nil(t, action)
}

func TestDetectAppAction_EmptyUses(t *testing.T) {
	action := detectAppAction("", nil)
	assert.Nil(t, action)
}

func TestDetectAppAction_PartialInputs(t *testing.T) {
	action := detectAppAction(
		"actions/create-github-app-token@v2",
		[]models.GithubActionsEnv{
			{Name: "app-id", Value: "${{ secrets.SOME_APP_ID }}"},
		},
	)

	require.NotNil(t, action)
	assert.Empty(t, action.PrivateKey)
	assert.Equal(t, "SOME_APP_ID", action.AppID)
}

func TestDetectAppAction_HardcodedAppID(t *testing.T) {
	action := detectAppAction(
		"actions/create-github-app-token@v2",
		[]models.GithubActionsEnv{
			{Name: "private-key", Value: "${{ secrets.MY_PEM }}"},
			{Name: "app-id", Value: "12345"},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, "MY_PEM", action.PrivateKey)
	assert.Empty(t, action.AppID)
	assert.Equal(t, "12345", action.HardcodedAppID)
}

func TestDetectAppAction_HardcodedAppIDWithWhitespace(t *testing.T) {
	action := detectAppAction(
		"actions/create-github-app-token@v2",
		[]models.GithubActionsEnv{
			{Name: "private-key", Value: "${{ secrets.MY_PEM }}"},
			{Name: "app-id", Value: "  67890  "},
		},
	)

	require.NotNil(t, action)
	assert.Equal(t, "67890", action.HardcodedAppID)
}

func TestExtractLiteralAppID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"numeric", "12345", "12345"},
		{"with whitespace", "  67890  ", "67890"},
		{"empty", "", ""},
		{"secret ref", "${{ secrets.FOO }}", ""},
		{"alpha", "abc", ""},
		{"mixed", "123abc", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractLiteralAppID(tt.input))
		})
	}
}

// =============================================================================
// extractSecretRef Tests
// =============================================================================

func TestExtractSecretRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"full expression", "${{ secrets.FOO }}", "FOO"},
		{"no whitespace", "${{secrets.FOO}}", "FOO"},
		{"extra spaces", "${{  secrets.FOO  }}", "FOO"},
		{"literal value", "some-literal", ""},
		{"empty string", "", ""},
		{"bare secrets ref", "secrets.BAR", "BAR"},
		{"only prefix", "${{ secrets. }}", ""},
		{"non-secret expression", "${{ github.actor }}", ""},
		{"underscores and numbers", "${{ secrets.MY_KEY_2 }}", "MY_KEY_2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractSecretRef(tt.input))
		})
	}
}

// =============================================================================
// buildSecretTypes Tests
// =============================================================================

func TestBuildSecretTypes_WithEnvAliases(t *testing.T) {
	job := models.GithubActionsJob{
		Steps: []models.GithubActionsStep{
			{
				Env: models.GithubActionsEnvs{
					{Name: "MY_KEY", Value: "${{ secrets.WHOOLI_BOT_APP_PRIVATE_KEY }}"},
					{Name: "MY_ID", Value: "${{ secrets.WHOOLI_BOT_APP_ID }}"},
					{Name: "UNRELATED", Value: "static-value"},
				},
			},
		},
	}
	appActions := []AppAction{
		{
			Action:     "actions/create-github-app-token",
			PrivateKey: "WHOOLI_BOT_APP_PRIVATE_KEY",
			AppID:      "WHOOLI_BOT_APP_ID",
		},
	}

	result := buildSecretTypes(job, appActions)

	require.NotNil(t, result)
	assert.Equal(t, "github_app_key", result["WHOOLI_BOT_APP_PRIVATE_KEY"])
	assert.Equal(t, "github_app_id", result["WHOOLI_BOT_APP_ID"])
	assert.Equal(t, "github_app_key", result["MY_KEY"])
	assert.Equal(t, "github_app_id", result["MY_ID"])
	_, hasUnrelated := result["UNRELATED"]
	assert.False(t, hasUnrelated)
}

func TestBuildSecretTypes_NoAppActions(t *testing.T) {
	job := models.GithubActionsJob{}
	result := buildSecretTypes(job, nil)
	assert.Nil(t, result)
}

// =============================================================================
// extractWorkflowMeta Integration Tests (AppAction wiring)
// =============================================================================

func TestExtractWorkflowMeta_AppActionDetected(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/whooli/xyz",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/whooli-analyzer.yml",
				Jobs: models.GithubActionsJobs{
					{
						ID: "analyze",
						Steps: models.GithubActionsSteps{
							{
								Uses: "actions/create-github-app-token@v2",
								With: models.GithubActionsEnvs{
									{Name: "private-key", Value: "${{ secrets.WHOOLI_BOT_APP_PRIVATE_KEY }}"},
									{Name: "app-id", Value: "${{ secrets.WHOOLI_BOT_APP_ID }}"},
								},
							},
						},
					},
				},
			},
		},
	}

	extractWorkflowMeta(result, pkg, "whooli/xyz")

	require.Len(t, result.Workflows, 1)
	wf := result.Workflows[0]

	require.Len(t, wf.Jobs, 1)
	job := wf.Jobs[0]
	require.Len(t, job.AppActions, 1)
	assert.Equal(t, "actions/create-github-app-token", job.AppActions[0].Action)
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", job.AppActions[0].PrivateKey)
	assert.Equal(t, "WHOOLI_BOT_APP_ID", job.AppActions[0].AppID)

	require.NotNil(t, job.SecretTypes)
	assert.Equal(t, "github_app_key", job.SecretTypes["WHOOLI_BOT_APP_PRIVATE_KEY"])
	assert.Equal(t, "github_app_id", job.SecretTypes["WHOOLI_BOT_APP_ID"])

	require.NotNil(t, wf.SecretTypes)
	assert.Equal(t, "github_app_key", wf.SecretTypes["WHOOLI_BOT_APP_PRIVATE_KEY"])
	assert.Equal(t, "github_app_id", wf.SecretTypes["WHOOLI_BOT_APP_ID"])
}

func TestExtractWorkflowMeta_EnvAliasResolved(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/app",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: models.GithubActionsJobs{
					{
						ID: "deploy",
						Steps: models.GithubActionsSteps{
							{
								Uses: "tibdex/github-app-token@v2",
								With: models.GithubActionsEnvs{
									{Name: "private_key", Value: "${{ secrets.BANANA }}"},
									{Name: "app_id", Value: "${{ secrets.BANANA_ID }}"},
								},
							},
							{
								Env: models.GithubActionsEnvs{
									{Name: "MY_KEY", Value: "${{ secrets.BANANA }}"},
								},
							},
						},
					},
				},
			},
		},
	}

	extractWorkflowMeta(result, pkg, "acme/app")

	require.Len(t, result.Workflows, 1)
	st := result.Workflows[0].SecretTypes

	assert.Equal(t, "github_app_key", st["BANANA"])
	assert.Equal(t, "github_app_id", st["BANANA_ID"])
	assert.Equal(t, "github_app_key", st["MY_KEY"])
}

func TestExtractWorkflowMeta_NoAppActions(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/lib",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/test.yml",
				Jobs: models.GithubActionsJobs{
					{
						ID: "test",
						Steps: models.GithubActionsSteps{
							{
								Uses: "actions/checkout@v4",
							},
						},
					},
				},
			},
		},
	}

	extractWorkflowMeta(result, pkg, "acme/lib")

	require.Len(t, result.Workflows, 1)
	assert.Nil(t, result.Workflows[0].SecretTypes)
	assert.Empty(t, result.Workflows[0].Jobs[0].AppActions)
}

func TestExtractWorkflowMeta_HardcodedAppID(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/whooli/xyz",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: models.GithubActionsJobs{
					{
						ID: "analyze",
						Steps: models.GithubActionsSteps{
							{
								Uses: "actions/create-github-app-token@v2",
								With: models.GithubActionsEnvs{
									{Name: "private-key", Value: "${{ secrets.BOT_PEM }}"},
									{Name: "app-id", Value: "98765"},
								},
							},
						},
					},
				},
			},
		},
	}

	extractWorkflowMeta(result, pkg, "whooli/xyz")

	require.Len(t, result.Workflows, 1)
	wf := result.Workflows[0]

	assert.Equal(t, "github_app_key", wf.SecretTypes["BOT_PEM"])
	_, hasAppIDType := wf.SecretTypes["98765"]
	assert.False(t, hasAppIDType, "literal App ID should not be in SecretTypes")
	require.Len(t, wf.HardcodedAppIDs, 1)
	assert.Equal(t, "98765", wf.HardcodedAppIDs[0])
}

func TestExtractWorkflowMeta_MultipleJobsMerged(t *testing.T) {
	result := &AnalysisResult{Findings: []Finding{}}
	pkg := &models.PackageInsights{
		Purl: "pkg:github/acme/api",
		GithubActionsWorkflows: []models.GithubActionsWorkflow{
			{
				Path: ".github/workflows/ci.yml",
				Jobs: models.GithubActionsJobs{
					{
						ID: "build",
						Steps: models.GithubActionsSteps{
							{
								Uses: "actions/create-github-app-token@v2",
								With: models.GithubActionsEnvs{
									{Name: "private-key", Value: "${{ secrets.BUILD_PEM }}"},
									{Name: "app-id", Value: "${{ secrets.BUILD_APP_ID }}"},
								},
							},
						},
					},
					{
						ID: "deploy",
						Steps: models.GithubActionsSteps{
							{
								Uses: "tibdex/github-app-token@v2",
								With: models.GithubActionsEnvs{
									{Name: "private_key", Value: "${{ secrets.DEPLOY_PEM }}"},
									{Name: "app_id", Value: "${{ secrets.DEPLOY_APP_ID }}"},
								},
							},
						},
					},
				},
			},
		},
	}

	extractWorkflowMeta(result, pkg, "acme/api")

	require.Len(t, result.Workflows, 1)
	st := result.Workflows[0].SecretTypes

	assert.Equal(t, "github_app_key", st["BUILD_PEM"])
	assert.Equal(t, "github_app_id", st["BUILD_APP_ID"])
	assert.Equal(t, "github_app_key", st["DEPLOY_PEM"])
	assert.Equal(t, "github_app_id", st["DEPLOY_APP_ID"])
}
