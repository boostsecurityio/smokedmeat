// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSuggestions_PrioritizesDispatchWhenCredentialAvailable(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/comment.yml",
			Job:        "comment",
			Line:       10,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   ".github/workflows/dispatch.yml",
			Job:        "dispatch",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "workflow_dispatch",
			Context:    "workflow_dispatch_input",
		},
	}
	m.lootStash = []CollectedSecret{{
		Name:   "GITHUB_TOKEN",
		Value:  "ghs_ephemeral",
		Type:   "github_token",
		Scopes: []string{"actions:write", "contents:read"},
	}}

	m.GenerateSuggestions()

	require.NotEmpty(t, m.suggestions)
	top := m.suggestions[0]
	require.GreaterOrEqual(t, top.VulnIndex, 0)
	assert.Equal(t, "V002", m.vulnerabilities[top.VulnIndex].ID)
	assert.Contains(t, top.Description, "dispatch ready")
}

func TestGenerateSuggestions_PrioritizesCurrentTargetRepo(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme/private-infra"
	m.targetType = "repo"
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/public-site",
			Workflow:   ".github/workflows/comment.yml",
			Job:        "comment",
			Line:       10,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
		{
			ID:         "V002",
			Repository: "acme/private-infra",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "push",
			Context:    "bash_run",
		},
	}

	m.GenerateSuggestions()

	require.NotEmpty(t, m.suggestions)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V002", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)
}

func TestGenerateSuggestions_AllowsDistinctTriggersFromSameWorkflow(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/analyzer.yml",
			Job:        "issues",
			Line:       10,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "bash_run",
		},
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   ".github/workflows/analyzer.yml",
			Job:        "comment",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
		{
			ID:         "V003",
			Repository: "acme/other-1",
			Workflow:   ".github/workflows/ci-1.yml",
			Job:        "build",
			Line:       30,
			RuleID:     "injection",
			Trigger:    "push",
			Context:    "bash_run",
		},
		{
			ID:         "V004",
			Repository: "acme/other-2",
			Workflow:   ".github/workflows/ci-2.yml",
			Job:        "build",
			Line:       40,
			RuleID:     "injection",
			Trigger:    "push",
			Context:    "bash_run",
		},
		{
			ID:         "V005",
			Repository: "acme/other-3",
			Workflow:   ".github/workflows/ci-3.yml",
			Job:        "build",
			Line:       50,
			RuleID:     "injection",
			Trigger:    "push",
			Context:    "bash_run",
		},
		{
			ID:         "V006",
			Repository: "acme/other-4",
			Workflow:   ".github/workflows/ci-4.yml",
			Job:        "build",
			Line:       60,
			RuleID:     "injection",
			Trigger:    "push",
			Context:    "bash_run",
		},
	}

	m.GenerateSuggestions()

	ids := make([]string, 0, len(m.suggestions))
	for _, suggestion := range m.suggestions {
		if suggestion.VulnIndex >= 0 {
			ids = append(ids, m.vulnerabilities[suggestion.VulnIndex].ID)
		}
	}

	assert.Contains(t, ids, "V001")
	assert.Contains(t, ids, "V002")
}

func TestGenerateSuggestions_DeduplicatesSourceVariantsWithinSameJob(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V004",
			Repository: "whooli/xyz",
			Workflow:   ".github/workflows/auto-labeler.yml",
			Job:        "whooli-triage",
			Step:       "alpha-cleanup",
			Line:       41,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "issue_title",
			Expression: "${{ github.event.issue.title }}",
		},
		{
			ID:         "V001",
			Repository: "whooli/xyz",
			Workflow:   ".github/workflows/auto-labeler.yml",
			Job:        "whooli-triage",
			Step:       "zeta-triage",
			Line:       23,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "issue_body",
			Expression: "${{ github.event.issue.body }}",
		},
		{
			ID:         "V003",
			Repository: "whooli/xyz",
			Workflow:   ".github/workflows/auto-labeler.yml",
			Job:        "whooli-triage",
			Step:       "alpha-cleanup",
			Line:       41,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "issue_body",
			Expression: "${{ github.event.issue.body }}",
		},
		{
			ID:         "V002",
			Repository: "whooli/xyz",
			Workflow:   ".github/workflows/auto-labeler.yml",
			Job:        "whooli-triage",
			Step:       "zeta-triage",
			Line:       23,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "issue_title",
			Expression: "${{ github.event.issue.title }}",
		},
	}

	m.GenerateSuggestions()

	require.Len(t, m.suggestions, 1)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V001", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)
}

func TestRankVulnerabilities_IgnoresSeverity(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   ".github/workflows/auto-labeler.yml",
			Job:        "beta",
			Step:       "1",
			Line:       23,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "issue_body",
			Severity:   "critical",
		},
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/auto-labeler.yml",
			Job:        "alpha",
			Step:       "1",
			Line:       23,
			RuleID:     "injection",
			Trigger:    "issues",
			Context:    "issue_body",
			Severity:   "high",
		},
	}

	ranked := m.rankVulnerabilities()
	require.Len(t, ranked, 2)
	assert.Equal(t, "V001", m.vulnerabilities[ranked[0]].ID)
	assert.Equal(t, "V002", m.vulnerabilities[ranked[1]].ID)
}

func TestRenderSuggestions_DropsFocusIndicatorWhenModalActive(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.focus = FocusSessions
	m.paneFocus = PaneFocusMenu
	m.suggestions = []SuggestedAction{{
		Label:       "Dispatch workflows",
		Description: "actions:write scope available",
		Command:     "pivot dispatch",
		Priority:    1,
	}}

	normal := stripANSI(m.RenderSuggestions(40, 8))

	m.view = ViewOmnibox
	modal := stripANSI(m.RenderSuggestions(40, 8))

	assert.Contains(t, normal, "│")
	assert.NotContains(t, modal, "│")
}

func TestRenderVulnMenuItem_HyperlinksLOTPTargets(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	lines := m.renderVulnMenuItem("[1]", Vulnerability{
		Repository:  "acme/api",
		Workflow:    ".github/workflows/pr.yml",
		Job:         "verify",
		Line:        12,
		RuleID:      "untrusted_checkout_exec",
		LOTPTool:    "bash",
		LOTPTargets: []string{"scripts/verify.sh"},
	}, 120)

	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, "https://github.com/acme/api/blob/HEAD/scripts/verify.sh")
}

func TestGenerateSuggestions_DoesNotTreatExpiredDispatchLootAsReady(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	expired := time.Now().Add(-time.Minute)
	m.vulnerabilities = []Vulnerability{{
		ID:         "V002",
		Repository: "acme/api",
		Workflow:   ".github/workflows/dispatch.yml",
		Job:        "dispatch",
		Line:       20,
		RuleID:     "injection",
		Trigger:    "workflow_dispatch",
		Context:    "workflow_dispatch_input",
	}}
	m.lootStash = []CollectedSecret{{
		Name:          "GITHUB_TOKEN",
		Value:         "ghs_expired",
		Type:          "github_token",
		Ephemeral:     true,
		DwellDeadline: &expired,
		Scopes:        []string{"actions:write"},
	}}

	m.GenerateSuggestions()

	require.NotEmpty(t, m.suggestions)
	assert.NotContains(t, m.suggestions[0].Description, "dispatch ready")
}

func TestGenerateSuggestions_DoesNotTreatScopeLessPATAsDispatchReady(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{
		Value: "ghp_abcdef1234567890abcdef1234567890abcd",
		Type:  TokenTypeClassicPAT,
	}
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/comment.yml",
			Job:        "comment",
			Line:       10,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   ".github/workflows/dispatch.yml",
			Job:        "dispatch",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "workflow_dispatch",
			Context:    "workflow_dispatch_input",
		},
	}

	m.GenerateSuggestions()

	require.NotEmpty(t, m.suggestions)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V001", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)
	assert.NotContains(t, m.suggestions[0].Description, "dispatch ready")
}

func TestGenerateSuggestions_PrefersAutomaticDeliveryOverManualOnlyLOTP(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme/manual-only"
	m.targetType = "repo"
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/manual-only",
			Workflow:   ".github/workflows/pr.yml",
			Job:        "verify",
			Line:       10,
			RuleID:     "untrusted_checkout_exec",
			Trigger:    "pull_request_target",
			Context:    "bash_run",
			LOTPAction: "actions/setup-go",
		},
		{
			ID:         "V002",
			Repository: "acme/auto-ready",
			Workflow:   ".github/workflows/comment.yml",
			Job:        "comment",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
	}

	m.GenerateSuggestions()

	require.NotEmpty(t, m.suggestions)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V002", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)
}

func TestGenerateSuggestions_FallsBackToManualOnlyLOTPWhenNoAutomaticDeliveryExists(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/manual-only",
			Workflow:   ".github/workflows/pr.yml",
			Job:        "verify",
			Line:       10,
			RuleID:     "untrusted_checkout_exec",
			Trigger:    "pull_request_target",
			Context:    "bash_run",
			LOTPAction: "actions/setup-go",
		},
	}

	m.GenerateSuggestions()

	require.Len(t, m.suggestions, 1)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V001", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)
}

func TestSwapActiveToken_RecalculatesSuggestions(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.initialTokenInfo = &TokenInfo{
		Value:  "ghp_initial1234567890abcdef1234567890abcd",
		Type:   TokenTypeClassicPAT,
		Source: "config",
	}
	m.tokenInfo = m.initialTokenInfo
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/comment.yml",
			Job:        "comment",
			Line:       10,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   ".github/workflows/dispatch.yml",
			Job:        "dispatch",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "workflow_dispatch",
			Context:    "workflow_dispatch_input",
		},
	}
	m.GenerateSuggestions()
	require.NotEmpty(t, m.suggestions)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	require.Equal(t, "V001", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)

	m.appTokenPermissions = map[string]string{"actions": "write"}
	m.swapActiveToken(CollectedSecret{
		Name:  "APP_TOKEN",
		Value: "ghs_app_token",
		Type:  "github_app_token",
	})

	require.NotEmpty(t, m.suggestions)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V002", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)
}

func TestGenerateSuggestions_OmitsAnalyzeOnlyFindings(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/pr.yml",
			Job:        "build",
			Line:       20,
			RuleID:     "pr_runs_on_self_hosted",
			Trigger:    "pull_request",
			Context:    "bash_run",
		},
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   "azure-pipelines.yml",
			Job:        "build",
			Line:       22,
			RuleID:     "injection",
			Trigger:    "pull_request",
			Context:    "bash_run",
		},
	}

	m.GenerateSuggestions()

	for _, suggestion := range m.suggestions {
		assert.Less(t, suggestion.VulnIndex, 0)
	}
}
