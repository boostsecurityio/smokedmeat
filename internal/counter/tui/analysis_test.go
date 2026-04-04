// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func TestModel_Update_AnalysisStarted(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(AnalysisStartedMsg{
		Target:     "acme/api",
		TargetType: "repo",
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[0].Content, "acme/api")
}

func TestModel_Update_AnalysisCompleted(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme"
	m.targetType = "org"

	result, _ := m.Update(AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme",
			ReposAnalyzed: 5,
			TotalFindings: 3,
			Findings: []poutine.Finding{
				{ID: "V001", Repository: "acme/api", RuleID: "injection", Severity: "critical"},
				{ID: "V002", Repository: "acme/web", RuleID: "injection", Severity: "high"},
				{ID: "V003", Repository: "acme/lib", RuleID: "debug", Severity: "medium"},
			},
		},
	})

	model := result.(Model)
	assert.True(t, model.analysisComplete)
}

func TestModel_Update_AnalysisCompleted_AddsSecretsWithoutVulns(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme/private-repo"
	m.targetType = "repo"

	result, _ := m.Update(AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme/private-repo",
			TargetType:    "repo",
			Repository:    "acme/private-repo",
			ReposAnalyzed: 1,
			SecretFindings: []poutine.SecretFinding{
				{
					RuleID:      "private-key",
					Description: "Private Key detected",
					Repository:  "acme/private-repo",
					File:        "README.md",
					StartLine:   12,
					Secret:      "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
				},
				{
					RuleID:      "github-fine-grained-pat",
					Description: "GitHub Fine-Grained PAT",
					Repository:  "acme/private-repo",
					File:        ".env",
					StartLine:   4,
					Secret:      "github_pat_abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyzABCDEFG",
				},
			},
		},
	})

	model := result.(Model)
	assert.True(t, model.analysisComplete)
	assert.Empty(t, model.vulnerabilities)
	require.Len(t, model.lootStash, 2)
	assert.Equal(t, "Private Key detected (README.md:12)", model.lootStash[0].Name)
	assert.Equal(t, "private_key", model.lootStash[0].Type)
	assert.Equal(t, "acme/private-repo", model.lootStash[0].Repository)
	assert.Equal(t, "GitHub Fine-Grained PAT (.env:4)", model.lootStash[1].Name)
	assert.Equal(t, "github_pat", model.lootStash[1].Type)
	assert.Equal(t, "acme/private-repo", model.lootStash[1].Repository)

	var output []string
	for _, line := range model.output {
		output = append(output, line.Content)
	}
	assert.Contains(t, output, "No exploitable vulnerabilities found.")
	assert.Contains(t, output, "Found 2 secrets (private keys / credentials)")
}

func TestModel_Update_AnalysisCompleted_AnalyzeOnlyFindingsRemainVisible(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme"
	m.targetType = "org"

	result, _ := m.Update(AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme",
			ReposAnalyzed: 1,
			TotalFindings: 1,
			Findings: []poutine.Finding{
				{
					ID:         "V001",
					Repository: "acme/api",
					Workflow:   ".github/workflows/pr.yml",
					RuleID:     "pr_runs_on_self_hosted",
					Severity:   "critical",
				},
			},
		},
	})

	model := result.(Model)
	require.Len(t, model.vulnerabilities, 1)
	assert.Equal(t, 0, model.selectedVuln)

	var output []string
	for _, line := range model.output {
		output = append(output, line.Content)
	}
	assert.Contains(t, output, "Found 1 analyze-only finding")
	assert.Contains(t, output, "Selected: V001. Analyze-only finding. Use 'use <id>' to inspect findings.")
}

func TestModel_Update_AnalysisError(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme"
	m.targetType = "org"

	result, cmd := m.Update(AnalysisErrorMsg{
		Err: errors.New("poutine binary not found"),
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "error", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "poutine binary not found")
	assert.NotNil(t, cmd, "Should record failed analysis in history")
}

func TestModel_Update_HistoryFetched(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	entries := []HistoryEntry{
		{ID: "h1", Type: "analysis.completed"},
		{ID: "h2", Type: "exploit.attempted"},
	}

	result, _ := m.Update(HistoryFetchedMsg{Entries: entries})

	model := result.(Model)
	assert.Len(t, model.opHistory.entries, 2)
}

func TestModel_Update_HistoryFetchError(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(HistoryFetchErrorMsg{Err: errors.New("db error")})

	model := result.(Model)
	assert.Len(t, model.activityLog.entries, 1)
}

func TestModel_Update_HistoryEntry(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(HistoryEntryMsg{
		Entry: HistoryEntry{ID: "h3", Type: "beacon.received"},
	})

	model := result.(Model)
	assert.Len(t, model.opHistory.entries, 1)
}

func TestModel_Update_HistoryRecordError(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(HistoryRecordErrorMsg{Err: errors.New("network timeout")})

	model := result.(Model)
	require.Len(t, model.activityLog.entries, 1)
	assert.Contains(t, model.activityLog.entries[0].Message, "History recording failed")
	assert.Contains(t, model.activityLog.entries[0].Message, "network timeout")
}

func TestModel_Update_AnalysisCompleted_PreservesAllVulnFields(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme"
	m.targetType = "org"

	result, _ := m.Update(AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme",
			ReposAnalyzed: 1,
			TotalFindings: 1,
			Findings: []poutine.Finding{
				{
					ID:                "V001",
					Repository:        "acme/api",
					Workflow:          ".github/workflows/ci.yml",
					Job:               "build",
					RuleID:            "injection",
					Severity:          "critical",
					Context:           "comment_body",
					Trigger:           "issue_comment",
					Expression:        "${{ github.event.comment.body }}",
					InjectionSources:  []string{"github.event.comment.body"},
					ReferencedSecrets: []string{"AWS_KEY"},
					GateTriggers:      []string{"/deploy"},
					GateRaw:           "contains(github.event.comment.body, '/deploy')",
					GateUnsolvable:    "",
				},
			},
		},
	})

	model := result.(Model)
	require.Len(t, model.vulnerabilities, 1)
	v := model.vulnerabilities[0]

	assert.Equal(t, []string{"github.event.comment.body"}, v.InjectionSources)
	assert.Equal(t, []string{"AWS_KEY"}, v.ReferencedSecrets)
	assert.Equal(t, []string{"/deploy"}, v.GateTriggers)
	assert.Equal(t, "contains(github.event.comment.body, '/deploy')", v.GateRaw)
	assert.True(t, isCommentInjection(&v),
		"isCommentInjection should return true for fresh analysis vuln")
}

func TestModel_Update_AnalysisCompleted_AssignsUniqueIDsAcrossRuns(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme/xyz"
	m.targetType = "repo"

	result, _ := m.Update(AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme/xyz",
			ReposAnalyzed: 1,
			TotalFindings: 1,
			Findings: []poutine.Finding{
				{
					ID:          "V001",
					Fingerprint: "fp-xyz",
					Repository:  "acme/xyz",
					Workflow:    ".github/workflows/community-build.yml",
					Job:         "verify",
					Line:        25,
					RuleID:      "injection",
					Severity:    "high",
				},
			},
		},
	})

	model := result.(Model)

	result, _ = model.Update(AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme/infrastructure",
			ReposAnalyzed: 1,
			TotalFindings: 1,
			Findings: []poutine.Finding{
				{
					ID:          "V001",
					Fingerprint: "fp-infra",
					Repository:  "acme/infrastructure",
					Workflow:    ".github/workflows/benchmark-intake.yml",
					Job:         "intake",
					Line:        32,
					RuleID:      "injection",
					Severity:    "high",
				},
			},
		},
	})

	model = result.(Model)

	require.Len(t, model.vulnerabilities, 2)
	assert.Equal(t, "V001", model.vulnerabilities[0].ID)
	assert.Equal(t, "V002", model.vulnerabilities[1].ID)
	assert.Equal(t, "acme/infrastructure", model.vulnerabilities[1].Repository)
}

func TestModel_Update_AnalysisCompleted_DeduplicatesByFingerprint(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.target = "acme"
	m.targetType = "org"

	first := AnalysisCompletedMsg{
		Result: &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme",
			ReposAnalyzed: 1,
			TotalFindings: 1,
			Findings: []poutine.Finding{
				{
					ID:          "V001",
					Fingerprint: "fp-shared",
					Repository:  "acme/api",
					Workflow:    ".github/workflows/ci.yml",
					Job:         "build",
					Line:        20,
					RuleID:      "injection",
					Severity:    "critical",
				},
			},
		},
	}

	result, _ := m.Update(first)
	model := result.(Model)

	result, _ = model.Update(first)
	model = result.(Model)

	require.Len(t, model.vulnerabilities, 1)
	assert.Equal(t, "V001", model.vulnerabilities[0].ID)
}

func TestPivotResult_AutoTriggersAnalysis(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenURL: "http://localhost:8080"})
	m.phase = PhasePostExploit
	m.tokenInfo = &TokenInfo{Value: "ghp_test123"}

	_, cmd := m.Update(PivotResultMsg{
		Success:  true,
		Type:     PivotTypeGitHubToken,
		NewRepos: []string{"org/repo1", "org/repo2"},
	})

	assert.NotNil(t, cmd, "PivotResultMsg with new repos should return analysis cmd")
}

func TestPivotResult_NoAnalysisWhenNoNewRepos(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenURL: "http://localhost:8080"})
	m.phase = PhasePostExploit
	m.tokenInfo = &TokenInfo{Value: "ghp_test123"}

	_, cmd := m.Update(PivotResultMsg{
		Success:    true,
		Type:       PivotTypeGitHubToken,
		TotalFound: 5,
	})

	assert.Nil(t, cmd, "PivotResultMsg with no new repos should return nil cmd")
}

func TestPivotResult_NoAnalysisWithoutPrereqs(t *testing.T) {
	tests := []struct {
		name       string
		tokenInfo  *TokenInfo
		kitchenURL string
	}{
		{"no token", nil, "http://localhost:8080"},
		{"no kitchen URL", &TokenInfo{Value: "ghp_test"}, ""},
		{"neither", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel(Config{SessionID: "test", KitchenURL: tt.kitchenURL})
			m.phase = PhasePostExploit
			m.tokenInfo = tt.tokenInfo

			_, cmd := m.Update(PivotResultMsg{
				Success:  true,
				Type:     PivotTypeGitHubToken,
				NewRepos: []string{"org/repo1"},
			})

			assert.Nil(t, cmd, "Should not auto-analyze without prerequisites")
		})
	}
}
