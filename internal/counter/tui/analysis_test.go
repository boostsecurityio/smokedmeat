// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func TestNewAnalysisID(t *testing.T) {
	first, err := newAnalysisID()
	require.NoError(t, err)
	second, err := newAnalysisID()
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
	assert.True(t, strings.HasPrefix(first, "analysis_"))
	assert.Len(t, strings.TrimPrefix(first, "analysis_"), 32)
}

func TestModel_Update_AnalysisStarted(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(AnalysisStartedMsg{
		Target:     "acme/api",
		TargetType: "repo",
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[0].Content, "acme/api")
	require.NotNil(t, model.analysisProgress)
	assert.Equal(t, analysisPhaseWorkflow, model.analysisProgress.Phase)
}

func TestModel_Update_AnalysisStarted_PreservesExistingDeepProgress(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	startedAt := time.Now().Add(-5 * time.Second)
	m.analysisProgress = &counter.AnalysisProgressPayload{
		Target:         "acme",
		TargetType:     "org",
		Deep:           true,
		Phase:          analysisPhaseSecret,
		ReposCompleted: 3,
		ReposTotal:     10,
		StartedAt:      startedAt,
		UpdatedAt:      startedAt,
	}

	result, _ := m.Update(AnalysisStartedMsg{
		Target:     "acme",
		TargetType: "org",
	})

	model := result.(Model)
	require.NotNil(t, model.analysisProgress)
	assert.True(t, model.analysisProgress.Deep)
	assert.Equal(t, analysisPhaseSecret, model.analysisProgress.Phase)
	assert.Equal(t, 3, model.analysisProgress.ReposCompleted)
	assert.Equal(t, 10, model.analysisProgress.ReposTotal)
	assert.Equal(t, startedAt, model.analysisProgress.StartedAt)
}

func TestModel_Update_AnalysisProgress_TracksStateWithoutSpammingLog(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	startedAt := time.Now().Add(-3 * time.Second)
	m.beginAnalysisProgress("analysis_123", "acme", "org", false)

	result, _ := m.Update(AnalysisProgressMsg{
		Progress: counter.AnalysisProgressPayload{
			AnalysisID: "analysis_123",
			Phase:      analysisPhaseSecret,
			ReposTotal: 3,
			StartedAt:  startedAt,
		},
	})
	model := result.(Model)
	require.NotNil(t, model.analysisProgress)
	assert.Equal(t, analysisPhaseSecret, model.analysisProgress.Phase)
	require.Len(t, model.activityLog.entries, 1)
	assert.Contains(t, model.activityLog.entries[0].Message, "Secret scan running")

	result, _ = model.Update(AnalysisProgressMsg{
		Progress: counter.AnalysisProgressPayload{
			AnalysisID:     "analysis_123",
			Phase:          analysisPhaseSecret,
			CurrentRepo:    "acme/api",
			ReposCompleted: 1,
			ReposTotal:     3,
			StartedAt:      startedAt,
		},
	})
	model = result.(Model)
	require.Len(t, model.activityLog.entries, 1)
	require.NotNil(t, model.analysisProgress)
	assert.Equal(t, "acme/api", model.analysisProgress.CurrentRepo)

	result, _ = model.Update(AnalysisProgressMsg{
		Progress: counter.AnalysisProgressPayload{
			AnalysisID: "analysis_123",
			Phase:      analysisPhaseImport,
			StartedAt:  startedAt,
		},
	})
	model = result.(Model)
	require.Len(t, model.activityLog.entries, 2)
	assert.Contains(t, model.activityLog.entries[1].Message, "Importing analysis results")
}

func TestModel_Update_AnalysisProgress_IgnoresStaleAnalysisID(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.activeAnalysisID = "analysis_current"
	m.analysisProgress = &counter.AnalysisProgressPayload{
		AnalysisID:  "analysis_current",
		Phase:       analysisPhaseWorkflow,
		CurrentRepo: "acme/api",
	}

	result, _ := m.Update(AnalysisProgressMsg{
		Progress: counter.AnalysisProgressPayload{
			AnalysisID:  "analysis_old",
			Phase:       analysisPhaseImport,
			CurrentRepo: "acme/old",
		},
	})

	model := result.(Model)
	require.NotNil(t, model.analysisProgress)
	assert.Equal(t, "analysis_current", model.analysisProgress.AnalysisID)
	assert.Equal(t, analysisPhaseWorkflow, model.analysisProgress.Phase)
	assert.Equal(t, "acme/api", model.analysisProgress.CurrentRepo)
}

func TestModel_Update_AnalysisResponseDropped_StartsRecoveryPoll(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.activeAnalysisID = "analysis_123"
	m.analysisProgress = &counter.AnalysisProgressPayload{
		AnalysisID: "analysis_123",
		Phase:      analysisPhaseImport,
	}

	result, cmd := m.Update(AnalysisResponseDroppedMsg{
		AnalysisID: "analysis_123",
		Err:        io.EOF,
	})

	model := result.(Model)
	require.NotNil(t, model.analysisResultPoll)
	assert.Equal(t, "analysis_123", model.analysisResultPoll.AnalysisID)
	assert.NotNil(t, model.analysisProgress)
	assert.NotNil(t, cmd)
}

func TestModel_Update_AnalysisProgress_IgnoresLateProgressAfterCompletion(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.beginAnalysisProgress("analysis_123", "acme", "org", false)
	m.clearAnalysisProgress()

	result, _ := m.Update(AnalysisProgressMsg{
		Progress: counter.AnalysisProgressPayload{
			AnalysisID:  "analysis_123",
			Phase:       analysisPhaseImport,
			Message:     "Persisting attack graph",
			CurrentRepo: "acme/repo",
		},
	})

	model := result.(Model)
	assert.Nil(t, model.analysisProgress)
	assert.Equal(t, "analysis_123", model.lastAnalysisID)
}

func TestModel_Update_AnalysisProgress_IgnoresProgressWithoutActiveAnalysisID(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lastAnalysisID = "analysis_previous"

	result, _ := m.Update(AnalysisProgressMsg{
		Progress: counter.AnalysisProgressPayload{
			AnalysisID:  "analysis_other",
			Phase:       analysisPhaseImport,
			Message:     "Persisting attack graph",
			CurrentRepo: "acme/repo",
		},
	})

	model := result.(Model)
	assert.Nil(t, model.analysisProgress)
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
	assert.Nil(t, model.analysisProgress)
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
					BashContext:       "bash_single_quoted",
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

	assert.Equal(t, "bash_single_quoted", v.BashContext)
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
