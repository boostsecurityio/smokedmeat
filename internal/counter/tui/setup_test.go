// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"io"
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupTokenInfo_FineGrainedShowsWarning(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:         5,
		TokenSubStep: setupTokenSubStepInput,
		TokenValue:   "github_pat_abcdefghijklmnopqrstuvwxyz123456",
	}

	result, _ := m.Update(SetupTokenInfoMsg{
		Owner:  "tester",
		Scopes: []string{"contents:read"},
	})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 5, model.setupWizard.Step)
	assert.Equal(t, setupTokenSubStepWarning, model.setupWizard.TokenSubStep)
	assert.Equal(t, "tester", model.setupWizard.TokenOwner)
	assert.Equal(t, "contents:read", model.setupWizard.TokenScopes)
	require.NotNil(t, model.tokenInfo)
	assert.Equal(t, TokenTypeFineGrainedPAT, model.tokenInfo.Type)
}

func TestSetupTokenInfoError_FineGrainedShowsWarning(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:         5,
		TokenSubStep: setupTokenSubStepInput,
		TokenValue:   "github_pat_abcdefghijklmnopqrstuvwxyz123456",
	}

	result, _ := m.Update(SetupTokenInfoErrorMsg{})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 5, model.setupWizard.Step)
	assert.Equal(t, setupTokenSubStepWarning, model.setupWizard.TokenSubStep)
	require.NotNil(t, model.tokenInfo)
	assert.Equal(t, TokenTypeFineGrainedPAT, model.tokenInfo.Type)
}

func TestSetupTokenInfo_ClassicAdvancesToTargetStep(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:         5,
		TokenSubStep: setupTokenSubStepInput,
		TokenValue:   "ghp_abcdefghijklmnopqrstuvwxyz123456",
	}

	result, _ := m.Update(SetupTokenInfoMsg{
		Owner:  "tester",
		Scopes: []string{"public_repo"},
	})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 6, model.setupWizard.Step)
	assert.Equal(t, 0, model.setupWizard.TargetSubStep)
}

func TestSetupWarningEnterContinuesToTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:          5,
		BackStepFloor: 5,
		TokenSubStep:  setupTokenSubStepWarning,
		TokenValue:    "github_pat_abcdefghijklmnopqrstuvwxyz123456",
	}

	result, _ := m.handleSetupWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 6, model.setupWizard.Step)
	assert.Equal(t, 0, model.setupWizard.TargetSubStep)
}

func TestSetupTabDoesNotLeaveTokenStepAtBackFloor(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:          5,
		BackStepFloor: 5,
		TokenSubStep:  setupTokenSubStepChoice,
	}

	result, _ := m.handleSetupWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyTab})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 5, model.setupWizard.Step)
	assert.Equal(t, setupTokenSubStepChoice, model.setupWizard.TokenSubStep)
}

func TestSetupTabBlockedPreservesFeedback(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:          5,
		BackStepFloor: 5,
		TokenSubStep:  setupTokenSubStepChoice,
		Error:         "keep this error",
		Status:        "keep this status",
	}

	result, _ := m.handleSetupWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyTab})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, "keep this error", model.setupWizard.Error)
	assert.Equal(t, "keep this status", model.setupWizard.Status)
}

func TestSetupTabReturnsToTokenChoiceWithinStep(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:          5,
		BackStepFloor: 5,
		TokenSubStep:  setupTokenSubStepWarning,
	}

	result, _ := m.handleSetupWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyTab})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 5, model.setupWizard.Step)
	assert.Equal(t, setupTokenSubStepChoice, model.setupWizard.TokenSubStep)
}

func TestSetupTabFromTargetStepStopsAtTokenStep(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:          6,
		BackStepFloor: 5,
		TargetSubStep: 0,
	}

	result, _ := m.handleSetupWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyTab})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 5, model.setupWizard.Step)
}

func TestAdvanceSetupStep_PATUsesPasswordEcho(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:         5,
		TokenSubStep: setupTokenSubStepChoice,
		TokenChoice:  SetupTokenPAT,
	}

	result, _ := m.advanceSetupStep()

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, setupTokenSubStepInput, model.setupWizard.TokenSubStep)
	assert.Equal(t, textinput.EchoPassword, model.setupInput.EchoMode)
}

func TestAdvanceSetupStep_OPUsesNormalEcho(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:         5,
		TokenSubStep: setupTokenSubStepChoice,
		TokenChoice:  SetupTokenOP,
	}
	m.setupInput.EchoMode = textinput.EchoPassword

	result, _ := m.advanceSetupStep()

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, setupTokenSubStepInput, model.setupWizard.TokenSubStep)
	assert.Equal(t, textinput.EchoNormal, model.setupInput.EchoMode)
}

func TestSetupBrowserOpenedUsesPasswordEcho(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:        5,
		TokenChoice: SetupTokenBrowser,
	}

	result, _ := m.Update(setupBrowserOpenedMsg{})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, setupTokenSubStepInput, model.setupWizard.TokenSubStep)
	assert.Equal(t, textinput.EchoPassword, model.setupInput.EchoMode)
}

func TestRenderSetupWizardView_FineGrainedWarning(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 100
	m.setupWizard = &SetupWizardState{
		Step:         5,
		TokenSubStep: setupTokenSubStepWarning,
		TokenValue:   "github_pat_abcdefghijklmnopqrstuvwxyz123456",
	}

	out := stripANSI(m.renderSetupWizardView(24))

	assert.Contains(t, out, "Fine-grained PAT detected")
	assert.Contains(t, out, "Classic PAT is recommended for first access.")
	assert.Contains(t, out, "Press Enter to continue or Tab to choose a different token.")
	assert.NotContains(t, out, "whooli")
}

func TestSetupStep7EnterOnErrorRetriesInsteadOfLeavingSetup(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:   7,
		Error:  "Analysis failed: EOF",
		Status: "old status",
	}

	result, cmd := m.handleSetupWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.Equal(t, 7, model.setupWizard.Step)
	assert.True(t, model.setupWizard.AnalysisRunning)
	assert.False(t, model.setupWizard.AnalysisRetryPending)
	assert.Empty(t, model.setupWizard.Error)
	assert.Empty(t, model.setupWizard.Status)
	assert.NotNil(t, cmd)
}

func TestSetupAnalysisErrorMsg_RetryableSchedulesRetry(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:            7,
		AnalysisRunning: true,
	}

	result, cmd := m.Update(SetupAnalysisErrorMsg{
		Err: fmt.Errorf("failed to send request to Kitchen: %w", io.EOF),
	})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.False(t, model.setupWizard.AnalysisRunning)
	assert.True(t, model.setupWizard.AnalysisRetryPending)
	assert.Equal(t, 1, model.setupWizard.AnalysisAttempt)
	assert.Empty(t, model.setupWizard.Error)
	assert.Contains(t, model.setupWizard.Status, "retrying in 2s")
	assert.NotNil(t, cmd)
}

func TestSetupAnalysisRetryMsg_RestartsAnalysis(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:                 7,
		AnalysisAttempt:      1,
		AnalysisRetryPending: true,
		Error:                "Analysis failed: EOF",
		Status:               "Analyze request dropped, retrying in 2s... (attempt 1/3)",
	}

	result, cmd := m.Update(setupAnalysisRetryMsg{})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.True(t, model.setupWizard.AnalysisRunning)
	assert.False(t, model.setupWizard.AnalysisRetryPending)
	assert.Empty(t, model.setupWizard.Error)
	assert.Empty(t, model.setupWizard.Status)
	assert.Equal(t, 1, model.setupWizard.AnalysisAttempt)
	assert.NotNil(t, cmd)
}

func TestSetupAnalysisErrorMsg_RetryableExhaustedShowsError(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.setupWizard = &SetupWizardState{
		Step:            7,
		AnalysisRunning: true,
		AnalysisAttempt: len(setupAnalysisRetryDelays()),
	}

	result, cmd := m.Update(SetupAnalysisErrorMsg{
		Err: fmt.Errorf("failed to send request to Kitchen: %w", io.EOF),
	})

	model := result.(Model)
	require.NotNil(t, model.setupWizard)
	assert.False(t, model.setupWizard.AnalysisRunning)
	assert.False(t, model.setupWizard.AnalysisRetryPending)
	assert.Empty(t, model.setupWizard.Status)
	assert.Contains(t, model.setupWizard.Error, "Analysis failed after 3 retries")
	assert.Nil(t, cmd)
}
