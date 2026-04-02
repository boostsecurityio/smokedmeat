// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

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
}
