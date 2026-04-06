// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func TestAvailableCommentTargets_KeepsEditableTargetsAfterLookupFailure(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.wizard = &WizardState{
		Step:           3,
		DeliveryMethod: DeliveryComment,
		CommentTarget:  CommentTargetIssue,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
		Preflight: &counter.DeployPreflightResponse{
			Capabilities: map[string]counter.DeployPreflightCapability{
				deployCapabilityCommentIssue: {State: deployStateFail, Reason: "issue target does not exist"},
				deployCapabilityCommentPR:    {State: deployStateDenied, Reason: "denied"},
				deployCapabilityCommentStub:  {State: deployStateFail, Reason: "forking is disabled on this repository"},
			},
		},
	}

	m.normalizeCommentTarget()

	assert.Equal(t, CommentTargetIssue, m.wizard.CommentTarget)
	assert.Equal(t, []CommentTarget{CommentTargetIssue, CommentTargetPullRequest}, m.availableCommentTargets())
}

func TestWizardKeyMsg_CommentInputStartsPreflight(t *testing.T) {
	mock := &mockKitchenClient{fetchPreflightResp: &counter.DeployPreflightResponse{Capabilities: map[string]counter.DeployPreflightCapability{}}}
	m := NewModel(Config{SessionID: "test"})
	m.kitchenClient = mock
	m.phase = PhaseWizard
	m.view = ViewWizard
	m.tokenInfo = &TokenInfo{Value: "github_pat_test", Type: TokenTypeFineGrainedPAT}
	m.wizard = &WizardState{
		Step:           3,
		DeliveryMethod: DeliveryComment,
		CommentTarget:  CommentTargetIssue,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
	}
	m.wizardInput.Focus()

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Text: "5", Code: '5'})
	model := result.(Model)

	require.NotNil(t, cmd)
	assert.True(t, model.wizard.PreflightLoading)
	assert.NotEmpty(t, model.wizard.PreflightKey)
}

func TestHandlePasteMsg_WizardCommentInputStartsPreflight(t *testing.T) {
	mock := &mockKitchenClient{fetchPreflightResp: &counter.DeployPreflightResponse{Capabilities: map[string]counter.DeployPreflightCapability{}}}
	m := NewModel(Config{SessionID: "test"})
	m.kitchenClient = mock
	m.phase = PhaseWizard
	m.view = ViewWizard
	m.tokenInfo = &TokenInfo{Value: "github_pat_test", Type: TokenTypeFineGrainedPAT}
	m.wizard = &WizardState{
		Step:           3,
		DeliveryMethod: DeliveryComment,
		CommentTarget:  CommentTargetPullRequest,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
	}
	m.wizardInput.Focus()

	result, cmd := m.handlePasteMsg(tea.PasteMsg{Content: "12"})
	model := result.(Model)

	require.NotNil(t, cmd)
	assert.True(t, model.wizard.PreflightLoading)
	assert.NotEmpty(t, model.wizard.PreflightKey)
}

func TestExecuteWizardDeployment_PreflightBlockedBeforeStager(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp}
	m.wizard = &WizardState{
		Step:           3,
		DeliveryMethod: DeliveryAutoPR,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "pr_body", ID: "V001"},
		Preflight: &counter.DeployPreflightResponse{
			Capabilities: map[string]counter.DeployPreflightCapability{
				deployCapabilityPR: {State: deployStateFail, Reason: "forking is disabled on this repository"},
			},
		},
	}

	result, cmd := m.executeWizardDeployment()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "forking is disabled on this repository")
}

func TestStartWizardPreflight_ClearsStaleDispatchStatusWithoutCredential(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.kitchenClient = &mockKitchenClient{}
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT}
	m.wizard = &WizardState{
		Step:             3,
		DeliveryMethod:   DeliveryAutoDispatch,
		SelectedVuln:     &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "workflow_dispatch_input"},
		PreflightKey:     "stale",
		PreflightError:   "stale error",
		PreflightLoading: true,
		Preflight: &counter.DeployPreflightResponse{
			Capabilities: map[string]counter.DeployPreflightCapability{
				deployCapabilityDispatch: {State: deployStateConfirmed, Reason: ""},
			},
		},
	}

	cmd := m.startWizardPreflight(false)
	state, reason := m.deliveryMethodStatus(DeliveryAutoDispatch)

	assert.Nil(t, cmd)
	assert.Empty(t, m.wizard.PreflightKey)
	assert.False(t, m.wizard.PreflightLoading)
	assert.Empty(t, m.wizard.PreflightError)
	assert.Nil(t, m.wizard.Preflight)
	assert.Equal(t, deployStateFail, state)
	assert.Equal(t, "No dispatch-capable token is available", reason)
}
