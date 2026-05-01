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

func TestHandleKeyMsg_XOpensWorkflowDispatchWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.paneFocus = PaneFocusFindings
	m.focus = FocusSessions
	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/api", Type: TreeNodeRepo, Label: "acme/api", Parent: root, Expanded: true}
	workflow := &TreeNode{
		ID:       "repo:acme/api:workflow:.github/workflows/deploy.yml",
		Type:     TreeNodeWorkflow,
		Label:    ".github/workflows/deploy.yml",
		Parent:   repo,
		Expanded: true,
		Properties: map[string]interface{}{
			"path":           ".github/workflows/deploy.yml",
			"default_branch": "main",
			"event_triggers": []string{"push", "workflow_dispatch"},
			"dispatch_inputs": []counter.WorkflowDispatchInput{{
				Name:     "environment",
				Required: true,
				Default:  "prod",
				Type:     "choice",
				Options:  []string{"dev", "prod"},
			}},
		},
	}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{workflow}
	m.treeRoot = root
	m.ReflattenTree()
	for i, node := range m.treeNodes {
		if node == workflow {
			m.treeCursor = i
			break
		}
	}

	result, _ := m.Update(tea.KeyPressMsg{Text: "x", Code: 'x'})

	model := result.(Model)
	require.NotNil(t, model.wizard)
	require.NotNil(t, model.wizard.SelectedDispatch)
	assert.Equal(t, WizardKindWorkflowDispatch, model.wizard.Kind)
	assert.Equal(t, "acme/api", model.wizard.SelectedDispatch.Repository)
	assert.Equal(t, "prod", model.wizard.SelectedDispatch.Values["environment"])
}

func TestWorkflowDispatchWizard_BlocksMissingRequiredInput(t *testing.T) {
	m := newModelWithMockClient(&mockKitchenClient{})
	require.NoError(t, m.OpenWorkflowDispatchWizard(&WorkflowDispatchSelection{
		Repository: "acme/api",
		Workflow:   ".github/workflows/deploy.yml",
		Inputs: []counter.WorkflowDispatchInput{{
			Name:     "environment",
			Required: true,
			Type:     "string",
		}},
		Values: map[string]string{"environment": ""},
	}))

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "required input environment is empty")
}

func TestWorkflowDispatchWizard_TriggersWithInputs(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelWithMockClient(mock)
	m.lootStash = []CollectedSecret{{
		Name:  "PAT",
		Value: "ghp_dispatch",
		Type:  "github_pat",
	}}
	require.NoError(t, m.OpenWorkflowDispatchWizard(&WorkflowDispatchSelection{
		Repository: "acme/api",
		Workflow:   ".github/workflows/deploy.yml",
		Ref:        "main",
		Inputs: []counter.WorkflowDispatchInput{{
			Name:    "environment",
			Default: "prod",
			Type:    "string",
		}},
		Values: map[string]string{"environment": "prod"},
	}))

	_, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})
	require.NotNil(t, cmd)
	msg := cmd()

	success, ok := msg.(AutoDispatchSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "acme/api", success.Repository)
	assert.Equal(t, ".github/workflows/deploy.yml", success.Workflow)
	assert.Equal(t, "prod", mock.lastTriggerDispatchReq.Inputs["environment"])
	assert.Equal(t, "main", mock.lastTriggerDispatchReq.Ref)
}
