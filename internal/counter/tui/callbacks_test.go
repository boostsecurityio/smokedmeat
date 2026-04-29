// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenCallbacksModal_PrefersWaitingCachePoisonVictim(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.view = ViewFindings
	m.focus = FocusInput
	m.waiting = NewWaitingState("writer-stager", "whooli/infrastructure-definitions", "V001", ".github/workflows/benchmark-bot.yml", "review", "Comment", 0)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "whooli/infrastructure-definitions",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "sync",
		},
		VictimStagerID: "victim-stager",
	}

	_ = m.openCallbacksModal()

	require.NotNil(t, m.callbackModal)
	assert.Equal(t, "victim-stager", m.callbackModal.PreferredID)
	assert.Equal(t, ViewCallbacks, m.view)
}

func TestSetCallbacks_SelectsPreferredCallbackID(t *testing.T) {
	now := time.Now()
	m := NewModel(Config{SessionID: "test"})
	m.callbackModal = &CallbackModalState{PreferredID: "victim-stager"}

	m.setCallbacks([]counter.CallbackPayload{
		{ID: "older", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "victim-stager", CreatedAt: now.Add(-time.Minute)},
		{ID: "newer", CreatedAt: now},
	})

	require.NotNil(t, m.selectedCallback())
	assert.Equal(t, "victim-stager", m.selectedCallback().ID)
}

func TestHandleCallbacksKeyMsg_AttachResidentFoothold(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.view = ViewCallbacks
	m.phase = PhaseRecon
	m.callbackModal = &CallbackModalState{Cursor: 0}
	m.callbacks = []counter.CallbackPayload{
		{
			ID:          "cb-runner",
			LastAgentID: "agt-runner",
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
				"repository":       "whooli/infrastructure-definitions",
				"workflow":         runnerTargetWorkflowPath(),
				"job":              runnerTargetWorkflowJobName(),
			},
		},
	}
	m.sessions = []Session{
		{
			AgentID:  "agt-runner",
			Hostname: "whooli-gh-runner",
			LastSeen: time.Now(),
			IsOnline: true,
		},
	}

	result, cmd := m.handleCallbacksKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-runner", model.activeAgent.ID)
	assert.Equal(t, "whooli/infrastructure-definitions", model.activeAgent.Repo)
	assert.Equal(t, agentModeResident, model.activeAgent.Mode)
	assert.True(t, model.dwellMode)
	assert.Equal(t, ViewAgent, model.view)
}

func TestHandleCallbacksKeyMsg_AttachResidentFootholdWarnsWhenOffline(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.view = ViewCallbacks
	m.phase = PhaseRecon
	m.callbackModal = &CallbackModalState{Cursor: 0}
	m.callbacks = []counter.CallbackPayload{
		{
			ID: "cb-runner",
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
				"branch":           "smokedmeat-runner-123",
			},
		},
	}

	result, cmd := m.handleCallbacksKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	last := model.output[len(model.output)-1]
	assert.Equal(t, "warning", last.Type)
	assert.Contains(t, last.Content, "smokedmeat-runner-123")
	assert.Equal(t, ViewCallbacks, model.view)
}

func TestHandleCallbacksKeyMsg_CopyResidentFootholdHandle(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.view = ViewCallbacks
	m.phase = PhaseRecon
	m.callbackModal = &CallbackModalState{Cursor: 0}
	m.callbacks = []counter.CallbackPayload{
		{
			ID: "cb-runner",
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
				"repository":       "whooli/infrastructure-definitions",
				"workflow":         runnerTargetWorkflowPath(),
				"job":              runnerTargetWorkflowJobName(),
				"branch":           "smokedmeat-runner-123",
				"deploy_route":     "ssh",
				"retry_policy":     "trycloudflare-1h",
			},
		},
	}

	original := clipboardWriteAll
	t.Cleanup(func() { clipboardWriteAll = original })

	var copied string
	clipboardWriteAll = func(text string) error {
		copied = text
		return nil
	}

	result, cmd := m.handleCallbacksKeyMsg(tea.KeyPressMsg{Text: "c", Code: 'c'})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Contains(t, copied, "Foothold:")
	assert.Contains(t, copied, "Repo: whooli/infrastructure-definitions")
	assert.Contains(t, copied, "Workflow: "+runnerTargetWorkflowPath())
	assert.Contains(t, copied, "Branch: smokedmeat-runner-123")
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Copied resident foothold handle")
}

func TestHandleCallbacksKeyMsg_CopiesResidentFootholdRetriggerRecipe(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.view = ViewCallbacks
	m.phase = PhaseRecon
	m.callbackModal = &CallbackModalState{Cursor: 0}
	m.callbacks = []counter.CallbackPayload{
		{
			ID: "cb-runner",
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
				"repository":       "whooli/infrastructure-definitions",
				"workflow":         runnerTargetWorkflowPath(),
				"job":              runnerTargetWorkflowJobName(),
				"branch":           "smokedmeat-runner-123",
				"deploy_route":     "ssh",
			},
		},
	}

	original := clipboardWriteAll
	t.Cleanup(func() { clipboardWriteAll = original })

	var copied string
	clipboardWriteAll = func(text string) error {
		copied = text
		return nil
	}

	result, cmd := m.handleCallbacksKeyMsg(tea.KeyPressMsg{Text: "t", Code: 't'})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Contains(t, copied, "# Re-trigger resident foothold")
	assert.Contains(t, copied, "git clone git@github.com:whooli/infrastructure-definitions.git")
	assert.Contains(t, copied, "git push origin smokedmeat-runner-123")
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Copied retrigger recipe for branch smokedmeat-runner-123")
}
