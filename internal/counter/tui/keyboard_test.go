// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKeyboardTestModel() Model {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusInput
	m.input.Focus()
	m.input.SetValue("")
	return m
}

func TestHandleKeyMsg_InputFocusTypesFirstCharacter(t *testing.T) {
	m := newKeyboardTestModel()
	m.paneFocus = PaneFocusFindings

	result, _ := m.Update(tea.KeyPressMsg{Text: "g", Code: 'g'})

	model := result.(Model)
	assert.Equal(t, "g", model.input.Value())
	assert.False(t, model.quitting)
}

func TestHandleKeyMsg_InputFocusSuppressesLootShortcut(t *testing.T) {
	m := newKeyboardTestModel()
	m.paneFocus = PaneFocusLoot
	m.lootStash = []CollectedSecret{
		{Name: "PAT", Value: "ghp_test123", Type: "github_pat"},
	}
	m.RebuildLootTree()

	result, _ := m.Update(tea.KeyPressMsg{Text: "c", Code: 'c'})

	model := result.(Model)
	assert.Equal(t, "c", model.input.Value())
	assert.False(t, model.lootFlash)
}

func TestHandleKeyMsg_InputFocusEnterDoesNotTriggerPaneAction(t *testing.T) {
	m := newKeyboardTestModel()
	m.paneFocus = PaneFocusMenu
	m.suggestions = []SuggestedAction{{Command: "graph"}}
	m.menuCursor = 0

	result, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	assert.Empty(t, model.input.Value())
	assert.Empty(t, model.output)
}

func TestHandleKeyMsg_InputFocusEnterShowsUnknownCommandInActivityLog(t *testing.T) {
	m := newKeyboardTestModel()
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.input.SetValue("8oifsdfusoi")

	result, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	assert.Empty(t, model.input.Value())
	require.NotEmpty(t, model.activityLog.Entries())
	last := model.activityLog.Entries()[len(model.activityLog.Entries())-1]
	assert.Equal(t, "Type 'help' for local commands", last.Message)
	prev := model.activityLog.Entries()[len(model.activityLog.Entries())-2]
	assert.Equal(t, "Unknown command: 8oifsdfusoi", prev.Message)
	assert.False(t, model.activityLogExpandedUntil.IsZero())
}

func TestHandleKeyMsg_InputFocusUpDownBrowseHistory(t *testing.T) {
	m := newKeyboardTestModel()
	m.history = []string{"recon", "pivot gcp", "cloud buckets"}
	m.historyIndex = -1

	result, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	model := result.(Model)
	assert.Equal(t, "cloud buckets", model.input.Value())
	assert.Equal(t, 0, model.historyIndex)

	result, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	model = result.(Model)
	assert.Equal(t, "pivot gcp", model.input.Value())
	assert.Equal(t, 1, model.historyIndex)

	result, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	model = result.(Model)
	assert.Equal(t, "cloud buckets", model.input.Value())
	assert.Equal(t, 0, model.historyIndex)

	result, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	model = result.(Model)
	assert.Empty(t, model.input.Value())
	assert.Equal(t, -1, model.historyIndex)
}

func TestHandleKeyMsg_InputFocusQTypesIntoInput(t *testing.T) {
	m := newKeyboardTestModel()
	m.input.SetValue("cloud")

	result, _ := m.Update(tea.KeyPressMsg{Text: "q", Code: 'q'})

	model := result.(Model)
	assert.Equal(t, "cloudq", model.input.Value())
	assert.False(t, model.quitting)
}

func TestHandleKeyMsg_WaitingPhaseDoesNotRouteLettersToHiddenInput(t *testing.T) {
	m := newKeyboardTestModel()
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stager-1", "org/repo", "V001", ".github/workflows/ci.yml", "build", "Issue", 0)

	result, _ := m.Update(tea.KeyPressMsg{Text: "I", Code: 'I'})

	model := result.(Model)
	assert.Equal(t, ViewCallbacks, model.view)
	assert.Empty(t, model.input.Value())
}

func TestHandleCallbacksKeyMsg_CloseRestoresFocus(t *testing.T) {
	m := newKeyboardTestModel()
	m.view = ViewCallbacks
	m.prevView = ViewAgent
	m.focus = FocusSessions
	m.prevFocus = FocusInput
	m.input.Blur()

	result, _ := m.handleCallbacksKeyMsg(tea.KeyPressMsg{Code: tea.KeyEscape})

	model := result.(Model)
	assert.Equal(t, ViewAgent, model.view)
	assert.Equal(t, FocusInput, model.focus)
	assert.True(t, model.input.Focused())
}

func TestHandleKeyMsg_FKeysFocusPanes(t *testing.T) {
	tests := []struct {
		name      string
		key       rune
		focus     Focus
		paneFocus PaneFocus
	}{
		{"f1 findings", tea.KeyF1, FocusSessions, PaneFocusFindings},
		{"f2 menu", tea.KeyF2, FocusSessions, PaneFocusMenu},
		{"f3 loot", tea.KeyF3, FocusSessions, PaneFocusLoot},
		{"f4 activity", tea.KeyF4, FocusSessions, PaneFocusActivity},
		{"f5 input", tea.KeyF5, FocusInput, PaneFocusFindings},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newKeyboardTestModel()
			m.focus = FocusInput
			m.paneFocus = PaneFocusFindings

			result, _ := m.Update(tea.KeyPressMsg{Code: tt.key})

			model := result.(Model)
			assert.Equal(t, tt.focus, model.focus)
			assert.Equal(t, tt.paneFocus, model.paneFocus)
		})
	}
}

func TestHandleKeyMsg_SlashOpensOmnibox(t *testing.T) {
	m := newKeyboardTestModel()

	result, _ := m.Update(tea.KeyPressMsg{Text: "/", Code: '/'})

	model := result.(Model)
	assert.Equal(t, ViewOmnibox, model.view)
	if assert.NotNil(t, model.omnibox) {
		assert.True(t, model.omnibox.input.Focused())
	}
}

func TestHandleKeyMsg_SlashTypesInInputWhenCommandStarted(t *testing.T) {
	m := newKeyboardTestModel()
	m.input.SetValue("pivot github whooli")
	m.input.CursorEnd()

	result, _ := m.Update(tea.KeyPressMsg{Text: "/", Code: '/'})

	model := result.(Model)
	assert.Equal(t, ViewAgent, model.view)
	assert.Nil(t, model.omnibox)
	assert.Equal(t, "pivot github whooli/", model.input.Value())
}
