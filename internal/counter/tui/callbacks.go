// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

const persistentCallbackDefaultDwell = 15 * time.Minute

func cachePoisonPersistentDwell(duration time.Duration) time.Duration {
	if duration > 0 {
		return duration
	}
	return persistentCallbackDefaultDwell
}

func (m *Model) openCallbacksModal() tea.Cmd {
	m.prevView = m.view
	m.prevFocus = m.focus
	m.view = ViewCallbacks
	if m.callbackModal == nil {
		m.callbackModal = &CallbackModalState{}
	}
	m.callbackModal.PreferredID = m.preferredCallbackID()
	return m.fetchCallbacksCmd()
}

func (m Model) fetchCallbacksCmd() tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return CallbackFetchErrorMsg{Err: fmt.Errorf("not connected to kitchen")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		callbacks, err := m.kitchenClient.FetchCallbacks(ctx, m.config.SessionID)
		if err != nil {
			return CallbackFetchErrorMsg{Err: err}
		}
		return CallbacksFetchedMsg{Callbacks: callbacks}
	}
}

func (m Model) controlCallbackCmd(callbackID, action string) tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return CallbackControlFailedMsg{CallbackID: callbackID, Action: action, Err: fmt.Errorf("not connected to kitchen")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		callback, err := m.kitchenClient.ControlCallback(ctx, callbackID, counter.CallbackControlRequest{Action: action})
		if err != nil {
			return CallbackControlFailedMsg{CallbackID: callbackID, Action: action, Err: err}
		}
		return CallbackControlSuccessMsg{Action: action, Callback: *callback}
	}
}

func (m *Model) setCallbacks(callbacks []counter.CallbackPayload) {
	filtered := make([]counter.CallbackPayload, 0, len(callbacks))
	for _, callback := range callbacks {
		if callback.RevokedAt != nil {
			continue
		}
		filtered = append(filtered, callback)
	}
	slices.SortFunc(filtered, func(a, b counter.CallbackPayload) int {
		aTime := a.CreatedAt
		if a.CallbackAt != nil {
			aTime = *a.CallbackAt
		}
		bTime := b.CreatedAt
		if b.CallbackAt != nil {
			bTime = *b.CallbackAt
		}
		switch {
		case aTime.After(bTime):
			return -1
		case aTime.Before(bTime):
			return 1
		default:
			return strings.Compare(a.ID, b.ID)
		}
	})
	m.callbacks = filtered
	if m.callbackModal == nil {
		m.callbackModal = &CallbackModalState{}
	}
	if len(m.callbacks) == 0 {
		m.callbackModal.Cursor = 0
		return
	}
	if preferred := strings.TrimSpace(m.callbackModal.PreferredID); preferred != "" {
		for i := range m.callbacks {
			if m.callbacks[i].ID == preferred {
				m.callbackModal.Cursor = i
				return
			}
		}
	}
	if m.callbackModal.Cursor >= len(m.callbacks) {
		m.callbackModal.Cursor = len(m.callbacks) - 1
	}
	if m.callbackModal.Cursor < 0 {
		m.callbackModal.Cursor = 0
	}
}

func (m *Model) upsertCallback(callback counter.CallbackPayload) {
	for i := range m.callbacks {
		if m.callbacks[i].ID == callback.ID {
			m.callbacks[i] = callback
			m.setCallbacks(m.callbacks)
			return
		}
	}
	m.callbacks = append(m.callbacks, callback)
	m.setCallbacks(m.callbacks)
}

func (m *Model) removeCallback(callbackID string) {
	if strings.TrimSpace(callbackID) == "" {
		return
	}
	filtered := make([]counter.CallbackPayload, 0, len(m.callbacks))
	for _, callback := range m.callbacks {
		if callback.ID == callbackID {
			continue
		}
		filtered = append(filtered, callback)
	}
	m.setCallbacks(filtered)
}

func (m Model) preferredCallbackID() string {
	if m.waiting != nil {
		if m.waiting.CachePoison != nil && strings.TrimSpace(m.waiting.CachePoison.VictimStagerID) != "" {
			return m.waiting.CachePoison.VictimStagerID
		}
		if strings.TrimSpace(m.waiting.StagerID) != "" {
			return m.waiting.StagerID
		}
	}
	return ""
}

func (m Model) callbackIsPersistent(callbackID string) bool {
	for _, callback := range m.callbacks {
		if callback.ID == callbackID {
			return callback.Persistent
		}
	}
	return false
}

func callbackMetadataValue(callback *counter.CallbackPayload, key string) string {
	if callback == nil || callback.Metadata == nil {
		return ""
	}
	return strings.TrimSpace(callback.Metadata[key])
}

func (m Model) callbackIsResidentFoothold(callback *counter.CallbackPayload) bool {
	return callbackMetadataValue(callback, runnerTargetMetadataKindKey) == runnerTargetMetadataKindValue &&
		callbackMetadataValue(callback, runnerTargetMetadataModeKey) == runnerTargetMetadataModeResident
}

func (m Model) callbackIDIsResidentFoothold(callbackID string) bool {
	if strings.TrimSpace(callbackID) == "" {
		return false
	}
	for i := range m.callbacks {
		if m.callbacks[i].ID == callbackID {
			return m.callbackIsResidentFoothold(&m.callbacks[i])
		}
	}
	return false
}

func (m Model) callbackByID(callbackID string) *counter.CallbackPayload {
	if strings.TrimSpace(callbackID) == "" {
		return nil
	}
	for i := range m.callbacks {
		if m.callbacks[i].ID != callbackID {
			continue
		}
		callback := m.callbacks[i]
		return &callback
	}
	return nil
}

func (m *Model) activateWaitingResidentFootholdIfLive() bool {
	if m.waiting == nil || !m.callbackIDIsResidentFoothold(m.waiting.StagerID) {
		return false
	}
	callback := m.callbackByID(m.waiting.StagerID)
	if callback == nil {
		return false
	}
	return m.attachCallback(callback)
}

func (m Model) liveSessionForAgent(agentID string) *Session {
	if strings.TrimSpace(agentID) == "" {
		return nil
	}
	for i := range m.sessions {
		session := &m.sessions[i]
		if session.AgentID != agentID {
			continue
		}
		if session.IsOnline || time.Since(session.LastSeen) < 2*time.Minute {
			return session
		}
	}
	return nil
}

func (m Model) liveSessionForCallback(callback *counter.CallbackPayload) *Session {
	if callback == nil {
		return nil
	}
	if session := m.liveSessionForAgent(strings.TrimSpace(callback.LastAgentID)); session != nil {
		return session
	}
	for _, link := range m.callbackAgents[callback.ID] {
		if session := m.liveSessionForAgent(link.AgentID); session != nil {
			return session
		}
	}
	return nil
}

func (m *Model) attachCallback(callback *counter.CallbackPayload) bool {
	session := m.liveSessionForCallback(callback)
	if session == nil {
		return false
	}

	mode := agentModeExpress
	if m.callbackIsResidentFoothold(callback) {
		mode = agentModeResident
	} else {
		for _, link := range m.callbackAgents[callback.ID] {
			if link.AgentID == session.AgentID && strings.TrimSpace(link.Mode) != "" {
				mode = strings.TrimSpace(link.Mode)
				break
			}
		}
	}

	m.activeAgent = &AgentState{
		ID:        session.AgentID,
		Runner:    session.Hostname,
		Repo:      callbackMetadataValue(callback, "repository"),
		Workflow:  callbackMetadataValue(callback, "workflow"),
		Job:       callbackMetadataValue(callback, "job"),
		Mode:      mode,
		StartTime: time.Now(),
	}
	m.clearDismissedDwellAgent(session.AgentID)
	m.selectSessionByAgentID(session.AgentID)
	switch mode {
	case agentModeResident:
		m.jobDeadline = time.Time{}
		m.dwellMode = true
	case agentModeDwell:
		m.jobDeadline = time.Time{}
		m.dwellMode = true
	default:
		m.jobDeadline = time.Time{}
		m.dwellMode = false
	}
	m.waiting = nil
	m.TransitionToPhase(PhasePostExploit)
	return true
}

func (m *Model) noteCallbackHit(callbackID, agentID, mode string, when time.Time) {
	if callbackID == "" {
		return
	}
	for i := range m.callbacks {
		if m.callbacks[i].ID != callbackID {
			continue
		}
		callbackAt := when
		m.callbacks[i].CalledBack = true
		m.callbacks[i].CallbackAt = &callbackAt
		m.callbacks[i].LastAgentID = agentID
		m.callbacks[i].CallbackCount++
		if mode != "" {
			m.callbacks[i].NextMode = ""
		}
		m.setCallbacks(m.callbacks)
		return
	}
}

func (m Model) selectedCallback() *counter.CallbackPayload {
	if len(m.callbacks) == 0 || m.callbackModal == nil {
		return nil
	}
	cursor := m.callbackModal.Cursor
	if cursor < 0 || cursor >= len(m.callbacks) {
		return nil
	}
	callback := m.callbacks[cursor]
	return &callback
}

func (m *Model) callbackCursorDown() {
	if len(m.callbacks) == 0 || m.callbackModal == nil {
		return
	}
	if m.callbackModal.Cursor < len(m.callbacks)-1 {
		m.callbackModal.Cursor++
	}
}

func (m *Model) callbackCursorUp() {
	if len(m.callbacks) == 0 || m.callbackModal == nil {
		return
	}
	if m.callbackModal.Cursor > 0 {
		m.callbackModal.Cursor--
	}
}

func (m *Model) recordCallbackAgent(callbackID, agentID, hostname, mode string, when time.Time) {
	if callbackID == "" || agentID == "" {
		return
	}
	links := m.callbackAgents[callbackID]
	for i := range links {
		if links[i].AgentID != agentID {
			continue
		}
		links[i].Hostname = hostname
		links[i].LastSeen = when
		if mode != "" {
			links[i].Mode = mode
		}
		m.callbackAgents[callbackID] = links
		return
	}
	links = append(links, CallbackAgentLink{
		AgentID:  agentID,
		Hostname: hostname,
		LastSeen: when,
		Mode:     mode,
	})
	slices.SortFunc(links, func(a, b CallbackAgentLink) int {
		switch {
		case a.LastSeen.After(b.LastSeen):
			return -1
		case a.LastSeen.Before(b.LastSeen):
			return 1
		default:
			return strings.Compare(a.AgentID, b.AgentID)
		}
	})
	m.callbackAgents[callbackID] = links
}

func (m *Model) recordCallbackSecrets(callbackID, agentID string, hits int) {
	if callbackID == "" || agentID == "" || hits <= 0 {
		return
	}
	links := m.callbackAgents[callbackID]
	for i := range links {
		if links[i].AgentID == agentID {
			links[i].SecretHits += hits
			m.callbackAgents[callbackID] = links
			return
		}
	}
}

func (m Model) handleCallbacksKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc", "q", "I", "shift+i", "C", "shift+c":
		m.view = m.prevView
		m.focus = m.prevFocus
		m.updateFocus()
		return m, nil
	case "j", "down":
		m.callbackCursorDown()
		return m, nil
	case "k", "up":
		m.callbackCursorUp()
		return m, nil
	case "enter", "a":
		if callback := m.selectedCallback(); callback != nil {
			if m.attachCallback(callback) {
				m.activityLog.Add(IconSuccess, fmt.Sprintf("Attached to foothold %s", callbackDetailLabel(*callback)))
				return m, nil
			}
			if branch := callbackMetadataValue(callback, runnerTargetMetadataBranchKey); branch != "" {
				m.AddOutput("warning", fmt.Sprintf("Foothold is not live right now. Re-trigger branch %s or wait for the next beacon.", branch))
			} else {
				m.AddOutput("warning", "Foothold is not live right now. Wait for the next beacon before attaching.")
			}
			return m, nil
		}
	case "r":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "revoke")
		}
	case "c":
		if callback := m.selectedCallback(); callback != nil && m.callbackIsResidentFoothold(callback) {
			handle := callbackResidentHandle(*callback)
			if err := clipboardWriteAll(handle); err != nil {
				m.AddOutput("error", fmt.Sprintf("Copy failed: %v", err))
				return m, nil
			}
			m.AddOutput("success", "Copied resident foothold handle to clipboard")
			m.activityLog.Add(IconSuccess, fmt.Sprintf("Copied foothold handle %s", callbackDetailLabel(*callback)))
			return m, nil
		}
	case "t":
		if callback := m.selectedCallback(); callback != nil && m.callbackIsResidentFoothold(callback) {
			instructions := callbackResidentRetriggerRecipe(*callback)
			if err := clipboardWriteAll(instructions); err != nil {
				m.AddOutput("error", fmt.Sprintf("Copy failed: %v", err))
				return m, nil
			}
			if branch := callbackMetadataValue(callback, runnerTargetMetadataBranchKey); branch != "" {
				m.AddOutput("success", fmt.Sprintf("Copied retrigger recipe for branch %s", branch))
			} else {
				m.AddOutput("success", "Copied retrigger recipe for resident foothold")
			}
			m.activityLog.Add(IconSuccess, fmt.Sprintf("Copied retrigger recipe %s", callbackDetailLabel(*callback)))
			return m, nil
		}
	case "e":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "default_express")
		}
	case "d":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "default_dwell")
		}
	case "n":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "arm_next_dwell")
		}
	case "x":
		if callback := m.selectedCallback(); callback != nil {
			return m, m.controlCallbackCmd(callback.ID, "clear_next_override")
		}
	}
	return m, nil
}

func callbackResidentHandle(callback counter.CallbackPayload) string {
	workflow := callbackMetadataValue(&callback, "workflow")
	if workflow == "" {
		workflow = runnerTargetWorkflowPath()
	}
	job := callbackMetadataValue(&callback, "job")
	if job == "" {
		job = runnerTargetWorkflowJobName()
	}

	lines := []string{
		"Foothold: " + callbackDetailLabel(callback),
		"Repo: " + callbackMetadataValue(&callback, "repository"),
		"Workflow: " + workflow,
		"Job: " + job,
	}
	if branch := callbackMetadataValue(&callback, runnerTargetMetadataBranchKey); branch != "" {
		lines = append(lines, "Branch: "+branch)
		if repo := callbackMetadataValue(&callback, "repository"); repo != "" {
			lines = append(lines, "Branch URL: "+GitHubRepoURL(repo)+"/tree/"+branch)
		}
	}
	if route := callbackMetadataValue(&callback, runnerTargetMetadataRouteKey); route != "" {
		lines = append(lines, "Route: "+route)
	}
	if retry := callbackMetadataValue(&callback, runnerTargetMetadataRetryKey); retry != "" {
		lines = append(lines, "Retry: "+retry)
	}
	lines = append(lines, "Callback ID: "+callback.ID)
	return strings.Join(lines, "\n")
}

func callbackResidentRetriggerRecipe(callback counter.CallbackPayload) string {
	repo := callbackMetadataValue(&callback, "repository")
	branch := callbackMetadataValue(&callback, runnerTargetMetadataBranchKey)
	workflow := callbackMetadataValue(&callback, "workflow")
	if workflow == "" {
		workflow = runnerTargetWorkflowPath()
	}
	lines := []string{
		"# Re-trigger resident foothold",
		"# Push any new commit to the branch below to fire the on:push workflow again.",
	}
	if repo != "" {
		lines = append(lines, "Repo: "+repo)
	}
	if branch != "" {
		lines = append(lines, "Branch: "+branch)
	}
	lines = append(lines, "Workflow: "+workflow)
	if route := callbackMetadataValue(&callback, runnerTargetMetadataRouteKey); route != "" {
		lines = append(lines, "Route: "+route)
	}
	if repo != "" && branch != "" {
		lines = append(lines,
			"",
			fmt.Sprintf("git clone git@github.com:%s.git", repo),
			fmt.Sprintf("cd %s", repo[strings.LastIndex(repo, "/")+1:]),
			fmt.Sprintf("git switch %s || git switch -c %s --track origin/%s", branch, branch, branch),
			"git commit --allow-empty -m \"ci: retrigger self-hosted foothold\"",
			fmt.Sprintf("git push origin %s", branch),
		)
	}
	return strings.Join(lines, "\n")
}
