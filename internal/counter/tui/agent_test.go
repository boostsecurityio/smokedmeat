// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func TestHandleColeslaw_PlainStdout(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	coleslaw := &models.Coleslaw{
		OrderID: "order-12345678",
		AgentID: "brisket-001",
		Stdout:  b64("line1\nline2\n"),
	}

	result, _ := m.handleColeslaw(ColeslawMsg{Coleslaw: coleslaw})

	model := result.(Model)
	require.True(t, len(model.output) >= 3)
	assert.Equal(t, "info", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "order-12")
	assert.Equal(t, "output", model.output[1].Type)
	assert.Equal(t, "line1", model.output[1].Content)
	assert.Equal(t, "output", model.output[2].Type)
	assert.Equal(t, "line2", model.output[2].Content)
}

func TestHandleColeslaw_Stderr(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	coleslaw := &models.Coleslaw{
		OrderID: "order-12345678",
		AgentID: "brisket-001",
		Stderr:  b64("error occurred"),
	}

	result, _ := m.handleColeslaw(ColeslawMsg{Coleslaw: coleslaw})

	model := result.(Model)
	hasError := false
	for _, line := range model.output {
		if line.Type == "error" && line.Content == "error occurred" {
			hasError = true
		}
	}
	assert.True(t, hasError, "Should display stderr as error output")
}

func TestHandleColeslaw_NonZeroExitCode(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	coleslaw := &models.Coleslaw{
		OrderID:  "order-12345678",
		AgentID:  "brisket-001",
		ExitCode: 1,
	}

	result, _ := m.handleColeslaw(ColeslawMsg{Coleslaw: coleslaw})

	model := result.(Model)
	hasWarning := false
	for _, line := range model.output {
		if line.Type == "warning" && line.Content == "Exit code: 1" {
			hasWarning = true
		}
	}
	assert.True(t, hasWarning, "Should display non-zero exit code as warning")
}

func TestHandleColeslaw_EmptyOutput(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	coleslaw := &models.Coleslaw{
		OrderID: "order-12345678",
		AgentID: "brisket-001",
	}

	result, _ := m.handleColeslaw(ColeslawMsg{Coleslaw: coleslaw})

	model := result.(Model)
	require.Len(t, model.output, 1, "Should only have the info header line")
	assert.Equal(t, "info", model.output[0].Type)
}

func TestHandleExpressData_SecretsCollected(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.target = "acme/api"

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "GITHUB_TOKEN", Value: "ghs_test123", Type: "github_token", Source: "env", HighValue: false},
			{Name: "AWS_ACCESS_KEY_ID", Value: "AKIAXXXXXXXX", Type: "aws", Source: "env", HighValue: true},
		},
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Job:        "build",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})

	model := result.(Model)
	assert.Len(t, model.sessionLoot, 1, "Ephemeral secret should go to session loot")
	assert.Equal(t, "GITHUB_TOKEN", model.sessionLoot[0].Name)
	assert.True(t, model.sessionLoot[0].ExpressMode)

	assert.Len(t, model.lootStash, 1, "High-value secret should go to loot stash")
	assert.Equal(t, "AWS_ACCESS_KEY_ID", model.lootStash[0].Name)
	assert.False(t, model.lootStash[0].ExpressMode)
}

func TestHandleExpressData_BackfillsActiveAgentContext(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.activityLog = NewActivityLog()
	m.sessions = []Session{{AgentID: "agt-victim"}}
	m.selectedIndex = 0
	m.activeAgent = &AgentState{
		ID:     "agt-victim",
		Runner: "runner-1",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: counter.ExpressDataPayload{
		AgentID:    "agt-victim",
		Hostname:   "runner-1",
		Repository: "whooli/infrastructure-definitions",
		Workflow:   ".github/workflows/deploy.yml",
		Job:        "sync",
		Timestamp:  time.Now(),
	}})

	model := result.(Model)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "whooli/infrastructure-definitions", model.activeAgent.Repo)
	assert.Equal(t, ".github/workflows/deploy.yml", model.activeAgent.Workflow)
	assert.Equal(t, "sync", model.activeAgent.Job)
	require.NotNil(t, model.SelectedSession())
	assert.Equal(t, "whooli/infrastructure-definitions", model.SelectedSession().Repo)
	assert.Equal(t, ".github/workflows/deploy.yml", model.SelectedSession().Workflow)
	assert.Equal(t, "sync", model.SelectedSession().Job)
}

func TestClearSessionContext_RemovesRepoWorkflowJobForAgent(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.sessions = []Session{
		{
			AgentID:  "agt-1",
			Repo:     "acme/api",
			Workflow: ".github/workflows/deploy.yml",
			Job:      "deploy",
		},
		{
			AgentID:  "agt-2",
			Repo:     "acme/other",
			Workflow: ".github/workflows/build.yml",
			Job:      "build",
		},
	}

	m.clearSessionContext("agt-1")

	assert.Empty(t, m.sessions[0].Repo)
	assert.Empty(t, m.sessions[0].Workflow)
	assert.Empty(t, m.sessions[0].Job)
	assert.Equal(t, "acme/other", m.sessions[1].Repo)
	assert.Equal(t, ".github/workflows/build.yml", m.sessions[1].Workflow)
	assert.Equal(t, "build", m.sessions[1].Job)
}

func TestHandleExpressData_TokenPermissions(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	data := counter.ExpressDataPayload{
		AgentID:  "brisket-001234567890",
		Hostname: "runner-1",
		Secrets: []counter.ExtractedSecret{{
			Name:       "GITHUB_TOKEN",
			Value:      "ghs_live123",
			Type:       "github_token",
			Source:     "env",
			Repository: "acme/api",
			Workflow:   ".github/workflows/ci.yml",
			Job:        "build",
		}},
		TokenPermissions: map[string]string{
			"contents": "write",
			"packages": "read",
		},
		Timestamp: time.Now(),
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})

	model := result.(Model)
	require.NotNil(t, model.tokenPermissions)
	assert.Equal(t, "write", model.tokenPermissions["contents"])
	assert.Equal(t, "read", model.tokenPermissions["packages"])
	require.Len(t, model.sessionLoot, 1)
	assert.Equal(t, "write", model.displayPermissionsForSecret(model.sessionLoot[0])["contents"])
}

func TestHandleExpressData_CachePoisonArmed(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Create Issue", 0)
	m.waiting.CachePoison = &CachePoisonWaitingState{}

	data := counter.ExpressDataPayload{
		AgentID:    "brisket-001234567890",
		Hostname:   "runner-1",
		Timestamp:  time.Now(),
		CallbackID: "stg-1",
		CachePoison: &models.CachePoisonStatus{
			Status:  "armed",
			Key:     "nucleus-build-123",
			Version: "aeec744d",
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.Len(t, model.output, 2)
	assert.Equal(t, "success", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "Cache poison armed")
	assert.Contains(t, model.output[0].Content, "nucleus-build-123")
	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	require.NotNil(t, model.waiting.CachePoison.WriterStatus)
	assert.Equal(t, "armed", model.waiting.CachePoison.WriterStatus.Status)
}

func TestHandleExpressData_CachePoisonArmedBeforeStartWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pendingCachePoison = &CachePoisonWaitingState{
		WriterStagerID: "stg-1",
	}

	data := counter.ExpressDataPayload{
		AgentID:    "brisket-001234567890",
		Hostname:   "runner-1",
		Timestamp:  time.Now(),
		CallbackID: "stg-1",
		CachePoison: &models.CachePoisonStatus{
			Status:  "armed",
			Key:     "nucleus-build-123",
			Version: "aeec744d",
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.NotNil(t, model.pendingCachePoison)
	require.NotNil(t, model.pendingCachePoison.WriterStatus)
	assert.Equal(t, "armed", model.pendingCachePoison.WriterStatus.Status)
	assert.Equal(t, "brisket-001234567890", model.pendingCachePoison.WriterAgentID)

	vuln := &Vulnerability{Repository: "acme/api", ID: "V001", Workflow: ".github/workflows/lint.yml", Job: "lint"}
	model.StartWaiting("stg-1", "", vuln, "Issue", 0)
	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	require.NotNil(t, model.waiting.CachePoison.WriterStatus)
	assert.Equal(t, "armed", model.waiting.CachePoison.WriterStatus.Status)
	assert.Equal(t, "brisket-001234567890", model.waiting.CachePoison.WriterAgentID)
}

func TestHandleExpressData_CachePoisonArmedWithoutCallbackIDUsesCurrentWaitingWriter(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 0)
	m.waiting.CachePoison = &CachePoisonWaitingState{}

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		CachePoison: &models.CachePoisonStatus{
			Status:  "armed",
			Key:     "nucleus-build-123",
			Version: "aeec744d",
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	require.NotNil(t, model.waiting.CachePoison.WriterStatus)
	assert.Equal(t, "armed", model.waiting.CachePoison.WriterStatus.Status)
	assert.Equal(t, "brisket-001234567890", model.waiting.CachePoison.WriterAgentID)
}

func TestHandleExpressData_CachePoisonFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		CachePoison: &models.CachePoisonStatus{
			Status: "failed",
			Error:  "no actions cache service URL found in environment",
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.Len(t, model.output, 2)
	assert.Equal(t, "error", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "Cache poison failed")
	assert.Contains(t, model.output[0].Content, "no actions cache service URL found in environment")
}

func TestHandleExpressData_CachePoisonVictimWithCallbackIDTransitionsToPostExploit(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}

	data := counter.ExpressDataPayload{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		Timestamp:    time.Now(),
		CallbackID:   "victim-stg",
		CallbackMode: "dwell",
		Repository:   "acme/api",
		Workflow:     ".github/workflows/deploy.yml",
		Job:          "deploy",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-victim", model.activeAgent.ID)
	assert.Equal(t, ".github/workflows/deploy.yml", model.activeAgent.Workflow)
	assert.Equal(t, "deploy", model.activeAgent.Job)
	assert.Nil(t, model.waiting)
}

func TestHandleExpressData_CachePoisonVictimWithoutCallbackIDUsesMatchingExpressData(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.sessions = []Session{
		{AgentID: "agt-old"},
		{AgentID: "agt-victim"},
	}
	m.selectedIndex = 0
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}
	m.waiting.PendingAgents["agt-victim"] = time.Now()

	data := counter.ExpressDataPayload{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		Timestamp:    time.Now(),
		CallbackMode: "dwell",
		Repository:   "acme/api",
		Workflow:     ".github/workflows/deploy.yml",
		Job:          "deploy",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-victim", model.activeAgent.ID)
	assert.Equal(t, ".github/workflows/deploy.yml", model.activeAgent.Workflow)
	assert.Equal(t, "deploy", model.activeAgent.Job)
	assert.Nil(t, model.waiting)
	require.NotNil(t, model.SelectedSession())
	assert.Equal(t, "agt-victim", model.SelectedSession().AgentID)
}

func TestHandleExpressData_CachePoisonVictimWithoutCallbackIDIgnoresMismatchedOrigin(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}
	m.waiting.PendingAgents["agt-victim"] = time.Now()

	data := counter.ExpressDataPayload{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		Timestamp:    time.Now(),
		CallbackMode: "dwell",
		Repository:   "acme/api",
		Workflow:     ".github/workflows/release.yml",
		Job:          "deploy",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, PhaseWaiting, model.phase)
	assert.Nil(t, model.activeAgent)
	assert.Empty(t, model.waiting.CachePoison.VictimAgentID)
}

func TestHandleExpressData_CachePoisonVictimWithoutCallbackIDMatchesOriginBeforeBeacon(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.sessions = []Session{{AgentID: "agt-victim"}}
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}

	data := counter.ExpressDataPayload{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		Timestamp:    time.Now(),
		CallbackMode: "dwell",
		Repository:   "acme/api",
		Workflow:     ".github/workflows/deploy.yml",
		Job:          "deploy",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-victim", model.activeAgent.ID)
	assert.Nil(t, model.waiting)
}

func TestHandleExpressData_CachePoisonVictimWithoutCallbackModeActivatesAfterDwellBeacon(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}

	beaconResult, _ := m.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:       "agt-victim",
		Hostname:      "victim-runner",
		OS:            "linux",
		Arch:          "amd64",
		Timestamp:     time.Now(),
		CallbackMode:  "dwell",
		DwellDeadline: ptrTime(time.Now().Add(30 * time.Second)),
	}})
	model := beaconResult.(Model)

	data := counter.ExpressDataPayload{
		AgentID:    "agt-victim",
		Hostname:   "victim-runner",
		Timestamp:  time.Now(),
		Repository: "acme/api",
		Workflow:   ".github/workflows/deploy.yml",
		Job:        "deploy",
	}

	result, _ := model.handleExpressData(ExpressDataMsg{Data: data})
	model = result.(Model)

	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-victim", model.activeAgent.ID)
	assert.Nil(t, model.waiting)
}

func TestHandleBeacon_CachePoisonPendingVictimActivatesOnLaterDwellBeacon(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}

	data := counter.ExpressDataPayload{
		AgentID:    "agt-victim",
		Hostname:   "victim-runner",
		Timestamp:  time.Now(),
		Repository: "acme/api",
		Workflow:   ".github/workflows/deploy.yml",
		Job:        "deploy",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, "agt-victim", model.waiting.CachePoison.PendingVictim)
	assert.Equal(t, PhaseWaiting, model.phase)

	beaconResult, _ := model.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:       "agt-victim",
		Hostname:      "victim-runner",
		OS:            "linux",
		Arch:          "amd64",
		Timestamp:     time.Now(),
		CallbackMode:  "dwell",
		DwellDeadline: ptrTime(time.Now().Add(30 * time.Second)),
	}})
	model = beaconResult.(Model)

	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-victim", model.activeAgent.ID)
	assert.Nil(t, model.waiting)
}

func TestHandleBeacon_CachePoisonPendingVictimIgnoresSessionDeadlineWithoutDwellMode(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
		PendingVictim:  "agt-victim",
	}

	result, _ := m.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:       "agt-victim",
		Hostname:      "victim-runner",
		OS:            "linux",
		Arch:          "amd64",
		Timestamp:     time.Now(),
		DwellDeadline: ptrTime(time.Now().Add(30 * time.Second)),
	}})
	model := result.(Model)

	assert.Equal(t, PhaseWaiting, model.phase)
	assert.Nil(t, model.activeAgent)
	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, "agt-victim", model.waiting.CachePoison.PendingVictim)
}

func TestHandleExpressData_CachePoisonVictimWithoutCallbackIDRequiresMatchingOrigin(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		WriterAgentID:  "agt-writer",
		VictimStagerID: "victim-stg",
	}

	data := counter.ExpressDataPayload{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		Timestamp:    time.Now(),
		CallbackMode: "dwell",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, PhaseWaiting, model.phase)
	assert.Nil(t, model.activeAgent)
	assert.Empty(t, model.waiting.CachePoison.VictimAgentID)
}

func TestHandleExpressData_FallsBackToWaitingRepo(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "waiting-org/waiting-repo", "V001", "ci.yml", "build", "auto_pr", 0)

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "GITHUB_TOKEN", Value: "ghs_test", Type: "github_token", Source: "env"},
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})

	model := result.(Model)
	require.Len(t, model.sessionLoot, 1)
	assert.Equal(t, "waiting-org/waiting-repo", model.sessionLoot[0].Repository)
}

func TestHandleExpressData_PersistentRunnerTargetExpressHitStaysWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-runner-1", "whooli/infrastructure-definitions", "", runnerTargetWorkflowPath(), runnerTargetWorkflowJobName(), "Self-Hosted Workflow Push", 90*time.Second)
	m.callbacks = []counter.CallbackPayload{
		{ID: "stg-runner-1", Persistent: true},
	}

	data := counter.ExpressDataPayload{
		AgentID:      "brisket-runner-01",
		Hostname:     "whooli-gh-runner",
		Timestamp:    time.Now(),
		CallbackID:   "stg-runner-1",
		CallbackMode: "express",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Nil(t, model.activeAgent)
	assert.Contains(t, model.waiting.PendingAgents, "brisket-runner-01")
	require.Len(t, model.output, 3)
	assert.Equal(t, "info", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "Persistent callback hit in express mode")
	assert.Equal(t, "info", model.output[1].Type)
	assert.Contains(t, model.output[1].Content, "implants modal")
}

func TestHandleBeacon_PersistentRunnerTargetExpressHitStaysWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-runner-1", "whooli/infrastructure-definitions", "", runnerTargetWorkflowPath(), runnerTargetWorkflowJobName(), "Self-Hosted Workflow Push", 90*time.Second)
	m.callbacks = []counter.CallbackPayload{
		{ID: "stg-runner-1", Persistent: true},
	}

	beacon := counter.Beacon{
		AgentID:      "brisket-runner-01",
		Hostname:     "whooli-gh-runner",
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    time.Now(),
		CallbackID:   "stg-runner-1",
		CallbackMode: "express",
	}

	result, _ := m.handleBeacon(BeaconMsg{Beacon: beacon})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Nil(t, model.activeAgent)
	assert.Contains(t, model.waiting.PendingAgents, "brisket-runner-01")
}

func TestHandleBeacon_PersistentRunnerTargetResidentHitTransitionsToPostExploit(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-runner-1", "whooli/infrastructure-definitions", "", runnerTargetWorkflowPath(), runnerTargetWorkflowJobName(), "Self-Hosted Workflow Push", 0)
	m.callbacks = []counter.CallbackPayload{
		{
			ID:         "stg-runner-1",
			Persistent: true,
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
			},
		},
	}

	beacon := counter.Beacon{
		AgentID:      "brisket-runner-01",
		Hostname:     "whooli-gh-runner",
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    time.Now(),
		CallbackID:   "stg-runner-1",
		CallbackMode: "resident",
	}

	result, _ := m.handleBeacon(BeaconMsg{Beacon: beacon})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "brisket-runner-01", model.activeAgent.ID)
	assert.Equal(t, "whooli/infrastructure-definitions", model.activeAgent.Repo)
	assert.Equal(t, runnerTargetWorkflowPath(), model.activeAgent.Workflow)
	assert.Equal(t, runnerTargetWorkflowJobName(), model.activeAgent.Job)
	assert.Equal(t, agentModeResident, model.activeAgent.Mode)
	assert.True(t, model.dwellMode)
	assert.True(t, model.jobDeadline.IsZero())
	assert.Nil(t, model.waiting)
}

func TestHandleBeacon_PersistentRunnerTargetResidentHitWithoutResidentMetadataTransitionsToPostExploit(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-runner-1", "whooli/infrastructure-definitions", "", runnerTargetWorkflowPath(), runnerTargetWorkflowJobName(), "Self-Hosted Workflow Push", 0)
	m.callbacks = []counter.CallbackPayload{
		{
			ID:         "stg-runner-1",
			Persistent: true,
		},
	}

	beacon := counter.Beacon{
		AgentID:      "brisket-runner-01",
		Hostname:     "whooli-gh-runner",
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    time.Now(),
		CallbackID:   "stg-runner-1",
		CallbackMode: "resident",
	}

	result, _ := m.handleBeacon(BeaconMsg{Beacon: beacon})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "brisket-runner-01", model.activeAgent.ID)
	assert.Equal(t, agentModeResident, model.activeAgent.Mode)
	assert.True(t, model.dwellMode)
	assert.True(t, model.jobDeadline.IsZero())
	assert.Nil(t, model.waiting)
}

func TestHandleBeacon_PersistentRunnerTargetResidentHitWithoutModeTransitionsToPostExploit(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-runner-1", "whooli/infrastructure-definitions", "", runnerTargetWorkflowPath(), runnerTargetWorkflowJobName(), "Self-Hosted Workflow Push", 0)
	m.callbacks = []counter.CallbackPayload{
		{
			ID:         "stg-runner-1",
			Persistent: true,
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
			},
		},
	}

	beacon := counter.Beacon{
		AgentID:    "brisket-runner-01",
		Hostname:   "whooli-gh-runner",
		OS:         "linux",
		Arch:       "amd64",
		Timestamp:  time.Now(),
		CallbackID: "stg-runner-1",
	}

	result, _ := m.handleBeacon(BeaconMsg{Beacon: beacon})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "brisket-runner-01", model.activeAgent.ID)
	assert.Equal(t, agentModeResident, model.activeAgent.Mode)
	assert.True(t, model.dwellMode)
	assert.True(t, model.jobDeadline.IsZero())
	assert.Nil(t, model.waiting)
}

func TestHandleExpressData_RunnerTargetDwellHitTransitionsToPostExploit(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-runner-1", "whooli/infrastructure-definitions", "", runnerTargetWorkflowPath(), runnerTargetWorkflowJobName(), "Self-Hosted Workflow Push", 2*time.Minute)

	data := counter.ExpressDataPayload{
		AgentID:      "brisket-runner-01",
		Hostname:     "whooli-gh-runner",
		Timestamp:    time.Now(),
		CallbackID:   "stg-runner-1",
		CallbackMode: "dwell",
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "brisket-runner-01", model.activeAgent.ID)
	assert.Equal(t, "whooli/infrastructure-definitions", model.activeAgent.Repo)
	assert.Equal(t, runnerTargetWorkflowPath(), model.activeAgent.Workflow)
	assert.Equal(t, runnerTargetWorkflowJobName(), model.activeAgent.Job)
	assert.Nil(t, model.waiting)
}

func TestHandleExpressData_UpdatesPantryState(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.waiting = &WaitingState{TargetRepo: "org/repo"}

	p := pantry.New()
	secret := pantry.NewSecret("WHOOLI_BOT_APP_PRIVATE_KEY", "job1", "github")
	_ = p.AddAsset(secret)
	m.pantry = p

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "WHOOLI_BOT_APP_PRIVATE_KEY", Value: "-----BEGIN RSA PRIVATE KEY-----", Type: "private_key", Source: "env", HighValue: true},
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	updated, err := model.pantry.GetAsset(secret.ID)
	require.NoError(t, err)
	assert.Equal(t, pantry.StateExploited, updated.State, "secret should be marked exploited after collection")
}

func TestHandleExpressData_ReclassifiesViaStructuralType(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.waiting = &WaitingState{TargetRepo: "org/repo"}
	m.workflowSecretTypes = map[string]string{
		"MY_KEY": "github_app_key",
	}

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "MY_KEY", Value: "-----BEGIN RSA PRIVATE KEY-----", Type: "private_key", Source: "env", HighValue: true},
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.Len(t, model.lootStash, 1)
	assert.Equal(t, "github_app_key", model.lootStash[0].Type, "should override type via structural detection")
}

func TestHandleExpressData_PairsGitHubAppCredentials(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.waiting = &WaitingState{TargetRepo: "whooli/xyz"}
	m.workflowSecretTypes = map[string]string{
		"WHOOLI_BOT_APP_PRIVATE_KEY": "github_app_key",
		"WHOOLI_BOT_APP_ID":          "github_app_id",
	}

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "WHOOLI_BOT_APP_PRIVATE_KEY", Value: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----", Type: "private_key", Source: "env", HighValue: true},
			{Name: "WHOOLI_BOT_APP_ID", Value: "12345", Type: "generic", Source: "env", HighValue: true},
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.Len(t, model.lootStash, 1, "App ID should be removed from loot, leaving only PEM")
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", model.lootStash[0].Name)
	assert.Equal(t, "12345", model.lootStash[0].PairedAppID)
}

func TestHandleExpressData_PairsGitHubAppInSessionLoot(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.target = "whooli/xyz"
	m.workflowSecretTypes = map[string]string{
		"WHOOLI_BOT_APP_PRIVATE_KEY": "github_app_key",
		"WHOOLI_BOT_APP_ID":          "github_app_id",
	}

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "WHOOLI_BOT_APP_PRIVATE_KEY", Value: "-----BEGIN RSA PRIVATE KEY-----\ntest", Type: "private_key", Source: "env", HighValue: false},
			{Name: "WHOOLI_BOT_APP_ID", Value: "  67890  ", Type: "generic", Source: "env", HighValue: false},
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	require.Len(t, model.sessionLoot, 1, "App ID should be removed from session loot")
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", model.sessionLoot[0].Name)
	assert.Equal(t, "67890", model.sessionLoot[0].PairedAppID, "should trim whitespace")
}

func TestHandleExpressData_NoPairingWithoutStructuralTypes(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.waiting = &WaitingState{TargetRepo: "org/repo"}

	data := counter.ExpressDataPayload{
		AgentID:   "brisket-001234567890",
		Hostname:  "runner-1",
		Timestamp: time.Now(),
		Secrets: []counter.ExtractedSecret{
			{Name: "SOME_KEY", Value: "-----BEGIN RSA PRIVATE KEY-----", Type: "private_key", Source: "env", HighValue: true},
			{Name: "SOME_ID", Value: "12345", Type: "generic", Source: "env", HighValue: true},
		},
	}

	result, _ := m.handleExpressData(ExpressDataMsg{Data: data})
	model := result.(Model)

	assert.Len(t, model.lootStash, 2, "without structural types, both secrets remain")
	assert.Empty(t, model.lootStash[0].PairedAppID)
	assert.Empty(t, model.lootStash[1].PairedAppID)
}

func TestReclassifyLootTypes(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "WHOOLI_BOT_APP_PRIVATE_KEY", Value: "pem-data", Type: "private_key"},
		{Name: "WHOOLI_BOT_APP_ID", Value: "12345", Type: "generic"},
	}
	m.workflowSecretTypes = map[string]string{
		"WHOOLI_BOT_APP_PRIVATE_KEY": "github_app_key",
		"WHOOLI_BOT_APP_ID":          "github_app_id",
	}

	m.reclassifyLootTypes()

	assert.Equal(t, "github_app_key", m.lootStash[0].Type)
	assert.Equal(t, "github_app_id", m.lootStash[1].Type)
	assert.True(t, m.lootStashDirty)
}

func TestPairGitHubAppCredentials_FromCollectedTypes(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "WHOOLI_BOT_APP_PRIVATE_KEY", Value: "pem-data", Type: "github_app_key"},
		{Name: "WHOOLI_BOT_APP_ID", Value: "12345", Type: "github_app_id"},
	}

	m.pairGitHubAppCredentials()

	require.Len(t, m.lootStash, 1)
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", m.lootStash[0].Name)
	assert.Equal(t, "12345", m.lootStash[0].PairedAppID)
}

func TestPairGitHubAppCredentials_HardcodedAppID(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "BOT_PEM", Value: "pem-data", Type: "github_app_key"},
	}
	m.hardcodedAppIDs = []string{"98765"}

	m.pairGitHubAppCredentials()

	require.Len(t, m.lootStash, 1)
	assert.Equal(t, "98765", m.lootStash[0].PairedAppID)
}

func TestPairGitHubAppCredentials_AlreadyPaired(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "PEM", Value: "pem-data", Type: "github_app_key", PairedAppID: "existing"},
		{Name: "NEW_PEM", Value: "other-pem", Type: "github_app_key"},
	}
	m.hardcodedAppIDs = []string{"99999"}

	m.pairGitHubAppCredentials()

	assert.Equal(t, "existing", m.lootStash[0].PairedAppID, "should not overwrite existing pairing")
	assert.Empty(t, m.lootStash[1].PairedAppID, "should bail out early when already paired")
}

func TestSendOrder_NoSession(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	cmd := m.sendOrder("whoami", nil)
	msg := cmd()

	fail, ok := msg.(OrderFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "no session selected")
}

func TestSendOrder_NilKitchenClient(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.sessions = []Session{{AgentID: "brisket-001"}}
	m.selectedIndex = 0
	m.kitchenClient = nil

	cmd := m.sendOrder("whoami", nil)
	msg := cmd()

	fail, ok := msg.(OrderFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "not connected to Kitchen")
}

func TestSendOrder_Success(t *testing.T) {
	mock := &mockKitchenClient{}
	m := NewModel(Config{SessionID: "test"})
	m.sessions = []Session{{AgentID: "brisket-001"}}
	m.selectedIndex = 0
	m.kitchenClient = mock

	cmd := m.sendOrder("whoami", nil)
	msg := cmd()

	success, ok := msg.(OrderSentMsg)
	require.True(t, ok)
	assert.Equal(t, "brisket-001", success.AgentID)
	assert.NotEmpty(t, success.OrderID)
	require.Len(t, mock.publishedOrders, 1)
	assert.Equal(t, "whoami", mock.publishedOrders[0].Command)
}

func TestSendOrder_WithArgs(t *testing.T) {
	mock := &mockKitchenClient{}
	m := NewModel(Config{SessionID: "test"})
	m.sessions = []Session{{AgentID: "brisket-001"}}
	m.selectedIndex = 0
	m.kitchenClient = mock

	cmd := m.sendOrder("cat", []string{"/etc/passwd"})
	msg := cmd()

	success, ok := msg.(OrderSentMsg)
	require.True(t, ok)
	assert.NotEmpty(t, success.OrderID)
	require.Len(t, mock.publishedOrders, 1)
	assert.Equal(t, "cat", mock.publishedOrders[0].Command)
	assert.Equal(t, []string{"/etc/passwd"}, mock.publishedOrders[0].Args)
}

func TestSendOrder_PublishError(t *testing.T) {
	mock := &mockKitchenClient{
		publishOrderErr: fmt.Errorf("NATS timeout"),
	}
	m := NewModel(Config{SessionID: "test"})
	m.sessions = []Session{{AgentID: "brisket-001"}}
	m.selectedIndex = 0
	m.kitchenClient = mock

	cmd := m.sendOrder("whoami", nil)
	msg := cmd()

	fail, ok := msg.(OrderFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "NATS timeout")
}

func TestSelectVulnerability_SyncsTreeSelection(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.vulnerabilities = []Vulnerability{
		{ID: "V001", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/build.yml", Job: "build", Context: "issue_body"},
		{ID: "V004", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/internal-sync.yml", Job: "archive-feedback", Context: "workflow_dispatch_input"},
	}

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/xyz", Type: TreeNodeRepo, Label: "acme/xyz", Parent: root}
	job := &TreeNode{ID: "job:archive-feedback", Type: TreeNodeJob, Label: "archive-feedback", Parent: repo}
	vuln := &TreeNode{ID: "V004", Type: TreeNodeVuln, Label: "Bash injection", Parent: job}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{job}
	job.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()

	m.selectVulnerability("dispatch input")

	require.NotNil(t, m.SelectedTreeNode())
	assert.Equal(t, "V004", m.SelectedTreeNode().ID)
	assert.Equal(t, 1, m.selectedVuln)
	assert.Equal(t, PaneFocusFindings, m.paneFocus)
}

func TestExecuteCommand_ExploitQueryOpensWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.vulnerabilities = []Vulnerability{
		{ID: "V004", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/internal-sync.yml", Job: "archive-feedback", RuleID: "injection", Context: "workflow_dispatch_input"},
	}
	m.input.SetValue("exploit dispatch input")

	result, cmd := m.executeCommand()

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotNil(t, model.wizard)
	require.NotNil(t, model.wizard.SelectedVuln)
	assert.Equal(t, "V004", model.wizard.SelectedVuln.ID)
	assert.Equal(t, PhaseWizard, model.phase)
}

func TestExecuteCommand_ExploitQueryRejectsAnalyzeOnlyFinding(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.vulnerabilities = []Vulnerability{
		{ID: "V005", Title: "Self-hosted runner", Repository: "acme/xyz", Workflow: ".github/workflows/pr.yml", Job: "build", RuleID: "pr_runs_on_self_hosted", Context: "bash_run"},
	}
	m.input.SetValue("exploit self-hosted")

	result, cmd := m.executeCommand()

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotNil(t, model.wizard)
	assert.Nil(t, model.wizard.SelectedVuln)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "error", model.output[len(model.output)-1].Type)
	assert.Equal(t, "Self-hosted runner findings are analyze-only in v0.1.0. Exploit actions are not supported yet.", model.output[len(model.output)-1].Content)
	for _, line := range model.output {
		assert.NotContains(t, line.Content, "Usage: exploit [vuln-id or query]")
	}
}

func TestHandleKeyMsg_XRequiresVulnerabilityTreeNode(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	m.vulnerabilities = []Vulnerability{
		{ID: "V001", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/build.yml", Job: "build", Context: "issue_body"},
		{ID: "V004", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/internal-sync.yml", Job: "archive-feedback", Context: "workflow_dispatch_input"},
	}
	m.selectedVuln = 1

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/xyz", Type: TreeNodeRepo, Label: "acme/xyz", Parent: root}
	root.Children = []*TreeNode{repo}
	m.treeRoot = root
	m.ReflattenTree()

	result, cmd := m.Update(tea.KeyPressMsg{Text: "x", Code: 'x'})

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotNil(t, model.wizard)
	assert.Nil(t, model.wizard.SelectedVuln)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "error", model.output[len(model.output)-1].Type)
	assert.Equal(t, "Action shortcut requires a [WORKFLOW], [VULN], or [SH-RUNNER] node.", model.output[len(model.output)-1].Content)
}

func TestHandleKeyMsg_XUsesHighlightedTreeVulnerabilityFromPantryNode(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	m.vulnerabilities = []Vulnerability{
		{ID: "V001", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/build.yml", Job: "build", Line: 12, RuleID: "injection", Context: "issue_body"},
		{ID: "V004", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/internal-sync.yml", Job: "archive-feedback", Line: 41, RuleID: "injection", Context: "workflow_dispatch_input"},
	}
	m.selectedVuln = 0

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/xyz", Type: TreeNodeRepo, Label: "acme/xyz", Expanded: true, Parent: root}
	job := &TreeNode{ID: "job:archive-feedback", Type: TreeNodeJob, Label: "archive-feedback", Expanded: true, Parent: repo}
	firstVuln := &TreeNode{
		ID:     "vuln:injection:.github/workflows/build.yml:12",
		Type:   TreeNodeVuln,
		Label:  "Bash injection",
		RuleID: "injection",
		Parent: repo,
		Properties: map[string]interface{}{
			"path":    ".github/workflows/build.yml",
			"line":    12,
			"context": "issue_body",
			"job":     "build",
		},
	}
	secondVuln := &TreeNode{
		ID:     "vuln:injection:.github/workflows/internal-sync.yml:41",
		Type:   TreeNodeVuln,
		Label:  "Bash injection",
		RuleID: "injection",
		Parent: job,
		Properties: map[string]interface{}{
			"path":       ".github/workflows/internal-sync.yml",
			"line":       41,
			"context":    "workflow_dispatch_input",
			"job":        "archive-feedback",
			"expression": "${{ github.event.inputs.target }}",
		},
	}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{firstVuln, job}
	job.Children = []*TreeNode{secondVuln}
	m.treeRoot = root
	m.ReflattenTree()
	require.True(t, m.TreeSelectByID(secondVuln.ID))

	result, cmd := m.Update(tea.KeyPressMsg{Text: "x", Code: 'x'})

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotNil(t, model.wizard)
	require.NotNil(t, model.wizard.SelectedVuln)
	assert.Equal(t, "V004", model.wizard.SelectedVuln.ID)
}

func TestHandleKeyMsg_XRejectsAnalyzeOnlyFinding(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	m.vulnerabilities = []Vulnerability{
		{ID: "V005", Title: "Self-hosted runner", Repository: "acme/xyz", Workflow: ".github/workflows/pr.yml", Job: "build", Line: 12, RuleID: "pr_runs_on_self_hosted", Context: "bash_run"},
	}
	m.selectedVuln = 0

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/xyz", Type: TreeNodeRepo, Label: "acme/xyz", Expanded: true, Parent: root}
	vuln := &TreeNode{
		ID:     "V005",
		Type:   TreeNodeVuln,
		Label:  "Self-hosted runner",
		RuleID: "pr_runs_on_self_hosted",
		Parent: repo,
		Properties: map[string]interface{}{
			"path":    ".github/workflows/pr.yml",
			"line":    12,
			"context": "bash_run",
			"job":     "build",
		},
	}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()
	require.True(t, m.TreeSelectByID("V005"))

	result, cmd := m.Update(tea.KeyPressMsg{Text: "x", Code: 'x'})

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotNil(t, model.wizard)
	assert.Nil(t, model.wizard.SelectedVuln)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "error", model.output[len(model.output)-1].Type)
	assert.Equal(t, "Self-hosted runner findings are analyze-only in v0.1.0. Exploit actions are not supported yet.", model.output[len(model.output)-1].Content)
}

func TestHandleKeyMsg_XUsesRunnerTargetPreferredVulnerability(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	m.vulnerabilities = []Vulnerability{
		{ID: "vuln:injection:.github/workflows/pr.yml:12", Title: "Bash injection", Repository: "acme/xyz", Workflow: ".github/workflows/pr.yml", Job: "build", Line: 12, RuleID: "injection", Context: "issue_body", ExploitSupported: true},
	}

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/xyz", Type: TreeNodeRepo, Label: "acme/xyz", Expanded: true, Parent: root}
	target := &TreeNode{
		ID:     "runner:1",
		Type:   TreeNodeSelfHostedRunner,
		Label:  "linux-x64",
		Parent: repo,
		Properties: map[string]interface{}{
			"repo_id":                 "github:acme/xyz",
			"label_display":           "linux-x64",
			"label_set":               []string{"self-hosted", "linux", "x64"},
			"observed_workflow_paths": []string{".github/workflows/pr.yml"},
			"observed_job_names":      []string{"build"},
		},
	}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{target}
	m.treeRoot = root
	m.ReflattenTree()
	require.True(t, m.TreeSelectByID(target.ID))

	result, cmd := m.Update(tea.KeyPressMsg{Text: "x", Code: 'x'})

	require.Nil(t, cmd)
	model := result.(Model)
	require.NotNil(t, model.wizard)
	assert.Equal(t, WizardKindRunnerTarget, model.wizard.Kind)
	require.NotNil(t, model.wizard.SelectedRunnerTarget)
	assert.Equal(t, "linux-x64", model.wizard.SelectedRunnerTarget.LabelDisplay)
	assert.Equal(t, "vuln:injection:.github/workflows/pr.yml:12", model.wizard.SelectedRunnerTarget.PreferredPath)
}
