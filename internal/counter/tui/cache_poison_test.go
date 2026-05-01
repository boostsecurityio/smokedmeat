// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

func TestWizardKeyMsg_CachePoisonToggleAndCycle(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			ID:                "V001",
			Repository:        "acme/api",
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{ID: "victim-1", Workflow: ".github/workflows/deploy.yml", Strategy: cachepoison.StrategySetupNode, Ready: true},
				{ID: "victim-2", Workflow: ".github/workflows/release.yml", Strategy: cachepoison.StrategyActionsCache, Ready: true},
			},
		},
	}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'c'})
	model := result.(Model)
	require.True(t, model.wizard.CachePoisonEnabled)

	result, _ = model.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'v'})
	model = result.(Model)
	assert.Equal(t, 1, model.wizard.CachePoisonVictimIndex)
}

func TestHandleBeacon_CachePoisonWaitsForSecondAgent(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		VictimStagerID: "victim-stg",
	}

	first, _ := m.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:    "agt-writer",
		Hostname:   "writer-runner",
		OS:         "linux",
		Arch:       "amd64",
		Timestamp:  time.Now(),
		CallbackID: "stg-1",
	}})
	model := first.(Model)
	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, PhaseWaiting, model.phase)
	assert.Equal(t, "agt-writer", model.waiting.CachePoison.WriterAgentID)
	assert.Nil(t, model.activeAgent)

	second, _ := model.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    time.Now(),
		CallbackID:   "victim-stg",
		CallbackMode: "dwell",
	}})
	model = second.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	assert.Equal(t, "agt-victim", model.activeAgent.ID)
	assert.Equal(t, ".github/workflows/deploy.yml", model.activeAgent.Workflow)
	assert.Equal(t, "deploy", model.activeAgent.Job)
	assert.Nil(t, model.waiting)
}

func TestHandleCachePoisonBeacon_ExpressVictimKeepsWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Issue", 30*time.Second)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim: cachepoison.VictimCandidate{
			Repository: "acme/api",
			Workflow:   ".github/workflows/deploy.yml",
			Job:        "deploy",
		},
		VictimStagerID: "victim-stg",
	}

	m.handleCachePoisonBeacon(counter.Beacon{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    time.Now(),
		CallbackID:   "victim-stg",
		CallbackMode: "express",
	})

	require.NotNil(t, m.waiting)
	require.NotNil(t, m.waiting.CachePoison)
	assert.Equal(t, PhaseWaiting, m.phase)
	assert.Nil(t, m.activeAgent)
	assert.Empty(t, m.waiting.CachePoison.VictimAgentID)
	_, ok := m.waiting.PendingAgents["agt-victim"]
	assert.True(t, ok)
}

func TestHandleBeacon_CachePoisonVictimWithoutCallbackIDKeepsWaiting(t *testing.T) {
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

	result, _ := m.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:      "agt-victim",
		Hostname:     "victim-runner",
		OS:           "linux",
		Arch:         "amd64",
		Timestamp:    time.Now(),
		CallbackMode: "dwell",
	}})
	model := result.(Model)

	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, PhaseWaiting, model.phase)
	assert.Nil(t, model.activeAgent)
	assert.Empty(t, model.waiting.CachePoison.VictimAgentID)
	_, ok := model.waiting.PendingAgents["agt-victim"]
	assert.True(t, ok)
}

func TestHandleBeacon_CachePoisonWriterBeforeStartWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pendingCachePoison = &CachePoisonWaitingState{
		WriterStagerID: "stg-1",
	}

	first, _ := m.handleBeacon(BeaconMsg{Beacon: counter.Beacon{
		AgentID:    "agt-writer",
		Hostname:   "writer-runner",
		OS:         "linux",
		Arch:       "amd64",
		Timestamp:  time.Now(),
		CallbackID: "stg-1",
	}})
	model := first.(Model)

	require.NotNil(t, model.pendingCachePoison)
	assert.Equal(t, "agt-writer", model.pendingCachePoison.WriterAgentID)

	vuln := &Vulnerability{Repository: "acme/api", ID: "V001", Workflow: ".github/workflows/lint.yml", Job: "lint"}
	model.StartWaiting("stg-1", "", vuln, "Issue", 0)
	require.NotNil(t, model.waiting)
	require.NotNil(t, model.waiting.CachePoison)
	assert.Equal(t, "agt-writer", model.waiting.CachePoison.WriterAgentID)
}

func TestCachePoisonAvailability_RequiresReadyVictim(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	available, reason := m.cachePoisonAvailability(&Vulnerability{
		CachePoisonWriter: true,
		CachePoisonVictims: []cachepoison.VictimCandidate{
			{ID: "victim-1", Workflow: ".github/workflows/release.yml", Strategy: cachepoison.StrategySetupJava, Ready: false},
		},
	})
	assert.False(t, available)
	assert.Equal(t, "no runtime-ready victim workflow found", reason)
}

func TestReadyCachePoisonVictims_FiltersUnreadyStrategies(t *testing.T) {
	ready := readyCachePoisonVictims([]cachepoison.VictimCandidate{
		{ID: "python", Workflow: ".github/workflows/python.yml", Strategy: cachepoison.StrategySetupPython, Ready: false},
		{ID: "java", Workflow: ".github/workflows/java.yml", Strategy: cachepoison.StrategySetupJava, Ready: false},
		{ID: "go", Workflow: ".github/workflows/deploy.yml", Strategy: cachepoison.StrategySetupGo, Ready: true},
	})

	require.Len(t, ready, 1)
	assert.Equal(t, "go", ready[0].ID)
}

func TestSelectedCachePoisonVictim_UsesReadyVictimList(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.wizard = &WizardState{
		SelectedVuln: &Vulnerability{
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{ID: "victim-1", Workflow: ".github/workflows/skip.yml", Ready: false},
				{ID: "victim-2", Workflow: ".github/workflows/deploy.yml", Ready: true},
			},
		},
	}

	victim := m.selectedCachePoisonVictim()
	require.NotNil(t, victim)
	assert.Equal(t, "victim-2", victim.ID)
}

func TestCallbackMetadataForVulnerability_MarksResidentPersistence(t *testing.T) {
	metadata := callbackMetadataForVulnerability(&Vulnerability{
		Repository: "acme/api",
		Workflow:   ".github/workflows/lint.yml",
		Job:        "lint",
	})

	assert.Equal(t, "resident", metadata["persistence_mode"])
	assert.Equal(t, "acme/api", metadata["repository"])
	assert.Equal(t, ".github/workflows/lint.yml", metadata["workflow"])
	assert.Equal(t, "lint", metadata["job"])
}

func TestPrepareWizardStager_CachePoisonEncodesDeploymentConfig(t *testing.T) {
	m := NewModel(Config{
		SessionID:          "sess-1",
		KitchenURL:         "https://kitchen.example",
		KitchenExternalURL: "https://public.example",
	})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN"}
	m.appTokenPermissions = map[string]string{"actions": "write"}
	mock := &mockKitchenClient{
		prepareCachePoisonResp: &counter.PrepareCachePoisonResponse{
			VictimCallback: counter.CallbackPayload{
				ID:           "victim-callback",
				SessionID:    "sess-1",
				ResponseType: "bash",
				CreatedAt:    time.Now(),
				Persistent:   true,
				DefaultMode:  "express",
			},
			WriterCallback: counter.CallbackPayload{
				ID:           "writer-callback",
				SessionID:    "sess-1",
				ResponseType: "bash",
				CreatedAt:    time.Now(),
				Persistent:   true,
				DefaultMode:  "express",
			},
			VictimStagerID:  "victim-callback",
			VictimStagerURL: "https://public.example/r/victim-callback",
		},
	}
	m.kitchenClient = mock
	m.wizard = &WizardState{
		CachePoisonEnabled: true,
		CachePoisonReplace: true,
		DwellTime:          45 * time.Second,
		DeliveryMethod:     DeliveryComment,
		SelectedVuln: &Vulnerability{
			ID:                "V001",
			Repository:        "acme/api",
			Workflow:          ".github/workflows/lint.yml",
			Job:               "lint",
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{
					ID:         "victim-1",
					Repository: "acme/api",
					Workflow:   ".github/workflows/release.yml",
					Job:        "release",
					Ready:      true,
					CacheEntry: cachepoison.CacheEntryPlan{
						Mode:                cachepoison.CacheEntryModePredicted,
						Strategy:            cachepoison.StrategySetupGo,
						CacheDependencyPath: "go.sum",
						VersionSpec:         "1.24.3",
					},
					Execution: cachepoison.ExecutionPlan{
						Kind:       cachepoison.ExecutionKindCheckoutPost,
						GadgetUses: "actions/setup-go@v5",
						Checkouts: []cachepoison.CheckoutTarget{
							{Uses: "actions/checkout@v6", Ref: "v6"},
						},
					},
					ConsumerLabel: "actions/setup-go",
					Strategy:      cachepoison.StrategySetupGo,
				},
			},
		},
	}

	stager, _, err := m.prepareWizardStager(m.wizard.SelectedVuln, rye.BashRun)
	require.NoError(t, err)
	require.NotNil(t, stager)
	require.NotNil(t, m.pendingCachePoison)
	assert.Equal(t, m.wizard.VictimStagerID, m.pendingCachePoison.VictimStagerID)
	require.Len(t, m.callbacks, 2)

	req := mock.lastPrepareCachePoisonReq
	assert.Equal(t, "sess-1", req.SessionID)
	assert.Equal(t, "https://public.example", req.ExternalURL)
	assert.Equal(t, stager.ID, req.WriterStagerID)
	assert.Equal(t, "acme/api", req.WriterRepository)
	assert.Equal(t, ".github/workflows/lint.yml", req.WriterWorkflow)
	assert.Equal(t, "lint", req.WriterJob)
	assert.Equal(t, ".github/workflows/release.yml", req.Victim.Workflow)
	assert.Equal(t, "release", req.Victim.Job)
	assert.Equal(t, "45s", req.VictimDwellTime)
	assert.Equal(t, "ghs_app_token", req.PurgeToken)
	assert.Empty(t, req.PurgeKey)
	assert.Equal(t, "setup-go-", req.PurgeKeyPrefix)
	assert.Equal(t, "", req.PurgeRef)
	assert.Equal(t, cachepoison.ExecutionKindCheckoutPost, req.Victim.Execution.Kind)
	assert.Equal(t, cachepoison.CacheEntryModePredicted, req.Victim.CacheEntry.Mode)
}

func TestPrepareWizardStager_CachePoisonUsesExactPurgeKeyWhenAvailable(t *testing.T) {
	m := NewModel(Config{
		SessionID:          "sess-1",
		KitchenURL:         "https://kitchen.example",
		KitchenExternalURL: "https://public.example",
	})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN"}
	m.appTokenPermissions = map[string]string{"actions": "write"}
	mock := &mockKitchenClient{
		prepareCachePoisonResp: &counter.PrepareCachePoisonResponse{
			VictimStagerID:  "victim-callback",
			VictimStagerURL: "https://public.example/r/victim-callback",
		},
	}
	m.kitchenClient = mock
	m.wizard = &WizardState{
		CachePoisonEnabled: true,
		CachePoisonReplace: true,
		DwellTime:          45 * time.Second,
		DeliveryMethod:     DeliveryComment,
		SelectedVuln: &Vulnerability{
			ID:                "V001",
			Repository:        "acme/api",
			Workflow:          ".github/workflows/lint.yml",
			Job:               "lint",
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{
					ID:         "victim-1",
					Repository: "acme/api",
					Workflow:   ".github/workflows/release.yml",
					Job:        "release",
					Ready:      true,
					CacheEntry: cachepoison.CacheEntryPlan{
						Mode:                cachepoison.CacheEntryModePredicted,
						Strategy:            cachepoison.StrategySetupGo,
						PredictedKey:        "setup-go-Linux-x64-ubuntu24-go-1.24.3-abc123",
						CacheDependencyPath: "go.sum",
						VersionSpec:         "1.24.3",
					},
					Execution: cachepoison.ExecutionPlan{
						Kind:       cachepoison.ExecutionKindCheckoutPost,
						GadgetUses: "actions/setup-go@v5",
					},
					ConsumerLabel: "actions/setup-go",
					Strategy:      cachepoison.StrategySetupGo,
				},
			},
		},
	}

	_, _, err := m.prepareWizardStager(m.wizard.SelectedVuln, rye.BashRun)
	require.NoError(t, err)
	assert.Equal(t, "ghs_app_token", mock.lastPrepareCachePoisonReq.PurgeToken)
	assert.Equal(t, "setup-go-Linux-x64-ubuntu24-go-1.24.3-abc123", mock.lastPrepareCachePoisonReq.PurgeKey)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeKeyPrefix)
}

func TestPrepareWizardStager_CachePoisonDoesNotPurgeWithoutReplaceToggle(t *testing.T) {
	m := NewModel(Config{
		SessionID:          "sess-1",
		KitchenURL:         "https://kitchen.example",
		KitchenExternalURL: "https://public.example",
	})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN"}
	m.appTokenPermissions = map[string]string{"actions": "write"}
	mock := &mockKitchenClient{
		prepareCachePoisonResp: &counter.PrepareCachePoisonResponse{
			VictimStagerID:  "victim-callback",
			VictimStagerURL: "https://public.example/r/victim-callback",
		},
	}
	m.kitchenClient = mock
	m.wizard = &WizardState{
		CachePoisonEnabled: true,
		DwellTime:          45 * time.Second,
		DeliveryMethod:     DeliveryComment,
		SelectedVuln: &Vulnerability{
			ID:                "V001",
			Repository:        "acme/api",
			Workflow:          ".github/workflows/lint.yml",
			Job:               "lint",
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{
					ID:         "victim-1",
					Repository: "acme/api",
					Workflow:   ".github/workflows/release.yml",
					Job:        "release",
					Ready:      true,
					CacheEntry: cachepoison.CacheEntryPlan{
						Mode:                cachepoison.CacheEntryModePredicted,
						Strategy:            cachepoison.StrategySetupGo,
						CacheDependencyPath: "go.sum",
						VersionSpec:         "1.24.3",
					},
					Execution: cachepoison.ExecutionPlan{
						Kind:       cachepoison.ExecutionKindCheckoutPost,
						GadgetUses: "actions/setup-go@v5",
					},
					ConsumerLabel: "actions/setup-go",
					Strategy:      cachepoison.StrategySetupGo,
				},
			},
		},
	}

	_, _, err := m.prepareWizardStager(m.wizard.SelectedVuln, rye.BashRun)
	require.NoError(t, err)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeToken)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeKey)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeKeyPrefix)
}

func TestPrepareWizardStager_CachePoisonSkipsPurgeForManualDelivery(t *testing.T) {
	m := NewModel(Config{
		SessionID:          "sess-1",
		KitchenURL:         "https://kitchen.example",
		KitchenExternalURL: "https://public.example",
	})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN"}
	m.appTokenPermissions = map[string]string{"actions": "write"}
	mock := &mockKitchenClient{
		prepareCachePoisonResp: &counter.PrepareCachePoisonResponse{
			VictimStagerID:  "victim-callback",
			VictimStagerURL: "https://public.example/r/victim-callback",
		},
	}
	m.kitchenClient = mock
	m.wizard = &WizardState{
		CachePoisonEnabled: true,
		CachePoisonReplace: true,
		DwellTime:          45 * time.Second,
		DeliveryMethod:     DeliveryManualSteps,
		SelectedVuln: &Vulnerability{
			ID:                "V001",
			Repository:        "acme/api",
			Workflow:          ".github/workflows/lint.yml",
			Job:               "lint",
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{
					ID:         "victim-1",
					Repository: "acme/api",
					Workflow:   ".github/workflows/release.yml",
					Job:        "release",
					Ready:      true,
					CacheEntry: cachepoison.CacheEntryPlan{
						Mode:                cachepoison.CacheEntryModePredicted,
						Strategy:            cachepoison.StrategySetupGo,
						CacheDependencyPath: "go.sum",
						VersionSpec:         "1.24.3",
					},
					Execution: cachepoison.ExecutionPlan{
						Kind:       cachepoison.ExecutionKindCheckoutPost,
						GadgetUses: "actions/setup-go@v5",
					},
					ConsumerLabel: "actions/setup-go",
					Strategy:      cachepoison.StrategySetupGo,
				},
			},
		},
	}

	_, _, err := m.prepareWizardStager(m.wizard.SelectedVuln, rye.BashRun)
	require.NoError(t, err)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeToken)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeKey)
	assert.Empty(t, mock.lastPrepareCachePoisonReq.PurgeKeyPrefix)
}

func TestPrepareWizardStager_RequiresWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "sess-1"})
	m.wizard = nil

	stager, payload, err := m.prepareWizardStager(&Vulnerability{ID: "V001"}, rye.BashRun)

	require.Error(t, err)
	assert.Nil(t, stager)
	assert.Empty(t, payload)
}
