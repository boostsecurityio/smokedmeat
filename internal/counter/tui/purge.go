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
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func (m Model) handlePurgeCommand(parts []string) (tea.Model, tea.Cmd) {
	if m.kitchenClient == nil {
		m.AddOutput("error", "Not connected to Kitchen")
		return m, nil
	}
	if strings.TrimSpace(m.config.SessionID) == "" {
		m.AddOutput("error", "Operator session is not available")
		m.AddOutput("info", "Reconnect to Kitchen and try again before purging analysis state")
		return m, nil
	}

	dryRun := true
	if len(parts) > 0 && parts[0] == "confirm" {
		dryRun = false
		parts = parts[1:]
	}

	scopeSpec := strings.TrimSpace(strings.Join(parts, " "))
	if scopeSpec == "" {
		scopeSpec = m.currentTargetSpec()
	}
	if scopeSpec == "" {
		m.showPurgeUsage()
		return m, nil
	}

	scopeValue, scopeType, normalized := normalizeTargetValue(scopeSpec)
	if scopeType != "org" && scopeType != "repo" {
		m.showPurgeUsage()
		return m, nil
	}

	if dryRun {
		m.AddOutput("info", "Previewing purge for "+normalized+"...")
	} else {
		m.AddOutput("warning", "Purging analysis state for "+normalized+"...")
	}

	return m, m.runPurgeCmd(scopeType, scopeValue, dryRun)
}

func (m Model) runPurgeCmd(scopeType, scopeValue string, dryRun bool) tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return PurgeErrorMsg{Err: fmt.Errorf("not connected to kitchen")}
		}
		if strings.TrimSpace(m.config.SessionID) == "" {
			return PurgeErrorMsg{Err: fmt.Errorf("operator session is not available")}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		resp, err := m.kitchenClient.Purge(ctx, counter.PurgeRequest{
			SessionID:  m.config.SessionID,
			ScopeType:  scopeType,
			ScopeValue: scopeValue,
			DryRun:     dryRun,
		})
		if err != nil {
			return PurgeErrorMsg{Err: err}
		}
		if dryRun {
			return PurgePreviewMsg{Response: *resp}
		}

		p, err := m.kitchenClient.FetchPantry(ctx)
		if err != nil {
			return PurgeErrorMsg{Err: err}
		}
		entities, err := m.kitchenClient.FetchKnownEntities(ctx, m.config.SessionID)
		if err != nil {
			return PurgeErrorMsg{Err: err}
		}

		return PurgeCompletedMsg{
			Response:      *resp,
			Pantry:        p,
			KnownEntities: entities,
		}
	}
}

func (m *Model) replaceKnownEntities(payloads []counter.KnownEntityPayload) {
	m.knownEntities = make(map[string]*KnownEntity, len(payloads))
	for _, e := range payloads {
		m.knownEntities[e.ID] = &KnownEntity{
			ID:            e.ID,
			EntityType:    e.EntityType,
			Name:          e.Name,
			DiscoveredAt:  e.DiscoveredAt,
			DiscoveredVia: e.DiscoveredVia,
			IsPrivate:     e.IsPrivate,
			Permissions:   e.Permissions,
			SSHPermission: e.SSHPermission,
		}
	}
}

func (m *Model) applyPurgedPantry(p *pantry.Pantry) {
	if p == nil {
		m.pantry = pantry.New()
	} else {
		m.pantry = p
	}
	m.vulnerabilities = m.extractVulnerabilitiesFromPantry()
	if len(m.vulnerabilities) == 0 {
		m.selectedVuln = -1
		m.analysisComplete = false
	} else {
		if m.selectedVuln < 0 || m.selectedVuln >= len(m.vulnerabilities) {
			m.selectedVuln = 0
		}
		m.analysisComplete = true
	}
	m.RebuildTree()
	m.GenerateSuggestions()
}

func purgeScopeCoversTarget(scopeType, scopeValue, targetType, targetValue string) bool {
	scopeValue = strings.TrimSpace(scopeValue)
	targetValue = strings.TrimSpace(targetValue)
	switch scopeType {
	case "repo":
		return targetType == "repo" && targetValue == scopeValue
	case "org":
		if targetType == "org" {
			return targetValue == scopeValue
		}
		return targetType == "repo" && strings.HasPrefix(targetValue, scopeValue+"/")
	default:
		return false
	}
}

func (m *Model) clearPurgedTarget(scopeType, scopeValue string) {
	prev := m.currentTargetSpec()
	m.target = ""
	m.targetType = ""
	m.analysisFocusRepo = ""
	m.vulnerabilities = nil
	m.selectedVuln = -1
	m.analysisComplete = false
	m.updatePlaceholder()
	m.GenerateSuggestions()

	cfg, err := counter.LoadConfig()
	if err == nil && cfg != nil {
		cfg.Target = ""
		if saveErr := counter.SaveConfig(cfg); saveErr != nil {
			m.AddOutput("warning", fmt.Sprintf("Could not save config: %v", saveErr))
		}
	}

	scopeSpec := scopeType + ":" + scopeValue
	if prev != "" {
		m.AddOutput("warning", "Current target was purged and has been cleared: "+prev)
	} else {
		m.AddOutput("warning", "Purged target "+scopeSpec)
	}
	m.AddOutput("info", "Choose a new target with 'set target org:<owner>' or 'set target repo:<owner/repo>'")
	m.activityLog.Add(IconWarning, "Purged current target "+scopeSpec+" - choose a new target with 'set target ...'")
	m.flashMessage = "Target cleared"
	m.flashUntil = time.Now().Add(2 * time.Second)
}

func (m *Model) showPurgeUsage() {
	m.AddOutput("error", "Usage: purge [confirm] <org:owner|repo:owner/repo>")
	m.AddOutput("info", "Examples: purge repo:acme/api | purge confirm org:acme")
	if target := m.currentTargetSpec(); target != "" {
		m.AddOutput("info", "Tip: 'purge' with no target uses the current target ("+target+")")
	}
}
