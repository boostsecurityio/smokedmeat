// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type PurgeRequest struct {
	SessionID  string `json:"session_id"`
	ScopeType  string `json:"scope_type"`
	ScopeValue string `json:"scope_value"`
	DryRun     bool   `json:"dry_run"`
}

type PurgeResponse struct {
	Status        string `json:"status"`
	SessionID     string `json:"session_id,omitempty"`
	ScopeType     string `json:"scope_type"`
	ScopeValue    string `json:"scope_value"`
	DryRun        bool   `json:"dry_run"`
	PantryAssets  int    `json:"pantry_assets"`
	KnownEntities int    `json:"known_entities"`
}

func (h *Handler) handlePurge(w http.ResponseWriter, r *http.Request) {
	var req PurgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	scopeType, scopeValue, err := normalizePurgeScope(req.ScopeType, req.ScopeValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.SessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	resp, err := h.runPurge(req.SessionID, scopeType, scopeValue, req.DryRun)
	if err != nil {
		http.Error(w, "failed to purge state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func normalizePurgeScope(scopeType, scopeValue string) (string, string, error) {
	scopeType = strings.TrimSpace(strings.ToLower(scopeType))
	scopeValue = strings.TrimSpace(scopeValue)

	if scopeValue == "" {
		return "", "", fmt.Errorf("scope_value is required")
	}

	switch scopeType {
	case "repo":
		if !strings.Contains(scopeValue, "/") {
			return "", "", fmt.Errorf("repo scope_value must be owner/repo")
		}
		return scopeType, scopeValue, nil
	case "org":
		if strings.Contains(scopeValue, "/") {
			return "", "", fmt.Errorf("org scope_value must be owner")
		}
		return scopeType, scopeValue, nil
	default:
		return "", "", fmt.Errorf("scope_type must be 'org' or 'repo'")
	}
}

func (h *Handler) runPurge(sessionID, scopeType, scopeValue string, dryRun bool) (PurgeResponse, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return PurgeResponse{}, fmt.Errorf("session_id is required")
	}

	resp := PurgeResponse{
		Status:     "preview",
		SessionID:  sessionID,
		ScopeType:  scopeType,
		ScopeValue: scopeValue,
		DryRun:     dryRun,
	}

	if h.pantry != nil {
		resp.PantryAssets = countPurgeAssets(h.pantry, purgeRootAssetID(scopeType, scopeValue))
	}
	if h.database != nil {
		entityRepo := db.NewKnownEntityRepository(h.database)
		count, err := entityRepo.CountByScopeAndSession(db.EntityType(scopeType), scopeValue, sessionID)
		if err != nil {
			return PurgeResponse{}, err
		}
		resp.KnownEntities = count
	}

	if dryRun {
		return resp, nil
	}

	if h.pantry != nil && resp.PantryAssets > 0 {
		for _, id := range collectPurgeAssetIDs(h.pantry, purgeRootAssetID(scopeType, scopeValue)) {
			if err := h.pantry.RemoveAsset(id); err != nil && err != pantry.ErrAssetNotFound {
				return PurgeResponse{}, err
			}
		}
		if err := h.SavePantry(); err != nil {
			return PurgeResponse{}, err
		}
	}

	if h.database != nil && resp.KnownEntities > 0 {
		entityRepo := db.NewKnownEntityRepository(h.database)
		if _, err := entityRepo.DeleteByScopeAndSession(db.EntityType(scopeType), scopeValue, sessionID); err != nil {
			return PurgeResponse{}, err
		}
	}

	resp.Status = "purged"
	if err := h.recordPurgeHistory(sessionID, scopeType, scopeValue, resp); err != nil {
		return PurgeResponse{}, err
	}

	return resp, nil
}

func purgeRootAssetID(scopeType, scopeValue string) string {
	switch scopeType {
	case "org":
		return "github:org:" + scopeValue
	case "repo":
		return "github:" + scopeValue
	default:
		return ""
	}
}

func countPurgeAssets(p *pantry.Pantry, rootID string) int {
	return len(collectPurgeAssetIDs(p, rootID))
}

func collectPurgeAssetIDs(p *pantry.Pantry, rootID string) []string {
	if p == nil || rootID == "" || !p.HasAsset(rootID) {
		return nil
	}

	seen := make(map[string]bool)
	var ids []string
	var walk func(string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
		for _, edge := range p.GetOutgoingEdges(id) {
			switch edge.Relationship.Type {
			case pantry.RelContains, pantry.RelExposes, pantry.RelVulnerableTo:
			default:
				continue
			}
			walk(edge.To)
		}
	}

	walk(rootID)
	return ids
}

func (h *Handler) recordPurgeHistory(sessionID, scopeType, scopeValue string, resp PurgeResponse) error {
	if h.database == nil {
		return nil
	}

	entryID := fmt.Sprintf("hist_%d_pur", time.Now().UnixNano())
	row := &db.HistoryRow{
		ID:          entryID,
		Type:        db.HistoryPurgeExecuted,
		Timestamp:   time.Now(),
		SessionID:   sessionID,
		Target:      scopeValue,
		TargetType:  scopeType,
		Outcome:     fmt.Sprintf("%d pantry assets, %d known entities", resp.PantryAssets, resp.KnownEntities),
		ErrorDetail: "",
	}

	repo := db.NewHistoryRepository(h.database)
	if err := repo.Insert(row); err != nil {
		return err
	}

	if h.operators != nil {
		h.operators.BroadcastHistory(HistoryPayload{
			ID:         row.ID,
			Type:       string(row.Type),
			Timestamp:  row.Timestamp,
			SessionID:  row.SessionID,
			Target:     row.Target,
			TargetType: row.TargetType,
			Outcome:    row.Outcome,
		})
	}

	return nil
}
