// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
)

type CallbackSummary struct {
	ID            string            `json:"id"`
	SessionID     string            `json:"session_id"`
	ResponseType  string            `json:"response_type"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	CalledBack    bool              `json:"called_back"`
	CallbackAt    *time.Time        `json:"callback_at,omitempty"`
	CallbackIP    string            `json:"callback_ip,omitempty"`
	DwellTime     string            `json:"dwell_time,omitempty"`
	Persistent    bool              `json:"persistent"`
	MaxCallbacks  int               `json:"max_callbacks,omitempty"`
	DefaultMode   string            `json:"default_mode,omitempty"`
	NextMode      string            `json:"next_mode,omitempty"`
	CallbackCount int               `json:"callback_count"`
	LastAgentID   string            `json:"last_agent_id,omitempty"`
	RevokedAt     *time.Time        `json:"revoked_at,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type CallbackListResponse struct {
	Callbacks []CallbackSummary `json:"callbacks"`
}

type CallbackControlRequest struct {
	Action string `json:"action"`
}

func (h *Handler) handleGetCallbacks(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	callbacks := h.stagerStore.ListPersistent(sessionID)
	response := CallbackListResponse{Callbacks: make([]CallbackSummary, 0, len(callbacks))}
	for _, callback := range callbacks {
		response.Callbacks = append(response.Callbacks, callbackSummary(callback))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) handlePostCallback(w http.ResponseWriter, r *http.Request) {
	callbackID := r.PathValue("callbackID")
	if !isValidID(callbackID) {
		http.Error(w, "invalid callback ID", http.StatusBadRequest)
		return
	}

	var req CallbackControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Action == "" {
		http.Error(w, "action is required", http.StatusBadRequest)
		return
	}

	callback, err := h.stagerStore.ControlPersistent(callbackID, req.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.persistStager(callback)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(callbackSummary(callback))
}

func callbackSummary(stager *RegisteredStager) CallbackSummary {
	summary := CallbackSummary{
		ID:            stager.ID,
		SessionID:     stager.SessionID,
		ResponseType:  stager.ResponseType,
		CreatedAt:     stager.CreatedAt,
		CalledBack:    stager.CalledBack,
		CallbackIP:    stager.CallbackIP,
		Persistent:    stager.Persistent,
		MaxCallbacks:  stager.MaxCallbacks,
		DefaultMode:   stager.DefaultMode,
		NextMode:      stager.NextMode,
		CallbackCount: stager.CallbackCount,
		LastAgentID:   stager.LastAgentID,
		RevokedAt:     stager.RevokedAt,
		Metadata:      publicStagerMetadata(stager.Metadata),
	}
	if !stager.ExpiresAt.IsZero() {
		expiresAt := stager.ExpiresAt
		summary.ExpiresAt = &expiresAt
	}
	if !stager.CallbackAt.IsZero() {
		callbackAt := stager.CallbackAt
		summary.CallbackAt = &callbackAt
	}
	if stager.DwellTime > 0 {
		summary.DwellTime = stager.DwellTime.String()
	}
	return summary
}

func (h *Handler) persistStager(stager *RegisteredStager) {
	if h.database == nil || stager == nil {
		return
	}
	repo := db.NewStagerRepository(h.database)
	if err := repo.Upsert(stagerRowFromRegistered(stager)); err != nil {
		slog.Warn("failed to persist stager", "stager_id", stager.ID, "error", err)
	}
}

func (h *Handler) deleteStager(id string) {
	if h.database == nil || id == "" {
		return
	}
	repo := db.NewStagerRepository(h.database)
	if err := repo.Delete(id); err != nil {
		slog.Warn("failed to delete stager", "stager_id", id, "error", err)
	}
}

func stagerRowFromRegistered(stager *RegisteredStager) *db.StagerRow {
	if stager == nil {
		return nil
	}
	metadata, legacyPrivateMetadata := splitStagerMetadata(stager.Metadata)
	privateMetadata := cloneStagerMetadata(stager.PrivateMetadata)
	privateMetadata = mergeStagerMetadata(privateMetadata, legacyPrivateMetadata)

	row := &db.StagerRow{
		ID:              stager.ID,
		ResponseType:    stager.ResponseType,
		Payload:         stager.Payload,
		CreatedAt:       stager.CreatedAt,
		ExpiresAt:       stager.ExpiresAt,
		CalledBack:      stager.CalledBack,
		CallbackAt:      stager.CallbackAt,
		CallbackIP:      stager.CallbackIP,
		SessionID:       stager.SessionID,
		Metadata:        metadata,
		PrivateMetadata: privateMetadata,
		DwellTime:       stager.DwellTime,
		Persistent:      stager.Persistent,
		MaxCallbacks:    stager.MaxCallbacks,
		DefaultMode:     stager.DefaultMode,
		NextMode:        stager.NextMode,
		CallbackCount:   stager.CallbackCount,
		LastAgentID:     stager.LastAgentID,
		RevokedAt:       stager.RevokedAt,
	}
	return row
}

func registeredStagerFromRow(row *db.StagerRow) *RegisteredStager {
	if row == nil {
		return nil
	}
	metadata, legacyPrivateMetadata := splitStagerMetadata(row.Metadata)
	privateMetadata := cloneStagerMetadata(row.PrivateMetadata)
	privateMetadata = mergeStagerMetadata(privateMetadata, legacyPrivateMetadata)

	return &RegisteredStager{
		ID:              row.ID,
		ResponseType:    row.ResponseType,
		Payload:         row.Payload,
		CreatedAt:       row.CreatedAt,
		ExpiresAt:       row.ExpiresAt,
		CalledBack:      row.CalledBack,
		CallbackAt:      row.CallbackAt,
		CallbackIP:      row.CallbackIP,
		SessionID:       row.SessionID,
		Metadata:        metadata,
		PrivateMetadata: privateMetadata,
		DwellTime:       row.DwellTime,
		Persistent:      row.Persistent,
		MaxCallbacks:    row.MaxCallbacks,
		DefaultMode:     row.DefaultMode,
		NextMode:        row.NextMode,
		CallbackCount:   row.CallbackCount,
		LastAgentID:     row.LastAgentID,
		RevokedAt:       row.RevokedAt,
	}
}
