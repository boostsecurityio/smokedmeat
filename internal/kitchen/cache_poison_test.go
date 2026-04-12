// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

func TestHandler_PrepareCachePoison_RegistersWriterAndVictim(t *testing.T) {
	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)

	reqBody := map[string]any{
		"session_id":        "sess-1",
		"external_url":      "https://public.example",
		"writer_stager_id":  "writer-stg",
		"writer_repository": "acme/api",
		"writer_workflow":   ".github/workflows/lint.yml",
		"writer_job":        "lint",
		"victim_dwell_time": "45s",
		"victim": cachepoison.VictimCandidate{
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
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cache-poison/prepare", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp prepareCachePoisonResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp.VictimStagerID)
	assert.Equal(t, stagerurl.Join("https://public.example", resp.VictimStagerID), resp.VictimStagerURL)
	assert.Regexp(t, regexp.MustCompile(`^stg_sm_[0-9a-f]{16}$`), resp.VictimStagerID)
	assert.Equal(t, "writer-stg", resp.WriterCallback.ID)
	assert.True(t, resp.WriterCallback.Persistent)
	assert.True(t, resp.VictimCallback.Persistent)
	require.NotNil(t, h.stagerStore.Get("writer-stg"))
	require.NotNil(t, h.stagerStore.Get(resp.VictimStagerID))
}

func TestHandler_PrepareCachePoison_EncodesDeploymentConfigInKitchen(t *testing.T) {
	mock := &mockPublisher{}
	h, _ := newTestHandler(mock, nil)

	reqBody := map[string]any{
		"session_id":        "sess-1",
		"external_url":      "https://public.example",
		"writer_stager_id":  "writer-stg",
		"writer_repository": "acme/api",
		"writer_workflow":   ".github/workflows/lint.yml",
		"writer_job":        "lint",
		"victim_dwell_time": "45s",
		"victim": cachepoison.VictimCandidate{
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
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/cache-poison/prepare", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.handlePrepareCachePoison(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	writer := h.stagerStore.Get("writer-stg")
	require.NotNil(t, writer)
	assert.Equal(t, "Cache poison writer · .github/workflows/lint.yml", writer.Metadata["callback_label"])
	assert.Contains(t, writer.Payload, "sudo -E")
	assert.True(t, strings.Contains(writer.Payload, `"${AGENT_BIN}"`) || strings.Contains(writer.Payload, `"$AGENT_BIN"`))
	assert.Contains(t, writer.Payload, `-callback-id "$CALLBACK_ID"`)
	assert.Contains(t, writer.Payload, `-callback-mode "$CALLBACK_MODE"`)
	assert.Contains(t, writer.Payload, `-cache-poison "$CACHE_POISON_CONFIG"`)

	match := regexp.MustCompile(`CACHE_POISON_CONFIG="([^"]+)"`).FindStringSubmatch(writer.Payload)
	require.Len(t, match, 2)

	cfg, err := cachepoison.DecodeDeploymentConfig(match[1])
	require.NoError(t, err)
	assert.Equal(t, ".github/workflows/release.yml", cfg.Candidate.Workflow)
	assert.Equal(t, "release", cfg.Candidate.Job)
	assert.Equal(t, cachepoison.ExecutionKindCheckoutPost, cfg.Candidate.Execution.Kind)
	assert.Equal(t, cachepoison.CacheEntryModePredicted, cfg.Candidate.CacheEntry.Mode)

	victim := h.stagerStore.Get(cfg.VictimCallbackID)
	require.NotNil(t, victim)
	assert.Equal(t, "Cache poison victim · .github/workflows/release.yml", victim.Metadata["callback_label"])
	assert.Equal(t, stagerurl.Join("https://public.example", cfg.VictimCallbackID), cfg.VictimStagerURL)
	assert.Equal(t, "45s", victim.DwellTime.String())
}
