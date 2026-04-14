// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-github/v59/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

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

func TestHandler_PrepareCachePoison_PurgeFlagsOnlyDeleteRequests(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	var repoGetUA string
	var listCachesUA string
	var deleteCacheUA string

	ghMux := http.NewServeMux()
	ghMux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		repoGetUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"default_branch":"main"}`))
	})
	ghMux.HandleFunc("GET /repos/{owner}/{repo}/actions/caches", func(w http.ResponseWriter, r *http.Request) {
		listCachesUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"total_count":1,"actions_caches":[{"id":11,"key":"setup-go-linux-abc","ref":"refs/heads/main","version":"v1","created_at":"2026-03-27T12:00:00Z"}]}`))
	})
	ghMux.HandleFunc("DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}", func(w http.ResponseWriter, r *http.Request) {
		deleteCacheUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusNoContent)
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token, graphqlURL: ghSrv.URL + "/graphql"}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	reqBody := map[string]any{
		"session_id":        "sess-1",
		"external_url":      "https://public.example",
		"writer_stager_id":  "writer-stg",
		"writer_repository": "acme/api",
		"writer_workflow":   ".github/workflows/lint.yml",
		"writer_job":        "lint",
		"purge_token":       "ghs_app_token",
		"purge_key":         "setup-go-linux-abc",
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
	assert.NotContains(t, repoGetUA, gitHubExploitUserAgentID)
	assert.NotContains(t, listCachesUA, gitHubExploitUserAgentID)
	assert.Equal(t, gitHubExploitUserAgent(), deleteCacheUA)
}
