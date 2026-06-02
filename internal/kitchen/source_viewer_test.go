// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/auth"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestHandleGitHubSourceContentFetchesAndCaches(t *testing.T) {
	var contentCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		contentCalls++
		assert.Equal(t, "Bearer ghp_test", r.Header.Get("Authorization"))
		assert.Equal(t, "main", r.URL.Query().Get("ref"))
		assert.Equal(t, ".github/workflows/ci.yml", r.PathValue("path"))
		writeSourceContentFixture(w, "name: CI\non: push\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	body := `{"token":"ghp_test","owner":"acme","repo":"api","ref":"main","path":".github/workflows/ci.yml"}`

	first := httptest.NewRecorder()
	h.handleGitHubSourceContent(first, httptest.NewRequest(http.MethodPost, "/github/source/content", strings.NewReader(body)))
	assert.Equal(t, http.StatusOK, first.Code)
	var firstResp SourceContentResponse
	require.NoError(t, json.NewDecoder(first.Body).Decode(&firstResp))
	assert.False(t, firstResp.CacheHit)
	assert.Equal(t, "name: CI\non: push\n", firstResp.Content)

	second := httptest.NewRecorder()
	h.handleGitHubSourceContent(second, httptest.NewRequest(http.MethodPost, "/github/source/content", strings.NewReader(body)))
	assert.Equal(t, http.StatusOK, second.Code)
	var secondResp SourceContentResponse
	require.NoError(t, json.NewDecoder(second.Body).Decode(&secondResp))
	assert.True(t, secondResp.CacheHit)
	assert.Equal(t, 1, contentCalls)
}

func TestHandleGitHubSourceContentDoesNotCacheHEAD(t *testing.T) {
	var contentCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		contentCalls++
		assert.Empty(t, r.URL.Query().Get("ref"))
		writeSourceContentFixture(w, fmt.Sprintf("run: %d\n", contentCalls))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	body := `{"owner":"acme","repo":"api","path":".github/workflows/ci.yml"}`

	first := httptest.NewRecorder()
	h.handleGitHubSourceContent(first, httptest.NewRequest(http.MethodPost, "/github/source/content", strings.NewReader(body)))
	assert.Equal(t, http.StatusOK, first.Code)
	var firstResp SourceContentResponse
	require.NoError(t, json.NewDecoder(first.Body).Decode(&firstResp))
	assert.False(t, firstResp.CacheHit)
	assert.Equal(t, "run: 1\n", firstResp.Content)

	second := httptest.NewRecorder()
	h.handleGitHubSourceContent(second, httptest.NewRequest(http.MethodPost, "/github/source/content", strings.NewReader(body)))
	assert.Equal(t, http.StatusOK, second.Code)
	var secondResp SourceContentResponse
	require.NoError(t, json.NewDecoder(second.Body).Decode(&secondResp))
	assert.False(t, secondResp.CacheHit)
	assert.Equal(t, "run: 2\n", secondResp.Content)
	assert.Equal(t, 2, contentCalls)
}

func TestHandleGitHubSourceContentRefreshesStaleCacheEntry(t *testing.T) {
	var contentCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		contentCalls++
		assert.Equal(t, "main", r.URL.Query().Get("ref"))
		writeSourceContentFixture(w, "fresh\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	h.sourceCache = newMemorySourceCache()
	key := sourceContentCacheKey("github.com", "acme", "api", "main", ".github/workflows/ci.yml")
	h.sourceCache.entries[key] = sourceCacheEntry{
		Host:       "github.com",
		Repository: "acme/api",
		Owner:      "acme",
		Repo:       "api",
		Ref:        "main",
		Path:       ".github/workflows/ci.yml",
		Content:    "stale\n",
		FetchedAt:  time.Now().UTC().Add(-sourceCacheTTL - time.Second),
	}

	rec := httptest.NewRecorder()
	body := `{"owner":"acme","repo":"api","ref":"main","path":".github/workflows/ci.yml"}`
	h.handleGitHubSourceContent(rec, httptest.NewRequest(http.MethodPost, "/github/source/content", strings.NewReader(body)))

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp SourceContentResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.False(t, resp.CacheHit)
	assert.Equal(t, "fresh\n", resp.Content)
	assert.Equal(t, 1, contentCalls)
}

func TestSourceCacheGetRemovesStaleDiskEntry(t *testing.T) {
	dir := t.TempDir()
	cache := newDiskSourceCache(dir)
	key := "stale"
	entry := sourceCacheEntry{
		Host:      "github.com",
		Owner:     "acme",
		Repo:      "api",
		Ref:       "main",
		Path:      "README.md",
		Content:   "stale",
		FetchedAt: time.Now().UTC().Add(-sourceCacheTTL - time.Second),
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)
	path := filepath.Join(dir, key+".json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, ok := cache.get(key, time.Now().UTC())

	assert.False(t, ok)
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestHandleGitHubSourceContentDistinguishesMissingAndInvalidPath(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing",
			body: `{"owner":"acme","repo":"api","path":""}`,
			want: "path is required",
		},
		{
			name: "invalid",
			body: `{"owner":"acme","repo":"api","path":"../ci.yml"}`,
			want: "invalid path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handleGitHubSourceContent(rec, httptest.NewRequest(http.MethodPost, "/github/source/content", strings.NewReader(tt.body)))
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			var resp gitHubErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
			assert.Equal(t, tt.want, resp.Error)
		})
	}
}

func TestHandleGitHubSourceTokenRejectsMissingToken(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/github/source/token", strings.NewReader(`{"token":"  "}`))

	h.handleGitHubSourceToken(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp gitHubErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "token is required", resp.Error)
}

func TestHandleGitHubSourceTokenStoresOperatorSessionToken(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/github/source/token", strings.NewReader(`{"token":"ghp_session","source":"test","session_id":"sess-1"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.ClaimsKey, &auth.Claims{OperatorID: "op-1"}))

	h.handleGitHubSourceToken(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp SourceTokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.ExpiresAt.After(time.Now().UTC()))
	token, ok := h.sourceTokens.get([]string{"op-1:sess-1"}, time.Now().UTC())
	assert.True(t, ok)
	assert.Equal(t, "ghp_session", token)
	_, ok = h.sourceTokens.get([]string{"op-1:sess-2"}, time.Now().UTC())
	assert.False(t, ok)
	token, ok = h.sourceTokens.get([]string{"op-1"}, time.Now().UTC())
	assert.True(t, ok)
	assert.Equal(t, "ghp_session", token)
}

func TestSourceTokenCacheExpiresTokens(t *testing.T) {
	cache := newSourceTokenCache()
	now := time.Now().UTC()
	cache.put([]string{"op-1:sess-1"}, "ghp_session", "test", now)

	token, ok := cache.get([]string{"op-1:sess-1"}, now.Add(sourceTokenTTL-time.Second))
	assert.True(t, ok)
	assert.Equal(t, "ghp_session", token)
	_, ok = cache.get([]string{"op-1:sess-1"}, now.Add(sourceTokenTTL+time.Second))
	assert.False(t, ok)
}

func TestHandleSourceViewerRendersGitHubLikeFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, "main", r.URL.Query().Get("ref"))
		writeSourceContentFixture(w, "name: CI\nrun: echo '<ok>'\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/blob/{ref}/{path...}", h.handleSourceViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/blob/main/.github/workflows/ci.yml?line=2", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "script-src 'none'")
	assert.NotContains(t, rec.Header().Get("Content-Security-Policy"), "unsafe-inline")
	body := rec.Body.String()
	assert.Contains(t, body, "acme/api")
	assert.Contains(t, body, `<link rel="stylesheet" href="/viewer/assets/source-viewer.css">`)
	assert.Contains(t, body, `<a class="repo-host" href="/viewer/github.com/">github.com</a>`)
	assert.Contains(t, body, `<a class="repo-owner" href="/viewer/github.com/acme">acme</a>`)
	assert.Contains(t, body, `<a class="repo-link" href="/viewer/github.com/acme/api?ref=main"><strong>api</strong></a>`)
	assert.Contains(t, body, ".github/workflows/ci.yml")
	assert.Contains(t, body, `id="L2"`)
	assert.Contains(t, body, "line-highlight")
	assert.Contains(t, body, "echo &#39;&lt;ok&gt;&#39;")
	assert.Contains(t, body, `/viewer/github.com/acme/api/tree/main/.github/workflows`)
}

func TestHandleSourceViewerRendersMarkdownSafely(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		writeSourceContentFixture(w, "# Hello\n\n[bad](javascript:alert(1))\n\n<script>alert(2)</script>\n\n| A | B |\n| - | - |\n| one | two |\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/blob/{ref}/{path...}", h.handleSourceViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/blob/main/README.md", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `<div class="markdown-file-view">`)
	assert.Contains(t, body, `<h1>Hello</h1>`)
	assert.Contains(t, body, `<table>`)
	assert.NotContains(t, body, `javascript:alert`)
	assert.NotContains(t, body, `<script`)
	assert.NotContains(t, body, `<td class="line-num">`)
}

func TestHandleBrowserSessionSetsScopedCookiesAndRedirects(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/browser/session?token=jwt&session_id=sess&next=/graph", nil)
	rec := httptest.NewRecorder()

	h.handleBrowserSession(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/graph", rec.Header().Get("Location"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))

	cookies := rec.Result().Cookies()
	assert.Len(t, cookies, 3)
	assertSourceCookie(t, cookies, "smokedmeat_operator", "/viewer", "jwt")
	assertSourceCookie(t, cookies, "smokedmeat_operator", "/graph", "jwt")
	assertSourceCookie(t, cookies, sourceSessionCookie, "/viewer", "sess")
}

func TestHandleBrowserSessionRejectsExternalRedirect(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/browser/session?token=jwt&next=https%3A%2F%2Fevil.example%2F", nil)
	rec := httptest.NewRecorder()

	h.handleBrowserSession(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
}

func TestHandleBrowserAssetServesEmbeddedAssets(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /viewer/assets/{name}", h.handleBrowserAsset)
	mux.HandleFunc("GET /graph/assets/{name}", h.handleBrowserAsset)

	tests := []struct {
		name        string
		path        string
		contentType string
		want        string
	}{
		{
			name:        "source css",
			path:        "/viewer/assets/source-viewer.css",
			contentType: "text/css; charset=utf-8",
			want:        ".repo-name",
		},
		{
			name:        "graph css",
			path:        "/graph/assets/graph.css",
			contentType: "text/css; charset=utf-8",
			want:        ".legend-organization",
		},
		{
			name:        "graph js",
			path:        "/graph/assets/graph.js",
			contentType: "text/javascript; charset=utf-8",
			want:        "initCytoscape",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tt.contentType, rec.Header().Get("Content-Type"))
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
			assert.NotContains(t, rec.Header().Get("Content-Security-Policy"), "unsafe-inline")
			assert.Contains(t, rec.Body.String(), tt.want)
		})
	}
}

func TestHandleBrowserAssetRejectsCrossScopedAsset(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /viewer/assets/{name}", h.handleBrowserAsset)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/viewer/assets/graph.js", nil))

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
}

func TestHandleSourceGraphRootViewerListsGraphOrgs(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	require.NoError(t, h.Pantry().AddAsset(pantry.NewOrganization("acme", "github")))
	require.NoError(t, h.Pantry().AddAsset(pantry.NewRepository("acme", "api", "github")))

	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/", h.handleSourceGraphRootViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/?token=jwt&session_id=sess", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "github.com")
	assert.Contains(t, body, "Organizations in graph")
	assert.Contains(t, body, "acme")
	assert.Contains(t, body, "1 repo")
	assert.Contains(t, body, `/viewer/github.com/acme`)
}

func TestHandleSourceOwnerViewerRendersRepositories(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/{owner}/repos", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "acme", r.PathValue("owner"))
		writeSourceOwnerReposFixture(w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}", h.handleSourceOwnerViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme?token=jwt&session_id=sess", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Repositories")
	assert.Contains(t, body, `<a class="repo-host" href="/viewer/github.com/">github.com</a>`)
	assert.Contains(t, body, "api")
	assert.Contains(t, body, "private")
	assert.Contains(t, body, `/viewer/github.com/acme/api`)
}

func TestHandleSourceOwnerViewerUsesGraphRepositories(t *testing.T) {
	h := NewHandlerWithPublisher(nil, nil)
	repo := pantry.NewRepository("acme", "api", "github")
	repo.Properties["private"] = true
	repo.Properties["default_branch"] = "main"
	require.NoError(t, h.Pantry().AddAsset(repo))

	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}", h.handleSourceOwnerViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme?token=jwt", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Repositories")
	assert.Contains(t, body, "api")
	assert.Contains(t, body, "private")
	assert.Contains(t, body, "main")
	assert.Contains(t, body, `/viewer/github.com/acme/api`)
}

func TestHandleSourceRepositoryViewerRendersNavigableRoot(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "acme", r.PathValue("owner"))
		assert.Equal(t, "api", r.PathValue("repo"))
		writeSourceRepositoryFixture(w)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.URL.Query().Get("ref"))
		writeSourceDirectoryFixture(w, []sourceDirectoryFixtureEntry{
			{Name: ".github", Path: ".github", Type: "dir"},
			{Name: "README.md", Path: "README.md", Type: "file", Size: 16},
			{Name: "main.go", Path: "main.go", Type: "file", Size: 123},
		})
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/README.md", func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.URL.Query().Get("ref"))
		writeSourceContentFixture(w, "# API\n\nhello\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}", h.handleSourceRepositoryViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/", h.handleSourceRepositoryViewer)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api?token=jwt&session_id=sess", nil)
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "acme/api")
	assert.Contains(t, body, `<a class="repo-host" href="/viewer/github.com/">github.com</a>`)
	assert.Contains(t, body, `<a class="repo-owner" href="/viewer/github.com/acme">acme</a>`)
	assert.Contains(t, body, `<a class="repo-link" href="/viewer/github.com/acme/api?ref=main"><strong>api</strong></a>`)
	assert.Contains(t, body, "Example repository")
	assert.Contains(t, body, `<div class="ref-pill">main</div>`)
	assert.Contains(t, body, `/viewer/github.com/acme/api/tree/main/.github`)
	assert.Contains(t, body, `/viewer/github.com/acme/api/blob/main/main.go`)
	assert.Contains(t, body, `<div class="readme-title">README.md</div>`)
	assert.Contains(t, body, `<h1>API</h1>`)
}

func TestHandleSourceViewerFallsBackToDirectoryForBlobDirectoryURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		writeSourceRepositoryFixture(w)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/.github", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "main", r.URL.Query().Get("ref"))
		writeSourceDirectoryFixture(w, []sourceDirectoryFixtureEntry{
			{Name: "workflows", Path: ".github/workflows", Type: "dir"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/blob/{ref}/{path...}", h.handleSourceViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/blob/main/.github?token=jwt", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, ".github")
	assert.Contains(t, body, "workflows")
	assert.NotContains(t, body, "source viewer only supports files")
}

func TestHandleSourceTreeViewerRendersNestedDirectory(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		writeSourceRepositoryFixture(w)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/.github", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "main", r.URL.Query().Get("ref"))
		writeSourceDirectoryFixture(w, []sourceDirectoryFixtureEntry{
			{Name: "workflows", Path: ".github/workflows", Type: "dir"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/tree/{ref}/{path...}", h.handleSourceTreeViewer)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/tree/main/.github?token=jwt", nil)
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, ".github")
	assert.Contains(t, body, `/viewer/github.com/acme/api?ref=main`)
	assert.Contains(t, body, `/viewer/github.com/acme/api/tree/main/.github/workflows`)
}

func TestHandleSourceViewerSupportsSlashContainingRefs(t *testing.T) {
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.URL.Query().Get("ref")
		path := r.PathValue("path")
		calls = append(calls, ref+" "+path)
		if ref != "feature/foo" || path != ".github/workflows/ci.yml" {
			http.NotFound(w, r)
			return
		}
		writeSourceContentFixture(w, "name: CI\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/blob/{ref}/{path...}", h.handleSourceViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/blob/feature/foo/.github/workflows/ci.yml", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "feature/foo")
	assert.Contains(t, body, ".github/workflows/ci.yml")
	assert.Equal(t, []string{
		"feature foo/.github/workflows/ci.yml",
		"feature/foo .github/workflows/ci.yml",
	}, calls)
}

func TestSourceViewerPathCandidatesCapsAttempts(t *testing.T) {
	parts := []string{"feature"}
	for i := 0; i < sourceViewerMaxPathCandidates+5; i++ {
		parts = append(parts, fmt.Sprintf("part-%d", i))
	}

	candidates := sourceViewerPathCandidates(SourceContentRequest{
		Ref:  "HEAD",
		Path: strings.Join(parts, "/"),
	})

	require.Len(t, candidates, sourceViewerMaxPathCandidates)
	assert.Equal(t, "HEAD", candidates[0].Ref)
	assert.Equal(t, strings.Join(parts, "/"), candidates[0].Path)
	assert.Equal(t, "HEAD/feature", candidates[1].Ref)
	assert.Equal(t, strings.Join(parts[1:], "/"), candidates[1].Path)
}

func TestSourceCachePutWritesDiskCacheFile(t *testing.T) {
	dir := t.TempDir()
	cache := newDiskSourceCache(dir)
	entry := sourceCacheEntry{
		Host:       "github.com",
		Repository: "acme/api",
		Owner:      "acme",
		Repo:       "api",
		Ref:        "main",
		Path:       ".github/workflows/ci.yml",
		Content:    "name: CI\n",
		Size:       len("name: CI\n"),
		FetchedAt:  time.Now().UTC(),
	}

	require.NoError(t, cache.put("abc123", entry))
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "abc123.json", files[0].Name())

	data, err := os.ReadFile(filepath.Join(dir, "abc123.json"))
	require.NoError(t, err)
	var persisted sourceCacheEntry
	require.NoError(t, json.Unmarshal(data, &persisted))
	assert.Equal(t, entry.Content, persisted.Content)
}

func sourceTestGitHubClientFactory(t *testing.T, serverURL string) func(string) *gitHubClient {
	t.Helper()
	return func(token string) *gitHubClient {
		baseURL, err := url.Parse(serverURL + "/")
		require.NoError(t, err)
		var httpClient *http.Client
		if token == "" {
			httpClient = http.DefaultClient
		} else {
			httpClient = oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		}
		c := github.NewClient(httpClient)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
}

func writeSourceContentFixture(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "application/json")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	fmt.Fprintf(w, `{"type":"file","encoding":"base64","content":%q,"sha":"abc123","html_url":"https://github.com/acme/api/blob/main/.github/workflows/ci.yml","size":%d}`, encoded, len([]byte(content)))
}

func writeSourceRepositoryFixture(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"default_branch":"main","html_url":"https://github.com/acme/api","description":"Example repository"}`)
}

func writeSourceOwnerReposFixture(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `[{"name":"api","full_name":"acme/api","private":true,"default_branch":"main","html_url":"https://github.com/acme/api","description":"API repo"}]`)
}

type sourceDirectoryFixtureEntry struct {
	Name string
	Path string
	Type string
	Size int
}

func writeSourceDirectoryFixture(w http.ResponseWriter, entries []sourceDirectoryFixtureEntry) {
	w.Header().Set("Content-Type", "application/json")
	var b strings.Builder
	b.WriteString("[")
	for i, entry := range entries {
		if i > 0 {
			b.WriteString(",")
		}
		size := entry.Size
		fmt.Fprintf(&b, `{"name":%q,"path":%q,"type":%q,"sha":%q,"html_url":%q,"size":%d}`,
			entry.Name,
			entry.Path,
			entry.Type,
			"sha-"+entry.Name,
			"https://github.com/acme/api/"+entry.Path,
			size,
		)
	}
	b.WriteString("]")
	_, _ = w.Write([]byte(b.String()))
}

func assertSourceCookie(t *testing.T, cookies []*http.Cookie, name, path, value string) {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Path == path {
			assert.Equal(t, value, cookie.Value)
			assert.True(t, cookie.HttpOnly)
			assert.False(t, cookie.Secure)
			assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
			assert.Equal(t, int(browserSessionCookieMaxAge.Seconds()), cookie.MaxAge)
			return
		}
	}
	assert.Failf(t, "missing cookie", "missing %s cookie at path %s", name, path)
}
