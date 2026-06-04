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
	req := httptest.NewRequest(http.MethodPost, "/github/source/token", strings.NewReader(`{"token":"ghp_session","source":"test","session_id":"sess-1","app_id":"42"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.ClaimsKey, &auth.Claims{OperatorID: "op-1"}))

	h.handleGitHubSourceToken(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp SourceTokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.ExpiresAt.After(time.Now().UTC()))
	token, ok := h.sourceTokens.get([]string{"op-1:sess-1"}, time.Now().UTC())
	assert.True(t, ok)
	assert.Equal(t, "ghp_session", token)
	entry, ok := h.sourceTokens.getEntry([]string{"op-1:sess-1"}, time.Now().UTC())
	assert.True(t, ok)
	assert.Equal(t, "test", entry.Source)
	assert.Equal(t, "42", entry.AppID)
	_, ok = h.sourceTokens.get([]string{"op-1:sess-2"}, time.Now().UTC())
	assert.False(t, ok)
	token, ok = h.sourceTokens.get([]string{"op-1"}, time.Now().UTC())
	assert.True(t, ok)
	assert.Equal(t, "ghp_session", token)
}

func TestSourceViewerIdentityUserToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer ghp_user", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"alice","name":"Alice Example","avatar_url":"https://avatars.githubusercontent.com/u/1","html_url":"https://github.com/alice","type":"User","public_repos":12,"total_private_repos":3,"two_factor_authentication":true}`)
	})
	mux.HandleFunc("GET /user/installations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	})
	mux.HandleFunc("GET /rate_limit", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"resources":{"core":{"limit":5000,"remaining":4988,"reset":1780502400},"search":{"limit":30,"remaining":29,"reset":1780502460},"graphql":{"limit":5000,"remaining":4999,"reset":1780502520}}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	h.sourceTokens.put([]string{"operator"}, "ghp_user", "pat", time.Now().UTC())
	rec := httptest.NewRecorder()
	h.handleSourceViewerIdentity(rec, httptest.NewRequest(http.MethodGet, "/viewer/identity", nil))

	var resp sourceViewerIdentityResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "user", resp.Kind)
	assert.Equal(t, "Signed in as @alice", resp.Label)
	assert.Equal(t, "Alice Example", resp.Name)
	assert.Equal(t, "https://github.com/alice", resp.HTMLURL)
	assert.Contains(t, resp.Badges, "user")
	assertSourceIdentityDetail(t, resp, "private repos", "3")
	assertSourceIdentityDetailAbsent(t, resp, "profile")
	assertSourceIdentityDetailAbsent(t, resp, "external link")
	assertSourceRateLimit(t, resp, "core", 4988, 5000)
}

func TestSourceViewerIdentityAppToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":42,"slug":"smokedmeat-lab","name":"SmokedMeat Lab","html_url":"https://github.com/apps/smokedmeat-lab","installations_count":7,"owner":{"login":"boostsecurityio","avatar_url":"https://avatars.githubusercontent.com/u/2"}}`)
	})
	mux.HandleFunc("GET /app/installations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":99,"repository_selection":"selected","account":{"login":"whooli"}}]`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	h.sourceTokens.put([]string{"operator"}, "app_jwt", "pivot:app:42", time.Now().UTC())
	rec := httptest.NewRecorder()
	h.handleSourceViewerIdentity(rec, httptest.NewRequest(http.MethodGet, "/viewer/identity", nil))

	var resp sourceViewerIdentityResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "app", resp.Kind)
	assert.Equal(t, "SmokedMeat Lab", resp.Label)
	assert.Equal(t, "smokedmeat-lab", resp.Login)
	assert.Equal(t, "https://github.com/apps/smokedmeat-lab", resp.HTMLURL)
	assertSourceIdentityDetail(t, resp, "installations", "7")
	assertSourceIdentityDetail(t, resp, "sample account", "whooli")
	assertSourceIdentityDetailAbsent(t, resp, "external link")
}

func TestSourceViewerIdentityInstallationToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cached_app_jwt" {
			http.Error(w, `{"message":"A JSON web token could not be decoded"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":42,"slug":"smokedmeat-lab","name":"SmokedMeat Lab","html_url":"https://github.com/apps/smokedmeat-lab","installations_count":7,"owner":{"login":"boostsecurityio","avatar_url":"https://avatars.githubusercontent.com/u/2"},"permissions":{"contents":"read","issues":"write","metadata":"read"},"events":["issues","pull_request"]}`)
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total_count":2,"repositories":[{"full_name":"whooli/xyz","html_url":"https://github.com/whooli/xyz","permissions":{"pull":true,"push":true},"owner":{"login":"whooli","html_url":"https://github.com/whooli","avatar_url":"https://avatars.githubusercontent.com/u/3"}}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	now := time.Now().UTC()
	h.sourceAppJWTs.put("42", "cached_app_jwt", now)
	h.sourceTokens.putWithAppID([]string{"operator"}, "ghs_installation", "loot:APP_TOKEN_whooli", "42", now)
	rec := httptest.NewRecorder()
	h.handleSourceViewerIdentity(rec, httptest.NewRequest(http.MethodGet, "/viewer/identity", nil))

	var resp sourceViewerIdentityResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "installation", resp.Kind)
	assert.Equal(t, "GitHub App access to whooli", resp.Label)
	assert.Equal(t, "SmokedMeat Lab", resp.Name)
	assert.Equal(t, "https://github.com/apps/smokedmeat-lab", resp.HTMLURL)
	assertSourceIdentityDetail(t, resp, "visible repositories", "2")
	assertSourceIdentityDetail(t, resp, "app", "SmokedMeat Lab")
	assertSourceIdentityDetail(t, resp, "permissions", "contents: read, issues: write, metadata: read")
	assertSourceIdentityDetail(t, resp, "events", "issues, pull_request")
	assertSourceIdentityDetail(t, resp, "sample repo", "whooli/xyz")
	assertSourceIdentityDetail(t, resp, "sample repo permissions", "push, pull")
	assertSourceIdentityDetailAbsent(t, resp, "app page")
	assertSourceIdentityDetailAbsent(t, resp, "external link")
}

func TestFetchGitHubSourceIssuesSkipsPullRequestsAcrossPages(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/api/issues", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=2>; rel="next"`, r.Host, r.URL.Path))
			fmt.Fprint(w, `[
				{"number":101,"title":"PR one","state":"open","pull_request":{"url":"https://api.github.com/repos/acme/api/pulls/101"}},
				{"number":102,"title":"PR two","state":"open","pull_request":{"url":"https://api.github.com/repos/acme/api/pulls/102"}}
			]`)
		case "2":
			fmt.Fprint(w, `[{"number":17,"title":"Actual issue","state":"open","user":{"login":"alice"}}]`)
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	issues, pagination, err := fetchGitHubSourceIssues(context.Background(), SourceContentRequest{Owner: "acme", Repo: "api"}, "open", 1)

	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, 17, issues[0].Number)
	assert.Equal(t, "Actual issue", issues[0].Title)
	assert.Equal(t, 2, calls)
	assert.Equal(t, sourcePagination{Page: 1}, pagination)
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

func assertSourceIdentityDetail(t *testing.T, resp sourceViewerIdentityResponse, label, value string) {
	t.Helper()
	for _, detail := range resp.Details {
		if detail.Label == label {
			assert.Equal(t, value, detail.Value)
			return
		}
	}
	t.Fatalf("identity detail %q not found in %#v", label, resp.Details)
}

func assertSourceIdentityDetailAbsent(t *testing.T, resp sourceViewerIdentityResponse, label string) {
	t.Helper()
	for _, detail := range resp.Details {
		assert.NotEqual(t, label, detail.Label)
	}
}

func assertSourceRateLimit(t *testing.T, resp sourceViewerIdentityResponse, label string, remaining, limit int) {
	t.Helper()
	for _, rate := range resp.Rates {
		if rate.Label == label {
			assert.Equal(t, remaining, rate.Remaining)
			assert.Equal(t, limit, rate.Limit)
			assert.NotEmpty(t, rate.Reset)
			return
		}
	}
	t.Fatalf("rate limit %q not found in %#v", label, resp.Rates)
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
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "script-src 'self'")
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
	assert.NotContains(t, body, `<script>alert`)
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
			name:        "source js",
			path:        "/viewer/assets/source-viewer.js",
			contentType: "text/javascript; charset=utf-8",
			want:        "collapse-toggle",
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
	assert.Contains(t, body, `href="/graph"`)
	assert.Contains(t, body, `class="active" href="/viewer/github.com/"`)
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

func TestHandleSourceViewerRendersWorkflowAuditSidebar(t *testing.T) {
	workflow := `name: CI
on:
  pull_request_target:
permissions:
  id-token: write
jobs:
  build:
    runs-on: [self-hosted, linux]
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@main
      - name: dangerous
        run: echo "${{ github.event.pull_request.title }}"
`
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		writeSourceContentFixture(w, workflow)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	vuln := pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 13)
	require.NoError(t, h.Pantry().AddAsset(vuln))

	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/blob/{ref}/{path...}", h.handleSourceViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/blob/main/.github/workflows/ci.yml", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Workflow audit")
	assert.Contains(t, body, `href="#L3"><span class="risk-label">trigger</span>`)
	assert.Contains(t, body, "self-hosted")
	assert.Contains(t, body, "OIDC")
	assert.Contains(t, body, "write token")
	assert.Contains(t, body, "tainted input")
	assert.Contains(t, body, "User-controlled workflow input")
	assert.NotContains(t, body, "Poutine")
	assert.NotContains(t, body, "pantry")
	assert.Contains(t, body, "repo-nav-item-active")
	assert.Contains(t, body, "/viewer/assets/source-viewer.js")
	assert.Contains(t, body, `class="source-layout source-layout-sidebar"`)
	assert.Contains(t, body, "ch-")
}

func TestHandleSourceViewerGroupsTaintedInputAuditEvidence(t *testing.T) {
	workflow := `name: CI
on:
  issues:
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: dangerous
        run: |
          ISSUE_TITLE="${{ github.event.issue.title }}"
          ISSUE_BODY="${{ github.event.issue.body }}"
          echo "$ISSUE_TITLE $ISSUE_BODY"
`
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		writeSourceContentFixture(w, workflow)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	vulnTitle := pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 11)
	vulnTitle.Properties["injection_sources"] = []string{"github.event.issue.title"}
	require.NoError(t, h.Pantry().AddAsset(vulnTitle))
	vulnBody := pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/ci.yml", 11)
	vulnBody.Properties["injection_sources"] = []string{"github.event.issue.body"}
	require.NoError(t, h.Pantry().AddAsset(vulnBody))

	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/blob/{ref}/{path...}", h.handleSourceViewer)
	req := httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/blob/main/.github/workflows/ci.yml", nil)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Equal(t, 1, strings.Count(body, `<a class="risk-link risk-high" href="#L11"><span class="risk-label">tainted input</span>`))
	assert.Contains(t, body, `<span class="risk-detail-pill">github.event.issue.body</span>`)
	assert.Contains(t, body, `<span class="risk-detail-pill">github.event.issue.title</span>`)
	assert.Equal(t, 1, strings.Count(body, `Shell command uses attacker-controlled GitHub context.`))
}

func TestSourceRepoSectionViewersRenderGitHubData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/branches", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"main","commit":{"sha":"abc123456789abcdef"},"protected":true}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/tags", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"v1.0.0","commit":{"sha":"def123456789abcdef"}}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/releases", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"Release 1","tag_name":"v1.0.0","html_url":"https://github.com/acme/api/releases/tag/v1.0.0","published_at":"2026-06-01T12:00:00Z"}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"workflow_runs":[{"id":123,"name":"CI","display_title":"build main","head_branch":"main","event":"push","status":"completed","conclusion":"success","run_number":7,"run_attempt":1,"html_url":"https://github.com/acme/api/actions/runs/123","created_at":"2026-06-02T21:17:00Z","run_started_at":"2026-06-02T21:18:00Z","actor":{"login":"alice"}}]}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runners", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"total_count":1,"runners":[{"id":99,"name":"runner-1","os":"linux","status":"online","busy":true,"labels":[{"name":"self-hosted"},{"name":"linux"},{"name":"x64"}]}]}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/caches", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "last_accessed_at", r.URL.Query().Get("sort"))
		assert.Equal(t, "desc", r.URL.Query().Get("direction"))
		fmt.Fprint(w, `{"total_count":1,"actions_caches":[{"id":44,"key":"go-build-cache","ref":"refs/heads/main","version":"abcdef1234567890","size_in_bytes":2097152,"created_at":"2026-06-01T10:00:00Z","last_accessed_at":"2026-06-02T10:00:00Z"}]}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/cache/usage", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"full_name":"acme/api","active_caches_size_in_bytes":2097152,"active_caches_count":1}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "open", r.URL.Query().Get("state"))
		assert.Equal(t, "updated", r.URL.Query().Get("sort"))
		fmt.Fprint(w, `[{"number":17,"title":"Runner token exposure","state":"open","state_reason":"reopened","comments":3,"html_url":"https://github.com/acme/api/issues/17","created_at":"2026-06-01T10:00:00Z","updated_at":"2026-06-02T11:00:00Z","user":{"login":"alice"},"labels":[{"name":"security"},{"name":"runner"}]},{"number":18,"title":"PR shaped issue","state":"open","pull_request":{"url":"https://api.github.com/repos/acme/api/pulls/18"}}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "open", r.URL.Query().Get("state"))
		assert.Equal(t, "updated", r.URL.Query().Get("sort"))
		fmt.Fprint(w, `[{"number":22,"title":"Harden workflow","state":"open","draft":true,"comments":2,"review_comments":4,"commits":5,"changed_files":3,"additions":120,"deletions":9,"created_at":"2026-06-01T12:00:00Z","updated_at":"2026-06-02T12:00:00Z","user":{"login":"bob"},"base":{"ref":"main"},"head":{"label":"bob:harden-workflow","ref":"harden-workflow"}}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/environments", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"environments":[{"name":"production","html_url":"https://github.com/acme/api/settings/environments/1","wait_timer":30,"reviewers":[{"type":"User","id":1}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":true},"can_admins_bypass":false,"protection_rules":[{"id":1,"type":"wait_timer","wait_timer":30}],"updated_at":"2026-06-02T21:18:00Z"}]}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/rulesets", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "true", r.URL.Query().Get("includes_parents"))
		fmt.Fprint(w, `[{"id":42,"name":"Release branches","source_type":"Repository","source":"acme/api","target":"branch","enforcement":"active","bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"pull_request"}],"conditions":{"ref_name":{"include":["refs/heads/main"],"exclude":["refs/heads/tmp/*"]},"repository_name":{"include":["acme/api"],"exclude":["acme/legacy"],"protected":true}},"rules":[{"type":"pull_request","parameters":{"required_approving_review_count":2,"require_code_owner_review":true,"require_last_push_approval":true,"dismiss_stale_reviews_on_push":false,"required_review_thread_resolution":true}},{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"ci/test"}],"strict_required_status_checks_policy":true}},{"type":"required_deployments","parameters":{"required_deployment_environments":["production"]}},{"type":"commit_message_pattern","parameters":{"operator":"contains","pattern":"SECURITY","negate":false}}]}]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/branches", h.handleSourceBranchesViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/tags", h.handleSourceTagsViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/releases", h.handleSourceReleasesViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions", h.handleSourceActionsViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions/runners", h.handleSourceActionRunnersViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions/caches", h.handleSourceActionCachesViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/issues", h.handleSourceIssuesViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/issues/{issue_number}", h.handleSourceIssueViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/pulls", h.handleSourcePullRequestsViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/pulls/{pull_number}", h.handleSourcePullRequestViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/environments", h.handleSourceEnvironmentsViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/rulesets", h.handleSourceRulesetsViewer)

	tests := []struct {
		path string
		want []string
	}{
		{path: "/viewer/github.com/acme/api/branches", want: []string{"Branches", "main", "protected", "abc123456789"}},
		{path: "/viewer/github.com/acme/api/tags", want: []string{"Tags", "v1.0.0", "def123456789"}},
		{path: "/viewer/github.com/acme/api/releases", want: []string{"Releases", "Release 1", "v1.0.0"}},
		{path: "/viewer/github.com/acme/api/actions", want: []string{"Workflow runs", "build main", "success", "/viewer/github.com/acme/api/actions/runs/123", "/viewer/github.com/acme/api/actions/runners", "/viewer/github.com/acme/api/actions/caches", `action="/viewer/github.com/acme/api/actions"`, `https://github.com/acme/api/actions`, `<span class="repo-row-meta-label">branch</span><strong>main</strong>`, `<span class="repo-row-meta-label">event</span><strong>push</strong>`, `<span class="repo-row-meta-label">actor</span><strong>alice</strong>`, `<span class="repo-row-meta-label">started</span><strong>Jun 2, 2026 21:18 UTC</strong>`}},
		{path: "/viewer/github.com/acme/api/actions/runners", want: []string{"Actions runners", "runner-1", "online", "busy", `<span class="repo-row-meta-label">id</span><strong>99</strong>`, `<span class="repo-row-meta-label">os</span><strong>linux</strong>`, `<span class="repo-row-meta-label">labels</span><strong>self-hosted, linux, x64</strong>`, `https://github.com/acme/api/actions/runners`}},
		{path: "/viewer/github.com/acme/api/actions/caches", want: []string{"Actions caches", "go-build-cache", "2.0 MB", "Cache usage", "1 active caches using 2.0 MB.", `<span class="repo-row-meta-label">ref</span><strong>refs/heads/main</strong>`, `<span class="repo-row-meta-label">created</span><strong>2026-06-01</strong>`, `<span class="repo-row-meta-label">last used</span><strong>2026-06-02</strong>`, `<span class="repo-row-meta-label">version</span><strong>abcdef123456</strong>`, `https://github.com/acme/api/actions/caches`}},
		{path: "/viewer/github.com/acme/api/issues", want: []string{"Issues", "#17 Runner token exposure", `/viewer/github.com/acme/api/issues/17`, `href="/viewer/github.com/acme/api/issues?state=closed"`, "open", "reopened", `<span class="repo-row-meta-label">author</span><strong>alice</strong>`, `<span class="repo-row-meta-label">comments</span><strong>3</strong>`, `<span class="repo-row-meta-label">labels</span><strong>security, runner</strong>`, `https://github.com/acme/api/issues`}},
		{path: "/viewer/github.com/acme/api/pulls", want: []string{"Pull requests", "#22 Harden workflow", `/viewer/github.com/acme/api/pulls/22`, `href="/viewer/github.com/acme/api/pulls?state=closed"`, "open", "draft", `<span class="repo-row-meta-label">author</span><strong>bob</strong>`, `<span class="repo-row-meta-label">base</span><strong>main</strong>`, `<span class="repo-row-meta-label">head</span><strong>bob:harden-workflow</strong>`, `<span class="repo-row-meta-label">commits</span><strong>5</strong>`, `<span class="repo-row-meta-label">files</span><strong>3</strong>`, `<span class="repo-row-meta-label">diff</span><strong>&#43;120 / -9</strong>`, `https://github.com/acme/api/pulls`}},
		{path: "/viewer/github.com/acme/api/environments", want: []string{"Environments", "production", "protected", `<span class="repo-row-meta-label">wait</span><strong>30 min</strong>`, `<span class="repo-row-meta-label">branches</span><strong>protected branches and custom policies</strong>`, `<span class="repo-row-meta-label">admin bypass</span><strong>blocked</strong>`, `<span class="repo-row-meta-label">updated</span><strong>2026-06-02</strong>`, "Reviewers: user #1.", `https://github.com/acme/api/settings/environments`}},
		{path: "/viewer/github.com/acme/api/rulesets", want: []string{"Repository rulesets", "Release branches", "active", `<span class="repo-row-meta-label">target</span><strong>branch</strong>`, `<span class="repo-row-meta-label">rules</span><strong>4</strong>`, `<span class="repo-row-meta-label">include</span><strong>refs/heads/main</strong>`, `<span class="repo-row-meta-label">exclude</span><strong>refs/heads/tmp/*</strong>`, `<span class="repo-row-meta-label">repos</span><strong>acme/api</strong>`, `<span class="repo-row-meta-label">repo exclude</span><strong>acme/legacy</strong>`, `<span class="repo-row-meta-label">protected repos</span><strong>allowed</strong>`, "Rules: pull request, 2 approvals, code owner review, last push approval, conversation resolution; required status checks, strict, ci/test; required deployments, production; commit message pattern, contains SECURITY.", "Bypass: repository role #5 (pull request).", `https://github.com/acme/api/settings/rules`}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			viewerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			assert.Equal(t, http.StatusOK, rec.Code)
			for _, want := range tt.want {
				assert.Contains(t, rec.Body.String(), want)
			}
			if tt.path == "/viewer/github.com/acme/api/environments" {
				assert.NotContains(t, rec.Body.String(), "https://github.com/acme/api/settings/environments/1")
			}
		})
	}
}

func TestSourceViewerPullRequestDiscussionSortsTimelineChronologically(t *testing.T) {
	base := time.Date(2026, 6, 2, 21, 18, 0, 0, time.UTC)
	view := sourceViewerPullRequestDiscussion(sourcePullRequestDetail{
		Pull: sourcePullRequestEntry{Number: 22, Title: "Harden workflow", State: "open"},
		IssueComments: []sourceDiscussionEntry{{
			Type:      "comment",
			Author:    "alice",
			CreatedAt: base.Add(2 * time.Minute),
		}},
		Reviews: []sourceDiscussionEntry{{
			Type:      "review",
			Author:    "bob",
			CreatedAt: base.Add(time.Minute),
		}},
		ReviewComments: []sourceDiscussionEntry{{
			Type:      "review comment",
			Author:    "carol",
			CreatedAt: base.Add(3 * time.Minute),
		}},
	})

	require.Len(t, view.Timeline, 3)
	assert.Equal(t, "review", view.Timeline[0].Type)
	assert.Equal(t, "comment", view.Timeline[1].Type)
	assert.Equal(t, "review comment", view.Timeline[2].Type)
}

func TestSourceIssuesAndPullRequestsSupportStatePaginationAndDetails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "closed", r.URL.Query().Get("state"))
		var body strings.Builder
		body.WriteString("[")
		for i := 1; i <= 61; i++ {
			if i > 1 {
				body.WriteString(",")
			}
			fmt.Fprintf(&body, `{"number":%d,"title":"Closed issue","state":"closed","state_reason":"completed","comments":1,"html_url":"https://github.com/acme/api/issues/%d","created_at":"2026-05-01T10:00:00Z","updated_at":"2026-05-02T11:00:00Z","user":{"login":"alice"}}`, i, i)
		}
		body.WriteString("]")
		fmt.Fprint(w, body.String())
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues/{issue_number}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "31", r.PathValue("issue_number"))
		fmt.Fprint(w, `{"number":31,"title":"Closed issue","body":"The runner leaked a token.","state":"closed","state_reason":"completed","comments":1,"html_url":"https://github.com/acme/api/issues/31","created_at":"2026-05-01T10:00:00Z","updated_at":"2026-05-02T11:00:00Z","user":{"login":"alice"}}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues/{issue_number}/comments", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"body":"Confirmed fixed.","html_url":"https://github.com/acme/api/issues/31#issuecomment-1","author_association":"MEMBER","created_at":"2026-05-02T12:00:00Z","updated_at":"2026-05-02T12:00:00Z","user":{"login":"bob"}}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "closed", r.URL.Query().Get("state"))
		assert.Equal(t, "2", r.URL.Query().Get("page"))
		w.Header().Set("Link", `<https://api.github.test/repos/acme/api/pulls?state=closed&page=1>; rel="prev"`)
		fmt.Fprint(w, `[{"number":41,"title":"Closed pull request","body":"Merged hardening changes.","state":"closed","merged":true,"comments":2,"review_comments":1,"commits":2,"changed_files":1,"additions":20,"deletions":5,"html_url":"https://github.com/acme/api/pull/41","created_at":"2026-05-03T10:00:00Z","updated_at":"2026-05-04T11:00:00Z","user":{"login":"carol"},"base":{"ref":"main"},"head":{"label":"carol:hardening"}}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{pull_number}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "41", r.PathValue("pull_number"))
		fmt.Fprint(w, `{"number":41,"title":"Closed pull request","body":"Merged hardening changes.","state":"closed","merged":true,"comments":2,"review_comments":1,"commits":2,"changed_files":1,"additions":20,"deletions":5,"html_url":"https://github.com/acme/api/pull/41","created_at":"2026-05-03T10:00:00Z","updated_at":"2026-05-04T11:00:00Z","user":{"login":"carol"},"base":{"ref":"main"},"head":{"label":"carol:hardening"}}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"body":"Looks good.","state":"APPROVED","html_url":"https://github.com/acme/api/pull/41#pullrequestreview-1","author_association":"MEMBER","submitted_at":"2026-05-04T10:00:00Z","user":{"login":"dana"}}]`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{pull_number}/comments", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"body":"Check this line.","path":".github/workflows/ci.yml","line":12,"html_url":"https://github.com/acme/api/pull/41#discussion_r1","author_association":"CONTRIBUTOR","created_at":"2026-05-04T10:30:00Z","updated_at":"2026-05-04T10:30:00Z","user":{"login":"erin"}}]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/issues", h.handleSourceIssuesViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/issues/{issue_number}", h.handleSourceIssueViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/pulls", h.handleSourcePullRequestsViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/pulls/{pull_number}", h.handleSourcePullRequestViewer)

	tests := []struct {
		path string
		want []string
	}{
		{path: "/viewer/github.com/acme/api/issues?state=closed&page=2", want: []string{"#31 Closed issue", `/viewer/github.com/acme/api/issues/31`, `href="/viewer/github.com/acme/api/issues?state=closed"`, `href="/viewer/github.com/acme/api/issues?page=3&amp;state=closed"`, "Page 2"}},
		{path: "/viewer/github.com/acme/api/issues/31", want: []string{"Issue #31", `<div class="markdown-body discussion-body"><p>The runner leaked a token.</p>`, `<a class="discussion-author" href="https://github.com/acme/api/issues/31#issuecomment-1">bob</a>`, `<p>Confirmed fixed.</p>`, `<span class="repo-row-meta-label">role</span><strong>member</strong>`, `https://github.com/acme/api/issues/31`}},
		{path: "/viewer/github.com/acme/api/pulls?state=closed&page=2", want: []string{"#41 Closed pull request", `/viewer/github.com/acme/api/pulls/41`, `href="/viewer/github.com/acme/api/pulls?state=closed"`, "Previous", "Page 2"}},
		{path: "/viewer/github.com/acme/api/pulls/41", want: []string{"Pull request #41", "Merged hardening changes.", "Looks good.", "Check this line.", `<span class="repo-row-meta-label">path</span><strong>.github/workflows/ci.yml</strong>`, `<span class="repo-row-meta-label">line</span><strong>12</strong>`, `https://github.com/acme/api/pull/41`}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			viewerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			assert.Equal(t, http.StatusOK, rec.Code)
			for _, want := range tt.want {
				assert.Contains(t, rec.Body.String(), want)
			}
		})
	}
}

func TestSourceActionsViewerAppliesFilters(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		assert.Equal(t, "alice", query.Get("actor"))
		assert.Equal(t, "main", query.Get("branch"))
		assert.Equal(t, ">=2026-06-01", query.Get("created"))
		assert.Equal(t, "schedule", query.Get("event"))
		assert.Equal(t, "success", query.Get("status"))
		fmt.Fprint(w, `{"workflow_runs":[]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions", h.handleSourceActionsViewer)

	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/actions?actor=alice&branch=main&created=%3E%3D2026-06-01&event=schedule&status=success", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `value="alice"`)
	assert.Contains(t, body, `value="main"`)
	assert.Contains(t, body, `value="&gt;=2026-06-01"`)
	assert.Contains(t, body, `value="schedule"`)
	assert.Contains(t, body, `<option value="success" selected>success</option>`)
}

func TestSourceActionRunAndJobLogViewers(t *testing.T) {
	mux := http.NewServeMux()
	var logCalls int
	var downloadBase string
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runs/{run_id}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":123,"name":"CI","display_title":"build main","status":"completed","conclusion":"failure","html_url":"https://github.com/acme/api/actions/runs/123"}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jobs":[{"id":456,"name":"build","status":"completed","conclusion":"failure","html_url":"https://github.com/acme/api/actions/runs/123/job/456","labels":["self-hosted","linux"],"steps":[{"name":"checkout","status":"completed","conclusion":"success","number":1},{"name":"test","status":"completed","conclusion":"failure","number":2}]}]}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, downloadBase+"/download/job.log", http.StatusFound)
	})
	mux.HandleFunc("GET /download/job.log", func(w http.ResponseWriter, r *http.Request) {
		logCalls++
		fmt.Fprint(w, "ok\n::warning::heads up\n::error::failed\nmasked ***\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	downloadBase = srv.URL

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions/runs/{run_id}", h.handleSourceActionRunViewer)
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions/runs/{run_id}/jobs/{job_id}/logs", h.handleSourceActionJobLogViewer)

	runRec := httptest.NewRecorder()
	viewerMux.ServeHTTP(runRec, httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/actions/runs/123", nil))
	assert.Equal(t, http.StatusOK, runRec.Code)
	runBody := runRec.Body.String()
	assert.Contains(t, runBody, "Workflow run")
	assert.Contains(t, runBody, "build")
	assert.Contains(t, runBody, `<a class="button" href="https://github.com/acme/api/actions/runs/123">View on GitHub</a>`)
	assert.Contains(t, runBody, `<span>build main</span>`)
	assert.NotContains(t, runBody, `<a href="/viewer/github.com/acme/api/actions/runs/123">build main</a>`)
	assert.Contains(t, runBody, "/viewer/github.com/acme/api/actions/runs/123/jobs/456/logs")

	logRec := httptest.NewRecorder()
	viewerMux.ServeHTTP(logRec, httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/actions/runs/123/jobs/456/logs", nil))
	assert.Equal(t, http.StatusOK, logRec.Code)
	body := logRec.Body.String()
	assert.Contains(t, body, "Workflow logs may contain sensitive data")
	assert.Contains(t, body, "::warning::heads up")
	assert.Contains(t, body, "::error::failed")
	assert.Contains(t, body, "masked ***")
	assert.Contains(t, body, `class="source-layout"`)
	assert.NotContains(t, body, "source-layout-sidebar")
	assert.Equal(t, 1, logCalls)
}

func TestSourceRepoSectionViewerExplainsPermissionFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}/actions", h.handleSourceActionsViewer)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/viewer/github.com/acme/api/actions", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Actions unavailable")
	assert.Contains(t, body, "active token cannot read")
	assert.Contains(t, body, `class="notice-action"`)
	assert.Contains(t, body, "current token or repository permissions")
}

func TestSourceViewerExplainsKnownPrivateRepoNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer ghs_expired", r.Header.Get("Authorization"))
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = sourceTestGitHubClientFactory(t, srv.URL)
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(nil, nil)
	repo := pantry.NewRepository("whooli", "cost-optimized-github-runner", "github")
	repo.SetProperty("private", true)
	repo.SetProperty("discovered_by", "loot:APP_TOKEN_whooli")
	require.NoError(t, h.Pantry().AddAsset(repo))
	h.sourceTokens.put([]string{"operator"}, "ghs_expired", "loot:APP_TOKEN_whooli", time.Now().UTC())

	viewerMux := http.NewServeMux()
	viewerMux.HandleFunc("GET /viewer/github.com/{owner}/{repo}", h.handleSourceRepositoryViewer)
	rec := httptest.NewRecorder()
	viewerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/viewer/github.com/whooli/cost-optimized-github-runner", nil))

	assert.Equal(t, http.StatusNotFound, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Private repository not visible to the active token.")
	assert.Contains(t, body, `<div class="error-action">Re-pivot or register a fresh token with read access to whooli/cost-optimized-github-runner.</div>`)
	assert.Contains(t, body, "Known private repo in graph.")
	assert.Contains(t, body, "GitHub returns 404 for private repositories the token cannot see.")
	assert.Contains(t, body, "Active token source: loot:APP_TOKEN_whooli.")
	assert.Contains(t, body, "exchange the app credentials again and select the fresh installation token")
	assert.Contains(t, body, "Graph metadata says this repo was discovered via loot:APP_TOKEN_whooli.")
	assert.NotContains(t, body, "GET https://api.github.com")
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
