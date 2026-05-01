// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func swapGitHubClientTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := newGitHubClientFunc
	newGitHubClientFunc = func(token string) *gitHubClient {
		client := github.NewClient(&http.Client{Transport: rt})
		return &gitHubClient{client: client, token: token, graphqlURL: "https://api.github.com/graphql"}
	}
	t.Cleanup(func() {
		newGitHubClientFunc = orig
	})
}

func TestDeployPreflightCacheKeyIncludesEvidence(t *testing.T) {
	base := DeployPreflightRequest{
		Token:      "github_pat_test",
		TokenType:  "fine_grained_pat",
		TokenOwner: "vikorium",
		Scopes:     []string{"repo"},
		Vuln: VulnerabilityInfo{
			Repository: "acme/api",
			Workflow:   "ci.yml",
			Context:    "pr_body",
		},
	}

	contextChanged := base
	contextChanged.Vuln.Context = "issue_body"
	assert.NotEqual(t, deployPreflightCacheKey(base), deployPreflightCacheKey(contextChanged))

	permsChanged := base
	permsChanged.KnownPermissions = map[string]string{"issues": "write"}
	assert.NotEqual(t, deployPreflightCacheKey(base), deployPreflightCacheKey(permsChanged))
}

func TestMergeObservedCapabilities_RecomputesCommentAny(t *testing.T) {
	cache := newDeployPreflightCache()
	cache.putObserved(observedCapabilityCacheKey("github_pat_test", "acme/api", deployCapabilityCommentIssue), deployStateConfirmed, "", nowForTest())

	merged := mergeObservedCapabilities(DeployPreflightRequest{
		Token: "github_pat_test",
		Vuln: VulnerabilityInfo{
			Repository: "acme/api",
		},
	}, DeployPreflightResponse{
		Capabilities: map[string]DeployPreflightCapability{
			deployCapabilityCommentAny:   {State: deployStateUnknown, Reason: "Comment access could not be pre-verified"},
			deployCapabilityCommentIssue: {State: deployStateUnknown, Reason: "Comment access could not be pre-verified"},
			deployCapabilityCommentPR:    {State: deployStateFail, Reason: "pull requests are disabled on this repository"},
			deployCapabilityCommentStub:  {State: deployStateFail, Reason: "pull requests are disabled on this repository"},
		},
	}, cache, nowForTest())

	assert.Equal(t, deployStateConfirmed, merged.Capabilities[deployCapabilityCommentIssue].State)
	assert.Equal(t, deployStateConfirmed, merged.Capabilities[deployCapabilityCommentAny].State)
}

func TestHandleGitHubDeployPreflight_UsesCacheAndObservedEvidence(t *testing.T) {
	var mu sync.Mutex
	var repoGets int
	var graphqlCalls int

	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			repoGets++
			return jsonResponse(http.StatusOK, `{"private":false,"default_branch":"main","allow_forking":true,"has_issues":true,"has_pull_requests":true}`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			graphqlCalls++
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch {
			case strings.Contains(string(body), "RepoFlags"):
				return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
			default:
				return jsonResponse(http.StatusOK, `{"data":{}}`), nil
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	h, mux := newGitHubTestHandler()

	body := `{"token":"github_pat_test","token_type":"fine_grained_pat","token_owner":"vikorium","vuln":{"repository":"acme/api","context":"issue_comment"}}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var first DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&first))
	assert.False(t, first.CacheHit)
	assert.Equal(t, deployStateUnknown, first.Capabilities[deployCapabilityCommentAny].State)

	req = httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var second DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&second))
	assert.True(t, second.CacheHit)

	mu.Lock()
	assert.Equal(t, 1, repoGets)
	assert.Equal(t, 1, graphqlCalls)
	mu.Unlock()

	h.recordObservedCapability("github_pat_test", "acme/api", deployCapabilityCommentIssue, nil)

	req = httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var observed DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&observed))
	assert.True(t, observed.CacheHit)
	assert.Equal(t, deployStateConfirmed, observed.Capabilities[deployCapabilityCommentIssue].State)
	assert.Equal(t, deployStateConfirmed, observed.Capabilities[deployCapabilityCommentAny].State)
}

func TestHandleGitHubDeployPreflight_RepoAccessFailureReturnsStructuredResult(t *testing.T) {
	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/private":
			return jsonResponse(http.StatusNotFound, `{"message":"Not Found"}`), nil
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	_, mux := newGitHubTestHandler()
	body := `{"token":"github_pat_test","token_type":"fine_grained_pat","vuln":{"repository":"acme/private","workflow":"ci.yml","context":"pr_body"}}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Checks, 1)
	assert.Equal(t, "repo_access", resp.Checks[0].Name)
	assert.Equal(t, deployStateFail, resp.Checks[0].State)
	assert.Equal(t, deployStateFail, resp.Capabilities[deployCapabilityIssue].State)
	assert.Equal(t, deployStateFail, resp.Capabilities[deployCapabilityPR].State)
	assert.Equal(t, deployStateFail, resp.Capabilities[deployCapabilityDispatch].State)
}

func TestHandleGitHubDeployPreflight_CommentTriggerIssuePathRequiresIssueWrite(t *testing.T) {
	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			return jsonResponse(http.StatusOK, `{"private":true,"default_branch":"main","allow_forking":true,"has_issues":true,"has_pull_requests":true}`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch {
			case strings.Contains(string(body), "RepoFlags"):
				return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
			default:
				return jsonResponse(http.StatusOK, `{"data":{}}`), nil
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	_, mux := newGitHubTestHandler()
	body := `{
		"token":"ghs_app_token",
		"token_type":"install_app",
		"known_permissions":{"pull_requests":"write"},
		"vuln":{"repository":"acme/api","context":"issue_comment"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, deployStateFail, resp.Capabilities[deployCapabilityIssue].State)
	assert.Equal(t, "token lacks issue-write permission", resp.Capabilities[deployCapabilityIssue].Reason)
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityCommentPR].State)
}

func TestHandleGitHubDeployPreflight_UsesGraphQLPullRequestAvailability(t *testing.T) {
	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			return jsonResponse(http.StatusOK, `{"private":false,"default_branch":"main","allow_forking":true,"has_issues":true}`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch {
			case strings.Contains(string(body), "RepoFlags"):
				return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
			default:
				return jsonResponse(http.StatusOK, `{"data":{}}`), nil
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	_, mux := newGitHubTestHandler()
	body := `{
		"token":"github_pat_test",
		"token_type":"fine_grained_pat",
		"token_owner":"vikorium",
		"known_permissions":{"contents":"write","pull_requests":"write"},
		"vuln":{"repository":"acme/api","context":"pr_body"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityPR].State)
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityLOTP].State)
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityCommentPR].State)
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityCommentStub].State)
}

func TestHandleGitHubDeployPreflight_NormalizesWorkflowPathForVisibilityCheck(t *testing.T) {
	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			return jsonResponse(http.StatusOK, `{"private":false,"default_branch":"main","allow_forking":true,"has_issues":true}`), nil
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/actions/workflows/analyze.yml":
			return jsonResponse(http.StatusOK, `{"id":1,"path":".github/workflows/analyze.yml","state":"active"}`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch {
			case strings.Contains(string(body), "RepoFlags"):
				return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
			default:
				return jsonResponse(http.StatusOK, `{"data":{}}`), nil
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	_, mux := newGitHubTestHandler()
	body := `{
		"token":"ghp_test",
		"token_type":"classic_pat",
		"token_owner":"vikorium",
		"scopes":["repo","workflow"],
		"vuln":{"repository":"acme/api","workflow":".github/workflows/analyze.yml","context":"workflow_dispatch_input"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityDispatch].State)
}

func TestHandleGitHubDeployPreflight_WorkflowPushRequiresRepoPushPermission(t *testing.T) {
	tests := []struct {
		name          string
		repoPush      bool
		expectedState string
		expected      string
	}{
		{
			name:          "repo push denied",
			repoPush:      false,
			expectedState: deployStateFail,
			expected:      "token lacks repository write access",
		},
		{
			name:          "repo push allowed",
			repoPush:      true,
			expectedState: deployStatePass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
					return jsonResponse(http.StatusOK, fmt.Sprintf(`{"private":false,"default_branch":"main","allow_forking":true,"has_issues":true,"permissions":{"push":%t}}`, tt.repoPush)), nil
				case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/actions/workflows/analyze.yml":
					return jsonResponse(http.StatusOK, `{"id":1,"path":".github/workflows/analyze.yml","state":"active"}`), nil
				case r.Method == http.MethodPost && r.URL.Path == "/graphql":
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					switch {
					case strings.Contains(string(body), "RepoFlags"):
						return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
					default:
						return jsonResponse(http.StatusOK, `{"data":{}}`), nil
					}
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
					return nil, nil
				}
			}))

			_, mux := newGitHubTestHandler()
			body := `{
				"token":"ghp_test",
				"token_type":"classic_pat",
				"token_owner":"vikorium",
				"scopes":["repo","workflow"],
				"vuln":{"repository":"acme/api","workflow":".github/workflows/analyze.yml","context":"workflow_dispatch_input"}
			}`
			req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
			var resp DeployPreflightResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
			capability := resp.Capabilities[deployCapabilityWorkflowPush]
			assert.Equal(t, tt.expectedState, capability.State)
			if tt.expected != "" {
				assert.Equal(t, tt.expected, capability.Reason)
			}
		})
	}
}

func TestHandleGitHubDeployPreflight_NoForkPRBlockedButStubAllowed(t *testing.T) {
	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			return jsonResponse(http.StatusOK, `{"private":true,"default_branch":"main","allow_forking":false,"has_issues":true,"has_pull_requests":true}`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch {
			case strings.Contains(string(body), "RepoFlags"):
				return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
			default:
				return jsonResponse(http.StatusOK, `{"data":{}}`), nil
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	_, mux := newGitHubTestHandler()
	body := `{
		"token":"github_pat_test",
		"token_type":"fine_grained_pat",
		"token_owner":"vikorium",
		"known_permissions":{"contents":"write","pull_requests":"write"},
		"vuln":{"repository":"acme/api","context":"issue_comment"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, deployStateFail, resp.Capabilities[deployCapabilityPR].State)
	assert.Equal(t, "forking is disabled on this repository", resp.Capabilities[deployCapabilityPR].Reason)
	assert.Equal(t, deployStateFail, resp.Capabilities[deployCapabilityLOTP].State)
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityCommentStub].State)
}

func TestHandleGitHubDeployPreflight_NoForkBlankOwnerDowngradesPRToUnknown(t *testing.T) {
	swapGitHubClientTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api":
			return jsonResponse(http.StatusOK, `{"private":true,"default_branch":"main","allow_forking":false,"has_issues":true,"has_pull_requests":true}`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			switch {
			case strings.Contains(string(body), "RepoFlags"):
				return jsonResponse(http.StatusOK, `{"data":{"repository":{"hasIssuesEnabled":true,"hasPullRequestsEnabled":true}}}`), nil
			default:
				return jsonResponse(http.StatusOK, `{"data":{}}`), nil
			}
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	}))

	_, mux := newGitHubTestHandler()
	body := `{
		"token":"github_pat_test",
		"token_type":"fine_grained_pat",
		"known_permissions":{"contents":"write","pull_requests":"write"},
		"vuln":{"repository":"acme/api","context":"issue_comment"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, deployStateUnknown, resp.Capabilities[deployCapabilityPR].State)
	assert.Equal(t, "Direct push access could not be pre-verified", resp.Capabilities[deployCapabilityPR].Reason)
	assert.Equal(t, deployStateUnknown, resp.Capabilities[deployCapabilityLOTP].State)
	assert.Equal(t, deployStatePass, resp.Capabilities[deployCapabilityCommentStub].State)
}

func TestMergeObservedCapabilities_ScopesDispatchEvidencePerWorkflow(t *testing.T) {
	cache := newDeployPreflightCache()
	cache.putObserved(observedCapabilityCacheKey("github_pat_test", "acme/api", dispatchObservedCapability("workflow-a.yml")), deployStateConfirmed, "", nowForTest())

	respA := mergeObservedCapabilities(DeployPreflightRequest{
		Token: "github_pat_test",
		Vuln: VulnerabilityInfo{
			Repository: "acme/api",
			Workflow:   ".github/workflows/workflow-a.yml",
		},
	}, DeployPreflightResponse{
		Capabilities: map[string]DeployPreflightCapability{
			deployCapabilityDispatch: {State: deployStateUnknown, Reason: "Workflow dispatch access could not be pre-verified"},
		},
	}, cache, nowForTest())
	assert.Equal(t, deployStateConfirmed, respA.Capabilities[deployCapabilityDispatch].State)

	respB := mergeObservedCapabilities(DeployPreflightRequest{
		Token: "github_pat_test",
		Vuln: VulnerabilityInfo{
			Repository: "acme/api",
			Workflow:   ".github/workflows/workflow-b.yml",
		},
	}, DeployPreflightResponse{
		Capabilities: map[string]DeployPreflightCapability{
			deployCapabilityDispatch: {State: deployStateUnknown, Reason: "Workflow dispatch access could not be pre-verified"},
		},
	}, cache, nowForTest())
	assert.Equal(t, deployStateUnknown, respB.Capabilities[deployCapabilityDispatch].State)
}

func TestMergeObservedCapabilities_PreservesExplicitCommentTargetFailures(t *testing.T) {
	tests := []struct {
		name        string
		capability  string
		observation string
		issueNumber int
		prNumber    int
		failReason  string
	}{
		{
			name:        "issue target missing",
			capability:  deployCapabilityCommentIssue,
			observation: deployCapabilityCommentIssue,
			issueNumber: 999,
			failReason:  "issue target does not exist",
		},
		{
			name:        "pr target missing",
			capability:  deployCapabilityCommentPR,
			observation: deployCapabilityCommentPR,
			prNumber:    999,
			failReason:  "pull request target does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newDeployPreflightCache()
			cache.putObserved(observedCapabilityCacheKey("github_pat_test", "acme/api", tt.observation), deployStateConfirmed, "", nowForTest())

			req := DeployPreflightRequest{
				Token:       "github_pat_test",
				IssueNumber: tt.issueNumber,
				PRNumber:    tt.prNumber,
				Vuln: VulnerabilityInfo{
					Repository: "acme/api",
				},
			}
			resp := mergeObservedCapabilities(req, DeployPreflightResponse{
				Capabilities: map[string]DeployPreflightCapability{
					deployCapabilityCommentIssue: {State: deployStateFail, Reason: map[bool]string{true: tt.failReason, false: "issues are disabled on this repository"}[tt.capability == deployCapabilityCommentIssue]},
					deployCapabilityCommentPR:    {State: deployStateFail, Reason: map[bool]string{true: tt.failReason, false: "pull requests are disabled on this repository"}[tt.capability == deployCapabilityCommentPR]},
					deployCapabilityCommentStub:  {State: deployStateFail, Reason: "pull requests are disabled on this repository"},
					deployCapabilityCommentAny:   {State: deployStateFail, Reason: tt.failReason},
				},
			}, cache, nowForTest())

			assert.Equal(t, deployStateFail, resp.Capabilities[tt.capability].State)
			assert.Equal(t, tt.failReason, resp.Capabilities[tt.capability].Reason)
		})
	}
}

func nowForTest() time.Time {
	return time.Unix(1700000000, 0)
}

func TestShouldRecordObservedDenied_RequiresGitHubHTTPStatus(t *testing.T) {
	assert.False(t, shouldRecordObservedDenied(nil))

	plainErr := fmt.Errorf("connection refused on port 403")
	assert.False(t, shouldRecordObservedDenied(plainErr), "plain error containing '403' must not trigger")

	resp401 := &http.Response{StatusCode: http.StatusUnauthorized}
	assert.True(t, shouldRecordObservedDenied(&github.ErrorResponse{Response: resp401}))

	resp403 := &http.Response{StatusCode: http.StatusForbidden}
	assert.True(t, shouldRecordObservedDenied(&github.ErrorResponse{Response: resp403}))

	resp404 := &http.Response{StatusCode: http.StatusNotFound}
	assert.False(t, shouldRecordObservedDenied(&github.ErrorResponse{Response: resp404}), "404 should not be treated as denied")
}
