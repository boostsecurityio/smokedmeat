// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build githubacceptance
// +build githubacceptance

package kitchen

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type acceptanceToken struct {
	name  string
	value string
	info  *FetchTokenInfoResponse
}

type acceptanceExpectation struct {
	capability string
	state      string
}

func TestGitHubDeployPreflightAcceptance_Poutineville(t *testing.T) {
	tokens := loadAcceptanceTokens(t)
	org := envOrDefault("GH_TEST_ORG", "poutineville")
	repos := map[string]struct {
		name     string
		workflow string
	}{
		"full_delivery_public": {
			name:     envOrDefault("GH_TEST_REPO_FULL_DELIVERY_PUBLIC", "full-delivery-public"),
			workflow: workflowForAcceptanceRepo("GH_TEST_WORKFLOW_FULL_DELIVERY_PUBLIC"),
		},
		"full_delivery_private": {
			name:     envOrDefault("GH_TEST_REPO_FULL_DELIVERY_PRIVATE", "full-delivery-private"),
			workflow: workflowForAcceptanceRepo("GH_TEST_WORKFLOW_FULL_DELIVERY_PRIVATE"),
		},
		"no_fork_private": {
			name:     envOrDefault("GH_TEST_REPO_NO_FORK_PRIVATE", "no-fork-private"),
			workflow: workflowForAcceptanceRepo("GH_TEST_WORKFLOW_NO_FORK_PRIVATE"),
		},
		"no_pr_public": {
			name:     envOrDefault("GH_TEST_REPO_NO_PR_PUBLIC", "no-pr-public"),
			workflow: workflowForAcceptanceRepo("GH_TEST_WORKFLOW_NO_PR_PUBLIC"),
		},
		"no_issues_public": {
			name:     envOrDefault("GH_TEST_REPO_NO_ISSUES_PUBLIC", "no-issues-public"),
			workflow: workflowForAcceptanceRepo("GH_TEST_WORKFLOW_NO_ISSUES_PUBLIC"),
		},
	}
	workflows := acceptanceWorkflows(t, tokens["classic"], org, repos)

	_, mux := newGitHubTestHandler()

	tests := []struct {
		name         string
		token        acceptanceToken
		repository   string
		expectations []acceptanceExpectation
	}{
		{
			name:       "classic_full_delivery_public",
			token:      tokens["classic"],
			repository: org + "/" + repos["full_delivery_public"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityIssue, state: deployStatePass},
				{capability: deployCapabilityPR, state: deployStatePass},
				{capability: deployCapabilityDispatch, state: deployStatePass},
			},
		},
		{
			name:       "classic_no_pr_public",
			token:      tokens["classic"],
			repository: org + "/" + repos["no_pr_public"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityIssue, state: deployStatePass},
				{capability: deployCapabilityPR, state: deployStateFail},
				{capability: deployCapabilityLOTP, state: deployStateFail},
				{capability: deployCapabilityCommentStub, state: deployStateFail},
			},
		},
		{
			name:       "classic_no_issues_public",
			token:      tokens["classic"],
			repository: org + "/" + repos["no_issues_public"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityIssue, state: deployStateFail},
				{capability: deployCapabilityCommentIssue, state: deployStateFail},
				{capability: deployCapabilityPR, state: deployStatePass},
				{capability: deployCapabilityDispatch, state: deployStatePass},
			},
		},
		{
			name:       "classic_no_fork_private",
			token:      tokens["classic"],
			repository: org + "/" + repos["no_fork_private"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityPR, state: deployStateFail},
				{capability: deployCapabilityLOTP, state: deployStateFail},
				{capability: deployCapabilityCommentStub, state: deployStatePass},
				{capability: deployCapabilityDispatch, state: deployStatePass},
			},
		},
		{
			name:       "fg_issues_full_delivery_private",
			token:      tokens["fg_issues"],
			repository: org + "/" + repos["full_delivery_private"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityIssue, state: deployStateUnknown},
				{capability: deployCapabilityCommentAny, state: deployStateUnknown},
				{capability: deployCapabilityPR, state: deployStateUnknown},
				{capability: deployCapabilityDispatch, state: deployStateFail},
			},
		},
		{
			name:       "fg_issues_no_fork_private",
			token:      tokens["fg_issues"],
			repository: org + "/" + repos["no_fork_private"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityPR, state: deployStateFail},
				{capability: deployCapabilityLOTP, state: deployStateFail},
				{capability: deployCapabilityCommentStub, state: deployStateUnknown},
				{capability: deployCapabilityDispatch, state: deployStateFail},
			},
		},
		{
			name:       "fg_full_full_delivery_private",
			token:      tokens["fg_full"],
			repository: org + "/" + repos["full_delivery_private"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityIssue, state: deployStateUnknown},
				{capability: deployCapabilityPR, state: deployStateUnknown},
				{capability: deployCapabilityCommentAny, state: deployStateUnknown},
				{capability: deployCapabilityDispatch, state: deployStateUnknown},
			},
		},
		{
			name:       "fg_full_no_fork_private",
			token:      tokens["fg_full"],
			repository: org + "/" + repos["no_fork_private"].name,
			expectations: []acceptanceExpectation{
				{capability: deployCapabilityPR, state: deployStateFail},
				{capability: deployCapabilityLOTP, state: deployStateFail},
				{capability: deployCapabilityCommentStub, state: deployStateUnknown},
				{capability: deployCapabilityDispatch, state: deployStateUnknown},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := DeployPreflightRequest{
				Token:      tt.token.value,
				TokenType:  tt.token.info.TokenType,
				TokenOwner: tt.token.info.Owner,
				Scopes:     append([]string(nil), tt.token.info.Scopes...),
				Vuln: VulnerabilityInfo{
					Repository: tt.repository,
					Workflow:   workflows[tt.repository],
					Context:    "issue_comment",
				},
			}

			resp := runAcceptancePreflight(t, mux, req)
			for _, expectation := range tt.expectations {
				got := resp.Capabilities[expectation.capability]
				assert.Equalf(t, expectation.state, got.State, "capability=%s reason=%s", expectation.capability, got.Reason)
			}
		})
	}
}

func runAcceptancePreflight(t *testing.T, mux *http.ServeMux, req DeployPreflightRequest) DeployPreflightResponse {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/github/deploy/preflight", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	var resp DeployPreflightResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return resp
}

func loadAcceptanceTokens(t *testing.T) map[string]acceptanceToken {
	t.Helper()
	values := map[string]string{
		"classic":   strings.TrimSpace(os.Getenv("GH_TOKEN_CLASSIC")),
		"fg_issues": strings.TrimSpace(os.Getenv("GH_TOKEN_FG_ISSUES")),
		"fg_full":   strings.TrimSpace(os.Getenv("GH_TOKEN_FG_FULL")),
	}
	for name, value := range values {
		if value == "" {
			t.Skipf("missing acceptance token env %s", envNameForAcceptanceToken(name))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokens := make(map[string]acceptanceToken, len(values))
	for name, value := range values {
		info, err := fetchTokenInfoRaw(ctx, value)
		require.NoError(t, err)
		tokens[name] = acceptanceToken{
			name:  name,
			value: value,
			info:  info,
		}
	}
	return tokens
}

func envNameForAcceptanceToken(name string) string {
	switch name {
	case "classic":
		return "GH_TOKEN_CLASSIC"
	case "fg_issues":
		return "GH_TOKEN_FG_ISSUES"
	default:
		return "GH_TOKEN_FG_FULL"
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func workflowForAcceptanceRepo(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func acceptanceWorkflows(t *testing.T, token acceptanceToken, org string, repos map[string]struct {
	name     string
	workflow string
}) map[string]string {
	t.Helper()
	workflows := make(map[string]string, len(repos))
	for _, repo := range repos {
		repository := org + "/" + repo.name
		if repo.workflow != "" {
			workflows[repository] = repo.workflow
			continue
		}
		workflows[repository] = discoverAcceptanceWorkflow(t, token.value, org, repo.name)
	}
	return workflows
}

func discoverAcceptanceWorkflow(t *testing.T, token, owner, repo string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := newGitHubClient(token)
	workflows, _, err := client.client.Actions.ListWorkflows(ctx, owner, repo, &github.ListOptions{PerPage: 100})
	require.NoError(t, err)

	for _, workflow := range workflows.Workflows {
		content, _, _, err := client.client.Repositories.GetContents(ctx, owner, repo, workflow.GetPath(), nil)
		if err != nil {
			continue
		}
		decoded, err := content.GetContent()
		if err != nil {
			continue
		}
		if strings.Contains(decoded, "workflow_dispatch") {
			return workflow.GetPath()
		}
	}

	var known []string
	for _, workflow := range workflows.Workflows {
		known = append(known, path.Clean(workflow.GetPath()))
	}
	t.Fatalf("no dispatchable workflow found in %s/%s, workflows=%v", owner, repo, known)
	return ""
}
