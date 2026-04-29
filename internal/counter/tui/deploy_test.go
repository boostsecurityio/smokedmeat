// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func createTestPantry() *pantry.Pantry {
	p := pantry.New()
	p.AddAsset(pantry.Asset{
		ID:   "repo:test/repo",
		Name: "test/repo",
		Type: pantry.AssetRepository,
	})
	return p
}

func newModelWithMockClient(mock *mockKitchenClient) Model {
	m := NewModel(Config{SessionID: "test", KitchenURL: "http://localhost:8080"})
	m.kitchenClient = mock
	return m
}

func TestParseDeploymentError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"nil error", nil, ""},
		{"preflight 404", errors.New("preflight: GET 404 Not Found"), "Workflow not found"},
		{"preflight 403", errors.New("preflight: GET 403 Forbidden"), "Token cannot access repository actions"},
		{"preflight other", errors.New("preflight: connection refused"), "preflight:"},
		{"403 actions post-preflight", errors.New("403 actions workflow dispatch"), "actions:read but lacks actions:write"},
		{"403 workflow post-preflight", errors.New("403 workflow dispatch denied"), "actions:read but lacks actions:write"},
		{"410 Gone", errors.New("410 Gone"), "Issues are disabled"},
		{"403 workflow file commit", errors.New("failed to commit .github/workflows/smokedmeat-self-hosted.yml: PUT https://api.github.com/repos/acme/api/contents/.github/workflows/smokedmeat-self-hosted.yml: 403 Resource not accessible by integration []"), "workflow-file write"},
		{"403 Resource not accessible", errors.New("403 Resource not accessible by integration"), "effective Contents: write and Pull requests: write"},
		{"403 must have admin", errors.New("403 must have admin access"), "admin access"},
		{"403 generic", errors.New("403 Forbidden"), "Classic token needs"},
		{"404 Not Found", errors.New("404 Not Found"), "not found or not accessible"},
		{"422 transient issue comment", errors.New("422 Validation Failed Could not resolve to a node with the global id of 'I_kwDOQ-jpaM72Na2a'"), "not ready to accept a comment"},
		{"422 head sha blank", errors.New("422 head sha can't be blank"), "Fork not ready"},
		{"422 generic", errors.New("422 something else"), "forbidden characters"},
		{"rate limit text", errors.New("rate limit exceeded"), "rate limit"},
		{"rate_limit underscore", errors.New("rate_limit"), "rate limit"},
		{"token not set", errors.New("token not set"), "No token configured"},
		{"unknown passthrough", errors.New("something unknown"), "something unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDeploymentError(tt.err)
			if tt.err == nil {
				assert.Equal(t, "", result)
			} else {
				assert.Contains(t, result, tt.contains)
			}
		})
	}
}

func TestMaskCommandToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"long token masked", "set token ghp_1234567890abcdef", "set token ghp_…cdef"},
		{"short token unchanged", "set token short", "set token short"},
		{"exactly 8 chars unchanged", "set token 12345678", "set token 12345678"},
		{"9 chars masked", "set token 123456789", "set token 1234…6789"},
		{"non-token command unchanged", "set target foo/bar", "set target foo/bar"},
		{"unrelated command unchanged", "deploy now", "deploy now"},
		{"missing token value unchanged", "set token", "set token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, maskCommandToken(tt.input))
		})
	}
}

func TestModel_Update_CommentDeploymentSuccess(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(CommentDeploymentSuccessMsg{
		StagerID:   "stager-comment-1",
		CommentURL: "https://github.com/org/repo/issues/5#issuecomment-123",
		Vuln: &Vulnerability{
			ID:         "V010",
			Repository: "org/repo",
		},
		DwellTime: 30 * time.Second,
	})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Equal(t, "stager-comment-1", model.waiting.StagerID)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "success", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Comment created")
	assert.NotNil(t, cmd)
}

func TestModel_Update_CommentDeploymentFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(CommentDeploymentFailedMsg{
		StagerID: "stager-comment-fail",
		Err:      errors.New("403 Resource not accessible"),
	})

	model := result.(Model)
	require.Len(t, model.output, 2)
	assert.Equal(t, "error", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "Comment deployment failed")
	assert.Equal(t, "hint", model.output[1].Type)
	assert.NotNil(t, cmd)
}

func TestModel_Update_AutoDispatchSuccess(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(AutoDispatchSuccessMsg{
		StagerID:  "stager-dispatch-1",
		InputName: "payload_url",
		Vuln: &Vulnerability{
			ID:         "V020",
			Repository: "org/repo",
		},
		DwellTime: 60 * time.Second,
	})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Equal(t, "stager-dispatch-1", model.waiting.StagerID)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "success", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "dispatch")
	assert.NotNil(t, cmd)
}

func TestModel_Update_AutoDispatchFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(AutoDispatchFailedMsg{
		StagerID: "stager-dispatch-fail",
		Err:      errors.New("workflow not found"),
	})

	model := result.(Model)
	require.Len(t, model.output, 1)
	assert.Equal(t, "error", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "workflow_dispatch failed")
	assert.NotNil(t, cmd)
}

func TestRegisterStagerWithMeta_Success(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackResp: &counter.RegisterCallbackResponse{},
	}
	m := newModelWithMockClient(mock)
	m.config.SessionID = "sess-1"
	meta := map[string]string{"repository": "acme/api", "workflow": "ci.yml", "job": "build"}
	err := m.registerStagerWithMeta("stg-abc", 0, 1, meta)

	require.NoError(t, err)
	assert.Equal(t, "stg-abc", mock.lastRegisterCallbackID)
	assert.Equal(t, "bash", mock.lastRegisterCallbackReq.ResponseType)
	assert.Equal(t, "sess-1", mock.lastRegisterCallbackReq.SessionID)
	assert.Equal(t, "", mock.lastRegisterCallbackReq.DwellTime)
	assert.Equal(t, 1, mock.lastRegisterCallbackReq.MaxCallbacks)
	assert.Equal(t, "acme/api", mock.lastRegisterCallbackReq.Metadata["repository"])
}

func TestRegisterStagerWithMeta_WithDwell(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackResp: &counter.RegisterCallbackResponse{},
	}
	m := newModelWithMockClient(mock)
	m.config.SessionID = "sess-1"
	err := m.registerStagerWithMeta("stg-dwell", 30*time.Second, 3, nil)

	require.NoError(t, err)
	assert.Equal(t, "30s", mock.lastRegisterCallbackReq.DwellTime)
	assert.Equal(t, 3, mock.lastRegisterCallbackReq.MaxCallbacks)
}

func TestRegisterStagerWithMeta_ServerError(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackErr: fmt.Errorf("unexpected status: 500"),
	}
	m := newModelWithMockClient(mock)
	m.config.SessionID = "sess-1"
	err := m.registerStagerWithMeta("stg-err", 0, 1, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status: 500")
}

func TestRegisterStagerWithMeta_PersistentMode(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackResp: &counter.RegisterCallbackResponse{
			Callback: &counter.CallbackPayload{ID: "cb-1", Persistent: true, DefaultMode: "express"},
		},
	}
	m := newModelWithMockClient(mock)
	m.config.SessionID = "sess-1"
	callback, err := m.registerPersistentCallback("stg-auth", "payload", 0, map[string]string{"repository": "acme/api"})

	require.NoError(t, err)
	require.NotNil(t, callback)
	assert.Equal(t, "stg-auth", mock.lastRegisterCallbackID)
	assert.True(t, mock.lastRegisterCallbackReq.Persistent)
	assert.Equal(t, 0, mock.lastRegisterCallbackReq.MaxCallbacks)
	assert.Equal(t, "express", mock.lastRegisterCallbackReq.DefaultMode)
	assert.Equal(t, "payload", mock.lastRegisterCallbackReq.Payload)
	assert.Equal(t, "acme/api", mock.lastRegisterCallbackReq.Metadata["repository"])
}

func TestDeployAutoPR_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployPRResp: counter.DeployPRResponse{PRURL: "https://github.com/acme/api/pull/1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT}
	vuln := &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body", ID: "V001"}

	cmd := m.deployAutoPR(vuln, "stg-1", "payload", 0, nil, nil)
	msg := cmd()

	success, ok := msg.(AutoPRDeploymentSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "stg-1", success.StagerID)
	assert.Contains(t, success.PRURL, "github.com/acme/api/pull")
}

func TestDeployAutoPR_Error(t *testing.T) {
	mock := &mockKitchenClient{
		deployPRErr: fmt.Errorf("fork failed"),
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", ID: "V001"}

	cmd := m.deployAutoPR(vuln, "stg-2", "payload", 0, nil, nil)
	msg := cmd()

	fail, ok := msg.(AutoPRDeploymentFailedMsg)
	require.True(t, ok)
	assert.Equal(t, "stg-2", fail.StagerID)
	assert.Contains(t, fail.Err.Error(), "fork failed")
}

func TestDeployAutoPR_NilToken(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelWithMockClient(mock)
	vuln := &Vulnerability{Repository: "acme/api"}

	cmd := m.deployAutoPR(vuln, "stg-3", "payload", 0, nil, nil)
	msg := cmd()

	fail, ok := msg.(AutoPRDeploymentFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "token not set")
}

func TestDeployAutoPR_PassesStagerIDAndDraft(t *testing.T) {
	mock := &mockKitchenClient{
		deployPRResp: counter.DeployPRResponse{PRURL: "https://github.com/acme/api/pull/1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT}
	vuln := &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body", ID: "V001"}

	draft := boolPtr(false)
	autoClose := boolPtr(true)
	cmd := m.deployAutoPR(vuln, "stg-draft", "payload", 0, draft, autoClose)
	msg := cmd()

	_, ok := msg.(AutoPRDeploymentSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "stg-draft", mock.lastDeployPRReq.StagerID)
	require.NotNil(t, mock.lastDeployPRReq.Draft)
	assert.False(t, *mock.lastDeployPRReq.Draft)
	require.NotNil(t, mock.lastDeployPRReq.AutoClose)
	assert.True(t, *mock.lastDeployPRReq.AutoClose)
}

func TestDeployIssue_PassesStagerIDAndAutoClose(t *testing.T) {
	mock := &mockKitchenClient{
		deployIssueResp: counter.DeployIssueResponse{IssueURL: "https://github.com/acme/api/issues/1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_body", ID: "V001"}

	autoClose := boolPtr(false)
	cmd := m.deployIssue(vuln, "stg-ac", "payload", 0, autoClose)
	msg := cmd()

	_, ok := msg.(IssueDeploymentSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "stg-ac", mock.lastDeployIssueReq.StagerID)
	require.NotNil(t, mock.lastDeployIssueReq.AutoClose)
	assert.False(t, *mock.lastDeployIssueReq.AutoClose)
}

func TestDeployIssue_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployIssueResp: counter.DeployIssueResponse{IssueURL: "https://github.com/acme/api/issues/1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_body", ID: "V001"}

	cmd := m.deployIssue(vuln, "stg-4", "payload", 0, nil)
	msg := cmd()

	success, ok := msg.(IssueDeploymentSuccessMsg)
	require.True(t, ok)
	assert.Contains(t, success.IssueURL, "github.com/acme/api/issues")
}

func TestDeployIssue_Error(t *testing.T) {
	mock := &mockKitchenClient{
		deployIssueErr: fmt.Errorf("403 Forbidden"),
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", ID: "V001"}

	cmd := m.deployIssue(vuln, "stg-5", "payload", 0, nil)
	msg := cmd()

	fail, ok := msg.(IssueDeploymentFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "403")
}

func TestDeployComment_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployCommentResp: counter.DeployCommentResponse{CommentURL: "https://github.com/acme/api/issues/5#issuecomment-1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", ID: "V001"}

	cmd := m.deployComment(vuln, "stg-6", "payload", 5, 0, CommentTargetPullRequest, boolPtr(true))
	msg := cmd()

	success, ok := msg.(CommentDeploymentSuccessMsg)
	require.True(t, ok)
	assert.Contains(t, success.CommentURL, "issues/5")
	assert.Equal(t, "pull_request", mock.lastDeployCommentReq.Target)
	require.NotNil(t, mock.lastDeployCommentReq.AutoClose)
	assert.True(t, *mock.lastDeployCommentReq.AutoClose)
}

func TestDeployComment_Error(t *testing.T) {
	mock := &mockKitchenClient{
		deployCommentErr: fmt.Errorf("issue not found"),
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", ID: "V001"}

	cmd := m.deployComment(vuln, "stg-7", "payload", 0, 0, CommentTargetIssue, nil)
	msg := cmd()

	fail, ok := msg.(CommentDeploymentFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "issue not found")
}

func TestDeployLOTP_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployLOTPResp: counter.DeployLOTPResponse{PRURL: "https://github.com/acme/api/pull/2"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{
		Repository:   "acme/api",
		Workflow:     ".github/workflows/ci.yml",
		Context:      "untrusted_checkout",
		LOTPTool:     "bash",
		ID:           "V001",
		GateTriggers: []string{"gravy"},
		GateRaw:      "contains(github.event.pull_request.title, 'gravy')",
	}

	cmd := m.deployLOTP(vuln, "stg-8", 0)
	msg := cmd()

	success, ok := msg.(LOTPDeploymentSuccessMsg)
	require.True(t, ok)
	assert.Contains(t, success.PRURL, "github.com/acme/api/pull")
	assert.Equal(t, "acme/api", mock.lastDeployLOTPReq.Vuln.Repository)
	assert.Equal(t, ".github/workflows/ci.yml", mock.lastDeployLOTPReq.Vuln.Workflow)
	assert.Equal(t, []string{"gravy"}, mock.lastDeployLOTPReq.Vuln.GateTriggers)
	assert.Equal(t, "contains(github.event.pull_request.title, 'gravy')", mock.lastDeployLOTPReq.Vuln.GateRaw)
}

func TestDeployLOTP_Error(t *testing.T) {
	mock := &mockKitchenClient{
		deployLOTPErr: fmt.Errorf("branch creation failed"),
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{Repository: "acme/api", LOTPTool: "bash", ID: "V001"}

	cmd := m.deployLOTP(vuln, "stg-9", 0)
	msg := cmd()

	fail, ok := msg.(LOTPDeploymentFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "branch creation failed")
}

func TestDeployAutoDispatch_Success(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelWithMockClient(mock)
	vuln := &Vulnerability{Repository: "acme/api", Workflow: ".github/workflows/ci.yml", ID: "V001"}
	token := &CollectedSecret{Value: "ghs_ephemeral", Name: "GITHUB_TOKEN"}

	cmd := m.deployAutoDispatch(vuln, "stg-10", "payload", token, "command", 0)
	msg := cmd()

	success, ok := msg.(AutoDispatchSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "stg-10", success.StagerID)
	assert.Equal(t, "command", success.InputName)
}

func TestDeployAutoDispatch_WithoutInputs(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelWithMockClient(mock)
	vuln := &Vulnerability{Repository: "acme/api", Workflow: ".github/workflows/deploy.yml", ID: "V011"}
	token := &CollectedSecret{Value: "ghs_ephemeral", Name: "GITHUB_TOKEN"}

	cmd := m.deployAutoDispatch(vuln, "", "", token, "", 0)
	msg := cmd()

	success, ok := msg.(AutoDispatchSuccessMsg)
	require.True(t, ok)
	assert.Empty(t, success.StagerID)
	assert.Empty(t, success.InputName)
	assert.Nil(t, mock.lastTriggerDispatchReq.Inputs)
}

func TestDeployAutoDispatch_Error(t *testing.T) {
	mock := &mockKitchenClient{
		triggerDispatchErr: fmt.Errorf("workflow not found"),
	}
	m := newModelWithMockClient(mock)
	vuln := &Vulnerability{Repository: "acme/api", Workflow: ".github/workflows/ci.yml", ID: "V001"}
	token := &CollectedSecret{Value: "ghs_ephemeral"}

	cmd := m.deployAutoDispatch(vuln, "stg-11", "payload", token, "command", 0)
	msg := cmd()

	fail, ok := msg.(AutoDispatchFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "workflow not found")
}

func TestDeployAutoDispatch_NilToken(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelWithMockClient(mock)
	vuln := &Vulnerability{Repository: "acme/api", Workflow: ".github/workflows/ci.yml"}

	cmd := m.deployAutoDispatch(vuln, "stg-12", "payload", nil, "command", 0)
	msg := cmd()

	fail, ok := msg.(AutoDispatchFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "no ephemeral token")
}

func TestDeployAutoDispatch_InvalidRepo(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelWithMockClient(mock)
	vuln := &Vulnerability{Repository: "noslash", Workflow: ".github/workflows/ci.yml"}
	token := &CollectedSecret{Value: "ghs_ephemeral"}

	cmd := m.deployAutoDispatch(vuln, "stg-13", "payload", token, "command", 0)
	msg := cmd()

	fail, ok := msg.(AutoDispatchFailedMsg)
	require.True(t, ok)
	assert.Contains(t, fail.Err.Error(), "invalid repository format")
}

func TestIsCommentInjection(t *testing.T) {
	tests := []struct {
		name   string
		vuln   *Vulnerability
		expect bool
	}{
		{"comment.body source", &Vulnerability{InjectionSources: []string{"comment.body"}}, true},
		{"issue_comment source", &Vulnerability{InjectionSources: []string{"issue_comment.body"}}, true},
		{"mixed sources with comment", &Vulnerability{InjectionSources: []string{"issue.title", "comment.body"}}, true},
		{"issue_body only", &Vulnerability{InjectionSources: []string{"issue.body"}}, false},
		{"pr_body only", &Vulnerability{InjectionSources: []string{"pull_request.body"}}, false},
		{"empty sources", &Vulnerability{InjectionSources: nil}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, isCommentInjection(tt.vuln))
		})
	}
}

func TestDeployIssue_CommentMode_SetForCommentVuln(t *testing.T) {
	mock := &mockKitchenClient{
		deployIssueResp: counter.DeployIssueResponse{IssueURL: "https://github.com/acme/api/issues/1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{
		Repository:       "acme/api",
		Workflow:         "ci.yml",
		Context:          "comment.body",
		ID:               "V001",
		InjectionSources: []string{"comment.body"},
	}

	cmd := m.deployIssue(vuln, "stg-cm", "payload", 0, nil)
	_ = cmd()

	assert.True(t, mock.lastDeployIssueReq.CommentMode, "CommentMode should be true for comment injection vulns")
}

func TestDeployIssue_CommentMode_NotSetForIssueVuln(t *testing.T) {
	mock := &mockKitchenClient{
		deployIssueResp: counter.DeployIssueResponse{IssueURL: "https://github.com/acme/api/issues/1"},
	}
	m := newModelWithMockClient(mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	vuln := &Vulnerability{
		Repository:       "acme/api",
		Workflow:         "ci.yml",
		Context:          "issue_body",
		ID:               "V001",
		InjectionSources: []string{"issue.body"},
	}

	cmd := m.deployIssue(vuln, "stg-nm", "payload", 0, nil)
	_ = cmd()

	assert.False(t, mock.lastDeployIssueReq.CommentMode, "CommentMode should be false for non-comment vulns")
}
