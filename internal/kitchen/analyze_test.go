// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/bashctx"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

// =============================================================================
// Analyze Endpoint Tests (POST /analyze)
// =============================================================================

func TestHandler_Analyze_MissingToken(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	body := `{"target": "acme/repo", "target_type": "repo"}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "token is required")
}

func TestHandler_Analyze_MissingTarget(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	body := `{"token": "ghp_xxx", "target_type": "repo"}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "target is required")
}

func TestHandler_Analyze_InvalidTargetType(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	body := `{"token": "ghp_xxx", "target": "acme/repo", "target_type": "invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "target_type must be 'org' or 'repo'")
}

func TestHandler_Analyze_InvalidAnalysisID(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	body := `{"token":"ghp_xxx","target":"acme/repo","target_type":"repo","session_id":"sess-1","analysis_id":"analysis 123"}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "analysis_id contains invalid characters")
}

func TestHandler_Analyze_AnalysisIDRequiresSessionID(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	body := `{"token":"ghp_xxx","target":"acme/repo","target_type":"repo","analysis_id":"analysis_123"}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "session_id is required when analysis_id is provided")
}

func TestHandler_Analyze_InvalidJSON(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	body := `{invalid json}`
	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid request body")
}

func TestHandler_Analyze_EmptyBody(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	req := httptest.NewRequest(http.MethodPost, "/analyze", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAnalyzeRequest_Structure(t *testing.T) {
	// Test request marshaling/unmarshaling
	reqData := `{"token":"ghp_test","target":"acme/repo","target_type":"repo"}`

	var req AnalyzeRequest
	err := json.Unmarshal([]byte(reqData), &req)
	assert.NoError(t, err)
	assert.Equal(t, "ghp_test", req.Token)
	assert.Equal(t, "acme/repo", req.Target)
	assert.Equal(t, "repo", req.TargetType)
}

func TestAnalysisRequestTimeout(t *testing.T) {
	tests := []struct {
		name       string
		targetType string
		deep       bool
		want       time.Duration
	}{
		{name: "repo", targetType: "repo", deep: false, want: 20 * time.Minute},
		{name: "org", targetType: "org", deep: false, want: 60 * time.Minute},
		{name: "deep repo", targetType: "repo", deep: true, want: 30 * time.Minute},
		{name: "deep org", targetType: "org", deep: true, want: 90 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, analysisRequestTimeout(tt.targetType, tt.deep))
		})
	}
}

func TestCollectScanTargets_UsesAnalyzedReposForOrg(t *testing.T) {
	repos := collectScanTargets(AnalyzeRequest{Target: "acme", TargetType: "org"}, &poutine.AnalysisResult{
		AnalyzedRepos: []string{"acme/newcleus-core-v3", "acme/worker"},
		Findings: []poutine.Finding{
			{Repository: "acme/newcleus-core-v3"},
		},
	})

	assert.Equal(t, []string{"acme/newcleus-core-v3", "acme/worker"}, repos)
}

func TestHandler_PersistAnalysisLoot(t *testing.T) {
	mock := &mockPublisher{}
	h, _ := newTestHandler(mock, nil)

	database, err := db.Open(db.Config{Path: filepath.Join(t.TempDir(), "analysis-loot.db")})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, database.Close())
	})
	h.SetDatabase(database)

	err = h.persistAnalysisLoot(AnalyzeRequest{SessionID: "sess-1"}, &poutine.AnalysisResult{
		SecretFindings: []poutine.SecretFinding{
			{
				RuleID:      "private-key",
				Description: "Private Key detected",
				Repository:  "acme/newcleus-core-v3",
				File:        "README.md",
				StartLine:   12,
				Secret:      "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			},
		},
	})
	require.NoError(t, err)

	rows, err := db.NewLootRepository(database).List()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, db.LootOriginAnalysis, rows[0].Origin)
	assert.Equal(t, "sess-1", rows[0].SessionID)
	assert.Equal(t, "Private Key detected (README.md:12)", rows[0].Name)
	assert.Equal(t, "private_key", rows[0].Type)
	assert.Equal(t, "acme/newcleus-core-v3:README.md:12", rows[0].Source)
	assert.Equal(t, "acme/newcleus-core-v3", rows[0].Repository)
	assert.Empty(t, rows[0].Workflow)
}

func TestHandler_GetAnalyzeResult_ReturnsStatuses(t *testing.T) {
	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)

	reqInfo := AnalyzeRequest{
		AnalysisID: "analysis_123",
		SessionID:  "sess-1",
		Target:     "acme",
		TargetType: "org",
	}

	h.recordAnalysisPending(reqInfo)

	req := httptest.NewRequest(http.MethodGet, "/analyze/result/analysis_123?session_id=sess-1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var pending AnalyzeResultStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pending))
	assert.Equal(t, "analysis_123", pending.AnalysisID)
	assert.Equal(t, analysisStatusPending, pending.Status)

	h.recordAnalysisCompleted(reqInfo, &poutine.AnalysisResult{Success: true, ReposAnalyzed: 3})

	req = httptest.NewRequest(http.MethodGet, "/analyze/result/analysis_123?session_id=sess-1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var completed AnalyzeResultStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &completed))
	assert.Equal(t, analysisStatusCompleted, completed.Status)
	require.NotNil(t, completed.Result)
	assert.Equal(t, 3, completed.Result.ReposAnalyzed)

	h.recordAnalysisFailure(reqInfo, "boom")

	req = httptest.NewRequest(http.MethodGet, "/analyze/result/analysis_123?session_id=sess-1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var failed AnalyzeResultStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &failed))
	assert.Equal(t, analysisStatusFailed, failed.Status)
	assert.Equal(t, "boom", failed.Error)
}

func TestHandler_GetAnalyzeResult_HidesOtherSessions(t *testing.T) {
	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)

	h.recordAnalysisPending(AnalyzeRequest{
		AnalysisID: "analysis_123",
		SessionID:  "sess-1",
	})

	req := httptest.NewRequest(http.MethodGet, "/analyze/result/analysis_123?session_id=sess-2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var status AnalyzeResultStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	assert.Equal(t, analysisStatusUnknown, status.Status)
}

func TestHandler_GetAnalyzeResult_RequiresSessionID(t *testing.T) {
	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)

	h.recordAnalysisPending(AnalyzeRequest{
		AnalysisID: "analysis_123",
		SessionID:  "sess-1",
	})

	req := httptest.NewRequest(http.MethodGet, "/analyze/result/analysis_123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var status AnalyzeResultStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	assert.Equal(t, analysisStatusUnknown, status.Status)
}

func TestHandler_BroadcastAnalysisProgress_TargetsSession(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	hub := NewOperatorHub(nil, nil, nil)
	target := &OperatorConn{sessionID: "sess-1", send: make(chan OperatorMessage, 1), hub: hub}
	other := &OperatorConn{sessionID: "sess-2", send: make(chan OperatorMessage, 1), hub: hub}
	hub.operators[target] = true
	hub.operators[other] = true
	h.operators = hub

	startedAt := time.Now().Add(-2 * time.Second).UTC()
	h.broadcastAnalysisProgress(AnalyzeRequest{
		SessionID:  "sess-1",
		Target:     "acme",
		TargetType: "org",
		Deep:       true,
	}, startedAt, analysisPhaseSecret, "Scanning repositories for secrets", "acme/api", 1, 3, 2)

	select {
	case msg := <-target.send:
		require.NotNil(t, msg.AnalysisProgress)
		assert.Equal(t, "analysis_progress", msg.Type)
		assert.Equal(t, "sess-1", msg.AnalysisProgress.SessionID)
		assert.Equal(t, "acme", msg.AnalysisProgress.Target)
		assert.Equal(t, "org", msg.AnalysisProgress.TargetType)
		assert.True(t, msg.AnalysisProgress.Deep)
		assert.Equal(t, analysisPhaseSecret, msg.AnalysisProgress.Phase)
		assert.Equal(t, "Scanning repositories for secrets", msg.AnalysisProgress.Message)
		assert.Equal(t, "acme/api", msg.AnalysisProgress.CurrentRepo)
		assert.Equal(t, 1, msg.AnalysisProgress.ReposCompleted)
		assert.Equal(t, 3, msg.AnalysisProgress.ReposTotal)
		assert.Equal(t, 2, msg.AnalysisProgress.SecretFindings)
		assert.Equal(t, startedAt, msg.AnalysisProgress.StartedAt)
		assert.False(t, msg.AnalysisProgress.UpdatedAt.IsZero())
	case <-time.After(time.Second):
		t.Fatal("expected targeted operator session to receive analysis progress")
	}

	select {
	case msg := <-other.send:
		t.Fatalf("unexpected analysis progress for other session: %#v", msg)
	default:
	}
}

func TestHandler_BroadcastAnalysisMetadataSync_TargetsSession(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	hub := NewOperatorHub(nil, nil, nil)
	target := &OperatorConn{sessionID: "sess-1", send: make(chan OperatorMessage, 1), hub: hub}
	other := &OperatorConn{sessionID: "sess-2", send: make(chan OperatorMessage, 1), hub: hub}
	hub.operators[target] = true
	hub.operators[other] = true
	h.operators = hub

	h.broadcastAnalysisMetadataSync(AnalyzeRequest{
		AnalysisID: "analysis_123",
		SessionID:  "sess-1",
		Target:     "acme",
		TargetType: "org",
	}, analysisMetadataDone, "Repository access updated", 12, nil)

	select {
	case msg := <-target.send:
		require.NotNil(t, msg.AnalysisMetadataSync)
		assert.Equal(t, "analysis_metadata_sync", msg.Type)
		assert.Equal(t, "analysis_123", msg.AnalysisMetadataSync.AnalysisID)
		assert.Equal(t, "sess-1", msg.AnalysisMetadataSync.SessionID)
		assert.Equal(t, "acme", msg.AnalysisMetadataSync.Target)
		assert.Equal(t, "org", msg.AnalysisMetadataSync.TargetType)
		assert.Equal(t, analysisMetadataDone, msg.AnalysisMetadataSync.Status)
		assert.Equal(t, "Repository access updated", msg.AnalysisMetadataSync.Message)
		assert.Equal(t, 12, msg.AnalysisMetadataSync.ReposTotal)
		assert.False(t, msg.AnalysisMetadataSync.UpdatedAt.IsZero())
	case <-time.After(time.Second):
		t.Fatal("expected analysis metadata sync message")
	}

	select {
	case <-other.send:
		t.Fatal("unexpected metadata sync message for non-target session")
	default:
	}
}

func TestAnalysisProgressObserver_TracksOrgProgress(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	hub := NewOperatorHub(nil, nil, nil)
	target := &OperatorConn{sessionID: "sess-1", send: make(chan OperatorMessage, 8), hub: hub}
	hub.operators[target] = true
	h.operators = hub

	startedAt := time.Now().Add(-2 * time.Second).UTC()
	observer := newAnalysisProgressObserver(h, AnalyzeRequest{
		SessionID:  "sess-1",
		Target:     "acme",
		TargetType: "org",
	}, startedAt)

	observer.OnAnalysisStarted("Discovering repositories")
	msg := requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "Discovering repositories", msg.Message)
	assert.Equal(t, 0, msg.ReposCompleted)
	assert.Equal(t, 0, msg.ReposTotal)
	assert.Empty(t, msg.CurrentRepo)

	observer.OnDiscoveryCompleted("acme", 3)
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "Analyzing workflows", msg.Message)
	assert.Equal(t, 0, msg.ReposCompleted)
	assert.Equal(t, 3, msg.ReposTotal)

	observer.OnRepoStarted("acme/api")
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "acme/api", msg.CurrentRepo)
	assert.Equal(t, 0, msg.ReposCompleted)
	assert.Equal(t, 3, msg.ReposTotal)

	observer.OnRepoCompleted("acme/api")
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "acme/api", msg.CurrentRepo)
	assert.Equal(t, 1, msg.ReposCompleted)
	assert.Equal(t, 3, msg.ReposTotal)

	observer.OnRepoSkipped("acme/docs", "fork")
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "acme/docs", msg.CurrentRepo)
	assert.Equal(t, 2, msg.ReposCompleted)
	assert.Equal(t, 3, msg.ReposTotal)

	observer.OnRepoError("acme/web", errors.New("boom"))
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "acme/web", msg.CurrentRepo)
	assert.Equal(t, 3, msg.ReposCompleted)
	assert.Equal(t, 3, msg.ReposTotal)

	observer.OnFinalizeStarted(1)
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "Finalizing analysis results", msg.Message)
	assert.Equal(t, 3, msg.ReposCompleted)
	assert.Equal(t, 3, msg.ReposTotal)
	assert.Empty(t, msg.CurrentRepo)
}

func TestAnalysisProgressObserver_TracksRepoSteps(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	hub := NewOperatorHub(nil, nil, nil)
	target := &OperatorConn{sessionID: "sess-1", send: make(chan OperatorMessage, 8), hub: hub}
	hub.operators[target] = true
	h.operators = hub

	startedAt := time.Now().Add(-2 * time.Second).UTC()
	observer := newAnalysisProgressObserver(h, AnalyzeRequest{
		SessionID:  "sess-1",
		Target:     "acme/api",
		TargetType: "repo",
	}, startedAt)

	observer.OnAnalysisStarted("Cloning repository")
	msg := requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "Cloning repository", msg.Message)
	assert.Equal(t, "acme/api", msg.CurrentRepo)
	assert.Equal(t, 0, msg.ReposCompleted)
	assert.Equal(t, 1, msg.ReposTotal)

	observer.OnStepCompleted("Generated package insights")
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "Generated package insights", msg.Message)
	assert.Equal(t, "acme/api", msg.CurrentRepo)
	assert.Equal(t, 0, msg.ReposCompleted)
	assert.Equal(t, 1, msg.ReposTotal)

	observer.OnRepoCompleted("acme/api")
	msg = requireAnalysisProgressMessage(t, target.send)
	assert.Equal(t, "Analyzing workflows", msg.Message)
	assert.Equal(t, "acme/api", msg.CurrentRepo)
	assert.Equal(t, 1, msg.ReposCompleted)
	assert.Equal(t, 1, msg.ReposTotal)
}

func TestHandleAnalyze_DefersAnalysisMetadataSync(t *testing.T) {
	origAnalyze := analyzeRemoteWithObserverFunc
	analyzeRemoteWithObserverFunc = func(_ context.Context, _, _, _ string, _ poutine.AnalysisObserver) (*poutine.AnalysisResult, error) {
		return &poutine.AnalysisResult{
			Success:       true,
			Target:        "acme/api",
			TargetType:    "repo",
			ReposAnalyzed: 1,
			AnalyzedRepos: []string{"acme/api"},
			Findings: []poutine.Finding{
				{ID: "V001", Repository: "acme/api", RuleID: "injection"},
			},
		}, nil
	}
	t.Cleanup(func() { analyzeRemoteWithObserverFunc = origAnalyze })

	var repoInfoCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/api", func(w http.ResponseWriter, r *http.Request) {
		repoInfoCalls++
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"full_name":"acme/api","private":true,"permissions":{"push":true}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(_ string) *gitHubClient {
		baseURL, _ := url.Parse(srv.URL + "/")
		c := github.NewClient(nil)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: "test"}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.database = newTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(`{"token":"ghp_test","target":"acme/api","target_type":"repo","session_id":"sess-1","analysis_id":"analysis_123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	started := time.Now()
	h.handleAnalyze(rec, req)
	elapsed := time.Since(started)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Less(t, elapsed, 250*time.Millisecond)

	entityRepo := db.NewKnownEntityRepository(h.database)
	require.Eventually(t, func() bool {
		entities, err := entityRepo.ListRepos("sess-1")
		if err != nil || len(entities) != 1 {
			return false
		}
		return entities[0].Name == "acme/api" && entities[0].IsPrivate
	}, 2*time.Second, 25*time.Millisecond)

	require.Eventually(t, func() bool {
		repos := h.Pantry().GetAssetsByType(pantry.AssetRepository)
		if len(repos) != 1 {
			return false
		}
		if repos[0].Name != "api" {
			return false
		}
		private, _ := repos[0].Properties["private"].(bool)
		return private
	}, 2*time.Second, 25*time.Millisecond)
	assert.Equal(t, 1, repoInfoCalls)
}

func requireAnalysisProgressMessage(t *testing.T, ch <-chan OperatorMessage) AnalysisProgressPayload {
	t.Helper()

	select {
	case msg := <-ch:
		require.NotNil(t, msg.AnalysisProgress)
		return *msg.AnalysisProgress
	case <-time.After(time.Second):
		t.Fatal("expected analysis progress message")
		return AnalysisProgressPayload{}
	}
}

func TestSanitizeError_TruncatesLongMessages(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short message",
			input:    "short error",
			expected: "short error",
		},
		{
			name:     "exactly 100 chars",
			input:    strings.Repeat("a", 100),
			expected: strings.Repeat("a", 100),
		},
		{
			name:     "over 100 chars",
			input:    strings.Repeat("a", 150),
			expected: strings.Repeat("a", 100) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{msg: tt.input}
			result := sanitizeError(err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// testError is a simple error implementation for testing.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// =============================================================================
// Cloud Asset Creation Tests
// =============================================================================

func TestCreateCloudAsset_AWS(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAWS,
		Action:   "aws-actions/configure-aws-credentials",
		Version:  "v4",
		Inputs: map[string]string{
			"role-to-assume": "arn:aws:iam::123456789:role/deploy-role",
			"aws-region":     "us-east-1",
		},
	}

	asset := createCloudAsset(action, "job123", "deploy")

	assert.Equal(t, "aws", asset.Provider)
	assert.Equal(t, pantry.AssetCloud, asset.Type)
	assert.Equal(t, pantry.StateHighValue, asset.State)
	assert.Equal(t, "aws-actions/configure-aws-credentials", asset.Properties["action"])
	assert.Equal(t, "v4", asset.Properties["version"])
	assert.Equal(t, "deploy", asset.Properties["job"])
	assert.Equal(t, "arn:aws:iam::123456789:role/deploy-role", asset.Properties["role-to-assume"])
	assert.Equal(t, "us-east-1", asset.Properties["aws-region"])
}

func TestCreateCloudAsset_GCP(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderGCP,
		Action:   "google-github-actions/auth",
		Version:  "v2",
		Inputs: map[string]string{
			"workload_identity_provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
			"service_account":            "sa@project.iam.gserviceaccount.com",
		},
	}

	asset := createCloudAsset(action, "job123", "deploy")

	assert.Equal(t, "gcp", asset.Provider)
	assert.Contains(t, asset.Properties["workload_identity_provider"], "workloadIdentityPools")
	assert.Contains(t, asset.Properties["service_account"], "@project.iam.gserviceaccount.com")
}

func TestCreateCloudAsset_Azure(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAzure,
		Action:   "azure/login",
		Version:  "v1",
		Inputs: map[string]string{
			"client-id": "client-uuid",
			"tenant-id": "tenant-uuid",
		},
	}

	asset := createCloudAsset(action, "job123", "deploy")

	assert.Equal(t, "azure", asset.Provider)
	assert.Equal(t, "client-uuid", asset.Properties["client-id"])
	assert.Equal(t, "tenant-uuid", asset.Properties["tenant-id"])
}

func TestExtractCloudResourceID_AWS(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAWS,
		Inputs: map[string]string{
			"role-to-assume": "arn:aws:iam::123456789:role/my-role",
		},
	}

	id := extractCloudResourceID(action)
	assert.Equal(t, "arn:aws:iam::123456789:role/my-role", id)
}

func TestExtractCloudResourceID_GCP(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderGCP,
		Inputs: map[string]string{
			"service_account": "sa@project.iam.gserviceaccount.com",
		},
	}

	id := extractCloudResourceID(action)
	assert.Equal(t, "sa@project.iam.gserviceaccount.com", id)
}

func TestExtractCloudResourceID_Azure(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAzure,
		Inputs: map[string]string{
			"client-id": "00000000-0000-0000-0000-000000000001",
		},
	}

	id := extractCloudResourceID(action)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", id)
}

func TestExtractCloudResourceID_Fallback(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAWS,
		Action:   "aws-actions/configure-aws-credentials",
		Inputs:   map[string]string{},
	}

	id := extractCloudResourceID(action)
	assert.Equal(t, "aws-actions/configure-aws-credentials", id)
}

func TestCreateCloudToken_AWS(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAWS,
		Inputs: map[string]string{
			"role-to-assume": "arn:aws:iam::123456789:role/my-role",
			"aws-region":     "us-east-1",
		},
	}

	token := createCloudToken(action, "cloud123", "deploy")

	assert.Equal(t, pantry.AssetToken, token.Type)
	assert.Equal(t, pantry.StateHighValue, token.State)
	assert.Equal(t, "aws_oidc", token.Properties["token_type"])
	assert.Equal(t, "arn:aws:iam::123456789:role/my-role", token.Properties["role_arn"])
	assert.Equal(t, "us-east-1", token.Properties["region"])
	assert.Equal(t, "deploy", token.Properties["job"])
	assert.Equal(t, "aws", token.Properties["provider"])
}

func TestCreateCloudToken_GCP(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderGCP,
		Inputs: map[string]string{
			"workload_identity_provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
			"service_account":            "sa@project.iam.gserviceaccount.com",
			"project_id":                 "my-project",
		},
	}

	token := createCloudToken(action, "cloud123", "deploy")

	assert.Equal(t, "gcp_oidc", token.Properties["token_type"])
	assert.Contains(t, token.Properties["workload_provider"], "workloadIdentityPools")
	assert.Equal(t, "sa@project.iam.gserviceaccount.com", token.Properties["service_account"])
	assert.Equal(t, "my-project", token.Properties["project_id"])
}

func TestCreateCloudToken_Azure(t *testing.T) {
	action := poutine.CloudAction{
		Provider: poutine.CloudProviderAzure,
		Inputs: map[string]string{
			"client-id":       "client-uuid",
			"tenant-id":       "tenant-uuid",
			"subscription-id": "sub-uuid",
		},
	}

	token := createCloudToken(action, "cloud123", "deploy")

	assert.Equal(t, "azure_oidc", token.Properties["token_type"])
	assert.Equal(t, "tenant-uuid", token.Properties["tenant_id"])
	assert.Equal(t, "client-uuid", token.Properties["client_id"])
	assert.Equal(t, "sub-uuid", token.Properties["subscription_id"])
}

func TestCreateCloudToken_UnknownProvider(t *testing.T) {
	action := poutine.CloudAction{
		Provider: "oracle",
		Inputs:   map[string]string{},
	}

	token := createCloudToken(action, "cloud123", "deploy")

	assert.Equal(t, "cloud_oidc", token.Properties["token_type"])
	assert.Equal(t, "oracle", token.Properties["provider"])
}

// =============================================================================
// Private Repo Import Tests (importPrivateReposToPantry)
// =============================================================================

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(db.Config{Path: filepath.Join(t.TempDir(), "test.db")})
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	return database
}

func seedKnownEntities(t *testing.T, database *db.DB, entities []*db.KnownEntityRow) {
	t.Helper()
	repo := db.NewKnownEntityRepository(database)
	for _, e := range entities {
		require.NoError(t, repo.Upsert(e))
	}
}

func TestImportPrivateReposToPantry_AddsPrivateRepos(t *testing.T) {
	database := newTestDB(t)
	seedKnownEntities(t, database, []*db.KnownEntityRow{
		{ID: "r1", EntityType: db.EntityTypeRepo, Name: "acme/secret-repo", SessionID: "sess1", IsPrivate: true},
		{ID: "r2", EntityType: db.EntityTypeRepo, Name: "acme/internal-tools", SessionID: "sess1", IsPrivate: true},
	})

	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	h.importPrivateReposToPantry("sess1")

	p := h.Pantry()
	repos := p.GetAssetsByType(pantry.AssetRepository)
	assert.Len(t, repos, 2)

	for _, repo := range repos {
		assert.Equal(t, pantry.StateValidated, repo.State)
		assert.Equal(t, true, repo.Properties["private"])
	}
}

func TestImportPrivateReposToPantry_SkipsPublicRepos(t *testing.T) {
	database := newTestDB(t)
	seedKnownEntities(t, database, []*db.KnownEntityRow{
		{ID: "r1", EntityType: db.EntityTypeRepo, Name: "acme/public-lib", SessionID: "sess1", IsPrivate: false},
		{ID: "r2", EntityType: db.EntityTypeRepo, Name: "acme/private-api", SessionID: "sess1", IsPrivate: true},
		{ID: "r3", EntityType: db.EntityTypeRepo, Name: "acme/docs", SessionID: "sess1", IsPrivate: false},
	})

	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	h.importPrivateReposToPantry("sess1")

	p := h.Pantry()
	repos := p.GetAssetsByType(pantry.AssetRepository)
	assert.Len(t, repos, 1)
	assert.Equal(t, "private-api", repos[0].Name)
	assert.Equal(t, true, repos[0].Properties["private"])
}

func TestImportPrivateReposToPantry_CreatesOrgAssets(t *testing.T) {
	database := newTestDB(t)
	seedKnownEntities(t, database, []*db.KnownEntityRow{
		{ID: "r1", EntityType: db.EntityTypeRepo, Name: "acme/secret-repo", SessionID: "sess1", IsPrivate: true},
		{ID: "r2", EntityType: db.EntityTypeRepo, Name: "globex/internal", SessionID: "sess1", IsPrivate: true},
	})

	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	h.importPrivateReposToPantry("sess1")

	p := h.Pantry()

	orgs := p.GetAssetsByType(pantry.AssetOrganization)
	assert.Len(t, orgs, 2)

	orgNames := make(map[string]bool)
	for _, org := range orgs {
		orgNames[org.Name] = true
	}
	assert.True(t, orgNames["acme"])
	assert.True(t, orgNames["globex"])

	acmeOrgID := "github:org:acme"
	acmeRepoID := "github:acme/secret-repo"
	edges := p.GetOutgoingEdges(acmeOrgID)
	assert.Len(t, edges, 1)
	assert.Equal(t, acmeRepoID, edges[0].To)
	assert.Equal(t, pantry.RelContains, edges[0].Relationship.Type)

	globexOrgID := "github:org:globex"
	globexRepoID := "github:globex/internal"
	edges = p.GetOutgoingEdges(globexOrgID)
	assert.Len(t, edges, 1)
	assert.Equal(t, globexRepoID, edges[0].To)
	assert.Equal(t, pantry.RelContains, edges[0].Relationship.Type)
}

func TestImportPrivateReposToPantry_ImportsSSHAccessRepos(t *testing.T) {
	database := newTestDB(t)
	seedKnownEntities(t, database, []*db.KnownEntityRow{
		{ID: "r1", EntityType: db.EntityTypeRepo, Name: "acme/public-write", SessionID: "sess1", SSHPermission: "write", Permissions: []string{"push"}},
	})

	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	h.importPrivateReposToPantry("sess1")

	repos := h.Pantry().GetAssetsByType(pantry.AssetRepository)
	require.Len(t, repos, 1)
	assert.Equal(t, "public-write", repos[0].Name)
	assert.Equal(t, "write", repos[0].Properties["ssh_access"])
	assert.Equal(t, []string{"push"}, repos[0].Properties["permissions"])
}

func TestRecordAnalyzedRepoVisibility(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"full_name":"acme/api","private":true,"permissions":{"push":true}}`))
	})
	mux.HandleFunc("GET /repos/acme/web", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"full_name":"acme/web","private":false,"permissions":{"push":false}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(_ string) *gitHubClient {
		baseURL, _ := url.Parse(srv.URL + "/")
		c := github.NewClient(nil)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: "test"}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	database := newTestDB(t)
	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	result := &poutine.AnalysisResult{
		AnalyzedRepos: []string{"acme/api", "acme/web"},
	}

	h.recordAnalyzedRepoVisibility(t.Context(), AnalyzeRequest{
		Token:      "test-token",
		SessionID:  "sess1",
		Target:     "acme/api",
		TargetType: "repo",
	}, result)

	entityRepo := db.NewKnownEntityRepository(database)
	entities, err := entityRepo.ListRepos("sess1")
	require.NoError(t, err)
	require.Len(t, entities, 2)

	entityMap := make(map[string]*db.KnownEntityRow)
	for _, e := range entities {
		entityMap[e.Name] = e
	}

	assert.True(t, entityMap["acme/api"].IsPrivate, "acme/api should be marked private")
	assert.False(t, entityMap["acme/web"].IsPrivate, "acme/web should not be marked private")
	assert.Equal(t, []string{"push"}, entityMap["acme/api"].Permissions)
}

func TestHandleAnalyze_EmptySessionID_SkipsRepoVisibility(t *testing.T) {
	database := newTestDB(t)
	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	result := &poutine.AnalysisResult{
		Success:       true,
		AnalyzedRepos: []string{"acme/private-repo"},
		Findings: []poutine.Finding{
			{ID: "V001", Repository: "acme/private-repo", RuleID: "injection"},
		},
	}

	req := AnalyzeRequest{
		Token:     "ghp_test",
		SessionID: "", // BUG: setup wizard sent empty SessionID
	}

	// The guard in handleAnalyze: `if req.SessionID != "" && h.database != nil`
	// When SessionID is empty, this block is skipped entirely.
	if req.SessionID != "" && h.database != nil {
		h.recordAnalyzedRepoVisibility(t.Context(), req, result)
		h.importPrivateReposToPantry(req.SessionID)
	}

	// Prove: no known entities recorded
	entityRepo := db.NewKnownEntityRepository(database)
	entities, err := entityRepo.ListBySession("")
	require.NoError(t, err)
	assert.Empty(t, entities, "empty SessionID means recordAnalyzedRepoVisibility is never called - no entities in DB")

	// Prove: pantry has no private property
	p := h.Pantry()
	h.importAnalysisToPantry(result)
	repos := p.GetAssetsByType(pantry.AssetRepository)
	for _, repo := range repos {
		_, hasPrivate := repo.Properties["private"]
		assert.False(t, hasPrivate, "repo %s should NOT have 'private' property - visibility check was skipped", repo.Name)
	}
}

func TestHandleAnalyze_WithSessionID_RecordsRepoVisibility(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/acme/private-repo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"full_name":"acme/private-repo","private":true,"permissions":{"push":true}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(_ string) *gitHubClient {
		baseURL, _ := url.Parse(srv.URL + "/")
		c := github.NewClient(nil)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: "test"}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	database := newTestDB(t)
	mock := &mockPublisher{}
	h := NewHandlerWithPublisher(mock, nil)
	h.database = database

	result := &poutine.AnalysisResult{
		Success:       true,
		AnalyzedRepos: []string{"acme/private-repo"},
		Findings: []poutine.Finding{
			{ID: "V001", Repository: "acme/private-repo", RuleID: "injection"},
		},
	}

	req := AnalyzeRequest{
		Token:     "ghp_test",
		SessionID: "sess-abc123", // FIX: setup wizard now sends SessionID
	}

	// Same guard as handleAnalyze
	if req.SessionID != "" && h.database != nil {
		h.recordAnalyzedRepoVisibility(t.Context(), req, result)
		h.importPrivateReposToPantry(req.SessionID)
	}

	// Prove: entity recorded with IsPrivate=true
	entityRepo := db.NewKnownEntityRepository(database)
	entities, err := entityRepo.ListRepos("sess-abc123")
	require.NoError(t, err)
	require.Len(t, entities, 1, "with SessionID, recordAnalyzedRepoVisibility stores the entity")
	assert.True(t, entities[0].IsPrivate, "GitHub API said private=true, should be recorded")

	// Prove: pantry has private property
	p := h.Pantry()
	repos := p.GetAssetsByType(pantry.AssetRepository)
	found := false
	for _, repo := range repos {
		if repo.Name == "private-repo" {
			assert.Equal(t, true, repo.Properties["private"], "private repo should have private=true in pantry")
			found = true
		}
	}
	assert.True(t, found, "private-repo should exist in pantry")
}

func TestRecordAnalyzedRepoVisibility_OrgTargetPrefersGraphQL(t *testing.T) {
	var graphqlCalls int
	var listReposCalls int
	var repoGetCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		graphqlCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"repositoryOwner":{"repositories":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[{"nameWithOwner":"acme/api","isPrivate":true,"viewerPermission":"WRITE"},{"nameWithOwner":"acme/web","isPrivate":false,"viewerPermission":"READ"},{"nameWithOwner":"acme/extra","isPrivate":true,"viewerPermission":"ADMIN"}]}}}}`))
	})
	mux.HandleFunc("GET /user/repos", func(w http.ResponseWriter, r *http.Request) {
		listReposCalls++
		http.Error(w, "unexpected fallback", http.StatusInternalServerError)
	})
	mux.HandleFunc("GET /repos/acme/api", func(w http.ResponseWriter, r *http.Request) {
		repoGetCalls++
		http.Error(w, "unexpected per-repo fallback", http.StatusInternalServerError)
	})
	mux.HandleFunc("GET /repos/acme/web", func(w http.ResponseWriter, r *http.Request) {
		repoGetCalls++
		http.Error(w, "unexpected per-repo fallback", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origNew := newGitHubClientFunc
	newGitHubClientFunc = func(_ string) *gitHubClient {
		baseURL, _ := url.Parse(srv.URL + "/")
		c := github.NewClient(nil)
		c.BaseURL = baseURL
		return &gitHubClient{client: c, token: "test", graphqlURL: srv.URL + "/graphql"}
	}
	t.Cleanup(func() { newGitHubClientFunc = origNew })

	database := newTestDB(t)
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.database = database

	result := &poutine.AnalysisResult{
		AnalyzedRepos: []string{"acme/api", "acme/web"},
	}

	h.recordAnalyzedRepoVisibility(t.Context(), AnalyzeRequest{
		Token:      "test-token",
		SessionID:  "sess1",
		Target:     "acme",
		TargetType: "org",
	}, result)

	assert.Equal(t, 1, graphqlCalls)
	assert.Zero(t, listReposCalls)
	assert.Zero(t, repoGetCalls)

	entityRepo := db.NewKnownEntityRepository(database)
	entities, err := entityRepo.ListRepos("sess1")
	require.NoError(t, err)
	require.Len(t, entities, 2)
	assert.True(t, entities[0].IsPrivate || entities[1].IsPrivate)
}

func TestImportAnalysisToPantry_SetsExploitSupportMetadata(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Findings: []poutine.Finding{
			{
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				RuleID:     "debug_enabled",
				Severity:   "high",
			},
		},
	}

	h.importAnalysisToPantry(result)

	vulns := h.Pantry().FindVulnerabilities()
	require.Len(t, vulns, 1)
	assert.Equal(t, false, vulns[0].Properties["exploit_supported"])
	assert.Equal(t, "This finding is analyze-only in v0.1.0. Exploit actions are only available for injection and pwn-request findings.", vulns[0].Properties["exploit_support_reason"])
}

func TestImportAnalysisToPantry_SkipsSelfHostedRunnerAnalyzeOnlyVuln(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Findings: []poutine.Finding{
			{
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				Job:        "build",
				RuleID:     "pr_runs_on_self_hosted",
				Severity:   "critical",
			},
		},
	}

	h.importAnalysisToPantry(result)

	assert.Empty(t, h.Pantry().FindVulnerabilities())
	targets := h.Pantry().GetAssetsByType(pantry.AssetSelfHostedRunner)
	require.Len(t, targets, 1)
	assert.Equal(t, []string{"build"}, targets[0].StringSliceProperty("observed_job_names"))
}

func TestImportAnalysisToPantry_CreatesSelfHostedRunnerTargets(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Workflows: []poutine.WorkflowMeta{
			{
				Repository: "acme/api",
				Path:       ".github/workflows/pr.yml",
				Jobs: []poutine.JobMeta{
					{
						ID:         "build",
						SelfHosted: true,
						RunsOn:     []string{"self-hosted", "linux", "x64"},
					},
				},
			},
		},
		Findings: []poutine.Finding{
			{
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				Job:        "build",
				Line:       12,
				RuleID:     "injection",
				Severity:   "critical",
				Context:    "issue_body",
			},
		},
	}

	h.importAnalysisToPantry(result)

	targets := h.Pantry().GetAssetsByType(pantry.AssetSelfHostedRunner)
	require.Len(t, targets, 1)
	assert.Equal(t, []string{"self-hosted", "linux", "x64"}, targets[0].StringSliceProperty("label_set"))
	assert.Equal(t, []string{"build"}, targets[0].StringSliceProperty("observed_job_names"))
}

func TestImportAnalysisToPantry_AttachesGitleaksSecretsToFindingRepo(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Workflows: []poutine.WorkflowMeta{
			{Repository: "acme/worker", Path: ".github/workflows/ci.yml"},
		},
		SecretFindings: []poutine.SecretFinding{
			{
				RuleID:      "private-key",
				Description: "Private Key detected",
				Repository:  "acme/newcleus-core-v3",
				File:        "README.md",
				StartLine:   12,
				Secret:      "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			},
		},
	}

	h.importAnalysisToPantry(result)

	secrets := h.Pantry().GetAssetsByType(pantry.AssetSecret)
	require.Len(t, secrets, 1)
	assert.Equal(t, "Private Key detected (README.md:12)", secrets[0].Name)
	assert.Equal(t, "private_key", secrets[0].Properties["inferred_type"])

	edges := h.Pantry().AllRelationships()
	assert.Contains(t, edges, pantry.Edge{
		From:         "github:acme/newcleus-core-v3",
		To:           secrets[0].ID,
		Relationship: pantry.Exposes("gitleaks", "private-key"),
	})
}

func TestImportAnalysisToPantry_PersistsBashContextBeforeExploitSupport(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Findings: []poutine.Finding{
			{
				Repository:  "acme/api",
				Workflow:    ".github/workflows/pr.yml",
				RuleID:      "injection",
				Severity:    "critical",
				BashContext: bashctx.QuotedHeredoc,
			},
		},
	}

	h.importAnalysisToPantry(result)

	vulns := h.Pantry().FindVulnerabilities()
	require.Len(t, vulns, 1)
	assert.Equal(t, bashctx.QuotedHeredoc, vulns[0].Properties["bash_context"])
	assert.Equal(t, false, vulns[0].Properties["exploit_supported"])
	assert.Equal(t, "Quoted heredoc bodies do not evaluate shell substitutions.", vulns[0].Properties["exploit_support_reason"])
}

func TestImportAnalysisToPantry_PreservesMultiSourceInjectionFindings(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Findings: []poutine.Finding{
			{
				Repository:       "whooli/xyz",
				Workflow:         ".github/workflows/auto-labeler.yml",
				Line:             23,
				Job:              "whooli-triage",
				Step:             "1",
				RuleID:           "injection",
				Title:            "Auto labeler step 1",
				Severity:         "critical",
				Trigger:          "issues",
				Fingerprint:      "fp-auto-labeler-step-1",
				InjectionSources: []string{"github.event.issue.title", "github.event.issue.body"},
			},
			{
				Repository:       "whooli/xyz",
				Workflow:         ".github/workflows/auto-labeler.yml",
				Line:             41,
				Job:              "whooli-triage",
				Step:             "2",
				RuleID:           "injection",
				Title:            "Auto labeler step 2",
				Severity:         "critical",
				Trigger:          "issues",
				Fingerprint:      "fp-auto-labeler-step-2",
				InjectionSources: []string{"github.event.issue.title", "github.event.issue.body"},
			},
		},
	}

	h.importAnalysisToPantry(result)

	vulns := h.Pantry().FindVulnerabilities()
	require.Len(t, vulns, 4)
	seenSources := make(map[string]bool, len(vulns))
	for _, vuln := range vulns {
		sources, ok := vuln.Properties["injection_sources"].([]string)
		require.True(t, ok)
		assert.Len(t, sources, 1)
		seenSources[sources[0]] = true
	}
	assert.True(t, seenSources["github.event.issue.title"])
	assert.True(t, seenSources["github.event.issue.body"])
}

func TestAnalyzeRequest_IncludesSessionID(t *testing.T) {
	reqData := `{"token":"ghp_test","target":"acme/repo","target_type":"repo","session_id":"sess-abc-123"}`

	var req AnalyzeRequest
	err := json.Unmarshal([]byte(reqData), &req)
	assert.NoError(t, err)
	assert.Equal(t, "sess-abc-123", req.SessionID)

	marshaled, err := json.Marshal(req)
	assert.NoError(t, err)

	var roundTripped AnalyzeRequest
	err = json.Unmarshal(marshaled, &roundTripped)
	assert.NoError(t, err)
	assert.Equal(t, "sess-abc-123", roundTripped.SessionID)
}
