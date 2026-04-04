// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v59/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	h.recordAnalyzedRepoVisibility(t.Context(), "test-token", "sess1", result)

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
		h.recordAnalyzedRepoVisibility(t.Context(), req.Token, req.SessionID, result)
		h.importPrivateReposToPantry(req.SessionID)
	}

	// Prove: no known entities recorded
	entityRepo := db.NewKnownEntityRepository(database)
	entities, err := entityRepo.ListBySession("")
	require.NoError(t, err)
	assert.Empty(t, entities, "empty SessionID means recordAnalyzedRepoVisibility is never called — no entities in DB")

	// Prove: pantry has no private property
	p := h.Pantry()
	h.importAnalysisToPantry(result)
	repos := p.GetAssetsByType(pantry.AssetRepository)
	for _, repo := range repos {
		_, hasPrivate := repo.Properties["private"]
		assert.False(t, hasPrivate, "repo %s should NOT have 'private' property — visibility check was skipped", repo.Name)
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
		h.recordAnalyzedRepoVisibility(t.Context(), req.Token, req.SessionID, result)
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

func TestImportAnalysisToPantry_SetsExploitSupportMetadata(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	result := &poutine.AnalysisResult{
		Success: true,
		Findings: []poutine.Finding{
			{
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				RuleID:     "pr_runs_on_self_hosted",
				Severity:   "critical",
			},
		},
	}

	h.importAnalysisToPantry(result)

	vulns := h.Pantry().FindVulnerabilities()
	require.Len(t, vulns, 1)
	assert.Equal(t, false, vulns[0].Properties["exploit_supported"])
	assert.Equal(t, "Self-hosted runner findings are analyze-only in v0.1.0. Exploit actions are not supported yet.", vulns[0].Properties["exploit_support_reason"])
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
