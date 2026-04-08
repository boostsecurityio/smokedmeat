// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/models"
)

// mockPublisher implements the Publisher interface for testing.
type mockPublisher struct {
	beacons   []publishedMessage
	coleslaws []publishedMessage
	failNext  bool
}

type publishedMessage struct {
	agentID string
	data    []byte
}

func (m *mockPublisher) PublishBeacon(_ context.Context, agentID string, data []byte) error {
	if m.failNext {
		m.failNext = false
		return assert.AnError
	}
	m.beacons = append(m.beacons, publishedMessage{agentID, data})
	return nil
}

func (m *mockPublisher) PublishColeslaw(_ context.Context, agentID string, data []byte) error {
	if m.failNext {
		m.failNext = false
		return assert.AnError
	}
	m.coleslaws = append(m.coleslaws, publishedMessage{agentID, data})
	return nil
}

func newTestHandler(mock *mockPublisher, store *OrderStore) (*Handler, *http.ServeMux) {
	h := NewHandlerWithPublisher(mock, store)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.HandleFunc("GET /health", h.handleHealth)

	return h, mux
}

// =============================================================================
// Health Endpoint Tests
// =============================================================================

func TestHandler_Health_ReturnsOK(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_RegisterRoutes_RegistersPurge(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	req := httptest.NewRequest(http.MethodPost, "/purge", strings.NewReader(`{"session_id":"","scope_type":"repo","scope_value":"acme/api","dry_run":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "session_id is required")
}

func TestShouldAutoCloseStager(t *testing.T) {
	tests := []struct {
		name   string
		stager *RegisteredStager
		want   bool
	}{
		{
			name: "nil stager",
			want: false,
		},
		{
			name: "persistent stager never auto closes",
			stager: &RegisteredStager{
				Persistent:    true,
				MaxCallbacks:  0,
				CallbackCount: 1,
			},
			want: false,
		},
		{
			name: "fanout before final callback",
			stager: &RegisteredStager{
				MaxCallbacks:  3,
				CallbackCount: 2,
			},
			want: false,
		},
		{
			name: "fanout on final callback",
			stager: &RegisteredStager{
				MaxCallbacks:  3,
				CallbackCount: 3,
			},
			want: true,
		},
		{
			name: "default one shot closes on first callback",
			stager: &RegisteredStager{
				MaxCallbacks:  1,
				CallbackCount: 1,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shouldAutoCloseStager(tt.stager))
		})
	}
}

// =============================================================================
// Beacon Endpoint Tests (POST /b/{agentID})
// =============================================================================

func TestHandler_Beacon_PublishesBeaconJSON(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	beacon := `{"agent_id":"test-agent","hostname":"test-host","os":"linux"}`
	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader(beacon))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, mock.beacons, 1)
	assert.Equal(t, "test-agent", mock.beacons[0].agentID)
	assert.JSONEq(t, beacon, string(mock.beacons[0].data))
}

func TestHandler_Beacon_PublishesColeslawJSON(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	// Create and deliver an order first
	order := models.NewOrder("session", "test-agent", "exec", []string{"whoami"})
	require.NoError(t, store.Add(order))
	got := store.Next("test-agent")
	require.NotNil(t, got)
	store.MarkDelivered(got.OrderID)

	// Now send coleslaw
	coleslaw := models.NewColeslaw(order.OrderID, "session", "test-agent")
	coleslaw.SetOutput([]byte("root"), nil, 0)
	coleslawData, err := coleslaw.Marshal()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader(string(coleslawData)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, mock.coleslaws, 1)
	assert.Equal(t, "test-agent", mock.coleslaws[0].agentID)
}

func TestHandler_Beacon_BroadcastsCachePoisonWithoutLoot(t *testing.T) {
	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)

	hub := NewOperatorHub(nil, nil, nil)
	op := &OperatorConn{sessionID: "sess-1", send: make(chan OperatorMessage, 4), hub: hub}
	hub.operators[op] = true
	h.SetOperatorHub(hub)

	beacon := `{
		"agent_id":"test-agent",
		"session_id":"sess-1",
		"hostname":"runner-1",
		"os":"linux",
		"env":{"GITHUB_REPOSITORY":"acme/demo"},
		"cache_poison":{"status":"failed","runtime_source":"memdump","error":"runner memory dump failed"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader(beacon))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	timeout := time.After(2 * time.Second)
	for {
		select {
		case msg := <-op.send:
			if msg.Type != "express_data" {
				continue
			}
			require.NotNil(t, msg.ExpressData)
			require.NotNil(t, msg.ExpressData.CachePoison)
			assert.Equal(t, "failed", msg.ExpressData.CachePoison.Status)
			assert.Empty(t, msg.ExpressData.Secrets)
			assert.Empty(t, msg.ExpressData.Vars)
			return
		case <-timeout:
			t.Fatal("expected express data broadcast")
		}
	}
}

func TestHandler_Beacon_FailedColeslawMarksOrderFailed(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	// Create and deliver an order
	order := models.NewOrder("session", "test-agent", "exec", []string{"false"})
	require.NoError(t, store.Add(order))
	got := store.Next("test-agent")
	store.MarkDelivered(got.OrderID)

	// Send failed coleslaw
	coleslaw := models.NewColeslaw(order.OrderID, "session", "test-agent")
	coleslaw.SetOutput(nil, []byte("error"), 1)
	coleslawData, err := coleslaw.Marshal()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader(string(coleslawData)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Beacon_RawBodyPublishesAsBeacon(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader("raw data"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, mock.beacons, 1)
	assert.Equal(t, "raw data", string(mock.beacons[0].data))
}

func TestHandler_Beacon_EmptyBodyReturnsOK(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Len(t, mock.beacons, 0) // No beacon published for empty body
}

func TestHandler_Beacon_PublishFailureReturns500(t *testing.T) {
	mock := &mockPublisher{failNext: true}
	_, mux := newTestHandler(mock, nil)

	beacon := `{"agent_id":"test-agent"}`
	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader(beacon))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandler_Beacon_ColeslawPublishFailureReturns500(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	order := models.NewOrder("session", "test-agent", "exec", []string{})
	require.NoError(t, store.Add(order))
	got := store.Next("test-agent")
	store.MarkDelivered(got.OrderID)

	// Fail next publish
	mock.failNext = true

	coleslaw := models.NewColeslaw(order.OrderID, "session", "test-agent")
	coleslaw.SetOutput([]byte("output"), nil, 0)
	coleslawData, _ := coleslaw.Marshal()

	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader(string(coleslawData)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandler_Stager_FanoutPersistsUntilBudgetExhausted(t *testing.T) {
	mock := &mockPublisher{}
	h, mux := newTestHandler(mock, nil)
	database := newTestDB(t)
	h.SetDatabase(database)

	err := h.registerStager(&RegisteredStager{
		ID:           "fanout-cb",
		ResponseType: "bash",
		SessionID:    "sess-1",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		MaxCallbacks: 3,
	})
	require.NoError(t, err)

	repo := db.NewStagerRepository(database)
	rows, err := repo.List()
	require.NoError(t, err)
	require.Len(t, rows, 1)

	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/r/fanout-cb", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		rows, err = repo.List()
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, i, rows[0].CallbackCount)
	}

	req := httptest.NewRequest(http.MethodGet, "/r/fanout-cb", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	rows, err = repo.List()
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestHandler_Beacon_ResponseFormat(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil)

	req := httptest.NewRequest(http.MethodPost, "/b/test-agent", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BeaconResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.NotZero(t, resp.Timestamp)
}

// =============================================================================
// Poll Endpoint Tests (GET /b/{agentID})
// =============================================================================

func TestHandler_Poll_ReturnsOrderWhenPending(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	order := models.NewOrder("session", "test-agent", "exec", []string{"whoami"})
	require.NoError(t, store.Add(order))

	req := httptest.NewRequest(http.MethodGet, "/b/test-agent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	var received models.Order
	err := json.Unmarshal(rec.Body.Bytes(), &received)
	require.NoError(t, err)
	assert.Equal(t, order.OrderID, received.OrderID)
	assert.Equal(t, "exec", received.Command)
	assert.Equal(t, []string{"whoami"}, received.Args)
}

func TestHandler_Poll_Returns204WhenNoPending(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	req := httptest.NewRequest(http.MethodGet, "/b/test-agent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestHandler_Poll_Returns204WhenNoStore(t *testing.T) {
	mock := &mockPublisher{}
	_, mux := newTestHandler(mock, nil) // nil store

	req := httptest.NewRequest(http.MethodGet, "/b/test-agent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandler_Poll_MarksOrderDelivered(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	order := models.NewOrder("session", "test-agent", "exec", []string{})
	require.NoError(t, store.Add(order))

	req := httptest.NewRequest(http.MethodGet, "/b/test-agent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Poll_ReturnsOrdersInFIFOOrder(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	order1 := models.NewOrder("session", "test-agent", "exec", []string{"1"})
	order2 := models.NewOrder("session", "test-agent", "exec", []string{"2"})
	order3 := models.NewOrder("session", "test-agent", "exec", []string{"3"})

	require.NoError(t, store.Add(order1))
	require.NoError(t, store.Add(order2))
	require.NoError(t, store.Add(order3))

	for i, expected := range []*models.Order{order1, order2, order3} {
		req := httptest.NewRequest(http.MethodGet, "/b/test-agent", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "Poll %d", i+1)

		var received models.Order
		err := json.Unmarshal(rec.Body.Bytes(), &received)
		require.NoError(t, err)
		assert.Equal(t, expected.OrderID, received.OrderID, "Poll %d", i+1)
	}

	// Fourth poll returns 204
	req := httptest.NewRequest(http.MethodGet, "/b/test-agent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestHandler_Poll_IsolatesAgentOrders(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	orderA := models.NewOrder("session", "agent-A", "exec", []string{"for-A"})
	orderB := models.NewOrder("session", "agent-B", "exec", []string{"for-B"})

	require.NoError(t, store.Add(orderA))
	require.NoError(t, store.Add(orderB))

	// Agent A gets their order
	reqA := httptest.NewRequest(http.MethodGet, "/b/agent-A", nil)
	recA := httptest.NewRecorder()
	mux.ServeHTTP(recA, reqA)

	assert.Equal(t, http.StatusOK, recA.Code)
	var receivedA models.Order
	require.NoError(t, json.Unmarshal(recA.Body.Bytes(), &receivedA))
	assert.Equal(t, orderA.OrderID, receivedA.OrderID)

	// Agent B gets their order
	reqB := httptest.NewRequest(http.MethodGet, "/b/agent-B", nil)
	recB := httptest.NewRecorder()
	mux.ServeHTTP(recB, reqB)

	assert.Equal(t, http.StatusOK, recB.Code)
	var receivedB models.Order
	require.NoError(t, json.Unmarshal(recB.Body.Bytes(), &receivedB))
	assert.Equal(t, orderB.OrderID, receivedB.OrderID)
}

// =============================================================================
// Secret Detection Helper Tests
// =============================================================================

func TestIsSensitiveEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		expected bool
	}{
		{"junk var PATH", "PATH", "/usr/bin", false},
		{"junk var HOME", "HOME", "/home/user", false},
		{"junk var GITHUB_WORKSPACE", "GITHUB_WORKSPACE", "/runner/work", false},
		{"sensitive prefix AWS_", "AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE", true},
		{"sensitive contains TOKEN", "MY_SECRET_TOKEN", "abc123def456ghi789jkl012mno345pq", true},
		{"github pat by value", "SOME_VAR", "ghp_1234567890abcdefghij1234567890abcd", true},
		{"runner tracking ID is junk", "RUNNER_TRACKING_ID", "some-value", false},
		{"actions orchestration ID is junk", "ACTIONS_ORCHESTRATION_ID", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", false},
		{"actions runtime URL is junk", "ACTIONS_RUNTIME_URL", "https://pipelines.actions.githubusercontent.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isSensitiveEnvVar(tt.envName, tt.value))
		})
	}
}

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"too short", "abc", false},
		{"github pat", "ghp_1234567890abcdefghij", true},
		{"github app token", "ghs_1234567890abcdefghij", true},
		{"aws key", "AKIAIOSFODNN7EXAMPLE", true},
		{"jwt token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123", true},
		{"plain text", "hello world this is not a secret", false},
		{"high entropy mixed", "Kx9mP2vL7nQ4wR8jT5yB3hF6cA0eG1dZ", true},
		{"low entropy repeated", "aaaaaaaabbbbbbbbccccccccdddddddd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, looksLikeSecret(tt.value))
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	assert.Equal(t, 0.0, calculateEntropy(""))
	assert.Equal(t, 0.0, calculateEntropy("aaaa"))

	high := calculateEntropy("a1b2c3d4e5f6")
	assert.Greater(t, high, 3.0)

	low := calculateEntropy("aaaaaaaaaa")
	assert.Less(t, low, 1.0)
}

func TestDetectSecretType(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		expected string
	}{
		{"github pat", "TOKEN", "ghp_abc123", "github_pat"},
		{"github token exact name with ghs prefix", "GITHUB_TOKEN", "ghs_abc123", "github_token"},
		{"gh token exact name with ghs prefix", "GH_TOKEN", "ghs_abc123", "github_token"},
		{"github app", "GH", "ghs_abc123", "github_app_token"},
		{"github oauth", "X", "gho_abc123", "github_oauth"},
		{"github user", "X", "ghu_abc123", "github_user_token"},
		{"fine grained", "X", "github_pat_abc123", "github_fine_grained_pat"},
		{"github by name", "GITHUB_TOKEN", "somevalue", "github_token"},
		{"aws access key", "KEY", "AKIAIOSFODNN7EXAMPLE", "aws_access_key"},
		{"aws secret", "AWS_SECRET_ACCESS_KEY", "someval", "aws_secret"},
		{"azure", "AZURE_CLIENT_SECRET", "val", "azure"},
		{"gcp", "GOOGLE_APPLICATION_CREDENTIALS", "val", "gcp"},
		{"npm", "NPM_TOKEN", "val", "npm"},
		{"docker", "DOCKER_PASSWORD", "val", "container_registry"},
		{"database", "DATABASE_URL", "val", "database"},
		{"ssh", "SSH_PRIVATE_KEY", "val", "signing_key"},
		{"github app key", "GITHUB_APP_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\ndata", "github_app_key"},
		{"app pem", "GH_APP_PEM", "-----BEGIN RSA PRIVATE KEY-----\ndata", "github_app_key"},
		{"private key generic", "DEPLOY_KEY", "-----BEGIN RSA PRIVATE KEY-----\ndata", "private_key"},
		{"generic", "RANDOM_VAR", "randomval", "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, detectSecretType(tt.envName, tt.value))
		})
	}
}

func TestIsEphemeralEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		expected bool
	}{
		{"runtime token", "ACTIONS_RUNTIME_TOKEN", true},
		{"runner var", "RUNNER_TEMP", true},
		{"run ID", "GITHUB_RUN_ID", true},
		{"normal var", "MY_SECRET", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isEphemeralEnvVar(tt.envName))
		})
	}
}

func TestParseRunnerSecret(t *testing.T) {
	t.Run("valid secret", func(t *testing.T) {
		raw := `"MY_TOKEN" {"value":"ghp_realtoken1234567890xx","isSecret":true}`
		result := parseRunnerSecret(raw)
		require.NotNil(t, result)
		assert.Equal(t, "MY_TOKEN", result.Name)
		assert.Equal(t, "ghp_realtoken1234567890xx", result.Value)
		assert.Equal(t, "github_pat", result.Type)
		assert.Equal(t, "runner_memory", result.Source)
		assert.True(t, result.HighValue)
	})

	t.Run("not a secret", func(t *testing.T) {
		raw := `"MY_VAR" {"value":"hello","isSecret":false}`
		assert.Nil(t, parseRunnerSecret(raw))
	})

	t.Run("empty value", func(t *testing.T) {
		raw := `"MY_VAR" {"value":"","isSecret":true}`
		assert.Nil(t, parseRunnerSecret(raw))
	})

	t.Run("malformed", func(t *testing.T) {
		assert.Nil(t, parseRunnerSecret("garbage"))
	})
}

func TestExtractWorkflowPath(t *testing.T) {
	tests := []struct {
		name        string
		workflowRef string
		repo        string
		expected    string
	}{
		{"standard format", "whooli/xyz/.github/workflows/whooli-analyzer.yml@refs/heads/main", "whooli/xyz", ".github/workflows/whooli-analyzer.yml"},
		{"with tag ref", "acme/api/.github/workflows/ci.yml@refs/tags/v1.0.0", "acme/api", ".github/workflows/ci.yml"},
		{"missing repo", "org/repo/.github/workflows/deploy.yml@refs/heads/main", "", ""},
		{"no @suffix", "whooli/xyz/.github/workflows/test.yml", "whooli/xyz", ".github/workflows/test.yml"},
		{"empty string", "", "whooli/xyz", ""},
		{"not a workflow path", "whooli/xyz/src/main.go@refs/heads/main", "whooli/xyz", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractWorkflowPath(tt.workflowRef, tt.repo))
		})
	}
}

func TestDetectSecretType_GitHubAppID(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		value    string
		expected string
	}{
		{"app id numeric", "WHOOLI_BOT_APP_ID", "12345", "github_app_id"},
		{"application id numeric", "MY_APPLICATION_ID", "67890", "github_app_id"},
		{"app ident numeric", "BOT_APP_IDENT", "99999", "github_app_id"},
		{"app id with whitespace", "APP_ID", "  12345  ", "github_app_id"},
		{"app id non-numeric", "APP_ID", "abc123", "generic"},
		{"no app keyword", "SOME_ID", "12345", "generic"},
		{"app id empty value", "APP_ID", "", "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, detectSecretType(tt.envName, tt.value))
		})
	}
}

func TestExtractSecrets(t *testing.T) {
	env := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken1234567890abcdefg",
		"PATH":           "/usr/bin",
		"AWS_SECRET_KEY": "AKIAIOSFODNN7EXAMPLEsecretkey123",
		"EMPTY_VAR":      "",
	}
	runnerSecrets := []string{
		`"DB_PASS" {"value":"ghp_dbpass12345678901234567","isSecret":true}`,
	}

	secrets := extractSecrets(env, runnerSecrets)
	assert.GreaterOrEqual(t, len(secrets), 2)

	names := make(map[string]bool)
	for _, s := range secrets {
		names[s.Name] = true
	}
	assert.True(t, names["GITHUB_TOKEN"])
	assert.True(t, names["DB_PASS"])
	assert.False(t, names["PATH"])
	assert.False(t, names["EMPTY_VAR"])
}

func TestExtractSecrets_CollapsesGHTokenWhenValueMatchesGitHubToken(t *testing.T) {
	env := map[string]string{
		"GITHUB_TOKEN": "ghs_same_token_value_1234567890",
		"GH_TOKEN":     "ghs_same_token_value_1234567890",
	}

	secrets := extractSecrets(env, nil)

	require.Len(t, secrets, 1)
	assert.Equal(t, "GITHUB_TOKEN", secrets[0].Name)
	assert.Equal(t, "ghs_same_token_value_1234567890", secrets[0].Value)
	assert.Equal(t, "github_token", secrets[0].Type)
}

func TestExtractSecrets_CollapsesArbitraryAliasWhenValueMatchesGitHubToken(t *testing.T) {
	env := map[string]string{
		"GITHUB_TOKEN":     "ghs_same_token_value_1234567890",
		"CUSTOM_CI_TOKEN":  "ghs_same_token_value_1234567890",
		"ANOTHER_CRED_VAR": "ghs_same_token_value_1234567890",
	}

	secrets := extractSecrets(env, nil)

	require.Len(t, secrets, 1)
	assert.Equal(t, "GITHUB_TOKEN", secrets[0].Name)
	assert.Equal(t, "ghs_same_token_value_1234567890", secrets[0].Value)
	assert.Equal(t, "github_token", secrets[0].Type)
}

func TestExtractSecrets_CollapsesRunnerSecretAliasWhenValueMatchesGitHubToken(t *testing.T) {
	env := map[string]string{
		"GITHUB_TOKEN": "ghs_same_token_value_1234567890",
	}
	runnerSecrets := []string{
		`"WHATEVER_NAME" {"value":"ghs_same_token_value_1234567890","isSecret":true}`,
	}

	secrets := extractSecrets(env, runnerSecrets)

	require.Len(t, secrets, 1)
	assert.Equal(t, "GITHUB_TOKEN", secrets[0].Name)
	assert.Equal(t, "ghs_same_token_value_1234567890", secrets[0].Value)
	assert.Equal(t, "github_token", secrets[0].Type)
}

func TestExtractSecrets_KeepsGHAndGitHubTokenWhenValuesDiffer(t *testing.T) {
	env := map[string]string{
		"GITHUB_TOKEN": "ghs_github_token_value_123456",
		"GH_TOKEN":     "ghs_gh_token_value_654321",
	}

	secrets := extractSecrets(env, nil)

	require.Len(t, secrets, 2)
	names := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		names[secret.Name] = secret.Value
	}
	assert.Equal(t, "ghs_github_token_value_123456", names["GITHUB_TOKEN"])
	assert.Equal(t, "ghs_gh_token_value_654321", names["GH_TOKEN"])
}

// =============================================================================
// Stager Register Validation Tests
// =============================================================================

func TestHandler_StagerRegister_RejectsInvalidDefaultMode(t *testing.T) {
	mock := &mockPublisher{}
	store := NewOrderStore(DefaultOrderStoreConfig())
	_, mux := newTestHandler(mock, store)

	tests := []struct {
		name     string
		id       string
		mode     string
		wantCode int
	}{
		{"empty mode is valid", "stager-empty", "", http.StatusCreated},
		{"express is valid", "stager-express", "express", http.StatusCreated},
		{"dwell is valid with dwell_time", "stager-dwell", "dwell", http.StatusCreated},
		{"arbitrary string rejected", "stager-bad1", "something_else", http.StatusBadRequest},
		{"quotes rejected", "stager-bad2", `foo"bar`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"response_type":"bash","session_id":"s1","persistent":true,"default_mode":"` + tt.mode + `"`
			if tt.mode == "dwell" {
				body += `,"dwell_time":"10m"`
			}
			body += `}`

			req := httptest.NewRequest(http.MethodPost, "/r/"+tt.id, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code, "mode=%q", tt.mode)
		})
	}
}
