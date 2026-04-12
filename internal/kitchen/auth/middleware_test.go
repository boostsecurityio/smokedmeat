// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuthWithToken(t *testing.T) (*Auth, string) {
	t.Helper()
	_, pubKey := generateTestKey(t)
	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	a, err := New(Config{AuthorizedKeysData: keysData})
	require.NoError(t, err)

	token, err := a.GenerateToken("alice", "")
	require.NoError(t, err)
	return a, token
}

func TestExtractToken_Bearer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer mytoken123")
	assert.Equal(t, "mytoken123", extractToken(r))
}

func TestExtractToken_QueryParam(t *testing.T) {
	r := httptest.NewRequest("GET", "/?token=qptoken", nil)
	assert.Equal(t, "qptoken", extractToken(r))
}

func TestExtractToken_Empty(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	assert.Empty(t, extractToken(r))
}

func TestExtractToken_BearerTakesPrecedence(t *testing.T) {
	r := httptest.NewRequest("GET", "/?token=qp", nil)
	r.Header.Set("Authorization", "Bearer bearer")
	assert.Equal(t, "bearer", extractToken(r))
}

type mockAuditLogger struct {
	events []SecurityEvent
}

func (m *mockAuditLogger) LogSecurityEvent(event SecurityEvent) {
	m.events = append(m.events, event)
}

func TestRequireOperatorAuth_NoToken(t *testing.T) {
	a, _ := setupAuthWithToken(t)
	audit := &mockAuditLogger{}
	handler := RequireOperatorAuth(a, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/test", nil))
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Len(t, audit.events, 1)
	assert.Equal(t, EventAuthFailure, audit.events[0].EventType)
	assert.Equal(t, PrincipalUnknown, audit.events[0].Principal)
}

func TestRequireOperatorAuth_ValidToken(t *testing.T) {
	a, token := setupAuthWithToken(t)
	audit := &mockAuditLogger{}
	handler := RequireOperatorAuth(a, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(ClaimsKey).(*Claims)
		assert.Equal(t, "alice", claims.OperatorID)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, audit.events)
}

func TestRequireAgentAuth_NoToken(t *testing.T) {
	a, _ := setupAuthWithToken(t)
	audit := &mockAuditLogger{}
	handler := RequireAgentAuth(a, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/b/agent1", nil))
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Len(t, audit.events, 1)
	assert.Equal(t, EventAgentTokenInvalid, audit.events[0].EventType)
}

func TestRequireAgentAuth_ValidToken(t *testing.T) {
	a, _ := setupAuthWithToken(t)
	agentToken, err := a.GenerateAgentToken("agent1", "sess1")
	require.NoError(t, err)

	audit := &mockAuditLogger{}
	handler := RequireAgentAuth(a, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := r.Context().Value(AgentClaimsKey).(*AgentClaims)
		require.NotNil(t, claims)
		assert.Equal(t, "agent1", claims.AgentID)
		assert.Equal(t, "sess1", claims.SessionID)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/b/agent1", nil)
	r.Header.Set(AgentTokenHeader, agentToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, audit.events)
}

type mockStagerValidator struct {
	sessionID string
	expired   bool
	exists    bool
}

func (m *mockStagerValidator) ValidateStager(id string) (string, bool, bool) {
	return m.sessionID, m.expired, m.exists
}

func TestRequireStagerAuth_MissingID(t *testing.T) {
	audit := &mockAuditLogger{}
	validator := &mockStagerValidator{}
	handler := RequireStagerAuth(validator, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/r/smokedmeat/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRequireStagerAuth_NotFound(t *testing.T) {
	audit := &mockAuditLogger{}
	validator := &mockStagerValidator{exists: false}

	mux := http.NewServeMux()
	mux.Handle("GET /r/smokedmeat/{stagerID}", RequireStagerAuth(validator, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	r := httptest.NewRequest("GET", "/r/smokedmeat/unknown123", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Len(t, audit.events, 1)
	assert.Equal(t, EventStagerNotFound, audit.events[0].EventType)
}

func TestRequireStagerAuth_Expired(t *testing.T) {
	audit := &mockAuditLogger{}
	validator := &mockStagerValidator{exists: true, expired: true}

	mux := http.NewServeMux()
	mux.Handle("GET /r/smokedmeat/{stagerID}", RequireStagerAuth(validator, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	r := httptest.NewRequest("GET", "/r/smokedmeat/stg_abc", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Len(t, audit.events, 1)
	assert.Equal(t, EventStagerExpired, audit.events[0].EventType)
}

func TestRequireStagerAuth_Valid(t *testing.T) {
	audit := &mockAuditLogger{}
	validator := &mockStagerValidator{exists: true, expired: false, sessionID: "s1"}

	mux := http.NewServeMux()
	mux.Handle("GET /r/smokedmeat/{stagerID}", RequireStagerAuth(validator, audit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	r := httptest.NewRequest("GET", "/r/smokedmeat/stg_valid", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, audit.events)
}

func TestGenerateSecureID(t *testing.T) {
	id, err := GenerateSecureID(PrefixAgent)
	require.NoError(t, err)
	assert.True(t, len(id) == len(PrefixAgent)+idLength)
	assert.Equal(t, PrefixAgent, id[:len(PrefixAgent)])

	id2, err := GenerateSecureID(PrefixStager)
	require.NoError(t, err)
	assert.Equal(t, PrefixStager, id2[:len(PrefixStager)])
	assert.NotEqual(t, id[len(PrefixAgent):], id2[len(PrefixStager):])
}

func TestGenerateAgentToken(t *testing.T) {
	a, _ := New(DefaultConfig())
	require.NotNil(t, a)

	token, err := a.GenerateAgentToken("agent1", "session1")
	require.NoError(t, err)
	assert.True(t, len(token) > len(PrefixAgent))

	claims, err := a.ValidateAgentToken(token)
	require.NoError(t, err)
	assert.Equal(t, "agent1", claims.AgentID)
	assert.Equal(t, "session1", claims.SessionID)
}

func TestRevokeAgentToken(t *testing.T) {
	a, _ := New(DefaultConfig())
	token, err := a.GenerateAgentToken("agent1", "session1")
	require.NoError(t, err)

	assert.True(t, a.RevokeAgentToken(token))
	assert.False(t, a.RevokeAgentToken(token))

	_, err = a.ValidateAgentToken(token)
	assert.ErrorIs(t, err, ErrInvalidAgentToken)
}

func TestValidateAgentToken_Invalid(t *testing.T) {
	a, _ := New(DefaultConfig())
	_, err := a.ValidateAgentToken("agt_nonexistent")
	assert.ErrorIs(t, err, ErrInvalidAgentToken)
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		expected string
	}{
		{"x-forwarded-for", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "9.9.9.9:1234", "1.2.3.4"},
		{"x-real-ip", map[string]string{"X-Real-IP": "5.6.7.8"}, "9.9.9.9:1234", "5.6.7.8"},
		{"remote addr fallback", map[string]string{}, "10.0.0.1:5555", "10.0.0.1:5555"},
		{"xff takes precedence", map[string]string{"X-Forwarded-For": "1.1.1.1", "X-Real-IP": "2.2.2.2"}, "3.3.3.3:80", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			assert.Equal(t, tt.expected, extractClientIP(r))
		})
	}
}

func TestNewSecurityEventFromRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/verify", nil)
	r.RemoteAddr = "10.0.0.1:4444"
	r.Header.Set("User-Agent", "brisket/1.0")

	event := NewSecurityEventFromRequest(r, EventAuthFailure, PrincipalOperator, "bad sig")
	assert.Equal(t, EventAuthFailure, event.EventType)
	assert.Equal(t, "10.0.0.1:4444", event.ClientIP)
	assert.Equal(t, "/auth/verify", event.Path)
	assert.Equal(t, "POST", event.Method)
	assert.Equal(t, PrincipalOperator, event.Principal)
	assert.Equal(t, "bad sig", event.Reason)
	assert.Equal(t, "brisket/1.0", event.UserAgent)
	assert.False(t, event.Timestamp.IsZero())
}

func TestNewStructuredAuditLogger(t *testing.T) {
	logger := slog.Default()
	audit := NewStructuredAuditLogger(logger)
	assert.NotNil(t, audit)

	audit.LogSecurityEvent(SecurityEvent{
		EventType: EventAuthFailure,
		Principal: PrincipalOperator,
		Reason:    "test",
	})
}
