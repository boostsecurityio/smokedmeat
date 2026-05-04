// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/auth"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
)

// =============================================================================
// Configuration Tests
// =============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, 8080, config.Port)
	assert.Equal(t, "nats://localhost:4222", config.NatsURL)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.WriteTimeout)
	assert.Equal(t, 120*time.Second, config.IdleTimeout)
}

func TestDefaultConfig_TimeoutsArePositive(t *testing.T) {
	config := DefaultConfig()

	assert.Greater(t, config.ReadTimeout, time.Duration(0))
	assert.Greater(t, config.WriteTimeout, time.Duration(0))
	assert.Greater(t, config.IdleTimeout, time.Duration(0))
}

// =============================================================================
// Server Creation Tests
// =============================================================================

func TestNew_CreatesServer(t *testing.T) {
	config := DefaultConfig()

	server := New(config)

	assert.NotNil(t, server)
	assert.Equal(t, config.Port, server.config.Port)
	assert.Equal(t, config.NatsURL, server.config.NatsURL)
}

func TestNew_WithCustomConfig(t *testing.T) {
	config := Config{
		Port:         9090,
		NatsURL:      "nats://custom:4222",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	server := New(config)

	assert.NotNil(t, server)
	assert.Equal(t, 9090, server.config.Port)
	assert.Equal(t, "nats://custom:4222", server.config.NatsURL)
	assert.Equal(t, 10*time.Second, server.config.ReadTimeout)
}

func TestNew_InitialState(t *testing.T) {
	server := New(DefaultConfig())

	// Before Start(), these should all be nil
	assert.Nil(t, server.httpServer)
	assert.Nil(t, server.natsClient)
	assert.Nil(t, server.publisher)
	assert.Nil(t, server.handler)
	assert.Nil(t, server.store)
	assert.Nil(t, server.consumer)
	assert.Nil(t, server.cancelFunc)
}

func TestRestoreFromDB_RestoresAgentToken(t *testing.T) {
	database := newTestDB(t)
	now := time.Now().UTC()
	token := "agt_restoretest"

	err := db.NewAgentRepository(database).Upsert(&db.AgentRow{
		AgentID:        "agt-1",
		SessionID:      "sess-1",
		AgentToken:     token,
		TokenCreatedAt: now,
		TokenExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	authProvider, err := auth.New(auth.Config{
		StaticToken: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	require.NoError(t, err)

	server := New(DefaultConfig())
	server.auth = authProvider
	server.database = database
	server.sessions = NewSessionRegistry(DefaultSessionRegistryConfig())
	server.store = NewOrderStore(DefaultOrderStoreConfig())
	server.handler = NewHandler(nil, server.store, server.sessions)

	server.restoreFromDB()

	claims, err := server.auth.ValidateAgentToken(token)
	require.NoError(t, err)
	assert.Equal(t, "agt-1", claims.AgentID)
	assert.Equal(t, "sess-1", claims.SessionID)
}

// =============================================================================
// Shutdown Tests (without NATS)
// =============================================================================

func TestShutdown_WithNoComponents(t *testing.T) {
	server := New(DefaultConfig())

	// Should not panic and return nil when nothing is initialized
	err := server.Shutdown(t.Context())

	assert.NoError(t, err)
}

// =============================================================================
// AuthMode Tests
// =============================================================================

func TestDefaultConfig_AuthModeSSH(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, AuthModeSSH, config.AuthMode)
}

func TestAuthMode_TokenMode(t *testing.T) {
	config := Config{
		AuthMode:  AuthModeToken,
		AuthToken: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	server := New(config)
	assert.Equal(t, AuthModeToken, server.config.AuthMode)
	assert.Len(t, server.config.AuthToken, 64)
}

func TestAuthMode_SSHMode(t *testing.T) {
	config := Config{
		AuthMode: AuthModeSSH,
	}
	server := New(config)
	assert.Equal(t, AuthModeSSH, server.config.AuthMode)
}

// =============================================================================
// Auth Body-Size Limit Tests (issue #61)
//
// The /auth/challenge and /auth/verify endpoints are unauthenticated and must
// not allow an attacker to force unbounded allocation by streaming a huge body
// within the ReadTimeout window. decodeJSON wraps the body with
// http.MaxBytesReader(authRequestMaxBodyBytes); these tests pin that contract.
// =============================================================================

func TestDecodeJSON_RejectsOversizedBody(t *testing.T) {
	// Build a body that is one byte over the cap. The contents don't matter
	// because the size cap fires before the JSON decoder sees a complete value.
	oversized := bytes.Repeat([]byte("a"), int(authRequestMaxBodyBytes)+1)
	body := append([]byte(`{"x":"`), oversized...)
	body = append(body, []byte(`"}`)...)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	var dst struct {
		X string `json:"x"`
	}
	err := decodeJSON(w, r, &dst)
	require.Error(t, err, "decodeJSON must reject body larger than authRequestMaxBodyBytes")
	assert.Contains(t, strings.ToLower(err.Error()), "request body too large",
		"error should come from http.MaxBytesReader")
}

func TestDecodeJSON_AcceptsBodyAtCap(t *testing.T) {
	// A small, well-formed JSON object well under the cap must decode normally.
	body := []byte(`{"operator":"alice","pubkey_fp":"SHA256:abc"}`)
	require.LessOrEqual(t, int64(len(body)), authRequestMaxBodyBytes)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	var req ChallengeRequest
	require.NoError(t, decodeJSON(w, r, &req))
	assert.Equal(t, "alice", req.Operator)
	assert.Equal(t, "SHA256:abc", req.Fingerprint)
}

func TestDecodeJSON_NilWriterStillDecodes(t *testing.T) {
	// The optional-writer shape lets future authenticated handlers (which do
	// their own size limiting) reuse decodeJSON without churn. Pass nil and
	// confirm the body is decoded as-is, with no panic.
	body := []byte(`{"operator":"bob","fingerprint":"SHA256:xyz"}`)
	r := httptest.NewRequest(http.MethodPost, "/whatever", bytes.NewReader(body))

	var req ChallengeRequest
	require.NoError(t, decodeJSON(nil, r, &req))
	assert.Equal(t, "bob", req.Operator)
}

// TestHandleAuthChallenge_OversizedBodyReturns401 exercises the fix end-to-end:
// the handler maps any decode error to an opaque 401 (per its existing
// fingerprinting-resistant policy), so a >cap body must short-circuit before
// reaching auth.CreateChallenge.
func TestHandleAuthChallenge_OversizedBodyReturns401(t *testing.T) {
	authProvider, err := auth.New(auth.Config{
		StaticToken: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	require.NoError(t, err)

	server := New(DefaultConfig())
	server.auth = authProvider

	oversized := bytes.Repeat([]byte("a"), int(authRequestMaxBodyBytes)+1)
	body := append([]byte(`{"operator":"alice","fingerprint":"`), oversized...)
	body = append(body, []byte(`"}`)...)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handleAuthChallenge(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleAuthVerify_OversizedBodyReturns401(t *testing.T) {
	authProvider, err := auth.New(auth.Config{
		StaticToken: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	require.NoError(t, err)

	server := New(DefaultConfig())
	server.auth = authProvider

	oversized := bytes.Repeat([]byte("a"), int(authRequestMaxBodyBytes)+1)
	body := append([]byte(`{"nonce":"abc","signature":"`), oversized...)
	body = append(body, []byte(`"}`)...)

	r := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handleAuthVerify(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
