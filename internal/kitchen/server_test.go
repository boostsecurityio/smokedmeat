// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
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
