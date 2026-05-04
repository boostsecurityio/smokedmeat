// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

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

func TestDecodeJSON_RejectsOversizedBody(t *testing.T) {
	body := paddedAuthJSON(t, `{"operator":"alice","pubkey_fp":"SHA256:abc","padding":"`, `"}`, authRequestMaxBodyBytes+1)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	var req ChallengeRequest
	err := decodeJSON(w, r, &req)
	require.Error(t, err, "decodeJSON must reject body larger than authRequestMaxBodyBytes")
	assertMaxBytesError(t, err)
}

func TestDecodeJSON_AcceptsBodyAtCap(t *testing.T) {
	body := paddedAuthJSON(t, `{"operator":"alice","pubkey_fp":"SHA256:abc","padding":"`, `"}`, authRequestMaxBodyBytes)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	var req ChallengeRequest
	require.NoError(t, decodeJSON(w, r, &req))
	assert.Equal(t, "alice", req.Operator)
	assert.Equal(t, "SHA256:abc", req.Fingerprint)
}

func TestDecodeJSON_RejectsTrailingJSON(t *testing.T) {
	body := []byte(`{"operator":"alice","pubkey_fp":"SHA256:abc"}{}`)
	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	var req ChallengeRequest
	require.Error(t, decodeJSON(w, r, &req))
}

func TestHandleAuthChallenge_OversizedBodyReturns401(t *testing.T) {
	server, _, fingerprint, _ := newAuthServerWithOperator(t)

	body := paddedAuthJSON(t, `{"operator":"alice","pubkey_fp":"`+fingerprint+`","padding":"`, `"}`, authRequestMaxBodyBytes+1)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handleAuthChallenge(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleAuthChallenge_BodyAtCapSucceeds(t *testing.T) {
	server, _, fingerprint, _ := newAuthServerWithOperator(t)

	body := paddedAuthJSON(t, `{"operator":"alice","pubkey_fp":"`+fingerprint+`","padding":"`, `"}`, authRequestMaxBodyBytes)

	r := httptest.NewRequest(http.MethodPost, "/auth/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handleAuthChallenge(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ChallengeResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	nonce, err := base64.StdEncoding.DecodeString(resp.Nonce)
	require.NoError(t, err)
	assert.Len(t, nonce, 32)
}

func TestHandleAuthVerify_OversizedBodyReturns401(t *testing.T) {
	server, signer, _, authProvider := newAuthServerWithOperator(t)
	nonce, signature := signedChallenge(t, authProvider, signer)

	body := paddedAuthJSON(t,
		`{"nonce":"`+base64.StdEncoding.EncodeToString(nonce)+`","signature":"`+base64.StdEncoding.EncodeToString(signature)+`","padding":"`,
		`"}`,
		authRequestMaxBodyBytes+1,
	)

	r := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handleAuthVerify(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	_, err := authProvider.VerifyChallenge(nonce, signature)
	require.NoError(t, err)
}

func TestHandleAuthVerify_BodyAtCapSucceeds(t *testing.T) {
	server, signer, _, authProvider := newAuthServerWithOperator(t)
	nonce, signature := signedChallenge(t, authProvider, signer)

	body := paddedAuthJSON(t,
		`{"nonce":"`+base64.StdEncoding.EncodeToString(nonce)+`","signature":"`+base64.StdEncoding.EncodeToString(signature)+`","padding":"`,
		`"}`,
		authRequestMaxBodyBytes,
	)

	r := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.handleAuthVerify(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp VerifyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "alice", resp.Operator)
	claims, err := authProvider.ValidateToken(resp.Token)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.OperatorID)
}

func paddedAuthJSON(t *testing.T, prefix, suffix string, size int64) []byte {
	t.Helper()

	paddingLen := int(size) - len(prefix) - len(suffix)
	require.GreaterOrEqual(t, paddingLen, 0)

	body := []byte(prefix + strings.Repeat("a", paddingLen) + suffix)
	require.Len(t, body, int(size))

	return body
}

func newAuthServerWithOperator(t *testing.T) (*Server, ssh.Signer, string, *auth.Auth) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	pubKey, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	keysData := "alice " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))) + "\n"
	authProvider, err := auth.New(auth.Config{AuthorizedKeysData: keysData})
	require.NoError(t, err)

	server := New(DefaultConfig())
	server.auth = authProvider

	return server, signer, ssh.FingerprintSHA256(pubKey), authProvider
}

func signedChallenge(t *testing.T, authProvider *auth.Auth, signer ssh.Signer) ([]byte, []byte) {
	t.Helper()

	nonce, err := authProvider.CreateChallenge("alice", ssh.FingerprintSHA256(signer.PublicKey()))
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)

	return nonce, ssh.Marshal(sig)
}

func assertMaxBytesError(t *testing.T, err error) {
	t.Helper()

	var maxBytesErr *http.MaxBytesError
	require.Truef(t, errors.As(err, &maxBytesErr), "expected MaxBytesError, got %T: %v", err, err)
}
