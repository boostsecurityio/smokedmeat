// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kitchen implements the C2 server (HTTP-to-NATS bridge).
// In deli terms: The Kitchen is where orders are prepared and managed.
package kitchen

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/auth"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pass"
)

// AuthMode specifies the authentication mode for operator access.
type AuthMode string

const (
	// AuthModeSSH uses SSH challenge-response authentication (default, production).
	AuthModeSSH AuthMode = "ssh"
	// AuthModeToken uses a shared secret token (quickstart/E2E).
	AuthModeToken AuthMode = "token"
)

// Config holds configuration for the Kitchen server.
type Config struct {
	// Port is the HTTP server port.
	Port int

	// NatsURL is the NATS server URL.
	NatsURL string

	// DBPath is the path to the SQLite database file.
	// Use ":memory:" for in-memory database (testing).
	// Empty string disables persistence.
	DBPath string

	// ReadTimeout is the HTTP read timeout.
	ReadTimeout time.Duration

	// WriteTimeout is the HTTP write timeout.
	WriteTimeout time.Duration

	// IdleTimeout is the HTTP idle timeout.
	IdleTimeout time.Duration

	// AuthorizedKeysPath is the path to the authorized_keys file for operator authentication.
	// Format: <operator_name> <key_type> <public_key> <comment>
	// Example: alice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop
	AuthorizedKeysPath string

	// AuthMode specifies the authentication mode: "ssh" (default) or "token".
	// SSH mode uses challenge-response with authorized_keys.
	// Token mode uses a shared secret (AUTH_TOKEN env var) for quickstart/E2E.
	AuthMode AuthMode

	// AuthToken is the shared secret token when AuthMode is "token".
	// Must be a 64-character hex string (256 bits of entropy).
	AuthToken string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:               8080,
		NatsURL:            "nats://localhost:4222",
		DBPath:             "data/kitchen.db",
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		IdleTimeout:        120 * time.Second,
		AuthMode:           AuthModeSSH,
		AuthorizedKeysPath: defaultAuthorizedKeysPath(),
	}
}

func defaultAuthorizedKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}
	return filepath.Join(home, ".smokedmeat", "authorized_keys")
}

// Server is the Kitchen C2 server.
type Server struct {
	config     Config
	httpServer *http.Server
	natsClient *pass.Client
	publisher  *pass.Publisher
	handler    *Handler
	store      *OrderStore
	consumer   *pass.Consumer
	sessions   *SessionRegistry
	operators  *OperatorHub
	graphHub   *GraphHub
	auth       *auth.Auth
	cancelFunc context.CancelFunc
	database   *db.DB
}

// New creates a new Kitchen server.
func New(config Config) *Server {
	return &Server{
		config: config,
	}
}

// Start starts the Kitchen server.
func (s *Server) Start(ctx context.Context) error {
	var err error

	// Initialize auth based on mode
	authConfig := auth.Config{
		TokenExpiry:     24 * time.Hour,
		ChallengeExpiry: 5 * time.Minute,
	}

	if s.config.AuthMode == AuthModeToken {
		if s.config.AuthToken == "" {
			return fmt.Errorf("AUTH_TOKEN required when AUTH_MODE=token")
		}
		if len(s.config.AuthToken) != 64 {
			return fmt.Errorf("AUTH_TOKEN must be 64 hex characters (got %d)", len(s.config.AuthToken))
		}
		authConfig.StaticToken = s.config.AuthToken
		slog.Info("auth mode: token (shared secret)")
	} else {
		authConfig.AuthorizedKeysPath = s.config.AuthorizedKeysPath
		slog.Info("auth mode: ssh (challenge-response)", "keys_path", s.config.AuthorizedKeysPath)
	}

	s.auth, err = auth.New(authConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize auth: %w", err)
	}

	if s.config.AuthMode == AuthModeSSH {
		operators := s.auth.ListOperators()
		if len(operators) == 0 {
			slog.Warn("ssh auth enabled but no operators configured",
				"keys_path", s.config.AuthorizedKeysPath)
		} else {
			for _, op := range operators {
				slog.Info("operator loaded", "name", op.Name, "fingerprint", op.Fingerprint)
			}
		}
	}

	if s.config.DBPath != "" {
		dbConfig := db.Config{Path: s.config.DBPath, CreateDir: true}
		s.database, err = db.Open(dbConfig)
		if err != nil {
			return fmt.Errorf("failed to open database: %w", err)
		}
		slog.Info("database opened", "path", s.config.DBPath)
	}

	natsConfig := pass.DefaultConfig(s.config.NatsURL)
	natsConfig.Name = "smokedmeat-kitchen"

	s.natsClient, err = pass.NewClient(ctx, natsConfig)
	if err != nil {
		s.closeDB()
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	_, err = s.natsClient.EnsureStream(ctx, pass.DefaultStreamConfig())
	if err != nil {
		s.natsClient.Close()
		s.closeDB()
		return fmt.Errorf("failed to ensure stream: %w", err)
	}

	s.store = NewOrderStore(DefaultOrderStoreConfig())
	s.sessions = NewSessionRegistry(DefaultSessionRegistryConfig())
	s.publisher = pass.NewPublisher(s.natsClient)
	s.operators = NewOperatorHub(s.publisher, s.store, s.database)
	s.handler = NewHandler(s.publisher, s.store, s.sessions)

	if s.database != nil {
		// restoreFromDB repopulates handler-owned stagers and callbacks.
		s.restoreFromDB()
	}

	consumerConfig := pass.ConsumerConfig{
		StreamName:    "SMOKEDMEAT",
		ConsumerName:  "kitchen-orders",
		FilterSubject: pass.SubjectOrdersPrefix + ".>",
		Durable:       true,
	}
	s.consumer, err = pass.NewConsumer(ctx, s.natsClient, consumerConfig)
	if err != nil {
		s.natsClient.Close()
		return fmt.Errorf("failed to create orders consumer: %w", err)
	}

	consumerCtx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel
	go s.consumeOrders(consumerCtx)
	go s.store.StartCleanup(consumerCtx)
	go s.runAgentStatusUpdater(consumerCtx)

	s.handler.SetDatabase(s.database)
	s.handler.SetOperatorHub(s.operators)
	s.handler.SetAuth(s.auth)

	// Create GraphHub for real-time graph visualization
	s.graphHub = NewGraphHub(s.handler.Pantry())

	mux := http.NewServeMux()

	// Auth routes (SSH challenge-response) - always public
	mux.HandleFunc("POST /auth/challenge", s.handleAuthChallenge)
	mux.HandleFunc("POST /auth/verify", s.handleAuthVerify)

	// Health check - always public
	mux.HandleFunc("GET /health", s.handler.handleHealth)

	audit := auth.NewStructuredAuditLogger(slog.Default())
	opAuth := auth.RequireOperatorAuth(s.auth, audit)
	agentAuth := auth.RequireAgentAuth(s.auth, audit)
	stagerAuth := auth.RequireStagerAuth(s.handler.StagerStore(), audit)

	// Homepage - requires operator auth
	mux.Handle("GET /", opAuth(http.HandlerFunc(s.handleHomepage)))

	// Operator routes (require operator auth - token or SSH-based)
	mux.Handle("GET /ws", opAuth(http.HandlerFunc(s.operators.HandleWebSocket)))
	mux.Handle("POST /analyze", opAuth(http.HandlerFunc(s.handler.handleAnalyze)))
	mux.Handle("POST /github/deploy/pr", opAuth(http.HandlerFunc(s.handler.handleGitHubDeployPR)))
	mux.Handle("POST /github/deploy/issue", opAuth(http.HandlerFunc(s.handler.handleGitHubDeployIssue)))
	mux.Handle("POST /github/deploy/comment", opAuth(http.HandlerFunc(s.handler.handleGitHubDeployComment)))
	mux.Handle("POST /github/deploy/lotp", opAuth(http.HandlerFunc(s.handler.handleGitHubDeployLOTP)))
	mux.Handle("POST /github/deploy/dispatch", opAuth(http.HandlerFunc(s.handler.handleGitHubDeployDispatch)))
	mux.Handle("POST /github/deploy/preflight", opAuth(http.HandlerFunc(s.handler.handleGitHubDeployPreflight)))
	mux.Handle("POST /github/repos", opAuth(http.HandlerFunc(s.handler.handleGitHubListRepos)))
	mux.Handle("POST /github/repos/info", opAuth(http.HandlerFunc(s.handler.handleGitHubListReposWithInfo)))
	mux.Handle("POST /github/workflows", opAuth(http.HandlerFunc(s.handler.handleGitHubListWorkflows)))
	mux.Handle("POST /github/user", opAuth(http.HandlerFunc(s.handler.handleGitHubGetUser)))
	mux.Handle("POST /github/token/info", opAuth(http.HandlerFunc(s.handler.handleGitHubTokenInfo)))
	mux.Handle("POST /github/app/installations", opAuth(http.HandlerFunc(s.handler.handleGitHubAppInstallations)))
	mux.Handle("POST /github/app/token", opAuth(http.HandlerFunc(s.handler.handleGitHubAppToken)))
	mux.Handle("POST /cache-poison/prepare", opAuth(http.HandlerFunc(s.handler.handlePrepareCachePoison)))
	mux.Handle("GET /pantry", opAuth(http.HandlerFunc(s.handler.handleGetPantry)))
	mux.Handle("GET /history", opAuth(http.HandlerFunc(s.handler.handleGetHistory)))
	mux.Handle("POST /history", opAuth(http.HandlerFunc(s.handler.handlePostHistory)))
	mux.Handle("GET /callbacks", opAuth(http.HandlerFunc(s.handler.handleGetCallbacks)))
	mux.Handle("POST /callbacks/{callbackID}", opAuth(http.HandlerFunc(s.handler.handlePostCallback)))
	mux.Handle("GET /known-entities", opAuth(http.HandlerFunc(s.handler.handleGetKnownEntities)))
	mux.Handle("POST /known-entities", opAuth(http.HandlerFunc(s.handler.handlePostKnownEntities)))

	// Graph visualization (require operator auth)
	mux.Handle("GET /graph", opAuth(http.HandlerFunc(s.handler.handleGraph)))
	mux.Handle("GET /graph/data", opAuth(http.HandlerFunc(s.handler.handleGraphData)))
	mux.Handle("GET /graph/ws", opAuth(http.HandlerFunc(s.graphHub.HandleWebSocket)))

	// Stager registration (require operator auth)
	mux.Handle("POST /r/{stagerID}", opAuth(http.HandlerFunc(s.handler.handleStagerRegister)))

	// Stager callback (require valid stager ID)
	mux.Handle("GET /r/{stagerID}", stagerAuth(http.HandlerFunc(s.handler.handleStager)))

	// Agent routes (require agent token)
	mux.Handle("GET /agent/{filename}", agentAuth(http.HandlerFunc(s.handler.handleAgentDownload)))
	mux.Handle("POST /b/{agentID}", agentAuth(http.HandlerFunc(s.handler.handleBeacon)))
	mux.Handle("GET /b/{agentID}", agentAuth(http.HandlerFunc(s.handler.handlePoll)))

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Port),
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	errChan := make(chan error, 1)
	go func() {
		slog.Info("kitchen listening", "port", s.config.Port)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errChan:
		return err
	}
}

// consumeOrders consumes orders from NATS and adds them to the store.
func (s *Server) consumeOrders(ctx context.Context) {
	cc, err := s.consumer.ConsumeWithTimeout(pass.DefaultCallbackTimeout, func(_ context.Context, msg jetstream.Msg) {
		order, err := models.UnmarshalOrder(msg.Data())
		if err != nil {
			slog.Error("failed to parse order", "error", err)
			_ = msg.Nak()
			return
		}

		if order.AgentID == "" {
			slog.Warn("order missing agent_id", "order_id", order.OrderID)
			_ = msg.Nak()
			return
		}

		if err := s.store.Add(order); err != nil {
			slog.Error("failed to store order", "order_id", order.OrderID, "error", err)
			_ = msg.Ack() // queue might be full, retrying won't help
			return
		}

		slog.Debug("queued order", "order_id", order.OrderID, "agent_id", order.AgentID)
		_ = msg.Ack()
	})

	if err != nil {
		slog.Error("failed to start order consumer", "error", err)
		return
	}

	<-ctx.Done()
	cc.Stop()
}

// runAgentStatusUpdater periodically updates agent online/offline status.
func (s *Server) runAgentStatusUpdater(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sessions.UpdateAgentOnlineStatus()
		}
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down kitchen")

	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	var errs []error

	if s.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("HTTP shutdown: %w", err))
		}
	}

	if s.natsClient != nil {
		s.natsClient.Close()
	}

	if s.handler != nil {
		if err := s.handler.SavePantry(); err != nil {
			slog.Warn("failed to save pantry on shutdown", "error", err)
		} else {
			slog.Info("pantry saved on shutdown")
		}
	}

	s.closeDB()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// closeDB closes the database connection.
func (s *Server) closeDB() {
	if s.database != nil {
		if err := s.database.Close(); err != nil {
			slog.Error("failed to close database", "error", err)
		}
		s.database = nil
	}
}

// restoreFromDB restores state from the database.
func (s *Server) restoreFromDB() {
	agentRepo := db.NewAgentRepository(s.database)
	sessionRepo := db.NewSessionRepository(s.database)

	sessions, err := sessionRepo.List()
	if err != nil {
		slog.Warn("failed to restore sessions", "error", err)
	} else {
		for _, session := range sessions {
			s.sessions.GetOrCreateSession(session.ID)
			slog.Debug("restored session", "session_id", session.ID)
		}
	}

	agentRows, err := agentRepo.List()
	if err != nil {
		slog.Warn("failed to restore agents", "error", err)
	} else {
		for _, row := range agentRows {
			s.sessions.UpdateAgentBeacon(row.AgentID, row.SessionID, row.Hostname, row.OS, row.Arch)
			agentState := s.sessions.GetAgent(row.AgentID)
			if agentState != nil {
				agentState.FirstSeen = row.FirstSeen
				agentState.LastSeen = row.LastSeen
				agentState.IsOnline = row.IsOnline
			}
			slog.Debug("restored agent", "agent_id", row.AgentID, "session_id", row.SessionID)
		}
	}

	orderRepo := db.NewOrderRepository(s.database)
	pendingOrders, err := orderRepo.ListPending()
	if err != nil {
		slog.Warn("failed to restore orders", "error", err)
	} else {
		for _, order := range pendingOrders {
			if addErr := s.store.Add(order); addErr != nil {
				slog.Warn("failed to restore order", "order_id", order.OrderID, "error", addErr)
			} else {
				slog.Debug("restored order", "order_id", order.OrderID, "agent_id", order.AgentID)
			}
		}
	}

	stagerRepo := db.NewStagerRepository(s.database)
	stagerRows, err := stagerRepo.List()
	if err != nil {
		slog.Warn("failed to restore callbacks", "error", err)
	} else {
		for _, row := range stagerRows {
			stager := registeredStagerFromRow(row)
			if registerErr := s.handler.stagerStore.Register(stager); registerErr != nil {
				slog.Warn("failed to restore callback", "callback_id", row.ID, "error", registerErr)
			}
		}
	}

	slog.Info("state restored from database",
		"sessions", len(sessions),
		"agents", len(agentRows),
		"pending_orders", len(pendingOrders),
		"callbacks", len(stagerRows),
	)
}

// handleHomepage returns the Kitchen banner for authenticated operators.
func (s *Server) handleHomepage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Something's smoking in the kitchen."))
}

// ChallengeRequest is the request body for POST /auth/challenge.
type ChallengeRequest struct {
	Operator    string `json:"operator"`
	Fingerprint string `json:"pubkey_fp"`
}

// ChallengeResponse is the response body for POST /auth/challenge.
type ChallengeResponse struct {
	Nonce string `json:"nonce"`
}

// VerifyRequest is the request body for POST /auth/verify.
type VerifyRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// VerifyResponse is the response body for POST /auth/verify.
type VerifyResponse struct {
	Token    string `json:"token"`
	Operator string `json:"operator"`
}

// handleAuthChallenge handles POST /auth/challenge - initiates SSH challenge-response auth.
// Returns opaque 401 for any failure to prevent fingerprinting.
func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	var req ChallengeRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if req.Operator == "" || req.Fingerprint == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	nonce, err := s.auth.CreateChallenge(req.Operator, req.Fingerprint)
	if err != nil {
		slog.Debug("challenge creation failed", "error", err, "operator", req.Operator)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	slog.Debug("challenge created", "operator", req.Operator)

	w.Header().Set("Content-Type", "application/json")
	resp := ChallengeResponse{
		Nonce: encodeBase64(nonce),
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAuthVerify handles POST /auth/verify - verifies signed challenge.
// Returns opaque 401 for any failure to prevent fingerprinting.
func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if req.Nonce == "" || req.Signature == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	nonce, err := decodeBase64(req.Nonce)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	signature, err := decodeBase64(req.Signature)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := s.auth.VerifyChallenge(nonce, signature)
	if err != nil {
		slog.Debug("challenge verification failed", "error", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claims, _ := s.auth.ValidateToken(token)
	operatorName := ""
	if claims != nil {
		operatorName = claims.OperatorID
	}

	slog.Info("operator authenticated via SSH challenge-response", "operator", operatorName)

	w.Header().Set("Content-Type", "application/json")
	resp := VerifyResponse{
		Token:    token,
		Operator: operatorName,
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeJSON decodes JSON from the request body.
func decodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// writeJSON writes JSON to the response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// encodeBase64 encodes bytes to base64 string.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes a base64 string to bytes.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
