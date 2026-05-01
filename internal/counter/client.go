// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package counter implements the Counter TUI operator interface.
package counter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

// KitchenAPI defines the interface for Kitchen client operations used by the TUI.
type KitchenAPI interface {
	PublishOrder(ctx context.Context, order *models.Order) error
	FetchPantry(ctx context.Context) (*pantry.Pantry, error)
	FetchHistory(ctx context.Context, limit int) ([]HistoryPayload, error)
	RecordHistory(ctx context.Context, entry HistoryPayload) error
	FetchCallbacks(ctx context.Context, sessionID string) ([]CallbackPayload, error)
	ControlCallback(ctx context.Context, callbackID string, request CallbackControlRequest) (*CallbackPayload, error)
	FetchKnownEntities(ctx context.Context, sessionID string) ([]KnownEntityPayload, error)
	RecordKnownEntity(ctx context.Context, entity KnownEntityPayload) error
	Purge(ctx context.Context, req PurgeRequest) (*PurgeResponse, error)
	StartConsuming() error
	IsConnected() bool
	Close()
	Reconnect(ctx context.Context) error
	DeployPR(ctx context.Context, req DeployPRRequest) (DeployPRResponse, error)
	DeployIssue(ctx context.Context, req DeployIssueRequest) (DeployIssueResponse, error)
	DeployComment(ctx context.Context, req DeployCommentRequest) (DeployCommentResponse, error)
	DeployLOTP(ctx context.Context, req DeployLOTPRequest) (DeployLOTPResponse, error)
	DeploySelfHostedCallbackPR(ctx context.Context, req DeploySelfHostedCallbackPRRequest) (DeploySelfHostedCallbackPRResponse, error)
	DeploySelfHostedWorkflowPush(ctx context.Context, req DeploySelfHostedWorkflowPushRequest) (DeploySelfHostedWorkflowPushResponse, error)
	TriggerDispatch(ctx context.Context, req DeployDispatchRequest) error
	FetchDeployPreflight(ctx context.Context, req DeployPreflightRequest) (*DeployPreflightResponse, error)
	ListReposWithInfo(ctx context.Context, token string) ([]RepoInfo, error)
	ListWorkflowsWithDispatch(ctx context.Context, token, owner, repo string) ([]DispatchableWorkflow, error)
	GetAuthenticatedUser(ctx context.Context, token string) (GetUserResponse, error)
	FetchTokenInfo(ctx context.Context, token, source string) (*FetchTokenInfoResponse, error)
	ListAppInstallations(ctx context.Context, pem, appID string) ([]AppInstallation, error)
	CreateInstallationToken(ctx context.Context, pem, appID string, installationID int64) (*CreateInstallationTokenResponse, error)
	RegisterCallback(ctx context.Context, stagerID string, req RegisterCallbackRequest) (*RegisterCallbackResponse, error)
	PrepareCachePoisonDeployment(ctx context.Context, req PrepareCachePoisonRequest) (*PrepareCachePoisonResponse, error)
	SetCallbacks(onBeacon func(Beacon), onColeslaw func(*models.Coleslaw), onError func(error))
	SetEventCallback(onEvent func(KitchenEvent))
	SetHistoryCallback(onHistory func(HistoryPayload))
	SetExpressDataCallback(onExpressData func(ExpressDataPayload))
	SetLootSyncCallback(onLootSync func(LootSyncPayload))
	SetAnalysisProgressCallback(onAnalysisProgress func(AnalysisProgressPayload))
	SetAnalysisMetadataSyncCallback(onAnalysisMetadataSync func(AnalysisMetadataSyncPayload))
	SetAuthExpiredCallback(onAuthExpired func())
	SetReconnectCallbacks(onReconnecting func(attempt int), onReconnected func())
}

// KitchenClient manages WebSocket connection to the Kitchen C2 server.
// This replaces direct NATS connection for production deployments.
type KitchenClient struct {
	mu          sync.RWMutex
	kitchenURL  string
	sessionID   string
	token       string
	conn        *websocket.Conn
	connected   bool
	ctx         context.Context
	cancel      context.CancelFunc
	reconnectCh chan struct{}
	stopCh      chan struct{}

	// Reconnection state
	reconnecting   bool
	reconnectDelay time.Duration

	// Callbacks
	onBeacon           func(beacon Beacon)
	onColeslaw         func(coleslaw *models.Coleslaw)
	onError            func(err error)
	onEvent            func(event KitchenEvent)
	onHistory          func(history HistoryPayload)
	onExpressData      func(data ExpressDataPayload)
	onLootSync         func(sync LootSyncPayload)
	onAnalysisProgress func(progress AnalysisProgressPayload)
	onAnalysisMetadata func(sync AnalysisMetadataSyncPayload)
	onAuthExpired      func()
	onReconnecting     func(attempt int)
	onReconnected      func()
}

const (
	AnalysisMetadataSyncStatusStarted   = "started"
	AnalysisMetadataSyncStatusCompleted = "completed"
	AnalysisMetadataSyncStatusFailed    = "failed"
)

// KitchenEvent represents system events from the Kitchen.
type KitchenEvent struct {
	Type      string    `json:"type"`
	AgentID   string    `json:"agent_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	OrderID   string    `json:"order_id,omitempty"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// OperatorMessage is the WebSocket message format (matches kitchen/operator.go).
type OperatorMessage struct {
	Type string `json:"type"`

	// For "order" type (outgoing)
	Order *models.Order `json:"order,omitempty"`

	// For "beacon" type (incoming)
	Beacon *BeaconPayload `json:"beacon,omitempty"`

	// For "coleslaw" type (incoming)
	Coleslaw *models.Coleslaw `json:"coleslaw,omitempty"`

	// For "event" type (incoming)
	Event *KitchenEvent `json:"event,omitempty"`

	// For "history" type (incoming broadcast)
	History *HistoryPayload `json:"history,omitempty"`

	// For "express_data" type (incoming broadcast)
	ExpressData *ExpressDataPayload `json:"express_data,omitempty"`

	// For "loot_sync" type (incoming broadcast)
	LootSync *LootSyncPayload `json:"loot_sync,omitempty"`

	// For "analysis_progress" type (incoming broadcast)
	AnalysisProgress *AnalysisProgressPayload `json:"analysis_progress,omitempty"`

	// For "analysis_metadata_sync" type (incoming broadcast)
	AnalysisMetadataSync *AnalysisMetadataSyncPayload `json:"analysis_metadata_sync,omitempty"`

	// For "error" type (incoming)
	Error string `json:"error,omitempty"`
}

// HistoryPayload represents an operation history entry from Kitchen.
type HistoryPayload struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id,omitempty"`
	Target      string    `json:"target,omitempty"`
	TargetType  string    `json:"target_type,omitempty"`
	TokenType   string    `json:"token_type,omitempty"`
	VulnID      string    `json:"vuln_id,omitempty"`
	Repository  string    `json:"repository,omitempty"`
	StagerID    string    `json:"stager_id,omitempty"`
	PRURL       string    `json:"pr_url,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
	ErrorDetail string    `json:"error_detail,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
}

type AnalysisProgressPayload struct {
	AnalysisID     string    `json:"analysis_id,omitempty"`
	SessionID      string    `json:"session_id,omitempty"`
	Target         string    `json:"target,omitempty"`
	TargetType     string    `json:"target_type,omitempty"`
	Deep           bool      `json:"deep,omitempty"`
	Phase          string    `json:"phase"`
	Message        string    `json:"message,omitempty"`
	CurrentRepo    string    `json:"current_repo,omitempty"`
	ReposCompleted int       `json:"repos_completed,omitempty"`
	ReposTotal     int       `json:"repos_total,omitempty"`
	SecretFindings int       `json:"secret_findings,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

type AnalysisMetadataSyncPayload struct {
	AnalysisID string    `json:"analysis_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Target     string    `json:"target,omitempty"`
	TargetType string    `json:"target_type,omitempty"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	ReposTotal int       `json:"repos_total,omitempty"`
	Error      string    `json:"error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type CallbackPayload struct {
	ID            string            `json:"id"`
	SessionID     string            `json:"session_id"`
	ResponseType  string            `json:"response_type"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	CalledBack    bool              `json:"called_back"`
	CallbackAt    *time.Time        `json:"callback_at,omitempty"`
	CallbackIP    string            `json:"callback_ip,omitempty"`
	DwellTime     string            `json:"dwell_time,omitempty"`
	Persistent    bool              `json:"persistent"`
	MaxCallbacks  int               `json:"max_callbacks,omitempty"`
	DefaultMode   string            `json:"default_mode,omitempty"`
	NextMode      string            `json:"next_mode,omitempty"`
	CallbackCount int               `json:"callback_count"`
	LastAgentID   string            `json:"last_agent_id,omitempty"`
	RevokedAt     *time.Time        `json:"revoked_at,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type CallbackControlRequest struct {
	Action string `json:"action"`
}

// BeaconPayload represents agent beacon data from Kitchen.
type BeaconPayload struct {
	AgentID       string     `json:"agent_id"`
	SessionID     string     `json:"session_id,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
	OS            string     `json:"os,omitempty"`
	Arch          string     `json:"arch,omitempty"`
	Timestamp     time.Time  `json:"timestamp"`
	DwellDeadline *time.Time `json:"dwell_deadline,omitempty"`
	CallbackID    string     `json:"callback_id,omitempty"`
	CallbackMode  string     `json:"callback_mode,omitempty"`
}

// ExtractedSecret represents a secret extracted from express data.
type ExtractedSecret struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	HighValue bool   `json:"high_value"`

	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Job        string `json:"job,omitempty"`
}

// ExpressDataPayload represents extracted secrets from express mode agents.
type ExpressDataPayload struct {
	AgentID          string                    `json:"agent_id"`
	SessionID        string                    `json:"session_id"`
	Hostname         string                    `json:"hostname"`
	Secrets          []ExtractedSecret         `json:"secrets"`
	Vars             map[string]string         `json:"vars,omitempty"`
	TokenPermissions map[string]string         `json:"token_permissions,omitempty"`
	CachePoison      *models.CachePoisonStatus `json:"cache_poison,omitempty"`
	Timestamp        time.Time                 `json:"timestamp"`
	Repository       string                    `json:"repository,omitempty"`
	Workflow         string                    `json:"workflow,omitempty"`
	Job              string                    `json:"job,omitempty"`
	CallbackID       string                    `json:"callback_id,omitempty"`
	CallbackMode     string                    `json:"callback_mode,omitempty"`
}

type LootSyncPayload struct {
	Entries []LootSyncEntry `json:"entries"`
}

type LootSyncEntry struct {
	SessionID string    `json:"session_id,omitempty"`
	AgentID   string    `json:"agent_id,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Origin    string    `json:"origin,omitempty"`

	Name      string `json:"name"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	HighValue bool   `json:"high_value"`

	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Job        string `json:"job,omitempty"`

	TokenPermissions map[string]string `json:"token_permissions,omitempty"`
}

// KitchenConfig holds configuration for the Kitchen WebSocket client.
type KitchenConfig struct {
	URL       string // e.g., "wss://kitchen.example.com/ws" or "ws://localhost:8080/ws"
	SessionID string
	Token     string // JWT authentication token (optional if auth not required)
}

// NewKitchenClient creates a new WebSocket client for the Counter.
func NewKitchenClient(config KitchenConfig) *KitchenClient {
	return &KitchenClient{
		kitchenURL:     config.URL,
		sessionID:      config.SessionID,
		token:          config.Token,
		reconnectCh:    make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		reconnectDelay: time.Second,
	}
}

// SetCallbacks sets the callbacks for Kitchen events.
// This matches the KitchenAPI interface.
func (k *KitchenClient) SetCallbacks(onBeacon func(Beacon), onColeslaw func(*models.Coleslaw), onError func(error)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onBeacon = onBeacon
	k.onColeslaw = onColeslaw
	k.onError = onError
}

// SetEventCallback sets an optional callback for system events.
func (k *KitchenClient) SetEventCallback(onEvent func(KitchenEvent)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onEvent = onEvent
}

// SetHistoryCallback sets the callback for history entry broadcasts.
func (k *KitchenClient) SetHistoryCallback(onHistory func(HistoryPayload)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onHistory = onHistory
}

// SetExpressDataCallback sets the callback for express data broadcasts.
func (k *KitchenClient) SetExpressDataCallback(onExpressData func(ExpressDataPayload)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onExpressData = onExpressData
}

func (k *KitchenClient) SetLootSyncCallback(onLootSync func(LootSyncPayload)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onLootSync = onLootSync
}

func (k *KitchenClient) SetAnalysisProgressCallback(onAnalysisProgress func(AnalysisProgressPayload)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onAnalysisProgress = onAnalysisProgress
}

func (k *KitchenClient) SetAnalysisMetadataSyncCallback(onAnalysisMetadataSync func(AnalysisMetadataSyncPayload)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onAnalysisMetadata = onAnalysisMetadataSync
}

// SetAuthExpiredCallback sets the callback for when authentication expires.
func (k *KitchenClient) SetAuthExpiredCallback(onAuthExpired func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onAuthExpired = onAuthExpired
}

// SetReconnectCallbacks sets callbacks for reconnection events.
func (k *KitchenClient) SetReconnectCallbacks(onReconnecting func(attempt int), onReconnected func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.onReconnecting = onReconnecting
	k.onReconnected = onReconnected
}

// Connect establishes the WebSocket connection to Kitchen.
func (k *KitchenClient) Connect(ctx context.Context) error {
	k.mu.Lock()
	if k.connected {
		k.mu.Unlock()
		return nil
	}
	k.mu.Unlock()

	// Build WebSocket URL with session ID
	wsURL, err := k.buildWSURL()
	if err != nil {
		return fmt.Errorf("invalid kitchen URL: %w", err)
	}

	// Connect with context
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to kitchen: %w", err)
	}

	k.mu.Lock()
	k.conn = conn
	k.connected = true
	k.ctx, k.cancel = context.WithCancel(ctx)
	k.mu.Unlock()

	// Log suppressed during TUI mode - corrupts display
	// slog.Info("connected to kitchen", "url", k.kitchenURL, "session_id", k.sessionID)
	return nil
}

// buildWSURL constructs the WebSocket URL with session ID and token.
func (k *KitchenClient) buildWSURL() (string, error) {
	u, err := url.Parse(k.kitchenURL)
	if err != nil {
		return "", err
	}

	// Add query params
	q := u.Query()
	if k.sessionID != "" {
		q.Set("session", k.sessionID)
	}
	if k.token != "" {
		q.Set("token", k.token)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// StartConsuming starts receiving messages from Kitchen.
// This matches the KitchenAPI interface.
func (k *KitchenClient) StartConsuming() error {
	k.mu.RLock()
	if !k.connected || k.conn == nil {
		k.mu.RUnlock()
		return fmt.Errorf("not connected to kitchen")
	}
	ctx := k.ctx
	k.mu.RUnlock()

	go k.readLoop(ctx)
	go k.keepAlive(ctx)

	return nil
}

// readLoop reads messages from the WebSocket connection.
func (k *KitchenClient) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-k.stopCh:
			return
		default:
		}

		k.mu.RLock()
		conn := k.conn
		k.mu.RUnlock()

		if conn == nil {
			return
		}

		var msg OperatorMessage
		err := wsjson.Read(ctx, conn, &msg)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return
			}
			k.handleError(fmt.Errorf("websocket read error: %w", err))
			k.markDisconnected()

			// Trigger automatic reconnection
			go k.autoReconnect()
			return
		}

		k.handleMessage(msg)
	}
}

// handleMessage processes incoming WebSocket messages.
func (k *KitchenClient) handleMessage(msg OperatorMessage) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	switch msg.Type {
	case "beacon":
		if msg.Beacon != nil && k.onBeacon != nil {
			k.onBeacon(Beacon{
				AgentID:       msg.Beacon.AgentID,
				Hostname:      msg.Beacon.Hostname,
				OS:            msg.Beacon.OS,
				Arch:          msg.Beacon.Arch,
				Timestamp:     msg.Beacon.Timestamp,
				DwellDeadline: msg.Beacon.DwellDeadline,
				CallbackID:    msg.Beacon.CallbackID,
				CallbackMode:  msg.Beacon.CallbackMode,
			})
		}

	case "coleslaw":
		if msg.Coleslaw != nil && k.onColeslaw != nil {
			k.onColeslaw(msg.Coleslaw)
		}

	case "event":
		if msg.Event != nil && k.onEvent != nil {
			k.onEvent(*msg.Event)
		}

	case "error":
		if msg.Error != "" && k.onError != nil {
			k.onError(fmt.Errorf("kitchen error: %s", msg.Error))
		}

	case "history":
		if msg.History != nil && k.onHistory != nil {
			k.onHistory(*msg.History)
		}

	case "express_data":
		if msg.ExpressData != nil && k.onExpressData != nil {
			k.onExpressData(*msg.ExpressData)
		}

	case "loot_sync":
		if msg.LootSync != nil && k.onLootSync != nil {
			k.onLootSync(*msg.LootSync)
		}

	case "analysis_progress":
		if msg.AnalysisProgress != nil && k.onAnalysisProgress != nil {
			k.onAnalysisProgress(*msg.AnalysisProgress)
		}

	case "analysis_metadata_sync":
		if msg.AnalysisMetadataSync != nil && k.onAnalysisMetadata != nil {
			k.onAnalysisMetadata(*msg.AnalysisMetadataSync)
		}

	case "pong":
		// Keepalive response, ignore

	default:
		slog.Debug("unknown message type from kitchen", "type", msg.Type)
	}
}

// keepAlive sends periodic pings to keep the connection alive.
func (k *KitchenClient) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.mu.RLock()
			conn := k.conn
			connected := k.connected
			k.mu.RUnlock()

			if !connected || conn == nil {
				return
			}

			err := wsjson.Write(ctx, conn, OperatorMessage{Type: "ping"})
			if err != nil {
				slog.Debug("keepalive ping failed", "error", err)
				return
			}
		}
	}
}

// PublishOrder sends an order to Kitchen for delivery to an agent.
// This matches the KitchenAPI interface.
func (k *KitchenClient) PublishOrder(ctx context.Context, order *models.Order) error {
	k.mu.RLock()
	conn := k.conn
	connected := k.connected
	k.mu.RUnlock()

	if !connected || conn == nil {
		return fmt.Errorf("not connected to kitchen")
	}

	msg := OperatorMessage{
		Type:  "order",
		Order: order,
	}

	if err := wsjson.Write(ctx, conn, msg); err != nil {
		return fmt.Errorf("failed to send order: %w", err)
	}

	slog.Debug("order sent to kitchen", "order_id", order.OrderID, "agent_id", order.AgentID)
	return nil
}

// IsConnected returns true if connected to Kitchen.
func (k *KitchenClient) IsConnected() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.connected
}

// Close closes the WebSocket connection and stops reconnection.
func (k *KitchenClient) Close() {
	// Signal stop to all goroutines
	select {
	case <-k.stopCh:
	default:
		close(k.stopCh)
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if k.cancel != nil {
		k.cancel()
	}

	if k.conn != nil {
		_ = k.conn.Close(websocket.StatusNormalClosure, "client closing")
		k.conn = nil
	}

	k.connected = false
	slog.Info("disconnected from kitchen")
}

// handleError calls the error callback if set.
func (k *KitchenClient) handleError(err error) {
	k.mu.RLock()
	onError := k.onError
	k.mu.RUnlock()

	if onError != nil {
		onError(err)
	}
}

// markDisconnected marks the client as disconnected.
func (k *KitchenClient) markDisconnected() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.connected = false
}

// Reconnect attempts to reconnect to Kitchen.
func (k *KitchenClient) Reconnect(ctx context.Context) error {
	k.closeConnection()

	// Wait before reconnecting
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
	}

	return k.Connect(ctx)
}

// autoReconnect handles automatic reconnection with exponential backoff.
func (k *KitchenClient) autoReconnect() {
	k.mu.Lock()
	if k.reconnecting {
		k.mu.Unlock()
		return
	}
	k.reconnecting = true
	k.reconnectDelay = time.Second
	k.mu.Unlock()

	defer func() {
		k.mu.Lock()
		k.reconnecting = false
		k.mu.Unlock()
	}()

	const maxDelay = 30 * time.Second
	const maxAttempts = 100

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		select {
		case <-k.stopCh:
			return
		default:
		}

		k.mu.RLock()
		onReconnecting := k.onReconnecting
		k.mu.RUnlock()
		if onReconnecting != nil {
			onReconnecting(attempt)
		}

		k.mu.RLock()
		delay := k.reconnectDelay
		k.mu.RUnlock()

		select {
		case <-k.stopCh:
			return
		case <-time.After(delay):
		}

		ctx := context.Background()
		err := k.doConnect(ctx)
		if err != nil {
			// Check for auth failure
			if isAuthError(err) {
				k.mu.RLock()
				onAuthExpired := k.onAuthExpired
				k.mu.RUnlock()
				if onAuthExpired != nil {
					onAuthExpired()
				}
				return
			}

			// Exponential backoff (cap at maxDelay)
			k.mu.Lock()
			k.reconnectDelay *= 2
			if k.reconnectDelay > maxDelay {
				k.reconnectDelay = maxDelay
			}
			k.mu.Unlock()
			continue
		}

		// Successfully reconnected
		k.mu.Lock()
		k.reconnectDelay = time.Second
		k.mu.Unlock()

		if err := k.StartConsuming(); err != nil {
			slog.Debug("failed to start consuming after reconnect", "error", err)
			continue
		}

		k.mu.RLock()
		onReconnected := k.onReconnected
		k.mu.RUnlock()
		if onReconnected != nil {
			onReconnected()
		}
		return
	}

	slog.Warn("max reconnection attempts reached")
}

// doConnect establishes connection without checking if already connected.
func (k *KitchenClient) doConnect(ctx context.Context) error {
	wsURL, err := k.buildWSURL()
	if err != nil {
		return fmt.Errorf("invalid kitchen URL: %w", err)
	}

	conn, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			return fmt.Errorf("authentication failed: %w", err)
		}
		return fmt.Errorf("failed to connect to kitchen: %w", err)
	}

	k.mu.Lock()
	k.conn = conn
	k.connected = true
	k.ctx, k.cancel = context.WithCancel(ctx)
	k.mu.Unlock()

	return nil
}

// isAuthError checks if an error is an authentication failure.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "authentication failed") ||
		strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "unauthorized")
}

// closeConnection closes the WebSocket without stopping auto-reconnect.
func (k *KitchenClient) closeConnection() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.cancel != nil {
		k.cancel()
	}

	if k.conn != nil {
		_ = k.conn.Close(websocket.StatusNormalClosure, "reconnecting")
		k.conn = nil
	}

	k.connected = false
}

// FetchPantry retrieves the attack graph from Kitchen via HTTP.
func (k *KitchenClient) FetchPantry(ctx context.Context) (*pantry.Pantry, error) {
	httpURL, err := k.buildHTTPURL("/pantry")
	if err != nil {
		return nil, fmt.Errorf("failed to build pantry URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pantry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pantry request failed: %s", resp.Status)
	}

	p := pantry.New()
	if err := json.NewDecoder(resp.Body).Decode(p); err != nil {
		return nil, fmt.Errorf("failed to decode pantry: %w", err)
	}

	slog.Debug("fetched pantry from kitchen", "assets", p.Size(), "edges", p.EdgeCount())
	return p, nil
}

// buildHTTPURL converts the WebSocket URL to an HTTP URL for the given path.
func (k *KitchenClient) buildHTTPURL(path string) (string, error) {
	u, err := url.Parse(k.kitchenURL)
	if err != nil {
		return "", err
	}

	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}

	u.Path = strings.TrimSuffix(u.Path, "/ws") + path
	u.RawQuery = ""

	return u.String(), nil
}

// FetchHistory retrieves operation history from Kitchen via HTTP.
func (k *KitchenClient) FetchHistory(ctx context.Context, limit int) ([]HistoryPayload, error) {
	httpURL, err := k.buildHTTPURL("/history")
	if err != nil {
		return nil, fmt.Errorf("failed to build history URL: %w", err)
	}

	if limit > 0 {
		httpURL += fmt.Sprintf("?limit=%d", limit)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch history: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("history request failed: %s", resp.Status)
	}

	var response struct {
		Entries []HistoryPayload `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode history: %w", err)
	}
	entries := response.Entries

	slog.Debug("fetched history from kitchen", "entries", len(entries))
	return entries, nil
}

// RecordHistory posts a new history entry to Kitchen.
func (k *KitchenClient) RecordHistory(ctx context.Context, entry HistoryPayload) error {
	httpURL, err := k.buildHTTPURL("/history")
	if err != nil {
		return fmt.Errorf("failed to build history URL: %w", err)
	}

	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal history entry: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to record history: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("record history failed: %s", resp.Status)
	}

	slog.Debug("recorded history entry", "type", entry.Type)
	return nil
}

func (k *KitchenClient) FetchCallbacks(ctx context.Context, sessionID string) ([]CallbackPayload, error) {
	httpURL, err := k.buildHTTPURL("/callbacks")
	if err != nil {
		return nil, fmt.Errorf("failed to build callbacks URL: %w", err)
	}

	if sessionID != "" {
		httpURL += "?session_id=" + url.QueryEscape(sessionID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch callbacks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("callbacks request failed: %s", resp.Status)
	}

	var response struct {
		Callbacks []CallbackPayload `json:"callbacks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode callbacks: %w", err)
	}

	return response.Callbacks, nil
}

func (k *KitchenClient) ControlCallback(ctx context.Context, callbackID string, request CallbackControlRequest) (*CallbackPayload, error) {
	httpURL, err := k.buildHTTPURL("/callbacks/" + url.PathEscape(callbackID))
	if err != nil {
		return nil, fmt.Errorf("failed to build callback URL: %w", err)
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal callback request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to control callback: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("callback control failed: %s", resp.Status)
	}

	var payload CallbackPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode callback response: %w", err)
	}

	return &payload, nil
}

// KnownEntityPayload represents a known entity (repo or org) for the Kitchen API.
type KnownEntityPayload struct {
	ID            string    `json:"id"`
	EntityType    string    `json:"entity_type"`
	Name          string    `json:"name"`
	SessionID     string    `json:"session_id"`
	DiscoveredAt  time.Time `json:"discovered_at,omitempty"`
	DiscoveredVia string    `json:"discovered_via,omitempty"`
	IsPrivate     bool      `json:"is_private,omitempty"`
	Permissions   []string  `json:"permissions,omitempty"`
	SSHPermission string    `json:"ssh_permission,omitempty"`
}

// FetchKnownEntities retrieves known entities from Kitchen for the given session.
func (k *KitchenClient) FetchKnownEntities(ctx context.Context, sessionID string) ([]KnownEntityPayload, error) {
	httpURL, err := k.buildHTTPURL("/known-entities")
	if err != nil {
		return nil, fmt.Errorf("failed to build known-entities URL: %w", err)
	}

	httpURL += "?session_id=" + url.QueryEscape(sessionID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch known entities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("known entities request failed: %s", resp.Status)
	}

	var result struct {
		Entities []KnownEntityPayload `json:"entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode known entities: %w", err)
	}

	slog.Debug("fetched known entities from kitchen", "count", len(result.Entities))
	return result.Entities, nil
}

// RecordKnownEntity posts a new known entity to Kitchen.
func (k *KitchenClient) RecordKnownEntity(ctx context.Context, entity KnownEntityPayload) error {
	httpURL, err := k.buildHTTPURL("/known-entities")
	if err != nil {
		return fmt.Errorf("failed to build known-entities URL: %w", err)
	}

	body, err := json.Marshal(entity)
	if err != nil {
		return fmt.Errorf("failed to marshal known entity: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to record known entity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("record known entity failed: %s", resp.Status)
	}

	slog.Debug("recorded known entity", "id", entity.ID, "type", entity.EntityType)
	return nil
}

// --- GitHub proxy types (mirrors kitchen/github.go) ---

type VulnerabilityInfo struct {
	Repository   string   `json:"repository"`
	Workflow     string   `json:"workflow"`
	Context      string   `json:"context"`
	ID           string   `json:"id"`
	IssueNumber  int      `json:"issue_number,omitempty"`
	GateTriggers []string `json:"gate_triggers,omitempty"`
	GateRaw      string   `json:"gate_raw,omitempty"`
}

type RepoInfo struct {
	FullName  string `json:"full_name"`
	IsPrivate bool   `json:"is_private"`
	CanPush   bool   `json:"can_push"`
}

type DeployPRRequest struct {
	Token     string            `json:"token"`
	Vuln      VulnerabilityInfo `json:"vuln"`
	Payload   string            `json:"payload"`
	StagerID  string            `json:"stager_id,omitempty"`
	Draft     *bool             `json:"draft,omitempty"`
	AutoClose *bool             `json:"auto_close,omitempty"`
}

type DeployPRResponse struct {
	PRURL string `json:"pr_url"`
	Error string `json:"error,omitempty"`
}

type DeployIssueRequest struct {
	Token       string            `json:"token"`
	Vuln        VulnerabilityInfo `json:"vuln"`
	Payload     string            `json:"payload"`
	CommentMode bool              `json:"comment_mode,omitempty"`
	StagerID    string            `json:"stager_id,omitempty"`
	AutoClose   *bool             `json:"auto_close,omitempty"`
}

type DeployIssueResponse struct {
	IssueURL string `json:"issue_url"`
	Error    string `json:"error,omitempty"`
}

type DeployCommentRequest struct {
	Token     string            `json:"token"`
	Vuln      VulnerabilityInfo `json:"vuln"`
	Payload   string            `json:"payload"`
	Target    string            `json:"target,omitempty"`
	StagerID  string            `json:"stager_id,omitempty"`
	AutoClose *bool             `json:"auto_close,omitempty"`
}

type DeployCommentResponse struct {
	CommentURL string `json:"comment_url"`
	Error      string `json:"error,omitempty"`
}

type DeployLOTPRequest struct {
	Token       string            `json:"token"`
	RepoName    string            `json:"repo_name"`
	Vuln        VulnerabilityInfo `json:"vuln,omitempty"`
	StagerID    string            `json:"stager_id"`
	LOTPTool    string            `json:"lotp_tool,omitempty"`
	LOTPAction  string            `json:"lotp_action,omitempty"`
	LOTPTargets []string          `json:"lotp_targets,omitempty"`
	CallbackURL string            `json:"callback_url,omitempty"`
}

type DeployLOTPResponse struct {
	PRURL string `json:"pr_url"`
	Error string `json:"error,omitempty"`
}

type DeploySelfHostedCallbackPRRequest struct {
	Token    string `json:"token"`
	RepoName string `json:"repo_name"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Title    string `json:"title,omitempty"`
	Body     string `json:"body,omitempty"`
	StagerID string `json:"stager_id,omitempty"`
	Draft    *bool  `json:"draft,omitempty"`
}

type DeploySelfHostedCallbackPRResponse struct {
	PRURL string `json:"pr_url"`
	Error string `json:"error,omitempty"`
}

type DeploySelfHostedWorkflowPushRequest struct {
	Token    string `json:"token"`
	RepoName string `json:"repo_name"`
	Branch   string `json:"branch,omitempty"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	Title    string `json:"title,omitempty"`
	StagerID string `json:"stager_id,omitempty"`
}

type DeploySelfHostedWorkflowPushResponse struct {
	Branch    string `json:"branch,omitempty"`
	BranchURL string `json:"branch_url,omitempty"`
	Error     string `json:"error,omitempty"`
}

type DeployDispatchRequest struct {
	Token        string                 `json:"token"`
	Owner        string                 `json:"owner"`
	Repo         string                 `json:"repo"`
	WorkflowFile string                 `json:"workflow_file"`
	Ref          string                 `json:"ref"`
	Inputs       map[string]interface{} `json:"inputs,omitempty"`
}

type DeployDispatchResponse struct {
	Error string `json:"error,omitempty"`
}

type DeployPreflightRequest struct {
	Token            string            `json:"token"`
	Vuln             VulnerabilityInfo `json:"vuln"`
	TokenType        string            `json:"token_type,omitempty"`
	TokenOwner       string            `json:"token_owner,omitempty"`
	Scopes           []string          `json:"scopes,omitempty"`
	KnownPermissions map[string]string `json:"known_permissions,omitempty"`
	IssueNumber      int               `json:"issue_number,omitempty"`
	PRNumber         int               `json:"pr_number,omitempty"`
}

type DeployPreflightCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type DeployPreflightCapability struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type DeployPreflightResponse struct {
	CacheHit     bool                                 `json:"cache_hit"`
	Capabilities map[string]DeployPreflightCapability `json:"capabilities"`
	Checks       []DeployPreflightCheck               `json:"checks,omitempty"`
}

type ListReposRequest struct {
	Token string `json:"token"`
}

type ListReposResponse struct {
	Repos []string `json:"repos"`
	Error string   `json:"error,omitempty"`
}

type ListReposWithInfoRequest struct {
	Token string `json:"token"`
}

type ListReposWithInfoResponse struct {
	Repos []RepoInfo `json:"repos"`
	Error string     `json:"error,omitempty"`
}

type ListWorkflowsRequest struct {
	Token string `json:"token"`
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

type WorkflowDispatchInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     string   `json:"default,omitempty"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type DispatchableWorkflow struct {
	Path   string                  `json:"path"`
	Ref    string                  `json:"ref,omitempty"`
	Inputs []WorkflowDispatchInput `json:"inputs,omitempty"`
}

type ListWorkflowsResponse struct {
	Workflows []DispatchableWorkflow `json:"workflows"`
	Error     string                 `json:"error,omitempty"`
}

type GetUserRequest struct {
	Token string `json:"token"`
}

type GetUserResponse struct {
	Login  string   `json:"login"`
	Scopes []string `json:"scopes,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type FetchTokenInfoRequest struct {
	Token  string `json:"token"`
	Source string `json:"source"`
}

type FetchTokenInfoResponse struct {
	Owner        string   `json:"owner"`
	Scopes       []string `json:"scopes,omitempty"`
	RateLimitMax int      `json:"rate_limit_max,omitempty"`
	TokenType    string   `json:"token_type"`
	StatusCode   int      `json:"status_code"`
	Error        string   `json:"error,omitempty"`
}

type AppInstallation struct {
	ID      int64  `json:"id"`
	Account string `json:"account"`
	AppSlug string `json:"app_slug"`
}

type ListAppInstallationsRequest struct {
	PEM   string `json:"pem"`
	AppID string `json:"app_id"`
}

type ListAppInstallationsResponse struct {
	Installations []AppInstallation `json:"installations"`
	Error         string            `json:"error,omitempty"`
}

type CreateInstallationTokenRequest struct {
	PEM            string `json:"pem"`
	AppID          string `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
}

type CreateInstallationTokenResponse struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// --- doPostJSON helper ---

func (k *KitchenClient) doPostJSON(ctx context.Context, path string, reqBody, respBody interface{}, timeout time.Duration) error {
	httpURL, err := k.buildHTTPURL(path)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpClient := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Error string `json:"error"`
		}
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("kitchen returned: %s", resp.Status)
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// --- GitHub proxy methods ---

func (k *KitchenClient) DeployPR(ctx context.Context, req DeployPRRequest) (DeployPRResponse, error) {
	var resp DeployPRResponse
	err := k.doPostJSON(ctx, "/github/deploy/pr", req, &resp, 3*time.Minute)
	return resp, err
}

func (k *KitchenClient) DeployIssue(ctx context.Context, req DeployIssueRequest) (DeployIssueResponse, error) {
	var resp DeployIssueResponse
	err := k.doPostJSON(ctx, "/github/deploy/issue", req, &resp, 30*time.Second)
	return resp, err
}

func (k *KitchenClient) DeployComment(ctx context.Context, req DeployCommentRequest) (DeployCommentResponse, error) {
	var resp DeployCommentResponse
	err := k.doPostJSON(ctx, "/github/deploy/comment", req, &resp, 30*time.Second)
	return resp, err
}

func (k *KitchenClient) DeployLOTP(ctx context.Context, req DeployLOTPRequest) (DeployLOTPResponse, error) {
	var resp DeployLOTPResponse
	err := k.doPostJSON(ctx, "/github/deploy/lotp", req, &resp, 3*time.Minute)
	return resp, err
}

func (k *KitchenClient) DeploySelfHostedCallbackPR(ctx context.Context, req DeploySelfHostedCallbackPRRequest) (DeploySelfHostedCallbackPRResponse, error) {
	var resp DeploySelfHostedCallbackPRResponse
	err := k.doPostJSON(ctx, "/github/deploy/self-hosted-callback-pr", req, &resp, 3*time.Minute)
	return resp, err
}

func (k *KitchenClient) DeploySelfHostedWorkflowPush(ctx context.Context, req DeploySelfHostedWorkflowPushRequest) (DeploySelfHostedWorkflowPushResponse, error) {
	var resp DeploySelfHostedWorkflowPushResponse
	err := k.doPostJSON(ctx, "/github/deploy/self-hosted-workflow-push", req, &resp, 3*time.Minute)
	return resp, err
}

func (k *KitchenClient) TriggerDispatch(ctx context.Context, req DeployDispatchRequest) error {
	return k.doPostJSON(ctx, "/github/deploy/dispatch", req, nil, 30*time.Second)
}

func (k *KitchenClient) FetchDeployPreflight(ctx context.Context, req DeployPreflightRequest) (*DeployPreflightResponse, error) {
	var resp DeployPreflightResponse
	err := k.doPostJSON(ctx, "/github/deploy/preflight", req, &resp, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (k *KitchenClient) ListReposWithInfo(ctx context.Context, token string) ([]RepoInfo, error) {
	var resp ListReposWithInfoResponse
	err := k.doPostJSON(ctx, "/github/repos/info", ListReposWithInfoRequest{Token: token}, &resp, 60*time.Second)
	return resp.Repos, err
}

func (k *KitchenClient) ListWorkflowsWithDispatch(ctx context.Context, token, owner, repo string) ([]DispatchableWorkflow, error) {
	var resp ListWorkflowsResponse
	err := k.doPostJSON(ctx, "/github/workflows", ListWorkflowsRequest{Token: token, Owner: owner, Repo: repo}, &resp, 60*time.Second)
	return resp.Workflows, err
}

func (k *KitchenClient) GetAuthenticatedUser(ctx context.Context, token string) (GetUserResponse, error) {
	var resp GetUserResponse
	err := k.doPostJSON(ctx, "/github/user", GetUserRequest{Token: token}, &resp, 10*time.Second)
	return resp, err
}

func (k *KitchenClient) FetchTokenInfo(ctx context.Context, token, source string) (*FetchTokenInfoResponse, error) {
	var resp FetchTokenInfoResponse
	err := k.doPostJSON(ctx, "/github/token/info", FetchTokenInfoRequest{Token: token, Source: source}, &resp, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (k *KitchenClient) ListAppInstallations(ctx context.Context, pemData, appID string) ([]AppInstallation, error) {
	var resp ListAppInstallationsResponse
	err := k.doPostJSON(ctx, "/github/app/installations", ListAppInstallationsRequest{PEM: pemData, AppID: appID}, &resp, 30*time.Second)
	return resp.Installations, err
}

func (k *KitchenClient) CreateInstallationToken(ctx context.Context, pemData, appID string, installationID int64) (*CreateInstallationTokenResponse, error) {
	var resp CreateInstallationTokenResponse
	err := k.doPostJSON(ctx, "/github/app/token", CreateInstallationTokenRequest{PEM: pemData, AppID: appID, InstallationID: installationID}, &resp, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
