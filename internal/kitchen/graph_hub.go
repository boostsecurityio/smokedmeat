// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

const (
	graphBatchWindow   = 100 * time.Millisecond
	graphSendBuffer    = 256
	graphStaleVersions = 100
)

// GraphHub manages WebSocket connections for real-time graph updates.
// Implements pantry.Observer to receive change notifications.
type GraphHub struct {
	mu      sync.RWMutex
	clients map[*GraphClient]bool
	pantry  *pantry.Pantry

	// Delta batching
	deltaMu      sync.Mutex
	pendingDelta *GraphDelta
	batchTimer   *time.Timer
}

// GraphClient represents a connected graph visualization client.
type GraphClient struct {
	conn    *websocket.Conn
	send    chan GraphMessage
	hub     *GraphHub
	version uint64
	mode    string
}

// NewGraphHub creates a new graph hub.
func NewGraphHub(p *pantry.Pantry) *GraphHub {
	hub := &GraphHub{
		clients: make(map[*GraphClient]bool),
		pantry:  p,
	}
	p.AddObserver(hub)
	return hub
}

// HandleWebSocket handles WebSocket connections for graph visualization.
func (h *GraphHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	writeGraphSecurityHeaders(w)
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		slog.Error("failed to accept graph websocket", "error", err)
		return
	}

	client := &GraphClient{
		conn: conn,
		send: make(chan GraphMessage, graphSendBuffer),
		hub:  h,
		mode: normalizeGraphMode(r.URL.Query().Get("mode")),
	}

	h.register(client)
	defer h.unregister(client)

	// Send initial snapshot
	snapshot := h.buildSnapshot(client.mode)
	client.version = snapshot.Version
	client.send <- GraphMessage{Type: "snapshot", Data: snapshot}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	go client.writePump(ctx)
	client.readPump(ctx)
}

func (h *GraphHub) register(client *GraphClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[client] = true
	slog.Debug("graph client connected", "total", len(h.clients))
}

func (h *GraphHub) unregister(client *GraphClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)
	}
	slog.Debug("graph client disconnected", "total", len(h.clients))
}

func (h *GraphHub) buildSnapshot(mode string) GraphSnapshot {
	return buildGraphSnapshot(h.pantry, h.pantry.Revision(), mode)
}

// broadcast sends a message to all connected clients.
func (h *GraphHub) broadcast(msg GraphMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		select {
		case client.send <- msg:
		default:
			slog.Warn("graph client buffer full, dropping message")
		}
	}
}

// flushDelta sends accumulated changes to all clients.
func (h *GraphHub) flushDelta() {
	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	delta := h.pendingDelta
	h.pendingDelta = nil
	h.batchTimer = nil

	if delta == nil {
		return
	}

	// Keep the publication fence held so a replacement snapshot cannot overtake this older delta.
	h.broadcast(GraphMessage{Type: "delta", Data: delta})
}

// scheduleDeltaFlush ensures a delta is flushed after the batch window.
func (h *GraphHub) scheduleDeltaFlush() {
	if h.batchTimer == nil {
		h.batchTimer = time.AfterFunc(graphBatchWindow, h.flushDelta)
	}
}

func (h *GraphHub) OnPantryChange(change pantry.ChangeSet) {
	if change.Kind == pantry.ChangeCommittedState {
		h.deltaMu.Lock()
		if h.batchTimer != nil {
			h.batchTimer.Stop()
		}
		h.batchTimer = nil
		h.pendingDelta = nil
		h.deltaMu.Unlock()
		h.broadcastSnapshots()
		return
	}

	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	if h.pendingDelta == nil {
		h.pendingDelta = &GraphDelta{}
	}
	h.pendingDelta.Version = change.Revision
	for _, asset := range change.Granular.AddedAssets {
		h.pendingDelta.AddedNodes = append(h.pendingDelta.AddedNodes, AssetToGraphNode(asset))
	}
	for _, update := range change.Granular.UpdatedAssets {
		node := AssetToGraphNode(update.After)
		h.pendingDelta.UpdatedNodes = append(h.pendingDelta.UpdatedNodes, NodeUpdate{
			ID:                update.After.ID,
			OldState:          string(update.Before.State),
			NewState:          string(update.After.State),
			Label:             node.Label,
			Properties:        node.Properties,
			TooltipProperties: node.TooltipProperties,
		})
	}
	for _, edge := range change.Granular.AddedRelationships {
		h.pendingDelta.AddedEdges = append(h.pendingDelta.AddedEdges, GraphEdge{
			Source: edge.From,
			Target: edge.To,
			Type:   string(edge.Relationship.Type),
		})
	}
	h.pendingDelta.RemovedNodes = append(h.pendingDelta.RemovedNodes, change.Granular.RemovedAssetIDs...)
	for _, edge := range change.Granular.RemovedRelationships {
		h.pendingDelta.RemovedEdges = append(h.pendingDelta.RemovedEdges, EdgeRef{Source: edge.From, Target: edge.To})
	}
	h.scheduleDeltaFlush()
}

func (h *GraphHub) broadcastSnapshots() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		snapshot := h.buildSnapshot(client.mode)
		select {
		case client.send <- GraphMessage{Type: "snapshot", Data: snapshot}:
		default:
			slog.Warn("graph client buffer full, dropping snapshot")
		}
	}
}

// ClientCount returns the number of connected graph clients.
func (h *GraphHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (c *GraphClient) readPump(ctx context.Context) {
	defer c.conn.Close(websocket.StatusNormalClosure, "")

	for {
		var msg GraphMessage
		err := wsjson.Read(ctx, c.conn, &msg)
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				slog.Debug("graph websocket read error", "error", err)
			}
			return
		}

		switch msg.Type {
		case "ping":
			c.send <- GraphMessage{Type: "pong"}
		case "snapshot_request":
			c.mode = graphModeFromData(msg.Data, c.mode)
			snapshot := c.hub.buildSnapshot(c.mode)
			c.version = snapshot.Version
			c.send <- GraphMessage{Type: "snapshot", Data: snapshot}
		}
	}
}

func (c *GraphClient) writePump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-c.send:
			if !ok {
				return
			}
			if err := wsjson.Write(ctx, c.conn, msg); err != nil {
				slog.Debug("graph websocket write error", "error", err)
				return
			}
		}
	}
}
