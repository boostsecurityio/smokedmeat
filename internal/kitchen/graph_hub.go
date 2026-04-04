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
	version int64
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
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		slog.Error("failed to accept graph websocket", "error", err)
		return
	}

	client := &GraphClient{
		conn: conn,
		send: make(chan GraphMessage, graphSendBuffer),
		hub:  h,
	}

	h.register(client)
	defer h.unregister(client)

	// Send initial snapshot
	snapshot := h.buildSnapshot()
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

func (h *GraphHub) buildSnapshot() GraphSnapshot {
	assets := h.pantry.AllAssets()
	edges := h.pantry.AllRelationships()

	nodes := make([]GraphNode, 0, len(assets))
	for _, asset := range assets {
		nodes = append(nodes, AssetToGraphNode(asset))
	}

	graphEdges := make([]GraphEdge, 0, len(edges))
	for _, edge := range edges {
		graphEdges = append(graphEdges, EdgeToGraphEdge(edge))
	}

	return GraphSnapshot{
		Version: h.pantry.Version(),
		Nodes:   nodes,
		Edges:   graphEdges,
	}
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
	delta := h.pendingDelta
	h.pendingDelta = nil
	h.batchTimer = nil
	h.deltaMu.Unlock()

	if delta == nil {
		return
	}

	delta.Version = h.pantry.Version()
	h.broadcast(GraphMessage{Type: "delta", Data: delta})
}

// scheduleDeltaFlush ensures a delta is flushed after the batch window.
func (h *GraphHub) scheduleDeltaFlush() {
	if h.batchTimer == nil {
		h.batchTimer = time.AfterFunc(graphBatchWindow, h.flushDelta)
	}
}

// PantryObserver implementation

func (h *GraphHub) OnAssetAdded(asset pantry.Asset) {
	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	if h.pendingDelta == nil {
		h.pendingDelta = &GraphDelta{}
	}
	h.pendingDelta.AddedNodes = append(h.pendingDelta.AddedNodes, AssetToGraphNode(asset))
	h.scheduleDeltaFlush()
}

func (h *GraphHub) OnAssetUpdated(asset pantry.Asset, oldState pantry.AssetState) {
	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	if h.pendingDelta == nil {
		h.pendingDelta = &GraphDelta{}
	}
	node := AssetToGraphNode(asset)
	h.pendingDelta.UpdatedNodes = append(h.pendingDelta.UpdatedNodes, NodeUpdate{
		ID:                asset.ID,
		OldState:          string(oldState),
		NewState:          string(asset.State),
		Label:             node.Label,
		Properties:        node.Properties,
		TooltipProperties: node.TooltipProperties,
	})
	h.scheduleDeltaFlush()
}

func (h *GraphHub) OnRelationshipAdded(from, to string, rel pantry.Relationship) {
	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	if h.pendingDelta == nil {
		h.pendingDelta = &GraphDelta{}
	}
	h.pendingDelta.AddedEdges = append(h.pendingDelta.AddedEdges, GraphEdge{
		Source: from,
		Target: to,
		Type:   string(rel.Type),
	})
	h.scheduleDeltaFlush()
}

func (h *GraphHub) OnAssetRemoved(id string) {
	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	if h.pendingDelta == nil {
		h.pendingDelta = &GraphDelta{}
	}
	h.pendingDelta.RemovedNodes = append(h.pendingDelta.RemovedNodes, id)
	h.scheduleDeltaFlush()
}

func (h *GraphHub) OnRelationshipRemoved(from, to string) {
	h.deltaMu.Lock()
	defer h.deltaMu.Unlock()

	if h.pendingDelta == nil {
		h.pendingDelta = &GraphDelta{}
	}
	h.pendingDelta.RemovedEdges = append(h.pendingDelta.RemovedEdges, EdgeRef{
		Source: from,
		Target: to,
	})
	h.scheduleDeltaFlush()
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
			snapshot := c.hub.buildSnapshot()
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
