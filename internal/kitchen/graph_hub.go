// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

const graphSendBuffer = 256

// GraphHub manages WebSocket connections for real-time graph updates.
type GraphHub struct {
	mu      sync.RWMutex
	clients map[*GraphClient]bool
	pantry  *pantry.Pantry
}

// GraphClient represents a connected graph visualization client.
type GraphClient struct {
	conn   *websocket.Conn
	send   chan GraphMessage
	hub    *GraphHub
	cancel context.CancelFunc
	mode   string
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

	ctx, cancel := context.WithCancel(r.Context())
	client := &GraphClient{
		conn:   conn,
		send:   make(chan GraphMessage, graphSendBuffer),
		hub:    h,
		cancel: cancel,
		mode:   normalizeGraphMode(r.URL.Query().Get("mode")),
	}
	if !h.register(client) {
		cancel()
		_ = conn.Close(websocket.StatusPolicyViolation, "state queue unavailable")
		return
	}
	defer cancel()
	defer h.unregister(client)

	go client.writePump(ctx)
	client.readPump(ctx)
}

func (h *GraphHub) register(client *GraphClient) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[client] = true
	snapshot := h.buildSnapshot(client.mode)
	if !h.enqueueLocked(client, GraphMessage{Type: "snapshot", Data: snapshot}) {
		return false
	}
	slog.Debug("graph client connected", "total", len(h.clients))
	return true
}

func (h *GraphHub) unregister(client *GraphClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disconnectLocked(client)
	slog.Debug("graph client disconnected", "total", len(h.clients))
}

func (h *GraphHub) disconnectLocked(client *GraphClient) {
	if _, ok := h.clients[client]; !ok {
		return
	}
	delete(h.clients, client)
	close(client.send)
	if client.cancel != nil {
		client.cancel()
	}
}

func (h *GraphHub) enqueueLocked(client *GraphClient, message GraphMessage) bool {
	select {
	case client.send <- message:
		return true
	default:
		slog.Warn("graph client state queue full, disconnecting")
		h.disconnectLocked(client)
		return false
	}
}

func (h *GraphHub) enqueue(client *GraphClient, message GraphMessage) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client]; !ok {
		return false
	}
	return h.enqueueLocked(client, message)
}

func (h *GraphHub) buildSnapshot(mode string) GraphSnapshot {
	return buildGraphSnapshot(h.pantry, mode)
}

func (h *GraphHub) OnPantryChange(change pantry.ChangeSet) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var view *pantry.Pantry
	var delta GraphDelta
	hasDelta := false
	snapshots := make(map[string]GraphSnapshot, 2)
	for client := range h.clients {
		if client.mode == graphModeFull {
			message := GraphMessage{
				Type: "snapshot_required",
				Data: GraphSnapshotRequired{Revision: change.Revision},
			}
			if change.Kind == pantry.ChangeGranular {
				if !hasDelta {
					delta = graphDeltaFromChange(change)
					hasDelta = true
				}
				message = GraphMessage{Type: "delta", Data: delta}
			}
			h.enqueueLocked(client, message)
			continue
		}

		if view == nil {
			view = h.pantry.Clone()
		}
		snapshot, ok := snapshots[client.mode]
		if !ok {
			snapshot = buildGraphSnapshotFromView(view, client.mode)
			snapshots[client.mode] = snapshot
		}
		h.enqueueLocked(client, GraphMessage{Type: "snapshot", Data: snapshot})
	}
}

func graphDeltaFromChange(change pantry.ChangeSet) GraphDelta {
	delta := GraphDelta{
		BaseRevision: change.BaseRevision,
		Revision:     change.Revision,
	}
	for _, asset := range change.Granular.AddedAssets {
		delta.AddedNodes = append(delta.AddedNodes, AssetToGraphNode(asset))
	}
	for _, update := range change.Granular.UpdatedAssets {
		node := AssetToGraphNode(update.After)
		delta.UpdatedNodes = append(delta.UpdatedNodes, NodeUpdate{
			ID:                update.After.ID,
			OldState:          string(update.Before.State),
			NewState:          string(update.After.State),
			Label:             node.Label,
			Properties:        node.Properties,
			TooltipProperties: node.TooltipProperties,
		})
	}
	for _, edge := range change.Granular.AddedRelationships {
		delta.AddedEdges = append(delta.AddedEdges, GraphEdge{
			Source: edge.From,
			Target: edge.To,
			Type:   string(edge.Relationship.Type),
		})
	}
	delta.RemovedNodes = append(delta.RemovedNodes, change.Granular.RemovedAssetIDs...)
	for _, edge := range change.Granular.RemovedRelationships {
		delta.RemovedEdges = append(delta.RemovedEdges, EdgeRef{Source: edge.From, Target: edge.To})
	}
	return delta
}

func (h *GraphHub) sendSnapshot(client *GraphClient, mode string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[client]; !ok {
		return
	}
	client.mode = normalizeGraphMode(mode)
	snapshot := h.buildSnapshot(client.mode)
	h.enqueueLocked(client, GraphMessage{Type: "snapshot", Data: snapshot})
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
		if err := wsjson.Read(ctx, c.conn, &msg); err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure && ctx.Err() == nil {
				slog.Debug("graph websocket read error", "error", err)
			}
			return
		}

		switch msg.Type {
		case "ping":
			c.hub.enqueue(c, GraphMessage{Type: "pong"})
		case "snapshot_request":
			c.hub.sendSnapshot(c, graphModeFromData(msg.Data, c.mode))
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
				c.hub.unregister(c)
				return
			}
		}
	}
}
