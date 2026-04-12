// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Package tests contains end-to-end integration tests for SmokedMeat.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

// TestEndToEnd_OrderFlow tests the complete order flow:
// 1. Counter queues an order for an agent
// 2. Brisket agent polls and receives the order
// 3. Brisket executes and sends back coleslaw response
// 4. Order is marked as completed
func TestEndToEnd_OrderFlow(t *testing.T) {
	// Create a mock publisher that tracks published messages
	publisher := &mockPublisher{
		beacons:   make(map[string][][]byte),
		coleslaws: make(map[string][][]byte),
	}

	// Create order store and handler
	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	handler := kitchen.NewHandlerWithPublisher(publisher, store)

	// Create test server
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	agentID := "test-agent-001"
	sessionID := "test-session-001"

	// Step 1: Queue an order for the agent
	order := models.NewOrder(sessionID, agentID, "exec", []string{"whoami"})
	order.OperatorID = "op-1"
	order.OperatorName = "Alice"
	err := store.Add(order)
	require.NoError(t, err)

	// Step 2: Brisket polls for orders
	pollResp, err := http.Get(server.URL + "/b/" + agentID)
	require.NoError(t, err)
	defer pollResp.Body.Close()

	assert.Equal(t, http.StatusOK, pollResp.StatusCode)

	var receivedOrder models.Order
	err = json.NewDecoder(pollResp.Body).Decode(&receivedOrder)
	require.NoError(t, err)

	assert.Equal(t, order.OrderID, receivedOrder.OrderID)
	assert.Equal(t, agentID, receivedOrder.AgentID)
	assert.Equal(t, "exec", receivedOrder.Command)
	assert.Equal(t, []string{"whoami"}, receivedOrder.Args)
	assert.Equal(t, "op-1", receivedOrder.OperatorID)
	assert.Equal(t, "Alice", receivedOrder.OperatorName)

	// Step 3: Brisket sends coleslaw response
	coleslaw := &models.Coleslaw{
		OrderID:   order.OrderID,
		AgentID:   agentID,
		SessionID: sessionID,
		Stdout:    "root",
		ExitCode:  0,
	}
	coleslawData, _ := coleslaw.Marshal()

	beaconResp, err := http.Post(
		server.URL+"/b/"+agentID,
		"application/json",
		bytes.NewReader(coleslawData),
	)
	require.NoError(t, err)
	defer beaconResp.Body.Close()

	assert.Equal(t, http.StatusOK, beaconResp.StatusCode)

	// Verify coleslaw was published
	assert.Len(t, publisher.coleslaws[agentID], 1)

	// Step 4: Verify order is marked completed (poll should return 204)
	pollResp2, err := http.Get(server.URL + "/b/" + agentID)
	require.NoError(t, err)
	defer pollResp2.Body.Close()

	assert.Equal(t, http.StatusNoContent, pollResp2.StatusCode)
}

// TestEndToEnd_StagerFlow tests the stager registration and callback flow:
// 1. Counter registers a stager with custom payload
// 2. CI runner fetches the stager (callback)
// 3. Stager is marked as called back
func TestEndToEnd_StagerFlow(t *testing.T) {
	publisher := &mockPublisher{
		beacons:   make(map[string][][]byte),
		coleslaws: make(map[string][][]byte),
	}

	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	handler := kitchen.NewHandlerWithPublisher(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	stagerID := "test-stager-001"

	// Step 1: Register a stager
	registerReq := kitchen.StagerRegisterRequest{
		ResponseType: "bash",
		Payload:      "#!/bin/bash\necho 'pwned'",
		SessionID:    "test-session",
		TTLSeconds:   300,
	}
	registerData, _ := json.Marshal(registerReq)

	resp, err := http.Post(
		server.URL+stagerurl.Path(stagerID),
		"application/json",
		bytes.NewReader(registerData),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var registerResp map[string]string
	err = json.NewDecoder(resp.Body).Decode(&registerResp)
	require.NoError(t, err)
	assert.Equal(t, "registered", registerResp["status"])
	assert.Equal(t, stagerID, registerResp["stager_id"])

	// Step 2: CI runner fetches the stager
	fetchResp, err := http.Get(server.URL + stagerurl.Path(stagerID))
	require.NoError(t, err)
	defer fetchResp.Body.Close()

	assert.Equal(t, http.StatusOK, fetchResp.StatusCode)

	body, _ := io.ReadAll(fetchResp.Body)
	assert.Contains(t, string(body), "echo 'pwned'")

	// Step 3: Verify stager was marked as called back
	stager := handler.StagerStore().Get(stagerID)
	require.NotNil(t, stager)
	assert.True(t, stager.CalledBack)
	assert.False(t, stager.CallbackAt.IsZero())
}

// TestEndToEnd_MultipleAgents tests handling multiple agents concurrently
func TestEndToEnd_MultipleAgents(t *testing.T) {
	publisher := &mockPublisher{
		beacons:   make(map[string][][]byte),
		coleslaws: make(map[string][][]byte),
	}

	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	handler := kitchen.NewHandlerWithPublisher(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	sessionID := "test-session"
	agents := []string{"agent-1", "agent-2", "agent-3"}

	// Queue orders for each agent
	for i, agentID := range agents {
		order := models.NewOrder(sessionID, agentID, "exec", []string{fmt.Sprintf("cmd-%d", i)})
		err := store.Add(order)
		require.NoError(t, err)
	}

	// Each agent polls and receives their specific order
	for i, agentID := range agents {
		pollResp, err := http.Get(server.URL + "/b/" + agentID)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, pollResp.StatusCode)

		var order models.Order
		err = json.NewDecoder(pollResp.Body).Decode(&order)
		require.NoError(t, err)
		pollResp.Body.Close()

		// Verify agent receives their own order
		assert.Equal(t, agentID, order.AgentID)
		assert.Equal(t, []string{fmt.Sprintf("cmd-%d", i)}, order.Args)
	}

	// Verify all agents have no more pending orders
	for _, agentID := range agents {
		pollResp, err := http.Get(server.URL + "/b/" + agentID)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, pollResp.StatusCode)
		pollResp.Body.Close()
	}
}

// TestEndToEnd_FIFOOrderDelivery tests that orders are delivered in FIFO order
func TestEndToEnd_FIFOOrderDelivery(t *testing.T) {
	publisher := &mockPublisher{
		beacons:   make(map[string][][]byte),
		coleslaws: make(map[string][][]byte),
	}

	store := kitchen.NewOrderStore(kitchen.DefaultOrderStoreConfig())
	handler := kitchen.NewHandlerWithPublisher(publisher, store)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	agentID := "test-agent"
	sessionID := "test-session"

	// Queue multiple orders
	orders := make([]*models.Order, 5)
	for i := 0; i < 5; i++ {
		order := models.NewOrder(sessionID, agentID, "exec", []string{fmt.Sprintf("cmd-%d", i)})
		orders[i] = order
		err := store.Add(order)
		require.NoError(t, err)
		time.Sleep(1 * time.Millisecond) // Ensure ordering
	}

	// Verify orders are delivered in FIFO order
	for i := 0; i < 5; i++ {
		pollResp, err := http.Get(server.URL + "/b/" + agentID)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, pollResp.StatusCode)

		var order models.Order
		err = json.NewDecoder(pollResp.Body).Decode(&order)
		require.NoError(t, err)
		pollResp.Body.Close()

		assert.Equal(t, orders[i].OrderID, order.OrderID)
		assert.Equal(t, []string{fmt.Sprintf("cmd-%d", i)}, order.Args)
	}
}

// TestEndToEnd_SessionRegistry tests session and operator tracking
func TestEndToEnd_SessionRegistry(t *testing.T) {
	registry := kitchen.NewSessionRegistry(kitchen.DefaultSessionRegistryConfig())

	sessionID := "campaign-2024"

	// Operator joins
	op := kitchen.Operator{
		ID:        "op-alice",
		Name:      "Alice",
		SessionID: sessionID,
	}
	registry.RegisterOperator(op)

	// Agent connects
	registry.UpdateAgentBeacon("agent-1", sessionID, "target-host-1", "linux", "amd64")
	registry.UpdateAgentBeacon("agent-2", sessionID, "target-host-2", "windows", "amd64")

	// Verify session state
	session := registry.GetSession(sessionID)
	require.NotNil(t, session)
	assert.Len(t, session.Operators, 1)
	assert.Len(t, session.Agents, 2)

	// Verify stats
	stats := registry.Stats()
	assert.Equal(t, 1, stats["sessions"])
	assert.Equal(t, 1, stats["operators"])
	assert.Equal(t, 2, stats["agents_total"])
	assert.Equal(t, 2, stats["agents_online"])
}

// TestEndToEnd_EventBroadcasting tests event broadcasting for multi-operator coordination
func TestEndToEnd_EventBroadcasting(t *testing.T) {
	broadcaster := kitchen.NewEventBroadcaster(nil) // nil publisher for testing

	ctx := context.Background()
	sessionID := "test-session"

	// These should all work without panic even with nil publisher
	broadcaster.BroadcastAgentConnected(ctx, sessionID, "agent-1", "host-1", "linux", "amd64")
	broadcaster.BroadcastOrderQueued(ctx, sessionID, "agent-1", "order-1", "op-1", "exec")
	broadcaster.BroadcastOrderDelivered(ctx, sessionID, "agent-1", "order-1")
	broadcaster.BroadcastOrderCompleted(ctx, sessionID, "agent-1", "order-1", 0)
	broadcaster.BroadcastOperatorJoined(ctx, sessionID, "op-2", "Bob")
}

// mockPublisher implements kitchen.Publisher for testing
type mockPublisher struct {
	beacons   map[string][][]byte
	coleslaws map[string][][]byte
}

func (m *mockPublisher) PublishBeacon(_ context.Context, agentID string, data []byte) error {
	m.beacons[agentID] = append(m.beacons[agentID], data)
	return nil
}

func (m *mockPublisher) PublishColeslaw(_ context.Context, agentID string, data []byte) error {
	m.coleslaws[agentID] = append(m.coleslaws[agentID], data)
	return nil
}
