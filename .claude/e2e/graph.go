// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const graphProbeTimeout = 30 * time.Second

type graphWireMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type graphWireSnapshot struct {
	Revision   uint64            `json:"revision"`
	Mode       string            `json:"mode"`
	TotalNodes int               `json:"total_nodes"`
	TotalEdges int               `json:"total_edges"`
	Nodes      []json.RawMessage `json:"nodes"`
	Edges      []json.RawMessage `json:"edges"`
}

type graphWireDelta struct {
	BaseRevision uint64 `json:"base_revision"`
	Revision     uint64 `json:"revision"`
}

type graphWireFence struct {
	Revision uint64 `json:"revision"`
}

type graphProbe struct {
	connection *websocket.Conn
	mode       string
	revision   uint64
}

type graphSmokeProbes struct {
	full     *graphProbe
	filtered *graphProbe
	auto     *graphProbe
}

func connectGraphSmokeProbes(t *testing.T, kitchenURL, authToken string) *graphSmokeProbes {
	t.Helper()

	return &graphSmokeProbes{
		full:     connectGraphProbe(t, kitchenURL, authToken, "full"),
		filtered: connectGraphProbe(t, kitchenURL, authToken, "filtered"),
		auto:     connectGraphProbe(t, kitchenURL, authToken, "auto"),
	}
}

func connectGraphProbe(t *testing.T, kitchenURL, authToken, mode string) *graphProbe {
	t.Helper()

	endpoint, err := graphWebSocketURL(kitchenURL, authToken, mode)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), graphProbeTimeout)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, endpoint, nil)
	require.NoError(t, err)
	connection.SetReadLimit(-1)
	t.Cleanup(func() { _ = connection.Close(websocket.StatusNormalClosure, "") })

	probe := &graphProbe{connection: connection, mode: mode}
	message := probe.read(t)
	require.Equal(t, "snapshot", message.Type, "%s mode must start from a complete snapshot", mode)
	snapshot := decodeGraphData[graphWireSnapshot](t, message)
	require.Equal(t, uint64(0), snapshot.Revision, "%s mode should connect to the purged Pantry", mode)
	require.Zero(t, snapshot.TotalNodes)
	require.Zero(t, snapshot.TotalEdges)
	probe.revision = snapshot.Revision
	return probe
}

func graphWebSocketURL(kitchenURL, authToken, mode string) (string, error) {
	endpoint, err := url.Parse(kitchenURL)
	if err != nil {
		return "", fmt.Errorf("parse Kitchen URL: %w", err)
	}
	switch endpoint.Scheme {
	case "http":
		endpoint.Scheme = "ws"
	case "https":
		endpoint.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported Kitchen URL scheme %q", endpoint.Scheme)
	}
	endpoint.Path = "/graph/ws"
	query := endpoint.Query()
	query.Set("token", authToken)
	query.Set("mode", mode)
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func verifyGraphPublicationAfterAnalysis(t *testing.T, probes *graphSmokeProbes) {
	t.Helper()

	fullSnapshot := probes.full.refreshAfterFence(t)
	require.Equal(t, "full", fullSnapshot.Mode)
	require.NotZero(t, fullSnapshot.TotalNodes)
	require.Len(t, fullSnapshot.Nodes, fullSnapshot.TotalNodes)
	require.Len(t, fullSnapshot.Edges, fullSnapshot.TotalEdges)

	filteredSnapshot := probes.filtered.waitForSnapshot(t, fullSnapshot.Revision)
	require.Equal(t, "filtered", filteredSnapshot.Mode)
	require.NotZero(t, filteredSnapshot.TotalNodes)
	assert.LessOrEqual(t, len(filteredSnapshot.Nodes), filteredSnapshot.TotalNodes)
	assert.LessOrEqual(t, len(filteredSnapshot.Edges), filteredSnapshot.TotalEdges)

	autoSnapshot := probes.auto.waitForSnapshot(t, fullSnapshot.Revision)
	require.NotZero(t, autoSnapshot.TotalNodes)
	assert.Contains(t, []string{"full", "filtered"}, autoSnapshot.Mode)
	assert.LessOrEqual(t, len(autoSnapshot.Nodes), autoSnapshot.TotalNodes)
	assert.LessOrEqual(t, len(autoSnapshot.Edges), autoSnapshot.TotalEdges)
}

func (p *graphProbe) refreshAfterFence(t *testing.T) graphWireSnapshot {
	t.Helper()

	minimumRevision := p.revision
	for {
		message := p.read(t)
		switch message.Type {
		case "delta":
			delta := decodeGraphData[graphWireDelta](t, message)
			require.Equal(t, p.revision, delta.BaseRevision, "full-mode deltas must be contiguous before a fence")
			require.Greater(t, delta.Revision, p.revision)
			p.revision = delta.Revision
		case "snapshot_required":
			fence := decodeGraphData[graphWireFence](t, message)
			require.Greater(t, fence.Revision, p.revision)
			minimumRevision = fence.Revision
			p.requestSnapshot(t)
			return p.waitForFullSnapshot(t, minimumRevision)
		default:
			t.Fatalf("full mode received unexpected graph message %q before committed-state fence", message.Type)
		}
	}
}

func (p *graphProbe) waitForFullSnapshot(t *testing.T, minimumRevision uint64) graphWireSnapshot {
	t.Helper()

	for {
		message := p.read(t)
		switch message.Type {
		case "snapshot":
			snapshot := decodeGraphData[graphWireSnapshot](t, message)
			require.GreaterOrEqual(t, snapshot.Revision, minimumRevision)
			p.revision = snapshot.Revision
			return snapshot
		case "delta":
			delta := decodeGraphData[graphWireDelta](t, message)
			minimumRevision = max(minimumRevision, delta.Revision)
		case "snapshot_required":
			fence := decodeGraphData[graphWireFence](t, message)
			minimumRevision = max(minimumRevision, fence.Revision)
		default:
			t.Fatalf("full mode received unexpected graph message %q while refreshing", message.Type)
		}
	}
}

func (p *graphProbe) waitForSnapshot(t *testing.T, minimumRevision uint64) graphWireSnapshot {
	t.Helper()

	for {
		message := p.read(t)
		require.Equal(t, "snapshot", message.Type, "%s mode must receive complete snapshots while refreshing", p.mode)
		snapshot := decodeGraphData[graphWireSnapshot](t, message)
		require.GreaterOrEqual(t, snapshot.Revision, p.revision)
		p.revision = snapshot.Revision
		if snapshot.Revision >= minimumRevision {
			return snapshot
		}
	}
}

func (p *graphProbe) requestSnapshot(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), graphProbeTimeout)
	defer cancel()
	require.NoError(t, wsjson.Write(ctx, p.connection, map[string]any{
		"type": "snapshot_request",
		"data": map[string]string{"mode": p.mode},
	}))
}

func (p *graphProbe) read(t *testing.T) graphWireMessage {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), graphProbeTimeout)
	defer cancel()
	var message graphWireMessage
	require.NoError(t, wsjson.Read(ctx, p.connection, &message), "%s graph stream did not publish in time", p.mode)
	return message
}

func decodeGraphData[T any](t *testing.T, message graphWireMessage) T {
	t.Helper()

	var data T
	require.NoError(t, json.Unmarshal(message.Data, &data))
	return data
}
