// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type graphHubSnapshotStore struct{}

func (graphHubSnapshotStore) Replace([]byte) error { return nil }

func TestGraphHubPublishesContiguousFullModeDeltas(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	client := registerGraphClient(t, hub, graphModeFull, 4)
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	for _, name := range []string{"acme", "globex"} {
		require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
			return candidate.AddAsset(pantry.NewOrganization(name, "github"))
		}))
	}

	first := receiveGraphMessage(t, client)
	assert.Equal(t, "delta", first.Type)
	firstDelta, ok := first.Data.(GraphDelta)
	require.True(t, ok)
	assert.Equal(t, uint64(0), firstDelta.BaseRevision)
	assert.Equal(t, uint64(1), firstDelta.Revision)
	require.Len(t, firstDelta.AddedNodes, 1)
	assert.Equal(t, "github:org:acme", firstDelta.AddedNodes[0].ID)

	second := receiveGraphMessage(t, client)
	assert.Equal(t, "delta", second.Type)
	secondDelta, ok := second.Data.(GraphDelta)
	require.True(t, ok)
	assert.Equal(t, uint64(1), secondDelta.BaseRevision)
	assert.Equal(t, uint64(2), secondDelta.Revision)
	require.Len(t, secondDelta.AddedNodes, 1)
	assert.Equal(t, "github:org:globex", secondDelta.AddedNodes[0].ID)
}

func TestGraphHubPublishesSnapshotForProjectedModesAfterEveryChange(t *testing.T) {
	for _, mode := range []string{graphModeFiltered, graphModeAuto} {
		t.Run(mode, func(t *testing.T) {
			live := pantry.New()
			hub := NewGraphHub(live)
			client := registerGraphClient(t, hub, mode, 2)
			state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

			require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
				return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
			}))

			message := receiveGraphMessage(t, client)
			assert.Equal(t, "snapshot", message.Type)
			snapshot, ok := message.Data.(GraphSnapshot)
			require.True(t, ok)
			assert.Equal(t, uint64(1), snapshot.Revision)
			assert.Equal(t, 1, snapshot.TotalNodes)
		})
	}
}

func TestGraphHubPublishesSnapshotRequiredForCommittedState(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	client := registerGraphClient(t, hub, graphModeFull, 3)
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))
	require.NoError(t, state.Replace(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("globex", "github"))
	}))

	deltaMessage := receiveGraphMessage(t, client)
	assert.Equal(t, "delta", deltaMessage.Type)

	fenceMessage := receiveGraphMessage(t, client)
	assert.Equal(t, "snapshot_required", fenceMessage.Type)
	fence, ok := fenceMessage.Data.(GraphSnapshotRequired)
	require.True(t, ok)
	assert.Equal(t, uint64(2), fence.Revision)
}

func TestGraphHubPublishesSnapshotForProjectedModeAfterCommittedState(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	client := registerGraphClient(t, hub, graphModeFiltered, 2)
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	require.NoError(t, state.Replace(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))

	message := receiveGraphMessage(t, client)
	assert.Equal(t, "snapshot", message.Type)
	snapshot, ok := message.Data.(GraphSnapshot)
	require.True(t, ok)
	assert.Equal(t, uint64(1), snapshot.Revision)
	assert.Equal(t, 1, snapshot.TotalNodes)
}

func TestGraphHubDisconnectsSaturatedClientWithoutAffectingHealthyClients(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	healthy := registerGraphClient(t, hub, graphModeFull, 2)
	saturated := &GraphClient{send: make(chan GraphMessage, 1), hub: hub, mode: graphModeFull}
	require.True(t, hub.register(saturated))
	t.Cleanup(func() { hub.unregister(saturated) })
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))

	assert.Equal(t, 1, hub.ClientCount())
	message := receiveGraphMessage(t, healthy)
	assert.Equal(t, "delta", message.Type)

	initial, ok := <-saturated.send
	require.True(t, ok)
	assert.Equal(t, "snapshot", initial.Type)
	_, ok = <-saturated.send
	assert.False(t, ok)
}

func TestGraphHubReconnectStartsWithCurrentSnapshot(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))

	client := &GraphClient{send: make(chan GraphMessage, 1), hub: hub, mode: graphModeFull}
	require.True(t, hub.register(client))
	t.Cleanup(func() { hub.unregister(client) })

	message := receiveGraphMessage(t, client)
	assert.Equal(t, "snapshot", message.Type)
	snapshot, ok := message.Data.(GraphSnapshot)
	require.True(t, ok)
	assert.Equal(t, uint64(1), snapshot.Revision)
	assert.Equal(t, 1, snapshot.TotalNodes)
}

func TestGraphHubSnapshotRevisionMatchesConcurrentState(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	const writes = 200
	done := make(chan struct{})
	var writerErr error
	go func() {
		defer close(done)
		for i := range writes {
			if err := state.Update(context.Background(), func(candidate *pantry.Pantry) error {
				return candidate.AddAsset(pantry.NewOrganization(fmt.Sprintf("org-%03d", i), "github"))
			}); err != nil {
				writerErr = err
				return
			}
		}
	}()

	for {
		snapshot := hub.buildSnapshot(graphModeFull)
		assert.Equal(t, snapshot.Revision, uint64(snapshot.TotalNodes))
		select {
		case <-done:
			require.NoError(t, writerErr)
			final := hub.buildSnapshot(graphModeFull)
			assert.Equal(t, uint64(writes), final.Revision)
			assert.Equal(t, writes, final.TotalNodes)
			return
		default:
		}
	}
}

func registerGraphClient(t *testing.T, hub *GraphHub, mode string, capacity int) *GraphClient {
	t.Helper()
	client := &GraphClient{send: make(chan GraphMessage, capacity), hub: hub, mode: mode}
	require.True(t, hub.register(client))
	t.Cleanup(func() { hub.unregister(client) })

	initial := receiveGraphMessage(t, client)
	require.Equal(t, "snapshot", initial.Type)
	return client
}

func receiveGraphMessage(t *testing.T, client *GraphClient) GraphMessage {
	t.Helper()
	select {
	case message, ok := <-client.send:
		require.True(t, ok)
		return message
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for graph message")
		return GraphMessage{}
	}
}
