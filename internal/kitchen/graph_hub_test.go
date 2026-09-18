// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type graphHubSnapshotStore struct{}

func (graphHubSnapshotStore) Replace([]byte) error { return nil }

func TestGraphHubTranslatesCommittedGranularChangeSet(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	client := &GraphClient{send: make(chan GraphMessage, 2), hub: hub, mode: graphModeFull}
	hub.register(client)
	t.Cleanup(func() { hub.unregister(client) })
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))
	hub.flushDelta()

	message := <-client.send
	assert.Equal(t, "delta", message.Type)
	delta, ok := message.Data.(*GraphDelta)
	require.True(t, ok)
	assert.Equal(t, uint64(1), delta.Version)
	require.Len(t, delta.AddedNodes, 1)
	assert.Equal(t, "github:org:acme", delta.AddedNodes[0].ID)
}

func TestGraphHubCommittedStateMarkerSupersedesPendingDelta(t *testing.T) {
	live := pantry.New()
	hub := NewGraphHub(live)
	client := &GraphClient{send: make(chan GraphMessage, 2), hub: hub, mode: graphModeFull}
	hub.register(client)
	t.Cleanup(func() { hub.unregister(client) })
	state := pantry.NewCommittedState(live, graphHubSnapshotStore{})

	require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))
	require.NoError(t, state.Replace(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("globex", "github"))
	}))

	message := <-client.send
	assert.Equal(t, "snapshot", message.Type)
	snapshot, ok := message.Data.(GraphSnapshot)
	require.True(t, ok)
	assert.Equal(t, uint64(2), snapshot.Version)
	assert.Equal(t, 2, snapshot.TotalNodes)

	time.Sleep(2 * graphBatchWindow)
	select {
	case unexpected := <-client.send:
		t.Fatalf("unexpected state after committed snapshot: %#v", unexpected)
	default:
	}
}
