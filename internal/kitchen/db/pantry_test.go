// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestPantrySnapshotStoreReopensCommittedRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pantry.db")
	database, err := Open(Config{Path: path, CreateDir: true})
	require.NoError(t, err)

	live := pantry.New()
	state := pantry.NewCommittedState(live, NewPantrySnapshotStore(database))
	require.NoError(t, state.Update(context.Background(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))
	require.NoError(t, database.Close())

	database, err = Open(Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, database.Close()) })
	restored, err := database.LoadPantry()
	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Equal(t, uint64(1), restored.Revision())
	assert.True(t, restored.HasAsset("github:org:acme"))
}

func TestPantrySnapshotStoreOwnsPersistedBytes(t *testing.T) {
	database, err := Open(Config{Path: filepath.Join(t.TempDir(), "pantry.db"), CreateDir: true})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, database.Close()) })

	snapshot := pantry.Snapshot{Revision: 7, Assets: []pantry.Asset{pantry.NewOrganization("acme", "github")}}
	serialized, err := json.Marshal(snapshot)
	require.NoError(t, err)
	require.NoError(t, NewPantrySnapshotStore(database).Replace(serialized))
	for index := range serialized {
		serialized[index] = 'x'
	}

	restored, err := database.LoadPantry()
	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Equal(t, uint64(7), restored.Revision())
	assert.True(t, restored.HasAsset("github:org:acme"))
}

func TestLoadPantryReturnsNilWithoutSnapshot(t *testing.T) {
	database, err := Open(Config{Path: filepath.Join(t.TempDir(), "pantry.db"), CreateDir: true})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, database.Close()) })

	restored, err := database.LoadPantry()
	require.NoError(t, err)
	assert.Nil(t, restored)
}
