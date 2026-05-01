// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "test.db")})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpen(t *testing.T) {
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "test.db"), CreateDir: true})
	require.NoError(t, err)
	defer db.Close()

	assert.NotNil(t, db)
}

func TestClose(t *testing.T) {
	db, err := Open(Config{Path: filepath.Join(t.TempDir(), "test.db")})
	require.NoError(t, err)

	err = db.Close()
	assert.NoError(t, err)
}

func TestOrderRepository_ListPending(t *testing.T) {
	db := setupDB(t)
	repo := NewOrderRepository(db)

	orders, err := repo.ListPending()
	require.NoError(t, err)
	assert.Empty(t, orders)
}

func TestAgentRepository_UpsertPreservesAgentToken(t *testing.T) {
	db := setupDB(t)
	repo := NewAgentRepository(db)
	now := time.Now().UTC()

	err := repo.Upsert(&AgentRow{
		AgentID:        "agt-1",
		SessionID:      "sess-1",
		AgentToken:     "agt_token",
		TokenCreatedAt: now,
		TokenExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	err = repo.Upsert(&AgentRow{
		AgentID:   "agt-1",
		SessionID: "sess-1",
		Hostname:  "runner-1",
		OS:        "linux",
		Arch:      "amd64",
		FirstSeen: now,
		LastSeen:  now,
		IsOnline:  true,
	})
	require.NoError(t, err)

	row, err := repo.Get("agt-1")
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "agt_token", row.AgentToken)
	assert.Equal(t, now, row.TokenCreatedAt)
	assert.Equal(t, now.Add(time.Hour), row.TokenExpiresAt)
	assert.Equal(t, "runner-1", row.Hostname)
}
