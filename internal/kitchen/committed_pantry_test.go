// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestHandlerKnownRepositoryCommitsOnePantryRevision(t *testing.T) {
	database := newTestDB(t)
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.SetDatabase(database)
	body, err := json.Marshal(KnownEntityRequest{
		ID:            "repo:acme/api",
		EntityType:    "repo",
		Name:          "acme/api",
		SessionID:     "session-1",
		DiscoveredVia: "analysis",
		IsPrivate:     true,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/known-entities", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.handlePostKnownEntities(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, uint64(1), h.Pantry().Revision())
	persisted, err := database.LoadPantry()
	require.NoError(t, err)
	require.NotNil(t, persisted)
	assert.Equal(t, uint64(1), persisted.Revision())
	repo, err := persisted.GetAsset("github:acme/api")
	require.NoError(t, err)
	assert.Equal(t, true, repo.Properties["private"])
}

func TestHandlerSetDatabaseRestoresCommittedPantryRevision(t *testing.T) {
	database := newTestDB(t)
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.SetDatabase(database)
	require.NoError(t, h.committedPantry().Update(t.Context(), func(candidate *pantry.Pantry) error {
		return candidate.AddAsset(pantry.NewOrganization("acme", "github"))
	}))

	restarted := NewHandlerWithPublisher(&mockPublisher{}, nil)
	restarted.SetDatabase(database)

	assert.Equal(t, uint64(1), restarted.Pantry().Revision())
	assert.True(t, restarted.Pantry().HasAsset("github:org:acme"))
}
