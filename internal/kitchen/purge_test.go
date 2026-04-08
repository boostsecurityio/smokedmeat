// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestHandler_runPurge_PreviewCountsRepoScopeForRequestingSession(t *testing.T) {
	database := newTestDB(t)
	entityRepo := db.NewKnownEntityRepository(database)
	require.NoError(t, entityRepo.Upsert(&db.KnownEntityRow{
		ID:         "repo-sess1",
		EntityType: db.EntityTypeRepo,
		Name:       "acme/api",
		SessionID:  "sess-1",
	}))
	require.NoError(t, entityRepo.Upsert(&db.KnownEntityRow{
		ID:         "repo-sess2",
		EntityType: db.EntityTypeRepo,
		Name:       "acme/api",
		SessionID:  "sess-2",
	}))

	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.database = database
	h.pantry = purgeTestPantry(t)

	resp, err := h.runPurge("sess-1", "repo", "acme/api", true)
	require.NoError(t, err)

	assert.Equal(t, "preview", resp.Status)
	assert.True(t, resp.DryRun)
	assert.Equal(t, 3, resp.PantryAssets)
	assert.Equal(t, 1, resp.KnownEntities)
	assert.True(t, h.Pantry().HasAsset("github:acme/api"))
}

func TestHandler_runPurge_ExecuteRemovesOrgScopeAndPreservesHistory(t *testing.T) {
	database := newTestDB(t)
	entityRepo := db.NewKnownEntityRepository(database)
	for _, row := range []*db.KnownEntityRow{
		{ID: "org-sess1", EntityType: db.EntityTypeOrg, Name: "acme", SessionID: "sess-1"},
		{ID: "repo-api-sess1", EntityType: db.EntityTypeRepo, Name: "acme/api", SessionID: "sess-1"},
		{ID: "repo-web-sess1", EntityType: db.EntityTypeRepo, Name: "acme/web", SessionID: "sess-1"},
		{ID: "repo-api-sess2", EntityType: db.EntityTypeRepo, Name: "acme/api", SessionID: "sess-2"},
		{ID: "repo-globex-sess1", EntityType: db.EntityTypeRepo, Name: "globex/portal", SessionID: "sess-1"},
	} {
		require.NoError(t, entityRepo.Upsert(row))
	}

	historyRepo := db.NewHistoryRepository(database)
	require.NoError(t, historyRepo.Insert(&db.HistoryRow{
		ID:        "hist-existing",
		Type:      db.HistoryAnalysisCompleted,
		Timestamp: time.Now().Add(-time.Minute),
		SessionID: "sess-1",
		Target:    "acme",
		Outcome:   "3 findings",
	}))

	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.database = database
	h.pantry = purgeTestPantry(t)

	resp, err := h.runPurge("sess-1", "org", "acme", false)
	require.NoError(t, err)

	assert.Equal(t, "purged", resp.Status)
	assert.False(t, resp.DryRun)
	assert.Equal(t, 6, resp.PantryAssets)
	assert.Equal(t, 3, resp.KnownEntities)

	assert.False(t, h.Pantry().HasAsset("github:org:acme"))
	assert.False(t, h.Pantry().HasAsset("github:acme/api"))
	assert.False(t, h.Pantry().HasAsset("github:acme/web"))
	assert.False(t, h.Pantry().HasAsset("github:acme/api:workflow:.github/workflows/build.yml"))
	assert.True(t, h.Pantry().HasAsset("github:org:globex"))
	assert.True(t, h.Pantry().HasAsset("github:globex/portal"))

	sess1Entities, err := entityRepo.ListBySession("sess-1")
	require.NoError(t, err)
	require.Len(t, sess1Entities, 1)
	assert.Equal(t, "globex/portal", sess1Entities[0].Name)

	sess2Entities, err := entityRepo.ListBySession("sess-2")
	require.NoError(t, err)
	require.Len(t, sess2Entities, 1)
	assert.Equal(t, "acme/api", sess2Entities[0].Name)

	entries, err := historyRepo.List(0)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, db.HistoryAnalysisCompleted, entries[0].Type)
	assert.Equal(t, db.HistoryPurgeExecuted, entries[1].Type)
	assert.Equal(t, "sess-1", entries[1].SessionID)
	assert.Equal(t, "org", entries[1].TargetType)
	assert.Equal(t, "acme", entries[1].Target)
	assert.Equal(t, "6 pantry assets, 3 known entities", entries[1].Outcome)
}

func TestHandler_runPurge_RejectsEmptySessionID(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)

	_, err := h.runPurge("", "repo", "acme/api", true)

	require.Error(t, err)
	assert.Equal(t, "session_id is required", err.Error())
}

func TestHandler_handlePurge_RejectsEmptySessionID(t *testing.T) {
	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/purge", bytes.NewBufferString(`{"session_id":"","scope_type":"repo","scope_value":"acme/api","dry_run":true}`))
	rec := httptest.NewRecorder()

	h.handlePurge(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "session_id is required")
}

func purgeTestPantry(t *testing.T) *pantry.Pantry {
	t.Helper()

	p := pantry.New()
	for _, asset := range []pantry.Asset{
		pantry.NewOrganization("acme", "github"),
		pantry.NewRepository("acme", "api", "github"),
		pantry.NewWorkflow("github:acme/api", ".github/workflows/build.yml"),
		pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/build.yml", 12),
		pantry.NewRepository("acme", "web", "github"),
		pantry.NewWorkflow("github:acme/web", ".github/workflows/deploy.yml"),
		pantry.NewOrganization("globex", "github"),
		pantry.NewRepository("globex", "portal", "github"),
	} {
		require.NoError(t, p.AddAsset(asset))
	}

	for _, edge := range []struct {
		from string
		to   string
		rel  pantry.Relationship
	}{
		{from: "github:org:acme", to: "github:acme/api", rel: pantry.Contains()},
		{from: "github:acme/api", to: "github:acme/api:workflow:.github/workflows/build.yml", rel: pantry.Contains()},
		{from: "github:acme/api:workflow:.github/workflows/build.yml", to: "vuln:injection:.github/workflows/build.yml:12", rel: pantry.VulnerableTo("injection", "critical")},
		{from: "github:org:acme", to: "github:acme/web", rel: pantry.Contains()},
		{from: "github:acme/web", to: "github:acme/web:workflow:.github/workflows/deploy.yml", rel: pantry.Contains()},
		{from: "github:org:globex", to: "github:globex/portal", rel: pantry.Contains()},
	} {
		require.NoError(t, p.AddRelationship(edge.from, edge.to, edge.rel))
	}

	return p
}
