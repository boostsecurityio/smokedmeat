// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestUpdate_PurgeCompletedClearsPurgedTargetAndReplacesState(t *testing.T) {
	client := &mockKitchenClient{}
	m := NewModel(Config{SessionID: "sess-1"})
	m.kitchenClient = client
	m.phase = PhaseRecon
	m.target = "acme/api"
	m.targetType = "repo"
	m.knownEntities["repo:stale"] = &KnownEntity{ID: "repo:stale", EntityType: "repo", Name: "acme/api"}
	m.knownEntities["repo:keep"] = &KnownEntity{ID: "repo:keep", EntityType: "repo", Name: "globex/portal"}
	m.pantry = purgeCounterPantry(t)

	result, _ := m.Update(PurgeCompletedMsg{
		Response: counter.PurgeResponse{
			Status:        "purged",
			SessionID:     "sess-1",
			ScopeType:     "repo",
			ScopeValue:    "acme/api",
			PantryAssets:  3,
			KnownEntities: 1,
		},
		Pantry: purgeCounterPantryAfterRepoPurge(t),
		KnownEntities: []counter.KnownEntityPayload{
			{ID: "repo:keep", EntityType: "repo", Name: "globex/portal"},
		},
	})
	model := result.(Model)

	assert.Empty(t, model.target)
	assert.Empty(t, model.targetType)
	assert.Len(t, model.knownEntities, 1)
	assert.Equal(t, "globex/portal", model.knownEntities["repo:keep"].Name)
	assert.False(t, model.pantry.HasAsset("github:acme/api"))
	assert.True(t, model.pantry.HasAsset("github:globex/portal"))
	assert.Equal(t, "warning", model.output[len(model.output)-2].Type)
	assert.Contains(t, model.output[len(model.output)-2].Content, "Current target was purged and has been cleared")
	assert.Equal(t, "info", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Choose a new target")
	require.NotEmpty(t, model.activityLog.Entries())
	assert.True(t, strings.Contains(model.activityLog.Entries()[len(model.activityLog.Entries())-1].Message, "choose a new target"))
}

func TestUpdate_PurgeCompletedKeepsUnrelatedTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "sess-1"})
	m.phase = PhaseRecon
	m.target = "globex/portal"
	m.targetType = "repo"

	result, _ := m.Update(PurgeCompletedMsg{
		Response: counter.PurgeResponse{
			Status:        "purged",
			SessionID:     "sess-1",
			ScopeType:     "repo",
			ScopeValue:    "acme/api",
			PantryAssets:  3,
			KnownEntities: 1,
		},
		Pantry:        purgeCounterPantryAfterRepoPurge(t),
		KnownEntities: []counter.KnownEntityPayload{{ID: "repo:keep", EntityType: "repo", Name: "globex/portal"}},
	})
	model := result.(Model)

	assert.Equal(t, "globex/portal", model.target)
	assert.Equal(t, "repo", model.targetType)
	require.NotEmpty(t, model.activityLog.Entries())
	assert.Equal(t, "Purged repo:acme/api", model.activityLog.Entries()[len(model.activityLog.Entries())-1].Message)
}

func TestHandlePurgeCommand_UsesCurrentTargetForPreview(t *testing.T) {
	m := NewModel(Config{SessionID: "sess-1"})
	m.kitchenClient = &mockKitchenClient{
		purgeResp: &counter.PurgeResponse{
			Status:        "preview",
			SessionID:     "sess-1",
			ScopeType:     "repo",
			ScopeValue:    "acme/api",
			DryRun:        true,
			PantryAssets:  3,
			KnownEntities: 1,
		},
	}
	m.phase = PhaseRecon
	m.target = "acme/api"
	m.targetType = "repo"

	result, cmd := m.handlePurgeCommand(nil)
	model := result.(Model)
	require.NotNil(t, cmd)
	require.Len(t, model.output, 1)
	assert.Equal(t, "Previewing purge for repo:acme/api...", model.output[0].Content)
}

func TestHandlePurgeCommand_RejectsEmptySessionID(t *testing.T) {
	m := NewModel(Config{})
	m.kitchenClient = &mockKitchenClient{}
	m.phase = PhaseRecon
	m.target = "acme/api"
	m.targetType = "repo"

	result, cmd := m.handlePurgeCommand(nil)
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 2)
	assert.Equal(t, "Operator session is not available", model.output[0].Content)
	assert.Equal(t, "Reconnect to Kitchen and try again before purging analysis state", model.output[1].Content)
}

func TestPurgeScopeCoversTarget(t *testing.T) {
	tests := []struct {
		name       string
		scopeType  string
		scopeValue string
		targetType string
		target     string
		want       bool
	}{
		{name: "repo matches repo", scopeType: "repo", scopeValue: "acme/api", targetType: "repo", target: "acme/api", want: true},
		{name: "repo misses other repo", scopeType: "repo", scopeValue: "acme/api", targetType: "repo", target: "acme/web", want: false},
		{name: "org matches repo in org", scopeType: "org", scopeValue: "acme", targetType: "repo", target: "acme/api", want: true},
		{name: "org matches org", scopeType: "org", scopeValue: "acme", targetType: "org", target: "acme", want: true},
		{name: "org misses other org", scopeType: "org", scopeValue: "acme", targetType: "org", target: "globex", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, purgeScopeCoversTarget(tt.scopeType, tt.scopeValue, tt.targetType, tt.target))
		})
	}
}

func purgeCounterPantry(t *testing.T) *pantry.Pantry {
	t.Helper()

	p := pantry.New()
	for _, asset := range []pantry.Asset{
		pantry.NewOrganization("acme", "github"),
		pantry.NewRepository("acme", "api", "github"),
		pantry.NewWorkflow("github:acme/api", ".github/workflows/build.yml"),
		pantry.NewVulnerability("injection", "pkg:github/acme/api", ".github/workflows/build.yml", 12),
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
		{from: "github:org:globex", to: "github:globex/portal", rel: pantry.Contains()},
	} {
		require.NoError(t, p.AddRelationship(edge.from, edge.to, edge.rel))
	}

	return p
}

func purgeCounterPantryAfterRepoPurge(t *testing.T) *pantry.Pantry {
	t.Helper()

	p := pantry.New()
	for _, asset := range []pantry.Asset{
		pantry.NewOrganization("globex", "github"),
		pantry.NewRepository("globex", "portal", "github"),
	} {
		require.NoError(t, p.AddAsset(asset))
	}
	require.NoError(t, p.AddRelationship("github:org:globex", "github:globex/portal", pantry.Contains()))
	return p
}
