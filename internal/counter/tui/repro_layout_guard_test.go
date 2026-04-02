// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartupRenderAllowsInitialTokenWithoutActiveToken(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", configDir)

	err := counter.SaveConfig(&counter.Config{
		KitchenURL:               "https://kitchen.example.com",
		TokenSource:              "gh",
		Target:                   "org:acme",
		LastAnalyzedTarget:       "org:acme",
		InitialAccessToken:       "ghp_initial_abc123",
		InitialAccessTokenSource: "op",
	})
	require.NoError(t, err)

	savedConfig, err := counter.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, savedConfig)

	m := NewModel(Config{
		KitchenURL:               savedConfig.KitchenURL,
		SessionID:                "test",
		Token:                    savedConfig.Token,
		TokenSource:              savedConfig.TokenSource,
		OPSecretRef:              savedConfig.OPSecretRef,
		Target:                   savedConfig.Target,
		InitialAccessToken:       savedConfig.InitialAccessToken,
		InitialAccessTokenSource: savedConfig.InitialAccessTokenSource,
	})

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	rendered := updated.(Model)

	assert.Equal(t, ViewFindings, rendered.view)
	assert.Nil(t, rendered.tokenInfo)
	require.NotNil(t, rendered.initialTokenInfo)
	assert.Equal(t, "ghp_initial_abc123", rendered.initialTokenInfo.Value)
	assert.NotEmpty(t, (&rendered).RenderStickersLayout())
}
