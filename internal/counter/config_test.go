// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_InitialAccessTokenFields_RoundTrip(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", t.TempDir())

	cfg := &Config{
		KitchenURL:               "https://kitchen.example.com",
		SessionID:                "sess1234",
		Operator:                 "testop",
		Token:                    "ghp_active",
		TokenSource:              "manual",
		Target:                   "acme/api",
		InitialAccessToken:       "ghp_initial_abc123",
		InitialAccessTokenSource: "setup-wizard",
	}

	err := SaveConfig(cfg)
	require.NoError(t, err)

	loaded, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "sess1234", loaded.SessionID)
	assert.Equal(t, "ghp_initial_abc123", loaded.InitialAccessToken)
	assert.Equal(t, "setup-wizard", loaded.InitialAccessTokenSource)
	assert.Equal(t, "ghp_active", loaded.Token)
	assert.Equal(t, "manual", loaded.TokenSource)
	assert.Equal(t, "https://kitchen.example.com", loaded.KitchenURL)
	assert.Equal(t, "testop", loaded.Operator)
	assert.Equal(t, "acme/api", loaded.Target)
}
