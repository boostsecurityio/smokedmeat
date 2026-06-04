// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
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
		CounterID:                "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4",
		CounterStartCount:        7,
		LastReportedStartCount:   4,
		LastVersionCheckAt:       time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
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
	assert.Equal(t, "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4", loaded.CounterID)
	assert.Equal(t, 7, loaded.CounterStartCount)
	assert.Equal(t, 4, loaded.LastReportedStartCount)
	assert.Equal(t, cfg.LastVersionCheckAt, loaded.LastVersionCheckAt)
}

func TestConfig_LastVersionCheckTimestamp_OmittedWhenZero(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", t.TempDir())

	err := SaveConfig(&Config{KitchenURL: "https://kitchen.example.com"})
	require.NoError(t, err)

	data, err := os.ReadFile(ConfigPath())
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(data), "last_version_check_timestamp"))
	assert.False(t, strings.Contains(string(data), "counter_id"))
	assert.False(t, strings.Contains(string(data), "counter_start_count"))
	assert.False(t, strings.Contains(string(data), "last_reported_counter_start_count"))
}

func TestConfig_CustomRulesRoundTrip(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", t.TempDir())
	enabled := true

	err := SaveConfig(&Config{
		Poutine: PoutineConfig{
			CustomRules: CustomRulesConfig{
				Enabled:             &enabled,
				Path:                "~/.smokedmeat/rules",
				DisableBuiltinRules: true,
				RuleMappings: map[string]poutine.CustomRuleMapping{
					"custom_injection_rule": {
						ExploitClass: poutine.ExploitClassInjection,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	loaded, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, loaded)
	require.NotNil(t, loaded.Poutine.CustomRules.Enabled)

	assert.True(t, *loaded.Poutine.CustomRules.Enabled)
	assert.Equal(t, "~/.smokedmeat/rules", loaded.Poutine.CustomRules.Path)
	assert.True(t, loaded.Poutine.CustomRules.DisableBuiltinRules)
	assert.Equal(t, poutine.ExploitClassInjection, loaded.Poutine.CustomRules.RuleMappings["custom_injection_rule"].ExploitClass)
}
