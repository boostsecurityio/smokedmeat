// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen"
)

func TestLoadConfigFromEnv_AuthLimitOverrides(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("AUTH_CHALLENGE_RATE_PER_SECOND", "0.25")
	t.Setenv("AUTH_CHALLENGE_BURST", "4")
	t.Setenv("AUTH_CHALLENGE_MAX_IP_BUCKETS", "64")
	t.Setenv("AUTH_MAX_PENDING_CHALLENGES", "128")
	t.Setenv("AUTH_MAX_PENDING_CHALLENGES_PER_OPERATOR", "3")

	config, err := loadConfigFromEnv()
	require.NoError(t, err)

	assert.Equal(t, 0.25, config.AuthChallengeRatePerSecond)
	assert.Equal(t, 4, config.AuthChallengeBurst)
	assert.Equal(t, 64, config.AuthChallengeMaxIPBuckets)
	assert.Equal(t, 128, config.AuthMaxPendingChallenges)
	assert.Equal(t, 3, config.AuthMaxPendingChallengesPerOperator)
}

func TestLoadConfigFromEnv_InvalidAuthLimit(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("AUTH_MAX_PENDING_CHALLENGES", "nope")

	_, err := loadConfigFromEnv()
	require.Error(t, err)
	assert.ErrorContains(t, err, "AUTH_MAX_PENDING_CHALLENGES")
}

func TestLoadConfigFromEnv_TokenMode(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("AUTH_MODE", "token")
	t.Setenv("AUTH_TOKEN", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	config, err := loadConfigFromEnv()
	require.NoError(t, err)

	assert.Equal(t, kitchen.AuthModeToken, config.AuthMode)
	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", config.AuthToken)
}

func clearConfigEnv(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"KITCHEN_PORT",
		"NATS_URL",
		"KITCHEN_DB_PATH",
		"AUTHORIZED_KEYS_PATH",
		"AUTH_MODE",
		"AUTH_TOKEN",
		"AUTH_CHALLENGE_RATE_PER_SECOND",
		"AUTH_CHALLENGE_BURST",
		"AUTH_CHALLENGE_MAX_IP_BUCKETS",
		"AUTH_MAX_PENDING_CHALLENGES",
		"AUTH_MAX_PENDING_CHALLENGES_PER_OPERATOR",
	} {
		t.Setenv(name, "")
	}
}
