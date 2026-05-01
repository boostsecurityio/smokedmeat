// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func TestDetermineSessionID_PrefersFlag(t *testing.T) {
	sid := determineSessionID("flag1234", &counter.Config{SessionID: "saved5678"})

	assert.Equal(t, "flag1234", sid)
}

func TestDetermineSessionID_UsesSavedConfig(t *testing.T) {
	sid := determineSessionID("", &counter.Config{SessionID: "saved5678"})

	assert.Equal(t, "saved5678", sid)
}

func TestDetermineSessionID_GeneratesWhenUnset(t *testing.T) {
	sid := determineSessionID("", nil)

	assert.Len(t, sid, 8)
	assert.NotEmpty(t, sid)
}
