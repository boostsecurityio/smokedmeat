// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHyperlink(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		displayText string
		expected    string
	}{
		{
			name:        "basic hyperlink",
			url:         "https://example.com",
			displayText: "Click here",
			expected:    "\033]8;;https://example.com\033\\Click here\033]8;;\033\\",
		},
		{
			name:        "hyperlink with special chars in URL",
			url:         "https://example.com/path?token=abc123",
			displayText: "Open →",
			expected:    "\033]8;;https://example.com/path?token=abc123\033\\Open →\033]8;;\033\\",
		},
		{
			name:        "empty display text",
			url:         "https://example.com",
			displayText: "",
			expected:    "\033]8;;https://example.com\033\\\033]8;;\033\\",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Hyperlink(tt.url, tt.displayText)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitHubFileLineURL(t *testing.T) {
	assert.Equal(t, "https://github.com/acme/repo/blob/HEAD/.github/workflows/build.yml#L27",
		GitHubFileLineURL("acme/repo", ".github/workflows/build.yml", 27))
	assert.Equal(t, "https://github.com/acme/repo/blob/HEAD/README.md",
		GitHubFileLineURL("acme/repo", "README.md", 0))
}

func TestStripANSI_RemovesHyperlinkEscapeSequences(t *testing.T) {
	linked := Hyperlink("https://github.com/acme/repo", "acme/repo")
	assert.Equal(t, "acme/repo", stripANSI(linked))
	assert.False(t, strings.Contains(stripANSI(linked), "https://"))
}

func TestConfigExternalURL(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "returns external URL when set",
			config: Config{
				KitchenURL:         "http://kitchen:8080",
				KitchenExternalURL: "https://tunnel.example.com",
			},
			expected: "https://tunnel.example.com",
		},
		{
			name: "falls back to KitchenURL when external not set",
			config: Config{
				KitchenURL:         "http://localhost:8080",
				KitchenExternalURL: "",
			},
			expected: "http://localhost:8080",
		},
		{
			name: "returns empty when both not set",
			config: Config{
				KitchenURL:         "",
				KitchenExternalURL: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.ExternalURL())
		})
	}
}

func TestConfigBrowserURL(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "returns browser URL when set",
			config: Config{
				KitchenURL:         "http://kitchen:8080",
				KitchenExternalURL: "https://tunnel.example.com",
				KitchenBrowserURL:  "http://127.0.0.1:18180",
			},
			expected: "http://127.0.0.1:18180",
		},
		{
			name: "falls back to external URL",
			config: Config{
				KitchenURL:         "http://kitchen:8080",
				KitchenExternalURL: "https://tunnel.example.com",
			},
			expected: "https://tunnel.example.com",
		},
		{
			name: "falls back to kitchen URL",
			config: Config{
				KitchenURL: "http://localhost:8080",
			},
			expected: "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.BrowserURL())
		})
	}
}

func TestExtractDispatchInputName(t *testing.T) {
	tests := []struct {
		name     string
		sources  []string
		expected string
	}{
		{
			name:     "finds dispatch input",
			sources:  []string{"github.event.inputs.command"},
			expected: "command",
		},
		{
			name:     "returns first match",
			sources:  []string{"other.source", "github.event.inputs.target"},
			expected: "target",
		},
		{
			name:     "no dispatch input",
			sources:  []string{"github.event.issue.body", "github.event.comment.body"},
			expected: "",
		},
		{
			name:     "empty sources",
			sources:  nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractDispatchInputName(tt.sources))
		})
	}
}

func TestGetEphemeralTokenForDispatch_UsesLiveSessionToken(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	m.sessionLoot = []CollectedSecret{{
		Name:      "GITHUB_TOKEN",
		Value:     "ghs_live123",
		Ephemeral: true,
		Type:      "github_token",
	}}
	m.tokenPermissions = map[string]string{"actions": "write"}

	secret := m.getEphemeralTokenForDispatch()

	if assert.NotNil(t, secret) {
		assert.Equal(t, "GITHUB_TOKEN", secret.Name)
		assert.Equal(t, "ghs_live123", secret.Value)
	}
}

func TestGetEphemeralTokenForDispatch_RequiresKnownDispatchPermission(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	m.sessionLoot = []CollectedSecret{{
		Name:      "GITHUB_TOKEN",
		Value:     "ghs_live123",
		Ephemeral: true,
		Type:      "github_token",
	}}

	secret := m.getEphemeralTokenForDispatch()

	assert.Nil(t, secret)
}

func TestGetEphemeralTokenForDispatch_IgnoresLootGitHubTokenWithoutPermissions(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	m.lootStash = []CollectedSecret{{
		Name:      "GITHUB_TOKEN",
		Value:     "ghs_live123",
		Ephemeral: true,
		Type:      "github_token",
	}}

	secret := m.getEphemeralTokenForDispatch()

	assert.Nil(t, secret)
}

func TestCanUseDeliveryMethod_AppTokenAllowsIssueWithIssuesWrite(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN_acme"}
	m.appTokenPermissions = map[string]string{"issues": "write", "metadata": "read"}

	assert.True(t, m.canUseDeliveryMethod(DeliveryIssue))
	assert.True(t, m.canUseDeliveryMethod(DeliveryComment))
	assert.False(t, m.canUseDeliveryMethod(DeliveryAutoPR))
}

func TestCanUseDeliveryMethod_AppTokenAllowsPRWithContentsAndPullRequests(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN_acme"}
	m.appTokenPermissions = map[string]string{
		"contents":      "write",
		"pull_requests": "write",
		"metadata":      "read",
	}

	assert.True(t, m.canUseDeliveryMethod(DeliveryAutoPR))
	assert.True(t, m.canUseDeliveryMethod(DeliveryLOTP))
}

func TestPermissionAllowsWrite_NormalizesHyphenatedKeys(t *testing.T) {
	perms := map[string]string{"pull-requests": "write"}

	assert.True(t, permissionAllowsWrite(perms, "pull_requests"))
}

func TestScrollInfo_HasOverflow(t *testing.T) {
	tests := []struct {
		name     string
		scroll   ScrollInfo
		overflow bool
	}{
		{"zero value", ScrollInfo{}, false},
		{"fits exactly", ScrollInfo{TotalLines: 10, ViewportSize: 10}, false},
		{"shorter than viewport", ScrollInfo{TotalLines: 5, ViewportSize: 10}, false},
		{"overflows", ScrollInfo{TotalLines: 20, ViewportSize: 10}, true},
		{"zero viewport", ScrollInfo{TotalLines: 5, ViewportSize: 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			col := scrollbarColumn(tt.scroll.ViewportSize, tt.scroll, true)
			assert.Equal(t, tt.overflow, col != nil)
		})
	}
}

func TestApplyScrollIndicator_NoOverflow_Unfocused(t *testing.T) {
	lines := []string{"a", "b"}
	result := applyScrollIndicator(lines, 4, false, nil, ScrollInfo{})
	for i, line := range result {
		assert.True(t, strings.HasPrefix(line, " "), "line %d should start with space, got %q", i, line)
	}
}

func TestApplyScrollIndicator_NoOverflow_Focused_ContentOnly(t *testing.T) {
	lines := []string{"a", "b"}
	result := applyScrollIndicator(lines, 4, true, nil, ScrollInfo{})
	assert.Contains(t, result[0], "a", "content line should have content")
	assert.Contains(t, result[1], "b", "content line should have content")
	assert.True(t, strings.HasPrefix(result[2], " "), "padding line should start with space")
	assert.True(t, strings.HasPrefix(result[3], " "), "padding line should start with space")
}

func TestApplyScrollIndicator_Overflow_ShowsScrollbar(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	scroll := ScrollInfo{TotalLines: 20, ViewportSize: 5, ScrollOffset: 0}
	result := applyScrollIndicator(lines, 5, true, nil, scroll)
	for i, line := range result {
		assert.False(t, strings.HasPrefix(line, " "), "line %d with overflow should not start with plain space", i)
	}
}

func TestApplyScrollIndicator_Overflow_ThumbMoves(t *testing.T) {
	lines := make([]string, 5)
	for i := range lines {
		lines[i] = "x"
	}
	scrollTop := ScrollInfo{TotalLines: 20, ViewportSize: 5, ScrollOffset: 0}
	scrollBot := ScrollInfo{TotalLines: 20, ViewportSize: 5, ScrollOffset: 15}
	resultTop := applyScrollIndicator(lines, 5, true, nil, scrollTop)
	resultBot := applyScrollIndicator(lines, 5, true, nil, scrollBot)

	topPattern := extractIndicatorPattern(resultTop)
	botPattern := extractIndicatorPattern(resultBot)
	assert.NotEqual(t, topPattern, botPattern, "thumb position should differ between top and bottom scroll")
}

func TestApplyScrollIndicator_SelectedOverridesScrollbar(t *testing.T) {
	lines := []string{"a", "b", "c"}
	scroll := ScrollInfo{TotalLines: 20, ViewportSize: 3, ScrollOffset: 0}
	selected := map[int]bool{1: true}
	result := applyScrollIndicator(lines, 3, true, selected, scroll)
	assert.NotEqual(t, result[0], result[1], "selected line should differ from non-selected")
}

func TestApplyScrollIndicator_BackwardCompat(t *testing.T) {
	lines := []string{"hello", "world"}
	oldResult := applyFocusIndicatorAndPad(lines, 4, true)
	newResult := applyScrollIndicator(lines, 4, true, nil, ScrollInfo{})
	assert.Equal(t, oldResult, newResult)

	oldUnfocused := applyFocusIndicatorAndPad(lines, 4, false)
	newUnfocused := applyScrollIndicator(lines, 4, false, nil, ScrollInfo{})
	assert.Equal(t, oldUnfocused, newUnfocused)
}

func TestApplyScrollIndicator_ExactFit(t *testing.T) {
	lines := []string{"a", "b", "c"}
	scroll := ScrollInfo{TotalLines: 3, ViewportSize: 3, ScrollOffset: 0}
	result := applyScrollIndicator(lines, 3, true, nil, scroll)
	for i, line := range result {
		assert.False(t, strings.Contains(line, "┃"), "line %d should not have thumb when content fits exactly", i)
	}
}

func TestApplyScrollIndicator_ThumbMinSize(t *testing.T) {
	lines := make([]string, 5)
	scroll := ScrollInfo{TotalLines: 1000, ViewportSize: 5, ScrollOffset: 0}
	result := applyScrollIndicator(lines, 5, true, nil, scroll)

	thumbCount := 0
	for _, line := range result {
		if strings.Contains(line, "┃") {
			thumbCount++
		}
	}
	assert.GreaterOrEqual(t, thumbCount, 1, "thumb should be at least 1 line even with very large content")
}

func extractIndicatorPattern(lines []string) string {
	var pattern []byte
	for _, line := range lines {
		if strings.Contains(line, "┃") {
			pattern = append(pattern, 'T')
		} else {
			pattern = append(pattern, 't')
		}
	}
	return string(pattern)
}
