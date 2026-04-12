// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package rye

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

func TestNewStager(t *testing.T) {
	stager := NewStager("http://kitchen.example.com", PRTitle)

	assert.NotEmpty(t, stager.ID)
	assert.Equal(t, "http://kitchen.example.com", stager.KitchenURL)
	assert.Equal(t, "bash", stager.ResponseType)
}

func TestStager_CallbackURL(t *testing.T) {
	stager := NewStagerWithID("test123", "http://kitchen.example.com", PRTitle)

	assert.Equal(t, "http://kitchen.example.com/r/smokedmeat/test123", stager.CallbackURL())
}

func TestStager_CallbackURL_TrailingSlash(t *testing.T) {
	stager := NewStagerWithID("test123", "http://kitchen.example.com/", PRTitle)

	assert.Equal(t, "http://kitchen.example.com/r/smokedmeat/test123", stager.CallbackURL())
}

func TestStager_GenerateBash_PRTitle(t *testing.T) {
	stager := NewStagerWithID("abc123", "http://k.io", PRTitle)
	payload := stager.Generate()

	assert.Equal(t, "pr_title", payload.Context)
	assert.Equal(t, "curl_bash", payload.Technique)
	assert.Contains(t, payload.Raw, "curl")
	assert.Contains(t, payload.Raw, "http://k.io/r/smokedmeat/abc123")
	assert.Contains(t, payload.Raw, "bash")
}

func TestStager_GenerateIFS_BranchName(t *testing.T) {
	stager := NewStagerWithID("br123", "http://k.io", BranchName)
	payload := stager.Generate()

	assert.Equal(t, "git_branch", payload.Context)
	assert.Equal(t, "ifs_base64_curl_bash", payload.Technique)

	// Should use $IFS instead of spaces
	assert.Contains(t, payload.Raw, "${IFS}")
	assert.NotContains(t, payload.Raw, " ")

	// Should have base64-encoded URL
	assert.NotEmpty(t, payload.Encoded)
	assert.Contains(t, payload.Raw, "base64")
}

func TestStager_GenerateJS_GitHubScript(t *testing.T) {
	stager := NewStagerWithID("js123", "http://k.io", GitHubScript)
	payload := stager.Generate()

	assert.Equal(t, "github_script", payload.Context)
	assert.Equal(t, "js_quote_polyglot", payload.Technique)
	assert.Contains(t, payload.Raw, "child_process")
	assert.Contains(t, payload.Raw, "execSync")
	assert.Contains(t, payload.Raw, "http://k.io/r/smokedmeat/js123")
	// Should have the polyglot pattern
	assert.Contains(t, payload.Raw, `";require`)
	assert.Contains(t, payload.Raw, `/*'`)
}

func TestStager_GeneratePolyglot(t *testing.T) {
	stager := NewStagerWithID("poly123", "http://k.io", GitHubScript)
	payload := stager.GeneratePolyglot()

	assert.Equal(t, "js_quote_polyglot", payload.Technique)
	// Should have universal quote-breaking pattern for both " and '
	assert.Contains(t, payload.Raw, `";require('child_process')`)
	assert.Contains(t, payload.Raw, `/*'`)
	assert.Contains(t, payload.Raw, `//*/`)
	assert.Contains(t, payload.Raw, "http://k.io/r/smokedmeat/poly123")
}

func TestStager_GenerateSingleQuoteBreak(t *testing.T) {
	stager := NewStagerWithID("single123", "http://k.io", GitHubScript)
	payload := stager.GenerateSingleQuoteBreak()

	assert.Equal(t, "js_single_quote_break", payload.Technique)
	assert.Contains(t, payload.Raw, "');")
	assert.Contains(t, payload.Raw, ";('")
	assert.Contains(t, payload.Raw, "child_process")
}

func TestBranchName_NoSpaces(t *testing.T) {
	stager := NewStagerWithID("test", "http://kitchen.example.com", BranchName)
	payload := stager.Generate()

	// Verify no spaces in the payload
	assert.NotContains(t, payload.Raw, " ", "Branch name payload should not contain spaces")
}

func TestBranchName_NoForbiddenChars(t *testing.T) {
	stager := NewStagerWithID("test", "http://kitchen.example.com", BranchName)
	payload := stager.Generate()

	forbidden := []rune{'~', '^', ':', '?', '*', '[', '\\', '@'}
	for _, c := range forbidden {
		assert.NotContains(t, payload.Raw, string(c),
			"Branch name payload should not contain %q", c)
	}
}

func TestConvenienceFunctions(t *testing.T) {
	kitchenURL := "http://k.io"

	branch := BranchNameStager(kitchenURL)
	assert.Equal(t, "git_branch", branch.Context.Name)

	prTitle := PRTitleStager(kitchenURL)
	assert.Equal(t, "pr_title", prTitle.Context.Name)

	prBody := PRBodyStager(kitchenURL)
	assert.Equal(t, "pr_body", prBody.Context.Name)

	ghScript := GitHubScriptStager(kitchenURL)
	assert.Equal(t, "github_script", ghScript.Context.Name)
}

func TestGenerateStagerID_Unique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateStagerID()
		assert.NotEmpty(t, id)
		assert.True(t, strings.HasPrefix(id, "stg_sm_"))
		assert.False(t, ids[id], "Generated duplicate ID: %s", id)
		ids[id] = true
	}
}

func TestStagerPayload_AllFieldsPopulated(t *testing.T) {
	stager := NewStagerWithID("full", "http://k.io", PRTitle)
	payload := stager.Generate()

	assert.NotEmpty(t, payload.Raw)
	assert.NotEmpty(t, payload.Context)
	assert.NotEmpty(t, payload.Technique)
	assert.Equal(t, stagerurl.Path("full"), payload.KitchenPath)
	assert.NotEmpty(t, payload.CallbackURL)
	assert.NotEmpty(t, payload.Notes)
}

func TestIFSPayload_FitsMaxLength(t *testing.T) {
	// Use a very long kitchen URL
	longURL := "http://" + strings.Repeat("x", 100) + ".com"
	stager := NewStagerWithID("len", longURL, BranchName)
	payload := stager.Generate()

	// Should fit within branch name limit
	if BranchName.MaxLength > 0 {
		assert.LessOrEqual(t, len(payload.Raw), BranchName.MaxLength+50,
			"Payload should approximately fit branch name limit")
	}
}
