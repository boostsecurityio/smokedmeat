// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package rye

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerator_GenerateBashPayloads(t *testing.T) {
	gen := NewGenerator(PRTitle)
	payloads := gen.Generate("id")

	require.NotEmpty(t, payloads)

	// Should have backtick substitution
	var hasBacktick bool
	for _, p := range payloads {
		if p.Technique == "backtick_substitution" {
			hasBacktick = true
			assert.Equal(t, "`id`", p.Raw)
		}
	}
	assert.True(t, hasBacktick, "Should generate backtick substitution")

	// Should have dollar-paren substitution
	var hasDollarParen bool
	for _, p := range payloads {
		if p.Technique == "dollar_paren_substitution" {
			hasDollarParen = true
			assert.Equal(t, "$(id)", p.Raw)
		}
	}
	assert.True(t, hasDollarParen, "Should generate dollar-paren substitution")
}

func TestGenerator_GenerateJSPayloads(t *testing.T) {
	gen := NewGenerator(GitHubScript)
	payloads := gen.Generate("id")

	require.NotEmpty(t, payloads)

	// Should have template literal exec
	var hasTemplateLiteral bool
	for _, p := range payloads {
		if p.Technique == "template_literal_exec" {
			hasTemplateLiteral = true
			assert.Contains(t, p.Raw, "child_process")
			assert.Contains(t, p.Raw, "execSync")
		}
	}
	assert.True(t, hasTemplateLiteral, "Should generate template literal payload")
}

func TestGenerator_FitsConstraints(t *testing.T) {
	tests := []struct {
		name    string
		context InjectionContext
		payload string
		fits    bool
	}{
		{
			name:    "branch name too long",
			context: BranchName,
			payload: strings.Repeat("a", 300),
			fits:    false,
		},
		{
			name:    "branch name with space",
			context: BranchName,
			payload: "feature branch",
			fits:    false,
		},
		{
			name:    "branch name valid",
			context: BranchName,
			payload: "feature/test-injection",
			fits:    true,
		},
		{
			name:    "pr title no newline",
			context: PRTitle,
			payload: "test\ninjection",
			fits:    false,
		},
		{
			name:    "pr body with newline",
			context: PRBody,
			payload: "test\ninjection",
			fits:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator(tt.context)
			assert.Equal(t, tt.fits, gen.fits(tt.payload))
		})
	}
}

func TestGetContextByName(t *testing.T) {
	tests := []struct {
		name     string
		exists   bool
		wantName string
	}{
		{"git_branch", true, "git_branch"},
		{"pr_title", true, "pr_title"},
		{"pr_body", true, "pr_body"},
		{"commit_message", true, "commit_message"},
		{"issue_title", true, "issue_title"},
		{"issue_body", true, "issue_body"},
		{"issue_comment", true, "bash_single_quoted"},
		{"comment_body", true, "bash_single_quoted"},
		{"comment.body", true, "bash_single_quoted"},
		{"issue_comment.body", true, "bash_single_quoted"},
		{"bash_unquoted", true, "bash_unquoted"},
		{"bash_single_quoted", true, "bash_single_quoted"},
		{"bash_double_quoted", true, "bash_double_quoted"},
		{"bash_heredoc_unquoted", true, "bash_heredoc_unquoted"},
		{"github_script", true, "github_script"},
		{"nonexistent", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ok := GetContextByName(tt.name)
			assert.Equal(t, tt.exists, ok)
			if tt.exists {
				assert.Equal(t, tt.wantName, ctx.Name)
			}
		})
	}
}

func TestGenerator_MultilineFiltering(t *testing.T) {
	// PR Title doesn't allow multiline
	titleGen := NewGenerator(PRTitle)
	titlePayloads := titleGen.Generate("id")

	for _, p := range titlePayloads {
		assert.NotContains(t, p.Raw, "\n", "PR title payloads should not contain newlines")
	}

	// PR Body allows multiline
	bodyGen := NewGenerator(PRBody)
	bodyPayloads := bodyGen.Generate("id")

	var hasNewline bool
	for _, p := range bodyPayloads {
		if strings.Contains(p.Raw, "\n") {
			hasNewline = true
		}
	}
	assert.True(t, hasNewline, "PR body should have newline payloads")
}

func TestInjectionContext_Languages(t *testing.T) {
	assert.Equal(t, LangBash, PRTitle.Language)
	assert.Equal(t, LangBash, PRBody.Language)
	assert.Equal(t, LangBash, BranchName.Language)
	assert.Equal(t, LangJavaScript, GitHubScript.Language)
}
