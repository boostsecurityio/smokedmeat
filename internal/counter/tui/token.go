// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

const (
	gitHubPATURL = "https://github.com/settings/personal-access-tokens/new"
)

type TokenAcquiredMsg struct {
	Token       string
	Source      string
	ShouldSave  bool
	OPSecretRef string
}

type TokenErrorMsg struct {
	Err    error
	Source string
}

type OPPromptMsg struct{}

func (m Model) handleTokenCommand(args []string) (tea.Model, tea.Cmd) {
	if len(args) == 0 {
		return m.openBrowserForToken()
	}

	switch args[0] {
	case "op":
		return m.handleTokenOP()
	case "gh":
		return m.handleTokenGH()
	default:
		token := strings.Join(args, " ")
		return m.setTokenDirect(token, true)
	}
}

func (m Model) openBrowserForToken() (tea.Model, tea.Cmd) {
	m.AddOutput("info", "Opening GitHub to create a new Personal Access Token...")
	m.AddOutput("info", "")
	m.AddOutput("info", "Recommended settings:")
	m.AddOutput("info", "  - Token name: smokedmeat-counter")
	m.AddOutput("info", "  - Expiration: 7 days (for testing)")
	m.AddOutput("info", "  - Repository access: Public Repositories (read-only)")
	m.AddOutput("info", "")
	m.AddOutput("info", Hyperlink(gitHubPATURL, "Click here if browser doesn't open →"))

	return m, openBrowserCmd(gitHubPATURL)
}

func openBrowserCmd(url string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("open", url)
		case "linux":
			cmd = exec.Command("xdg-open", url)
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		default:
			return TokenErrorMsg{Err: fmt.Errorf("unsupported platform: %s", runtime.GOOS), Source: "browser"}
		}

		if err := cmd.Start(); err != nil {
			return TokenErrorMsg{Err: fmt.Errorf("failed to open browser: %w", err), Source: "browser"}
		}

		return nil
	}
}

func (m Model) handleTokenOP() (tea.Model, tea.Cmd) {
	if !hasOPCLI() {
		m.AddOutput("error", "1Password CLI (op) not found in PATH")
		m.AddOutput("info", "Install from: https://1password.com/downloads/command-line/")
		return m, nil
	}

	m.AddOutput("info", "")
	m.AddOutput("info", "Enter your 1Password secret reference:")
	m.AddOutput("info", "  Format: op://Vault/Item/field")
	m.AddOutput("info", "  Example: op://Tokens/GitHub_PAT/password")
	m.AddOutput("info", "")
	m.AddOutput("info", "Paste the reference and press Enter:")

	m.opPromptActive = true
	m.input.SetValue("")
	m.input.Placeholder = "op://Vault/Item/field"

	return m, nil
}

func (m Model) executeOPRead(secretRef string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("op", "read", secretRef)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg == "" {
				errMsg = err.Error()
			}
			return TokenErrorMsg{
				Err:    fmt.Errorf("1Password: %s", errMsg),
				Source: "op",
			}
		}

		token := strings.TrimSpace(stdout.String())
		if token == "" {
			return TokenErrorMsg{
				Err:    fmt.Errorf("1Password returned empty token"),
				Source: "op",
			}
		}

		return TokenAcquiredMsg{
			Token:       token,
			Source:      "op",
			OPSecretRef: secretRef,
		}
	}
}

func (m Model) handleTokenGH() (tea.Model, tea.Cmd) {
	if !hasGHCLI() {
		m.AddOutput("error", "GitHub CLI (gh) not found in PATH")
		m.AddOutput("info", "Install from: https://cli.github.com/")
		return m, nil
	}

	m.AddOutput("info", "Fetching token from GitHub CLI...")
	m.AddOutput("warning", "Note: gh auth token may be over-privileged for this use case")

	return m, m.executeGHAuthToken()
}

func (m Model) executeGHAuthToken() tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("gh", "auth", "token")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg == "" {
				errMsg = err.Error()
			}
			if strings.Contains(errMsg, "not logged in") {
				return TokenErrorMsg{
					Err:    fmt.Errorf("not logged in to GitHub CLI - run 'gh auth login' first"),
					Source: "gh",
				}
			}
			return TokenErrorMsg{
				Err:    fmt.Errorf("GitHub CLI: %s", errMsg),
				Source: "gh",
			}
		}

		token := strings.TrimSpace(stdout.String())
		if token == "" {
			return TokenErrorMsg{
				Err:    fmt.Errorf("GitHub CLI returned empty token"),
				Source: "gh",
			}
		}

		return TokenAcquiredMsg{
			Token:      token,
			Source:     "gh",
			ShouldSave: false,
		}
	}
}

func (m Model) setTokenDirect(token string, shouldSave bool) (tea.Model, tea.Cmd) {
	if len(token) < 8 {
		m.AddOutput("error", "Token too short - please provide a valid GitHub token")
		return m, nil
	}

	info := &TokenInfo{
		Value:     token,
		Type:      DetectTokenType(token),
		Source:    "input",
		FetchedAt: time.Now(),
	}
	m.tokenInfo = info
	m.initialTokenInfo = info
	m.pivotToken = nil

	maskedToken := info.MaskedValue()
	m.AddOutput("success", fmt.Sprintf("Token set: %s (%s)", maskedToken, info.Type.FullTypeName()))

	if shouldSave {
		cfg, err := counter.LoadConfig()
		if err != nil || cfg == nil {
			cfg = &counter.Config{}
		}
		if m.config.KitchenURL != "" {
			cfg.KitchenURL = m.config.KitchenURL
		}
		cfg.Token = token
		cfg.TokenSource = "pat"
		cfg.OPSecretRef = ""
		cfg.InitialAccessToken = ""
		cfg.InitialAccessTokenSource = ""

		if err := counter.SaveConfig(cfg); err != nil {
			m.AddOutput("warning", fmt.Sprintf("Could not save config: %v", err))
		} else {
			m.AddOutput("info", "Token saved to ~/.smokedmeat/config.yaml")
		}
	} else {
		m.AddOutput("info", "Token stored in memory")
	}

	m.refreshAuthDrivenViews()
	return m, m.fetchTokenInfo(token, "input")
}

func (m Model) handleTokenAcquired(msg TokenAcquiredMsg) (tea.Model, tea.Cmd) {
	info := &TokenInfo{
		Value:     msg.Token,
		Type:      DetectTokenType(msg.Token),
		Source:    msg.Source,
		FetchedAt: time.Now(),
	}
	m.tokenInfo = info

	if msg.Source != "config" {
		m.initialTokenInfo = info
		m.pivotToken = nil
	}

	maskedToken := info.MaskedValue()
	sourceName := FullSourceName(msg.Source)
	m.AddOutput("success", fmt.Sprintf("Token acquired via %s: %s (%s)", sourceName, maskedToken, info.Type.FullTypeName()))

	if msg.Source != "config" {
		cfg, err := counter.LoadConfig()
		if err != nil || cfg == nil {
			cfg = &counter.Config{}
		}
		if m.config.KitchenURL != "" {
			cfg.KitchenURL = m.config.KitchenURL
		}
		cfg.TokenSource = msg.Source
		cfg.Token = ""
		cfg.OPSecretRef = msg.OPSecretRef
		cfg.InitialAccessToken = ""
		cfg.InitialAccessTokenSource = ""

		if err := counter.SaveConfig(cfg); err != nil {
			m.AddOutput("warning", fmt.Sprintf("Could not save config: %v", err))
		} else {
			m.AddOutput("info", fmt.Sprintf("Token source '%s' saved to config (will re-fetch on restart)", msg.Source))
		}
	}

	m.updatePlaceholder()
	return m, m.fetchTokenInfo(msg.Token, msg.Source)
}

func (m Model) fetchTokenInfo(token, source string) tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			info := &TokenInfo{Value: token, Type: DetectTokenType(token), Source: source, FetchedAt: time.Now()}
			return TokenInfoErrorMsg{Info: info, Err: fmt.Errorf("kitchen not connected yet")}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := m.kitchenClient.FetchTokenInfo(ctx, token, source)
		if err != nil {
			info := &TokenInfo{Value: token, Type: DetectTokenType(token), Source: source, FetchedAt: time.Now()}
			return TokenInfoErrorMsg{Info: info, Err: err}
		}
		info := &TokenInfo{
			Value:        token,
			Type:         TokenType(resp.TokenType),
			Source:       source,
			Scopes:       resp.Scopes,
			Owner:        resp.Owner,
			RateLimitMax: resp.RateLimitMax,
			FetchedAt:    time.Now(),
		}
		if resp.StatusCode == 403 || resp.StatusCode == 401 {
			return TokenInfoErrorMsg{Info: info, Err: fmt.Errorf("token unauthorized or expired (status %d)", resp.StatusCode)}
		}
		if info.Type == TokenTypeFineGrainedPAT && len(info.Scopes) == 0 {
			info.Scopes = []string{"(fine-grained permissions)"}
		}
		return TokenInfoFetchedMsg{Info: info}
	}
}

func (m Model) handleTokenError(msg TokenErrorMsg) (tea.Model, tea.Cmd) {
	m.AddOutput("error", fmt.Sprintf("Failed to acquire token (%s): %v", msg.Source, msg.Err))
	return m, nil
}

func (m Model) handleTokenInfoFetched(msg TokenInfoFetchedMsg) (tea.Model, tea.Cmd) {
	m.tokenInfo = msg.Info

	// Display owner and capabilities
	if msg.Info.Owner != "" {
		m.AddOutput("info", fmt.Sprintf("Token owner: %s", msg.Info.Owner))
	}

	if len(msg.Info.Scopes) > 0 {
		m.AddOutput("info", fmt.Sprintf("Scopes: %s", msg.Info.ScopeSummary()))
	}

	if msg.Info.RateLimitMax > 0 {
		m.AddOutput("info", fmt.Sprintf("Rate limit: %d/hour", msg.Info.RateLimitMax))
	}

	m.refreshAuthDrivenViews()
	if m.view == ViewWizard && m.wizard != nil {
		return m, m.startWizardPreflight(false)
	}
	return m, nil
}

func (m Model) handleTokenInfoError(msg TokenInfoErrorMsg) (tea.Model, tea.Cmd) {
	// Token is still usable, just couldn't fetch full info
	if msg.Info != nil {
		m.tokenInfo = msg.Info

	}
	m.AddOutput("warning", fmt.Sprintf("Could not fetch token info: %v", msg.Err))
	m.refreshAuthDrivenViews()
	if m.view == ViewWizard && m.wizard != nil {
		return m, m.startWizardPreflight(false)
	}
	return m, nil
}

func (m *Model) swapActiveToken(secret CollectedSecret) {
	info := &TokenInfo{
		Value:     secret.Value,
		Type:      tokenTypeFromCollectedSecret(secret),
		Source:    "loot:" + secret.Name,
		FetchedAt: time.Now(),
	}
	if secret.Owner != "" {
		info.Owner = secret.Owner
	}
	if len(secret.Scopes) > 0 {
		info.Scopes = secret.Scopes
	}
	if secret.ExpiresAt != nil {
		info.ExpiresAt = secret.ExpiresAt
	}
	m.tokenInfo = info

	m.activityLog.Add(IconSuccess, fmt.Sprintf("Swapped to %s (%s)", secret.Name, info.Type.ShortType()))
	m.refreshAuthDrivenViews()
}

func (m *Model) refreshAuthDrivenViews() {
	m.GenerateSuggestions()
	m.RebuildTree()
}

func tokenTypeFromCollectedSecret(secret CollectedSecret) TokenType {
	switch secret.Type {
	case "github_token":
		return TokenTypeGitHubActions
	case "github_app_token":
		return TokenTypeInstallApp
	case "github_pat":
		return TokenTypeClassicPAT
	case "github_fine_grained_pat":
		return TokenTypeFineGrainedPAT
	case "github_oauth":
		return TokenTypeOAuth
	default:
		return DetectTokenType(secret.Value)
	}
}
