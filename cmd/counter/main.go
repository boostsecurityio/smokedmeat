// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main implements the Counter CLI/TUI operator interface.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/google/uuid"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/counter/tui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Print(buildinfo.String())
		return nil
	}

	// Custom usage with banner
	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Usage: counter [options]\n\nOptions:\n")
		flag.PrintDefaults()
	}

	// Parse flags
	kitchenURL := flag.String("kitchen", getEnvOrDefault("KITCHEN_URL", ""), "Kitchen server URL (e.g., https://kitchen.example.com)")
	token := flag.String("token", getEnvOrDefault("OPERATOR_TOKEN", ""), "Operator authentication token (smk_...)")
	operator := flag.String("operator", getEnvOrDefault("OPERATOR_NAME", ""), "Operator name for SSH authentication")
	keyComment := flag.String("key", getEnvOrDefault("SSH_KEY_COMMENT", ""), "SSH key comment to filter which key to use")
	sessionID := flag.String("session", getEnvOrDefault("SESSION_ID", ""), "Session ID (auto-generated if not provided)")
	listKeys := flag.Bool("list-keys", false, "List SSH keys available in the agent and exit")
	flag.Parse()

	// Handle --list-keys
	if *listKeys {
		return listSSHKeys()
	}

	// Load saved config
	savedConfig, _ := counter.LoadConfig()

	// Use saved config as defaults if flags not provided
	effectiveKitchenURL := *kitchenURL
	effectiveOperator := *operator
	effectiveKeyComment := *keyComment

	if savedConfig != nil {
		if effectiveKitchenURL == "" {
			effectiveKitchenURL = savedConfig.KitchenURL
		}
		if effectiveOperator == "" {
			effectiveOperator = savedConfig.Operator
		}
		if effectiveKeyComment == "" {
			effectiveKeyComment = savedConfig.KeyComment
		}
	}

	sid := determineSessionID(*sessionID, savedConfig)
	if savedConfig == nil {
		savedConfig = &counter.Config{}
	}
	if savedConfig.SessionID != sid {
		savedConfig.SessionID = sid
		_ = counter.SaveConfig(savedConfig)
	}

	// If kitchen URL is set but no token, try SSH authentication
	authToken := *token
	authFailed := false
	if effectiveKitchenURL != "" && authToken == "" && effectiveOperator != "" {
		var err error
		authToken, err = authenticateWithSSH(effectiveKitchenURL, effectiveOperator, effectiveKeyComment)
		if err != nil {
			authFailed = true
		}
	}

	// Load GitHub token and target settings from saved config
	var ghToken, tokenSource, opSecretRef, target string
	if savedConfig != nil {
		ghToken = savedConfig.Token
		tokenSource = savedConfig.TokenSource
		opSecretRef = savedConfig.OPSecretRef
		target = savedConfig.Target
	}

	// External URL for stagers (must be reachable from outside Docker)
	kitchenExternalURL := getEnvOrDefault("KITCHEN_EXTERNAL_URL", effectiveKitchenURL)
	kitchenBrowserURL := getEnvOrDefault("KITCHEN_BROWSER_URL", kitchenExternalURL)

	var initialToken, initialTokenSource string
	if savedConfig != nil {
		initialToken = savedConfig.InitialAccessToken
		initialTokenSource = savedConfig.InitialAccessTokenSource
	}

	config := tui.Config{
		KitchenURL:               effectiveKitchenURL,
		KitchenExternalURL:       kitchenExternalURL,
		KitchenBrowserURL:        kitchenBrowserURL,
		AuthToken:                authToken,
		SessionID:                sid,
		Operator:                 effectiveOperator,
		KeyComment:               effectiveKeyComment,
		Token:                    ghToken,
		TokenSource:              tokenSource,
		OPSecretRef:              opSecretRef,
		Target:                   target,
		AuthFailed:               authFailed,
		InitialAccessToken:       initialToken,
		InitialAccessTokenSource: initialTokenSource,
	}

	if savedConfig != nil && savedConfig.Theme != "" {
		tui.ApplyTheme(tui.ThemeName(savedConfig.Theme))
	}

	// Create the TUI model
	model := tui.NewModel(config)

	p := tea.NewProgram(model)

	// Run the program
	_, err := p.Run()
	return err
}

func determineSessionID(flagValue string, savedConfig *counter.Config) string {
	if flagValue != "" {
		return flagValue
	}
	if savedConfig != nil && savedConfig.SessionID != "" {
		return savedConfig.SessionID
	}
	return uuid.New().String()[:8]
}

// getEnvOrDefault returns the environment variable value or a default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// authenticateWithSSH performs SSH challenge-response authentication.
func authenticateWithSSH(kitchenURL, operatorName, keyComment string) (string, error) {
	client := counter.NewSSHAuthClient(counter.SSHAuthConfig{
		KitchenURL: kitchenURL,
		Operator:   operatorName,
		KeyComment: keyComment,
	})
	return client.Authenticate()
}

func printBanner() {
	banner := `
 ____                  _            _ __  __            _
/ ___| _ __ ___   ___ | | _____  __| |  \/  | ___  __ _| |_
\___ \| '_ ` + "`" + ` _ \ / _ \| |/ / _ \/ _` + "`" + ` | |\/| |/ _ \/ _` + "`" + ` | __|
 ___) | | | | | | (_) |   <  __/ (_| | |  | |  __/ (_| | |_
|____/|_| |_| |_|\___/|_|\_\___|\__,_|_|  |_|\___|\__,_|\__|

SmokedMeat %s :: A Red Team CI/CD Exploitation Framework
Copyright (C) 2026 boostsecurity.io

Licensed under AGPL v3.0.
This program comes with ABSOLUTELY NO WARRANTY.
Type 'license' for full details.
`
	fmt.Printf(banner, buildinfo.Version)
}

// listSSHKeys lists SSH keys in the agent.
func listSSHKeys() error {
	keys, err := counter.GetKeyInfo()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No SSH keys found in agent")
		return nil
	}

	// Generate a suggested operator name
	suggestedName := counter.GenerateOperatorName()

	fmt.Println("SSH keys in agent:")
	fmt.Println()

	for i, k := range keys {
		fmt.Printf("[%d] %s\n", i+1, k.Comment)
		fmt.Printf("    Fingerprint: %s\n", k.Fingerprint)
		fmt.Printf("    Type:        %s\n", k.Type)
		fmt.Println()
		fmt.Printf("    authorized_keys line:\n")
		fmt.Printf("    %s %s\n", suggestedName, k.AuthorizedKey) // #nosec G104 -- public key, safe to print // codeql[go/clear-text-logging]
		fmt.Println()
	}

	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println("Setup:")
	fmt.Println("  1. Copy one of the 'authorized_keys line' entries above")
	fmt.Println("  2. Add it to Kitchen's authorized_keys file")
	fmt.Println()
	fmt.Printf("  Then connect: counter -kitchen <url> -operator %s\n", suggestedName)
	return nil
}
