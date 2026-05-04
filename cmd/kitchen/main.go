// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main implements the Kitchen C2 server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen"
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

	printBanner()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	config, err := loadConfigFromEnv()
	if err != nil {
		return err
	}

	server := kitchen.New(config)
	return server.Start(ctx)
}

func loadConfigFromEnv() (kitchen.Config, error) {
	config := kitchen.DefaultConfig()

	if port := os.Getenv("KITCHEN_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return config, fmt.Errorf("invalid KITCHEN_PORT: %w", err)
		}
		config.Port = p
	}

	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		config.NatsURL = natsURL
	}

	if dbPath := os.Getenv("KITCHEN_DB_PATH"); dbPath != "" {
		config.DBPath = dbPath
	}

	if keysPath := os.Getenv("AUTHORIZED_KEYS_PATH"); keysPath != "" {
		config.AuthorizedKeysPath = keysPath
	}
	if authMode := os.Getenv("AUTH_MODE"); authMode == "token" {
		config.AuthMode = kitchen.AuthModeToken
		config.AuthToken = os.Getenv("AUTH_TOKEN")
	}

	if ratePerSecond := os.Getenv("AUTH_CHALLENGE_RATE_PER_SECOND"); ratePerSecond != "" {
		r, err := strconv.ParseFloat(ratePerSecond, 64)
		if err != nil {
			return config, fmt.Errorf("invalid AUTH_CHALLENGE_RATE_PER_SECOND: %w", err)
		}
		config.AuthChallengeRatePerSecond = r
	}

	if burst := os.Getenv("AUTH_CHALLENGE_BURST"); burst != "" {
		b, err := strconv.Atoi(burst)
		if err != nil {
			return config, fmt.Errorf("invalid AUTH_CHALLENGE_BURST: %w", err)
		}
		config.AuthChallengeBurst = b
	}

	if maxIPBuckets := os.Getenv("AUTH_CHALLENGE_MAX_IP_BUCKETS"); maxIPBuckets != "" {
		m, err := strconv.Atoi(maxIPBuckets)
		if err != nil {
			return config, fmt.Errorf("invalid AUTH_CHALLENGE_MAX_IP_BUCKETS: %w", err)
		}
		config.AuthChallengeMaxIPBuckets = m
	}

	if maxPending := os.Getenv("AUTH_MAX_PENDING_CHALLENGES"); maxPending != "" {
		m, err := strconv.Atoi(maxPending)
		if err != nil {
			return config, fmt.Errorf("invalid AUTH_MAX_PENDING_CHALLENGES: %w", err)
		}
		config.AuthMaxPendingChallenges = m
	}

	if maxPendingPerOperator := os.Getenv("AUTH_MAX_PENDING_CHALLENGES_PER_OPERATOR"); maxPendingPerOperator != "" {
		m, err := strconv.Atoi(maxPendingPerOperator)
		if err != nil {
			return config, fmt.Errorf("invalid AUTH_MAX_PENDING_CHALLENGES_PER_OPERATOR: %w", err)
		}
		config.AuthMaxPendingChallengesPerOperator = m
	}

	return config, nil
}

func printBanner() {
	fmt.Printf("SmokedMeat Kitchen %s - C2 Server\n", buildinfo.Version)
	fmt.Println("Copyright (C) 2026 boostsecurity.io")
	fmt.Println("Licensed under AGPL v3.0 - For authorized security testing only.")
	fmt.Println()
}
