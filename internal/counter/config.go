// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds Counter configuration.
type Config struct {
	KitchenURL               string `yaml:"kitchen_url"`
	SessionID                string `yaml:"session_id,omitempty"`
	Operator                 string `yaml:"operator"`
	KeyComment               string `yaml:"key_comment,omitempty"`
	Token                    string `yaml:"token,omitempty"`
	TokenSource              string `yaml:"token_source,omitempty"`
	OPSecretRef              string `yaml:"op_secret_ref,omitempty"`
	Target                   string `yaml:"target,omitempty"`
	LastAnalyzedTarget       string `yaml:"last_analyzed_target,omitempty"`
	InitialAccessToken       string `yaml:"initial_access_token,omitempty"`
	InitialAccessTokenSource string `yaml:"initial_access_token_source,omitempty"`
	Theme                    string `yaml:"theme,omitempty"`
}

// ConfigPath returns the path to the config file.
// Respects SMOKEDMEAT_CONFIG_DIR env var, defaults to ~/.smokedmeat.
func ConfigPath() string {
	if dir := os.Getenv("SMOKEDMEAT_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".smokedmeat", "config.yaml")
}

// LoadConfig loads config from ~/.smokedmeat/config.yaml
func LoadConfig() (*Config, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No config yet
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// SaveConfig saves config to ~/.smokedmeat/config.yaml
func SaveConfig(cfg *Config) error {
	path := ConfigPath()

	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}
