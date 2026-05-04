// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	DisableVersionCheckEnv = "SMOKEDMEAT_DISABLE_VERSION_CHECK"
	VersionCheckURLEnv     = "SMOKEDMEAT_VERSION_CHECK_URL"
)

const (
	versionCheckInterval = 24 * time.Hour
	versionCheckTimeout  = 1200 * time.Millisecond
)

type versionCheckOptions struct {
	Config     *Config
	Version    string
	URL        string
	Client     *http.Client
	Now        func() time.Time
	SaveConfig func(*Config) error
	Env        func(string) string
	NewID      func() string
}

type VersionCheckResult struct {
	LatestVersion   string `json:"latest_version,omitempty"`
	LatestURL       string `json:"latest_url,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
}

func RunVersionCheck(cfg *Config, version, defaultURL string) *VersionCheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), versionCheckTimeout)
	defer cancel()

	result, _ := runVersionCheck(ctx, versionCheckOptions{
		Config:     cfg,
		Version:    version,
		URL:        defaultURL,
		Client:     &http.Client{Timeout: versionCheckTimeout},
		Now:        time.Now,
		SaveConfig: SaveConfig,
		Env:        os.Getenv,
		NewID:      uuid.NewString,
	})
	return result
}

func runVersionCheck(ctx context.Context, opts versionCheckOptions) (*VersionCheckResult, error) {
	if opts.Config == nil {
		opts.Config = &Config{}
	}
	if opts.Env == nil {
		opts.Env = os.Getenv
	}
	if versionCheckDisabled(opts.Env(DisableVersionCheckEnv)) {
		return nil, nil
	}

	endpoint := strings.TrimSpace(opts.Env(VersionCheckURLEnv))
	envEndpoint := endpoint != ""
	if endpoint == "" {
		endpoint = strings.TrimSpace(opts.URL)
	}
	version := strings.TrimSpace(opts.Version)
	if endpoint == "" || version == "" {
		return nil, nil
	}
	if isVersionCheckDevVersion(version) && !envEndpoint {
		return nil, nil
	}

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	if !opts.Config.LastVersionCheckAt.IsZero() && now.Sub(opts.Config.LastVersionCheckAt) < versionCheckInterval {
		return nil, nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	counterID := ensureCounterID(opts.Config, opts.NewID)
	startsSinceLastCheck := counterStartsSinceLastReport(opts.Config)
	requestURL := versionCheckRequestURL(u, version, counterID, opts.Config.CounterStartCount, startsSinceLastCheck)

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: versionCheckTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "smokedmeat-counter/"+version)

	resp, err := client.Do(req)
	opts.Config.LastVersionCheckAt = now
	if opts.SaveConfig == nil {
		opts.SaveConfig = SaveConfig
	}
	var result *VersionCheckResult
	var resultErr error
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			opts.Config.LastReportedStartCount = opts.Config.CounterStartCount
			result, resultErr = readVersionCheckResult(resp)
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}
	saveErr := opts.SaveConfig(opts.Config)
	if err != nil {
		return nil, err
	}
	if resultErr != nil {
		return nil, resultErr
	}
	if saveErr != nil {
		return result, saveErr
	}
	return result, nil
}

func versionCheckDisabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isVersionCheckDevVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version == "dev" || version == "unknown" || strings.Contains(version, "SNAPSHOT")
}

func recordCounterStart(cfg *Config, newID func() string) {
	if cfg == nil {
		return
	}
	ensureCounterID(cfg, newID)
	cfg.CounterStartCount++
}

func ensureCounterID(cfg *Config, newID func() string) string {
	counterID := strings.TrimSpace(cfg.CounterID)
	if counterID == "" {
		if newID == nil {
			newID = uuid.NewString
		}
		counterID = strings.TrimSpace(newID())
		cfg.CounterID = counterID
		return counterID
	}
	cfg.CounterID = counterID
	return counterID
}

func RecordCounterStart(cfg *Config) {
	if versionCheckDisabled(os.Getenv(DisableVersionCheckEnv)) {
		return
	}
	recordCounterStart(cfg, uuid.NewString)
	_ = SaveConfig(cfg)
}

func counterStartsSinceLastReport(cfg *Config) int {
	starts := cfg.CounterStartCount - cfg.LastReportedStartCount
	if starts < 0 {
		return cfg.CounterStartCount
	}
	return starts
}

func readVersionCheckResult(resp *http.Response) (*VersionCheckResult, error) {
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}
	var result VersionCheckResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func versionCheckRequestURL(u *url.URL, version, counterID string, counterStartCount, startsSinceLastCheck int) string {
	q := u.Query()
	q.Set("project", "smokedmeat")
	q.Set("component", "counter")
	q.Set("version", version)
	q.Set("instance_id", counterID)
	if counterStartCount > 0 {
		q.Set("start_count", strconv.Itoa(counterStartCount))
		q.Set("starts_since_last_check", strconv.Itoa(startsSinceLastCheck))
	}
	u.RawQuery = q.Encode()
	return u.String()
}
