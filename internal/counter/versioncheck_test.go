// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRunVersionCheck_SendsVersionAndRecordsTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	counterID := "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4"
	cfg := &Config{
		CounterID:         counterID,
		CounterStartCount: 7,
	}
	var gotReq *http.Request
	var saved *Config

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  cfg,
		Version: "0.2.0",
		URL:     "https://updates.example/check?channel=stable",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		Now: func() time.Time { return now },
		SaveConfig: func(cfg *Config) error {
			copy := *cfg
			saved = &copy
			return nil
		},
		Env:   func(string) string { return "" },
		NewID: func() string { return counterID },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	require.NotNil(t, gotReq)
	assert.Equal(t, "smokedmeat", gotReq.URL.Query().Get("project"))
	assert.Equal(t, "counter", gotReq.URL.Query().Get("component"))
	assert.Equal(t, "0.2.0", gotReq.URL.Query().Get("version"))
	assert.Equal(t, counterID, gotReq.URL.Query().Get("instance_id"))
	assert.Equal(t, "7", gotReq.URL.Query().Get("start_count"))
	assert.Equal(t, "7", gotReq.URL.Query().Get("starts_since_last_check"))
	assert.Equal(t, "stable", gotReq.URL.Query().Get("channel"))
	assert.Equal(t, "smokedmeat-counter/0.2.0", gotReq.Header.Get("User-Agent"))
	require.NotNil(t, saved)
	assert.Equal(t, counterID, saved.CounterID)
	assert.Equal(t, 7, saved.CounterStartCount)
	assert.Equal(t, 7, saved.LastReportedStartCount)
	assert.Equal(t, now, saved.LastVersionCheckAt)
}

func TestRunVersionCheck_ReturnsUpdateResult(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		CounterID:              "2ed05245-10d7-4d21-a8e8-7c4e8a9851b4",
		CounterStartCount:      5,
		LastReportedStartCount: 4,
	}

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  cfg,
		Version: "0.2.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "1", req.URL.Query().Get("starts_since_last_check"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"latest_version":"v0.2.1",
					"latest_url":"https://github.com/boostsecurityio/smokedmeat/releases/tag/v0.2.1",
					"update_available":true
				}`)),
			}, nil
		})},
		Now:        func() time.Time { return now },
		SaveConfig: func(*Config) error { return nil },
		Env:        func(string) string { return "" },
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.UpdateAvailable)
	assert.Equal(t, "v0.2.1", result.LatestVersion)
	assert.Equal(t, "https://github.com/boostsecurityio/smokedmeat/releases/tag/v0.2.1", result.LatestURL)
	assert.Equal(t, 5, cfg.LastReportedStartCount)
}

func TestRunVersionCheck_DisabledByEnv(t *testing.T) {
	called := false
	cfg := &Config{}

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  cfg,
		Version: "0.2.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Env: func(key string) string {
			if key == DisableVersionCheckEnv {
				return "true"
			}
			return ""
		},
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
	assert.Empty(t, cfg.CounterID)
	assert.Zero(t, cfg.CounterStartCount)
	assert.True(t, cfg.LastVersionCheckAt.IsZero())
}

func TestRunVersionCheck_RespectsInterval(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	called := false
	cfg := &Config{LastVersionCheckAt: now.Add(-time.Hour)}

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  cfg,
		Version: "0.2.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Now: func() time.Time { return now },
		Env: func(string) string { return "" },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
	assert.Empty(t, cfg.CounterID)
	assert.Zero(t, cfg.CounterStartCount)
}

func TestRecordCounterStart_GeneratesCounterIDAndIncrementsCount(t *testing.T) {
	cfg := &Config{}

	recordCounterStart(cfg, func() string {
		return "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e"
	})
	recordCounterStart(cfg, func() string {
		t.Fatal("existing counter_id should be reused")
		return ""
	})

	assert.Equal(t, "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e", cfg.CounterID)
	assert.Equal(t, 2, cfg.CounterStartCount)
}

func TestRecordCounterStart_DisabledByEnv(t *testing.T) {
	t.Setenv(DisableVersionCheckEnv, "1")
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", t.TempDir())
	cfg := &Config{}

	RecordCounterStart(cfg)

	assert.Empty(t, cfg.CounterID)
	assert.Zero(t, cfg.CounterStartCount)
	loaded, err := LoadConfig()
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestRunVersionCheck_ReusesCounterIDAndReportsStartCount(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	cfg := &Config{
		CounterID:              "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e",
		CounterStartCount:      42,
		LastReportedStartCount: 40,
		LastVersionCheckAt:     now.Add(-25 * time.Hour),
	}
	var gotReq *http.Request

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  cfg,
		Version: "0.2.0",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		Now:        func() time.Time { return now },
		SaveConfig: func(*Config) error { return nil },
		Env:        func(string) string { return "" },
		NewID: func() string {
			t.Fatal("existing counter_id should be reused")
			return ""
		},
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	require.NotNil(t, gotReq)
	assert.Equal(t, "97c5d9f0-7a5c-4a61-9f2a-09f4903de44e", gotReq.URL.Query().Get("instance_id"))
	assert.Equal(t, "42", gotReq.URL.Query().Get("start_count"))
	assert.Equal(t, "2", gotReq.URL.Query().Get("starts_since_last_check"))
	assert.Equal(t, 42, cfg.CounterStartCount)
	assert.Equal(t, 42, cfg.LastReportedStartCount)
	assert.Equal(t, now, cfg.LastVersionCheckAt)
}

func TestRunVersionCheck_SkipsDevVersionWithoutExplicitEndpoint(t *testing.T) {
	called := false

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  &Config{},
		Version: "dev",
		URL:     "https://updates.example/check",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected request")
		})},
		Env: func(string) string { return "" },
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.False(t, called)
}

func TestRunVersionCheck_ExplicitEndpointAllowsDevVersion(t *testing.T) {
	called := false

	result, err := runVersionCheck(context.Background(), versionCheckOptions{
		Config:  &Config{},
		Version: "dev",
		URL:     "https://updates.example/default",
		Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			assert.Equal(t, "https://override.example/check", req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		SaveConfig: func(*Config) error { return nil },
		Env: func(key string) string {
			if key == VersionCheckURLEnv {
				return "https://override.example/check"
			}
			return ""
		},
	})

	require.NoError(t, err)
	assert.Nil(t, result)
	assert.True(t, called)
}
