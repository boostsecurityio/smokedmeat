// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gump

import (
	"os"
	"path/filepath"
	"testing"
)

func collectProbeResults(fn func(chan<- Result)) []Result {
	results := make(chan Result, 100)
	fn(results)
	close(results)

	var collected []Result
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func TestProbeRuntimeContext_EmitsCurrentEnvironment(t *testing.T) {
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")
	t.Setenv("ACTIONS_RESULTS_URL", "https://results.example/_apis/results")
	t.Setenv("ACTIONS_CACHE_URL", "https://cache.example/_apis/artifactcache")
	t.Setenv("ACTIONS_CACHE_SERVICE_V2", "true")

	results := collectProbeResults(func(results chan<- Result) {
		ProbeRuntimeContext(0, results)
	})

	endpoints := collectEndpointResults(results)
	vars := collectVarResults(results)

	if endpoints["ACTIONS_RUNTIME_TOKEN"] != "runtime-token" {
		t.Fatalf("expected runtime token from environment")
	}
	if endpoints["ACTIONS_RESULTS_URL"] != "https://results.example/_apis/results" {
		t.Fatalf("unexpected results url %q", endpoints["ACTIONS_RESULTS_URL"])
	}
	if endpoints["ACTIONS_CACHE_URL"] != "https://cache.example/_apis/artifactcache" {
		t.Fatalf("unexpected cache url %q", endpoints["ACTIONS_CACHE_URL"])
	}
	if vars["ACTIONS_CACHE_SERVICE_V2"] != "true" {
		t.Fatalf("unexpected cache service flag %q", vars["ACTIONS_CACHE_SERVICE_V2"])
	}
}

func TestProbeEnvFileData_EmitsGitHubEnvValues(t *testing.T) {
	results := collectProbeResults(func(results chan<- Result) {
		probeEnvFileData("test-env", "ACTIONS_RESULTS_URL=https://results.example/_apis/results\nACTIONS_RUNTIME_TOKEN<<EOF\ntoken-line\nEOF\n", newResultEmitter(results).emit)
	})

	endpoints := collectEndpointResults(results)

	if endpoints["ACTIONS_RESULTS_URL"] != "https://results.example/_apis/results" {
		t.Fatalf("unexpected results url %q", endpoints["ACTIONS_RESULTS_URL"])
	}
	if endpoints["ACTIONS_RUNTIME_TOKEN"] != "token-line" {
		t.Fatalf("unexpected runtime token %q", endpoints["ACTIONS_RUNTIME_TOKEN"])
	}
}

func TestProbeRuntimeContext_ReadsGitHubEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "github_env")
	err := os.WriteFile(envPath, []byte("ACTIONS_RESULTS_URL=https://results.example/_apis/results\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ENV", envPath)
	t.Setenv("ACTIONS_RESULTS_URL", "")

	results := collectProbeResults(func(results chan<- Result) {
		ProbeRuntimeContext(0, results)
	})

	endpoints := collectEndpointResults(results)
	if endpoints["ACTIONS_RESULTS_URL"] != "https://results.example/_apis/results" {
		t.Fatalf("unexpected results url %q", endpoints["ACTIONS_RESULTS_URL"])
	}
}
