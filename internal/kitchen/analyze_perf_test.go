// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build analysisperf
// +build analysisperf

package kitchen

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

const analysisPerfEnvPath = ".claude/e2e/.env"

type analysisPerfConfig struct {
	Token      string
	Target     string
	TargetType string
	Deep       bool
	SessionID  string
}

type analysisPerfObserver struct {
	mu           sync.Mutex
	startedAt    time.Time
	total        int
	completed    int
	errors       int
	skipped      int
	nextReport   int
	reportStride int
	lastReport   time.Time
	lastPrinted  int
}

func TestAnalyzePerformanceProfile(t *testing.T) {
	config := loadAnalysisPerfConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), analysisRequestTimeout(config.TargetType, config.Deep)+15*time.Minute)
	defer cancel()

	h := NewHandlerWithPublisher(&mockPublisher{}, nil)
	h.database = newTestDB(t)

	req := AnalyzeRequest{
		Token:      config.Token,
		Target:     config.Target,
		TargetType: config.TargetType,
		Deep:       config.Deep,
		SessionID:  config.SessionID,
	}

	totalStarted := time.Now()
	scanStarted := time.Now()
	observer := newAnalysisPerfObserver(totalStarted)
	result, err := poutine.AnalyzeRemoteWithObserver(ctx, config.Token, config.Target, config.TargetType, observer)
	require.NoError(t, err)
	scanDuration := time.Since(scanStarted)
	fmt.Printf("[perf] scan complete - repos=%d findings=%d workflows=%d non_fatal_errors=%d elapsed=%s\n",
		len(collectAnalyzedRepos(result)),
		len(result.Findings),
		len(result.Workflows),
		len(result.Errors),
		roundPerfDuration(scanDuration),
	)

	var secretScanDuration time.Duration
	if config.Deep {
		repos := collectScanTargets(req, result)
		fmt.Printf("[perf] secret scan starting - repos=%d elapsed=%s\n", len(repos), roundPerfDuration(time.Since(totalStarted)))
		secretStarted := time.Now()
		h.runGitleaksScan(ctx, req, result, time.Now(), repos)
		secretScanDuration = time.Since(secretStarted)
		fmt.Printf("[perf] secret scan complete - secrets=%d elapsed=%s\n", len(result.SecretFindings), roundPerfDuration(time.Since(totalStarted)))
	}

	fmt.Printf("[perf] importing analysis results - elapsed=%s\n", roundPerfDuration(time.Since(totalStarted)))
	importStarted := time.Now()
	importedAssets := h.importAnalysisToPantry(result)
	importDuration := time.Since(importStarted)

	fmt.Printf("[perf] updating repository access - elapsed=%s\n", roundPerfDuration(time.Since(totalStarted)))
	accessStarted := time.Now()
	h.recordAnalyzedRepoVisibility(ctx, req, result)
	repoAccessDuration := time.Since(accessStarted)

	fmt.Printf("[perf] updating private repo inventory - elapsed=%s\n", roundPerfDuration(time.Since(totalStarted)))
	inventoryStarted := time.Now()
	h.importPrivateReposToPantry(config.SessionID)
	inventoryDuration := time.Since(inventoryStarted)

	fmt.Printf("[perf] persisting attack graph - elapsed=%s\n", roundPerfDuration(time.Since(totalStarted)))
	persistStarted := time.Now()
	require.NoError(t, h.SavePantry())
	persistDuration := time.Since(persistStarted)

	tailDuration := importDuration + secretScanDuration + repoAccessDuration + inventoryDuration + persistDuration
	totalDuration := time.Since(totalStarted)
	repoCount := len(collectAnalyzedRepos(result))

	t.Logf("analysis target=%s type=%s deep=%t repos=%d findings=%d workflows=%d secrets=%d imported_assets=%d pantry_assets=%d pantry_edges=%d",
		config.Target,
		config.TargetType,
		config.Deep,
		repoCount,
		len(result.Findings),
		len(result.Workflows),
		len(result.SecretFindings),
		importedAssets,
		h.Pantry().Size(),
		h.Pantry().EdgeCount(),
	)
	t.Logf("analysis timings scan=%s secret_scan=%s import=%s repo_access=%s private_repo_inventory=%s persist=%s tail=%s total=%s",
		scanDuration,
		secretScanDuration,
		importDuration,
		repoAccessDuration,
		inventoryDuration,
		persistDuration,
		tailDuration,
		totalDuration,
	)
}

func loadAnalysisPerfConfig(t *testing.T) analysisPerfConfig {
	t.Helper()

	env := loadAnalysisPerfEnv(t)
	config := analysisPerfConfig{
		Token:      firstNonEmpty(strings.TrimSpace(os.Getenv("GITHUB_TOKEN")), env["GITHUB_TOKEN"]),
		Target:     firstNonEmpty(strings.TrimSpace(os.Getenv("SM_ANALYZE_PERF_TARGET")), env["SM_ANALYZE_PERF_TARGET"]),
		TargetType: firstNonEmpty(strings.TrimSpace(os.Getenv("SM_ANALYZE_PERF_TARGET_TYPE")), env["SM_ANALYZE_PERF_TARGET_TYPE"], "org"),
		Deep:       parsePerfBool(firstNonEmpty(strings.TrimSpace(os.Getenv("SM_ANALYZE_PERF_DEEP")), env["SM_ANALYZE_PERF_DEEP"])),
		SessionID:  firstNonEmpty(strings.TrimSpace(os.Getenv("SM_ANALYZE_PERF_SESSION_ID")), env["SM_ANALYZE_PERF_SESSION_ID"], "analysisperf"),
	}

	if config.Token == "" {
		t.Skipf("GITHUB_TOKEN missing in environment and %s", analysisPerfEnvPath)
	}
	if config.Target == "" {
		t.Skipf("SM_ANALYZE_PERF_TARGET missing in environment and %s", analysisPerfEnvPath)
	}
	if config.TargetType != "org" && config.TargetType != "repo" {
		t.Fatalf("invalid SM_ANALYZE_PERF_TARGET_TYPE %q", config.TargetType)
	}

	return config
}

func newAnalysisPerfObserver(startedAt time.Time) *analysisPerfObserver {
	return &analysisPerfObserver{
		startedAt:  startedAt,
		lastReport: startedAt,
	}
}

func (o *analysisPerfObserver) OnAnalysisStarted(description string) {
	fmt.Printf("[perf] %s\n", description)
}

func (o *analysisPerfObserver) OnDiscoveryCompleted(org string, totalCount int) {
	o.mu.Lock()
	o.total = totalCount
	o.reportStride = perfReportStride(totalCount)
	o.nextReport = o.reportStride
	o.lastReport = time.Now()
	o.mu.Unlock()
	fmt.Printf("[perf] discovered %d repositories in %s\n", totalCount, org)
}

func (o *analysisPerfObserver) OnRepoStarted(string) {}

func (o *analysisPerfObserver) OnRepoCompleted(string) {
	o.advance(false, false)
}

func (o *analysisPerfObserver) OnRepoError(string, error) {
	o.advance(true, false)
}

func (o *analysisPerfObserver) OnRepoSkipped(string, string) {
	o.advance(false, true)
}

func (o *analysisPerfObserver) OnStepCompleted(string) {}

func (o *analysisPerfObserver) OnFinalizeStarted(totalPackages int) {
	o.report(true)
	fmt.Printf("[perf] finalizing %d analyzed packages - elapsed=%s\n", totalPackages, roundPerfDuration(time.Since(o.startedAt)))
}

func (o *analysisPerfObserver) OnFinalizeCompleted() {
	fmt.Printf("[perf] finalize complete - elapsed=%s\n", roundPerfDuration(time.Since(o.startedAt)))
}

func (o *analysisPerfObserver) advance(withError, skipped bool) {
	o.mu.Lock()
	o.completed++
	if withError {
		o.errors++
	}
	if skipped {
		o.skipped++
	}
	shouldReport := o.shouldReportLocked()
	o.mu.Unlock()

	if shouldReport {
		o.report(false)
	}
}

func (o *analysisPerfObserver) report(force bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !force && !o.shouldReportLocked() {
		return
	}
	if o.completed == o.lastPrinted {
		return
	}

	total := o.total
	if total == 0 {
		total = o.completed
	}
	percent := 100
	if total > 0 {
		percent = o.completed * 100 / total
	}
	fmt.Printf("[perf] scan progress %d/%d repos (%d%%) errors=%d skipped=%d elapsed=%s\n",
		o.completed,
		total,
		percent,
		o.errors,
		o.skipped,
		roundPerfDuration(time.Since(o.startedAt)),
	)
	o.lastPrinted = o.completed
	o.lastReport = time.Now()
	for o.nextReport <= o.completed {
		o.nextReport += o.reportStride
	}
	if total > 0 && o.nextReport > total {
		o.nextReport = total
	}
}

func (o *analysisPerfObserver) shouldReportLocked() bool {
	if o.completed == 0 {
		return false
	}
	if o.total > 0 && o.completed >= o.total {
		return true
	}
	if o.reportStride > 0 && o.completed >= o.nextReport {
		return true
	}
	return time.Since(o.lastReport) >= 10*time.Second
}

func perfReportStride(total int) int {
	if total <= 0 {
		return 10
	}
	stride := total / 20
	if stride < 10 {
		stride = 10
	}
	if stride <= 50 {
		return ((stride + 4) / 5) * 5
	}
	return ((stride + 24) / 25) * 25
}

func roundPerfDuration(d time.Duration) time.Duration {
	if d < 10*time.Second {
		return d.Round(100 * time.Millisecond)
	}
	return d.Round(time.Second)
}

func loadAnalysisPerfEnv(t *testing.T) map[string]string {
	t.Helper()

	root := findAnalysisPerfProjectRoot(t)
	data, err := os.ReadFile(filepath.Join(root, analysisPerfEnvPath))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}
		}
		t.Fatalf("read %s: %v", analysisPerfEnvPath, err)
	}

	env := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return env
}

func findAnalysisPerfProjectRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find project root from %s", dir)
		}
		dir = parent
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func parsePerfBool(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return parsed
}
