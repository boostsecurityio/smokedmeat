// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package brisket

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func TestResidentMemDumpHasData(t *testing.T) {
	assert.False(t, residentMemDumpHasData(nil))
	assert.False(t, residentMemDumpHasData(&MemDumpResult{}))
	assert.True(t, residentMemDumpHasData(&MemDumpResult{Secrets: []string{"secret"}}))
	assert.True(t, residentMemDumpHasData(&MemDumpResult{Vars: []string{"VAR=value"}}))
	assert.True(t, residentMemDumpHasData(&MemDumpResult{Endpoints: []gump.Endpoint{{EnvName: "ACTIONS_RUNTIME_TOKEN"}}}))
}

func TestResidentMemDumpFallback_PrefersEmptyScanOverLaterExit(t *testing.T) {
	empty := &MemDumpResult{ProcessID: 123, RegionsScanned: 10}
	failed := &MemDumpResult{ProcessID: 123, Error: "read /proc/123/maps: no such process"}

	result := residentMemDumpFallback(123, empty, failed)

	assert.Equal(t, empty, result)
	assert.Equal(t, "runner memory scan found no secrets", result.Error)
}

func TestMergeResidentMemDumpStats(t *testing.T) {
	result := mergeResidentMemDumpStats(123, nil, &MemDumpResult{
		ProcessID:      456,
		RegionsScanned: 3,
		BytesRead:      1024,
		ReadErrors:     1,
		ScanAttempts:   1,
		ProcessTargets: 1,
	})
	result = mergeResidentMemDumpStats(123, result, &MemDumpResult{
		ProcessID:      789,
		RegionsScanned: 4,
		BytesRead:      2048,
		ReadErrors:     2,
		ScanAttempts:   1,
		ProcessTargets: 2,
	})

	assert.Equal(t, 123, result.ProcessID)
	assert.Equal(t, 7, result.RegionsScanned)
	assert.Equal(t, int64(3072), result.BytesRead)
	assert.Equal(t, 3, result.ReadErrors)
	assert.Equal(t, 2, result.ScanAttempts)
	assert.Equal(t, 3, result.ProcessTargets)
}

func TestMergeResidentMemDumpStats_PreservesFirstError(t *testing.T) {
	result := mergeResidentMemDumpStats(123, nil, &MemDumpResult{
		ProcessID:      456,
		Error:          "first failure",
		ScanAttempts:   1,
		ProcessTargets: 1,
	})
	result = mergeResidentMemDumpStats(123, result, &MemDumpResult{
		ProcessID:      789,
		Error:          "second failure",
		ScanAttempts:   1,
		ProcessTargets: 1,
	})

	assert.Equal(t, "first failure", result.Error)
	assert.Equal(t, 2, result.ScanAttempts)
	assert.Equal(t, 2, result.ProcessTargets)
}

func TestNormalizeResidentMemDumpResult_SetsCounters(t *testing.T) {
	result := normalizeResidentMemDumpResult(123, &MemDumpResult{})

	assert.Equal(t, 123, result.ProcessID)
	assert.Equal(t, 1, result.ScanAttempts)
	assert.Equal(t, 1, result.ProcessTargets)
}

func TestResidentWorkerKey_FallsBackToPIDWhenStartTickMissing(t *testing.T) {
	first := residentWorkerKey(residentWorkerProcess{PID: 101, Root: "/runner", StartTick: ""})
	second := residentWorkerKey(residentWorkerProcess{PID: 202, Root: "/runner", StartTick: ""})

	assert.Equal(t, "/runner:101", first)
	assert.Equal(t, "/runner:202", second)
}

func TestResidentProcessStartTickFromStat_HandlesCommWithSpaces(t *testing.T) {
	stat := residentTestProcStat("Runner Worker", "42", "123456789")

	parent, ok := residentProcessParentFromStat(stat)

	assert.Equal(t, "123456789", residentProcessStartTickFromStat(stat))
	assert.True(t, ok)
	assert.Equal(t, 42, parent)
}

func TestResidentProcessTreeFromParents(t *testing.T) {
	parents := map[int]int{
		10: 1,
		11: 10,
		12: 10,
		13: 11,
		20: 1,
	}

	assert.Equal(t, []int{11, 12, 13, 10}, residentProcessTreeFromParents(10, parents, true))
	assert.Equal(t, []int{11, 12, 13}, residentProcessTreeFromParents(10, parents, false))
	assert.Empty(t, residentProcessTreeFromParents(10, nil, false))
	assert.Equal(t, []int{10}, residentProcessTreeFromParents(10, nil, true))
}

func residentTestProcStat(comm, ppid, startTick string) string {
	fields := []string{
		"S",
		ppid,
		"43",
		"44",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"1",
		"0",
		startTick,
	}
	return "99 (" + comm + ") " + strings.Join(fields, " ")
}
