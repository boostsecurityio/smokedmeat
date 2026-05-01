// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package gump

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type LinuxScanner struct{}

func GetScanner() Scanner { return &LinuxScanner{} }

func (ls *LinuxScanner) FindPID() (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", entry.Name()))
		if err == nil && strings.Contains(string(cmdBytes), "Runner.Worker") {
			return strconv.Atoi(entry.Name())
		}
	}
	return 0, fmt.Errorf("process not found")
}

func (ls *LinuxScanner) Scan(pid int, results chan<- Result) error {
	_, err := ls.ScanWithStats(pid, results)
	return err
}

func (ls *LinuxScanner) ScanWithStats(pid int, results chan<- Result) (ScanStats, error) {
	var stats ScanStats

	mapPath := fmt.Sprintf("/proc/%d/maps", pid)
	memPath := fmt.Sprintf("/proc/%d/mem", pid)

	mapFile, err := os.Open(mapPath)
	if err != nil {
		return stats, err
	}
	defer mapFile.Close()

	memFile, err := os.Open(memPath)
	if err != nil {
		return stats, err
	}
	defer memFile.Close()

	scanner := bufio.NewScanner(mapFile)
	emitter := newResultEmitter(results)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if !shouldScanLinuxMapping(fields) {
			continue
		}

		rangeParts := strings.Split(fields[0], "-")
		if len(rangeParts) != 2 {
			continue
		}
		start, _ := strconv.ParseInt(rangeParts[0], 16, 64)
		end, _ := strconv.ParseInt(rangeParts[1], 16, 64)
		size := end - start

		if size <= 0 {
			continue
		}

		bytesRead, readErrors := scanReadableRegion(memFile, start, size, readableRegionChunkSize, readableRegionOverlap, func(chunk []byte) {
			scanChunkWithEmitter(chunk, emitter.emit)
		})
		if bytesRead > 0 {
			stats.RegionsScanned++
			stats.BytesRead += bytesRead
		}
		stats.ReadErrors += readErrors
	}
	if err := scanner.Err(); err != nil {
		return stats, err
	}
	return stats, nil
}

func shouldScanLinuxMapping(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	perms := fields[1]
	if !strings.Contains(perms, "r") {
		return false
	}
	if isFileBacked(fields) && !strings.Contains(perms, "w") {
		return false
	}
	return true
}

func isFileBacked(fields []string) bool {
	if len(fields) < 6 {
		return false
	}
	pathname := fields[5]
	return strings.HasPrefix(pathname, "/")
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
