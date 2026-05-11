// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package gump

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
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
	stats, err := ls.scanWithStatsCurrentCreds(pid, results)
	if !linuxScanShouldRetryWithTargetFSIDs(stats, err) {
		return stats, err
	}

	retryStats, retryErr := scanWithLinuxTargetFSIDs(pid, func() (ScanStats, error) {
		return ls.scanWithStatsCurrentCreds(pid, results)
	})
	if retryErr == nil || retryStats.BytesRead > 0 {
		return retryStats, retryErr
	}
	if err != nil {
		return stats, err
	}
	return retryStats, retryErr
}

func (ls *LinuxScanner) scanWithStatsCurrentCreds(pid int, results chan<- Result) (ScanStats, error) {
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

func linuxScanShouldRetryWithTargetFSIDs(stats ScanStats, err error) bool {
	if os.Geteuid() != 0 {
		return false
	}
	if err != nil {
		return os.IsPermission(err)
	}
	return stats.BytesRead == 0 && stats.ReadErrors > 0
}

func scanWithLinuxTargetFSIDs(pid int, scan func() (ScanStats, error)) (ScanStats, error) {
	uid, gid, err := linuxProcessUIDGID(pid)
	if err != nil {
		return ScanStats{}, err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	previousGID, err := unix.SetfsgidRetGid(gid)
	if err != nil {
		return ScanStats{}, err
	}
	previousUID, err := unix.SetfsuidRetUid(uid)
	if err != nil {
		_ = unix.Setfsgid(previousGID)
		return ScanStats{}, err
	}
	defer func() {
		_ = unix.Setfsuid(previousUID)
		_ = unix.Setfsgid(previousGID)
	}()

	return scan()
}

func linuxProcessUIDGID(pid int) (int, int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	return linuxProcessUIDGIDFromStatus(string(data))
}

func linuxProcessUIDGIDFromStatus(status string) (int, int, error) {
	uid := -1
	gid := -1
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var err error
		switch fields[0] {
		case "Uid:":
			uid, err = strconv.Atoi(fields[1])
		case "Gid:":
			gid, err = strconv.Atoi(fields[1])
		}
		if err != nil {
			return 0, 0, err
		}
	}
	if uid < 0 || gid < 0 {
		return 0, 0, fmt.Errorf("process uid/gid not found")
	}
	return uid, gid, nil
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
