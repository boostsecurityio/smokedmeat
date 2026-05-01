// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package gump

import "testing"

func TestIsFileBacked(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		want   bool
	}{
		{"anonymous no pathname", []string{"7f00-7f01", "rw-p", "00000000", "00:00", "0"}, false},
		{"heap special region", []string{"7f00-7f01", "rw-p", "00000000", "00:00", "0", "[heap]"}, false},
		{"stack special region", []string{"7f00-7f01", "rw-p", "00000000", "00:00", "0", "[stack]"}, false},
		{"shared library", []string{"7f00-7f01", "r-xp", "00000000", "08:01", "12345", "/usr/lib/x86_64-linux-gnu/libc.so.6"}, true},
		{"locale data", []string{"7f00-7f01", "r--p", "00000000", "08:01", "99", "/usr/lib/locale/locale-archive"}, true},
		{"dotnet assembly", []string{"7f00-7f01", "r-xp", "00000000", "08:01", "42", "/opt/runner/bin/Runner.Worker.dll"}, true},
		{"fewer than 6 fields", []string{"7f00-7f01", "rw-p", "00000000", "00:00"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFileBacked(tc.fields); got != tc.want {
				t.Errorf("isFileBacked(%v) = %v, want %v", tc.fields, got, tc.want)
			}
		})
	}
}

func TestShouldScanLinuxMapping(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		want   bool
	}{
		{"anonymous writable", []string{"7f00-7f01", "rw-p", "00000000", "00:00", "0"}, true},
		{"heap writable", []string{"7f00-7f01", "rw-p", "00000000", "00:00", "0", "[heap]"}, true},
		{"file backed read only", []string{"7f00-7f01", "r--p", "00000000", "08:01", "42", "/opt/runner/bin/Runner.Worker.dll"}, false},
		{"file backed executable", []string{"7f00-7f01", "r-xp", "00000000", "08:01", "42", "/opt/runner/bin/Runner.Worker.dll"}, false},
		{"file backed writable", []string{"7f00-7f01", "rw-p", "00000000", "08:01", "42", "/tmp/CoreFxPipe"}, true},
		{"write only", []string{"7f00-7f01", "-w-p", "00000000", "00:00", "0"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldScanLinuxMapping(tc.fields); got != tc.want {
				t.Errorf("shouldScanLinuxMapping(%v) = %v, want %v", tc.fields, got, tc.want)
			}
		})
	}
}
