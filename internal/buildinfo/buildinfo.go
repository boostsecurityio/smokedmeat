// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package buildinfo

import (
	"fmt"
	"strings"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("Version: %s\nCommit: %s\nBuilt At: %s\n", Version, Commit, Date)
}

func IsDevVersion() bool {
	version := strings.TrimSpace(Version)
	return version == "" || version == "dev" || version == "unknown" || strings.Contains(version, "SNAPSHOT")
}
