// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux
// +build !linux

package brisket

import "context"

func (a *Agent) startResidentJobWatcher(_ context.Context) func() {
	return func() {}
}
