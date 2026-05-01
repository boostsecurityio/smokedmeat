// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOperationHistory_AddAndEntries(t *testing.T) {
	h := NewOperationHistory()
	assert.Empty(t, h.Entries())

	h.Add(HistoryEntry{Type: "analysis.started", Target: "acme-corp"})
	h.Add(HistoryEntry{Type: "analysis.completed", Target: "acme-corp", Outcome: "5 vulns"})

	entries := h.Entries()
	assert.Len(t, entries, 2)
	assert.Equal(t, "analysis.started", entries[0].Type)
	assert.Equal(t, "analysis.completed", entries[1].Type)
	assert.False(t, entries[0].Timestamp.IsZero(), "Add should set timestamp if zero")
}

func TestOperationHistory_AddPreservesTimestamp(t *testing.T) {
	h := NewOperationHistory()
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	h.Add(HistoryEntry{Type: "test", Timestamp: ts})
	assert.Equal(t, ts, h.Entries()[0].Timestamp)
}

func TestOperationHistory_SetEntries(t *testing.T) {
	h := NewOperationHistory()
	entries := make([]HistoryEntry, 250)
	for i := range entries {
		entries[i] = HistoryEntry{Type: "test"}
	}
	h.SetEntries(entries)
	assert.Len(t, h.Entries(), maxHistoryEntries, "Should cap at maxHistoryEntries")
}

func TestOperationHistory_AddCapsAtMax(t *testing.T) {
	h := NewOperationHistory()
	for i := 0; i < maxHistoryEntries+10; i++ {
		h.Add(HistoryEntry{Type: "test"})
	}
	assert.Len(t, h.Entries(), maxHistoryEntries)
}

func TestIconForHistoryType(t *testing.T) {
	tests := []struct {
		histType string
		icon     string
	}{
		{"analysis.started", IconScan},
		{"analysis.completed", IconScan},
		{"deep_analysis.completed", IconScan},
		{"analysis.failed", IconError},
		{"exploit.attempted", IconPivot},
		{"exploit.succeeded", IconSuccess},
		{"exploit.failed", IconError},
		{"workflow_dispatch.triggered", IconSuccess},
		{"agent.connected", IconAgent},
		{"secret.extracted", IconSecret},
		{"purge.executed", IconWarning},
		{"unknown.type", IconInfo},
		{"", IconInfo},
	}
	for _, tt := range tests {
		t.Run(tt.histType, func(t *testing.T) {
			assert.Equal(t, tt.icon, iconForHistoryType(tt.histType))
		})
	}
}

func TestMessageForHistoryEntry(t *testing.T) {
	tests := []struct {
		name  string
		entry HistoryEntry
		want  string
	}{
		{
			"analysis started",
			HistoryEntry{Type: "analysis.started", Target: "acme-corp"},
			"Analyzing acme-corp",
		},
		{
			"analysis completed with outcome",
			HistoryEntry{Type: "analysis.completed", Target: "acme-corp", Outcome: "5 vulns"},
			"Analyzed acme-corp → 5 vulns",
		},
		{
			"analysis completed no outcome",
			HistoryEntry{Type: "analysis.completed", Target: "acme-corp"},
			"Analyzed acme-corp",
		},
		{
			"deep analysis completed",
			HistoryEntry{Type: "deep_analysis.completed", Target: "org/repo", Outcome: "3 findings"},
			"Deep-analyzed org/repo → 3 findings",
		},
		{
			"deep analysis no outcome",
			HistoryEntry{Type: "deep_analysis.completed", Target: "org/repo"},
			"Deep-analyzed org/repo",
		},
		{
			"analysis failed",
			HistoryEntry{Type: "analysis.failed", ErrorDetail: "timeout"},
			"Analysis failed: timeout",
		},
		{
			"exploit attempted with repo",
			HistoryEntry{Type: "exploit.attempted", VulnID: "V001", Repository: "acme/app"},
			"Exploit V001 @ acme/app",
		},
		{
			"exploit attempted no repo",
			HistoryEntry{Type: "exploit.attempted", VulnID: "V002"},
			"Exploit V002",
		},
		{
			"exploit attempted repo only",
			HistoryEntry{Type: "exploit.attempted", Repository: "acme/app"},
			"Exploit attempted @ acme/app",
		},
		{
			"exploit succeeded with vuln",
			HistoryEntry{Type: "exploit.succeeded", VulnID: "V001"},
			"Success V001",
		},
		{
			"exploit succeeded no vuln",
			HistoryEntry{Type: "exploit.succeeded"},
			"Success",
		},
		{
			"exploit failed",
			HistoryEntry{Type: "exploit.failed", ErrorDetail: "PR rejected"},
			"Failed: PR rejected",
		},
		{
			"workflow dispatch triggered",
			HistoryEntry{Type: "workflow_dispatch.triggered", Repository: "acme/app"},
			"Workflow dispatch @ acme/app",
		},
		{
			"agent connected",
			HistoryEntry{Type: "agent.connected", AgentID: "agt_abc"},
			"Agent agt_abc",
		},
		{
			"secret extracted",
			HistoryEntry{Type: "secret.extracted"},
			"Secrets extracted",
		},
		{
			"purge executed",
			HistoryEntry{Type: "purge.executed", TargetType: "repo", Target: "acme/api", Outcome: "3 pantry assets, 1 known entities"},
			"Purged repo:acme/api → 3 pantry assets, 1 known entities",
		},
		{
			"unknown type",
			HistoryEntry{Type: "custom.event"},
			"custom.event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, messageForHistoryEntry(tt.entry))
		})
	}
}
