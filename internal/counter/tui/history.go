// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"time"
)

const maxHistoryEntries = 200

type HistoryEntry struct {
	ID        string
	Type      string
	Timestamp time.Time
	SessionID string

	Target     string
	TargetType string
	TokenType  string

	VulnID     string
	Repository string
	StagerID   string
	PRURL      string

	Outcome     string
	ErrorDetail string
	AgentID     string
}

type OperationHistory struct {
	entries []HistoryEntry
}

func NewOperationHistory() *OperationHistory {
	return &OperationHistory{
		entries: make([]HistoryEntry, 0, maxHistoryEntries),
	}
}

func (h *OperationHistory) SetEntries(entries []HistoryEntry) {
	h.entries = entries
	if len(h.entries) > maxHistoryEntries {
		h.entries = h.entries[len(h.entries)-maxHistoryEntries:]
	}
}

func (h *OperationHistory) Add(entry HistoryEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	h.entries = append(h.entries, entry)
	if len(h.entries) > maxHistoryEntries {
		h.entries = h.entries[1:]
	}
}

func (h *OperationHistory) Entries() []HistoryEntry {
	return h.entries
}

func iconForHistoryType(t string) string {
	switch t {
	case "analysis.started", "analysis.completed", "deep_analysis.completed":
		return IconScan
	case "analysis.failed":
		return IconError
	case "exploit.attempted":
		return IconPivot
	case "exploit.succeeded":
		return IconSuccess
	case "exploit.failed":
		return IconError
	case "workflow_dispatch.triggered":
		return IconSuccess
	case "agent.connected":
		return IconAgent
	case "secret.extracted":
		return IconSecret
	case "purge.executed":
		return IconWarning
	default:
		return IconInfo
	}
}

func messageForHistoryEntry(e HistoryEntry) string {
	switch e.Type {
	case "analysis.started":
		return "Analyzing " + e.Target
	case "analysis.completed":
		msg := "Analyzed " + e.Target
		if e.Outcome != "" {
			msg += " → " + e.Outcome
		}
		return msg
	case "deep_analysis.completed":
		msg := "Deep-analyzed " + e.Target
		if e.Outcome != "" {
			msg += " → " + e.Outcome
		}
		return msg
	case "analysis.failed":
		return "Analysis failed: " + e.ErrorDetail
	case "exploit.attempted":
		if e.VulnID != "" {
			target := e.VulnID
			if e.Repository != "" {
				target += " @ " + e.Repository
			}
			return "Exploit " + target
		}
		if e.Repository != "" {
			return "Exploit attempted @ " + e.Repository
		}
		return "Exploit attempted"
	case "workflow_dispatch.triggered":
		msg := "Workflow dispatch"
		if e.Repository != "" {
			msg += " @ " + e.Repository
		}
		return msg
	case "exploit.succeeded":
		msg := "Success"
		if e.VulnID != "" {
			msg += " " + e.VulnID
		}
		return msg
	case "exploit.failed":
		return "Failed: " + e.ErrorDetail
	case "agent.connected":
		return "Agent " + e.AgentID
	case "secret.extracted":
		return "Secrets extracted"
	case "purge.executed":
		msg := "Purged " + e.TargetType + ":" + e.Target
		if e.Outcome != "" {
			msg += " → " + e.Outcome
		}
		return msg
	default:
		return e.Type
	}
}
