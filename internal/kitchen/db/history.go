// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

type HistoryEventType string

const (
	HistoryAnalysisStarted   HistoryEventType = "analysis.started"
	HistoryAnalysisCompleted HistoryEventType = "analysis.completed"
	HistoryAnalysisFailed    HistoryEventType = "analysis.failed"
	HistoryExploitAttempted  HistoryEventType = "exploit.attempted"
	HistoryExploitSucceeded  HistoryEventType = "exploit.succeeded"
	HistoryExploitFailed     HistoryEventType = "exploit.failed"
	HistoryAgentConnected    HistoryEventType = "agent.connected"
	HistorySecretExtracted   HistoryEventType = "secret.extracted"
	HistoryPurgeExecuted     HistoryEventType = "purge.executed"
)

type HistoryRow struct {
	ID        string           `json:"id"`
	Type      HistoryEventType `json:"type"`
	Timestamp time.Time        `json:"timestamp"`
	SessionID string           `json:"session_id,omitempty"`

	Target     string `json:"target,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TokenType  string `json:"token_type,omitempty"`

	VulnID     string `json:"vuln_id,omitempty"`
	Repository string `json:"repository,omitempty"`
	StagerID   string `json:"stager_id,omitempty"`
	PRURL      string `json:"pr_url,omitempty"`

	Outcome     string `json:"outcome,omitempty"`
	ErrorDetail string `json:"error_detail,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
}

type HistoryRepository struct {
	db *DB
}

func NewHistoryRepository(db *DB) *HistoryRepository {
	return &HistoryRepository{db: db}
}

func (r *HistoryRepository) Insert(entry *HistoryRow) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketHistory)

		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal history entry: %w", err)
		}

		return b.Put([]byte(entry.ID), data)
	})
}

func (r *HistoryRepository) List(limit int) ([]*HistoryRow, error) {
	var entries []*HistoryRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketHistory)

		return b.ForEach(func(k, v []byte) error {
			var entry HistoryRow
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			entries = append(entries, &entry)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	// Keep the most recent entries when limiting
	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries, nil
}

func (r *HistoryRepository) ListBySession(sessionID string) ([]*HistoryRow, error) {
	var entries []*HistoryRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketHistory)

		return b.ForEach(func(k, v []byte) error {
			var entry HistoryRow
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}

			if entry.SessionID == sessionID {
				entries = append(entries, &entry)
			}
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	return entries, nil
}

func (r *HistoryRepository) ListSince(since time.Time) ([]*HistoryRow, error) {
	var entries []*HistoryRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketHistory)

		return b.ForEach(func(k, v []byte) error {
			var entry HistoryRow
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}

			if entry.Timestamp.After(since) || entry.Timestamp.Equal(since) {
				entries = append(entries, &entry)
			}
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	return entries, nil
}
