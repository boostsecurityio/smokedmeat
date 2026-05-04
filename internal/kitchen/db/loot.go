// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type LootRow struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Origin    string    `json:"origin,omitempty"`

	Name      string `json:"name"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	HighValue bool   `json:"high_value"`

	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Job        string `json:"job,omitempty"`

	TokenPermissions map[string]string `json:"token_permissions,omitempty"`

	ResidentJobKey        string `json:"resident_job_key,omitempty"`
	RunID                 string `json:"run_id,omitempty"`
	RunAttempt            string `json:"run_attempt,omitempty"`
	AttributionConfidence string `json:"attribution_confidence,omitempty"`
	HarvestProfile        string `json:"harvest_profile,omitempty"`
	SignalSource          string `json:"signal_source,omitempty"`
}

type LootRepository struct {
	db *DB
}

const (
	LootOriginExpress  = "express"
	LootOriginAnalysis = "analysis"
	LootOriginResident = "resident_job"
)

func NewLootRepository(db *DB) *LootRepository {
	return &LootRepository{db: db}
}

func (r *LootRepository) Upsert(entry *LootRow) error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketLoot)
		entry.ID = lootStableID(entry)

		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now()
		}

		if err := deleteLootConflicts(b, entry); err != nil {
			return err
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal loot entry: %w", err)
		}

		return b.Put([]byte(entry.ID), data)
	})
}

func deleteLootConflicts(b *bolt.Bucket, entry *LootRow) error {
	targetKey := lootLogicalKey(entry)
	return b.ForEach(func(k, v []byte) error {
		if string(k) == entry.ID {
			return nil
		}
		var existing LootRow
		if err := json.Unmarshal(v, &existing); err != nil {
			return err
		}
		if lootLogicalKey(&existing) == targetKey {
			if err := b.Delete(k); err != nil {
				return fmt.Errorf("failed to delete stale loot entry: %w", err)
			}
		}
		return nil
	})
}

func (r *LootRepository) List() ([]*LootRow, error) {
	latestByKey := make(map[string]*LootRow)

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketLoot)

		return b.ForEach(func(k, v []byte) error {
			var entry LootRow
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			key := lootLogicalKey(&entry)
			if existing, ok := latestByKey[key]; ok && existing.Timestamp.After(entry.Timestamp) {
				return nil
			}
			copy := entry
			latestByKey[key] = &copy
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	entries := make([]*LootRow, 0, len(latestByKey))
	for _, entry := range latestByKey {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	return entries, nil
}

func lootStableID(entry *LootRow) string {
	return lootLogicalKey(entry)
}

func lootLogicalKey(entry *LootRow) string {
	if entry == nil {
		return "loot:-"
	}
	if entry.Origin == LootOriginResident {
		return strings.Join([]string{
			"loot",
			"resident",
			normalizeLootKeyPart(entry.ResidentJobKey),
			normalizeLootKeyPart(entry.RunID),
			normalizeLootKeyPart(entry.RunAttempt),
			normalizeLootKeyPart(entry.Name),
		}, ":")
	}
	if entry.Repository != "" || entry.Workflow != "" || entry.Job != "" {
		return strings.Join([]string{
			"loot",
			normalizeLootKeyPart(entry.Repository),
			normalizeLootKeyPart(entry.Workflow),
			normalizeLootKeyPart(entry.Job),
			normalizeLootKeyPart(entry.Name),
		}, ":")
	}

	anchor := entry.AgentID
	if anchor == "" {
		anchor = entry.Source
	}
	if anchor == "" {
		anchor = entry.SessionID
	}

	return strings.Join([]string{
		"loot",
		"agent",
		normalizeLootKeyPart(anchor),
		normalizeLootKeyPart(entry.Name),
	}, ":")
}

func normalizeLootKeyPart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, ":", "_")
}
