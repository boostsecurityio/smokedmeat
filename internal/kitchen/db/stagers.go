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

type StagerRow struct {
	ID              string            `json:"id"`
	ResponseType    string            `json:"response_type"`
	Payload         string            `json:"payload"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	CalledBack      bool              `json:"called_back"`
	CallbackAt      time.Time         `json:"callback_at"`
	CallbackIP      string            `json:"callback_ip"`
	SessionID       string            `json:"session_id"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	PrivateMetadata map[string]string `json:"private_metadata,omitempty"`
	DwellTime       time.Duration     `json:"dwell_time"`
	Persistent      bool              `json:"persistent"`
	MaxCallbacks    int               `json:"max_callbacks,omitempty"`
	DefaultMode     string            `json:"default_mode,omitempty"`
	NextMode        string            `json:"next_mode,omitempty"`
	CallbackCount   int               `json:"callback_count"`
	LastAgentID     string            `json:"last_agent_id,omitempty"`
	RevokedAt       *time.Time        `json:"revoked_at,omitempty"`
}

type StagerRepository struct {
	db *DB
}

func NewStagerRepository(db *DB) *StagerRepository {
	return &StagerRepository{db: db}
}

func (r *StagerRepository) Upsert(row *StagerRow) error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketStagers)

		data, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("failed to marshal stager: %w", err)
		}

		return b.Put([]byte(row.ID), data)
	})
}

func (r *StagerRepository) Delete(id string) error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketStagers)
		return b.Delete([]byte(id))
	})
}

func (r *StagerRepository) List() ([]*StagerRow, error) {
	var rows []*StagerRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketStagers)
		return b.ForEach(func(_, v []byte) error {
			var row StagerRow
			if err := json.Unmarshal(v, &row); err != nil {
				return err
			}
			rows = append(rows, &row)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	return rows, nil
}
