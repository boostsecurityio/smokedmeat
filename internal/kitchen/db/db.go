// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package db provides BBolt persistence for Kitchen state.
package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
)

// Bucket names
var (
	BucketMeta          = []byte("meta")
	BucketOrders        = []byte("orders")
	BucketAgents        = []byte("agents")
	BucketSessions      = []byte("sessions")
	BucketStagers       = []byte("stagers")
	BucketMetrics       = []byte("metrics")
	BucketPantry        = []byte("pantry")
	BucketHistory       = []byte("history")
	BucketKnownEntities = []byte("known_entities")
	BucketLoot          = []byte("loot")
)

var schemaKey = []byte("schema")

const (
	currentSchemaMajor = 2
	currentSchemaMinor = 0
	legacySchemaMajor  = 1
	legacySchemaMinor  = 0
	// Keep this string stable - quickstart readiness checks grep for it in Kitchen logs.
	schemaPurgeHint = "purge the Kitchen volume with make quickstart-purge or make dev-quickstart-purge"
)

// DB wraps a BBolt database connection for Kitchen persistence.
type DB struct {
	bolt *bolt.DB
	path string
}

type schemaMetadata struct {
	Major        int       `json:"major"`
	Minor        int       `json:"minor"`
	CreatedBy    string    `json:"created_by,omitempty"`
	LastOpenedBy string    `json:"last_opened_by,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	LastOpenedAt time.Time `json:"last_opened_at,omitempty"`
}

type schemaVersionError struct {
	Path         string
	StoredMajor  int
	StoredMinor  int
	CurrentMajor int
	CurrentMinor int
}

type unversionedSchemaError struct {
	Path           string
	UnknownBuckets []string
}

func (e *schemaVersionError) Error() string {
	return fmt.Sprintf(
		"kitchen DB schema %d.%d is incompatible with this binary schema %d.%d - this existing Kitchen volume cannot be opened directly; %s, or remove %s manually",
		e.StoredMajor,
		e.StoredMinor,
		e.CurrentMajor,
		e.CurrentMinor,
		schemaPurgeHint,
		e.Path,
	)
}

func (e *unversionedSchemaError) Error() string {
	return fmt.Sprintf(
		"kitchen DB at %s has no schema metadata and unknown top-level buckets [%s] - %s, or remove %s manually",
		e.Path,
		strings.Join(e.UnknownBuckets, ", "),
		schemaPurgeHint,
		e.Path,
	)
}

// Config holds database configuration.
type Config struct {
	// Path is the path to the BBolt database file.
	Path string

	// CreateDir creates the parent directory if it doesn't exist.
	CreateDir bool
}

// Open opens or creates a BBolt database.
func Open(config Config) (*DB, error) {
	if config.CreateDir {
		dir := filepath.Dir(config.Path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("failed to create database directory: %w", err)
			}
		}
	}

	boltDB, err := bolt.Open(config.Path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{
		bolt: boltDB,
		path: config.Path,
	}

	if err := db.initialize(); err != nil {
		boltDB.Close()
		return nil, err
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	if db.bolt != nil {
		return db.bolt.Close()
	}
	return nil
}

func (db *DB) initialize() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		metaBucket := tx.Bucket(BucketMeta)
		existing, err := readSchemaMetadata(metaBucket)
		if err != nil {
			return err
		}
		if existing != nil && existing.Major != currentSchemaMajor {
			return &schemaVersionError{
				Path:         db.path,
				StoredMajor:  existing.Major,
				StoredMinor:  existing.Minor,
				CurrentMajor: currentSchemaMajor,
				CurrentMinor: currentSchemaMinor,
			}
		}
		if existing == nil {
			validateErr := validateUnversionedLayout(tx, db.path)
			if validateErr != nil {
				return validateErr
			}
		}

		metaBucket, err = tx.CreateBucketIfNotExists(BucketMeta)
		if err != nil {
			return fmt.Errorf("failed to create bucket %s: %w", BucketMeta, err)
		}

		if err := createBuckets(tx); err != nil {
			return err
		}

		return writeSchemaMetadata(metaBucket, existing)
	})
}

func createBuckets(tx *bolt.Tx) error {
	for _, bucket := range requiredBuckets() {
		if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
			return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
		}
	}
	return nil
}

func requiredBuckets() [][]byte {
	return [][]byte{
		BucketOrders,
		BucketAgents,
		BucketSessions,
		BucketStagers,
		BucketMetrics,
		BucketPantry,
		BucketHistory,
		BucketKnownEntities,
		BucketLoot,
	}
}

func validateUnversionedLayout(tx *bolt.Tx, path string) error {
	allowed := make(map[string]struct{}, len(requiredBuckets())+1)
	allowed[string(BucketMeta)] = struct{}{}
	for _, bucket := range requiredBuckets() {
		allowed[string(bucket)] = struct{}{}
	}

	var unknown []string
	hasKnownBuckets := false
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if _, ok := allowed[string(name)]; ok {
			if !bytes.Equal(name, BucketMeta) {
				hasKnownBuckets = true
			}
			return nil
		}
		unknown = append(unknown, string(name))
		return nil
	}); err != nil {
		return fmt.Errorf("failed to inspect top-level buckets: %w", err)
	}

	if len(unknown) == 0 {
		if hasKnownBuckets {
			return &schemaVersionError{
				Path:         path,
				StoredMajor:  legacySchemaMajor,
				StoredMinor:  legacySchemaMinor,
				CurrentMajor: currentSchemaMajor,
				CurrentMinor: currentSchemaMinor,
			}
		}
		return nil
	}

	sort.Strings(unknown)
	return &unversionedSchemaError{
		Path:           path,
		UnknownBuckets: unknown,
	}
}

func readSchemaMetadata(metaBucket *bolt.Bucket) (*schemaMetadata, error) {
	if metaBucket == nil {
		return nil, nil
	}

	data := metaBucket.Get(schemaKey)
	if len(data) == 0 {
		return nil, nil
	}

	var metadata schemaMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to decode schema metadata: %w", err)
	}

	return &metadata, nil
}

func writeSchemaMetadata(metaBucket *bolt.Bucket, existing *schemaMetadata) error {
	now := time.Now().UTC()
	version := buildinfo.Version
	if version == "" {
		version = "dev"
	}

	metadata := schemaMetadata{
		Major:        currentSchemaMajor,
		Minor:        currentSchemaMinor,
		CreatedBy:    version,
		LastOpenedBy: version,
		CreatedAt:    now,
		LastOpenedAt: now,
	}

	if existing != nil {
		if existing.Minor > metadata.Minor {
			metadata.Minor = existing.Minor
		}
		if !existing.CreatedAt.IsZero() {
			metadata.CreatedAt = existing.CreatedAt
		}
		if existing.CreatedBy != "" {
			metadata.CreatedBy = existing.CreatedBy
		}
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to encode schema metadata: %w", err)
	}

	return metaBucket.Put(schemaKey, data)
}
