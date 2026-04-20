// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestOpen_WritesSchemaMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(Config{Path: path, CreateDir: true})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	metadata := readSchemaMetadataFromHandle(t, db)
	require.NotNil(t, metadata)
	assert.Equal(t, currentSchemaMajor, metadata.Major)
	assert.Equal(t, currentSchemaMinor, metadata.Minor)
	assert.NotZero(t, metadata.CreatedAt)
	assert.NotZero(t, metadata.LastOpenedAt)
	assert.NotEmpty(t, metadata.CreatedBy)
	assert.NotEmpty(t, metadata.LastOpenedBy)
}

func TestOpen_RejectsUnversionedLegacyDB(t *testing.T) {
	path := createSchemaTestDB(t, nil, BucketOrders)

	db, err := Open(Config{Path: path})
	require.Error(t, err)
	assert.Nil(t, db)
	assert.ErrorContains(t, err, "schema 1.0")
	assert.ErrorContains(t, err, "cannot be opened directly")
	assert.ErrorContains(t, err, "make quickstart-purge")
	assert.ErrorContains(t, err, "make dev-quickstart-purge")
}

func TestOpen_PreservesCompatibleNewerMinor(t *testing.T) {
	path := createSchemaTestDB(t, &schemaMetadata{
		Major:        currentSchemaMajor,
		Minor:        currentSchemaMinor + 2,
		CreatedBy:    "v0.1.2",
		LastOpenedBy: "v0.1.2",
		CreatedAt:    time.Now().UTC().Add(-time.Hour),
		LastOpenedAt: time.Now().UTC().Add(-time.Minute),
	}, BucketOrders)

	db, err := Open(Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	metadata := readSchemaMetadataFromHandle(t, db)
	require.NotNil(t, metadata)
	assert.Equal(t, currentSchemaMajor, metadata.Major)
	assert.Equal(t, currentSchemaMinor+2, metadata.Minor)
	assert.Equal(t, "v0.1.2", metadata.CreatedBy)
}

func TestOpen_RejectsIncompatibleSchemaMajor(t *testing.T) {
	path := createSchemaTestDB(t, &schemaMetadata{
		Major: legacySchemaMajor,
		Minor: 0,
	}, BucketOrders)

	db, err := Open(Config{Path: path})
	require.Error(t, err)
	assert.Nil(t, db)
	assert.ErrorContains(t, err, "make quickstart-purge")
	assert.ErrorContains(t, err, "make dev-quickstart-purge")
	assert.ErrorContains(t, err, "incompatible")
}

func TestOpen_RejectsUnknownUnversionedLayout(t *testing.T) {
	path := createSchemaTestDB(t, nil, []byte("mystery"))

	db, err := Open(Config{Path: path})
	require.Error(t, err)
	assert.Nil(t, db)
	assert.ErrorContains(t, err, "unknown top-level buckets")
	assert.ErrorContains(t, err, "mystery")
	assert.ErrorContains(t, err, "make quickstart-purge")
}

func createSchemaTestDB(t *testing.T, metadata *schemaMetadata, buckets ...[]byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "schema.db")
	rawDB, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)

	err = rawDB.Update(func(tx *bolt.Tx) error {
		for _, bucket := range buckets {
			if _, bucketErr := tx.CreateBucketIfNotExists(bucket); bucketErr != nil {
				return bucketErr
			}
		}

		if metadata == nil {
			return nil
		}

		metaBucket, bucketErr := tx.CreateBucketIfNotExists(BucketMeta)
		if bucketErr != nil {
			return bucketErr
		}

		data, marshalErr := json.Marshal(metadata)
		if marshalErr != nil {
			return marshalErr
		}

		return metaBucket.Put(schemaKey, data)
	})
	require.NoError(t, err)
	require.NoError(t, rawDB.Close())

	return path
}

func readSchemaMetadataFromHandle(t *testing.T, db *DB) *schemaMetadata {
	t.Helper()

	var metadata *schemaMetadata
	err := db.bolt.View(func(tx *bolt.Tx) error {
		metaBucket := tx.Bucket(BucketMeta)
		require.NotNil(t, metaBucket)

		current, err := readSchemaMetadata(metaBucket)
		if err != nil {
			return err
		}
		metadata = current
		return nil
	})
	require.NoError(t, err)

	return metadata
}
