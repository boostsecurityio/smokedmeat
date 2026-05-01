// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
)

func TestNewStagerStore(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	assert.NotNil(t, store)
}

func TestStagerStore_Register(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	stager := &RegisteredStager{
		ID:           "test123",
		ResponseType: "bash",
		Payload:      "echo hello",
	}

	err := store.Register(stager)
	require.NoError(t, err)

	// Should be retrievable
	retrieved := store.Get("test123")
	assert.NotNil(t, retrieved)
	assert.Equal(t, "test123", retrieved.ID)
	assert.Equal(t, "bash", retrieved.ResponseType)
	assert.Equal(t, "echo hello", retrieved.Payload)
}

func TestStagerStore_Register_SetsDefaults(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 1 * time.Hour
	store := NewStagerStore(config)

	stager := &RegisteredStager{
		ID:           "test",
		ResponseType: "bash",
	}

	err := store.Register(stager)
	require.NoError(t, err)

	retrieved := store.Get("test")
	assert.NotZero(t, retrieved.CreatedAt)
	assert.NotZero(t, retrieved.ExpiresAt)
	assert.True(t, retrieved.ExpiresAt.After(retrieved.CreatedAt))
	assert.Equal(t, 1, retrieved.MaxCallbacks)
}

func TestStagerStore_Get_NotFound(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	result := store.Get("nonexistent")
	assert.Nil(t, result)
}

func TestStagerStore_Get_ReturnsClone(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	require.NoError(t, store.Register(&RegisteredStager{
		ID:       "clone-test",
		Metadata: map[string]string{"pr_url": "https://github.com/acme/api/pull/1"},
	}))

	retrieved := store.Get("clone-test")
	require.NotNil(t, retrieved)
	retrieved.CalledBack = true
	retrieved.Metadata["pr_url"] = "https://github.com/acme/api/pull/2"

	current := store.Get("clone-test")
	require.NotNil(t, current)
	assert.False(t, current.CalledBack)
	assert.Equal(t, "https://github.com/acme/api/pull/1", current.Metadata["pr_url"])
}

func TestStagerStore_MarkCalledBack(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	stager := &RegisteredStager{
		ID:           "callback-test",
		ResponseType: "bash",
	}
	_ = store.Register(stager)

	// Mark as called back
	ok := store.MarkCalledBack("callback-test", "192.168.1.100")
	assert.True(t, ok)

	// Verify
	retrieved := store.Get("callback-test")
	assert.True(t, retrieved.CalledBack)
	assert.Equal(t, "192.168.1.100", retrieved.CallbackIP)
	assert.NotZero(t, retrieved.CallbackAt)
}

func TestStagerStore_MarkCalledBack_NotFound(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	ok := store.MarkCalledBack("nonexistent", "192.168.1.100")
	assert.False(t, ok)
}

func TestStagerStore_Remove(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	stager := &RegisteredStager{ID: "to-remove"}
	_ = store.Register(stager)

	// Verify it exists
	assert.NotNil(t, store.Get("to-remove"))

	// Remove it
	store.Remove("to-remove")

	// Verify it's gone
	assert.Nil(t, store.Get("to-remove"))
}

func TestStagerStore_List(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	_ = store.Register(&RegisteredStager{ID: "stager1"})
	_ = store.Register(&RegisteredStager{ID: "stager2"})
	_ = store.Register(&RegisteredStager{ID: "stager3"})

	list := store.List()
	assert.Len(t, list, 3)

	ids := make(map[string]bool)
	for _, s := range list {
		ids[s.ID] = true
	}
	assert.True(t, ids["stager1"])
	assert.True(t, ids["stager2"])
	assert.True(t, ids["stager3"])
}

func TestStagerStore_List_ReturnsClones(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	require.NoError(t, store.Register(&RegisteredStager{
		ID:       "stager1",
		Metadata: map[string]string{"env": "production"},
	}))

	list := store.List()
	require.Len(t, list, 1)
	list[0].Metadata["env"] = "staging"

	current := store.Get("stager1")
	require.NotNil(t, current)
	assert.Equal(t, "production", current.Metadata["env"])
}

func TestStagerStore_Stats(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	_ = store.Register(&RegisteredStager{ID: "pending1"})
	_ = store.Register(&RegisteredStager{ID: "pending2"})
	triggered := &RegisteredStager{ID: "triggered1", CalledBack: true}
	_ = store.Register(triggered)

	stats := store.Stats()
	assert.Equal(t, 3, stats["total"])
	assert.Equal(t, 1, stats["triggered"])
	assert.Equal(t, 2, stats["pending"])
}

func TestStagerStore_MaxStagers(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.MaxStagers = 3
	store := NewStagerStore(config)

	_ = store.Register(&RegisteredStager{ID: "s1"})
	_ = store.Register(&RegisteredStager{ID: "s2"})
	_ = store.Register(&RegisteredStager{ID: "s3"})

	// Fourth should fail
	err := store.Register(&RegisteredStager{ID: "s4"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "full")
}

func TestStagerStore_Cleanup(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 10 * time.Millisecond
	config.CleanupPeriod = 5 * time.Millisecond
	store := NewStagerStore(config)

	_ = store.Register(&RegisteredStager{ID: "expire-me"})

	// Should exist initially
	assert.NotNil(t, store.Get("expire-me"))

	// Wait for expiry
	time.Sleep(50 * time.Millisecond)

	// Manually trigger cleanup (since we didn't start the goroutine)
	store.cleanup()

	// Should be gone
	assert.Nil(t, store.Get("expire-me"))
}

func TestDefaultBashPayload(t *testing.T) {
	payload := DefaultBashPayload("http://kitchen.example.com", "agent123", "session789")

	assert.Contains(t, payload, "#!/bin/bash")
	assert.Contains(t, payload, "KITCHEN_URL")
	assert.Contains(t, payload, "http://kitchen.example.com")
	assert.Contains(t, payload, "SESSION_ID")
	assert.Contains(t, payload, "session789")
	assert.Contains(t, payload, "curl")
	assert.Contains(t, payload, "brisket")
}

func TestDefaultJSPayload(t *testing.T) {
	payload := DefaultJSPayload("http://kitchen.example.com", "agent456", "session789")

	assert.Contains(t, payload, "require('https')")
	assert.Contains(t, payload, "os.hostname")
	assert.Contains(t, payload, "agent_id")
	assert.Contains(t, payload, "agent456")
	assert.Contains(t, payload, "session_id")
	assert.Contains(t, payload, "session789")
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

func TestDefaultStagerStoreConfig_Values(t *testing.T) {
	config := DefaultStagerStoreConfig()

	// Verify all fields are set
	assert.Greater(t, config.MaxStagers, 0)
	assert.Greater(t, config.DefaultTTL, time.Duration(0))
	assert.Greater(t, config.CleanupPeriod, time.Duration(0))
}

func TestStagerStore_Register_PreservesExistingTimestamps(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	customTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	stager := &RegisteredStager{
		ID:        "custom-time",
		CreatedAt: customTime,
		ExpiresAt: customTime.Add(1 * time.Hour),
	}

	err := store.Register(stager)
	require.NoError(t, err)

	retrieved := store.Get("custom-time")
	assert.Equal(t, customTime, retrieved.CreatedAt)
	assert.Equal(t, customTime.Add(1*time.Hour), retrieved.ExpiresAt)
}

func TestStagerStore_Register_NoDefaultTTL(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 0 // Disable default TTL
	store := NewStagerStore(config)

	stager := &RegisteredStager{ID: "no-ttl"}
	err := store.Register(stager)
	require.NoError(t, err)

	retrieved := store.Get("no-ttl")
	// Should have zero expiry (no default TTL applied)
	assert.True(t, retrieved.ExpiresAt.IsZero())
}

func TestStagerStore_Remove_NonExistent(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	// Should not panic
	store.Remove("does-not-exist")
}

func TestStagerStore_List_Empty(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	list := store.List()

	assert.NotNil(t, list)
	assert.Empty(t, list)
}

func TestStagerStore_Stats_Empty(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	stats := store.Stats()

	assert.Equal(t, 0, stats["total"])
	assert.Equal(t, 0, stats["triggered"])
	assert.Equal(t, 0, stats["pending"])
}

func TestStagerStore_Cleanup_NoExpiry(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 0 // No default TTL
	store := NewStagerStore(config)

	// Register with no expiry
	stager := &RegisteredStager{ID: "permanent"}
	store.stagers[stager.ID] = stager

	// Run cleanup
	store.cleanup()

	// Should still exist (no expiry time)
	assert.NotNil(t, store.Get("permanent"))
}

func TestStagerStore_StartStopCleanup(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.CleanupPeriod = 10 * time.Millisecond
	store := NewStagerStore(config)

	// Start and stop should not panic
	store.StartCleanup()
	time.Sleep(25 * time.Millisecond)
	store.StopCleanup()
}

func TestRegisteredStager_AllFields(t *testing.T) {
	now := time.Now()
	stager := RegisteredStager{
		ID:           "full-stager",
		ResponseType: "python",
		Payload:      "print('hello')",
		CreatedAt:    now,
		ExpiresAt:    now.Add(1 * time.Hour),
		CalledBack:   true,
		CallbackAt:   now.Add(30 * time.Minute),
		CallbackIP:   "10.0.0.1",
		SessionID:    "session-abc",
		Metadata:     map[string]string{"env": "production"},
		MaxCallbacks: 3,
	}

	assert.Equal(t, "full-stager", stager.ID)
	assert.Equal(t, "python", stager.ResponseType)
	assert.Equal(t, "print('hello')", stager.Payload)
	assert.Equal(t, now, stager.CreatedAt)
	assert.Equal(t, now.Add(1*time.Hour), stager.ExpiresAt)
	assert.True(t, stager.CalledBack)
	assert.Equal(t, now.Add(30*time.Minute), stager.CallbackAt)
	assert.Equal(t, "10.0.0.1", stager.CallbackIP)
	assert.Equal(t, "session-abc", stager.SessionID)
	assert.Equal(t, "production", stager.Metadata["env"])
	assert.Equal(t, 3, stager.MaxCallbacks)
}

func TestStagerStore_ValidateStager(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	_ = store.Register(&RegisteredStager{
		ID:        "valid",
		SessionID: "session-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Register(&RegisteredStager{
		ID:        "expired",
		SessionID: "session-2",
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	t.Run("valid stager", func(t *testing.T) {
		sessionID, expired, exists := store.ValidateStager("valid")
		assert.True(t, exists)
		assert.False(t, expired)
		assert.Equal(t, "session-1", sessionID)
	})

	t.Run("expired stager", func(t *testing.T) {
		_, expired, exists := store.ValidateStager("expired")
		assert.True(t, exists)
		assert.True(t, expired)
	})

	t.Run("nonexistent", func(t *testing.T) {
		_, _, exists := store.ValidateStager("nope")
		assert.False(t, exists)
	})
}

func TestStagerStore_GetBySessionID(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	_ = store.Register(&RegisteredStager{ID: "s1", SessionID: "session-A"})
	_ = store.Register(&RegisteredStager{ID: "s2", SessionID: "session-B"})

	result := store.GetBySessionID("session-A")
	require.NotNil(t, result)
	assert.Equal(t, "s1", result.ID)

	assert.Nil(t, store.GetBySessionID("nonexistent"))
}

func TestStagerStore_GetBySessionID_ReturnsClone(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	require.NoError(t, store.Register(&RegisteredStager{
		ID:        "s1",
		SessionID: "session-A",
		Metadata:  map[string]string{"repository": "acme/api"},
	}))

	result := store.GetBySessionID("session-A")
	require.NotNil(t, result)
	result.Metadata["repository"] = "acme/other"

	current := store.Get("s1")
	require.NotNil(t, current)
	assert.Equal(t, "acme/api", current.Metadata["repository"])
}

func TestStagerStore_UpdateMetadata(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())

	require.NoError(t, store.Register(&RegisteredStager{ID: "meta-test"}))

	updated := store.UpdateMetadata("meta-test", map[string]string{
		"pr_url":       "https://github.com/acme/api/pull/1",
		"deploy_token": "ghp_test",
	})
	require.NotNil(t, updated)
	assert.Equal(t, "https://github.com/acme/api/pull/1", updated.Metadata["pr_url"])
	assert.Empty(t, updated.Metadata["deploy_token"])
	assert.Equal(t, "ghp_test", updated.PrivateMetadata["deploy_token"])

	updated.Metadata["pr_url"] = "https://github.com/acme/api/pull/2"
	updated.PrivateMetadata["deploy_token"] = "ghp_changed"

	current := store.Get("meta-test")
	require.NotNil(t, current)
	assert.Equal(t, "https://github.com/acme/api/pull/1", current.Metadata["pr_url"])
	assert.Empty(t, current.Metadata["deploy_token"])
	assert.Equal(t, "ghp_test", current.PrivateMetadata["deploy_token"])
	assert.Nil(t, store.UpdateMetadata("missing", map[string]string{"pr_url": "x"}))
}

func TestStagerMetadata_TokenKeysStayPrivate(t *testing.T) {
	stager := &RegisteredStager{
		ID: "cb1",
		Metadata: map[string]string{
			"pr_url":       "https://github.com/acme/api/pull/1",
			"deploy_token": "ghp_test",
			"lotp_token":   "ghp_lotp",
		},
	}

	summary := callbackSummary(stager)
	row := stagerRowFromRegistered(stager)
	restored := registeredStagerFromRow(&db.StagerRow{
		ID: "cb1",
		Metadata: map[string]string{
			"pr_url":       "https://github.com/acme/api/pull/1",
			"deploy_token": "ghp_legacy",
		},
	})
	restoredCurrent := registeredStagerFromRow(&db.StagerRow{
		ID:       "cb2",
		Metadata: map[string]string{"pr_url": "https://github.com/acme/api/pull/2"},
		PrivateMetadata: map[string]string{
			"deploy_token": "ghp_current",
		},
	})

	assert.Equal(t, "https://github.com/acme/api/pull/1", summary.Metadata["pr_url"])
	assert.Empty(t, summary.Metadata["deploy_token"])
	assert.Empty(t, summary.Metadata["lotp_token"])
	assert.Equal(t, "https://github.com/acme/api/pull/1", row.Metadata["pr_url"])
	assert.Empty(t, row.Metadata["deploy_token"])
	assert.Empty(t, row.Metadata["lotp_token"])
	assert.Equal(t, "ghp_test", row.PrivateMetadata["deploy_token"])
	assert.Equal(t, "ghp_lotp", row.PrivateMetadata["lotp_token"])
	assert.Equal(t, "https://github.com/acme/api/pull/1", restored.Metadata["pr_url"])
	assert.Empty(t, restored.Metadata["deploy_token"])
	assert.Equal(t, "ghp_legacy", restored.PrivateMetadata["deploy_token"])
	assert.Equal(t, "https://github.com/acme/api/pull/2", restoredCurrent.Metadata["pr_url"])
	assert.Empty(t, restoredCurrent.Metadata["deploy_token"])
	assert.Equal(t, "ghp_current", restoredCurrent.PrivateMetadata["deploy_token"])
}

func TestDefaultBashPayloadWithDwell(t *testing.T) {
	payload := DefaultBashPayloadWithDwell("https://k.example.com", "agent1", "sess1", "agt_tok", "cb1", "dwell", 30*time.Minute)

	assert.Contains(t, payload, "https://k.example.com")
	assert.Contains(t, payload, "agent1")
	assert.Contains(t, payload, "agt_tok")
	assert.Contains(t, payload, `CALLBACK_ID="cb1"`)
	assert.Contains(t, payload, `CALLBACK_MODE="dwell"`)
	assert.Contains(t, payload, `-callback-id "$CALLBACK_ID"`)
	assert.Contains(t, payload, `-callback-mode "$CALLBACK_MODE"`)
	assert.Contains(t, payload, "-dwell 30m0s")
}

func TestDefaultBashPayloadForRegisteredStager_SelfHostedResidentTryCloudflare(t *testing.T) {
	stager := &RegisteredStager{
		ID:         "cb1",
		SessionID:  "sess1",
		Persistent: true,
		Metadata: map[string]string{
			"callback_kind":    "self_hosted_runner",
			"persistence_mode": "resident",
		},
	}

	payload := DefaultBashPayloadForRegisteredStager("https://demo-name.trycloudflare.com", "agent1", "sess1", "agt_tok", stager, CallbackInvocation{Mode: CallbackModeExpress})

	assert.Contains(t, payload, `PERSIST_CALLBACK_MODE="resident"`)
	assert.Contains(t, payload, `PERSIST_RELAUNCH_FLAGS="-interval 5s -max-offline 1h0m0s"`)
	assert.Contains(t, payload, `if [ -n "${SMOKEDMEAT_PERSIST:-}" ] && [ "$OS" = "linux" ]; then`)
	assert.Contains(t, payload, `PERSIST_RUN=`)
	assert.Contains(t, payload, `setsid sh -c "$PERSIST_RUN"`)
	assert.Contains(t, payload, `nohup sh -c "$PERSIST_RUN"`)
	assert.Contains(t, payload, `sudo -n -E true`)
	assert.Contains(t, payload, `sudo -n -E \"$PERSIST_BIN\" -kitchen`)
	assert.Contains(t, payload, `else \"$PERSIST_BIN\" -kitchen`)
	assert.Contains(t, payload, `-callback-mode \"$PERSIST_CALLBACK_MODE\" $PERSIST_RELAUNCH_FLAGS`)
	assert.NotContains(t, payload, `sleep "$SMOKEDMEAT_PERSIST_DELAY"`)
}

func TestDefaultBashPayloadForRegisteredStager_ResidentPersistenceDoesNotRequireCallbackKind(t *testing.T) {
	stager := &RegisteredStager{
		ID:         "cb1",
		SessionID:  "sess1",
		Persistent: true,
		Metadata: map[string]string{
			"persistence_mode": "resident",
		},
	}

	payload := DefaultBashPayloadForRegisteredStager("https://k.example.com", "agent1", "sess1", "agt_tok", stager, CallbackInvocation{Mode: CallbackModeExpress})

	assert.Contains(t, payload, `PERSIST_CALLBACK_MODE="resident"`)
	assert.Contains(t, payload, `PERSIST_RELAUNCH_FLAGS="-interval 5s"`)
	assert.Contains(t, payload, `sudo -n -E \"$PERSIST_BIN\" -kitchen`)
	assert.Contains(t, payload, `-callback-mode \"$PERSIST_CALLBACK_MODE\" $PERSIST_RELAUNCH_FLAGS`)
	assert.NotContains(t, payload, `-callback-mode \"$PERSIST_CALLBACK_MODE\" -express`)
}

func TestDefaultJSPayloadWithToken(t *testing.T) {
	payload := DefaultJSPayloadWithToken("https://k.example.com", "agent1", "sess1", "agt_token", "cb1", "express")

	assert.Contains(t, payload, "require('https')")
	assert.Contains(t, payload, "agent1")
	assert.Contains(t, payload, "sess1")
	assert.Contains(t, payload, "agt_token")
	assert.Contains(t, payload, "callback_id")
	assert.Contains(t, payload, "callback_mode")
	assert.Contains(t, payload, "X-Agent-Token")
}

func TestStagerStore_ResolveCallback_PersistentConsumesNextMode(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	err := store.Register(&RegisteredStager{
		ID:          "cb1",
		SessionID:   "session-1",
		Persistent:  true,
		DefaultMode: CallbackModeExpress,
		NextMode:    CallbackModeDwell,
		DwellTime:   10 * time.Minute,
	})
	require.NoError(t, err)

	stager, invocation, ok := store.ResolveCallback("cb1", "127.0.0.1", "agt-1")
	require.True(t, ok)
	require.NotNil(t, stager)
	assert.Equal(t, CallbackModeDwell, invocation.Mode)
	assert.Equal(t, 10*time.Minute, invocation.DwellTime)
	assert.Equal(t, 1, stager.CallbackCount)
	assert.Equal(t, "agt-1", stager.LastAgentID)

	current := store.Get("cb1")
	require.NotNil(t, current)
	assert.Equal(t, "", current.NextMode)
	assert.Equal(t, 1, current.CallbackCount)
}

func TestStagerStore_ControlPersistent_RevokeMakesCallbackInvalid(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	err := store.Register(&RegisteredStager{
		ID:         "cb1",
		SessionID:  "session-1",
		Persistent: true,
	})
	require.NoError(t, err)

	updated, err := store.ControlPersistent("cb1", "revoke")
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.NotNil(t, updated.RevokedAt)

	_, expired, exists := store.ValidateStager("cb1")
	assert.True(t, exists)
	assert.True(t, expired)
}

func TestStagerStore_ResolveCallback_RejectsExpired(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	err := store.Register(&RegisteredStager{
		ID:        "expired-cb",
		SessionID: "session-1",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	require.NoError(t, err)

	_, _, ok := store.ResolveCallback("expired-cb", "127.0.0.1", "agt-1")
	assert.False(t, ok, "ResolveCallback should reject expired stagers")
}

func TestStagerStore_ResolveCallback_RejectsRevoked(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	err := store.Register(&RegisteredStager{
		ID:         "revoked-cb",
		SessionID:  "session-1",
		Persistent: true,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	_, err = store.ControlPersistent("revoked-cb", "revoke")
	require.NoError(t, err)

	_, _, ok := store.ResolveCallback("revoked-cb", "127.0.0.1", "agt-1")
	assert.False(t, ok, "ResolveCallback should reject revoked stagers")
}

func TestStagerStore_ListPersistent_SortsByActivityOrCreationTime(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	now := time.Now()

	require.NoError(t, store.Register(&RegisteredStager{
		ID:         "triggered-old",
		SessionID:  "session-1",
		Persistent: true,
		CreatedAt:  now.Add(-2 * time.Hour),
		CallbackAt: now.Add(-90 * time.Minute),
	}))
	require.NoError(t, store.Register(&RegisteredStager{
		ID:         "untriggered-new",
		SessionID:  "session-1",
		Persistent: true,
		CreatedAt:  now.Add(-30 * time.Minute),
	}))
	require.NoError(t, store.Register(&RegisteredStager{
		ID:         "triggered-newest",
		SessionID:  "session-1",
		Persistent: true,
		CreatedAt:  now.Add(-4 * time.Hour),
		CallbackAt: now.Add(-10 * time.Minute),
	}))

	callbacks := store.ListPersistent("session-1")
	require.Len(t, callbacks, 3)
	assert.Equal(t, "triggered-newest", callbacks[0].ID)
	assert.Equal(t, "untriggered-new", callbacks[1].ID)
	assert.Equal(t, "triggered-old", callbacks[2].ID)
}

func TestStagerStore_ListPersistent_ExcludesRevoked(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	now := time.Now()

	require.NoError(t, store.Register(&RegisteredStager{
		ID:         "active-cb",
		SessionID:  "session-1",
		Persistent: true,
		CreatedAt:  now,
	}))
	require.NoError(t, store.Register(&RegisteredStager{
		ID:         "revoked-cb",
		SessionID:  "session-1",
		Persistent: true,
		CreatedAt:  now.Add(-time.Minute),
	}))

	_, err := store.ControlPersistent("revoked-cb", "revoke")
	require.NoError(t, err)

	callbacks := store.ListPersistent("session-1")
	require.Len(t, callbacks, 1)
	assert.Equal(t, "active-cb", callbacks[0].ID)
}

func TestStagerStore_ResolveCallback_AcceptsValid(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	err := store.Register(&RegisteredStager{
		ID:        "valid-cb",
		SessionID: "session-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	stager, _, ok := store.ResolveCallback("valid-cb", "127.0.0.1", "agt-1")
	assert.True(t, ok, "ResolveCallback should accept valid stagers")
	assert.NotNil(t, stager)
	assert.Nil(t, store.Get("valid-cb"))
}

func TestStagerStore_ResolveCallback_RetainsFanoutStagerUntilBudgetExhausted(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	err := store.Register(&RegisteredStager{
		ID:           "fanout-cb",
		SessionID:    "session-1",
		ExpiresAt:    time.Now().Add(time.Hour),
		MaxCallbacks: 3,
	})
	require.NoError(t, err)

	first, _, ok := store.ResolveCallback("fanout-cb", "127.0.0.1", "agt-1")
	require.True(t, ok)
	require.NotNil(t, first)
	assert.Equal(t, 1, first.CallbackCount)
	current := store.Get("fanout-cb")
	require.NotNil(t, current)
	assert.Equal(t, 1, current.CallbackCount)

	second, _, ok := store.ResolveCallback("fanout-cb", "127.0.0.1", "agt-2")
	require.True(t, ok)
	require.NotNil(t, second)
	assert.Equal(t, 2, second.CallbackCount)
	current = store.Get("fanout-cb")
	require.NotNil(t, current)
	assert.Equal(t, 2, current.CallbackCount)

	third, _, ok := store.ResolveCallback("fanout-cb", "127.0.0.1", "agt-3")
	require.True(t, ok)
	require.NotNil(t, third)
	assert.Equal(t, 3, third.CallbackCount)
	assert.Nil(t, store.Get("fanout-cb"))
}

func TestStagerStore_ResolveCallback_InvokesDeleteHookWhenBudgetExhausted(t *testing.T) {
	config := DefaultStagerStoreConfig()
	deleted := make([]string, 0, 1)
	config.DeleteHook = func(id string) {
		deleted = append(deleted, id)
	}
	store := NewStagerStore(config)

	err := store.Register(&RegisteredStager{
		ID:           "fanout-cb",
		SessionID:    "session-1",
		ExpiresAt:    time.Now().Add(time.Hour),
		MaxCallbacks: 2,
	})
	require.NoError(t, err)

	_, _, ok := store.ResolveCallback("fanout-cb", "127.0.0.1", "agt-1")
	require.True(t, ok)
	assert.Empty(t, deleted)

	_, _, ok = store.ResolveCallback("fanout-cb", "127.0.0.1", "agt-2")
	require.True(t, ok)
	assert.Equal(t, []string{"fanout-cb"}, deleted)
}

func TestStagerStore_Register_PersistentSkipsDefaultTTL(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 15 * time.Minute
	store := NewStagerStore(config)

	stager := &RegisteredStager{
		ID:         "persistent-no-ttl",
		Persistent: true,
	}
	err := store.Register(stager)
	require.NoError(t, err)

	retrieved := store.Get("persistent-no-ttl")
	assert.True(t, retrieved.ExpiresAt.IsZero(), "persistent stagers should not get a default TTL")
}

func TestStagerStore_Cleanup_SkipsPersistent(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 10 * time.Millisecond
	store := NewStagerStore(config)

	_ = store.Register(&RegisteredStager{
		ID:         "persistent-keep",
		Persistent: true,
		ExpiresAt:  time.Now().Add(-time.Hour),
	})
	_ = store.Register(&RegisteredStager{ID: "ephemeral-remove"})

	time.Sleep(15 * time.Millisecond)
	store.cleanup()

	assert.NotNil(t, store.Get("persistent-keep"), "cleanup should skip persistent stagers")
	assert.Nil(t, store.Get("ephemeral-remove"), "cleanup should remove expired ephemeral stagers")
}

func TestStagerStore_Cleanup_InvokesDeleteHookForExpiredEphemeral(t *testing.T) {
	config := DefaultStagerStoreConfig()
	config.DefaultTTL = 10 * time.Millisecond
	deleted := make([]string, 0, 1)
	config.DeleteHook = func(id string) {
		deleted = append(deleted, id)
	}
	store := NewStagerStore(config)

	_ = store.Register(&RegisteredStager{ID: "ephemeral-remove"})

	time.Sleep(15 * time.Millisecond)
	store.cleanup()

	assert.Equal(t, []string{"ephemeral-remove"}, deleted)
}

func TestStagerStore_ConcurrentAccess(t *testing.T) {
	store := NewStagerStore(DefaultStagerStoreConfig())
	done := make(chan bool, 30)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			_ = store.Register(&RegisteredStager{ID: string(rune('a' + id))})
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = store.List()
			_ = store.Stats()
			done <- true
		}()
	}

	// Concurrent mark callbacks
	for i := 0; i < 10; i++ {
		go func(id int) {
			store.MarkCalledBack(string(rune('a'+id)), "127.0.0.1")
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 30; i++ {
		<-done
	}
}
