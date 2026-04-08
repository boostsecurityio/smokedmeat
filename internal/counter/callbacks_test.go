// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKitchenClient_RegisterCallback_SendsRequest(t *testing.T) {
	var gotAuth string
	var gotPath string
	var gotBody RegisterCallbackRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, json.NewEncoder(w).Encode(RegisterCallbackResponse{
			Status:      "registered",
			StagerID:    "stg-1",
			CallbackURL: "https://kitchen.example/r/stg-1",
			Callback: &CallbackPayload{
				ID:           "stg-1",
				SessionID:    "sess-1",
				ResponseType: "bash",
				Persistent:   false,
				DefaultMode:  "express",
			},
		}))
	}))
	defer srv.Close()

	client := NewKitchenClient(KitchenConfig{
		URL:       srv.URL,
		SessionID: "sess-1",
		Token:     "jwt-secret",
	})
	resp, err := client.RegisterCallback(t.Context(), "stg-1", RegisterCallbackRequest{
		ResponseType: "bash",
		Payload:      "payload",
		SessionID:    "sess-1",
		DwellTime:    "30s",
		Persistent:   false,
		MaxCallbacks: 4,
		DefaultMode:  "express",
		Metadata:     map[string]string{"repository": "acme/api"},
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Callback)
	assert.Equal(t, "Bearer jwt-secret", gotAuth)
	assert.Equal(t, "/r/stg-1", gotPath)
	assert.Equal(t, "payload", gotBody.Payload)
	assert.Equal(t, "30s", gotBody.DwellTime)
	assert.False(t, gotBody.Persistent)
	assert.Equal(t, 4, gotBody.MaxCallbacks)
	assert.Equal(t, "express", gotBody.DefaultMode)
	assert.Equal(t, "acme/api", gotBody.Metadata["repository"])
	assert.Equal(t, "stg-1", resp.Callback.ID)
}

func TestKitchenClient_RegisterCallback_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "unexpected status: 500"}))
	}))
	defer srv.Close()

	client := NewKitchenClient(KitchenConfig{URL: srv.URL})
	resp, err := client.RegisterCallback(t.Context(), "stg-err", RegisterCallbackRequest{SessionID: "sess-1"})

	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status: 500")
}
