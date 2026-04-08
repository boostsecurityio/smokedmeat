// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"context"
	"time"
)

type PurgeRequest struct {
	SessionID  string `json:"session_id"`
	ScopeType  string `json:"scope_type"`
	ScopeValue string `json:"scope_value"`
	DryRun     bool   `json:"dry_run"`
}

type PurgeResponse struct {
	Status        string `json:"status"`
	SessionID     string `json:"session_id,omitempty"`
	ScopeType     string `json:"scope_type"`
	ScopeValue    string `json:"scope_value"`
	DryRun        bool   `json:"dry_run"`
	PantryAssets  int    `json:"pantry_assets"`
	KnownEntities int    `json:"known_entities"`
}

func (k *KitchenClient) Purge(ctx context.Context, req PurgeRequest) (*PurgeResponse, error) {
	var resp PurgeResponse
	err := k.doPostJSON(ctx, "/purge", req, &resp, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
