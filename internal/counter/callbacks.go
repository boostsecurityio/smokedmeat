// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"context"
	"net/url"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

type RegisterCallbackRequest struct {
	ResponseType string            `json:"response_type"`
	Payload      string            `json:"payload"`
	SessionID    string            `json:"session_id"`
	TTLSeconds   int               `json:"ttl_seconds"`
	Metadata     map[string]string `json:"metadata"`
	DwellTime    string            `json:"dwell_time"`
	Persistent   bool              `json:"persistent,omitempty"`
	MaxCallbacks int               `json:"max_callbacks,omitempty"`
	DefaultMode  string            `json:"default_mode,omitempty"`
}

type RegisterCallbackResponse struct {
	Status      string           `json:"status,omitempty"`
	StagerID    string           `json:"stager_id,omitempty"`
	CallbackURL string           `json:"callback_url,omitempty"`
	Callback    *CallbackPayload `json:"callback,omitempty"`
}

func (k *KitchenClient) RegisterCallback(ctx context.Context, stagerID string, req RegisterCallbackRequest) (*RegisterCallbackResponse, error) {
	var resp RegisterCallbackResponse
	err := k.doPostJSON(ctx, stagerurl.Path(url.PathEscape(stagerID)), req, &resp, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
