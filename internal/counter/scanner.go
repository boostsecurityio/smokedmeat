// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package counter implements the Counter operator interface components.
package counter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

const defaultAnalyzeHTTPTimeout = 2 * time.Hour

// Client is a thin client for interacting with Kitchen's analysis endpoints.
// Counter delegates all heavy lifting (poutine analysis) to Kitchen.
type Client struct {
	KitchenURL string
	AuthToken  string
	SessionID  string
	HTTPClient *http.Client
}

// NewClient creates a new Kitchen client. SessionID is required —
// Kitchen uses it to track known entities and repo visibility.
func NewClient(kitchenURL, authToken, sessionID string) *Client {
	return &Client{
		KitchenURL: kitchenURL,
		AuthToken:  authToken,
		SessionID:  sessionID,
		HTTPClient: &http.Client{
			Timeout: defaultAnalyzeHTTPTimeout,
		},
	}
}

// AnalyzeRequest is the request body for the /analyze endpoint.
type AnalyzeRequest struct {
	// Token is the GitHub token for API access.
	// SECURITY: This is the OPERATOR's token, used ephemerally by Kitchen.
	// It is NOT stored as loot.
	Token string `json:"token"`

	// Target is the org or org/repo to analyze.
	Target string `json:"target"`

	// TargetType is "org" or "repo".
	TargetType string `json:"target_type"`

	// Deep enables gitleaks scanning for private keys.
	Deep bool `json:"deep,omitempty"`

	// SessionID identifies the operator session (for known entity lookups).
	SessionID string `json:"session_id,omitempty"`

	AnalysisID string `json:"analysis_id,omitempty"`
}

type AnalyzeResultStatusResponse struct {
	AnalysisID string                  `json:"analysis_id"`
	Status     string                  `json:"status"`
	Result     *poutine.AnalysisResult `json:"result,omitempty"`
	Error      string                  `json:"error,omitempty"`
}

// Analyze performs a poutine analysis by delegating to Kitchen.
// The token is sent to Kitchen for ephemeral use - it is never stored.
func (c *Client) Analyze(ctx context.Context, token, target, targetType string) (*poutine.AnalysisResult, error) {
	return c.analyze(ctx, token, target, targetType, false, "")
}

func (c *Client) AnalyzeWithID(ctx context.Context, token, target, targetType, analysisID string) (*poutine.AnalysisResult, error) {
	return c.analyze(ctx, token, target, targetType, false, analysisID)
}

// DeepAnalyze performs poutine analysis plus gitleaks secret scanning.
func (c *Client) DeepAnalyze(ctx context.Context, token, target, targetType string) (*poutine.AnalysisResult, error) {
	return c.analyze(ctx, token, target, targetType, true, "")
}

func (c *Client) DeepAnalyzeWithID(ctx context.Context, token, target, targetType, analysisID string) (*poutine.AnalysisResult, error) {
	return c.analyze(ctx, token, target, targetType, true, analysisID)
}

func (c *Client) FetchAnalysisResult(ctx context.Context, analysisID string) (*AnalyzeResultStatusResponse, error) {
	if c.KitchenURL == "" {
		return nil, fmt.Errorf("kitchen URL not configured")
	}

	endpoint := fmt.Sprintf("%s/analyze/result/%s", c.KitchenURL, url.PathEscape(analysisID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if c.SessionID != "" {
		q := req.URL.Query()
		q.Set("session_id", c.SessionID)
		req.URL.RawQuery = q.Encode()
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch analysis result from Kitchen: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kitchen returned error: %s - %s", resp.Status, string(body))
	}

	var result AnalyzeResultStatusResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

func (c *Client) analyze(ctx context.Context, token, target, targetType string, deep bool, analysisID string) (*poutine.AnalysisResult, error) {
	if c.KitchenURL == "" {
		return nil, fmt.Errorf("kitchen URL not configured")
	}

	reqBody := AnalyzeRequest{
		Token:      token,
		Target:     target,
		TargetType: targetType,
		Deep:       deep,
		SessionID:  c.SessionID,
		AnalysisID: analysisID,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/analyze", c.KitchenURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Kitchen: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kitchen returned error: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var result poutine.AnalysisResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}
