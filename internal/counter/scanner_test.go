// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

// =============================================================================
// NewClient Tests
// =============================================================================

func TestNewClient(t *testing.T) {
	client := NewClient("http://kitchen.example.com", "", "test-session")

	assert.Equal(t, "http://kitchen.example.com", client.KitchenURL)
	assert.NotNil(t, client.HTTPClient)
	assert.Equal(t, defaultAnalyzeHTTPTimeout, client.HTTPClient.Timeout)
}

func TestNewClient_EmptyURL(t *testing.T) {
	client := NewClient("", "", "")

	assert.Equal(t, "", client.KitchenURL)
	assert.NotNil(t, client.HTTPClient)
}

// =============================================================================
// AnalyzeRequest Tests
// =============================================================================

func TestAnalyzeRequest_JSON(t *testing.T) {
	req := AnalyzeRequest{
		Token:      "ghp_test123",
		Target:     "acme/api",
		TargetType: "repo",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded AnalyzeRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Token, decoded.Token)
	assert.Equal(t, req.Target, decoded.Target)
	assert.Equal(t, req.TargetType, decoded.TargetType)
}

// =============================================================================
// Client.Analyze Tests
// =============================================================================

func TestClient_Analyze_Success(t *testing.T) {
	var receivedReq AnalyzeRequest
	var receivedPath string
	var receivedMethod string
	var receivedContentType string

	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		receivedPath = req.URL.Path
		receivedMethod = req.Method
		receivedContentType = req.Header.Get("Content-Type")
		json.NewDecoder(req.Body).Decode(&receivedReq)

		result := poutine.AnalysisResult{
			Success:       true,
			Target:        "acme/api",
			TargetType:    "repo",
			ReposAnalyzed: 1,
			TotalFindings: 2,
			Findings: []poutine.Finding{
				{ID: "V001", Repository: "acme/api", RuleID: "injection", Severity: "critical"},
				{ID: "V002", Repository: "acme/api", RuleID: "debug_enabled", Severity: "medium"},
			},
		}
		resultJSON, _ := json.Marshal(result)
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "ghp_test", "acme/api", "repo")

	require.NoError(t, err)
	assert.Equal(t, "/analyze", receivedPath)
	assert.Equal(t, "POST", receivedMethod)
	assert.Equal(t, "application/json", receivedContentType)
	assert.Equal(t, "ghp_test", receivedReq.Token)
	assert.Equal(t, "acme/api", receivedReq.Target)
	assert.Equal(t, "repo", receivedReq.TargetType)
	assert.True(t, result.Success)
	assert.Equal(t, "acme/api", result.Target)
	assert.Equal(t, 1, result.ReposAnalyzed)
	assert.Equal(t, 2, result.TotalFindings)
	assert.Len(t, result.Findings, 2)
}

func TestClient_Analyze_OrgTarget(t *testing.T) {
	var receivedReq AnalyzeRequest

	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&receivedReq)

		result := poutine.AnalysisResult{
			Success:       true,
			Target:        "acme",
			TargetType:    "org",
			ReposAnalyzed: 5,
			TotalFindings: 10,
		}
		resultJSON, _ := json.Marshal(result)
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "ghp_test", "acme", "org")

	require.NoError(t, err)
	assert.Equal(t, "acme", receivedReq.Target)
	assert.Equal(t, "org", receivedReq.TargetType)
	assert.Equal(t, "org", result.TargetType)
	assert.Equal(t, 5, result.ReposAnalyzed)
}

func TestClient_Analyze_EmptyKitchenURL(t *testing.T) {
	client := NewClient("", "", "")

	result, err := client.Analyze(context.Background(), "token", "target", "repo")

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kitchen URL not configured")
}

func TestClient_Analyze_HTTPError(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, "internal server error"), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "target", "repo")

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kitchen returned error")
	assert.Contains(t, err.Error(), "500")
}

func TestClient_Analyze_BadRequest(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, `{"error": "invalid token"}`), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "invalid", "target", "repo")

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

func TestClient_Analyze_InvalidJSON(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, "not json"), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "target", "repo")

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestClient_Analyze_ConnectionRefused(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "target", "repo")

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send request to Kitchen")
}

func TestClient_Analyze_ContextCanceled(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := client.Analyze(ctx, "token", "target", "repo")

	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestClient_Analyze_EmptyResponse(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, "{}"), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "target", "repo")

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Empty(t, result.Findings)
}

func TestClient_Analyze_WithErrors(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		result := poutine.AnalysisResult{
			Success:       false,
			Target:        "acme/api",
			ReposAnalyzed: 1,
			Errors:        []string{"rate limited", "timeout on repo X"},
		}
		resultJSON, _ := json.Marshal(result)
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "acme/api", "repo")

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Len(t, result.Errors, 2)
	assert.Contains(t, result.Errors[0], "rate limited")
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestClient_Analyze_LargeResponse(t *testing.T) {
	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		result := poutine.AnalysisResult{
			Success:       true,
			ReposAnalyzed: 100,
			TotalFindings: 500,
		}
		for i := 0; i < 500; i++ {
			result.Findings = append(result.Findings, poutine.Finding{
				ID:       "V" + string(rune('0'+i%10)),
				RuleID:   "injection",
				Severity: "high",
			})
		}
		resultJSON, _ := json.Marshal(result)
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "acme", "org")

	require.NoError(t, err)
	assert.Len(t, result.Findings, 500)
}

func TestNewClient_SessionID_Sent(t *testing.T) {
	var receivedReq AnalyzeRequest

	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&receivedReq)
		resultJSON, _ := json.Marshal(poutine.AnalysisResult{Success: true})
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "auth-token", "sess-abc123")
	client.HTTPClient = mockClient
	_, err := client.Analyze(context.Background(), "ghp_test", "whooli", "org")

	require.NoError(t, err)
	assert.Equal(t, "sess-abc123", receivedReq.SessionID, "NewClient must send session_id — Kitchen needs it for recordAnalyzedRepoVisibility")
}

func TestClient_AnalyzeWithID_SendsAnalysisID(t *testing.T) {
	var receivedReq AnalyzeRequest

	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&receivedReq)
		resultJSON, _ := json.Marshal(poutine.AnalysisResult{Success: true})
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "auth-token", "sess-abc123")
	client.HTTPClient = mockClient
	_, err := client.AnalyzeWithID(context.Background(), "ghp_test", "whooli", "org", "analysis_123")

	require.NoError(t, err)
	assert.Equal(t, "analysis_123", receivedReq.AnalysisID)
}

func TestClient_FetchAnalysisResult_SendsSessionID(t *testing.T) {
	var receivedPath string
	var receivedQuery string

	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		receivedPath = req.URL.Path
		receivedQuery = req.URL.RawQuery
		payload, _ := json.Marshal(AnalyzeResultStatusResponse{
			AnalysisID: "analysis_123",
			Status:     "pending",
		})
		return jsonResponse(http.StatusOK, string(payload)), nil
	})

	client := NewClient("http://test.local", "auth-token", "sess-abc123")
	client.HTTPClient = mockClient
	result, err := client.FetchAnalysisResult(context.Background(), "analysis_123")

	require.NoError(t, err)
	assert.Equal(t, "/analyze/result/analysis_123", receivedPath)
	assert.Equal(t, "session_id=sess-abc123", receivedQuery)
	assert.Equal(t, "pending", result.Status)
}

func TestClient_Analyze_SpecialCharactersInTarget(t *testing.T) {
	var receivedReq AnalyzeRequest

	mockClient := newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		json.NewDecoder(req.Body).Decode(&receivedReq)
		resultJSON, _ := json.Marshal(poutine.AnalysisResult{Success: true})
		return jsonResponse(http.StatusOK, string(resultJSON)), nil
	})

	client := NewClient("http://test.local", "", "test-session")
	client.HTTPClient = mockClient
	result, err := client.Analyze(context.Background(), "token", "my-org/my-repo.js", "repo")

	require.NoError(t, err)
	assert.Equal(t, "my-org/my-repo.js", receivedReq.Target)
	assert.True(t, result.Success)
}
