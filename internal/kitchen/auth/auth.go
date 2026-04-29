// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth provides SSH challenge-response authentication for Kitchen operators.
// Operators register SSH public keys (like authorized_keys), then prove identity
// by signing a random challenge with their private key (via SSH agent).
package auth

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrInvalidToken indicates the session token is invalid or expired.
	ErrInvalidToken = errors.New("invalid or expired token")

	// ErrOperatorNotFound indicates the operator is not in authorized_keys.
	ErrOperatorNotFound = errors.New("operator not found")

	// ErrInvalidChallenge indicates the challenge is invalid or expired.
	ErrInvalidChallenge = errors.New("invalid or expired challenge")

	// ErrInvalidSignature indicates the signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrKeyMismatch indicates the public key fingerprint doesn't match.
	ErrKeyMismatch = errors.New("public key fingerprint mismatch")

	// ErrInvalidAgentToken indicates the agent token is invalid or expired.
	ErrInvalidAgentToken = errors.New("invalid or expired agent token")

	errNotRegularFile = errors.New("authorized_keys path is not a regular file")
)

const (
	// PrefixAgent is the prefix for agent tokens.
	PrefixAgent = "agt_"
	// PrefixStager is the prefix for stager IDs.
	PrefixStager = "stg_"
	// idCharset is the alphanumeric charset for ID generation (62 chars, ~5.95 bits/char).
	idCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// idLength is the number of random chars to generate (~65 bits of entropy).
	idLength = 11
)

// Operator represents an authorized operator with their SSH public key.
type Operator struct {
	Name        string
	PublicKey   ssh.PublicKey
	Fingerprint string // SHA256 fingerprint
	Comment     string
}

// Challenge represents a pending authentication challenge.
type Challenge struct {
	Nonce       []byte
	OperatorID  string
	Fingerprint string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Token represents an active session token.
type Token struct {
	Value      string
	OperatorID string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Claims represents the authenticated operator context.
// Compatible with existing middleware.
type Claims struct {
	OperatorID string `json:"operator_id"`
	SessionID  string `json:"session_id,omitempty"`
}

// AgentToken represents an active agent authentication token.
type AgentToken struct {
	Token     string
	AgentID   string
	SessionID string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AgentClaims represents the authenticated agent context.
type AgentClaims struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
}

// Auth manages operator authentication via SSH challenge-response or static token.
type Auth struct {
	mu               sync.RWMutex
	operators        map[string]*Operator   // keyed by name
	byFingerprint    map[string]*Operator   // keyed by SHA256 fingerprint
	challenges       map[string]*Challenge  // keyed by base64(nonce)
	tokens           map[string]*Token      // keyed by token value
	agentTokens      map[string]*AgentToken // keyed by token value
	tokenExpiry      time.Duration
	agentTokenExpiry time.Duration
	challengeExpiry  time.Duration
	keysPath         string
	stopReload       chan struct{}
	staticToken      string // shared secret for quickstart/E2E mode
}

// Config holds authentication configuration.
type Config struct {
	// AuthorizedKeysPath is the path to the authorized_keys file.
	// Format: <operator_name> <key_type> <public_key> <comment>
	AuthorizedKeysPath string

	// AuthorizedKeysData is the raw authorized_keys content (alternative to path).
	AuthorizedKeysData string

	// StaticToken is an optional shared secret token for quickstart/E2E mode.
	// When set, operators can authenticate with this token directly via Bearer auth.
	// Must be 64 hex characters (256 bits of entropy).
	StaticToken string

	// TokenExpiry is how long operator session tokens are valid. Default: 24 hours.
	TokenExpiry time.Duration

	// AgentTokenExpiry is how long agent tokens are valid. Default: 24 hours.
	AgentTokenExpiry time.Duration

	// ChallengeExpiry is how long challenges are valid. Default: 5 minutes.
	ChallengeExpiry time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		TokenExpiry:      3 * time.Hour,
		AgentTokenExpiry: 24 * time.Hour,
		ChallengeExpiry:  5 * time.Minute,
	}
}

// New creates a new Auth instance.
func New(config Config) (*Auth, error) {
	if config.TokenExpiry == 0 {
		config.TokenExpiry = 3 * time.Hour
	}
	if config.AgentTokenExpiry == 0 {
		config.AgentTokenExpiry = 24 * time.Hour
	}
	if config.ChallengeExpiry == 0 {
		config.ChallengeExpiry = 5 * time.Minute
	}

	a := &Auth{
		operators:        make(map[string]*Operator),
		byFingerprint:    make(map[string]*Operator),
		challenges:       make(map[string]*Challenge),
		tokens:           make(map[string]*Token),
		agentTokens:      make(map[string]*AgentToken),
		tokenExpiry:      config.TokenExpiry,
		agentTokenExpiry: config.AgentTokenExpiry,
		challengeExpiry:  config.ChallengeExpiry,
		keysPath:         config.AuthorizedKeysPath,
		stopReload:       make(chan struct{}),
		staticToken:      config.StaticToken,
	}

	// Load authorized keys
	if config.AuthorizedKeysPath != "" {
		if err := a.LoadAuthorizedKeysFile(config.AuthorizedKeysPath); err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errNotRegularFile) {
				return nil, err
			}
			slog.Warn("authorized_keys file not found, will poll until it appears", "path", config.AuthorizedKeysPath)
		}
		a.StartAutoReload(10 * time.Second)
	} else if config.AuthorizedKeysData != "" {
		if err := a.LoadAuthorizedKeys(strings.NewReader(config.AuthorizedKeysData)); err != nil {
			return nil, err
		}
	}

	return a, nil
}

// LoadAuthorizedKeysFile loads operators from an authorized_keys file.
func (a *Auth) LoadAuthorizedKeysFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
		return fmt.Errorf("failed to stat authorized_keys: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errNotRegularFile
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	defer f.Close()

	return a.LoadAuthorizedKeys(f)
}

// LoadAuthorizedKeys loads operators from a reader.
// Format: <operator_name> <key_type> <public_key> <comment>
// Example: alice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop
func (a *Auth) LoadAuthorizedKeys(r io.Reader) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: <operator_name> <key_type> <public_key> [comment]
		parts := strings.Fields(line)
		if len(parts) < 3 {
			slog.Warn("invalid authorized_keys line", "line", lineNum, "content", line)
			continue
		}

		operatorName := parts[0]
		keyData := strings.Join(parts[1:], " ")

		// Parse the SSH public key
		pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyData))
		if err != nil {
			slog.Warn("failed to parse SSH key", "line", lineNum, "operator", operatorName, "error", err)
			continue
		}

		// Calculate fingerprint
		fingerprint := ssh.FingerprintSHA256(pubKey)

		op := &Operator{
			Name:        operatorName,
			PublicKey:   pubKey,
			Fingerprint: fingerprint,
			Comment:     comment,
		}

		a.operators[operatorName] = op
		a.byFingerprint[fingerprint] = op

		slog.Info("loaded operator", "name", operatorName, "fingerprint", fingerprint)
	}

	return scanner.Err()
}

// CreateChallenge creates a new authentication challenge for an operator.
func (a *Auth) CreateChallenge(operatorID, fingerprint string) ([]byte, error) {
	// Verify operator exists and fingerprint matches
	a.mu.RLock()
	op, ok := a.operators[operatorID]
	a.mu.RUnlock()

	if !ok {
		return nil, ErrOperatorNotFound
	}

	if op.Fingerprint != fingerprint {
		return nil, ErrKeyMismatch
	}

	// Generate random nonce (32 bytes)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	now := time.Now()
	challenge := &Challenge{
		Nonce:       nonce,
		OperatorID:  operatorID,
		Fingerprint: fingerprint,
		CreatedAt:   now,
		ExpiresAt:   now.Add(a.challengeExpiry),
	}

	// Store challenge keyed by base64 nonce
	nonceKey := base64.StdEncoding.EncodeToString(nonce)

	a.mu.Lock()
	a.challenges[nonceKey] = challenge
	a.mu.Unlock()

	slog.Debug("created challenge", "operator", operatorID, "fingerprint", fingerprint)

	return nonce, nil
}

// VerifyChallenge verifies a signed challenge and returns a session token.
func (a *Auth) VerifyChallenge(nonce, signature []byte) (string, error) {
	nonceKey := base64.StdEncoding.EncodeToString(nonce)

	a.mu.Lock()
	challenge, ok := a.challenges[nonceKey]
	if !ok {
		a.mu.Unlock()
		return "", ErrInvalidChallenge
	}

	// Remove challenge (one-time use)
	delete(a.challenges, nonceKey)
	a.mu.Unlock()

	// Check expiry
	if time.Now().After(challenge.ExpiresAt) {
		return "", ErrInvalidChallenge
	}

	// Get operator's public key
	a.mu.RLock()
	op, ok := a.operators[challenge.OperatorID]
	a.mu.RUnlock()

	if !ok {
		return "", ErrOperatorNotFound
	}

	// Parse the SSH signature. Standard SSH agents return signatures in wire format
	// (type string + blob), but some clients may return raw signature bytes.
	// We try wire format first, then fall back to raw blob with inferred type.
	sig := &ssh.Signature{}
	if err := ssh.Unmarshal(signature, sig); err != nil {
		sig = &ssh.Signature{
			Format: op.PublicKey.Type(),
			Blob:   signature,
		}
	}

	// Verify the signature
	if err := op.PublicKey.Verify(nonce, sig); err != nil {
		slog.Debug("signature verification failed", "operator", challenge.OperatorID, "error", err)
		return "", ErrInvalidSignature
	}

	// Generate session token
	token, err := a.generateToken(challenge.OperatorID)
	if err != nil {
		return "", err
	}

	slog.Info("operator authenticated", "operator", challenge.OperatorID)

	return token, nil
}

// generateToken creates a new session token.
func (a *Auth) generateToken(operatorID string) (string, error) {
	// Generate random token: smk_<32 random hex chars>
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	tokenValue := "smk_" + hex.EncodeToString(tokenBytes)

	now := time.Now()
	token := &Token{
		Value:      tokenValue,
		OperatorID: operatorID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(a.tokenExpiry),
	}

	a.mu.Lock()
	a.tokens[tokenValue] = token
	a.mu.Unlock()

	return tokenValue, nil
}

// ValidateToken validates a session token and returns claims.
// Accepts either a dynamic session token (smk_...) or a static shared secret.
func (a *Auth) ValidateToken(tokenValue string) (*Claims, error) {
	if a.staticToken != "" && tokenValue == a.staticToken {
		return &Claims{
			OperatorID: "quickstart",
		}, nil
	}

	a.mu.RLock()
	token, ok := a.tokens[tokenValue]
	a.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidToken
	}

	if time.Now().After(token.ExpiresAt) {
		a.mu.Lock()
		delete(a.tokens, tokenValue)
		a.mu.Unlock()
		return nil, ErrInvalidToken
	}

	return &Claims{
		OperatorID: token.OperatorID,
	}, nil
}

// GenerateSecureID generates a secure random ID with the given prefix.
// Format: prefix + 11 alphanumeric chars (~65 bits of entropy).
func GenerateSecureID(prefix string) (string, error) {
	b := make([]byte, idLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	result := make([]byte, idLength)
	for i := range b {
		result[i] = idCharset[int(b[i])%len(idCharset)]
	}

	return prefix + string(result), nil
}

// GenerateAgentToken creates a new agent authentication token.
func (a *Auth) GenerateAgentToken(agentID, sessionID string) (string, error) {
	token, err := GenerateSecureID(PrefixAgent)
	if err != nil {
		return "", err
	}

	now := time.Now()
	agentToken := &AgentToken{
		Token:     token,
		AgentID:   agentID,
		SessionID: sessionID,
		CreatedAt: now,
		ExpiresAt: now.Add(a.agentTokenExpiry),
	}

	a.mu.Lock()
	a.agentTokens[token] = agentToken
	a.mu.Unlock()

	slog.Debug("generated agent token", "agent_id", agentID, "session_id", sessionID)

	return token, nil
}

func (a *Auth) AgentTokenExpiry() time.Duration {
	return a.agentTokenExpiry
}

func (a *Auth) RestoreAgentToken(token, agentID, sessionID string, createdAt, expiresAt time.Time) bool {
	if token == "" || agentID == "" || sessionID == "" {
		return false
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return false
	}
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	if expiresAt.IsZero() {
		expiresAt = createdAt.Add(a.agentTokenExpiry)
	}

	a.mu.Lock()
	a.agentTokens[token] = &AgentToken{
		Token:     token,
		AgentID:   agentID,
		SessionID: sessionID,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	a.mu.Unlock()
	return true
}

// ValidateAgentToken validates an agent token and returns claims.
func (a *Auth) ValidateAgentToken(token string) (*AgentClaims, error) {
	a.mu.RLock()
	agentToken, ok := a.agentTokens[token]
	a.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidAgentToken
	}

	if time.Now().After(agentToken.ExpiresAt) {
		a.mu.Lock()
		delete(a.agentTokens, token)
		a.mu.Unlock()
		return nil, ErrInvalidAgentToken
	}

	return &AgentClaims{
		AgentID:   agentToken.AgentID,
		SessionID: agentToken.SessionID,
	}, nil
}

// ListOperators returns all registered operators.
func (a *Auth) ListOperators() []*Operator {
	a.mu.RLock()
	defer a.mu.RUnlock()

	operators := make([]*Operator, 0, len(a.operators))
	for _, op := range a.operators {
		operators = append(operators, op)
	}
	return operators
}

// GetOperator returns an operator by name.
func (a *Auth) GetOperator(name string) (*Operator, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	op, ok := a.operators[name]
	if !ok {
		return nil, ErrOperatorNotFound
	}
	return op, nil
}

// GetOperatorByFingerprint returns an operator by their public key fingerprint.
func (a *Auth) GetOperatorByFingerprint(fingerprint string) (*Operator, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	op, ok := a.byFingerprint[fingerprint]
	if !ok {
		return nil, ErrOperatorNotFound
	}
	return op, nil
}

// AddOperator adds a new operator with the given name and public key.
func (a *Auth) AddOperator(name string, publicKey []byte) error {
	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)
	op := &Operator{
		Name:        name,
		PublicKey:   pubKey,
		Fingerprint: fingerprint,
		Comment:     comment,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.operators[name] = op
	a.byFingerprint[fingerprint] = op
	return nil
}

// GenerateToken generates a session token for an operator (for testing).
func (a *Auth) GenerateToken(operatorID, sessionID string) (string, error) {
	return a.generateToken(operatorID)
}

// RevokeToken revokes a session token.
func (a *Auth) RevokeToken(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.tokens[token]; ok {
		delete(a.tokens, token)
		return true
	}
	return false
}

// RevokeAgentToken revokes an agent token.
func (a *Auth) RevokeAgentToken(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.agentTokens[token]; ok {
		delete(a.agentTokens, token)
		return true
	}
	return false
}

// CleanupExpired removes expired challenges, tokens, and agent tokens.
func (a *Auth) CleanupExpired() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	count := 0

	for k, c := range a.challenges {
		if now.After(c.ExpiresAt) {
			delete(a.challenges, k)
			count++
		}
	}

	for k, t := range a.tokens {
		if now.After(t.ExpiresAt) {
			delete(a.tokens, k)
			count++
		}
	}

	for k, t := range a.agentTokens {
		if now.After(t.ExpiresAt) {
			delete(a.agentTokens, k)
			count++
		}
	}

	return count
}

// StopAutoReload stops the auto-reload goroutine.
func (a *Auth) StopAutoReload() {
	select {
	case <-a.stopReload:
	default:
		close(a.stopReload)
	}
}

// StartAutoReload starts a goroutine that reloads authorized_keys periodically.
// Polls at fastInterval when no operators are loaded, then switches to interval.
func (a *Auth) StartAutoReload(interval time.Duration) {
	if a.keysPath == "" {
		return
	}

	fastInterval := 5 * time.Second

	go func() {
		ticker := time.NewTicker(fastInterval)
		defer ticker.Stop()
		fast := true

		for {
			select {
			case <-ticker.C:
				if err := a.ReloadAuthorizedKeys(); err != nil {
					slog.Warn("failed to reload authorized_keys", "error", err)
				}
				a.mu.RLock()
				hasOperators := len(a.operators) > 0
				a.mu.RUnlock()
				if hasOperators && fast {
					fast = false
					ticker.Reset(interval)
				} else if !hasOperators && !fast {
					fast = true
					ticker.Reset(fastInterval)
				}
			case <-a.stopReload:
				return
			}
		}
	}()
}

// ReloadAuthorizedKeys reloads operators from the authorized_keys file.
func (a *Auth) ReloadAuthorizedKeys() error {
	if a.keysPath == "" {
		return nil
	}

	info, err := os.Stat(a.keysPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to stat authorized_keys: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil
	}

	f, err := os.Open(a.keysPath)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	defer f.Close()

	newOps := make(map[string]*Operator)
	newByFP := make(map[string]*Operator)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		operatorName := parts[0]
		keyData := strings.Join(parts[1:], " ")

		pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyData))
		if err != nil {
			continue
		}

		fingerprint := ssh.FingerprintSHA256(pubKey)
		op := &Operator{
			Name:        operatorName,
			PublicKey:   pubKey,
			Fingerprint: fingerprint,
			Comment:     comment,
		}

		newOps[operatorName] = op
		newByFP[fingerprint] = op
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Log new operators
	for name, op := range newOps {
		if _, exists := a.operators[name]; !exists {
			slog.Info("operator loaded", "name", name, "fingerprint", op.Fingerprint)
		}
	}

	// Log removed operators
	for name := range a.operators {
		if _, exists := newOps[name]; !exists {
			slog.Info("operator removed", "name", name)
		}
	}

	a.operators = newOps
	a.byFingerprint = newByFP

	return nil
}
