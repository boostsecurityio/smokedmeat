// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// generateTestKey generates a test ed25519 key pair and returns the public key in authorized_keys format.
func generateTestKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	pubKey, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	// Format as authorized_keys line (without operator name prefix)
	authorizedKey := ssh.MarshalAuthorizedKey(pubKey)

	return signer, authorizedKey
}

func TestNew(t *testing.T) {
	auth, err := New(DefaultConfig())
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestLoadAuthorizedKeys(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	_ = signer

	// Create authorized_keys content
	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + " alice@laptop\n" +
		"# This is a comment\n" +
		"bob ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + " bob@desktop\n"

	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	// Should have loaded alice
	op, err := auth.GetOperator("alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", op.Name)
	assert.NotEmpty(t, op.Fingerprint)

	// Should have loaded bob
	op, err = auth.GetOperator("bob")
	require.NoError(t, err)
	assert.Equal(t, "bob", op.Name)
}

func TestChallengeResponse(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	// Create auth with test operator
	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	// Create challenge
	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)
	assert.Len(t, nonce, 32)

	// Sign the nonce with private key
	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)

	// Marshal signature to wire format
	sigBytes := ssh.Marshal(sig)

	// Verify and get token
	token, err := auth.VerifyChallenge(nonce, sigBytes)
	require.NoError(t, err)
	assert.True(t, len(token) > 4)
	assert.Equal(t, "smk_", token[:4])
}

func TestChallengeOperatorNotFound(t *testing.T) {
	auth, err := New(DefaultConfig())
	require.NoError(t, err)

	_, err = auth.CreateChallenge("unknown", "SHA256:abc123")
	assert.ErrorIs(t, err, ErrOperatorNotFound)
}

func TestChallengeFingerprintMismatch(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	_ = signer

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	// Wrong fingerprint
	_, err = auth.CreateChallenge("alice", "SHA256:wrongfingerprint")
	assert.ErrorIs(t, err, ErrKeyMismatch)
}

func TestChallengeOneTimeUse(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	// Create and use challenge
	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	// First verification should succeed
	_, err = auth.VerifyChallenge(nonce, sigBytes)
	require.NoError(t, err)

	// Second verification should fail (challenge already used)
	_, err = auth.VerifyChallenge(nonce, sigBytes)
	assert.ErrorIs(t, err, ErrInvalidChallenge)
}

func TestExpiredChallenge(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
		ChallengeExpiry:    time.Nanosecond, // Expires immediately
	})
	require.NoError(t, err)

	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	_, err = auth.VerifyChallenge(nonce, sigBytes)
	assert.ErrorIs(t, err, ErrInvalidChallenge)
}

func TestInvalidSignature(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	// Generate a different key to sign with (wrong key)
	wrongSigner, _ := generateTestKey(t)

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	// Sign with wrong key
	sig, err := wrongSigner.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	_, err = auth.VerifyChallenge(nonce, sigBytes)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestTokenValidation(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	// Authenticate
	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	token, err := auth.VerifyChallenge(nonce, sigBytes)
	require.NoError(t, err)

	// Validate token
	claims, err := auth.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.OperatorID)
}

func TestInvalidToken(t *testing.T) {
	auth, err := New(DefaultConfig())
	require.NoError(t, err)

	_, err = auth.ValidateToken("smk_invalid_token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestExpiredToken(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
		TokenExpiry:        time.Nanosecond, // Expires immediately
	})
	require.NoError(t, err)

	// Authenticate
	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	token, err := auth.VerifyChallenge(nonce, sigBytes)
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	_, err = auth.ValidateToken(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRevokeToken(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	// Authenticate
	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	token, err := auth.VerifyChallenge(nonce, sigBytes)
	require.NoError(t, err)

	// Revoke
	revoked := auth.RevokeToken(token)
	assert.True(t, revoked)

	// Should now be invalid
	_, err = auth.ValidateToken(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestAddOperator(t *testing.T) {
	auth, err := New(DefaultConfig())
	require.NoError(t, err)

	_, pubKey := generateTestKey(t)

	// Add operator
	err = auth.AddOperator("charlie", []byte("ssh-ed25519 "+string(pubKey[:len(pubKey)-1])))
	require.NoError(t, err)

	// Should be retrievable
	op, err := auth.GetOperator("charlie")
	require.NoError(t, err)
	assert.Equal(t, "charlie", op.Name)
}

func TestListOperators(t *testing.T) {
	_, pubKey := generateTestKey(t)

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n" +
		"bob ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"

	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	operators := auth.ListOperators()
	assert.Len(t, operators, 2)
}

func TestCleanupExpired(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
		ChallengeExpiry:    time.Nanosecond,
		TokenExpiry:        time.Nanosecond,
	})
	require.NoError(t, err)

	// Create expired challenge
	_, err = auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	// Generate expired token
	_, err = auth.GenerateToken("alice", "")
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	// Cleanup should remove both
	count := auth.CleanupExpired()
	assert.Equal(t, 2, count)
}

func TestGetOperatorByFingerprint(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	auth, err := New(Config{
		AuthorizedKeysData: keysData,
	})
	require.NoError(t, err)

	op, err := auth.GetOperatorByFingerprint(fingerprint)
	require.NoError(t, err)
	assert.Equal(t, "alice", op.Name)
}

func TestLoadAuthorizedKeysFile(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	_ = signer

	dir := t.TempDir()
	keysPath := dir + "/authorized_keys"
	content := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + " alice@laptop\n"
	require.NoError(t, os.WriteFile(keysPath, []byte(content), 0600))

	a, err := New(Config{AuthorizedKeysPath: keysPath})
	require.NoError(t, err)
	t.Cleanup(func() { a.StopAutoReload() })

	op, err := a.GetOperator("alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", op.Name)
}

func TestLoadAuthorizedKeysFile_NotFound(t *testing.T) {
	a, err := New(Config{AuthorizedKeysPath: "/tmp/claude/nonexistent_keys_file"})
	require.NoError(t, err)
	t.Cleanup(func() { a.StopAutoReload() })

	ops := a.ListOperators()
	assert.Empty(t, ops)
}

func TestLoadAuthorizedKeysFile_NotRegularFile(t *testing.T) {
	dir := t.TempDir()

	a := &Auth{
		operators:     make(map[string]*Operator),
		byFingerprint: make(map[string]*Operator),
		challenges:    make(map[string]*Challenge),
		tokens:        make(map[string]*Token),
		agentTokens:   make(map[string]*AgentToken),
		stopReload:    make(chan struct{}),
	}

	err := a.LoadAuthorizedKeysFile(dir)
	assert.ErrorIs(t, err, errNotRegularFile)
}

func TestReloadAuthorizedKeys(t *testing.T) {
	signer1, pubKey1 := generateTestKey(t)
	_ = signer1
	_, pubKey2 := generateTestKey(t)

	dir := t.TempDir()
	keysPath := dir + "/authorized_keys"

	content1 := "alice ssh-ed25519 " + string(pubKey1[:len(pubKey1)-1]) + "\n"
	require.NoError(t, os.WriteFile(keysPath, []byte(content1), 0600))

	a, err := New(Config{AuthorizedKeysPath: keysPath})
	require.NoError(t, err)
	t.Cleanup(func() { a.StopAutoReload() })

	ops := a.ListOperators()
	require.Len(t, ops, 1)
	assert.Equal(t, "alice", ops[0].Name)

	content2 := "bob ssh-ed25519 " + string(pubKey2[:len(pubKey2)-1]) + "\n"
	require.NoError(t, os.WriteFile(keysPath, []byte(content2), 0600))

	err = a.ReloadAuthorizedKeys()
	require.NoError(t, err)

	_, err = a.GetOperator("alice")
	assert.ErrorIs(t, err, ErrOperatorNotFound)

	op, err := a.GetOperator("bob")
	require.NoError(t, err)
	assert.Equal(t, "bob", op.Name)
}

func TestReloadAuthorizedKeys_NoPath(t *testing.T) {
	a := &Auth{
		operators:     make(map[string]*Operator),
		byFingerprint: make(map[string]*Operator),
		stopReload:    make(chan struct{}),
	}

	err := a.ReloadAuthorizedKeys()
	assert.NoError(t, err)
}

func TestReloadAuthorizedKeys_FileDeleted(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	_ = signer

	dir := t.TempDir()
	keysPath := dir + "/authorized_keys"
	content := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	require.NoError(t, os.WriteFile(keysPath, []byte(content), 0600))

	a, err := New(Config{AuthorizedKeysPath: keysPath})
	require.NoError(t, err)
	t.Cleanup(func() { a.StopAutoReload() })

	require.NoError(t, os.Remove(keysPath))

	err = a.ReloadAuthorizedKeys()
	assert.NoError(t, err)
}

func TestStartStopAutoReload(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	_ = signer

	dir := t.TempDir()
	keysPath := dir + "/authorized_keys"
	content := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	require.NoError(t, os.WriteFile(keysPath, []byte(content), 0600))

	a, err := New(Config{AuthorizedKeysPath: keysPath})
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)
	a.StopAutoReload()
}

func TestExpiredAgentToken(t *testing.T) {
	a, err := New(Config{AgentTokenExpiry: time.Nanosecond})
	require.NoError(t, err)

	token, err := a.GenerateAgentToken("agent1", "sess1")
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	_, err = a.ValidateAgentToken(token)
	assert.ErrorIs(t, err, ErrInvalidAgentToken)
}

func TestCleanupExpired_AgentTokens(t *testing.T) {
	a, err := New(Config{AgentTokenExpiry: time.Nanosecond})
	require.NoError(t, err)

	_, err = a.GenerateAgentToken("agent1", "sess1")
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	count := a.CleanupExpired()
	assert.Equal(t, 1, count)
}

func TestStaticToken_Valid(t *testing.T) {
	staticToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	a, err := New(Config{StaticToken: staticToken})
	require.NoError(t, err)

	claims, err := a.ValidateToken(staticToken)
	require.NoError(t, err)
	assert.Equal(t, "quickstart", claims.OperatorID)
}

func TestStaticToken_Invalid(t *testing.T) {
	staticToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	a, err := New(Config{StaticToken: staticToken})
	require.NoError(t, err)

	_, err = a.ValidateToken("wrong_token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestStaticToken_NotConfigured(t *testing.T) {
	a, err := New(DefaultConfig())
	require.NoError(t, err)

	_, err = a.ValidateToken("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestStaticToken_DynamicTokenStillWorks(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	staticToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	auth, err := New(Config{
		AuthorizedKeysData: keysData,
		StaticToken:        staticToken,
	})
	require.NoError(t, err)

	nonce, err := auth.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	sig, err := signer.Sign(rand.Reader, nonce)
	require.NoError(t, err)
	sigBytes := ssh.Marshal(sig)

	dynamicToken, err := auth.VerifyChallenge(nonce, sigBytes)
	require.NoError(t, err)

	claims, err := auth.ValidateToken(dynamicToken)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.OperatorID)

	claims, err = auth.ValidateToken(staticToken)
	require.NoError(t, err)
	assert.Equal(t, "quickstart", claims.OperatorID)
}

func TestCreateChallenge_RejectsBeyondMaxPending(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	a, err := New(Config{
		AuthorizedKeysData:              keysData,
		MaxPendingChallenges:            2,
		MaxPendingChallengesPerOperator: 2,
		ChallengeExpiry:                 time.Hour,
	})
	require.NoError(t, err)

	_, err = a.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)
	_, err = a.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	_, err = a.CreateChallenge("alice", fingerprint)
	assert.ErrorIs(t, err, ErrTooManyChallenges)

	a.mu.RLock()
	got := len(a.challenges)
	a.mu.RUnlock()
	assert.Equal(t, 2, got)
}

func TestCreateChallenge_RejectsBeyondMaxPendingPerOperator(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keyLine := "ssh-ed25519 " + string(pubKey[:len(pubKey)-1])
	keysData := "alice " + keyLine + "\n" +
		"bob " + keyLine + "\n"
	a, err := New(Config{
		AuthorizedKeysData:              keysData,
		MaxPendingChallenges:            10,
		MaxPendingChallengesPerOperator: 2,
		ChallengeExpiry:                 time.Hour,
	})
	require.NoError(t, err)

	_, err = a.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)
	_, err = a.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	_, err = a.CreateChallenge("alice", fingerprint)
	assert.ErrorIs(t, err, ErrTooManyChallenges)

	_, err = a.CreateChallenge("bob", fingerprint)
	assert.NoError(t, err)
}

func TestCreateChallenge_OpportunisticSweepRecoversCapacity(t *testing.T) {
	signer, pubKey := generateTestKey(t)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	keysData := "alice ssh-ed25519 " + string(pubKey[:len(pubKey)-1]) + "\n"
	a, err := New(Config{
		AuthorizedKeysData:              keysData,
		MaxPendingChallenges:            2,
		MaxPendingChallengesPerOperator: 2,
		ChallengeExpiry:                 time.Millisecond,
	})
	require.NoError(t, err)

	_, err = a.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)
	_, err = a.CreateChallenge("alice", fingerprint)
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	_, err = a.CreateChallenge("alice", fingerprint)
	assert.NoError(t, err, "cap-hit branch should sweep expired entries before rejecting")
}

func TestDefaultConfig_PopulatesMaxPendingChallenges(t *testing.T) {
	c := DefaultConfig()
	assert.Equal(t, defaultMaxPendingChallenges, c.MaxPendingChallenges)
	assert.Equal(t, defaultMaxPendingChallengesPerOperator, c.MaxPendingChallengesPerOperator)
	assert.Greater(t, c.MaxPendingChallenges, 0)
	assert.Greater(t, c.MaxPendingChallengesPerOperator, 0)
}

func TestNew_ZeroMaxPendingChallengesFallsBackToDefault(t *testing.T) {
	a, err := New(Config{})
	require.NoError(t, err)
	assert.Equal(t, defaultMaxPendingChallenges, a.maxPendingChallenges)
	assert.Equal(t, defaultMaxPendingChallengesPerOperator, a.maxPendingPerOperator)
}

func TestNew_MaxPendingPerOperatorCannotExceedGlobal(t *testing.T) {
	a, err := New(Config{
		MaxPendingChallenges:            2,
		MaxPendingChallengesPerOperator: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, a.maxPendingPerOperator)
}
