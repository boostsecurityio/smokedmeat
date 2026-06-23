// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"
)

const sshPivotProbeLimit = 10
const sshPivotProbeConcurrency = 4

var sshKeyMetadataCache sync.Map
var privateKeyBlockRe = regexp.MustCompile(`(?is)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----.*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`)
var sshProbeGitHubRepoFn atomic.Value
var sshPivotProbeTimeoutNanos atomic.Int64

// GitHub publishes current SSH host keys at https://api.github.com/meta.
var githubSSHHostKeys = mustParseAuthorizedKeys(
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
	"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
)

func init() {
	sshProbeGitHubRepoFn.Store(probeGitHubRepoAccess)
	sshPivotProbeTimeoutNanos.Store(int64(12 * time.Second))
}

func currentSSHProbeGitHubRepoFn() func(string, string) SSHTrialResult {
	probeFn, ok := sshProbeGitHubRepoFn.Load().(func(string, string) SSHTrialResult)
	if !ok || probeFn == nil {
		return probeGitHubRepoAccess
	}
	return probeFn
}

func setSSHProbeGitHubRepoFn(fn func(string, string) SSHTrialResult) {
	sshProbeGitHubRepoFn.Store(fn)
}

func currentSSHPivotProbeTimeout() time.Duration {
	return time.Duration(sshPivotProbeTimeoutNanos.Load())
}

func setSSHPivotProbeTimeout(timeout time.Duration) {
	sshPivotProbeTimeoutNanos.Store(int64(timeout))
}

type sshMetadataCacheEntry struct {
	KeyType     string
	Fingerprint string
	Err         string
}

type sshPivotCandidate struct {
	Repo             string
	Known            bool
	OperatorSupplied bool
}

func sshPrivateKeyMetadata(value string) (keyType, fingerprint string, err error) {
	normalized := normalizeSSHPrivateKey(value)
	cacheKey := sha256.Sum256([]byte(normalized))
	if cached, ok := sshKeyMetadataCache.Load(cacheKey); ok {
		entry, ok := cached.(sshMetadataCacheEntry)
		if ok {
			if entry.Err != "" {
				return "", "", fmt.Errorf("%s", entry.Err)
			}
			return entry.KeyType, entry.Fingerprint, nil
		}
	}

	signer, err := ssh.ParsePrivateKey([]byte(normalized))
	if err != nil {
		sshKeyMetadataCache.Store(cacheKey, sshMetadataCacheEntry{Err: err.Error()})
		return "", "", err
	}
	pub := signer.PublicKey()
	entry := sshMetadataCacheEntry{
		KeyType:     pub.Type(),
		Fingerprint: ssh.FingerprintSHA256(pub),
	}
	sshKeyMetadataCache.Store(cacheKey, entry)
	return entry.KeyType, entry.Fingerprint, nil
}

func normalizeSSHPrivateKey(value string) string {
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		value = unquoted
	}
	value = strings.ReplaceAll(value, `\r\n`, "\n")
	value = strings.ReplaceAll(value, `\n`, "\n")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if match := privateKeyBlockRe.FindString(value); match != "" {
		value = strings.TrimSpace(match)
	}
	if !strings.HasSuffix(value, "\n") {
		value += "\n"
	}
	return value
}

func repoOwner(repo string) string {
	owner, _, ok := strings.Cut(strings.TrimSpace(repo), "/")
	if !ok {
		return ""
	}
	return owner
}

func normalizeGitHubRepoTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "git@github.com:")
	target = strings.TrimPrefix(target, "https://github.com/")
	target = strings.TrimPrefix(target, "http://github.com/")
	target = strings.TrimPrefix(target, "github.com/")
	target = strings.Trim(target, "/")
	target = strings.TrimSuffix(target, ".git")
	if strings.Count(target, "/") != 1 {
		return ""
	}
	return target
}

func normalizeGitHubOwnerTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "git@github.com:")
	target = strings.TrimPrefix(target, "https://github.com/")
	target = strings.TrimPrefix(target, "http://github.com/")
	target = strings.TrimPrefix(target, "github.com/")
	target = strings.Trim(target, "/")
	target = strings.TrimSuffix(target, ".git")
	if target == "" || strings.Contains(target, "/") {
		return ""
	}
	return target
}

func parseExplicitSSHPivotTarget(target string) (scopeType, scope string, err error) {
	target = strings.TrimSpace(target)
	switch {
	case strings.HasPrefix(target, "org:"):
		scope = normalizeGitHubOwnerTarget(strings.TrimPrefix(target, "org:"))
		if scope == "" {
			return "", "", fmt.Errorf("invalid SSH pivot scope %q; use org:<owner> or repo:<owner/repo>", target)
		}
		return "org", scope, nil
	case strings.HasPrefix(target, "repo:"):
		scope = normalizeGitHubRepoTarget(strings.TrimPrefix(target, "repo:"))
		if scope == "" {
			return "", "", fmt.Errorf("invalid SSH pivot scope %q; use org:<owner> or repo:<owner/repo>", target)
		}
		return "repo", scope, nil
	default:
		return "", "", fmt.Errorf("invalid SSH pivot scope %q; use org:<owner> or repo:<owner/repo>", target)
	}
}

func formatSSHPivotScope(scopeType, scope string) string {
	if scopeType == "" || scope == "" {
		return ""
	}
	return scopeType + ":" + scope
}

func (m Model) currentSSHPivotScope() (scopeType, scope string) {
	switch m.targetType {
	case "org":
		scope = normalizeGitHubOwnerTarget(m.target)
		if scope != "" {
			return "org", scope
		}
	case "repo":
		scope = normalizeGitHubRepoTarget(m.target)
		if scope != "" {
			return "repo", scope
		}
	}
	return "", ""
}

func (m Model) executeSSHPivot(target string) PivotResultMsg {
	secret, err := m.resolveLootDrivenSecret("SSH private keys", func(secret CollectedSecret) bool {
		return secret.CanUseAsSSHKey()
	})
	if err != nil {
		return PivotResultMsg{
			Type:    PivotTypeSSHKey,
			Success: false,
			Err:     err,
		}
	}
	return m.runSSHPivot(secret, target)
}

func (m *Model) activateSelectedSSHSecret(secret CollectedSecret) error {
	keyValue := normalizeSSHPrivateKey(secret.Value)
	if keyValue == "" {
		keyValue = strings.TrimSpace(secret.Value)
	}
	if keyValue == "" {
		return fmt.Errorf("selected SSH key is empty")
	}

	scope := m.currentTargetSpec()

	msg := PivotResultMsg{
		Type:     PivotTypeSSHKey,
		Success:  true,
		KeyName:  secret.Name,
		KeyValue: keyValue,
		SSHScope: scope,
	}
	if m.updateSSHState(msg) {
		m.AddOutput("warning", "Replaced previous SSH shell session for a different key")
	}
	m.updateSSHPivotSecret(msg)
	m.AddOutput("success", fmt.Sprintf("SSH session ready with %s", secret.Name))
	if scope != "" {
		m.AddOutput("info", "  Scope: "+scope)
	}
	m.AddOutput("info", "  Try 'pivot ssh' for the current target or 'pivot ssh org:<owner>' / 'pivot ssh repo:<owner/repo>'")
	m.AddOutput("info", "  Type 'ssh shell' to enter an isolated git/ssh shell")
	return nil
}

func (m Model) executePivotWithSSHSecret(secret CollectedSecret, target string) tea.Cmd {
	return func() tea.Msg {
		return m.runSSHPivot(secret, target)
	}
}

func (m Model) startSSHPivot(secret CollectedSecret, target string) (tea.Model, tea.Cmd) {
	candidates, scope, err := m.sshPivotCandidateRepos(secret, target)
	if err != nil {
		if target != "" {
			m.AddOutput("error", fmt.Sprintf("Pivot failed: %v", err))
			return m, nil
		}
		if activateErr := m.activateSelectedSSHSecret(secret); activateErr != nil {
			m.AddOutput("error", fmt.Sprintf("Pivot failed: %v", err))
			return m, nil
		}
		m.AddOutput("warning", err.Error())
		return m, nil
	}

	scopeLabel := scope
	if scopeLabel == "" {
		scopeLabel = "discovered repos"
	}

	m.AddOutput("info", fmt.Sprintf("Using SSH key %s", secret.Name))
	if len(candidates) == 1 {
		m.AddOutput("info", fmt.Sprintf("Probing SSH access for %s...", scopeLabel))
	} else {
		m.AddOutput("info", fmt.Sprintf("Probing SSH access across %d repos in %s...", len(candidates), scopeLabel))
	}
	m.activityLog.Add(IconInfo, fmt.Sprintf("SSH probe started for %s", scopeLabel))
	m.flashMessage = "SSH pivot → " + scopeLabel
	m.flashUntil = time.Now().Add(2 * time.Second)
	return m, m.executePivotWithSSHSecret(secret, target)
}

func (m Model) runSSHPivot(secret CollectedSecret, target string) PivotResultMsg {
	keyType, fingerprint, err := sshPrivateKeyMetadata(secret.Value)
	if err != nil {
		return PivotResultMsg{
			Type:    PivotTypeSSHKey,
			Success: false,
			Err:     fmt.Errorf("invalid SSH private key: %w", err),
		}
	}

	candidates, scope, err := m.sshPivotCandidateRepos(secret, target)
	if err != nil {
		return PivotResultMsg{
			Type:    PivotTypeSSHKey,
			Success: false,
			Err:     err,
		}
	}

	results := make([]SSHTrialResult, len(candidates))
	var newPerms []PermissionGain
	var newRepos []string

	var wg sync.WaitGroup
	sem := make(chan struct{}, sshPivotProbeConcurrency)
	for i, repo := range candidates {
		wg.Add(1)
		go func(i int, repo sshPivotCandidate) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = runSSHPivotProbe(secret.Value, repo.Repo)
			<-sem
		}(i, repo)
	}
	wg.Wait()

	for i, repo := range candidates {
		result := results[i]
		if !result.Success {
			continue
		}

		entityID := "repo:" + repo.Repo
		isPrivate := false
		oldPerms := []string(nil)
		knownRepo := repo.Known
		if existing, ok := m.knownEntities[entityID]; ok {
			knownRepo = true
			isPrivate = existing.IsPrivate
			oldPerms = append(oldPerms, existing.Permissions...)
		}

		canPush := result.Permission == "write"
		m.recordPivotEntity(repo.Repo, "repo", "pivot:ssh:"+secret.Name, isPrivate, canPush, result.Permission)
		if repo.OperatorSupplied && !knownRepo {
			newRepos = append(newRepos, repo.Repo)
		}

		if knownRepo && canPush && !hasPerm(oldPerms, "push") {
			newPerms = append(newPerms, PermissionGain{
				Repo:     repo.Repo,
				OldPerms: oldPerms,
				NewPerms: append(append([]string(nil), oldPerms...), "push"),
			})
		}
	}

	return PivotResultMsg{
		Type:       PivotTypeSSHKey,
		Success:    true,
		KeyName:    secret.Name,
		KeyValue:   secret.Value,
		KeyType:    keyType,
		KeyFP:      fingerprint,
		SSHScope:   scope,
		SSHResults: results,
		NewRepos:   newRepos,
		NewPerms:   newPerms,
		TotalFound: len(results),
	}
}

func (m Model) sshPivotCandidateRepos(_ CollectedSecret, target string) ([]sshPivotCandidate, string, error) {
	if target != "" {
		scopeType, scope, err := parseExplicitSSHPivotTarget(target)
		if err != nil {
			return nil, "", err
		}
		return m.sshPivotCandidatesForScope(scopeType, scope)
	}

	scopeType, scope := m.currentSSHPivotScope()
	if scopeType == "" || scope == "" {
		return nil, "", fmt.Errorf("no current target for SSH pivot; use 'set target org:<owner>' or run 'pivot ssh org:<owner>'")
	}
	return m.sshPivotCandidatesForScope(scopeType, scope)
}

func (m Model) sshPivotCandidatesForScope(scopeType, scope string) ([]sshPivotCandidate, string, error) {
	switch scopeType {
	case "repo":
		repo := normalizeGitHubRepoTarget(scope)
		if repo == "" {
			return nil, "", fmt.Errorf("invalid repo scope %q", scope)
		}
		_, known := m.knownEntities["repo:"+repo]
		return []sshPivotCandidate{{
			Repo:             repo,
			Known:            known,
			OperatorSupplied: !known,
		}}, formatSSHPivotScope("repo", repo), nil
	case "org":
		owner := normalizeGitHubOwnerTarget(scope)
		if owner == "" {
			return nil, "", fmt.Errorf("invalid org scope %q", scope)
		}
		repos := m.knownReposForOwner(owner, false)
		if len(repos) == 0 {
			return nil, "", fmt.Errorf("no discovered repos found for org %s", owner)
		}
		return sshCandidatesFromRepos(limitPivotRepos(repos), true), formatSSHPivotScope("org", owner), nil
	default:
		return nil, "", fmt.Errorf("invalid SSH pivot scope %q", scopeType)
	}
}

func sshCandidatesFromRepos(repos []string, known bool) []sshPivotCandidate {
	candidates := make([]sshPivotCandidate, 0, len(repos))
	for _, repo := range repos {
		candidates = append(candidates, sshPivotCandidate{Repo: repo, Known: known})
	}
	return candidates
}

func (m Model) knownReposForOwner(owner string, privateOnly bool) []string {
	var repos []string
	for _, entity := range m.knownEntities {
		if entity == nil || entity.EntityType != "repo" {
			continue
		}
		if privateOnly && !entity.IsPrivate {
			continue
		}
		if repoOwner(entity.Name) == owner {
			repos = append(repos, entity.Name)
		}
	}
	sort.Strings(repos)
	return dedupeStrings(repos)
}

func limitPivotRepos(repos []string) []string {
	repos = dedupeStrings(repos)
	if len(repos) > sshPivotProbeLimit {
		return repos[:sshPivotProbeLimit]
	}
	return repos
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func (m *Model) updateSSHPivotSecret(msg PivotResultMsg) {
	if msg.KeyName == "" || msg.KeyValue == "" {
		return
	}

	update := func(secret *CollectedSecret) bool {
		if secret.Name != msg.KeyName || secret.Value != msg.KeyValue {
			return false
		}
		secret.KeyType = msg.KeyType
		secret.KeyFingerprint = msg.KeyFP
		secret.TrialResults = append([]SSHTrialResult(nil), msg.SSHResults...)
		secret.TrialsComplete = true
		return true
	}

	for i := range m.lootStash {
		if update(&m.lootStash[i]) {
			return
		}
	}
	for i := range m.sessionLoot {
		if update(&m.sessionLoot[i]) {
			return
		}
	}
}

func mergeSSHTrialResults(dst *CollectedSecret, incoming []SSHTrialResult) {
	if len(incoming) == 0 {
		return
	}
	index := make(map[string]int, len(dst.TrialResults))
	for i, result := range dst.TrialResults {
		index[result.Host+"\x00"+result.Repo] = i
	}
	for _, result := range incoming {
		key := result.Host + "\x00" + result.Repo
		if i, ok := index[key]; ok {
			dst.TrialResults[i] = result
			continue
		}
		index[key] = len(dst.TrialResults)
		dst.TrialResults = append(dst.TrialResults, result)
	}
}

func probeGitHubRepoAccess(keyValue, repo string) SSHTrialResult {
	start := time.Now()
	result := SSHTrialResult{
		Host: "github.com",
		Repo: repo,
	}

	auth, err := newGitHubGitAuth(keyValue)
	if err != nil {
		result.Error = compactProbeError(fmt.Errorf("invalid SSH private key: %w", err))
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := gitUploadPackProbe(ctx, auth, repo); err != nil {
		result.Error = compactProbeError(err)
		result.Latency = time.Since(start)
		return result
	}

	result.Success = true
	result.Permission = "read"

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer writeCancel()

	writeCh := make(chan error, 1)
	go func() {
		writeCh <- gitReceivePackProbe(writeCtx, auth, repo)
	}()

	select {
	case err := <-writeCh:
		if err == nil {
			result.Permission = "write"
		}
	case <-writeCtx.Done():
	}

	result.Latency = time.Since(start)
	return result
}

func newGitHubGitAuth(keyValue string) (*gitssh.PublicKeys, error) {
	auth, err := gitssh.NewPublicKeys("git", []byte(normalizeSSHPrivateKey(keyValue)), "")
	if err != nil {
		return nil, err
	}
	auth.HostKeyCallback = githubSSHHostKeyCallback
	return auth, nil
}

func gitUploadPackProbe(ctx context.Context, auth gittransport.AuthMethod, repo string) error {
	return probeGitService(ctx, auth, repo, func(client gittransport.Transport, endpoint *gittransport.Endpoint, auth gittransport.AuthMethod) (gittransport.Session, error) {
		return client.NewUploadPackSession(endpoint, auth)
	})
}

func gitReceivePackProbe(ctx context.Context, auth gittransport.AuthMethod, repo string) error {
	return probeGitService(ctx, auth, repo, func(client gittransport.Transport, endpoint *gittransport.Endpoint, auth gittransport.AuthMethod) (gittransport.Session, error) {
		return client.NewReceivePackSession(endpoint, auth)
	})
}

func probeGitService(
	ctx context.Context,
	auth gittransport.AuthMethod,
	repo string,
	open func(gittransport.Transport, *gittransport.Endpoint, gittransport.AuthMethod) (gittransport.Session, error),
) error {
	endpoint, err := gittransport.NewEndpoint("ssh://git@github.com/" + repo + ".git")
	if err != nil {
		return err
	}
	client := gitssh.NewClient(nil)
	session, err := open(client, endpoint, auth)
	if err != nil {
		return err
	}
	defer session.Close()
	_, err = session.AdvertisedReferencesContext(ctx)
	return err
}

func githubSSHHostKeyCallback(hostname string, _ net.Addr, key ssh.PublicKey) error {
	host, port, err := net.SplitHostPort(hostname)
	if err == nil {
		if host != "github.com" || port != "22" {
			return fmt.Errorf("unexpected SSH host %s", hostname)
		}
	} else if hostname != "github.com" {
		return fmt.Errorf("unexpected SSH host %s", hostname)
	}

	for _, allowed := range githubSSHHostKeys {
		if bytes.Equal(allowed.Marshal(), key.Marshal()) {
			return nil
		}
	}

	return fmt.Errorf("unexpected SSH host key %s", ssh.FingerprintSHA256(key))
}

func mustParseAuthorizedKeys(values ...string) []ssh.PublicKey {
	keys := make([]ssh.PublicKey, 0, len(values))
	for _, value := range values {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(value))
		if err != nil {
			panic(err)
		}
		keys = append(keys, key)
	}
	return keys
}

func compactProbeError(err error) string {
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > 160 {
		return msg[:157] + "..."
	}
	return msg
}

func runSSHPivotProbe(keyValue, repo string) SSHTrialResult {
	ch := make(chan SSHTrialResult, 1)
	start := time.Now()
	probeFn := currentSSHProbeGitHubRepoFn()
	timeout := currentSSHPivotProbeTimeout()

	go func() {
		ch <- probeFn(keyValue, repo)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-ch:
		return result
	case <-timer.C:
		return SSHTrialResult{
			Host:    "github.com",
			Repo:    repo,
			Error:   fmt.Sprintf("probe timed out after %s", timeout.Truncate(time.Second)),
			Latency: time.Since(start),
		}
	}
}
