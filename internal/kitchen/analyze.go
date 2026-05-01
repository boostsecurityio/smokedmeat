// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/gitleaks"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

const (
	analysisPhaseWorkflow   = "workflow_analysis"
	analysisPhaseSecret     = "secret_scan"
	analysisPhaseImport     = "import"
	analysisMetadataStarted = "started"
	analysisMetadataDone    = "completed"
	analysisMetadataFailed  = "failed"
	analysisResultTTL       = 2 * time.Hour
	analysisStatusUnknown   = "unknown"
	analysisStatusPending   = "pending"
	analysisStatusCompleted = "completed"
	analysisStatusFailed    = "failed"
)

var analyzeRemoteWithObserverFunc = poutine.AnalyzeRemoteWithObserver

type cachedAnalysisResult struct {
	SessionID string
	UpdatedAt time.Time
	Status    string
	Result    *poutine.AnalysisResult
	Error     string
}

func analysisRequestTimeout(targetType string, deep bool) time.Duration {
	switch {
	case deep && targetType == "org":
		return 90 * time.Minute
	case deep:
		return 30 * time.Minute
	case targetType == "org":
		return 60 * time.Minute
	default:
		return 20 * time.Minute
	}
}

func analysisMetadataSyncTimeout(targetType string) time.Duration {
	if targetType == "org" {
		return 20 * time.Minute
	}
	return 5 * time.Minute
}

func formatImportPhaseMessage(result *poutine.AnalysisResult) string {
	var parts []string
	if len(result.Workflows) > 0 {
		parts = append(parts, fmt.Sprintf("%d workflows", len(result.Workflows)))
	}
	if len(result.Findings) > 0 {
		parts = append(parts, fmt.Sprintf("%d findings", len(result.Findings)))
	}
	if len(result.SecretFindings) > 0 {
		parts = append(parts, fmt.Sprintf("%d secrets", len(result.SecretFindings)))
	}
	if len(parts) == 0 {
		return "Importing analysis results"
	}
	return "Importing " + strings.Join(parts, ", ")
}

func formatRepoVisibilityPhaseMessage(repoCount int) string {
	if repoCount == 1 {
		return "Updating repository access for 1 repo"
	}
	return fmt.Sprintf("Updating repository access for %d repos", repoCount)
}

// AnalyzeRequest is the request body for remote analysis.
// SECURITY: The token is used ephemerally and never persisted.
type AnalyzeRequest struct {
	// Token is the GitHub token for API access.
	// This is the OPERATOR's token, not loot. It is never stored.
	Token string `json:"token"`

	// Target is the org or org/repo to analyze.
	Target string `json:"target"`

	// TargetType is "org" or "repo".
	TargetType string `json:"target_type"`

	// Deep enables gitleaks scanning for private keys (deep-analyze).
	Deep bool `json:"deep,omitempty"`

	// SessionID identifies the operator session (for known entity lookups).
	SessionID string `json:"session_id,omitempty"`

	AnalysisID string `json:"analysis_id,omitempty"`
}

// AnalyzeResponse wraps the analysis result.
type AnalyzeResponse struct {
	*poutine.AnalysisResult
}

type AnalyzeResultStatusResponse struct {
	AnalysisID string                  `json:"analysis_id"`
	Status     string                  `json:"status"`
	Result     *poutine.AnalysisResult `json:"result,omitempty"`
	Error      string                  `json:"error,omitempty"`
}

// handleAnalyze handles remote poutine analysis requests from Counter.
// This endpoint uses the operator-provided token to scan remote repositories
// via the GitHub API, without requiring an agent on the target.
//
// SECURITY NOTES:
// - Token is used ephemerally for this request only
// - Token is NOT logged, stored, or included in the response
// - Token is NOT persisted to any store (not loot)
// - Results are returned synchronously and not persisted
func (h *Handler) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Validate required fields
	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if req.TargetType == "" {
		req.TargetType = "repo" // Default to repo if not specified
	}
	if req.TargetType != "org" && req.TargetType != "repo" {
		http.Error(w, "target_type must be 'org' or 'repo'", http.StatusBadRequest)
		return
	}
	if req.AnalysisID != "" && !isValidID(req.AnalysisID) {
		http.Error(w, "analysis_id contains invalid characters", http.StatusBadRequest)
		return
	}
	if req.AnalysisID != "" && req.SessionID == "" {
		http.Error(w, "session_id is required when analysis_id is provided", http.StatusBadRequest)
		return
	}

	h.recordAnalysisPending(req)

	ctx, cancel := context.WithTimeout(r.Context(), analysisRequestTimeout(req.TargetType, req.Deep))
	defer cancel()
	startedAt := time.Now()
	progressObserver := newAnalysisProgressObserver(h, req, startedAt)

	slog.Info("analysis starting", "target", req.Target, "type", req.TargetType, "token_len", len(req.Token), "deep", req.Deep)
	result, err := analyzeRemoteWithObserverFunc(ctx, req.Token, req.Target, req.TargetType, progressObserver)
	if err != nil {
		h.recordAnalysisFailure(req, sanitizeError(err))
		slog.Warn("analysis failed", "target", req.Target, "error", sanitizeError(err))
		http.Error(w, "analysis failed: "+sanitizeError(err), http.StatusInternalServerError)
		return
	}

	slog.Info("analysis completed", "target", req.Target, "repos", result.ReposAnalyzed, "findings", len(result.Findings), "workflows", len(result.Workflows), "errors", len(result.Errors), "duration", result.Duration)

	// Gitleaks deep scan: clone repos and scan for private keys
	if req.Deep {
		repos := collectScanTargets(req, result)
		if len(repos) > 0 {
			h.broadcastAnalysisProgress(req, startedAt, analysisPhaseSecret, fmt.Sprintf("Scanning %d repos for secrets", len(repos)), "", 0, len(repos), 0)
		}
		h.runGitleaksScan(ctx, req, result, startedAt, repos)
	}

	// Import findings and workflows to Kitchen's pantry and persist
	h.broadcastAnalysisProgress(req, startedAt, analysisPhaseImport, formatImportPhaseMessage(result), "", result.ReposAnalyzed, result.ReposAnalyzed, len(result.SecretFindings))
	if len(result.Findings) > 0 || len(result.Workflows) > 0 || len(result.SecretFindings) > 0 {
		importStarted := time.Now()
		imported := h.importAnalysisToPantry(result)
		slog.Info("imported analysis to pantry",
			"findings", len(result.Findings),
			"workflows", len(result.Workflows),
			"secrets", len(result.SecretFindings),
			"assets", imported,
			"duration", time.Since(importStarted))
	}

	if err := h.persistAnalysisLoot(req, result); err != nil {
		slog.Warn("failed to persist analysis loot", "target", req.Target, "error", err)
	}

	h.broadcastAnalysisProgress(req, startedAt, analysisPhaseImport, "Persisting attack graph", "", result.ReposAnalyzed, result.ReposAnalyzed, len(result.SecretFindings))
	saveStarted := time.Now()
	if err := h.SavePantry(); err != nil {
		slog.Warn("failed to persist pantry", "error", err)
	} else {
		slog.Info("analysis pantry persisted",
			"target", req.Target,
			"assets", h.Pantry().Size(),
			"edges", h.Pantry().EdgeCount(),
			"duration", time.Since(saveStarted))
	}

	h.recordAnalysisCompleted(req, result)

	// Return result
	// Note: result does NOT contain the token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(AnalyzeResponse{AnalysisResult: result})

	h.startAnalysisMetadataSync(req, result)
}

func (h *Handler) handleGetAnalyzeResult(w http.ResponseWriter, r *http.Request) {
	analysisID := r.PathValue("analysisID")
	sessionID := r.URL.Query().Get("session_id")

	result := AnalyzeResultStatusResponse{
		AnalysisID: analysisID,
		Status:     analysisStatusUnknown,
	}
	if entry, ok := h.lookupAnalysisResult(analysisID, sessionID); ok {
		result.Status = entry.Status
		result.Result = entry.Result
		result.Error = entry.Error
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

func (h *Handler) broadcastAnalysisProgress(req AnalyzeRequest, startedAt time.Time, phase, message, currentRepo string, reposCompleted, reposTotal, secretFindings int) {
	if h.operators == nil || req.SessionID == "" {
		return
	}
	h.operators.BroadcastAnalysisProgress(AnalysisProgressPayload{
		AnalysisID:     req.AnalysisID,
		SessionID:      req.SessionID,
		Target:         req.Target,
		TargetType:     req.TargetType,
		Deep:           req.Deep,
		Phase:          phase,
		Message:        message,
		CurrentRepo:    currentRepo,
		ReposCompleted: reposCompleted,
		ReposTotal:     reposTotal,
		SecretFindings: secretFindings,
		StartedAt:      startedAt,
		UpdatedAt:      time.Now(),
	})
}

func (h *Handler) broadcastAnalysisMetadataSync(req AnalyzeRequest, status, message string, reposTotal int, err error) {
	if h.operators == nil || req.SessionID == "" {
		return
	}
	payload := AnalysisMetadataSyncPayload{
		AnalysisID: req.AnalysisID,
		SessionID:  req.SessionID,
		Target:     req.Target,
		TargetType: req.TargetType,
		Status:     status,
		Message:    message,
		ReposTotal: reposTotal,
		UpdatedAt:  time.Now(),
	}
	if err != nil {
		payload.Error = sanitizeError(err)
	}
	h.operators.BroadcastAnalysisMetadataSync(payload)
}

func (h *Handler) startAnalysisMetadataSync(req AnalyzeRequest, result *poutine.AnalysisResult) {
	if req.SessionID == "" || h.database == nil {
		return
	}

	repoCount := len(collectAnalyzedRepos(result))
	if repoCount == 0 {
		return
	}

	go h.runAnalysisMetadataSync(req, result, repoCount)
}

func (h *Handler) runAnalysisMetadataSync(req AnalyzeRequest, result *poutine.AnalysisResult, repoCount int) {
	message := formatRepoVisibilityPhaseMessage(repoCount) + " in background"
	h.broadcastAnalysisMetadataSync(req, analysisMetadataStarted, message, repoCount, nil)

	ctx, cancel := context.WithTimeout(context.Background(), analysisMetadataSyncTimeout(req.TargetType))
	defer cancel()

	started := time.Now()
	visibilityStarted := time.Now()
	h.recordAnalyzedRepoVisibility(ctx, req, result)
	slog.Info("analysis repository access updated",
		"target", req.Target,
		"type", req.TargetType,
		"repos", repoCount,
		"duration", time.Since(visibilityStarted))

	inventoryStarted := time.Now()
	h.importPrivateReposToPantry(req.SessionID)
	slog.Info("analysis private repo inventory updated",
		"target", req.Target,
		"session", req.SessionID,
		"duration", time.Since(inventoryStarted))

	saveStarted := time.Now()
	if err := h.SavePantry(); err != nil {
		slog.Warn("failed to persist pantry after analysis metadata sync", "target", req.Target, "error", err)
		h.broadcastAnalysisMetadataSync(req, analysisMetadataFailed, "Repository access update incomplete", repoCount, err)
		return
	}

	slog.Info("analysis metadata sync completed",
		"target", req.Target,
		"type", req.TargetType,
		"repos", repoCount,
		"persist_duration", time.Since(saveStarted),
		"duration", time.Since(started))
	h.broadcastAnalysisMetadataSync(req, analysisMetadataDone, "Repository access updated", repoCount, nil)
}

type analysisProgressObserver struct {
	mu             sync.Mutex
	handler        *Handler
	req            AnalyzeRequest
	startedAt      time.Time
	reposCompleted int
	reposTotal     int
	currentRepo    string
}

func newAnalysisProgressObserver(handler *Handler, req AnalyzeRequest, startedAt time.Time) *analysisProgressObserver {
	observer := &analysisProgressObserver{
		handler:   handler,
		req:       req,
		startedAt: startedAt,
	}
	if req.TargetType == "repo" {
		observer.reposTotal = 1
	}
	return observer
}

func (h *Handler) recordAnalysisPending(req AnalyzeRequest) {
	if req.AnalysisID == "" || req.SessionID == "" {
		return
	}
	h.analysisMu.Lock()
	defer h.analysisMu.Unlock()
	h.pruneAnalysisResultsLocked()
	h.analysisRuns[req.AnalysisID] = &cachedAnalysisResult{
		SessionID: req.SessionID,
		UpdatedAt: time.Now(),
		Status:    analysisStatusPending,
	}
}

func (h *Handler) recordAnalysisCompleted(req AnalyzeRequest, result *poutine.AnalysisResult) {
	if req.AnalysisID == "" || req.SessionID == "" {
		return
	}
	h.analysisMu.Lock()
	defer h.analysisMu.Unlock()
	h.pruneAnalysisResultsLocked()
	h.analysisRuns[req.AnalysisID] = &cachedAnalysisResult{
		SessionID: req.SessionID,
		UpdatedAt: time.Now(),
		Status:    analysisStatusCompleted,
		Result:    result,
	}
}

func (h *Handler) recordAnalysisFailure(req AnalyzeRequest, err string) {
	if req.AnalysisID == "" || req.SessionID == "" {
		return
	}
	h.analysisMu.Lock()
	defer h.analysisMu.Unlock()
	h.pruneAnalysisResultsLocked()
	h.analysisRuns[req.AnalysisID] = &cachedAnalysisResult{
		SessionID: req.SessionID,
		UpdatedAt: time.Now(),
		Status:    analysisStatusFailed,
		Error:     err,
	}
}

func (h *Handler) lookupAnalysisResult(analysisID, sessionID string) (*cachedAnalysisResult, bool) {
	if analysisID == "" || sessionID == "" {
		return nil, false
	}
	h.analysisMu.Lock()
	defer h.analysisMu.Unlock()
	h.pruneAnalysisResultsLocked()
	entry, ok := h.analysisRuns[analysisID]
	if !ok {
		return nil, false
	}
	if entry.SessionID == "" || entry.SessionID != sessionID {
		return nil, false
	}
	entryCopy := *entry
	return &entryCopy, true
}

func (h *Handler) pruneAnalysisResultsLocked() {
	cutoff := time.Now().Add(-analysisResultTTL)
	for id, entry := range h.analysisRuns {
		if entry == nil || entry.UpdatedAt.Before(cutoff) {
			delete(h.analysisRuns, id)
		}
	}
}

func (o *analysisProgressObserver) OnAnalysisStarted(description string) {
	o.broadcast(description, "", 0, 0, false)
}

func (o *analysisProgressObserver) OnDiscoveryCompleted(_ string, totalCount int) {
	o.broadcast("Analyzing workflows", "", 0, totalCount, false)
}

func (o *analysisProgressObserver) OnRepoStarted(repo string) {
	o.broadcast("Analyzing workflows", repo, 0, 0, false)
}

func (o *analysisProgressObserver) OnRepoCompleted(repo string) {
	o.broadcast("Analyzing workflows", repo, 1, 0, false)
}

func (o *analysisProgressObserver) OnRepoError(repo string, _ error) {
	o.broadcast("Analyzing workflows", repo, 1, 0, false)
}

func (o *analysisProgressObserver) OnRepoSkipped(repo, _ string) {
	o.broadcast("Analyzing workflows", repo, 1, 0, false)
}

func (o *analysisProgressObserver) OnStepCompleted(description string) {
	o.broadcast(description, "", 0, 0, false)
}

func (o *analysisProgressObserver) OnFinalizeStarted(_ int) {
	o.broadcast("Finalizing analysis results", "", 0, 0, true)
}

func (o *analysisProgressObserver) OnFinalizeCompleted() {
	o.broadcast("Finalizing analysis results", "", 0, 0, true)
}

func (o *analysisProgressObserver) broadcast(message, repo string, completedDelta, reposTotal int, clearRepo bool) {
	o.mu.Lock()
	if reposTotal > o.reposTotal {
		o.reposTotal = reposTotal
	}
	if completedDelta > 0 {
		o.reposCompleted += completedDelta
	}
	if clearRepo {
		o.currentRepo = ""
	} else if repo != "" {
		o.currentRepo = repo
	}
	currentRepo := o.currentRepo
	if currentRepo == "" && !clearRepo && o.req.TargetType == "repo" {
		currentRepo = o.req.Target
	}
	reposCompleted := o.reposCompleted
	reposKnown := o.reposTotal
	o.mu.Unlock()

	o.handler.broadcastAnalysisProgress(o.req, o.startedAt, analysisPhaseWorkflow, message, currentRepo, reposCompleted, reposKnown, 0)
}

// importAnalysisToPantry imports poutine findings into the Kitchen's pantry.
func (h *Handler) importAnalysisToPantry(result *poutine.AnalysisResult) int {
	p := h.Pantry()
	imported := 0
	orgAssets := make(map[string]string)
	repoAssets := make(map[string]string)
	workflowAssets := make(map[string]string)
	jobAssets := make(map[string]string)

	for _, wfMeta := range result.Workflows {
		org, repoName := "", ""
		if wfMeta.Repository != "" {
			parts := strings.Split(wfMeta.Repository, "/")
			if len(parts) >= 2 {
				org, repoName = parts[0], parts[1]
			} else {
				repoName = wfMeta.Repository
			}
		}

		var orgID string
		var repoID string
		if repoName != "" {
			key := wfMeta.Repository
			if existing, ok := repoAssets[key]; ok {
				repoID = existing
			} else {
				if org == "" {
					org = "unknown"
				}

				if existingOrg, ok := orgAssets[org]; ok {
					orgID = existingOrg
				} else {
					orgAsset := pantry.NewOrganization(org, "github")
					if err := p.AddAsset(orgAsset); err == nil {
						orgID = orgAsset.ID
						orgAssets[org] = orgID
						imported++
					}
				}

				repo := pantry.NewRepository(org, repoName, "github")
				repo.State = pantry.StateValidated
				if err := p.AddAsset(repo); err == nil {
					repoID = repo.ID
					repoAssets[key] = repoID
					imported++
					if orgID != "" {
						_ = p.AddRelationship(orgID, repoID, pantry.Contains())
					}
				}
			}
		}

		var workflowID string
		if wfMeta.Path != "" {
			key := wfMeta.Repository + ":" + wfMeta.Path
			if existing, ok := workflowAssets[key]; ok {
				workflowID = existing
			} else {
				parentID := repoID
				if parentID == "" {
					parentID = "analysis"
				}
				wf := pantry.NewWorkflow(parentID, wfMeta.Path)
				wf.State = pantry.StateValidated
				if wfMeta.DefaultBranch != "" {
					wf.SetProperty("default_branch", wfMeta.DefaultBranch)
				}
				if len(wfMeta.EventTriggers) > 0 {
					wf.SetProperty("event_triggers", wfMeta.EventTriggers)
				}
				if len(wfMeta.DispatchInputs) > 0 {
					wf.SetProperty("dispatch_inputs", wfMeta.DispatchInputs)
				}
				if wfMeta.HasOIDC {
					wf.SetProperty("has_oidc", true)
				}
				if wfMeta.HasWrite {
					wf.SetProperty("has_write", true)
				}
				if wfMeta.SelfHosted {
					wf.SetProperty("self_hosted", true)
				}
				if len(wfMeta.CachePoisonVictims) > 0 {
					wf.SetProperty("cache_poison_victims", wfMeta.CachePoisonVictims)
				}
				if err := p.AddAsset(wf); err == nil {
					workflowID = wf.ID
					workflowAssets[key] = workflowID
					imported++
					if repoID != "" {
						_ = p.AddRelationship(repoID, workflowID, pantry.Contains())
					}
				}
			}
		}

		for _, jobMeta := range wfMeta.Jobs {
			jobKey := wfMeta.Repository + ":" + wfMeta.Path + ":" + jobMeta.ID
			job := pantry.NewJob(workflowID, jobMeta.ID)
			job.State = pantry.StateValidated
			if jobMeta.DisplayName != "" {
				job.SetProperty("display_name", jobMeta.DisplayName)
			}
			if jobMeta.HasOIDC {
				job.SetProperty("has_oidc", true)
			}
			if jobMeta.HasWrite {
				job.SetProperty("has_write", true)
			}
			if jobMeta.SelfHosted {
				job.SetProperty("self_hosted", true)
			}
			if len(jobMeta.RunsOn) > 0 {
				job.SetProperty("runs_on", pantry.NormalizeSelfHostedRunnerLabels(jobMeta.RunsOn))
			}
			if jobMeta.GitHubTokenRW {
				job.SetProperty("github_token_rw", true)
			}
			if err := p.AddAsset(job); err == nil {
				imported++
				jobAssets[jobKey] = job.ID
				if workflowID != "" {
					_ = p.AddRelationship(workflowID, job.ID, pantry.Contains())
				}

				for _, secretName := range jobMeta.Secrets {
					secret := pantry.NewSecret(secretName, job.ID, "github")
					secret.SetProperty("job", jobMeta.ID)
					if err := p.AddAsset(secret); err == nil {
						imported++
						_ = p.AddRelationship(job.ID, secret.ID, pantry.Exposes(jobMeta.ID, ""))
					}
				}

				if jobMeta.HasOIDC {
					token := pantry.NewToken("oidc", job.ID, []string{"id_token"})
					token.State = pantry.StateHighValue
					token.SetProperty("job", jobMeta.ID)
					if err := p.AddAsset(token); err == nil {
						imported++
						_ = p.AddRelationship(job.ID, token.ID, pantry.Exposes(jobMeta.ID, ""))
					}
				}

				if jobMeta.GitHubTokenRW {
					token := pantry.NewToken("github_token", job.ID, []string{"contents:write"})
					token.SetProperty("job", jobMeta.ID)
					if err := p.AddAsset(token); err == nil {
						imported++
						_ = p.AddRelationship(job.ID, token.ID, pantry.Exposes(jobMeta.ID, ""))
					}
				}

				for _, cloudAction := range jobMeta.CloudActions {
					cloudAsset := createCloudAsset(cloudAction, job.ID, jobMeta.ID)
					if err := p.AddAsset(cloudAsset); err == nil {
						imported++
						_ = p.AddRelationship(job.ID, cloudAsset.ID, pantry.Exposes(jobMeta.ID, ""))

						if jobMeta.HasOIDC {
							token := createCloudToken(cloudAction, cloudAsset.ID, jobMeta.ID)
							if err := p.AddAsset(token); err == nil {
								imported++
								_ = p.AddRelationship(cloudAsset.ID, token.ID, pantry.Contains())
							}
						}
					}
				}

				for _, appAction := range jobMeta.AppActions {
					if appAction.PrivateKey != "" {
						secret := pantry.NewSecret(appAction.PrivateKey, job.ID, "github")
						secret.SetProperty("inferred_type", "github_app_key")
						secret.SetProperty("action", appAction.Action)
						secret.SetProperty("job", jobMeta.ID)
						secret.State = pantry.StateHighValue
						if err := p.AddAsset(secret); err == nil {
							imported++
							_ = p.AddRelationship(job.ID, secret.ID, pantry.Exposes(jobMeta.ID, ""))
						}
					}
					if appAction.AppID != "" {
						secret := pantry.NewSecret(appAction.AppID, job.ID, "github")
						secret.SetProperty("inferred_type", "github_app_id")
						secret.SetProperty("action", appAction.Action)
						secret.SetProperty("job", jobMeta.ID)
						if err := p.AddAsset(secret); err == nil {
							imported++
							_ = p.AddRelationship(job.ID, secret.ID, pantry.Exposes(jobMeta.ID, ""))
						}
					}
				}
			}
		}
	}

	findings := poutine.ExpandFindings(result.Findings)
	for _, f := range findings {
		org, repoName := "", ""
		if f.Repository != "" {
			parts := strings.Split(f.Repository, "/")
			if len(parts) >= 2 {
				org, repoName = parts[0], parts[1]
			} else {
				repoName = f.Repository
			}
		}

		var orgID string
		var repoID string
		if repoName != "" {
			key := f.Repository
			if existing, ok := repoAssets[key]; ok {
				repoID = existing
			} else {
				if org == "" {
					org = "unknown"
				}

				if existingOrg, ok := orgAssets[org]; ok {
					orgID = existingOrg
				} else {
					orgAsset := pantry.NewOrganization(org, "github")
					if err := p.AddAsset(orgAsset); err == nil {
						orgID = orgAsset.ID
						orgAssets[org] = orgID
						imported++
					}
				}

				repo := pantry.NewRepository(org, repoName, "github")
				repo.State = pantry.StateValidated
				if err := p.AddAsset(repo); err == nil {
					repoID = repo.ID
					repoAssets[key] = repoID
					imported++
					if orgID != "" {
						_ = p.AddRelationship(orgID, repoID, pantry.Contains())
					}
				}
			}
		}

		var workflowID string
		if f.Workflow != "" {
			key := f.Repository + ":" + f.Workflow
			if existing, ok := workflowAssets[key]; ok {
				workflowID = existing
			} else {
				parentID := repoID
				if parentID == "" {
					parentID = "analysis"
				}
				wf := pantry.NewWorkflow(parentID, f.Workflow)
				wf.State = pantry.StateValidated
				if err := p.AddAsset(wf); err == nil {
					workflowID = wf.ID
					workflowAssets[key] = workflowID
					imported++
					if repoID != "" {
						_ = p.AddRelationship(repoID, workflowID, pantry.Contains())
					}
				}
			}
		}

		var jobID string
		if f.Job != "" {
			jobKey := f.Repository + ":" + f.Workflow + ":" + f.Job
			if existing, ok := jobAssets[jobKey]; ok {
				jobID = existing
			} else if workflowID != "" {
				job := pantry.NewJob(workflowID, f.Job)
				job.State = pantry.StateValidated
				if err := p.AddAsset(job); err == nil {
					jobID = job.ID
					jobAssets[jobKey] = jobID
					imported++
					_ = p.AddRelationship(workflowID, jobID, pantry.Contains())
				}
			}
		}

		purl := ""
		if repoID != "" {
			purl = fmt.Sprintf("pkg:github/%s/%s", org, repoName)
		}
		vuln := pantry.NewVulnerability(f.RuleID, purl, f.Workflow, f.Line, poutine.FindingVariantDiscriminator(f))
		if pantry.IsSelfHostedRunnerAnalyzeOnlyRule(f.RuleID) {
			markSelfHostedFindingJob(p, jobID)
			_ = p.RemoveAsset(vuln.ID)
			continue
		}
		vuln.Provider = "github"
		vuln.State = pantry.StateHighValue
		vuln.Severity = f.Severity
		if f.Title != "" {
			vuln.SetProperty("title", f.Title)
		}
		if f.Job != "" {
			vuln.SetProperty("job", f.Job)
		}
		if f.Step != "" {
			vuln.SetProperty("step", f.Step)
		}
		if f.Context != "" {
			vuln.SetProperty("context", f.Context)
		}
		if f.BashContext != "" {
			vuln.SetProperty("bash_context", f.BashContext)
		}
		if f.Trigger != "" {
			vuln.SetProperty("trigger", f.Trigger)
		}
		if f.Expression != "" {
			vuln.SetProperty("expression", f.Expression)
		}
		if f.Fingerprint != "" {
			vuln.SetProperty("fingerprint", f.Fingerprint)
		}
		if f.LOTPTool != "" {
			vuln.SetProperty("lotp_tool", f.LOTPTool)
		}
		if f.LOTPAction != "" {
			vuln.SetProperty("lotp_action", f.LOTPAction)
		}
		if len(f.LOTPTargets) > 0 {
			vuln.SetProperty("lotp_targets", f.LOTPTargets)
		}
		if len(f.InjectionSources) > 0 {
			vuln.SetProperty("injection_sources", f.InjectionSources)
		}
		if len(f.ReferencedSecrets) > 0 {
			vuln.SetProperty("referenced_secrets", f.ReferencedSecrets)
		}
		if len(f.GateTriggers) > 0 {
			vuln.SetProperty("gate_triggers", f.GateTriggers)
		}
		if f.GateRaw != "" {
			vuln.SetProperty("gate_raw", f.GateRaw)
		}
		if f.GateUnsolvable != "" {
			vuln.SetProperty("gate_unsolvable", f.GateUnsolvable)
		}
		if f.CachePoisonWriter {
			vuln.SetProperty("cache_poison_writer", true)
		}
		if f.CachePoisonReason != "" {
			vuln.SetProperty("cache_poison_reason", f.CachePoisonReason)
		}
		if len(f.CachePoisonVictims) > 0 {
			vuln.SetProperty("cache_poison_victims", f.CachePoisonVictims)
		}
		pantry.SetVulnerabilityExploitSupport(&vuln)

		if err := p.AddAsset(vuln); err == nil {
			imported++
			rel := pantry.VulnerableTo(f.RuleID, f.Severity)
			switch {
			case jobID != "":
				_ = p.AddRelationship(jobID, vuln.ID, rel)
			case workflowID != "":
				_ = p.AddRelationship(workflowID, vuln.ID, rel)
			case repoID != "":
				_ = p.AddRelationship(repoID, vuln.ID, rel)
			}
		}
	}

	imported += pantry.SyncObservedSelfHostedRunnerTargets(p)
	imported += importAnalysisSecretsToPantry(p, result, orgAssets, repoAssets)
	return imported
}

func importAnalysisSecretsToPantry(p *pantry.Pantry, result *poutine.AnalysisResult, orgAssets, repoAssets map[string]string) int {
	if p == nil || result == nil || len(result.SecretFindings) == 0 {
		return 0
	}
	imported := 0
	for _, sf := range result.SecretFindings {
		repoID, created := ensurePantryRepository(p, strings.TrimSpace(sf.Repository), orgAssets, repoAssets)
		imported += created

		secret := pantry.NewSecret(gitleaksFindingName(sf), repoID, "gitleaks")
		secret.State = pantry.StateHighValue
		secret.SetProperty("rule_id", sf.RuleID)
		secret.SetProperty("description", sf.Description)
		secret.SetProperty("file", sf.File)
		secret.SetProperty("line", sf.StartLine)
		secret.SetProperty("fingerprint", sf.Fingerprint)
		secret.SetProperty("inferred_type", gitleaksFindingType(sf.RuleID))
		secret.SetProperty("source", "gitleaks")

		existed := p.HasAsset(secret.ID)
		if err := p.AddAsset(secret); err != nil {
			continue
		}
		if !existed {
			imported++
		}
		if repoID != "" {
			_ = p.AddRelationship(repoID, secret.ID, pantry.Exposes("gitleaks", sf.RuleID))
		}
	}
	return imported
}

func ensurePantryRepository(p *pantry.Pantry, fullName string, orgAssets, repoAssets map[string]string) (repoID string, imported int) {
	if p == nil || strings.TrimSpace(fullName) == "" {
		return "", 0
	}
	fullName = strings.TrimSpace(fullName)
	if repoID, ok := repoAssets[fullName]; ok {
		return repoID, 0
	}
	parts := strings.Split(fullName, "/")
	if len(parts) < 2 {
		return "", 0
	}

	org := parts[0]
	repoName := parts[1]
	orgID, ok := orgAssets[org]
	if !ok {
		orgAsset := pantry.NewOrganization(org, "github")
		existed := p.HasAsset(orgAsset.ID)
		if err := p.AddAsset(orgAsset); err == nil {
			orgID = orgAsset.ID
			orgAssets[org] = orgID
			if !existed {
				imported++
			}
		}
	}

	repo := pantry.NewRepository(org, repoName, "github")
	repo.State = pantry.StateValidated
	existed := p.HasAsset(repo.ID)
	if err := p.AddAsset(repo); err != nil {
		return "", imported
	}
	repoAssets[fullName] = repo.ID
	if !existed {
		imported++
	}
	if orgID != "" {
		_ = p.AddRelationship(orgID, repo.ID, pantry.Contains())
	}
	return repo.ID, imported
}

func markSelfHostedFindingJob(p *pantry.Pantry, jobID string) {
	if p == nil || jobID == "" {
		return
	}
	job, err := p.GetAsset(jobID)
	if err != nil {
		return
	}
	job.SetProperty("self_hosted", true)
	if len(job.StringSliceProperty("runs_on")) == 0 {
		job.SetProperty("runs_on", []string{"self-hosted"})
	}
	_ = p.AddAsset(job)
}

func collectAnalyzedRepos(result *poutine.AnalysisResult) map[string]struct{} {
	repos := make(map[string]struct{})
	for _, r := range result.AnalyzedRepos {
		if r != "" {
			repos[r] = struct{}{}
		}
	}
	for _, f := range result.Findings {
		if f.Repository != "" {
			repos[f.Repository] = struct{}{}
		}
	}
	return repos
}

func (h *Handler) recordAnalyzedRepoVisibility(ctx context.Context, req AnalyzeRequest, result *poutine.AnalysisResult) {
	repos := collectAnalyzedRepos(result)
	client := newGitHubClient(req.Token)
	entityRepo := db.NewKnownEntityRepository(h.database)
	repoInfoByName := make(map[string]RepoInfo, len(repos))

	if req.TargetType == "org" && req.Target != "" && !strings.Contains(req.Target, "/") {
		infos, err := client.listOwnerReposWithInfoGraphQL(ctx, req.Target)
		if err != nil {
			slog.Debug("failed to prefetch owner repo visibility during analysis", "target", req.Target, "repo_count", len(repos), "error", err)
		} else {
			for _, info := range infos {
				if _, ok := repos[info.FullName]; ok {
					repoInfoByName[info.FullName] = info
				}
			}
		}
	}

	for fullName := range repos {
		parts := strings.Split(fullName, "/")
		if len(parts) < 2 {
			continue
		}
		info, ok := repoInfoByName[fullName]
		if !ok {
			var err error
			info, err = client.getRepoInfo(ctx, parts[0], parts[1])
			if err != nil {
				slog.Debug("failed to get repo info during analysis", "repo", fullName, "error", err)
				continue
			}
		}

		var perms []string
		if info.CanPush {
			perms = []string{"push"}
		}

		row := &db.KnownEntityRow{
			ID:            "repo:" + fullName,
			EntityType:    db.EntityTypeRepo,
			Name:          fullName,
			SessionID:     req.SessionID,
			DiscoveredVia: "analysis",
			IsPrivate:     info.IsPrivate,
			Permissions:   perms,
		}
		if err := entityRepo.Upsert(row); err != nil {
			slog.Debug("failed to record repo entity during analysis", "repo", fullName, "error", err)
		}
	}
}

func (h *Handler) importPrivateReposToPantry(sessionID string) {
	repo := db.NewKnownEntityRepository(h.database)
	entities, err := repo.ListRepos(sessionID)
	if err != nil {
		slog.Warn("failed to list known entities for private repo import", "session", sessionID, "error", err)
		return
	}
	p := h.Pantry()
	for _, entity := range entities {
		if !entity.IsPrivate && entity.SSHPermission == "" && len(entity.Permissions) == 0 {
			continue
		}
		upsertKnownRepoAsset(p, entity)
	}
}

func upsertKnownRepoAsset(p *pantry.Pantry, entity *db.KnownEntityRow) {
	parts := strings.Split(entity.Name, "/")
	if len(parts) < 2 {
		return
	}
	org, name := parts[0], parts[1]
	orgAsset := pantry.NewOrganization(org, "github")
	_ = p.AddAsset(orgAsset)

	repoAsset := pantry.NewRepository(org, name, "github")
	repoAsset.State = pantry.StateValidated
	if entity.IsPrivate {
		repoAsset.SetProperty("private", true)
	}
	if len(entity.Permissions) > 0 {
		repoAsset.SetProperty("permissions", append([]string(nil), entity.Permissions...))
	}
	if entity.SSHPermission != "" {
		repoAsset.SetProperty("ssh_access", entity.SSHPermission)
	}
	_ = p.AddAsset(repoAsset)
	_ = p.AddRelationship(orgAsset.ID, repoAsset.ID, pantry.Contains())
}

// runGitleaksScan runs gitleaks on repos discovered during analysis.
func (h *Handler) runGitleaksScan(ctx context.Context, req AnalyzeRequest, result *poutine.AnalysisResult, startedAt time.Time, repos []string) {
	for i, repo := range repos {
		h.broadcastAnalysisProgress(req, startedAt, analysisPhaseSecret, "Scanning repository for secrets", repo, i, len(repos), len(result.SecretFindings))
		scanResult, err := gitleaks.CloneAndScan(ctx, req.Token, repo)
		if err != nil {
			slog.Warn("gitleaks scan failed", "repo", repo, "error", err)
			result.Errors = append(result.Errors, fmt.Sprintf("gitleaks scan failed for %s: %s", repo, sanitizeError(err)))
			h.broadcastAnalysisProgress(req, startedAt, analysisPhaseSecret, "Secret scan error", repo, i+1, len(repos), len(result.SecretFindings))
			continue
		}

		for _, f := range scanResult.Findings {
			file := f.File
			if scanResult.RepoPath != "" {
				file = strings.TrimPrefix(file, scanResult.RepoPath+"/")
			}
			result.SecretFindings = append(result.SecretFindings, poutine.SecretFinding{
				RuleID:      f.RuleID,
				Description: f.Description,
				Repository:  repo,
				File:        file,
				StartLine:   f.StartLine,
				Secret:      f.Secret,
				Fingerprint: f.Fingerprint,
				Entropy:     f.Entropy,
			})
		}

		if len(scanResult.Findings) > 0 {
			slog.Info("gitleaks found secrets", "repo", repo, "count", len(scanResult.Findings))
		}
		h.broadcastAnalysisProgress(req, startedAt, analysisPhaseSecret, "Secret scan updated", repo, i+1, len(repos), len(result.SecretFindings))
	}
}

// collectScanTargets determines which repos to scan with gitleaks.
func collectScanTargets(req AnalyzeRequest, result *poutine.AnalysisResult) []string {
	if req.TargetType == "repo" {
		return []string{req.Target}
	}

	seen := make(map[string]bool)
	var repos []string
	addRepo := func(repo string) {
		repo = strings.TrimSpace(repo)
		if repo == "" || seen[repo] {
			return
		}
		seen[repo] = true
		repos = append(repos, repo)
	}

	for _, repo := range result.AnalyzedRepos {
		addRepo(repo)
	}
	if len(repos) > 0 {
		return repos
	}

	for _, f := range result.Findings {
		addRepo(f.Repository)
	}
	return repos
}

func (h *Handler) persistAnalysisLoot(req AnalyzeRequest, result *poutine.AnalysisResult) error {
	if h.database == nil || result == nil || len(result.SecretFindings) == 0 {
		return nil
	}

	lootRepo := db.NewLootRepository(h.database)
	now := time.Now()
	for _, sf := range result.SecretFindings {
		row := &db.LootRow{
			SessionID:  req.SessionID,
			Timestamp:  now,
			Origin:     db.LootOriginAnalysis,
			Name:       gitleaksFindingName(sf),
			Value:      sf.Secret,
			Type:       gitleaksFindingType(sf.RuleID),
			Source:     gitleaksFindingSource(sf),
			HighValue:  true,
			Repository: strings.TrimSpace(sf.Repository),
		}
		if strings.HasPrefix(strings.TrimSpace(sf.File), ".github/workflows/") {
			row.Workflow = strings.TrimSpace(sf.File)
		}
		if err := lootRepo.Upsert(row); err != nil {
			return err
		}
	}
	return nil
}

func gitleaksFindingName(sf poutine.SecretFinding) string {
	return fmt.Sprintf("%s (%s:%d)", sf.Description, sf.File, sf.StartLine)
}

func gitleaksFindingType(ruleID string) string {
	switch ruleID {
	case "private-key":
		return "private_key"
	case "pkcs12-file":
		return "pkcs12"
	case "github-pat", "github-fine-grained-pat":
		return "github_pat"
	}
	return ruleID
}

func gitleaksFindingSource(sf poutine.SecretFinding) string {
	repo := strings.TrimSpace(sf.Repository)
	file := strings.TrimSpace(sf.File)
	switch {
	case repo != "" && file != "":
		return fmt.Sprintf("%s:%s:%d", repo, file, sf.StartLine)
	case file != "":
		return fmt.Sprintf("%s:%d", file, sf.StartLine)
	default:
		return "gitleaks"
	}
}

// sanitizeError removes any potentially sensitive information from error messages.
func sanitizeError(err error) string {
	msg := err.Error()
	// Don't include full error chain which might have token in URL
	if len(msg) > 100 {
		return msg[:100] + "..."
	}
	return msg
}

// createCloudAsset creates a cloud resource asset from a detected cloud action.
func createCloudAsset(action poutine.CloudAction, _, jobName string) pantry.Asset {
	resourceID := extractCloudResourceID(action)
	asset := pantry.NewCloud(action.Provider, "oidc_trust", resourceID)
	asset.State = pantry.StateHighValue
	asset.SetProperty("action", action.Action)
	asset.SetProperty("version", action.Version)
	asset.SetProperty("job", jobName)

	for k, v := range action.Inputs {
		asset.SetProperty(k, v)
	}

	return asset
}

// extractCloudResourceID extracts a meaningful identifier from cloud action inputs.
func extractCloudResourceID(action poutine.CloudAction) string {
	switch action.Provider {
	case poutine.CloudProviderAWS:
		if role := action.Inputs["role-to-assume"]; role != "" {
			return role
		}
	case poutine.CloudProviderGCP:
		if sa := action.Inputs["service_account"]; sa != "" {
			return sa
		}
		if wp := action.Inputs["workload_identity_provider"]; wp != "" {
			return wp
		}
	case poutine.CloudProviderAzure:
		if clientID := action.Inputs["client-id"]; clientID != "" {
			return clientID
		}
	}
	return action.Action
}

// createCloudToken creates a provider-specific token asset for OIDC pivot.
func createCloudToken(action poutine.CloudAction, cloudAssetID, jobName string) pantry.Asset {
	var token pantry.Asset

	switch action.Provider {
	case poutine.CloudProviderAWS:
		token = pantry.NewToken("aws_oidc", cloudAssetID, []string{"sts:AssumeRoleWithWebIdentity"})
		if role := action.Inputs["role-to-assume"]; role != "" {
			token.SetProperty("role_arn", role)
		}
		if region := action.Inputs["aws-region"]; region != "" {
			token.SetProperty("region", region)
		}
		if dur := action.Inputs["role-duration-seconds"]; dur != "" {
			token.SetProperty("role_duration_seconds", dur)
		}
		if extID := action.Inputs["role-external-id"]; extID != "" {
			token.SetProperty("role_external_id", extID)
		}

	case poutine.CloudProviderGCP:
		token = pantry.NewToken("gcp_oidc", cloudAssetID, []string{"iam.serviceAccounts.getAccessToken"})
		if wp := action.Inputs["workload_identity_provider"]; wp != "" {
			token.SetProperty("workload_provider", wp)
		}
		if sa := action.Inputs["service_account"]; sa != "" {
			token.SetProperty("service_account", sa)
		}
		if proj := action.Inputs["project_id"]; proj != "" {
			token.SetProperty("project_id", proj)
		}
		if aud := action.Inputs["audience"]; aud != "" {
			token.SetProperty("audience", aud)
		}
		if del := action.Inputs["delegates"]; del != "" {
			token.SetProperty("delegates", del)
		}
		if lt := action.Inputs["access_token_lifetime"]; lt != "" {
			token.SetProperty("access_token_lifetime", lt)
		}
		if sc := action.Inputs["access_token_scopes"]; sc != "" {
			token.SetProperty("access_token_scopes", sc)
		}

	case poutine.CloudProviderAzure:
		token = pantry.NewToken("azure_oidc", cloudAssetID, []string{"Application.Read.All"})
		if tenant := action.Inputs["tenant-id"]; tenant != "" {
			token.SetProperty("tenant_id", tenant)
		}
		if client := action.Inputs["client-id"]; client != "" {
			token.SetProperty("client_id", client)
		}
		if sub := action.Inputs["subscription-id"]; sub != "" {
			token.SetProperty("subscription_id", sub)
		}
		if env := action.Inputs["environment"]; env != "" {
			token.SetProperty("environment", env)
		}
		if aud := action.Inputs["audience"]; aud != "" {
			token.SetProperty("audience", aud)
		}

	default:
		token = pantry.NewToken("cloud_oidc", cloudAssetID, []string{"unknown"})
	}

	token.State = pantry.StateHighValue
	token.SetProperty("job", jobName)
	token.SetProperty("provider", action.Provider)
	return token
}
