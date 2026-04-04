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
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/gitleaks"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

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
}

// AnalyzeResponse wraps the analysis result.
type AnalyzeResponse struct {
	*poutine.AnalysisResult
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

	// Run analysis with timeout
	// For orgs, this can take a while - allow up to 10 minutes
	timeout := 10 * time.Minute
	if req.TargetType == "repo" {
		timeout = 5 * time.Minute // Single repo is faster
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	slog.Info("analysis starting", "target", req.Target, "type", req.TargetType, "token_len", len(req.Token), "deep", req.Deep)

	result, err := poutine.AnalyzeRemote(ctx, req.Token, req.Target, req.TargetType)
	if err != nil {
		slog.Warn("analysis failed", "target", req.Target, "error", sanitizeError(err))
		http.Error(w, "analysis failed: "+sanitizeError(err), http.StatusInternalServerError)
		return
	}

	slog.Info("analysis completed", "target", req.Target, "repos", result.ReposAnalyzed, "findings", len(result.Findings), "workflows", len(result.Workflows), "errors", len(result.Errors), "duration", result.Duration)

	// Gitleaks deep scan: clone repos and scan for private keys
	if req.Deep {
		h.runGitleaksScan(ctx, req, result)
	}

	// Import findings and workflows to Kitchen's pantry and persist
	if len(result.Findings) > 0 || len(result.Workflows) > 0 || len(result.SecretFindings) > 0 {
		imported := h.importAnalysisToPantry(result)
		slog.Info("imported analysis to pantry",
			"findings", len(result.Findings),
			"workflows", len(result.Workflows),
			"secrets", len(result.SecretFindings),
			"assets", imported)
	}

	if req.SessionID != "" && h.database != nil {
		h.recordAnalyzedRepoVisibility(ctx, req.Token, req.SessionID, result)
		h.importPrivateReposToPantry(req.SessionID)
	}

	if err := h.SavePantry(); err != nil {
		slog.Warn("failed to persist pantry", "error", err)
	}

	// Return result
	// Note: result does NOT contain the token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(AnalyzeResponse{AnalysisResult: result})
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

	for _, f := range result.Findings {
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
		vuln := pantry.NewVulnerability(f.RuleID, purl, f.Workflow, f.Line)
		vuln.Provider = "github"
		pantry.SetVulnerabilityExploitSupport(&vuln)
		vuln.State = pantry.StateHighValue
		vuln.Severity = f.Severity
		if f.Title != "" {
			vuln.SetProperty("title", f.Title)
		}
		if f.Job != "" {
			vuln.SetProperty("job", f.Job)
		}
		if f.Context != "" {
			vuln.SetProperty("context", f.Context)
		}
		if f.Trigger != "" {
			vuln.SetProperty("trigger", f.Trigger)
		}
		if f.Expression != "" {
			vuln.SetProperty("expression", f.Expression)
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

	// Import gitleaks secret findings
	for _, sf := range result.SecretFindings {
		repoKey := ""
		for _, wf := range result.Workflows {
			if repoKey == "" {
				repoKey = wf.Repository
			}
		}
		if repoKey == "" {
			repoKey = result.Target
		}

		var parentID string
		if existing, ok := repoAssets[repoKey]; ok {
			parentID = existing
		}

		secret := pantry.NewSecret(sf.File, parentID, "gitleaks")
		secret.State = pantry.StateHighValue
		secret.SetProperty("rule_id", sf.RuleID)
		secret.SetProperty("description", sf.Description)
		secret.SetProperty("line", sf.StartLine)
		secret.SetProperty("fingerprint", sf.Fingerprint)
		secret.SetProperty("source", "gitleaks")
		if err := p.AddAsset(secret); err == nil {
			imported++
			if parentID != "" {
				_ = p.AddRelationship(parentID, secret.ID, pantry.Exposes("gitleaks", sf.RuleID))
			}
		}
	}

	return imported
}

func (h *Handler) recordAnalyzedRepoVisibility(ctx context.Context, token, sessionID string, result *poutine.AnalysisResult) {
	repos := make(map[string]struct{})
	for _, r := range result.AnalyzedRepos {
		repos[r] = struct{}{}
	}
	for _, f := range result.Findings {
		repos[f.Repository] = struct{}{}
	}

	client := newGitHubClient(token)
	entityRepo := db.NewKnownEntityRepository(h.database)

	for fullName := range repos {
		parts := strings.Split(fullName, "/")
		if len(parts) < 2 {
			continue
		}
		info, err := client.getRepoInfo(ctx, parts[0], parts[1])
		if err != nil {
			slog.Debug("failed to get repo info during analysis", "repo", fullName, "error", err)
			continue
		}

		var perms []string
		if info.CanPush {
			perms = []string{"push"}
		}

		row := &db.KnownEntityRow{
			ID:            "repo:" + fullName,
			EntityType:    db.EntityTypeRepo,
			Name:          fullName,
			SessionID:     sessionID,
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
func (h *Handler) runGitleaksScan(ctx context.Context, req AnalyzeRequest, result *poutine.AnalysisResult) {
	repos := collectScanTargets(req, result)
	for _, repo := range repos {
		scanResult, err := gitleaks.CloneAndScan(ctx, req.Token, repo)
		if err != nil {
			slog.Warn("gitleaks scan failed", "repo", repo, "error", err)
			result.Errors = append(result.Errors, fmt.Sprintf("gitleaks scan failed for %s: %s", repo, sanitizeError(err)))
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
	}
}

// collectScanTargets determines which repos to scan with gitleaks.
func collectScanTargets(req AnalyzeRequest, result *poutine.AnalysisResult) []string {
	if req.TargetType == "repo" {
		return []string{req.Target}
	}

	// For org targets, scan repos that have findings (high-value repos)
	seen := make(map[string]bool)
	var repos []string
	for _, f := range result.Findings {
		if f.Repository != "" && !seen[f.Repository] {
			seen[f.Repository] = true
			repos = append(repos, f.Repository)
		}
	}
	return repos
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
