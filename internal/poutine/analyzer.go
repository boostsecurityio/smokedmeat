// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/boostsecurityio/poutine/analyze"
	"github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/opa"
	"github.com/boostsecurityio/poutine/providers/gitops"
	"github.com/boostsecurityio/poutine/providers/local"
	"github.com/boostsecurityio/poutine/providers/scm"
	"github.com/boostsecurityio/poutine/results"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
)

// AnalysisResult represents the result of a poutine CI/CD security analysis.
// This is the unified result type used by both remote (Kitchen) and local (Brisket) analysis.
type AnalysisResult struct {
	Success  bool          `json:"success"`
	Duration time.Duration `json:"duration"`

	// Target metadata
	Target     string `json:"target"`      // org or org/repo (remote) or path (local)
	TargetType string `json:"target_type"` // "org", "repo", or "local"
	Repository string `json:"repository,omitempty"`

	// Findings summary
	ReposAnalyzed    int `json:"repos_analyzed"`
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`

	// Detailed findings
	Findings []Finding `json:"findings"`

	// Workflow metadata (for loot scoring)
	Workflows []WorkflowMeta `json:"workflows,omitempty"`

	// All repos that were analyzed (for tracking private repos with no vulns)
	AnalyzedRepos []string `json:"analyzed_repos,omitempty"`

	// Secret findings from gitleaks scanning
	SecretFindings []SecretFinding `json:"secret_findings,omitempty"`

	// Errors (non-fatal issues during analysis)
	Errors []string `json:"errors,omitempty"`
}

// SecretFinding represents a secret found by gitleaks during analysis.
type SecretFinding struct {
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description"`
	Repository  string  `json:"repository"`
	File        string  `json:"file"`
	StartLine   int     `json:"start_line"`
	Secret      string  `json:"secret"`
	Fingerprint string  `json:"fingerprint"`
	Entropy     float32 `json:"entropy"`
}

// WorkflowMeta contains metadata about a workflow for loot potential scoring.
type WorkflowMeta struct {
	Repository         string                        `json:"repository"`
	Path               string                        `json:"path"`
	Secrets            []string                      `json:"secrets,omitempty"`
	JobSecrets         map[string][]string           `json:"job_secrets,omitempty"`
	Jobs               []JobMeta                     `json:"jobs,omitempty"`
	SecretTypes        map[string]string             `json:"secret_types,omitempty"`
	HardcodedAppIDs    []string                      `json:"hardcoded_app_ids,omitempty"`
	HasOIDC            bool                          `json:"has_oidc,omitempty"`
	HasWrite           bool                          `json:"has_write,omitempty"`
	SelfHosted         bool                          `json:"self_hosted,omitempty"`
	CachePoisonVictims []cachepoison.VictimCandidate `json:"cache_poison_victims,omitempty"`
}

// JobMeta contains metadata about a specific job.
type JobMeta struct {
	ID            string            `json:"id"`                     // Mandatory job key from YAML
	DisplayName   string            `json:"display_name,omitempty"` // Optional name attribute
	Secrets       []string          `json:"secrets,omitempty"`
	CloudActions  []CloudAction     `json:"cloud_actions,omitempty"`
	AppActions    []AppAction       `json:"app_actions,omitempty"`
	SecretTypes   map[string]string `json:"secret_types,omitempty"`
	HasOIDC       bool              `json:"has_oidc,omitempty"`
	HasWrite      bool              `json:"has_write,omitempty"`
	SelfHosted    bool              `json:"self_hosted,omitempty"`
	GitHubTokenRW bool              `json:"github_token_rw,omitempty"`
}

// AppAction represents a detected GitHub App token action in a workflow.
type AppAction struct {
	Action         string `json:"action"`
	Version        string `json:"version"`
	PrivateKey     string `json:"private_key"`
	AppID          string `json:"app_id"`
	HardcodedAppID string `json:"hardcoded_app_id,omitempty"`
}

// CloudAction represents a detected cloud provider action in a workflow.
type CloudAction struct {
	Provider string            `json:"provider"` // aws, gcp, azure
	Action   string            `json:"action"`   // Full action name (owner/repo)
	Version  string            `json:"version"`  // Action version (@v1, @main, etc.)
	Inputs   map[string]string `json:"inputs"`   // Relevant inputs for pivot
}

// CloudProvider constants
const (
	CloudProviderAWS   = "aws"
	CloudProviderGCP   = "gcp"
	CloudProviderAzure = "azure"
)

// Finding represents a single vulnerability found during analysis.
type Finding struct {
	ID          string `json:"id"`                    // Generated ID (V001, V002, etc.)
	Repository  string `json:"repository"`            // org/repo
	Workflow    string `json:"workflow"`              // .github/workflows/foo.yml
	Line        int    `json:"line,omitempty"`        // Line number in workflow
	Job         string `json:"job,omitempty"`         // Job name
	Step        string `json:"step,omitempty"`        // Step name
	RuleID      string `json:"rule_id"`               // poutine rule ID
	Title       string `json:"title"`                 // Finding title
	Description string `json:"description,omitempty"` // Rule description
	Severity    string `json:"severity"`              // "critical", "high", "medium", "low"
	Details     string `json:"details,omitempty"`     // Additional details

	// Injection-specific metadata (for initial access exploitation)
	Context    string `json:"context,omitempty"`    // Injection context: "bash_run", "github_script", etc.
	Trigger    string `json:"trigger,omitempty"`    // Workflow trigger: "pull_request", "push", etc.
	Expression string `json:"expression,omitempty"` // The vulnerable expression (${{ ... }})

	InjectionSources   []string                      `json:"injection_sources,omitempty"`
	ReferencedSecrets  []string                      `json:"referenced_secrets,omitempty"`
	LOTPTool           string                        `json:"lotp_tool,omitempty"`
	LOTPAction         string                        `json:"lotp_action,omitempty"`
	LOTPTargets        []string                      `json:"lotp_targets,omitempty"`
	CachePoisonWriter  bool                          `json:"cache_poison_writer,omitempty"`
	CachePoisonReason  string                        `json:"cache_poison_reason,omitempty"`
	CachePoisonVictims []cachepoison.VictimCandidate `json:"cache_poison_victims,omitempty"`

	// Gate constraints (if: conditions on enclosing job/step)
	GateTriggers   []string `json:"gate_triggers,omitempty"`
	GateRaw        string   `json:"gate_raw,omitempty"`
	GateUnsolvable string   `json:"gate_unsolvable,omitempty"`

	// Fingerprint for deduplication
	Fingerprint string `json:"fingerprint,omitempty"`
}

type AnalysisObserver interface {
	OnAnalysisStarted(description string)
	OnDiscoveryCompleted(org string, totalCount int)
	OnRepoStarted(repo string)
	OnRepoCompleted(repo string)
	OnRepoError(repo string, err error)
	OnRepoSkipped(repo string, reason string)
	OnStepCompleted(description string)
	OnFinalizeStarted(totalPackages int)
	OnFinalizeCompleted()
}

type observerAdapter struct {
	observer AnalysisObserver
}

func (o observerAdapter) OnAnalysisStarted(description string) {
	if o.observer != nil {
		o.observer.OnAnalysisStarted(description)
	}
}

func (o observerAdapter) OnDiscoveryCompleted(org string, totalCount int) {
	if o.observer != nil {
		o.observer.OnDiscoveryCompleted(org, totalCount)
	}
}

func (o observerAdapter) OnRepoStarted(repo string) {
	if o.observer != nil {
		o.observer.OnRepoStarted(repo)
	}
}

func (o observerAdapter) OnRepoCompleted(repo string, _ *models.PackageInsights) {
	if o.observer != nil {
		o.observer.OnRepoCompleted(repo)
	}
}

func (o observerAdapter) OnRepoError(repo string, err error) {
	if o.observer != nil {
		o.observer.OnRepoError(repo, err)
	}
}

func (o observerAdapter) OnRepoSkipped(repo, reason string) {
	if o.observer != nil {
		o.observer.OnRepoSkipped(repo, reason)
	}
}

func (o observerAdapter) OnStepCompleted(description string) {
	if o.observer != nil {
		o.observer.OnStepCompleted(description)
	}
}

func (o observerAdapter) OnFinalizeStarted(totalPackages int) {
	if o.observer != nil {
		o.observer.OnFinalizeStarted(totalPackages)
	}
}

func (o observerAdapter) OnFinalizeCompleted() {
	if o.observer != nil {
		o.observer.OnFinalizeCompleted()
	}
}

// AnalyzeRemote performs analysis on a remote GitHub target using the GitHub API.
// This is used by Kitchen for pre-agent reconnaissance.
// The token is used ephemerally and NOT persisted.
func AnalyzeRemote(ctx context.Context, token, target, targetType string) (*AnalysisResult, error) {
	return AnalyzeRemoteWithObserver(ctx, token, target, targetType, nil)
}

func AnalyzeRemoteWithObserver(ctx context.Context, token, target, targetType string, observer AnalysisObserver) (*AnalysisResult, error) {
	start := time.Now()
	result := &AnalysisResult{
		Target:     target,
		TargetType: targetType,
		Findings:   []Finding{},
		Errors:     []string{},
	}

	// Validate inputs
	if token == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	// Create SCM client using poutine's abstraction
	scmClient, err := scm.NewScmClient(ctx, "github", "", token, "analyze_repo")
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	// Create config with offensive rules filter
	config := models.DefaultConfig()
	config.AllowedRules = OffensiveRules
	config.Quiet = true // No progress bar

	// Create OPA policy engine
	opaClient, err := opa.NewOpa(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	// Create git client for cloning operations
	gitClient := gitops.NewGitClient(nil)

	// Create analyzer with no-op formatter
	analyzer := analyze.NewAnalyzer(scmClient, gitClient, &NoopFormatter{}, config, opaClient)
	if observer != nil {
		analyzer.Observer = observerAdapter{observer: observer}
	}

	// Run analysis based on target type
	var packages []*models.PackageInsights
	if targetType == "org" {
		numWorkers := 2
		packages, err = analyzer.AnalyzeOrg(ctx, target, &numWorkers)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("org analysis failed: %v", err))
		}
	} else {
		pkg, err := analyzer.AnalyzeRepo(ctx, target, "HEAD")
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("repo analysis failed: %v", err))
		}
		if pkg != nil {
			packages = []*models.PackageInsights{pkg}
		}
	}

	result.ReposAnalyzed = len(packages)

	// Convert findings
	convertFindings(result, packages)

	result.Duration = time.Since(start)
	result.Success = len(result.Errors) == 0

	return result, nil
}

// AnalyzeLocal performs analysis on a local filesystem path.
// This is used by Brisket for on-target scanning.
func AnalyzeLocal(ctx context.Context, path string) (*AnalysisResult, error) {
	start := time.Now()
	result := &AnalysisResult{
		Target:     path,
		TargetType: "local",
		Findings:   []Finding{},
		Errors:     []string{},
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}
	result.Target = absPath

	// Get repository name from environment if available
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		result.Repository = repo
	} else if repo := os.Getenv("CI_PROJECT_PATH"); repo != "" {
		result.Repository = repo
	}

	// Create config with offensive rules filter
	config := models.DefaultConfig()
	config.AllowedRules = OffensiveRules
	config.Quiet = true

	// Create OPA policy engine
	opaClient, err := opa.NewOpa(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize policy engine: %w", err)
	}

	// Create git client for local operations
	gitClient := gitops.NewGitClient(nil)
	localGitClient := &gitops.LocalGitClient{GitClient: gitClient}

	// Create local SCM client
	scmClient, err := local.NewGitSCMClient(ctx, absPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCM client: %w", err)
	}

	// Create analyzer with no-op formatter
	analyzer := analyze.NewAnalyzer(scmClient, localGitClient, &NoopFormatter{}, config, opaClient)

	// Run local repo analysis
	pkg, err := analyzer.AnalyzeLocalRepo(ctx, absPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("analysis failed: %v", err))
		result.Duration = time.Since(start)
		return result, nil
	}

	if pkg != nil {
		result.ReposAnalyzed = 1
		convertFindings(result, []*models.PackageInsights{pkg})
	}

	result.Duration = time.Since(start)
	result.Success = len(result.Errors) == 0

	return result, nil
}

// convertFindings converts poutine PackageInsights to our Finding format.
func convertFindings(result *AnalysisResult, packages []*models.PackageInsights) {
	findingCounter := 0
	seenRepos := make(map[string]bool)

	for _, pkg := range packages {
		if pkg == nil {
			continue
		}

		repoName := extractRepoFromPurl(pkg.Purl)
		if repoName != "" && !seenRepos[repoName] {
			seenRepos[repoName] = true
			result.AnalyzedRepos = append(result.AnalyzedRepos, repoName)
		}

		workflowVictims, repoVictims := buildWorkflowVictimIndex(pkg, repoName, cachepoison.CollectVictimCandidates)
		extractWorkflowMetaWithVictims(result, pkg, repoName, workflowVictims)

		if len(pkg.FindingsResults.Findings) == 0 {
			continue
		}

		for _, f := range pkg.FindingsResults.Findings {
			findingCounter++
			finding := Finding{
				ID:          fmt.Sprintf("V%03d", findingCounter),
				Repository:  repoName,
				Workflow:    f.Meta.Path,
				Line:        f.Meta.Line,
				RuleID:      f.RuleId,
				Job:         f.Meta.Job,
				Step:        f.Meta.Step,
				Details:     f.Meta.Details,
				Fingerprint: f.GenerateFindingFingerprint(),
			}

			if rule, ok := pkg.FindingsResults.Rules[f.RuleId]; ok {
				finding.Title = rule.Title
				finding.Description = rule.Description
				finding.Severity = mapSeverity(rule.Level)
			}

			finding.InjectionSources = f.Meta.InjectionSources
			finding.ReferencedSecrets = f.Meta.ReferencedSecrets
			finding.LOTPTool = f.Meta.LOTPTool
			finding.LOTPAction = f.Meta.LOTPAction
			finding.LOTPTargets = f.Meta.LOTPTargets

			if len(f.Meta.InjectionSources) > 0 {
				finding.Context = determineContextFromSources(f.Meta.InjectionSources)
				finding.Expression = "${{ " + f.Meta.InjectionSources[0] + " }}"
			} else {
				finding.Context = determineContext(f.RuleId, f.Meta)
				finding.Expression = extractExpression(f.Meta.Details)
			}
			finding.Trigger = extractTrigger(f.Meta.EventTriggers)
			finding.CachePoisonWriter, finding.CachePoisonReason = cachepoison.ClassifyWriterEligible(f.RuleId, finding.Trigger)
			if finding.CachePoisonWriter {
				finding.CachePoisonVictims = cloneVictimCandidates(repoVictims)
			}

			gate := extractGateForFinding(
				pkg.GithubActionsWorkflows,
				f.Meta.Path, f.Meta.Job, f.Meta.Step,
				f.Meta.InjectionSources,
			)
			if gate.Expression != "" {
				finding.GateRaw = gate.Expression
				if gate.Solvable {
					finding.GateTriggers = gate.Triggers
				} else {
					finding.GateUnsolvable = gate.Unsolvable
				}
			}

			result.Findings = append(result.Findings, finding)

			switch finding.Severity {
			case "critical":
				result.CriticalFindings++
			case "high":
				result.HighFindings++
			case "medium":
				result.MediumFindings++
			default:
				result.LowFindings++
			}
		}
	}

	result.TotalFindings = len(result.Findings)
}

func extractWorkflowMeta(result *AnalysisResult, pkg *models.PackageInsights, repoName string) {
	workflowVictims, _ := buildWorkflowVictimIndex(pkg, repoName, cachepoison.CollectVictimCandidates)
	extractWorkflowMetaWithVictims(result, pkg, repoName, workflowVictims)
}

func extractWorkflowMetaWithVictims(result *AnalysisResult, pkg *models.PackageInsights, repoName string, workflowVictims map[string][]cachepoison.VictimCandidate) {
	for _, wf := range pkg.GithubActionsWorkflows {
		if !strings.HasPrefix(wf.Path, ".github/workflows/") {
			continue
		}

		meta := WorkflowMeta{
			Repository: repoName,
			Path:       wf.Path,
			JobSecrets: make(map[string][]string),
		}
		meta.CachePoisonVictims = cloneVictimCandidates(workflowVictims[wf.Path])

		workflowSecrets := make(map[string]struct{})
		workflowHasOIDC := false
		workflowHasWrite := false

		for _, perm := range wf.Permissions {
			if perm.Scope == "id-token" && perm.Permission == "write" {
				workflowHasOIDC = true
				meta.HasOIDC = true
			}
			if perm.Permission == "write" {
				workflowHasWrite = true
				meta.HasWrite = true
			}
		}

		for _, env := range wf.Env {
			extractSecretsFromString(env.Value, workflowSecrets)
		}

		for _, job := range wf.Jobs {
			jobMeta := JobMeta{
				ID:          job.ID,
				DisplayName: job.Name,
			}
			jobSecretSet := make(map[string]struct{})

			for secret := range workflowSecrets {
				jobSecretSet[secret] = struct{}{}
			}

			jobMeta.HasOIDC = workflowHasOIDC
			jobMeta.HasWrite = workflowHasWrite

			for _, perm := range job.Permissions {
				if perm.Scope == "id-token" && perm.Permission == "write" {
					jobMeta.HasOIDC = true
					meta.HasOIDC = true
				}
				if perm.Scope == "contents" && perm.Permission == "write" {
					jobMeta.GitHubTokenRW = true
				}
				if perm.Permission == "write" {
					jobMeta.HasWrite = true
					meta.HasWrite = true
				}
			}

			for _, runsOn := range job.RunsOn {
				if strings.Contains(strings.ToLower(runsOn), "self-hosted") {
					jobMeta.SelfHosted = true
					meta.SelfHosted = true
				}
			}

			for _, env := range job.Env {
				extractSecretsFromString(env.Value, jobSecretSet)
			}

			for _, secret := range job.Secrets {
				if secret.Name != "" && secret.Name != "GITHUB_TOKEN" && secret.Name != "*ALL" {
					jobSecretSet[secret.Name] = struct{}{}
				}
				extractSecretsFromString(secret.Value, jobSecretSet)
			}

			for _, step := range job.Steps {
				extractSecretsFromString(step.Run, jobSecretSet)
				extractSecretsFromString(step.If, jobSecretSet)
				for _, env := range step.Env {
					extractSecretsFromString(env.Value, jobSecretSet)
				}
				for _, with := range step.With {
					extractSecretsFromString(with.Value, jobSecretSet)
				}

				if cloudAction := detectCloudAction(step.Uses, step.With); cloudAction != nil {
					jobMeta.CloudActions = append(jobMeta.CloudActions, *cloudAction)
				}

				if appAction := detectAppAction(step.Uses, step.With); appAction != nil {
					jobMeta.AppActions = append(jobMeta.AppActions, *appAction)
				}
			}

			jobMeta.SecretTypes = buildSecretTypes(job, jobMeta.AppActions)

			for secret := range jobSecretSet {
				jobMeta.Secrets = append(jobMeta.Secrets, secret)
				meta.Secrets = append(meta.Secrets, secret)
			}

			meta.JobSecrets[jobMeta.ID] = jobMeta.Secrets
			meta.Jobs = append(meta.Jobs, jobMeta)
		}

		uniqueSecrets := make(map[string]struct{})
		for _, s := range meta.Secrets {
			uniqueSecrets[s] = struct{}{}
		}
		meta.Secrets = nil
		for s := range uniqueSecrets {
			meta.Secrets = append(meta.Secrets, s)
		}

		mergedSecretTypes := make(map[string]string)
		for _, jobMeta := range meta.Jobs {
			for name, typ := range jobMeta.SecretTypes {
				mergedSecretTypes[name] = typ
			}
		}
		if len(mergedSecretTypes) > 0 {
			meta.SecretTypes = mergedSecretTypes
		}

		for _, jobMeta := range meta.Jobs {
			for _, app := range jobMeta.AppActions {
				if app.HardcodedAppID != "" {
					meta.HardcodedAppIDs = append(meta.HardcodedAppIDs, app.HardcodedAppID)
				}
			}
		}

		if len(meta.Jobs) > 0 || len(meta.Secrets) > 0 || meta.HasOIDC || meta.HasWrite || meta.SelfHosted {
			result.Workflows = append(result.Workflows, meta)
		}
	}
}

func buildWorkflowVictimIndex(pkg *models.PackageInsights, repoName string, collect func(string, string, models.GithubActionsWorkflow) []cachepoison.VictimCandidate) (map[string][]cachepoison.VictimCandidate, []cachepoison.VictimCandidate) {
	workflowVictims := make(map[string][]cachepoison.VictimCandidate)
	var repoVictims []cachepoison.VictimCandidate
	for _, wf := range pkg.GithubActionsWorkflows {
		if !strings.HasPrefix(wf.Path, ".github/workflows/") {
			continue
		}
		victims := collect(repoName, pkg.SourceGitRepoPath, wf)
		workflowVictims[wf.Path] = cloneVictimCandidates(victims)
		repoVictims = append(repoVictims, victims...)
	}
	return workflowVictims, repoVictims
}

func cloneVictimCandidates(victims []cachepoison.VictimCandidate) []cachepoison.VictimCandidate {
	if len(victims) == 0 {
		return nil
	}
	cloned := make([]cachepoison.VictimCandidate, len(victims))
	copy(cloned, victims)
	return cloned
}

func extractSecretsFromString(s string, secretSet map[string]struct{}) {
	idx := 0
	for {
		start := strings.Index(s[idx:], "secrets.")
		if start == -1 {
			break
		}
		start += idx

		nameStart := start + len("secrets.")
		if nameStart >= len(s) {
			break
		}

		nameEnd := nameStart
		for nameEnd < len(s) {
			c := s[nameEnd]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
				nameEnd++
			} else {
				break
			}
		}

		if nameEnd > nameStart {
			name := s[nameStart:nameEnd]
			if name != "GITHUB_TOKEN" {
				secretSet[name] = struct{}{}
			}
		}

		idx = nameEnd
		if idx >= len(s) {
			break
		}
	}
}

// mapSeverity maps poutine severity levels to our severity scale.
func mapSeverity(level string) string {
	switch level {
	case "error":
		return "critical"
	case "warning":
		return "high"
	case "note":
		return "medium"
	default:
		return "low"
	}
}

func determineContextFromSources(sources []string) string {
	if len(sources) == 0 {
		return "unknown"
	}
	src := strings.ToLower(sources[0])
	switch {
	case strings.Contains(src, "github.event.inputs."):
		return "workflow_dispatch_input"
	case strings.Contains(src, "github.head_ref"):
		return "git_branch"
	case strings.Contains(src, "pull_request.title"):
		return "pr_title"
	case strings.Contains(src, "pull_request.body"):
		return "pr_body"
	case strings.Contains(src, "pull_request.head.ref"):
		return "git_branch"
	case strings.Contains(src, "issue.title"):
		return "issue_title"
	case strings.Contains(src, "issue.body"):
		return "issue_body"
	case strings.Contains(src, "comment.body"):
		return "comment_body"
	case strings.Contains(src, "commits") && strings.Contains(src, "message"):
		return "commit_message"
	default:
		return "bash_run"
	}
}

// determineContext determines the injection context from rule and metadata.
func determineContext(ruleID string, meta results.FindingMeta) string {
	details := strings.ToLower(meta.Details)

	switch {
	case strings.Contains(details, "actions/github-script") ||
		(strings.Contains(details, "github.event") && strings.Contains(details, "script")):
		return "github_script"
	case strings.Contains(details, "github.head_ref") ||
		strings.Contains(details, "branch"):
		return "git_branch"
	case strings.Contains(details, "pull_request.title") ||
		strings.Contains(details, "pr title"):
		return "pr_title"
	case strings.Contains(details, "pull_request.body") ||
		strings.Contains(details, "pr body"):
		return "pr_body"
	case strings.Contains(details, "comment.body"):
		return "comment_body"
	case strings.Contains(details, "issue.title"):
		return "issue_title"
	case strings.Contains(details, "issue.body"):
		return "issue_body"
	case strings.Contains(details, "commit") && strings.Contains(details, "message"):
		return "commit_message"
	}

	// Default based on rule type
	switch ruleID {
	case "injection":
		return "bash_run"
	case "untrusted_checkout_exec":
		return "untrusted_checkout"
	}

	return "unknown"
}

// extractTrigger returns the workflow trigger from EventTriggers slice.
func extractTrigger(eventTriggers []string) string {
	if len(eventTriggers) == 0 {
		return "unknown"
	}
	return strings.Join(eventTriggers, ", ")
}

// extractExpression extracts the vulnerable expression from details.
// Poutine formats Details as "Sources: github.event.issue.body github.event.issue.title"
// For non-injection rules, returns the details as-is (e.g., "Detected usage of `make`")
func extractExpression(details string) string {
	if strings.HasPrefix(details, "Sources: ") {
		sources := strings.TrimPrefix(details, "Sources: ")
		parts := strings.Fields(sources)
		if len(parts) > 0 {
			return "${{ " + parts[0] + " }}"
		}
		return ""
	}

	start := strings.Index(details, "${{")
	if start != -1 {
		end := strings.Index(details[start:], "}}")
		if end == -1 {
			return details[start:]
		}
		return details[start : start+end+2]
	}

	if strings.HasPrefix(details, "Detected usage") {
		return details
	}

	return ""
}

// extractRepoFromPurl extracts the repository name from a purl string.
func extractRepoFromPurl(purl string) string {
	// purl format: pkg:github/org/repo or pkg:github/org/repo@version
	if strings.HasPrefix(purl, "pkg:github/") {
		rest := strings.TrimPrefix(purl, "pkg:github/")
		// Remove version if present
		if idx := strings.Index(rest, "@"); idx != -1 {
			rest = rest[:idx]
		}
		// Remove query params if present
		if idx := strings.Index(rest, "?"); idx != -1 {
			rest = rest[:idx]
		}
		return rest
	}
	return purl
}

// Cloud action detection patterns
var cloudActionPatterns = map[string]struct {
	provider   string
	inputNames []string
}{
	"aws-actions/configure-aws-credentials": {
		provider: CloudProviderAWS,
		inputNames: []string{
			"role-to-assume", "aws-region", "role-session-name", "audience",
			"role-duration-seconds", "role-external-id", "role-chaining", "inline-session-policy",
		},
	},
	"google-github-actions/auth": {
		provider: CloudProviderGCP,
		inputNames: []string{
			"workload_identity_provider", "service_account",
			"project_id", "token_format", "audience",
			"delegates", "access_token_lifetime", "access_token_scopes",
		},
	},
	"azure/login": {
		provider: CloudProviderAzure,
		inputNames: []string{
			"client-id", "tenant-id", "subscription-id", "audience",
			"environment", "auth-type",
		},
	},
}

// detectCloudAction checks if a step uses a known cloud provider action.
func detectCloudAction(uses string, with []models.GithubActionsEnv) *CloudAction {
	if uses == "" {
		return nil
	}

	actionName, version := parseActionReference(uses)
	pattern, ok := cloudActionPatterns[actionName]
	if !ok {
		return nil
	}

	inputs := make(map[string]string)
	for _, env := range with {
		for _, wanted := range pattern.inputNames {
			if env.Name == wanted && env.Value != "" {
				inputs[env.Name] = env.Value
			}
		}
	}

	return &CloudAction{
		Provider: pattern.provider,
		Action:   actionName,
		Version:  version,
		Inputs:   inputs,
	}
}

// parseActionReference splits "owner/repo@version" into action name and version.
func parseActionReference(uses string) (action, version string) {
	if idx := strings.Index(uses, "@"); idx != -1 {
		return uses[:idx], uses[idx+1:]
	}
	return uses, ""
}

var appActionPatterns = map[string]struct {
	privateKeyInput string
	appIDInput      string
}{
	"actions/create-github-app-token":                {"private-key", "app-id"},
	"tibdex/github-app-token":                        {"private_key", "app_id"},
	"peter-murray/workflow-application-token-action": {"application_private_key", "application_id"},
}

func detectAppAction(uses string, with []models.GithubActionsEnv) *AppAction {
	if uses == "" {
		return nil
	}

	actionName, version := parseActionReference(uses)
	pattern, ok := appActionPatterns[actionName]
	if !ok {
		return nil
	}

	app := &AppAction{
		Action:  actionName,
		Version: version,
	}

	for _, env := range with {
		switch env.Name {
		case pattern.privateKeyInput:
			app.PrivateKey = extractSecretRef(env.Value)
		case pattern.appIDInput:
			if id := extractLiteralAppID(env.Value); id != "" {
				app.HardcodedAppID = id
			} else if ref := extractSecretRef(env.Value); ref != "" {
				app.AppID = ref
			}
		}
	}

	return app
}

func extractSecretRef(value string) string {
	s := strings.TrimSpace(value)
	s = strings.TrimPrefix(s, "${{")
	s = strings.TrimSuffix(s, "}}")
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "secrets.")
	if s == value || s == "" {
		return ""
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return ""
		}
	}
	return s
}

func extractLiteralAppID(value string) string {
	s := strings.TrimSpace(value)
	if s == "" {
		return ""
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return s
}

func buildSecretTypes(job models.GithubActionsJob, appActions []AppAction) map[string]string {
	if len(appActions) == 0 {
		return nil
	}

	secretNameToType := make(map[string]string)
	for _, app := range appActions {
		if app.PrivateKey != "" {
			secretNameToType[app.PrivateKey] = "github_app_key"
		}
		if app.AppID != "" {
			secretNameToType[app.AppID] = "github_app_id"
		}
	}

	for _, step := range job.Steps {
		for _, env := range step.Env {
			if ref := extractSecretRef(env.Value); ref != "" {
				if typ, ok := secretNameToType[ref]; ok {
					secretNameToType[env.Name] = typ
				}
			}
		}
	}

	return secretNameToType
}
