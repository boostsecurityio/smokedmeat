// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func (m Model) handleAnalyzeCommand() (tea.Model, tea.Cmd) {
	return m.handleAnalyzeForTarget(m.target, m.targetType, false, false)
}

func (m Model) handleDeepAnalyzeCommand() (tea.Model, tea.Cmd) {
	return m.handleAnalyzeForTarget(m.target, m.targetType, true, false)
}

func (m Model) handleAnalyzeForSelection(scopeType, scope string, deep bool) (tea.Model, tea.Cmd) {
	if strings.TrimSpace(scope) == "" {
		m.AddOutput("error", "Select an org or repo in the tree first.")
		return m, nil
	}
	current := m.currentTargetSpec()
	requested := scopeType + ":" + scope
	if current != "" && current != requested {
		m.AddOutput("info", fmt.Sprintf("Using selected %s (current target stays %s)", requested, current))
	} else {
		m.AddOutput("info", fmt.Sprintf("Using selected %s", requested))
	}
	return m.handleAnalyzeForTarget(scope, scopeType, deep, true)
}

func (m Model) handleAnalyzeForTarget(target, targetType string, deep, selection bool) (tea.Model, tea.Cmd) {
	if m.config.KitchenURL == "" {
		m.AddOutput("error", "Kitchen URL not set. Use 'set kitchen <url>' first.")
		return m, nil
	}
	if m.tokenInfo == nil {
		m.AddOutput("error", "GitHub token not set. Try 'set token' (Tab for options)")
		return m, nil
	}
	target = strings.TrimSpace(target)
	targetType = strings.TrimSpace(targetType)
	if target == "" {
		m.AddOutput("error", "Target not set. Use 'set target org:<name>' first.")
		return m, nil
	}
	if targetType == "" {
		targetType = "org"
	}
	targetSpec := targetType + ":" + target

	m.analysisFocusRepo = ""

	m.AddOutput("info", "")
	if deep {
		m.AddOutput("info", fmt.Sprintf("Starting deep analysis (poutine + gitleaks) via Kitchen (%s)...", m.config.KitchenURL))
		m.AddOutput("info", "Scanning for private keys and secrets — this may take longer than 'analyze'.")
		switch targetType {
		case "repo":
			m.AddOutput("info", fmt.Sprintf("Repo target: %s", target))
			m.analysisFocusRepo = target
		case "org":
			if selection {
				repos := m.knownReposForOwner(target, false)
				if len(repos) == 0 {
					m.AddOutput("error", fmt.Sprintf("No discovered repos found for org %s", target))
					return m, nil
				}
				m.AddOutput("info", fmt.Sprintf("Org selection: deep-analyzing %d discovered repos in %s", len(repos), target))
				m.activityLog.Add(IconScan, fmt.Sprintf("Starting deep analysis of %d repos in %s", len(repos), target))
				m.flashMessage = "Deep-analyzing " + target
				m.flashUntil = time.Now().Add(2 * time.Second)
				return m, m.runDeepAnalysisForTargets(repos, target)
			}
			m.AddOutput("info", "Tip: deep-analyze is most useful on a single repo. Highlight a repo and press 'd', or run 'set target repo:owner/repo'.")
		}
		m.activityLog.Add(IconScan, fmt.Sprintf("Starting deep analysis of %s", targetSpec))
		m.flashMessage = "Deep-analyzing " + target
		m.flashUntil = time.Now().Add(2 * time.Second)
		return m, m.runDeepAnalysisForTarget(target, targetType)
	}

	m.AddOutput("info", fmt.Sprintf("Starting poutine analysis via Kitchen (%s)...", m.config.KitchenURL))
	m.activityLog.Add(IconScan, fmt.Sprintf("Starting analysis of %s", targetSpec))
	m.flashMessage = "Analyzing " + target
	m.flashUntil = time.Now().Add(2 * time.Second)

	return m, m.runAnalysisForTarget(target, targetType)
}

func (m Model) runDeepAnalysisForTarget(target, targetType string) tea.Cmd {
	token := ""
	if m.tokenInfo != nil {
		token = m.tokenInfo.Value
	}

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		client := counter.NewClient(m.config.KitchenURL, m.config.AuthToken, m.config.SessionID)
		result, err := client.DeepAnalyze(ctx, token, target, targetType)
		if err != nil {
			return AnalysisErrorMsg{Err: err}
		}

		return AnalysisCompletedMsg{Result: result, Deep: true}
	}
}

func (m Model) runDeepAnalysisForTargets(repos []string, owner string) tea.Cmd {
	token := ""
	if m.tokenInfo != nil {
		token = m.tokenInfo.Value
	}

	targets := append([]string(nil), repos...)

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		client := counter.NewClient(m.config.KitchenURL, m.config.AuthToken, m.config.SessionID)

		started := time.Now()
		result := &poutine.AnalysisResult{
			Success:    true,
			Target:     owner,
			TargetType: "org",
		}

		for _, repo := range targets {
			repoResult, err := client.DeepAnalyze(ctx, token, repo, "repo")
			if err != nil {
				result.Success = false
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", repo, err))
				continue
			}
			result.ReposAnalyzed += repoResult.ReposAnalyzed
			result.TotalFindings += repoResult.TotalFindings
			result.CriticalFindings += repoResult.CriticalFindings
			result.HighFindings += repoResult.HighFindings
			result.MediumFindings += repoResult.MediumFindings
			result.LowFindings += repoResult.LowFindings
			result.Findings = append(result.Findings, repoResult.Findings...)
			result.Workflows = append(result.Workflows, repoResult.Workflows...)
			result.AnalyzedRepos = append(result.AnalyzedRepos, repoResult.AnalyzedRepos...)
			result.SecretFindings = append(result.SecretFindings, repoResult.SecretFindings...)
			result.Errors = append(result.Errors, repoResult.Errors...)
		}

		result.Duration = time.Since(started)
		return AnalysisCompletedMsg{Result: result, Deep: true}
	}
}

func (m Model) handleAnalyzePivotsCommand() (tea.Model, tea.Cmd) {
	if len(m.pivotTargets) == 0 {
		m.AddOutput("warning", "No pivot targets discovered yet.")
		m.AddOutput("info", "Use 'pivot github' to discover accessible repos first.")
		return m, nil
	}

	if m.config.KitchenURL == "" {
		m.AddOutput("error", "Kitchen URL not set. Use 'set kitchen <url>' first.")
		return m, nil
	}
	if m.tokenInfo == nil {
		m.AddOutput("error", "GitHub token not set. Try 'set token' (Tab for options)")
		return m, nil
	}

	m.AddOutput("info", "")
	m.AddOutput("info", fmt.Sprintf("Queuing analysis for %d pivot targets...", len(m.pivotTargets)))
	m.activityLog.Add(IconInfo, fmt.Sprintf("Analyzing %d pivot repos", len(m.pivotTargets)))
	m.flashMessage = fmt.Sprintf("Analyzing %d pivot repo(s)", len(m.pivotTargets))
	m.flashUntil = time.Now().Add(2 * time.Second)

	return m, m.runPivotAnalysis()
}

func (m Model) runPivotAnalysis() tea.Cmd {
	token := ""
	if m.tokenInfo != nil {
		token = m.tokenInfo.Value
	}

	targets := make([]string, len(m.pivotTargets))
	copy(targets, m.pivotTargets)

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		client := counter.NewClient(m.config.KitchenURL, m.config.AuthToken, m.config.SessionID)

		var allFindings []poutine.Finding
		var allWorkflows []poutine.WorkflowMeta
		var allAnalyzedRepos []string
		analyzed := 0

		for _, target := range targets {
			result, err := client.Analyze(ctx, token, target, "repo")
			if err != nil {
				continue
			}
			analyzed++
			allFindings = append(allFindings, result.Findings...)
			allWorkflows = append(allWorkflows, result.Workflows...)
			allAnalyzedRepos = append(allAnalyzedRepos, result.AnalyzedRepos...)
		}

		return AnalysisCompletedMsg{
			Result: &poutine.AnalysisResult{
				Success:       true,
				Target:        fmt.Sprintf("%d pivot repos", len(targets)),
				ReposAnalyzed: analyzed,
				TotalFindings: len(allFindings),
				Findings:      allFindings,
				Workflows:     allWorkflows,
				AnalyzedRepos: allAnalyzedRepos,
			},
		}
	}
}

func (m Model) runAnalysis() tea.Cmd {
	return m.runAnalysisForTarget(m.target, m.targetType)
}

func (m Model) runAnalysisForTarget(target, targetType string) tea.Cmd {
	token := ""
	if m.tokenInfo != nil {
		token = m.tokenInfo.Value
	}

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		client := counter.NewClient(m.config.KitchenURL, m.config.AuthToken, m.config.SessionID)
		result, err := client.Analyze(ctx, token, target, targetType)
		if err != nil {
			return AnalysisErrorMsg{Err: err}
		}

		return AnalysisCompletedMsg{Result: result}
	}
}

func (m *Model) handleGraphCommand() {
	kitchenURL := m.config.BrowserURL()
	if kitchenURL == "" {
		m.activityLog.Add(IconError, "Kitchen URL not set")
		return
	}

	graphURL := strings.TrimSuffix(kitchenURL, "/") + "/graph"
	if m.config.AuthToken != "" {
		graphURL += "?token=" + m.config.AuthToken
	}

	if err := m.openBrowser(graphURL); err != nil {
		m.activityLog.Add(IconInfo, Hyperlink(graphURL, "Click to open graph →"))
	} else {
		m.activityLog.Add(IconSuccess, "Opened graph in browser")
	}
}

func (m *Model) openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform")
	}
	return cmd.Start()
}

func (m Model) handleAnalysisCompleted(msg AnalysisCompletedMsg) (tea.Model, tea.Cmd) {
	result := msg.Result

	m.analysisComplete = true

	m.AddOutput("info", "")
	if result.Success && len(result.Errors) == 0 {
		m.AddOutput("success", fmt.Sprintf("Analysis completed in %s", result.Duration.Round(time.Second)))
	} else {
		if result.Success {
			m.AddOutput("success", fmt.Sprintf("Analysis completed in %s (with warnings)", result.Duration.Round(time.Second)))
		} else {
			m.AddOutput("warning", fmt.Sprintf("Analysis completed with errors in %s", result.Duration.Round(time.Second)))
		}
		for _, e := range result.Errors {
			m.AddOutput("error", "  "+e)
		}
	}

	m.AddOutput("info", fmt.Sprintf("Repositories analyzed: %d", result.ReposAnalyzed))

	for _, wf := range result.Workflows {
		for name, typ := range wf.SecretTypes {
			m.workflowSecretTypes[name] = typ
		}
		m.hardcodedAppIDs = append(m.hardcodedAppIDs, wf.HardcodedAppIDs...)
	}

	m.reclassifyLootTypes()
	m.pairGitHubAppCredentials()

	if m.kitchenClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := m.kitchenClient.FetchPantry(ctx)
		cancel()
		if err == nil && p != nil {
			m.pantry = p
		}
	}

	summary := m.importAnalysisToPantry(result)
	if summary.Total > 0 {
		m.activityLog.Add(IconScan, "Imported "+summary.String())
		m.AddOutput("info", "")
		m.AddOutput("success", "Imported to attack graph: "+summary.String())
	}

	supportedCount := 0
	for _, f := range result.Findings {
		if supported, _ := pantry.VulnerabilityExploitSupport("github", f.Workflow, f.RuleID); supported {
			supportedCount++
		}
	}
	analyzeOnlyCount := len(result.Findings) - supportedCount

	if len(result.Findings) == 0 {
		m.AddOutput("info", "No exploitable vulnerabilities found.")
	} else {
		switch {
		case supportedCount == 0:
			noun := "findings"
			if analyzeOnlyCount == 1 {
				noun = "finding"
			}
			m.AddOutput("info", fmt.Sprintf("Found %d analyze-only %s", analyzeOnlyCount, noun))
		case analyzeOnlyCount == 0:
			noun := "vulnerabilities"
			if supportedCount == 1 {
				noun = "vulnerability"
			}
			m.AddOutput("warning", fmt.Sprintf("Found %d exploitable %s", supportedCount, noun))
		default:
			vulnNoun := "vulnerabilities"
			if supportedCount == 1 {
				vulnNoun = "vulnerability"
			}
			findingNoun := "findings"
			if analyzeOnlyCount == 1 {
				findingNoun = "finding"
			}
			m.AddOutput("warning", fmt.Sprintf("Found %d exploitable %s and %d analyze-only %s", supportedCount, vulnNoun, analyzeOnlyCount, findingNoun))
		}

		existing := make(map[string]bool, len(m.vulnerabilities))
		for _, v := range m.vulnerabilities {
			existing[vulnerabilityDedupKey(v)] = true
		}
		nextVulnID := nextVulnerabilityOrdinal(m.vulnerabilities)
		for _, f := range result.Findings {
			key := findingDedupKey(f)
			if existing[key] {
				continue
			}
			supported, reason := pantry.VulnerabilityExploitSupport("github", f.Workflow, f.RuleID)
			vulnID := fmt.Sprintf("V%03d", nextVulnID)
			nextVulnID++
			m.vulnerabilities = append(m.vulnerabilities, Vulnerability{
				ID:                   vulnID,
				Fingerprint:          f.Fingerprint,
				Repository:           f.Repository,
				Workflow:             f.Workflow,
				Job:                  f.Job,
				Line:                 f.Line,
				Title:                f.Title,
				RuleID:               f.RuleID,
				Context:              f.Context,
				Trigger:              f.Trigger,
				Expression:           f.Expression,
				Severity:             f.Severity,
				InjectionSources:     f.InjectionSources,
				ReferencedSecrets:    f.ReferencedSecrets,
				LOTPTool:             f.LOTPTool,
				LOTPAction:           f.LOTPAction,
				LOTPTargets:          f.LOTPTargets,
				CachePoisonWriter:    f.CachePoisonWriter,
				CachePoisonReason:    f.CachePoisonReason,
				CachePoisonVictims:   append([]cachepoison.VictimCandidate(nil), f.CachePoisonVictims...),
				GateTriggers:         f.GateTriggers,
				GateRaw:              f.GateRaw,
				GateUnsolvable:       f.GateUnsolvable,
				ExploitSupported:     supported,
				ExploitSupportReason: reason,
			})
			existing[key] = true
		}
	}

	if len(result.SecretFindings) > 0 {
		m.AddOutput("info", "")
		m.AddOutput("warning", fmt.Sprintf("Found %d secrets (private keys / credentials)", len(result.SecretFindings)))
		for _, sf := range result.SecretFindings {
			m.AddOutput("info", fmt.Sprintf("  [%s] %s:%d", sf.RuleID, sf.File, sf.StartLine))
			secret := CollectedSecret{
				Name:        fmt.Sprintf("%s (%s:%d)", sf.Description, sf.File, sf.StartLine),
				Value:       sf.Secret,
				Source:      analysisSecretSource(sf),
				Repository:  sf.Repository,
				Workflow:    sf.File,
				Type:        gitleaksRuleToType(sf.RuleID),
				CollectedAt: time.Now(),
			}
			if secret.Type == "private_key" {
				secret.KeyType, secret.KeyFingerprint, _ = sshPrivateKeyMetadata(secret.Value)
			}
			m.AddToLootStash(secret)
		}
		m.activityLog.Add(IconSecret, fmt.Sprintf("Gitleaks: %d secrets found", len(result.SecretFindings)))
	}

	m.fetchKnownEntitiesFromKitchen()

	if len(m.vulnerabilities) > 0 {
		selected := 0
		for i := range m.vulnerabilities {
			if vulnerabilitySupportsExploit(&m.vulnerabilities[i]) {
				selected = i
				break
			}
		}
		m.selectedVuln = selected
		if vulnerabilitySupportsExploit(&m.vulnerabilities[selected]) {
			m.AddOutput("info", fmt.Sprintf("Selected: %s. Press 1-5 for suggested actions or 'use <id>'.", m.vulnerabilities[selected].ID))
		} else {
			m.AddOutput("info", fmt.Sprintf("Selected: %s. Analyze-only finding. Use 'use <id>' to inspect findings.", m.vulnerabilities[selected].ID))
		}
	}

	m.updatePlaceholder()

	m.GenerateSuggestions()
	m.RebuildTree()
	return m, nil
}

func findingDedupKey(f poutine.Finding) string {
	if fp := strings.TrimSpace(f.Fingerprint); fp != "" {
		return fp
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s", f.Repository, f.Workflow, f.Job, f.Line, f.RuleID, f.Context, f.Expression)
}

func vulnerabilityDedupKey(v Vulnerability) string {
	if fp := strings.TrimSpace(v.Fingerprint); fp != "" {
		return fp
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s", v.Repository, v.Workflow, v.Job, v.Line, v.RuleID, v.Context, v.Expression)
}

func nextVulnerabilityOrdinal(vulns []Vulnerability) int {
	maxOrdinal := 0
	for _, v := range vulns {
		if !strings.HasPrefix(v.ID, "V") {
			continue
		}
		ordinal, err := strconv.Atoi(strings.TrimPrefix(v.ID, "V"))
		if err != nil || ordinal > maxOrdinal {
			if err == nil {
				maxOrdinal = ordinal
			}
		}
	}
	return maxOrdinal + 1
}

func (m *Model) fetchKnownEntitiesFromKitchen() {
	if m.kitchenClient == nil || m.config.SessionID == "" {
		return
	}
	if m.knownEntities == nil {
		m.knownEntities = make(map[string]*KnownEntity)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entities, err := m.kitchenClient.FetchKnownEntities(ctx, m.config.SessionID)
	if err != nil {
		slog.Debug("failed to fetch known entities from Kitchen", "error", err)
		return
	}

	for _, e := range entities {
		m.knownEntities[e.ID] = &KnownEntity{
			ID:            e.ID,
			EntityType:    e.EntityType,
			Name:          e.Name,
			DiscoveredVia: e.DiscoveredVia,
			IsPrivate:     e.IsPrivate,
			Permissions:   e.Permissions,
			SSHPermission: e.SSHPermission,
		}
	}
}

func gitleaksRuleToType(ruleID string) string {
	switch ruleID {
	case "private-key":
		return "private_key"
	case "pkcs12-file":
		return "pkcs12"
	case "github-pat", "github-fine-grained-pat":
		return "github_pat"
	}
	slog.Warn("unknown gitleaks rule ID", "rule_id", ruleID)
	return ruleID
}

func analysisSecretSource(sf poutine.SecretFinding) string {
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

func isEphemeralSecretName(name string) bool {
	ephemeral := []string{
		"GITHUB_TOKEN",
		"ACTIONS_RUNTIME_TOKEN",
		"ACTIONS_ID_TOKEN",
		"ACTIONS_CACHE_URL",
		"CI_JOB_TOKEN",
		"RUNNER_TOKEN",
	}
	for _, e := range ephemeral {
		if name == e {
			return true
		}
	}
	return false
}

func scopesForSecretType(secretType models.SecretType) []string {
	switch secretType {
	case models.SecretTypeGitHub:
		return []string{"repo", "workflow"}
	case models.SecretTypeAWS:
		return []string{"cloud:aws"}
	case models.SecretTypeGCP:
		return []string{"cloud:gcp"}
	case models.SecretTypeAzure:
		return []string{"cloud:azure"}
	case models.SecretTypeNPM:
		return []string{"package:npm"}
	case models.SecretTypeDocker:
		return []string{"registry:docker"}
	case models.SecretTypeSSH:
		return []string{"access:ssh"}
	default:
		return nil
	}
}

func (m Model) fetchHistoryCmd() tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return HistoryFetchErrorMsg{Err: fmt.Errorf("not connected to kitchen")}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		entries, err := m.kitchenClient.FetchHistory(ctx, 100)
		if err != nil {
			return HistoryFetchErrorMsg{Err: err}
		}

		historyEntries := make([]HistoryEntry, len(entries))
		for i, e := range entries {
			historyEntries[i] = HistoryEntry{
				ID:          e.ID,
				Type:        e.Type,
				Timestamp:   e.Timestamp,
				SessionID:   e.SessionID,
				Target:      e.Target,
				TargetType:  e.TargetType,
				TokenType:   e.TokenType,
				VulnID:      e.VulnID,
				Repository:  e.Repository,
				StagerID:    e.StagerID,
				PRURL:       e.PRURL,
				Outcome:     e.Outcome,
				ErrorDetail: e.ErrorDetail,
				AgentID:     e.AgentID,
			}
		}

		return HistoryFetchedMsg{Entries: historyEntries}
	}
}

func (m Model) recordHistoryCmd(entry counter.HistoryPayload) tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := m.kitchenClient.RecordHistory(ctx, entry); err != nil {
			return HistoryRecordErrorMsg{Err: err}
		}
		return nil
	}
}

func timerTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return TimerTickMsg{} })
}
