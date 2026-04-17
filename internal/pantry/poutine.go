// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"fmt"
	"strings"
)

// OffensiveRules is the allowlist of poutine rules relevant for red teaming.
// These represent juicy vulnerabilities, not warnings.
var OffensiveRules = []string{
	// Critical: Direct code execution
	"untrusted_checkout_exec",
	"injection",
	"pr_runs_on_self_hosted",

	// High: Secret exposure and runner compromise
	"debug_enabled",
	"unverified_script_exec",
	"known_vulnerability_in_runner",

	// Medium: Excessive permissions
	"excessive_permissions",
	"unpinned_action",

	// Reconnaissance value
	"github_action_from_unverified_creator",
	"default_permissions_on_risky_events",
}

// IsOffensiveRule checks if a rule ID is in the offensive allowlist.
func IsOffensiveRule(ruleID string) bool {
	for _, r := range OffensiveRules {
		if r == ruleID {
			return true
		}
	}
	return false
}

// FindingMeta contains location and context for a finding.
type FindingMeta struct {
	Path          string   `json:"path"`
	Line          int      `json:"line"`
	Job           string   `json:"job,omitempty"`
	Step          string   `json:"step,omitempty"`
	Details       string   `json:"details,omitempty"`
	EventTriggers []string `json:"event_triggers,omitempty"`
	LOTPTool      string   `json:"lotp_tool,omitempty"`
	LOTPAction    string   `json:"lotp_action,omitempty"`
	LOTPTargets   []string `json:"lotp_targets,omitempty"`
}

// FindingResult represents a single poutine finding.
// This mirrors poutine's internal format for compatibility.
type FindingResult struct {
	RuleID   string      `json:"rule_id"`
	Purl     string      `json:"purl"`
	Meta     FindingMeta `json:"meta"`
	Severity string      `json:"severity,omitempty"`
}

// PackageInsights represents poutine scan results for a repository.
// This mirrors poutine's PackageInsights type.
type PackageInsights struct {
	Purl            string          `json:"purl"`
	FindingsResults []FindingResult `json:"findings_results"`
}

// ParsePurl extracts org and repo from a Package URL.
// Format: pkg:github/owner/repo or pkg:gitlab/owner/repo
func ParsePurl(purl string) (provider, org, repo string) {
	// Remove pkg: prefix
	purl = strings.TrimPrefix(purl, "pkg:")

	parts := strings.SplitN(purl, "/", 3)
	if len(parts) < 3 {
		return "", "", ""
	}

	provider = parts[0]
	org = parts[1]
	repo = parts[2]

	// Remove any version suffix (@ref)
	if idx := strings.Index(repo, "@"); idx != -1 {
		repo = repo[:idx]
	}

	return provider, org, repo
}

// ImportPoutineFindings converts poutine results to Pantry assets.
// Only imports findings that match the offensive rules allowlist.
func (p *Pantry) ImportPoutineFindings(insights *PackageInsights) error {
	if insights == nil {
		return nil
	}

	// Parse repository info from Purl
	provider, org, repoName := ParsePurl(insights.Purl)
	if provider == "" {
		provider = "github" // default
	}

	// Create organization asset if it doesn't exist
	orgID := fmt.Sprintf("%s:org:%s", provider, org)
	if !p.HasAsset(orgID) {
		orgAsset := NewOrganization(org, provider)
		if err := p.AddAsset(orgAsset); err != nil {
			return fmt.Errorf("failed to add organization: %w", err)
		}
	}

	// Create repository asset
	repo := NewRepository(org, repoName, provider)
	if err := p.AddAsset(repo); err != nil {
		return fmt.Errorf("failed to add repository: %w", err)
	}

	// Connect org -> repo
	_ = p.AddRelationship(orgID, repo.ID, Contains())

	// Track workflows to avoid duplicates
	workflowAssets := make(map[string]Asset)

	// Import each finding as a vulnerability asset
	for _, finding := range insights.FindingsResults {
		// Filter to offensive rules only
		if !IsOffensiveRule(finding.RuleID) {
			continue
		}

		// Create workflow asset if we haven't seen this path
		workflowID := ""
		if finding.Meta.Path != "" {
			if _, exists := workflowAssets[finding.Meta.Path]; !exists {
				workflow := NewWorkflow(repo.ID, finding.Meta.Path)
				if err := p.AddAsset(workflow); err == nil {
					workflowAssets[finding.Meta.Path] = workflow

					// Connect repo -> workflow
					_ = p.AddRelationship(repo.ID, workflow.ID, Contains())
				}
			}
			if wf, exists := workflowAssets[finding.Meta.Path]; exists {
				workflowID = wf.ID
			}
		}

		// Create vulnerability asset
		vuln := NewVulnerability(
			finding.RuleID,
			finding.Purl,
			finding.Meta.Path,
			finding.Meta.Line,
		)

		// Override severity if provided
		if finding.Severity != "" {
			vuln.Severity = finding.Severity
		}

		// Store additional context
		if finding.Meta.Job != "" {
			vuln.SetProperty("job", finding.Meta.Job)
		}
		if finding.Meta.Step != "" {
			vuln.SetProperty("step", finding.Meta.Step)
		}
		if finding.Meta.Details != "" {
			vuln.SetProperty("details", finding.Meta.Details)
		}
		if len(finding.Meta.EventTriggers) > 0 {
			vuln.SetProperty("event_triggers", finding.Meta.EventTriggers)
		}
		if finding.Meta.LOTPTool != "" {
			vuln.SetProperty("lotp_tool", finding.Meta.LOTPTool)
		}
		if finding.Meta.LOTPAction != "" {
			vuln.SetProperty("lotp_action", finding.Meta.LOTPAction)
		}
		if len(finding.Meta.LOTPTargets) > 0 {
			vuln.SetProperty("lotp_targets", finding.Meta.LOTPTargets)
		}
		SetVulnerabilityExploitSupport(&vuln)

		if err := p.AddAsset(vuln); err != nil {
			continue
		}

		// Create relationship: workflow -vulnerable_to-> vulnerability
		if workflowID != "" {
			rel := VulnerableTo(finding.RuleID, vuln.Severity)
			_ = p.AddRelationship(workflowID, vuln.ID, rel)
		} else {
			// Connect directly to repo if no workflow path
			rel := VulnerableTo(finding.RuleID, vuln.Severity)
			_ = p.AddRelationship(repo.ID, vuln.ID, rel)
		}
	}

	return nil
}

// ImportFindingsBatch imports multiple PackageInsights at once.
func (p *Pantry) ImportFindingsBatch(allInsights []*PackageInsights) error {
	for _, insights := range allInsights {
		if err := p.ImportPoutineFindings(insights); err != nil {
			// Log but continue with other packages
			continue
		}
	}
	return nil
}
