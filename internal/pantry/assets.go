// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pantry implements attack surface graph storage.
package pantry

import (
	"fmt"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/bashctx"
)

// AssetType represents the type of discovered asset.
type AssetType string

const (
	AssetOrganization  AssetType = "organization"
	AssetRepository    AssetType = "repository"
	AssetWorkflow      AssetType = "workflow"
	AssetJob           AssetType = "job"
	AssetSecret        AssetType = "secret"
	AssetToken         AssetType = "token"
	AssetCloud         AssetType = "cloud"
	AssetAgent         AssetType = "agent"
	AssetVulnerability AssetType = "vulnerability"
)

// AssetState indicates the operational state of an asset.
type AssetState string

const (
	StateNew       AssetState = "new"        // Just discovered
	StateValidated AssetState = "validated"  // Confirmed exploitable
	StateExploited AssetState = "exploited"  // Successfully exploited
	StateDeadEnd   AssetState = "dead_end"   // Not exploitable
	StateHighValue AssetState = "high_value" // Priority target
)

// Asset represents a node in the attack graph.
type Asset struct {
	ID           string         `json:"id"`
	Type         AssetType      `json:"type"`
	Name         string         `json:"name"`
	State        AssetState     `json:"state"`
	Provider     string         `json:"provider"` // github, gitlab, azure
	Properties   map[string]any `json:"properties,omitempty"`
	DiscoveredAt time.Time      `json:"discovered_at"`
	DiscoveredBy string         `json:"discovered_by"` // agent_id or "recon"

	// Poutine-specific fields
	Purl     string `json:"purl,omitempty"`     // Package URL
	RuleID   string `json:"rule_id,omitempty"`  // Poutine rule that found it
	Severity string `json:"severity,omitempty"` // critical, high, medium, low
}

// NewAsset creates a base asset with common fields initialized.
func NewAsset(id string, assetType AssetType, name string) Asset {
	return Asset{
		ID:           id,
		Type:         assetType,
		Name:         name,
		State:        StateNew,
		Properties:   make(map[string]any),
		DiscoveredAt: time.Now(),
		DiscoveredBy: "recon",
	}
}

// NewOrganization creates an organization asset.
func NewOrganization(name, provider string) Asset {
	id := fmt.Sprintf("%s:org:%s", provider, name)
	asset := NewAsset(id, AssetOrganization, name)
	asset.Provider = provider
	asset.Properties["org"] = name
	return asset
}

// NewRepository creates a repository asset.
func NewRepository(org, name, provider string) Asset {
	id := fmt.Sprintf("%s:%s/%s", provider, org, name)
	asset := NewAsset(id, AssetRepository, name)
	asset.Provider = provider
	asset.Properties["org"] = org
	asset.Properties["repo"] = name
	return asset
}

// NewWorkflow creates a workflow asset.
func NewWorkflow(repoID, path string) Asset {
	// Extract workflow name from path
	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}

	id := fmt.Sprintf("%s:workflow:%s", repoID, path)
	asset := NewAsset(id, AssetWorkflow, name)
	asset.Properties["path"] = path
	asset.Properties["repo_id"] = repoID
	return asset
}

// NewJob creates a job asset within a workflow.
func NewJob(workflowID, jobName string) Asset {
	id := fmt.Sprintf("%s:job:%s", workflowID, jobName)
	asset := NewAsset(id, AssetJob, jobName)
	asset.Properties["workflow_id"] = workflowID
	return asset
}

// NewSecret creates a secret asset.
func NewSecret(name, scope, provider string) Asset {
	id := fmt.Sprintf("%s:secret:%s:%s", provider, scope, name)
	asset := NewAsset(id, AssetSecret, name)
	asset.Provider = provider
	asset.Properties["scope"] = scope
	asset.State = StateHighValue // Secrets are always high value
	return asset
}

// NewToken creates a token asset.
func NewToken(tokenType, scope string, scopes []string) Asset {
	id := fmt.Sprintf("token:%s:%s", tokenType, scope)
	asset := NewAsset(id, AssetToken, tokenType)
	asset.Properties["token_type"] = tokenType
	asset.Properties["scope"] = scope
	asset.Properties["scopes"] = scopes
	return asset
}

// NewCloud creates a cloud resource asset.
func NewCloud(provider, resourceType, identifier string) Asset {
	id := fmt.Sprintf("%s:%s:%s", provider, resourceType, identifier)
	asset := NewAsset(id, AssetCloud, fmt.Sprintf("%s/%s", resourceType, identifier))
	asset.Provider = provider
	asset.Properties["resource_type"] = resourceType
	asset.Properties["identifier"] = identifier
	return asset
}

// NewAgent creates an agent asset.
func NewAgent(agentID, hostname, platform string) Asset {
	id := fmt.Sprintf("agent:%s", agentID)
	asset := NewAsset(id, AssetAgent, hostname)
	asset.Properties["agent_id"] = agentID
	asset.Properties["hostname"] = hostname
	asset.Properties["platform"] = platform
	return asset
}

// NewVulnerability creates a vulnerability asset from a poutine finding.
func NewVulnerability(ruleID, purl, path string, line int) Asset {
	id := fmt.Sprintf("vuln:%s:%s:%d", ruleID, path, line)
	asset := NewAsset(id, AssetVulnerability, ruleID)
	asset.RuleID = ruleID
	asset.Purl = purl
	if provider, _, _ := ParsePurl(purl); provider != "" {
		asset.Provider = provider
	}
	asset.Properties["path"] = path
	asset.Properties["line"] = line
	asset.Severity = classifyRuleSeverity(ruleID)
	return asset
}

func VulnerabilityExploitSupport(provider, path, ruleID string) (supported bool, reason string) {
	return VulnerabilityExploitSupportWithBashContext(provider, path, ruleID, "")
}

func VulnerabilityExploitSupportWithBashContext(provider, path, ruleID, bashContext string) (supported bool, reason string) {
	if strings.TrimSpace(provider) != "github" || !strings.HasPrefix(strings.TrimSpace(path), ".github/workflows/") {
		return false, "This finding is analyze-only in v0.1.0. Exploit actions are only available for GitHub Actions workflows."
	}
	switch strings.TrimSpace(ruleID) {
	case "injection", "untrusted_checkout_exec", "workflow_dispatch":
		if strings.TrimSpace(bashContext) == bashctx.QuotedHeredoc {
			return false, "Quoted heredoc bodies do not evaluate shell substitutions."
		}
		return true, ""
	case "pr_runs_on_self_hosted":
		return false, "Self-hosted runner findings are analyze-only in v0.1.0. Exploit actions are not supported yet."
	default:
		return false, "This finding is analyze-only in v0.1.0. Exploit actions are only available for injection and pwn-request findings."
	}
}

func SetVulnerabilityExploitSupport(asset *Asset) {
	if asset == nil {
		return
	}
	path, _ := asset.Properties["path"].(string)
	bashContext, _ := asset.Properties["bash_context"].(string)
	supported, reason := VulnerabilityExploitSupportWithBashContext(asset.Provider, path, asset.RuleID, bashContext)
	asset.Properties["exploit_supported"] = supported
	if reason == "" {
		delete(asset.Properties, "exploit_support_reason")
		return
	}
	asset.Properties["exploit_support_reason"] = reason
}

// classifyRuleSeverity maps poutine rule IDs to severity levels.
func classifyRuleSeverity(ruleID string) string {
	criticalRules := map[string]bool{
		"untrusted_checkout_exec": true,
		"injection":               true,
		"pr_runs_on_self_hosted":  true,
	}

	highRules := map[string]bool{
		"debug_enabled":                 true,
		"unverified_script_exec":        true,
		"known_vulnerability_in_runner": true,
		"excessive_permissions":         true,
	}

	if criticalRules[ruleID] {
		return "critical"
	}
	if highRules[ruleID] {
		return "high"
	}
	return "medium"
}

// SetState updates the asset state.
func (a *Asset) SetState(state AssetState) {
	a.State = state
}

// SetDiscoveredBy sets who discovered this asset.
func (a *Asset) SetDiscoveredBy(agentID string) {
	a.DiscoveredBy = agentID
}

// SetProperty sets a custom property.
func (a *Asset) SetProperty(key string, value any) {
	if a.Properties == nil {
		a.Properties = make(map[string]any)
	}
	a.Properties[key] = value
}

// GetProperty retrieves a custom property.
func (a *Asset) GetProperty(key string) (any, bool) {
	if a.Properties == nil {
		return nil, false
	}
	v, ok := a.Properties[key]
	return v, ok
}

// StringSliceProperty handles JSON round-trip where []string becomes []interface{}.
func (a *Asset) StringSliceProperty(key string) []string {
	val, ok := a.Properties[key]
	if !ok {
		return nil
	}
	if ss, ok := val.([]string); ok {
		return ss
	}
	if ifaces, ok := val.([]interface{}); ok {
		result := make([]string, 0, len(ifaces))
		for _, v := range ifaces {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
