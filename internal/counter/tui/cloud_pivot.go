// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

var secretRefPattern = regexp.MustCompile(`\$\{\{\s*secrets\.(\w+)\s*\}\}`)
var varRefPattern = regexp.MustCompile(`\$\{\{\s*vars\.(\w+)\s*\}\}`)

func (m Model) lookupCloudConfig(provider string) map[string]string {
	config := make(map[string]string)
	if m.pantry == nil {
		if strings.EqualFold(provider, "gcp") || strings.EqualFold(provider, "google") {
			if project := m.derivedGCPProject(""); project != "" {
				config["project-id"] = project
			}
		}
		return config
	}

	tokens := m.currentJobCloudTokens(provider)
	if len(tokens) == 0 {
		tokens = m.allCloudTokens(provider)
	}
	for _, token := range tokens {
		m.applyCloudTokenConfig(config, token)
	}

	if (strings.EqualFold(provider, "gcp") || strings.EqualFold(provider, "google")) && config["project-id"] == "" {
		config["project-id"] = m.derivedGCPProject(config["service-account"])
	}

	return config
}

func (m Model) derivedGCPProject(serviceAccount string) string {
	for _, key := range []string{"GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"} {
		if value := strings.TrimSpace(m.resolveRefs(m.runnerVars[key])); value != "" {
			return value
		}
	}
	return extractGCPProjectFromServiceAccount(serviceAccount)
}

func extractGCPProjectFromServiceAccount(serviceAccount string) string {
	parts := strings.SplitN(serviceAccount, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	domain := parts[1]
	if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
		return strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
	}
	return ""
}

func (m Model) resolveSecretRefs(value string) string {
	return secretRefPattern.ReplaceAllStringFunc(value, func(match string) string {
		sub := secretRefPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		secretName := sub[1]
		for _, s := range m.lootStash {
			if strings.EqualFold(s.Name, secretName) && s.Value != "" {
				return s.Value
			}
		}
		for _, s := range m.sessionLoot {
			if strings.EqualFold(s.Name, secretName) && s.Value != "" {
				return s.Value
			}
		}
		return match
	})
}

func (m Model) resolveVarRefs(value string) string {
	if m.runnerVars == nil {
		return value
	}
	return varRefPattern.ReplaceAllStringFunc(value, func(match string) string {
		sub := varRefPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		varName := sub[1]
		for k, v := range m.runnerVars {
			if strings.EqualFold(k, varName) && v != "" {
				return v
			}
		}
		return match
	})
}

func (m Model) resolveRefs(value string) string {
	value = m.resolveSecretRefs(value)
	value = m.resolveVarRefs(value)
	return value
}

func cloudTokenTypesForProvider(provider string) []string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return []string{"aws_oidc"}
	case "gcp", "google":
		return []string{"gcp_oidc"}
	case "azure", "az":
		return []string{"azure_oidc"}
	default:
		return []string{"aws_oidc", "gcp_oidc", "azure_oidc"}
	}
}

func cloudProviderAlias(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return "gcp"
	case "az":
		return "azure"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func cloudTokenMatchesProvider(token pantry.Asset, provider string) bool {
	tokenType, _ := token.Properties["token_type"].(string)
	for _, want := range cloudTokenTypesForProvider(provider) {
		if tokenType == want {
			return true
		}
	}
	return false
}

func sortAssetsByID(assets []pantry.Asset) {
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].ID < assets[j].ID
	})
}

func (m Model) allCloudTokens(provider string) []pantry.Asset {
	var tokens []pantry.Asset
	for _, token := range m.pantry.GetAssetsByType(pantry.AssetToken) {
		if cloudTokenMatchesProvider(token, provider) {
			tokens = append(tokens, token)
		}
	}
	sortAssetsByID(tokens)
	return tokens
}

func pantryRepoID(repo string) string {
	parts := strings.SplitN(strings.TrimSpace(repo), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return pantry.NewRepository(parts[0], parts[1], "github").ID
}

func (m Model) currentJobCloudTokens(provider string) []pantry.Asset {
	if m.pantry == nil || m.activeAgent == nil {
		return nil
	}
	repoID := pantryRepoID(m.activeAgent.Repo)
	workflowPath := strings.TrimSpace(m.activeAgent.Workflow)
	jobName := strings.TrimSpace(m.activeAgent.Job)
	if repoID == "" || workflowPath == "" || jobName == "" {
		return nil
	}
	workflowID := pantry.NewWorkflow(repoID, workflowPath).ID
	jobID := pantry.NewJob(workflowID, jobName).ID
	if !m.pantry.HasAsset(jobID) {
		return nil
	}

	providerAlias := cloudProviderAlias(provider)
	var tokens []pantry.Asset
	for _, cloudEdge := range m.pantry.GetOutgoingEdges(jobID) {
		cloudAsset, err := m.pantry.GetAsset(cloudEdge.To)
		if err != nil || cloudAsset.Type != pantry.AssetCloud {
			continue
		}
		if providerAlias != "" && providerAlias != "auto" && cloudProviderAlias(cloudAsset.Provider) != providerAlias {
			continue
		}
		for _, tokenEdge := range m.pantry.GetOutgoingEdges(cloudAsset.ID) {
			tokenAsset, err := m.pantry.GetAsset(tokenEdge.To)
			if err != nil || tokenAsset.Type != pantry.AssetToken {
				continue
			}
			if cloudTokenMatchesProvider(tokenAsset, provider) {
				tokens = append(tokens, tokenAsset)
			}
		}
	}
	sortAssetsByID(tokens)
	return tokens
}

func (m Model) applyCloudTokenConfig(config map[string]string, token pantry.Asset) {
	propKeys := map[string]string{
		"role_arn":              "role-arn",
		"region":                "region",
		"role_duration_seconds": "role-duration-seconds",
		"role_external_id":      "role-external-id",
		"workload_provider":     "workload-identity-provider",
		"service_account":       "service-account",
		"project_id":            "project-id",
		"audience":              "audience",
		"delegates":             "delegates",
		"access_token_lifetime": "token-lifetime",
		"access_token_scopes":   "token-scopes",
		"tenant_id":             "tenant-id",
		"client_id":             "client-id",
		"subscription_id":       "subscription-id",
		"environment":           "environment",
	}
	for propKey, argKey := range propKeys {
		if v, ok := token.Properties[propKey].(string); ok && v != "" {
			config[argKey] = m.resolveRefs(v)
		}
	}
}

func (m *Model) handlePivotResult(result *models.PivotResult) {
	if result.Success {
		m.AddOutput("success", fmt.Sprintf("Cloud pivot to %s succeeded (%s, %.0fms)", result.Provider, result.Method, result.Duration))
	} else {
		m.AddOutput("error", fmt.Sprintf("Cloud pivot to %s failed", result.Provider))
		for _, e := range result.Errors {
			m.AddOutput("error", "  "+e)
		}
		return
	}

	if len(result.Credentials) > 0 {
		m.AddOutput("info", "  Credentials:")
		for k, v := range result.Credentials {
			m.AddOutput("info", fmt.Sprintf("    %s = %s", k, v))
		}
	}

	if len(result.Resources) > 0 {
		m.AddOutput("info", fmt.Sprintf("  Resources: %d discovered", len(result.Resources)))
		for i, r := range result.Resources {
			if i >= 15 {
				m.AddOutput("info", fmt.Sprintf("    ... and %d more", len(result.Resources)-15))
				break
			}
			label := r.Name
			if label == "" {
				label = r.ID
			}
			m.AddOutput("info", fmt.Sprintf("    [%s] %s", r.Type, label))
		}
	}

	if m.cloudState != nil && m.cloudState.TempDir != "" {
		m.AddOutput("warning", fmt.Sprintf("Replacing previous %s cloud session (temp dir cleaned)", m.cloudState.Provider))
		os.RemoveAll(m.cloudState.TempDir)
	}

	cs := &CloudState{
		Provider:       result.Provider,
		Method:         result.Method,
		Credentials:    result.Credentials,
		RawCredentials: result.RawCredentials,
		PivotTime:      time.Now(),
		ResourceCount:  len(result.Resources),
	}

	if result.RawCredentials != nil {
		if result.Provider == "gcp" || result.Provider == "google" {
			if result.RawCredentials["PROJECT"] == "" {
				if project := m.derivedGCPProject(result.RawCredentials["SERVICE_ACCOUNT"]); project != "" {
					result.RawCredentials["PROJECT"] = project
				}
			}
		}
		if exp := result.RawCredentials["Expiration"]; exp != "" {
			if t, err := time.Parse(time.RFC3339, exp); err == nil {
				cs.Expiry = t
			}
		}
		if exp := result.RawCredentials["EXPIRES_ON"]; exp != "" {
			if t, err := time.Parse("2006-01-02 15:04:05.000000", exp); err == nil {
				cs.Expiry = t
			}
		}
	}

	m.cloudState = cs

	if len(result.RawCredentials) > 0 {
		m.AddOutput("info", "  Type 'cloud shell' to enter a local cloud CLI shell")
	}

	m.importCloudResourcesToPantry(result)
	m.activityLog.Add(IconSuccess, fmt.Sprintf("Cloud pivot: %s via %s (%d resources)", result.Provider, result.Method, len(result.Resources)))
}

func (m *Model) importCloudResourcesToPantry(result *models.PivotResult) {
	if m.pantry == nil {
		m.pantry = pantry.New()
	}

	for _, r := range result.Resources {
		identifier := r.ID
		if identifier == "" {
			identifier = r.Name
		}
		asset := pantry.NewCloud(result.Provider, r.Type, identifier)
		asset.State = pantry.StateValidated
		if r.Region != "" {
			asset.SetProperty("region", r.Region)
		}
		if r.Name != "" {
			asset.SetProperty("name", r.Name)
		}
		for k, v := range r.Metadata {
			asset.SetProperty(k, v)
		}
		_ = m.pantry.AddAsset(asset)
	}
}
