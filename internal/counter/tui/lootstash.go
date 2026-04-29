// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func (m *Model) RenderLootStash(width, height int) string {
	return m.renderLootTree(width, height, false)
}

func (m *Model) renderLootTree(width, height int, showDetailPanel bool) string {
	if len(m.lootStash) == 0 && len(m.sessionLoot) == 0 {
		return m.renderEmptyLootStash(width, height)
	}

	if m.lootStashDirty || m.lootTreeRoot == nil {
		m.RebuildLootTree()
	}

	focused := m.paneFocus == PaneFocusLoot && !m.view.IsModal() && m.focus != FocusInput

	var lines []string
	selectedLines := make(map[int]bool)

	if showDetailPanel {
		title := fmt.Sprintf("Loot (%d items)", len(m.lootStash)+len(m.sessionLoot))
		lines = append(lines, " "+panelTitleStyle.Render(title), "")
	} else {
		lines = append(lines, " "+panelTitleStyle.Render("Loot Stash"), "")
	}

	treeAreaHeight := height - 2
	if showDetailPanel {
		treeAreaHeight = height - 14
	}
	if treeAreaHeight < 3 {
		treeAreaHeight = 3
	}

	if m.lootTreeCursor < m.lootTreeScroll {
		m.lootTreeScroll = m.lootTreeCursor
	}
	if m.lootTreeCursor >= m.lootTreeScroll+treeAreaHeight {
		m.lootTreeScroll = m.lootTreeCursor - treeAreaHeight + 1
	}

	endIdx := m.lootTreeScroll + treeAreaHeight
	if endIdx > len(m.lootTreeNodes) {
		endIdx = len(m.lootTreeNodes)
	}

	for i := m.lootTreeScroll; i < endIdx; i++ {
		node := m.lootTreeNodes[i]
		isSelected := i == m.lootTreeCursor && focused
		line := m.renderLootNode(node, width-3, isSelected)
		if isSelected {
			selectedLines[len(lines)] = true
		}
		lines = append(lines, line)
	}

	if endIdx < len(m.lootTreeNodes) {
		lines = append(lines, mutedColor.Render(fmt.Sprintf("  ↓ %d more", len(m.lootTreeNodes)-endIdx)))
	}

	if showDetailPanel {
		lines = append(lines, "", "─────────────")
		secret := m.SelectedLootSecret()
		if secret != nil {
			lines = append(lines, m.renderSelectedLootDetail(*secret)...)
			if focused {
				shortcuts := "[c] Copy  [e] Export"
				if secret.CanUseAsToken() {
					shortcuts += "  [v] Validate"
					if m.canPivotSecret(*secret) {
						shortcuts += "  [p] Pivot"
					}
				} else if m.canPivotSecret(*secret) {
					shortcuts += "  [p] Pivot"
				}
				lines = append(lines, "", mutedColor.Render(shortcuts))
			}
		}
	} else if focused {
		secret := m.SelectedLootSecret()
		if secret != nil {
			lines = append(lines, "")
			lines = append(lines, m.renderCompactLootDetail(*secret, width-4)...)
		}
	}

	scroll := ScrollInfo{
		TotalLines:   2 + len(m.lootTreeNodes),
		ViewportSize: 2 + treeAreaHeight,
		ScrollOffset: m.lootTreeScroll,
	}
	return strings.Join(applyScrollIndicator(lines, height, focused, selectedLines, scroll), "\n")
}

func (m *Model) AddToLootStash(secret CollectedSecret) {
	if m.addToLootStashNoSave(secret) {
		m.RebuildLootTree()
	}
}

func (m *Model) addToLootStashNoSave(secret CollectedSecret) bool {
	for i, existing := range m.lootStash {
		if sameLootValue(existing, secret) {
			return mergeCollectedSecretMetadataPreferIncomingOrigin(&m.lootStash[i], secret)
		}
		if existing.Name == secret.Name && existing.Value == secret.Value {
			return mergeCollectedSecretMetadataPreferIncomingOrigin(&m.lootStash[i], secret)
		}
		if sameLootOriginSlot(existing, secret) && shouldReplaceCollectedSecret(existing, secret) {
			replacement := secret
			mergeCollectedSecretMetadata(&replacement, existing)
			if replacement.Source == "" {
				replacement.Source = secret.Source
			}
			if replacement.Source != "" && len(replacement.Sources) == 0 {
				replacement.Sources = []string{replacement.Source}
			}
			m.lootStash[i] = replacement
			return true
		}
	}
	if secret.Source != "" && len(secret.Sources) == 0 {
		secret.Sources = []string{secret.Source}
	}
	m.lootStash = append(m.lootStash, secret)
	return true
}

func sameLootValue(a, b CollectedSecret) bool {
	if sameSSHKeyValue(a, b) {
		return true
	}
	if a.Value == "" || b.Value == "" || a.Value != b.Value {
		return false
	}
	if a.Type == "" || b.Type == "" {
		return false
	}
	return a.Type == b.Type
}

func sameSSHKeyValue(a, b CollectedSecret) bool {
	if !a.CanUseAsSSHKey() || !b.CanUseAsSSHKey() {
		return false
	}
	aFingerprint := a.KeyFingerprint
	if aFingerprint == "" {
		_, aFingerprint, _ = sshPrivateKeyMetadata(a.Value)
	}
	bFingerprint := b.KeyFingerprint
	if bFingerprint == "" {
		_, bFingerprint, _ = sshPrivateKeyMetadata(b.Value)
	}
	if aFingerprint != "" && bFingerprint != "" {
		return aFingerprint == bFingerprint
	}
	return normalizeSSHPrivateKey(a.Value) == normalizeSSHPrivateKey(b.Value)
}

func containsSource(sources []string, source string) bool {
	for _, s := range sources {
		if s == source {
			return true
		}
	}
	return false
}

func mergeCollectedSecretMetadata(dst *CollectedSecret, src CollectedSecret) bool {
	return mergeCollectedSecretMetadataWithPreference(dst, src, false)
}

func mergeCollectedSecretMetadataPreferIncomingOrigin(dst *CollectedSecret, src CollectedSecret) bool {
	return mergeCollectedSecretMetadataWithPreference(dst, src, true)
}

func mergeCollectedSecretMetadataWithPreference(dst *CollectedSecret, src CollectedSecret, preferIncomingOrigin bool) bool {
	before := lootTreePlacementKey(*dst)
	preferOrigin := preferIncomingOrigin || shouldPreferCollectedSecretOrigin(*dst, src)
	if src.Name != "" && (dst.Name == "" || preferOrigin) {
		dst.Name = src.Name
	}
	if src.Type != "" && dst.Type == "" {
		dst.Type = src.Type
	}
	if src.Repository != "" && (dst.Repository == "" || preferOrigin) {
		dst.Repository = src.Repository
	}
	if src.Workflow != "" && (dst.Workflow == "" || preferOrigin) {
		dst.Workflow = src.Workflow
	}
	if src.Job != "" && (dst.Job == "" || preferOrigin) {
		dst.Job = src.Job
	}
	if src.AgentID != "" && (dst.AgentID == "" || preferOrigin) {
		dst.AgentID = src.AgentID
	}
	if dst.PairedAppID == "" && src.PairedAppID != "" {
		dst.PairedAppID = src.PairedAppID
	}
	if dst.BoundToRepo == "" && src.BoundToRepo != "" {
		dst.BoundToRepo = src.BoundToRepo
	}
	if src.KeyFingerprint != "" && (dst.KeyFingerprint == "" || preferOrigin) {
		dst.KeyFingerprint = src.KeyFingerprint
	}
	if src.KeyType != "" && (dst.KeyType == "" || preferOrigin) {
		dst.KeyType = src.KeyType
	}
	mergeSSHTrialResults(dst, src.TrialResults)
	if src.TrialsComplete {
		dst.TrialsComplete = true
	}
	if src.CollectedAt.After(dst.CollectedAt) {
		dst.CollectedAt = src.CollectedAt
	}
	for _, newSource := range src.Sources {
		if newSource != "" && !containsSource(dst.Sources, newSource) {
			dst.Sources = append(dst.Sources, newSource)
		}
	}
	if src.Source != "" && !containsSource(dst.Sources, src.Source) {
		dst.Sources = append(dst.Sources, src.Source)
	}
	if src.Source != "" && (dst.Source == "" || preferOrigin) {
		dst.Source = src.Source
	}
	return before != lootTreePlacementKey(*dst)
}

func shouldPreferCollectedSecretOrigin(existing, incoming CollectedSecret) bool {
	switch {
	case existing.CollectedAt.IsZero():
		return !incoming.CollectedAt.IsZero()
	case incoming.CollectedAt.IsZero():
		return false
	default:
		return incoming.CollectedAt.After(existing.CollectedAt)
	}
}

func sameLootOriginSlot(a, b CollectedSecret) bool {
	if a.Name != b.Name {
		return false
	}
	aKey := lootOriginSlotKey(a)
	bKey := lootOriginSlotKey(b)
	return aKey != "" && aKey == bKey
}

func lootOriginSlotKey(secret CollectedSecret) string {
	if secret.Repository != "" || secret.Workflow != "" || secret.Job != "" {
		return strings.Join([]string{secret.Repository, secret.Workflow, secret.Job, secret.Name}, "\x00")
	}
	if secret.AgentID != "" {
		return "agent\x00" + secret.AgentID + "\x00" + secret.Name
	}
	return ""
}

func lootTreePlacementKey(secret CollectedSecret) string {
	return strings.Join([]string{secret.Repository, secret.Workflow, secret.Job, secret.Name}, "\x00")
}

func secretPermissionDisplayKey(secret CollectedSecret) string {
	if key := lootOriginSlotKey(secret); key != "" {
		return key
	}
	return strings.Join([]string{secret.AgentID, secret.Source, secret.Name, secret.Value}, "\x00")
}

func shouldReplaceCollectedSecret(existing, incoming CollectedSecret) bool {
	if !existing.CollectedAt.IsZero() && !incoming.CollectedAt.IsZero() {
		return !incoming.CollectedAt.Before(existing.CollectedAt)
	}
	return incoming.Value != "" && incoming.Value != existing.Value
}

func (m *Model) AddToSessionLoot(secret CollectedSecret) {
	if m.addToSessionLootNoSave(secret) {
		m.RebuildLootTree()
	}
}

func (m *Model) addToSessionLootNoSave(secret CollectedSecret) bool {
	for i, existing := range m.sessionLoot {
		if existing.Name == secret.Name {
			return mergeCollectedSecretMetadataPreferIncomingOrigin(&m.sessionLoot[i], secret)
		}
	}
	m.sessionLoot = append(m.sessionLoot, secret)
	return true
}

func (m Model) handleLootSync(msg LootSyncMsg) (tea.Model, tea.Cmd) {
	changed := false
	for _, entry := range msg.Sync.Entries {
		secret := collectedSecretFromLootSyncEntry(entry)
		if secret.Name == "" && secret.Value == "" {
			continue
		}
		if secret.IsEphemeral() && secret.ExpressMode {
			if m.addToSessionLootNoSave(secret) {
				changed = true
			}
		} else if m.addToLootStashNoSave(secret) {
			changed = true
		}
		if (secret.Name == "GITHUB_TOKEN" || secret.Type == "github_token") && len(entry.TokenPermissions) > 0 {
			m.storeTokenDisplayPermissions(secret, entry.TokenPermissions)
		}
	}
	if changed {
		m.pairGitHubAppCredentials()
		m.RebuildLootTree()
	}
	return m, m.listenForLootSync()
}

func collectedSecretFromLootSyncEntry(entry counter.LootSyncEntry) CollectedSecret {
	origin := strings.TrimSpace(entry.Origin)
	expressOrigin := origin == "" || origin == "express"
	agentID := strings.TrimSpace(entry.AgentID)
	if expressOrigin && len(agentID) > 8 {
		agentID = agentID[:8]
	}

	source := strings.TrimSpace(entry.Source)
	if expressOrigin && agentID != "" {
		if source != "" {
			source = "agent:" + agentID + ":" + source
		} else {
			source = "agent:" + agentID
		}
	}

	secret := CollectedSecret{
		Name:        entry.Name,
		Value:       entry.Value,
		Source:      source,
		Ephemeral:   expressOrigin && !entry.HighValue,
		CollectedAt: entry.Timestamp,
		Type:        entry.Type,
		Repository:  entry.Repository,
		Workflow:    entry.Workflow,
		Job:         entry.Job,
		AgentID:     agentID,
		ExpressMode: expressOrigin && !entry.HighValue,
	}
	if secret.IsEphemeral() && secret.Repository != "" {
		secret.BoundToRepo = secret.Repository
	}
	if secret.Type == "private_key" {
		secret.KeyType, secret.KeyFingerprint, _ = sshPrivateKeyMetadata(secret.Value)
	}
	return secret
}

func permissionHeading(secret CollectedSecret) string {
	if secret.Type == "github_token" || secret.Name == "GITHUB_TOKEN" {
		return "Permissions (from memory):"
	}
	return "Permissions:"
}

func (m *Model) storeTokenDisplayPermissions(secret CollectedSecret, perms map[string]string) {
	if len(perms) == 0 {
		return
	}
	if m.lootPermissionView == nil {
		m.lootPermissionView = make(map[string]map[string]string)
	}
	m.lootPermissionView[secretPermissionDisplayKey(secret)] = clonePermissionMap(perms)
}

func (m *Model) storeAppDisplayPermissions(appID string, perms map[string]string) {
	appID = strings.TrimSpace(appID)
	if appID == "" || len(perms) == 0 {
		return
	}
	if m.appPermissionView == nil {
		m.appPermissionView = make(map[string]map[string]string)
	}
	m.appPermissionView[appID] = clonePermissionMap(perms)
}

func (m Model) displayPermissionsForSecret(secret CollectedSecret) map[string]string {
	switch {
	case secret.PairedAppID != "":
		return clonePermissionMap(m.appPermissionView[strings.TrimSpace(secret.PairedAppID)])
	case secret.Name == "GITHUB_TOKEN":
		return clonePermissionMap(m.lootPermissionView[secretPermissionDisplayKey(secret)])
	case secret.Type == "github_app_token":
		return clonePermissionMap(m.appTokenPermissions)
	case secret.Type == "github_token":
		return clonePermissionMap(m.lootPermissionView[secretPermissionDisplayKey(secret)])
	default:
		return nil
	}
}

func (m *Model) renderSelectedLootDetail(secret CollectedSecret) []string {
	var lines []string
	perms := m.displayPermissionsForSecret(secret)

	if secret.PairedAppID != "" {
		lines = append(lines,
			successColor.Render("GitHub App Credential"),
			"",
			"App ID: "+secret.PairedAppID,
			"PEM: "+secret.Name,
		)
		valPreview := secret.Value
		if len(valPreview) > 80 {
			valPreview = valPreview[:80] + "..."
		}
		lines = append(lines, mutedColor.Render(valPreview))
		if len(perms) > 0 {
			lines = append(lines, "", secondaryColorStyle.Render(permissionHeading(secret)))
			lines = append(lines, renderPermissionLines(perms, "  ")...)
		}
	} else {
		lines = append(lines,
			successColor.Render(secret.Name),
			mutedColor.Render(secret.Value),
		)
	}

	if secret.Type != "" && secret.PairedAppID == "" {
		lines = append(lines, "", "Type: "+formatSecretType(secret.Type))
	}

	if secret.Repository != "" || secret.Workflow != "" || secret.Job != "" || secret.AgentID != "" {
		lines = append(lines, "", secondaryColorStyle.Render("Origin:"))
		if secret.Repository != "" {
			lines = append(lines, "  Repo: "+hyperlinkOrText(GitHubRepoURL(secret.Repository), secret.Repository))
		}
		if secret.Workflow != "" {
			lines = append(lines, "  Workflow: "+hyperlinkOrText(GitHubFileURL(secret.Repository, secret.Workflow), secret.Workflow))
		}
		if secret.Job != "" {
			lines = append(lines, "  Job: "+secret.Job)
		}
		if secret.AgentID != "" {
			lines = append(lines, "  Agent: "+secret.AgentID)
		}
	}

	if secret.BoundToRepo != "" {
		lines = append(lines, warningColor.Render("  ⚠ Bound to: "+secret.BoundToRepo))
	}
	if secret.KeyType != "" || secret.KeyFingerprint != "" {
		lines = append(lines, "", secondaryColorStyle.Render("SSH Key:"))
		if secret.KeyType != "" {
			lines = append(lines, "  Type: "+secret.KeyType)
		}
		if secret.KeyFingerprint != "" {
			lines = append(lines, "  Fingerprint: "+secret.KeyFingerprint)
		}
	}

	if len(secret.Sources) > 1 {
		lines = append(lines, "",
			"Sources: "+strings.Join(secret.Sources, ", "),
			"Found: "+secret.CollectedAt.Format("15:04:05"),
		)
	} else {
		lines = append(lines, "",
			"Source: "+secret.Source,
			"Found: "+secret.CollectedAt.Format("15:04:05"),
		)
	}

	switch {
	case len(perms) > 0:
		lines = append(lines, "", secondaryColorStyle.Render(permissionHeading(secret)))
		lines = append(lines, renderPermissionLines(perms, "  ")...)
	case secret.Validated:
		lines = append(lines, "")
		if secret.ValidStatus == "valid" {
			lines = append(lines, successColor.Render("✓ Valid"))
			if len(secret.Scopes) > 0 {
				lines = append(lines, "Scopes: "+strings.Join(secret.Scopes, ", "))
			}
			if secret.Owner != "" {
				lines = append(lines, "Owner: "+secret.Owner)
			}
			if secret.ExpiresAt != nil {
				remaining := time.Until(*secret.ExpiresAt)
				switch {
				case remaining < 0:
					lines = append(lines, errorColor.Render("⚠ EXPIRED"))
				case remaining < 1*time.Hour:
					lines = append(lines, warningColor.Render(fmt.Sprintf("⚠ Expires in %d min", int(remaining.Minutes()))))
				case remaining < 24*time.Hour:
					lines = append(lines, warningColor.Render(fmt.Sprintf("Expires in %.1f hours", remaining.Hours())))
				default:
					lines = append(lines, "Expires: "+secret.ExpiresAt.Format("2006-01-02"))
				}
			}
		} else {
			lines = append(lines, errorColor.Render("✗ "+secret.ValidStatus))
		}
	case secret.IsEphemeral():
		lines = append(lines, "", warningColor.Render("⏱ Expires when workflow completes"))
	}

	if len(secret.TrialResults) > 0 || secret.TrialsComplete {
		lines = append(lines, "", secondaryColorStyle.Render("SSH Trials:"))
		successes := 0
		for _, result := range secret.TrialResults {
			if !result.Success {
				continue
			}
			successes++
			label := fmt.Sprintf("  %s/%s", result.Host, result.Repo)
			if result.Branch != "" {
				label += " → " + result.Branch
			}
			if result.Permission == "write" {
				lines = append(lines, warningColor.Render(label+" ("+result.Permission+")"))
			} else {
				lines = append(lines, successColor.Render(label+" ("+result.Permission+")"))
			}
		}
		if successes == 0 && secret.TrialsComplete {
			lines = append(lines, mutedColor.Render("  No GitHub repo access confirmed"))
		}
	}

	var recs []PivotRecommendation
	if m.canPivotSecret(secret) {
		recs = credentialRecommendations(secret, len(m.knownEntities))
	}
	if len(recs) > 0 {
		lines = append(lines, "")
		limit := 3
		if len(recs) < limit {
			limit = len(recs)
		}
		for _, rec := range recs[:limit] {
			lines = append(lines, warningColor.Render("→ ")+rec.Label)
		}
	}

	return lines
}

func (m *Model) renderCompactLootDetail(secret CollectedSecret, width int) []string {
	var lines []string
	perms := m.displayPermissionsForSecret(secret)

	switch {
	case secret.PairedAppID != "":
		lines = append(lines,
			mutedColor.Render("  App ID: ")+secret.PairedAppID,
			mutedColor.Render("  PEM: ")+secret.Name,
		)
		if len(perms) > 0 {
			lines = append(lines, renderPermissionLines(perms, "  ")...)
		}
	case len(perms) > 0:
		if secret.ExpressMode {
			lines = append(lines, errorColor.Render("  ⚠ Expired")+mutedColor.Render(" (express mode)"))
		}
		lines = append(lines, renderPermissionLines(perms, "  ")...)
	default:
		valPreview := secret.Value
		maxLen := width - 8
		if maxLen < 20 {
			maxLen = 20
		}
		if len(valPreview) > maxLen {
			valPreview = valPreview[:maxLen] + "..."
		}
		lines = append(lines, mutedColor.Render("  Value: ")+valPreview)

		if secret.Type != "" {
			lines = append(lines, mutedColor.Render("  Type: ")+secret.Type)
		}
	}

	shortcuts := "  [c] Copy"
	if secret.CanUseAsToken() {
		shortcuts += " [v] Validate"
		if m.canPivotSecret(secret) {
			shortcuts += " [p] Pivot"
		}
	} else if m.canPivotSecret(secret) {
		shortcuts += " [p] Pivot"
	}
	lines = append(lines, mutedColor.Render(shortcuts))

	return lines
}

func renderPermissionLines(perms map[string]string, indent string) []string {
	var writes, reads, others []string
	for perm := range perms {
		switch perms[perm] {
		case "write":
			writes = append(writes, perm)
		case "read":
			reads = append(reads, perm)
		default:
			others = append(others, perm)
		}
	}
	sort.Strings(writes)
	sort.Strings(reads)
	sort.Strings(others)

	var lines []string
	for _, perm := range writes {
		lines = append(lines, warningColor.Render(fmt.Sprintf("%s● %s: write", indent, perm)))
	}
	for _, perm := range reads {
		lines = append(lines, successColor.Render(fmt.Sprintf("%s◐ %s: read", indent, perm)))
	}
	for _, perm := range others {
		lines = append(lines, mutedColor.Render(fmt.Sprintf("%s○ %s: %s", indent, perm, perms[perm])))
	}
	return lines
}

func formatSecretType(t string) string {
	switch t {
	case "github_pat":
		return "GitHub PAT (Classic)"
	case "github_fine_grained_pat":
		return "GitHub PAT (Fine-grained)"
	case "github_token":
		return "GitHub Token"
	case "github_app_token":
		return "GitHub App Token"
	case "github_app_key":
		return "GitHub App Key (PEM)"
	case "github_oauth":
		return "GitHub OAuth Token"
	case "aws_access_key":
		return "AWS Access Key"
	case "aws_secret":
		return "AWS Secret Key"
	case "azure":
		return "Azure Credential"
	case "gcp":
		return "GCP Credential"
	case "npm":
		return "NPM Token"
	case "container_registry":
		return "Container Registry"
	case "database":
		return "Database Credential"
	case "signing_key":
		return "Signing Key"
	case "private_key":
		return "Private Key"
	default:
		return t
	}
}

func (m *Model) BuildLootTree() *TreeNode {
	root := &TreeNode{
		ID:       "root",
		Label:    "Loot",
		Expanded: true,
		Depth:    -1,
	}

	allSecrets := make([]*CollectedSecret, 0, len(m.lootStash)+len(m.sessionLoot))
	now := time.Now()
	for i := range m.lootStash {
		if m.lootStash[i].IsEphemeral() && m.lootStash[i].DwellDeadline != nil && now.After(*m.lootStash[i].DwellDeadline) {
			continue
		}
		allSecrets = append(allSecrets, &m.lootStash[i])
	}
	for i := range m.sessionLoot {
		if m.sessionLoot[i].IsEphemeral() && m.sessionLoot[i].DwellDeadline != nil && now.After(*m.sessionLoot[i].DwellDeadline) {
			continue
		}
		allSecrets = append(allSecrets, &m.sessionLoot[i])
	}

	if len(allSecrets) == 0 {
		return root
	}

	byRepo := make(map[string][]*CollectedSecret)
	for _, secret := range allSecrets {
		repo := secret.Repository
		if repo == "" {
			repo = "(unknown)"
		}
		byRepo[repo] = append(byRepo[repo], secret)
	}

	activeRepo := ""
	switch {
	case strings.TrimSpace(m.analysisFocusRepo) != "":
		activeRepo = strings.TrimSpace(m.analysisFocusRepo)
	case m.targetType == "repo" && strings.TrimSpace(m.target) != "":
		activeRepo = strings.TrimSpace(m.target)
	case m.activeAgent != nil:
		activeRepo = m.activeAgent.Repo
	}

	repoNames := make([]string, 0, len(byRepo))
	for repo := range byRepo {
		repoNames = append(repoNames, repo)
	}
	sort.Strings(repoNames)

	for _, repo := range repoNames {
		secrets := byRepo[repo]
		repoNode := &TreeNode{
			ID:       "loot:repo:" + repo,
			Label:    repo,
			Type:     TreeNodeRepo,
			Expanded: repo == activeRepo || len(byRepo) == 1,
			Depth:    0,
			Parent:   root,
			Properties: map[string]interface{}{
				"secret_count": len(secrets),
			},
		}
		if entity, ok := m.knownEntities["repo:"+repo]; ok && entity.IsPrivate {
			repoNode.State = TreeStateHighValue
		}

		type sourceKey struct{ workflow, job string }
		bySource := make(map[sourceKey][]*CollectedSecret)
		for _, s := range secrets {
			bySource[sourceKey{s.Workflow, s.Job}] = append(bySource[sourceKey{s.Workflow, s.Job}], s)
		}

		sourceKeys := make([]sourceKey, 0, len(bySource))
		for key := range bySource {
			sourceKeys = append(sourceKeys, key)
		}
		sort.Slice(sourceKeys, func(i, j int) bool {
			if sourceKeys[i].workflow != sourceKeys[j].workflow {
				return sourceKeys[i].workflow < sourceKeys[j].workflow
			}
			return sourceKeys[i].job < sourceKeys[j].job
		})

		for _, key := range sourceKeys {
			srcSecrets := bySource[key]
			var label, nodeID string
			nodeType := TreeNodeWorkflow
			switch {
			case key.workflow != "" && key.job != "":
				label = key.workflow + " → " + key.job
				nodeID = "loot:wf:" + repo + ":" + key.workflow + ":" + key.job
			case key.workflow != "":
				label = key.workflow
				nodeID = "loot:file:" + repo + ":" + key.workflow
			default:
				label = "(unknown)"
				nodeID = "loot:file:" + repo + ":unknown"
			}
			wfNode := &TreeNode{
				ID:       nodeID,
				Label:    label,
				Type:     nodeType,
				Expanded: true,
				Depth:    1,
				Parent:   repoNode,
			}

			for _, secret := range srcSecrets {
				secretNode := &TreeNode{
					ID:     "loot:secret:" + secret.Name + ":" + secret.Repository,
					Label:  secret.Name,
					Type:   TreeNodeSecret,
					Depth:  2,
					Parent: wfNode,
					Properties: map[string]interface{}{
						"secret": secret,
					},
				}
				if secret.IsEphemeral() {
					secretNode.State = TreeStateEphemeral
				}
				wfNode.Children = append(wfNode.Children, secretNode)
			}
			repoNode.Children = append(repoNode.Children, wfNode)
		}
		root.Children = append(root.Children, repoNode)
	}

	return root
}

func (m *Model) RebuildLootTree() {
	m.lootTreeRoot = m.BuildLootTree()
	m.lootTreeNodes = FlattenTree(m.lootTreeRoot)
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		m.lootTreeCursor = 0
	}
	m.lootStashDirty = false
}

func (m *Model) ReflattenLootTree() {
	m.lootTreeNodes = FlattenTree(m.lootTreeRoot)
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		m.lootTreeCursor = len(m.lootTreeNodes) - 1
	}
	if m.lootTreeCursor < 0 {
		m.lootTreeCursor = 0
	}
}

func (m *Model) LootTreeCursorUp() {
	if len(m.lootTreeNodes) == 0 {
		return
	}
	m.lootTreeCursor--
	if m.lootTreeCursor < 0 {
		m.lootTreeCursor = len(m.lootTreeNodes) - 1
	}
}

func (m *Model) LootTreeCursorDown() {
	if len(m.lootTreeNodes) == 0 {
		return
	}
	m.lootTreeCursor++
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		m.lootTreeCursor = 0
	}
}

func (m *Model) LootTreeToggleExpand() {
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		return
	}
	node := m.lootTreeNodes[m.lootTreeCursor]
	if node.HasChildren() {
		node.Toggle()
		m.ReflattenLootTree()
	}
}

func (m *Model) LootTreeExpand() {
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		return
	}
	node := m.lootTreeNodes[m.lootTreeCursor]
	if node.HasChildren() && !node.Expanded {
		node.Expanded = true
		m.ReflattenLootTree()
	}
}

func (m *Model) LootTreeCollapse() {
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		return
	}
	node := m.lootTreeNodes[m.lootTreeCursor]
	if node.HasChildren() && node.Expanded {
		node.Expanded = false
		m.ReflattenLootTree()
	} else if node.Parent != nil && node.Parent.ID != "root" {
		for i, n := range m.lootTreeNodes {
			if n == node.Parent {
				m.lootTreeCursor = i
				return
			}
		}
	}
}

func (m *Model) SelectedLootSecret() *CollectedSecret {
	if m.lootTreeCursor >= len(m.lootTreeNodes) {
		return nil
	}
	return m.getLootSecret(m.lootTreeNodes[m.lootTreeCursor])
}

func (m *Model) LootTreeSelectByID(id string) bool {
	node := findNodeByID(m.lootTreeRoot, id)
	if node == nil {
		return false
	}
	expandNodeAncestors(node)
	m.ReflattenLootTree()
	for i, current := range m.lootTreeNodes {
		if current == node {
			m.lootTreeCursor = i
			return true
		}
	}
	return false
}

func (m *Model) FindLootIndex(name string) int {
	for i, s := range m.lootStash {
		if s.Name == name {
			return i
		}
	}
	return -1
}

func (m *Model) getLootSecret(node *TreeNode) *CollectedSecret {
	if node == nil || node.Properties == nil {
		return nil
	}
	if s, ok := node.Properties["secret"].(*CollectedSecret); ok {
		return s
	}
	return nil
}

func (m *Model) formatLootSecretBadges(secret *CollectedSecret) string {
	var badges []string

	if secret.Validated && secret.ValidStatus == "valid" {
		badges = append(badges, successColor.Render("✓"))
	}

	switch {
	case secret.IsEphemeral() && secret.ExpressMode:
		badges = append(badges, errorColor.Render("[expired]"))
	case secret.IsEphemeral() && m.dwellMode && !m.jobDeadline.IsZero():
		remaining := time.Until(m.jobDeadline)
		if remaining > 0 {
			badges = append(badges, warningColor.Render("⏱"+formatDuration(remaining)))
		} else {
			badges = append(badges, errorColor.Render("[expired]"))
		}
	case secret.DwellDeadline != nil:
		remaining := time.Until(*secret.DwellDeadline)
		if remaining > 0 {
			badges = append(badges, warningColor.Render(formatDuration(remaining)))
		} else {
			badges = append(badges, errorColor.Render("[expired]"))
		}
	}

	if m.canPivotSecret(*secret) {
		badges = append(badges, warningColor.Render("[pivot]"))
	}

	if len(badges) == 0 {
		return ""
	}
	return " " + strings.Join(badges, " ")
}

func (m *Model) renderLootNode(node *TreeNode, width int, selected bool) string {
	depth := node.Depth
	if depth < 0 {
		depth = 0
	}
	indent := strings.Repeat("  ", depth)

	expandIcon := "  "
	if node.HasChildren() {
		if node.Expanded {
			expandIcon = "▼ "
		} else {
			expandIcon = "▶ "
		}
	}

	label := node.Label
	var style lipgloss.Style

	switch node.Type {
	case TreeNodeRepo:
		if !node.Expanded {
			if count, ok := node.Properties["secret_count"].(int); ok {
				label += fmt.Sprintf(" (%d)", count)
			}
		}
		if node.State == TreeStateHighValue {
			label = "🔒 " + label
			style = treePrivateRepoStyle
		} else {
			style = treeRepoStyle
		}

	case TreeNodeWorkflow:
		style = treeWorkflowStyle

	case TreeNodeSecret:
		secret := m.getLootSecret(node)
		if secret != nil {
			if secret.PairedAppID != "" {
				label = "🔐 GitHub App (" + secret.Name + ")"
			} else {
				label = secret.TypeIcon() + " " + label
			}
			label += m.formatLootSecretBadges(secret)
		}
		if node.State == TreeStateEphemeral {
			style = treeEphemeralStyle
		} else {
			style = treeSecretStyle
		}
	}

	maxLabelWidth := width - lipgloss.Width(indent) - lipgloss.Width(expandIcon)
	if maxLabelWidth < 4 {
		maxLabelWidth = 4
	}
	label = truncateVisual(label, maxLabelWidth)
	var labelDisplay string
	switch node.Type {
	case TreeNodeRepo, TreeNodeWorkflow:
		labelDisplay = m.renderTreeNodeLabel(node, label)
	default:
		labelDisplay = label
	}

	line := indent + expandIcon + labelDisplay

	if selected {
		return treeSelectedStyle.Render(padRight(line, width))
	}
	return style.Render(line)
}

func (m *Model) renderEmptyLootStash(width, height int) string {
	lines := []string{
		" " + panelTitleStyle.Render("Loot Stash"),
		"",
		mutedColor.Render("  No loot collected yet."),
		"",
		mutedColor.Render("  Secrets will appear here"),
		mutedColor.Render("  as agents discover them."),
	}
	focused := m.paneFocus == PaneFocusLoot && !m.view.IsModal() && m.focus != FocusInput
	return strings.Join(applyFocusIndicatorAndPad(lines, height, focused), "\n")
}

func (m *Model) exportableLoot() []CollectedSecret {
	exportable := make([]CollectedSecret, 0, len(m.lootStash)+len(m.sessionLoot))
	collect := func(secrets []CollectedSecret) {
		for _, s := range secrets {
			if s.IsEphemeral() {
				continue
			}
			if s.ExpressMode {
				continue
			}
			if s.DwellDeadline != nil && time.Now().After(*s.DwellDeadline) {
				continue
			}
			exportable = append(exportable, s)
		}
	}
	collect(m.lootStash)
	collect(m.sessionLoot)
	return exportable
}

func (m *Model) exportLootCmd() tea.Cmd {
	return func() tea.Msg {
		exportable := m.exportableLoot()
		if len(exportable) == 0 {
			return LootExportedMsg{Count: 0}
		}

		vault := FromCollectedSecrets(exportable)
		err := SaveTokenVault(vault)
		return LootExportedMsg{Count: len(vault.Tokens), Err: err}
	}
}
