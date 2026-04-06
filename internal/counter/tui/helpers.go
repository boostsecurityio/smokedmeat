// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
)

func Hyperlink(url, displayText string) string {
	return fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", url, displayText)
}

func GitHubOrgURL(org string) string {
	org = strings.TrimSpace(org)
	if org == "" {
		return ""
	}
	return "https://github.com/" + org
}

func GitHubRepoURL(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	return "https://github.com/" + repo
}

func GitHubFileURL(repo, path string) string {
	repo = strings.TrimSpace(repo)
	path = strings.Trim(strings.TrimSpace(path), "/")
	if repo == "" || path == "" {
		return ""
	}
	return "https://github.com/" + repo + "/blob/HEAD/" + path
}

func clonePermissionMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func appIDFromPivotSource(source string) string {
	if !strings.HasPrefix(source, "pivot:app:") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(source, "pivot:app:"))
}

func GitHubFileLineURL(repo, path string, line int) string {
	fileURL := GitHubFileURL(repo, path)
	if fileURL == "" {
		return ""
	}
	if line <= 0 {
		return fileURL
	}
	return fmt.Sprintf("%s#L%d", fileURL, line)
}

func GitHubActionsRunURL(repo, runID string) string {
	repo = strings.TrimSpace(repo)
	runID = strings.TrimSpace(runID)
	if repo == "" || runID == "" {
		return ""
	}
	return "https://github.com/" + repo + "/actions/runs/" + runID
}

func hyperlinkOrText(url, displayText string) string {
	if url == "" {
		return displayText
	}
	return Hyperlink(url, displayText)
}

func propertyStringSlice(props map[string]any, key string) []string {
	switch v := props[key].(type) {
	case []string:
		return v
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func propertyVictimCandidates(props map[string]any, key string) []cachepoison.VictimCandidate {
	value, ok := props[key]
	if !ok || value == nil {
		return nil
	}

	if typed, ok := value.([]cachepoison.VictimCandidate); ok {
		return append([]cachepoison.VictimCandidate(nil), typed...)
	}

	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}

	var victims []cachepoison.VictimCandidate
	if err := json.Unmarshal(raw, &victims); err != nil {
		return nil
	}
	return victims
}

type ScrollInfo struct {
	TotalLines   int
	ViewportSize int
	ScrollOffset int
}

func scrollbarColumn(height int, scroll ScrollInfo, focused bool) []string {
	if scroll.TotalLines <= scroll.ViewportSize {
		return nil
	}

	thumbSize := height * scroll.ViewportSize / scroll.TotalLines
	if thumbSize < 1 {
		thumbSize = 1
	}

	maxOffset := scroll.TotalLines - scroll.ViewportSize
	trackSpace := height - thumbSize
	thumbPos := 0
	if maxOffset > 0 && trackSpace > 0 {
		thumbPos = scroll.ScrollOffset * trackSpace / maxOffset
		if thumbPos > trackSpace {
			thumbPos = trackSpace
		}
	}

	var thumbStyle lipgloss.Style
	if focused {
		thumbStyle = focusIndicatorStyle
	} else {
		thumbStyle = mutedColor
	}
	trackStyle := mutedColor

	col := make([]string, height)
	for i := range height {
		if i >= thumbPos && i < thumbPos+thumbSize {
			col[i] = thumbStyle.Render("┃")
		} else {
			col[i] = trackStyle.Render("│")
		}
	}
	return col
}

func applyScrollIndicator(lines []string, targetHeight int, focused bool, selectedSet map[int]bool, scroll ScrollInfo) []string {
	col := scrollbarColumn(targetHeight, scroll, focused)
	indicatorFocused := mutedColor.Render("│")
	indicatorSelected := treeSelectedStyle.Render("│")

	result := make([]string, targetHeight)
	for i := range targetHeight {
		content := ""
		if i < len(lines) {
			content = lines[i]
		}

		switch {
		case focused && selectedSet[i]:
			result[i] = indicatorSelected + content
		case col != nil:
			result[i] = col[i] + content
		case focused && i < len(lines):
			result[i] = indicatorFocused + content
		default:
			result[i] = " " + content
		}
	}
	return result
}

func applyFocusIndicatorAndPad(lines []string, targetHeight int, focused bool) []string {
	return applyScrollIndicator(lines, targetHeight, focused, nil, ScrollInfo{})
}

func (m *Model) getEphemeralTokenForDispatch() *CollectedSecret {
	return m.dispatchCredential()
}

func (m Model) canPivotSecret(secret CollectedSecret) bool {
	if secret.Type == "github_app_key" || secret.Type == "github_app_id" || secret.CanUseAsSSHKey() {
		return true
	}
	if !secret.CanUseAsToken() {
		return false
	}
	if secret.ExpiresAt != nil && time.Now().After(*secret.ExpiresAt) {
		return false
	}
	if !secret.IsEphemeral() {
		return true
	}
	if secret.ExpressMode {
		return false
	}
	if secret.DwellDeadline != nil {
		return time.Now().Before(*secret.DwellDeadline)
	}
	if !m.jobDeadline.IsZero() {
		return time.Now().Before(m.jobDeadline)
	}
	return false
}

func (m Model) pivotUnavailableReason(secret CollectedSecret) string {
	if secret.Type == "github_app_key" || secret.Type == "github_app_id" || secret.CanUseAsSSHKey() {
		return ""
	}
	if !secret.CanUseAsToken() {
		return secret.Name + " cannot be used for pivot"
	}
	if secret.ExpiresAt != nil && time.Now().After(*secret.ExpiresAt) {
		return secret.Name + " has expired"
	}
	if !secret.IsEphemeral() {
		return ""
	}
	if secret.ExpressMode {
		return secret.Name + " expired when the workflow completed"
	}
	if secret.DwellDeadline != nil && time.Now().After(*secret.DwellDeadline) {
		return secret.Name + " expired when dwell ended"
	}
	if m.jobDeadline.IsZero() || time.Now().After(m.jobDeadline) {
		return secret.Name + " is no longer live"
	}
	return ""
}

func (m Model) hasDispatchCredential() bool {
	return m.dispatchCredential() != nil
}

func findLiveActionsWriteToken(secrets []CollectedSecret, tokenPermissions map[string]string) *CollectedSecret {
	now := time.Now()
	for i := range secrets {
		secret := &secrets[i]
		if secret.ExpressMode {
			continue
		}
		if secret.ExpiresAt != nil && now.After(*secret.ExpiresAt) {
			continue
		}
		if secret.DwellDeadline != nil && now.After(*secret.DwellDeadline) {
			continue
		}
		if secretAllowsDispatch(*secret, tokenPermissions) {
			return secret
		}
	}
	return nil
}

func (m Model) dispatchCredential() *CollectedSecret {
	if secret := m.SelectedLootSecret(); secret != nil && m.dispatchSecretAllowed(*secret, m.dispatchPermissionsForSecret(*secret)) {
		candidate := *secret
		return &candidate
	}
	if secret := m.findDispatchableToken(m.sessionLoot, m.tokenPermissions); secret != nil {
		return secret
	}
	if secret := m.activeDispatchToken(); secret != nil {
		return secret
	}
	return m.findDispatchableToken(m.lootStash, nil)
}

func (m Model) activeDispatchToken() *CollectedSecret {
	if m.tokenInfo == nil {
		return nil
	}
	if !strings.HasPrefix(m.tokenInfo.Source, "loot:") &&
		m.tokenInfo.Type != TokenTypeGitHubActions &&
		m.tokenInfo.Type != TokenTypeInstallApp {
		return nil
	}
	secret := m.resolveActiveTokenSecret()
	if secret == nil {
		return nil
	}
	if !m.dispatchSecretAllowed(*secret, m.activeDispatchPermissions()) {
		return nil
	}
	return secret
}

func activeTokenSecret(info *TokenInfo) CollectedSecret {
	if info == nil {
		return CollectedSecret{}
	}
	name := "ACTIVE_TOKEN"
	if strings.HasPrefix(info.Source, "loot:") {
		name = strings.TrimPrefix(info.Source, "loot:")
	} else {
		switch info.Type {
		case TokenTypeGitHubActions:
			name = "GITHUB_TOKEN"
		case TokenTypeInstallApp:
			name = "GITHUB_APP_TOKEN"
		case TokenTypeClassicPAT, TokenTypeFineGrainedPAT:
			name = "GITHUB_PAT"
		}
	}
	secret := CollectedSecret{
		Name:      name,
		Value:     info.Value,
		Scopes:    append([]string(nil), info.Scopes...),
		ExpiresAt: info.ExpiresAt,
	}
	switch info.Type {
	case TokenTypeGitHubActions:
		secret.Type = "github_token"
		secret.Ephemeral = true
	case TokenTypeInstallApp:
		secret.Type = "github_app_token"
	case TokenTypeClassicPAT:
		secret.Type = "github_pat"
	case TokenTypeFineGrainedPAT:
		secret.Type = "github_fine_grained_pat"
	case TokenTypeOAuth:
		secret.Type = "github_oauth"
	}
	return secret
}

func (m Model) resolveActiveTokenSecret() *CollectedSecret {
	if m.tokenInfo == nil || strings.TrimSpace(m.tokenInfo.Value) == "" {
		return nil
	}
	if strings.HasPrefix(m.tokenInfo.Source, "loot:") {
		name := strings.TrimPrefix(m.tokenInfo.Source, "loot:")
		if secret := findCollectedSecretByNameValue(m.sessionLoot, name, m.tokenInfo.Value); secret != nil {
			return secret
		}
		if secret := findCollectedSecretByNameValue(m.lootStash, name, m.tokenInfo.Value); secret != nil {
			return secret
		}
	}
	secret := activeTokenSecret(m.tokenInfo)
	return &secret
}

func findCollectedSecretByNameValue(secrets []CollectedSecret, name, value string) *CollectedSecret {
	for i := range secrets {
		if strings.TrimSpace(secrets[i].Value) != strings.TrimSpace(value) {
			continue
		}
		if name != "" && secrets[i].Name != name {
			continue
		}
		return &secrets[i]
	}
	return nil
}

func (m Model) activeTokenPermissionsMap() map[string]string {
	if m.tokenInfo == nil {
		return nil
	}
	switch {
	case strings.HasPrefix(m.tokenInfo.Source, "loot:GITHUB_TOKEN"), m.tokenInfo.Type == TokenTypeGitHubActions:
		return m.tokenPermissions
	case m.tokenInfo.Type == TokenTypeInstallApp:
		return m.appTokenPermissions
	default:
		return nil
	}
}

func (m Model) activeDispatchPermissions() map[string]string {
	return m.activeTokenPermissionsMap()
}

func (m Model) dispatchPermissionsForSecret(secret CollectedSecret) map[string]string {
	switch {
	case secret.Type == "github_app_token":
		return m.appTokenPermissions
	case secret.Type == "github_token" || secret.Name == "GITHUB_TOKEN":
		return m.tokenPermissions
	default:
		return nil
	}
}

func (m Model) findDispatchableToken(secrets []CollectedSecret, permissions map[string]string) *CollectedSecret {
	for i := range secrets {
		secret := &secrets[i]
		secretPermissions := permissions
		if secretPermissions == nil {
			secretPermissions = m.dispatchPermissionsForSecret(*secret)
		}
		if m.dispatchSecretAllowed(*secret, secretPermissions) {
			return secret
		}
	}
	return nil
}

func (m Model) dispatchSecretAllowed(secret CollectedSecret, permissions map[string]string) bool {
	if !m.canPivotSecret(secret) {
		return false
	}
	return secretAllowsDispatch(secret, permissions)
}

func secretAllowsDispatch(secret CollectedSecret, permissions map[string]string) bool {
	if !secret.CanUseAsToken() {
		return false
	}
	if secretHasActionsWrite(secret) {
		return true
	}
	if permissionAllowsWrite(permissions, "actions") || permissionAllowsWrite(permissions, "workflows") {
		return true
	}
	for _, scope := range secret.Scopes {
		switch scope {
		case "repo", "public_repo":
			return true
		}
		if strings.Contains(scope, "workflow") && strings.Contains(scope, "write") {
			return true
		}
	}
	return false
}

func secretHasActionsWrite(secret CollectedSecret) bool {
	if strings.HasPrefix(secret.Value, "ghp_") {
		return true
	}
	for _, scope := range secret.Scopes {
		if (strings.Contains(scope, "actions") || strings.Contains(scope, "workflow")) && strings.Contains(scope, "write") {
			return true
		}
	}
	return false
}

func (m Model) canUseDeliveryMethod(method DeliveryMethod) bool {
	state, _ := m.deliveryMethodStatus(method)
	return state != deployStateFail && state != deployStateDenied
}

func (m Model) canUseDeliveryMethodHeuristic(method DeliveryMethod) bool {
	switch method {
	case DeliveryCopyOnly, DeliveryManualSteps:
		return true
	case DeliveryAutoDispatch:
		return m.dispatchCredential() != nil
	}

	secret := m.resolveActiveTokenSecret()
	if secret == nil {
		return false
	}

	return secretAllowsDeliveryMethod(*secret, m.activeTokenPermissionsMap(), method)
}

func secretAllowsDeliveryMethod(secret CollectedSecret, permissions map[string]string, method DeliveryMethod) bool {
	switch method {
	case DeliveryAutoPR, DeliveryLOTP:
		return secretAllowsPullRequestWrite(secret, permissions)
	case DeliveryIssue:
		return secretAllowsIssueWrite(secret, permissions)
	case DeliveryComment:
		return secretAllowsCommentWrite(secret, permissions)
	case DeliveryAutoDispatch:
		return secretAllowsDispatch(secret, permissions)
	case DeliveryCopyOnly, DeliveryManualSteps:
		return true
	default:
		return false
	}
}

func secretAllowsPullRequestWrite(secret CollectedSecret, permissions map[string]string) bool {
	if !secret.CanUseAsToken() {
		return false
	}
	if permissionAllowsWrite(permissions, "contents") && permissionAllowsWrite(permissions, "pull_requests") {
		return true
	}
	return secretHasRepoWrite(secret)
}

func secretAllowsIssueWrite(secret CollectedSecret, permissions map[string]string) bool {
	if !secret.CanUseAsToken() {
		return false
	}
	if permissionAllowsWrite(permissions, "issues") {
		return true
	}
	return secretHasRepoWrite(secret)
}

func secretAllowsCommentWrite(secret CollectedSecret, permissions map[string]string) bool {
	if !secret.CanUseAsToken() {
		return false
	}
	if permissionAllowsWrite(permissions, "issues") || permissionAllowsWrite(permissions, "pull_requests") {
		return true
	}
	return secretHasRepoWrite(secret)
}

func secretHasRepoWrite(secret CollectedSecret) bool {
	if !secret.CanUseAsToken() {
		return false
	}
	if secret.Type == "github_fine_grained_pat" {
		return true
	}
	for _, scope := range secret.Scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		switch scope {
		case "repo", "public_repo":
			return true
		}
	}
	return false
}

func permissionAllowsWrite(permissions map[string]string, name string) bool {
	if len(permissions) == 0 || name == "" {
		return false
	}
	want := normalizePermissionName(name)
	for key, level := range permissions {
		if normalizePermissionName(key) == want && strings.EqualFold(strings.TrimSpace(level), "write") {
			return true
		}
	}
	return false
}

func normalizePermissionName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

func extractDispatchInputName(sources []string) string {
	for _, src := range sources {
		if strings.HasPrefix(src, "github.event.inputs.") {
			return strings.TrimPrefix(src, "github.event.inputs.")
		}
	}
	return ""
}
