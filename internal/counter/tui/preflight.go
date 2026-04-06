// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

const (
	deployCapabilityIssue        = "delivery.issue"
	deployCapabilityCommentAny   = "delivery.comment.any"
	deployCapabilityCommentIssue = "delivery.comment.issue"
	deployCapabilityCommentPR    = "delivery.comment.pr"
	deployCapabilityCommentStub  = "delivery.comment.stub_pr"
	deployCapabilityPR           = "delivery.pr"
	deployCapabilityLOTP         = "delivery.lotp"
	deployCapabilityDispatch     = "delivery.dispatch"

	deployStatePass      = "pass"
	deployStateFail      = "fail"
	deployStateUnknown   = "unknown"
	deployStateConfirmed = "confirmed"
	deployStateDenied    = "denied"
)

func tokenTypeFromSecret(secret CollectedSecret) string {
	switch secret.Type {
	case "github_token":
		return string(TokenTypeGitHubActions)
	case "github_app_token":
		return string(TokenTypeInstallApp)
	case "github_pat":
		return string(TokenTypeClassicPAT)
	case "github_fine_grained_pat":
		return string(TokenTypeFineGrainedPAT)
	case "github_oauth":
		return string(TokenTypeOAuth)
	default:
		return string(TokenTypeUnknown)
	}
}

func (m Model) wizardPreflightCredential() (secret *CollectedSecret, permissions map[string]string, owner string) {
	if m.wizard == nil {
		return nil, nil, ""
	}
	if m.wizard.DeliveryMethod == DeliveryAutoDispatch {
		dispatchSecret := m.dispatchCredential()
		if dispatchSecret == nil {
			return nil, nil, ""
		}
		return dispatchSecret, m.dispatchPermissionsForSecret(*dispatchSecret), ownerForSecret(m.tokenInfo, *dispatchSecret)
	}
	secret = m.resolveActiveTokenSecret()
	if secret == nil {
		return nil, nil, ""
	}
	return secret, m.activeTokenPermissionsMap(), ownerForSecret(m.tokenInfo, *secret)
}

func ownerForSecret(info *TokenInfo, secret CollectedSecret) string {
	if info == nil {
		return ""
	}
	if strings.TrimSpace(info.Value) != strings.TrimSpace(secret.Value) {
		return ""
	}
	return info.Owner
}

func (m Model) currentCommentIssueNumber() int {
	if m.wizard == nil || m.wizard.DeliveryMethod != DeliveryComment {
		return 0
	}
	if m.wizard.CommentTarget != CommentTargetIssue {
		return 0
	}
	value := strings.TrimSpace(m.wizardInput.Value())
	if value == "" {
		return 0
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
}

func (m Model) currentCommentPRNumber() int {
	if m.wizard == nil || m.wizard.DeliveryMethod != DeliveryComment {
		return 0
	}
	if m.wizard.CommentTarget != CommentTargetPullRequest {
		return 0
	}
	value := strings.TrimSpace(m.wizardInput.Value())
	if value == "" {
		return 0
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
}

func (m Model) buildWizardPreflightRequest() (req *counter.DeployPreflightRequest, key string) {
	if m.wizard == nil || m.wizard.SelectedVuln == nil || m.kitchenClient == nil {
		return nil, ""
	}
	secret, permissions, owner := m.wizardPreflightCredential()
	if secret == nil || strings.TrimSpace(secret.Value) == "" {
		return nil, ""
	}
	req = &counter.DeployPreflightRequest{
		Token:            secret.Value,
		TokenType:        tokenTypeFromSecret(*secret),
		TokenOwner:       owner,
		Scopes:           append([]string(nil), secret.Scopes...),
		KnownPermissions: cloneStringMap(permissions),
		IssueNumber:      m.currentCommentIssueNumber(),
		PRNumber:         m.currentCommentPRNumber(),
		Vuln: counter.VulnerabilityInfo{
			Repository: m.wizard.SelectedVuln.Repository,
			Workflow:   m.wizard.SelectedVuln.Workflow,
			Context:    m.wizard.SelectedVuln.Context,
			ID:         m.wizard.SelectedVuln.ID,
		},
	}
	return req, wizardPreflightKey(req)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func wizardPreflightKey(req *counter.DeployPreflightRequest) string {
	if req == nil {
		return ""
	}
	body, _ := json.Marshal(req)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}

func (m *Model) startWizardPreflight(force bool) tea.Cmd {
	req, key := m.buildWizardPreflightRequest()
	if m.wizard == nil {
		return nil
	}
	if req == nil || key == "" {
		m.wizard.PreflightKey = ""
		m.wizard.PreflightLoading = false
		m.wizard.PreflightError = ""
		m.wizard.Preflight = nil
		return nil
	}
	keyChanged := m.wizard.PreflightKey != key
	if !force && m.wizard.PreflightKey == key {
		if m.wizard.PreflightLoading || (m.wizard.Preflight != nil && m.wizard.PreflightError == "") {
			return nil
		}
	}
	m.wizard.PreflightKey = key
	m.wizard.PreflightLoading = true
	m.wizard.PreflightError = ""
	if force || keyChanged {
		m.wizard.Preflight = nil
	}
	return func() tea.Msg {
		resp, err := m.kitchenClient.FetchDeployPreflight(context.Background(), *req)
		if err != nil {
			return WizardPreflightErrorMsg{Key: key, Err: err}
		}
		return WizardPreflightFetchedMsg{Key: key, Response: resp}
	}
}

func deliveryCapabilityKey(method DeliveryMethod) string {
	switch method {
	case DeliveryIssue:
		return deployCapabilityIssue
	case DeliveryComment:
		return deployCapabilityCommentAny
	case DeliveryAutoPR:
		return deployCapabilityPR
	case DeliveryLOTP:
		return deployCapabilityLOTP
	case DeliveryAutoDispatch:
		return deployCapabilityDispatch
	default:
		return ""
	}
}

func commentCapabilityKey(target CommentTarget) string {
	switch target {
	case CommentTargetPullRequest:
		return deployCapabilityCommentPR
	case CommentTargetStubPullRequest:
		return deployCapabilityCommentStub
	default:
		return deployCapabilityCommentIssue
	}
}

func (m Model) wizardCapabilityStatus(capability string) (state, reason string) {
	if m.wizard == nil || m.wizard.Preflight == nil || capability == "" {
		return "", ""
	}
	value, ok := m.wizard.Preflight.Capabilities[capability]
	if !ok {
		return "", ""
	}
	return value.State, value.Reason
}

func (m Model) deliveryMethodStatus(method DeliveryMethod) (state, reason string) {
	switch method {
	case DeliveryCopyOnly, DeliveryManualSteps:
		return deployStatePass, ""
	}
	if method == DeliveryAutoDispatch && m.dispatchCredential() == nil {
		return deployStateFail, "No dispatch-capable token is available"
	}
	if method != DeliveryAutoDispatch && m.resolveActiveTokenSecret() == nil {
		return deployStateFail, "No token set"
	}
	state, reason = m.wizardCapabilityStatus(deliveryCapabilityKey(method))
	if state != "" {
		return state, reason
	}
	if m.wizard != nil && m.wizard.PreflightLoading {
		return deployStateUnknown, "Validating target..."
	}
	if m.canUseDeliveryMethodHeuristic(method) {
		return deployStateUnknown, "Capability not confirmed yet"
	}
	return deployStateFail, "Current token is unlikely to support this path"
}

func (m Model) commentTargetStatus(target CommentTarget) (state, reason string) {
	state, reason = m.wizardCapabilityStatus(commentCapabilityKey(target))
	if state != "" {
		return state, reason
	}
	if m.wizard != nil && m.wizard.PreflightLoading {
		return deployStateUnknown, "Validating target..."
	}
	return deployStateUnknown, ""
}

func (m Model) wizardPreflightBlockForMethod(method DeliveryMethod) (state, reason string) {
	capability := deliveryCapabilityKey(method)
	if capability == "" {
		return "", ""
	}
	state, reason = m.wizardCapabilityStatus(capability)
	if state == deployStateFail || state == deployStateDenied {
		return state, reason
	}
	return "", ""
}

func (m Model) wizardPreflightBlockForCommentTarget(target CommentTarget) (state, reason string) {
	state, reason = m.wizardCapabilityStatus(commentCapabilityKey(target))
	if state == deployStateFail || state == deployStateDenied {
		return state, reason
	}
	return "", ""
}

func (m Model) availableCommentTargets() []CommentTarget {
	targets := []CommentTarget{CommentTargetIssue, CommentTargetPullRequest, CommentTargetStubPullRequest}
	if m.wizard == nil || m.wizard.Preflight == nil {
		return targets
	}
	var available []CommentTarget
	for _, target := range targets {
		if target == CommentTargetIssue || target == CommentTargetPullRequest {
			available = append(available, target)
			continue
		}
		state, _ := m.commentTargetStatus(target)
		if state != deployStateFail && state != deployStateDenied {
			available = append(available, target)
		}
	}
	if len(available) == 0 {
		return targets
	}
	return available
}

func preferredDeliveryStatusRank(state string) int {
	switch state {
	case deployStateConfirmed:
		return 4
	case deployStatePass:
		return 3
	case deployStateUnknown:
		return 2
	default:
		return 1
	}
}
