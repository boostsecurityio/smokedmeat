// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	deployCapabilityWorkflowPush = "delivery.workflow_push"
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
	if m.wizard == nil || m.kitchenClient == nil {
		return nil, ""
	}
	if m.wizard.Kind == WizardKindRunnerTarget {
		if m.wizard.SelectedRunnerTarget == nil {
			return nil, ""
		}
		if m.wizard.RunnerTargetAction != RunnerTargetActionAutoWorkflowPush {
			return nil, ""
		}
		secret := m.resolveActiveTokenSecret()
		if secret == nil || strings.TrimSpace(secret.Value) == "" {
			return nil, ""
		}
		permissions := m.activeTokenPermissionsMap()
		req = &counter.DeployPreflightRequest{
			Token:            secret.Value,
			TokenType:        tokenTypeFromSecret(*secret),
			TokenOwner:       ownerForSecret(m.tokenInfo, *secret),
			Scopes:           append([]string(nil), secret.Scopes...),
			KnownPermissions: cloneStringMap(permissions),
			Vuln: counter.VulnerabilityInfo{
				Repository: m.wizard.SelectedRunnerTarget.Repository,
			},
		}
		return req, wizardPreflightKey(req)
	}
	if m.wizard.SelectedVuln == nil {
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
	var selectedVuln *Vulnerability
	if m.wizard != nil {
		selectedVuln = m.wizard.SelectedVuln
	}
	if reason = deliveryMethodBlockReason(selectedVuln, method); reason != "" {
		return deployStateFail, reason
	}
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
		return deployStateUnknown, "Checking token and target access..."
	}
	if m.canUseDeliveryMethodHeuristic(method) {
		return deployStateUnknown, "GitHub access for this action could not be pre-verified"
	}
	return deployStateFail, "Current token is unlikely to support this path"
}

func (m Model) commentTargetStatus(target CommentTarget) (state, reason string) {
	state, reason = m.wizardCapabilityStatus(commentCapabilityKey(target))
	if state != "" {
		return state, reason
	}
	if m.wizard != nil && m.wizard.PreflightLoading {
		return deployStateUnknown, "Checking token and target access..."
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

func (m Model) runnerTargetActionStatus(action RunnerTargetAction) (state, reason string) {
	switch action {
	case RunnerTargetActionPassiveDetails:
		return deployStatePass, ""
	case RunnerTargetActionAutoWorkflowPush:
		if result := m.runnerTargetSSHWriteResult(); result != nil {
			return deployStateConfirmed, fmt.Sprintf("Active SSH write access is confirmed for %s - direct branch push will use git over SSH", result.Repo)
		}
		secret := m.resolveActiveTokenSecret()
		if secret == nil {
			return deployStateFail, "No direct branch-write foothold is active - pivot a token or SSH deploy key first"
		}
		state, reason = m.wizardCapabilityStatus(deployCapabilityWorkflowPush)
		if state != "" {
			return state, reason
		}
		if m.wizard != nil && m.wizard.PreflightLoading {
			return deployStateUnknown, "Checking whether the current token can create a branch and commit a workflow file directly"
		}
		if m.wizard != nil && m.wizard.PreflightError != "" {
			return deployStateUnknown, "GitHub route check is unavailable - direct branch push may still work, or copy the workflow for manual use"
		}
		permissions := m.activeTokenPermissionsMap()
		hasContentsWrite := permissionAllowsWrite(permissions, "contents")
		hasWorkflowFileWrite := permissionAllowsWorkflowFileWrite(permissions)
		if len(permissions) > 0 {
			switch {
			case !hasContentsWrite:
				return deployStateDenied, "Current token cannot create a branch or commit workflow content - contents:write is required"
			case hasContentsWrite && !hasWorkflowFileWrite:
				return deployStateDenied, "Current token can write repository contents but cannot commit files under .github/workflows - workflows:write is required"
			default:
				return deployStateUnknown, "Current token may be able to push the workflow branch directly, but repository routing could not be pre-verified"
			}
		}
		if secretAllowsWorkflowPush(*secret, permissions) {
			return deployStateUnknown, "Current token may be able to push the workflow branch directly, but repository routing could not be pre-verified"
		}
		return deployStateUnknown, "Current token is unlikely to support direct workflow-file writes - SSH deploy-key access may still work"
	case RunnerTargetActionCopyWorkflow:
		if result := m.runnerTargetSSHWriteResult(); result != nil {
			return deployStatePass, fmt.Sprintf("Manual copy is available, and the active SSH foothold can push to %s", result.Repo)
		}
		return deployStatePass, "Manual workflow copy is available even if no token or SSH foothold can push it automatically"
	default:
		return deployStatePass, ""
	}
}

func (m Model) runnerTargetRouteSummary() string {
	if m.wizard == nil || m.wizard.SelectedRunnerTarget == nil {
		return ""
	}
	if result := m.runnerTargetSSHWriteResult(); result != nil {
		return fmt.Sprintf("Active SSH foothold can push branches directly to %s.", result.Repo)
	}
	secret := m.resolveActiveTokenSecret()
	if secret == nil {
		return "No token is set for a route check. The copied workflow is still usable if you can push it through another foothold."
	}
	if m.wizard.PreflightLoading {
		return "Checking whether the current token can create a branch and push the workflow directly."
	}
	if m.wizard.PreflightError != "" {
		return "GitHub route check is unavailable. The copied workflow can still be used manually."
	}

	pushState, pushReason := m.wizardCapabilityStatus(deployCapabilityWorkflowPush)

	switch {
	case pushState == deployStateConfirmed || pushState == deployStatePass:
		return "The current token appears able to create a branch and commit the workflow file directly."
	case pushState == deployStateFail || pushState == deployStateDenied:
		return "The current token does not look sufficient for direct workflow-file writes."
	case pushReason != "":
		return pushReason
	default:
		return ""
	}
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
