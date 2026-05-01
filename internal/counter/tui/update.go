// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

var clipboardWriteAll = clipboard.WriteAll

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.handleKeyMsg(msg)

	case tea.KeyReleaseMsg:
		return m.handleKeyReleaseMsg(msg)

	case tea.PasteMsg:
		return m.handlePasteMsg(msg)

	case BeaconMsg:
		return m.handleBeacon(msg)

	case ColeslawMsg:
		return m.handleColeslaw(msg)

	case kitchenClientCreatedMsg:
		return m.handleKitchenClientCreated(msg)

	case KitchenErrorMsg:
		m.AddOutput("error", "Kitchen: "+msg.Err.Error())
		return m, nil

	case setupKitchenVerifiedMsg:
		if m.setupWizard == nil {
			return m, nil
		}
		if msg.Err != "" {
			m.setupWizard.Status = ""
			m.setupWizard.Error = msg.Err
			m.setupWizard.Step = 1
			m.setupInput.Focus()
			return m, nil
		}
		m.setupWizard.Status = ""
		m.setupWizard.Step = 2
		return m, nil

	case SetupSSHKeysLoadedMsg:
		if m.setupWizard == nil {
			return m, nil
		}
		if msg.Err != nil {
			m.setupWizard.Error = fmt.Sprintf("SSH agent error: %v", msg.Err)
			m.setupWizard.Keys = nil
			return m, nil
		}
		m.setupWizard.Keys = msg.Keys
		m.setupWizard.Error = ""
		if len(msg.Keys) == 0 {
			m.setupWizard.Error = "No SSH keys in agent. Run: ssh-add"
		} else if len(msg.Keys) == 1 {
			m.setupWizard.SelectedKey = 0
			m.setupWizard.Step = 3
			m.setupWizard.GeneratedName = counter.GenerateOperatorName()
			m.setupWizard.OperatorNameChoice = OperatorNameGenerated
			m.setupInput.SetValue("")
			m.setupInput.Placeholder = "my_operator_name"
			m.setupInput.Blur()
		}
		return m, nil

	case SetupKeyDeployedMsg:
		if m.setupWizard == nil {
			return m, nil
		}
		if msg.Err != nil {
			m.setupWizard.Status = ""
			m.setupWizard.Error = fmt.Sprintf("SSH deploy failed: %v", msg.Err)
			return m, nil
		}
		m.setupWizard.Status = "Key deployed. Connecting..."
		m.setupWizard.AuthAttempt = 0
		m.setupWizard.Connecting = true
		return m, m.finishSetup()

	case SetupClipboardCopiedMsg:
		if m.setupWizard == nil {
			return m, nil
		}
		if msg.Err != nil {
			m.setupWizard.Error = fmt.Sprintf("Clipboard copy failed: %v", msg.Err)
		} else {
			m.setupWizard.Status = "Copied to clipboard. Deploy the key, then press Enter to connect."
		}
		return m, nil

	case SetupAuthResultMsg:
		if m.setupWizard == nil {
			return m, nil
		}
		if msg.Err != nil {
			sw := m.setupWizard
			sw.AuthAttempt++
			retryDelays := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}
			if sw.AuthAttempt <= len(retryDelays) {
				delay := retryDelays[sw.AuthAttempt-1]
				sw.Status = fmt.Sprintf("Auth failed, retrying in %ds... (attempt %d/3)", int(delay.Seconds()), sw.AuthAttempt)
				sw.Error = ""
				return m, tea.Tick(delay, func(time.Time) tea.Msg {
					return setupAuthRetryMsg{}
				})
			}
			sw.Status = ""
			sw.Connecting = false
			sw.Error = fmt.Sprintf("Auth failed after 3 attempts: %v", msg.Err)
			return m, nil
		}
		sw := m.setupWizard
		m.config.KitchenURL = sw.KitchenURL
		m.config.AuthToken = msg.Token
		m.config.Operator = sw.OperatorName
		if sw.SelectedKey >= 0 && sw.SelectedKey < len(sw.Keys) {
			m.config.KeyComment = sw.Keys[sw.SelectedKey].Comment
		}
		m.lightRye = rye.NewLightRye(sw.KitchenURL)
		m.setupWizard = &SetupWizardState{
			Step:          5,
			BackStepFloor: 5,
		}
		m.setupInput.SetValue("")
		m.setupInput.Placeholder = "ghp_xxxxxxxxxxxxxxxxxxxx"
		m.setupInput.Blur()
		return m, m.connectToKitchen()

	case setupBrowserOpenedMsg:
		if m.setupWizard != nil && m.setupWizard.Step == 5 {
			m.setupWizard.Status = ""
			m.setupWizard.TokenSubStep = setupTokenSubStepInput
			m.setupInput.SetValue("")
			m.setupInput.Placeholder = "ghp_xxxxxxxxxxxxxxxxxxxx"
			m.setupInput.EchoMode = textinput.EchoPassword
			m.setupInput.EchoCharacter = '•'
			m.setupInput.Focus()
		}
		return m, nil

	case SetupTokenAcquiredMsg:
		if m.setupWizard == nil || m.setupWizard.Step != 5 {
			return m, nil
		}
		sw := m.setupWizard
		sw.TokenValue = msg.Token
		sw.Status = "Verifying token..."
		return m, m.setupSaveTokenAndFetchInfo(msg.Token, msg.Source, msg.OPSecretRef)

	case SetupTokenErrorMsg:
		if m.setupWizard == nil || m.setupWizard.Step != 5 {
			return m, nil
		}
		m.setupWizard.Status = ""
		m.setupWizard.Error = fmt.Sprintf("Token error (%s): %v", msg.Source, msg.Err)
		m.setupWizard.TokenSubStep = setupTokenSubStepChoice
		return m, nil

	case SetupTokenInfoMsg:
		if m.setupWizard == nil || m.setupWizard.Step != 5 {
			return m, nil
		}
		sw := m.setupWizard
		sw.Status = ""
		sw.TokenOwner = msg.Owner
		sw.TokenScopes = strings.Join(msg.Scopes, ", ")

		info := &TokenInfo{
			Value:     sw.TokenValue,
			Type:      DetectTokenType(sw.TokenValue),
			Source:    "setup",
			Owner:     msg.Owner,
			Scopes:    msg.Scopes,
			FetchedAt: time.Now(),
		}
		m.tokenInfo = info
		m.initialTokenInfo = info
		m.pivotToken = nil

		m.finishSetupTokenVerification()
		return m, nil

	case SetupTokenInfoErrorMsg:
		if m.setupWizard == nil || m.setupWizard.Step != 5 {
			return m, nil
		}
		sw := m.setupWizard
		sw.Status = ""

		info := &TokenInfo{
			Value:     sw.TokenValue,
			Type:      DetectTokenType(sw.TokenValue),
			Source:    "setup",
			FetchedAt: time.Now(),
		}
		m.tokenInfo = info
		m.initialTokenInfo = info
		m.pivotToken = nil

		m.finishSetupTokenVerification()
		return m, nil

	case SetupAnalysisCompletedMsg:
		if msg.AnalysisID != "" && m.activeAnalysisID != "" && msg.AnalysisID != m.activeAnalysisID {
			return m, nil
		}
		if m.setupWizard == nil || m.setupWizard.Step != 7 {
			return m.handleAnalysisCompleted(AnalysisCompletedMsg{AnalysisID: msg.AnalysisID, Result: msg.Result})
		}

		updated, _ := m.handleAnalysisCompleted(AnalysisCompletedMsg{AnalysisID: msg.AnalysisID, Result: msg.Result})
		if um, ok := updated.(Model); ok {
			m = um
		}

		sw := m.setupWizard
		sw.AnalysisRunning = false
		sw.AnalysisAttempt = 0
		sw.AnalysisRetryPending = false
		sw.Status = ""
		sw.ReposAnalyzed = msg.Result.ReposAnalyzed
		sw.VulnsFound = len(msg.Result.Findings)
		sw.SecretsFound = len(msg.Result.SecretFindings)
		sw.AnalysisSummary = "complete"
		m.clearAnalysisProgress()

		cfg, _ := counter.LoadConfig()
		if cfg == nil {
			cfg = &counter.Config{}
		}
		cfg.LastAnalyzedTarget = cfg.Target
		_ = counter.SaveConfig(cfg)

		return m, nil

	case SetupAnalysisErrorMsg:
		if msg.AnalysisID != "" && m.activeAnalysisID != "" && msg.AnalysisID != m.activeAnalysisID {
			return m, nil
		}
		if m.setupWizard == nil || m.setupWizard.Step != 7 {
			return m, nil
		}
		sw := m.setupWizard
		sw.AnalysisRunning = false
		if isRetryableSetupAnalysisError(msg.Err) {
			if m.analysisProgress != nil {
				sw.AnalysisRetryPending = false
				sw.Status = ""
				sw.Error = "Analyze response dropped. Kitchen may still be finishing. Press r to retry if progress stalls."
				return m, nil
			}
			m.clearAnalysisProgress()
			retryDelays := setupAnalysisRetryDelays()
			if sw.AnalysisAttempt < len(retryDelays) {
				sw.AnalysisAttempt++
				delay := retryDelays[sw.AnalysisAttempt-1]
				sw.AnalysisRetryPending = true
				sw.Error = ""
				sw.Status = fmt.Sprintf("Analyze request dropped, retrying in %ds... (attempt %d/%d)", int(delay.Seconds()), sw.AnalysisAttempt, len(retryDelays))
				return m, tea.Tick(delay, func(time.Time) tea.Msg {
					return setupAnalysisRetryMsg{}
				})
			}
			sw.Error = fmt.Sprintf("Analysis failed after %d retries: %v", len(retryDelays), msg.Err)
		} else {
			m.clearAnalysisProgress()
			sw.Error = fmt.Sprintf("Analysis failed: %v", msg.Err)
		}
		sw.AnalysisRetryPending = false
		sw.Status = ""
		return m, nil

	case AnalysisResponseDroppedMsg:
		if msg.AnalysisID != "" && m.activeAnalysisID != "" && msg.AnalysisID != m.activeAnalysisID {
			return m, nil
		}
		if msg.Setup && m.setupWizard != nil && m.setupWizard.Step == 7 {
			m.setupWizard.AnalysisRunning = true
			m.setupWizard.AnalysisRetryPending = false
			m.setupWizard.Error = ""
			m.setupWizard.Status = "Analyze response dropped. Waiting for Kitchen result..."
		} else {
			m.AddOutput("warning", "Kitchen response dropped. Waiting for the final analysis result...")
		}
		return m, m.startAnalysisResultPoll(msg.AnalysisID, msg.Deep, msg.Setup, msg.Err)

	case AnalysisResultStatusFetchedMsg:
		if m.analysisResultPoll == nil || msg.AnalysisID == "" || msg.AnalysisID != m.analysisResultPoll.AnalysisID {
			return m, nil
		}
		poll := *m.analysisResultPoll
		switch msg.Response.Status {
		case "completed":
			if msg.Response.Result == nil {
				err := fmt.Errorf("kitchen reported analysis complete without a result body")
				if poll.Setup {
					return m.Update(SetupAnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
				}
				return m.Update(AnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
			}
			if poll.Setup {
				return m.Update(SetupAnalysisCompletedMsg{AnalysisID: msg.AnalysisID, Result: msg.Response.Result})
			}
			return m.Update(AnalysisCompletedMsg{AnalysisID: msg.AnalysisID, Result: msg.Response.Result, Deep: poll.Deep})
		case "failed":
			err := fmt.Errorf("analysis failed after response dropped: %s", msg.Response.Error)
			if poll.Setup {
				return m.Update(SetupAnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
			}
			return m.Update(AnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
		default:
			m.analysisResultPoll.Attempts++
			if m.analysisResultPoll.Attempts >= analysisResultPollMaxTries || (msg.Response.Status == "unknown" && m.analysisResultPoll.Attempts >= 3) {
				err := fmt.Errorf("lost Kitchen analysis result after dropped response: %v", poll.OriginalErr)
				if poll.Setup {
					return m.Update(SetupAnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
				}
				return m.Update(AnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
			}
			if poll.Setup && m.setupWizard != nil && m.setupWizard.Step == 7 {
				m.setupWizard.AnalysisRunning = true
				if msg.Response.Status == "unknown" {
					m.setupWizard.Status = "Checking whether Kitchen accepted the analysis request..."
				} else {
					m.setupWizard.Status = "Waiting for Kitchen result..."
				}
			}
			return m, m.pollAnalysisResultCmd(msg.AnalysisID)
		}

	case AnalysisResultStatusErrorMsg:
		if m.analysisResultPoll == nil || msg.AnalysisID == "" || msg.AnalysisID != m.analysisResultPoll.AnalysisID {
			return m, nil
		}
		poll := *m.analysisResultPoll
		m.analysisResultPoll.Attempts++
		if m.analysisResultPoll.Attempts >= analysisResultPollMaxTries {
			err := fmt.Errorf("failed to recover Kitchen analysis result after dropped response: %v", msg.Err)
			if poll.Setup {
				return m.Update(SetupAnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
			}
			return m.Update(AnalysisErrorMsg{AnalysisID: msg.AnalysisID, Err: err})
		}
		if poll.Setup && m.setupWizard != nil && m.setupWizard.Step == 7 {
			m.setupWizard.AnalysisRunning = true
			m.setupWizard.Status = "Waiting for Kitchen result..."
		}
		return m, m.pollAnalysisResultCmd(msg.AnalysisID)

	case setupAnalysisRetryMsg:
		if m.setupWizard == nil || m.setupWizard.Step != 7 || m.setupWizard.AnalysisRunning || !m.setupWizard.AnalysisRetryPending {
			return m, nil
		}
		return m.startSetupAnalysis(false)

	case setupAuthRetryMsg:
		if m.setupWizard == nil {
			return m, nil
		}
		m.setupWizard.Status = fmt.Sprintf("Connecting... (attempt %d/3)", m.setupWizard.AuthAttempt+1)
		return m, m.authenticateSSHCmd()

	case KitchenConnectedMsg:
		m.connected = true
		m.connectionState = "connected"
		m.AddOutput("success", "Connected to Kitchen")

		return m, tea.Batch(m.fetchPantryCmd(), m.fetchKnownEntitiesCmd(), m.fetchHistoryCmd(), m.fetchCallbacksCmd())

	case PantryFetchedMsg:
		if msg.Pantry != nil && msg.Pantry.Size() > 0 {
			hadVulnerabilities := len(m.vulnerabilities) > 0
			m.pantry = msg.Pantry
			m.activityLog.Add(IconSuccess, fmt.Sprintf("Loaded %d assets, %d edges", msg.Pantry.Size(), msg.Pantry.EdgeCount()))
			m.AddOutput("info", fmt.Sprintf("Loaded attack graph: %d repos, %d workflows, %d vulns (%d edges)",
				len(msg.Pantry.GetAssetsByType(pantry.AssetRepository)),
				len(msg.Pantry.GetAssetsByType(pantry.AssetWorkflow)),
				len(msg.Pantry.GetAssetsByType(pantry.AssetVulnerability)),
				msg.Pantry.EdgeCount()))

			m.vulnerabilities = m.extractVulnerabilitiesFromPantry()
			if len(m.vulnerabilities) > 0 {
				if !hadVulnerabilities {
					m.AddOutput("success", fmt.Sprintf("Loaded %d vulnerabilities from attack graph", len(m.vulnerabilities)))
				}
				m.analysisComplete = true
				if m.phase != PhasePostExploit && m.phase != PhasePivot && m.phase != PhaseWaiting {
					m.TransitionToPhase(PhaseRecon)
				}
			}
			m.RebuildTree()
		}
		return m, nil

	case KnownEntitiesFetchedMsg:
		m.replaceKnownEntities(msg.Entities)
		m.lootStashDirty = true
		m.RebuildTree()
		m.RebuildLootTree()
		m.GenerateSuggestions()
		return m, nil

	case KnownEntitiesFetchErrorMsg:
		m.AddOutput("warning", fmt.Sprintf("Failed to load known entities: %v", msg.Err))
		return m, nil

	case CallbacksFetchedMsg:
		m.setCallbacks(msg.Callbacks)
		return m, nil

	case CallbackFetchErrorMsg:
		m.AddOutput("warning", fmt.Sprintf("Failed to fetch implants: %v", msg.Err))
		return m, nil

	case CallbackControlSuccessMsg:
		if msg.Action == "revoke" {
			m.removeCallback(msg.Callback.ID)
		} else {
			m.upsertCallback(msg.Callback)
		}
		m.AddOutput("success", fmt.Sprintf("Implant %s: %s", msg.Callback.ID, msg.Action))
		return m, nil

	case CallbackControlFailedMsg:
		m.AddOutput("error", fmt.Sprintf("Implant %s: %s failed: %v", msg.CallbackID, msg.Action, msg.Err))
		return m, nil

	case PantryFetchErrorMsg:
		m.AddOutput("warning", fmt.Sprintf("Failed to load attack graph: %v", msg.Err))
		return m, nil

	case KitchenDisconnectedMsg:
		m.connected = false
		m.connectionState = "disconnected"
		m.AddOutput("warning", "Disconnected from Kitchen")
		return m, nil

	case ReconnectingMsg:
		m.connected = false
		m.reconnectAttempt = msg.Attempt
		m.connectionState = fmt.Sprintf("reconnecting (%d)", msg.Attempt)
		return m, m.listenForReconnecting()

	case ReconnectedMsg:
		m.connected = true
		m.reconnectAttempt = 0
		m.connectionState = "connected"
		m.AddOutput("success", "Reconnected to Kitchen")
		m.activityLog.Add(IconSuccess, "Connection restored")
		return m, tea.Batch(
			m.listenForReconnected(),
			m.listenForBeacons(),
			m.listenForColeslaw(),
			m.listenForHistory(),
			m.listenForExpressData(),
			m.listenForAnalysisProgress(),
			m.listenForAnalysisMetadataSync(),
			m.fetchPantryCmd(),
			m.fetchKnownEntitiesCmd(),
			m.fetchCallbacksCmd(),
		)

	case AuthExpiredMsg:
		m.needsReAuth = true
		m.connected = false
		m.connectionState = "auth expired"
		m.prevView = m.view
		m.prevFocus = m.focus
		m.view = ViewReAuth
		m.AddOutput("warning", "Session expired - re-authentication required")
		return m, m.listenForAuthExpired()

	case OrderSentMsg:
		orderShort := msg.OrderID
		if len(orderShort) > 8 {
			orderShort = orderShort[:8]
		}
		m.AddOutput("success", fmt.Sprintf("Order %s sent to %s", orderShort, msg.AgentID))
		return m, nil

	case OrderFailedMsg:
		orderShort := msg.OrderID
		if len(orderShort) > 8 {
			orderShort = orderShort[:8]
		}
		m.AddOutput("error", fmt.Sprintf("Failed to send order: %s", msg.Err.Error()))
		if orderShort != "" {
			m.AddOutput("info", fmt.Sprintf("  Order ID: %s", orderShort))
		}
		return m, nil

	case AutoPRDeploymentSuccessMsg:
		m.StartWaiting(msg.StagerID, msg.PRURL, msg.Vuln, "Auto PR", msg.DwellTime)
		m.AddOutput("success", fmt.Sprintf("PR created: %s", msg.PRURL))
		m.activityLog.Add(IconSuccess, "Payload deployed, waiting for callback")
		historyEntry := counter.HistoryPayload{
			Type:      "exploit.attempted",
			SessionID: m.config.SessionID,
			StagerID:  msg.StagerID,
			PRURL:     msg.PRURL,
			Outcome:   "pending",
		}
		if msg.Vuln != nil {
			historyEntry.VulnID = msg.Vuln.ID
			historyEntry.Repository = msg.Vuln.Repository
		}
		return m, m.recordHistoryCmd(historyEntry)

	case AutoPRDeploymentFailedMsg:
		m.pendingCachePoison = nil
		if m.phase == PhaseWaiting {
			m.CancelWaiting()
		}
		friendlyErr := parseDeploymentError(msg.Err)
		m.AddOutput("error", "PR deployment failed: "+friendlyErr)
		m.AddOutput("hint", "Try option [4] Copy payload for manual deployment")
		m.activityLog.Add(IconError, "Deployment failed: "+friendlyErr)
		historyEntry := counter.HistoryPayload{
			Type:        "exploit.failed",
			SessionID:   m.config.SessionID,
			StagerID:    msg.StagerID,
			ErrorDetail: msg.Err.Error(),
			Outcome:     "failed",
		}
		return m, m.recordHistoryCmd(historyEntry)

	case RunnerTargetWorkflowPushSuccessMsg:
		m.StartWaitingForRunnerTarget(msg.StagerID, msg.Target, "Workflow Push", msg.DwellTime)
		switch {
		case msg.BranchURL != "":
			m.AddOutput("success", fmt.Sprintf("Runner-target workflow branch pushed: %s", msg.BranchURL))
		case msg.Branch != "":
			m.AddOutput("success", fmt.Sprintf("Runner-target workflow branch pushed: %s", msg.Branch))
		default:
			m.AddOutput("success", "Runner-target workflow branch pushed")
		}
		m.activityLog.Add(IconSuccess, "Runner-target workflow deployed, waiting for callback")
		historyEntry := counter.HistoryPayload{
			Type:       "exploit.attempted",
			SessionID:  m.config.SessionID,
			StagerID:   msg.StagerID,
			Outcome:    "pending",
			Repository: "",
		}
		if msg.Target != nil {
			historyEntry.Repository = msg.Target.Repository
		}
		if msg.BranchURL != "" {
			historyEntry.PRURL = msg.BranchURL
		}
		return m, m.recordHistoryCmd(historyEntry)

	case RunnerTargetWorkflowPushFailedMsg:
		if m.phase == PhaseWizard || m.view == ViewWizard {
			m.CloseWizard()
		}
		friendlyErr := parseDeploymentError(msg.Err)
		m.AddOutput("error", "Runner-target workflow deployment failed: "+friendlyErr)
		m.AddOutput("hint", "Use the copy workflow path if you need a manual or alternate-foothold route.")
		m.activityLog.Add(IconError, "Runner-target deployment failed: "+friendlyErr)
		historyEntry := counter.HistoryPayload{
			Type:        "exploit.failed",
			SessionID:   m.config.SessionID,
			StagerID:    msg.StagerID,
			ErrorDetail: msg.Err.Error(),
			Outcome:     "failed",
		}
		if msg.Target != nil {
			historyEntry.Repository = msg.Target.Repository
		}
		return m, m.recordHistoryCmd(historyEntry)

	case IssueDeploymentSuccessMsg:
		m.StartWaiting(msg.StagerID, msg.IssueURL, msg.Vuln, "Issue", msg.DwellTime)
		m.AddOutput("success", fmt.Sprintf("Issue created: %s", msg.IssueURL))
		m.activityLog.Add(IconSuccess, "Issue deployed, waiting for callback")
		historyEntry := counter.HistoryPayload{
			Type:      "exploit.attempted",
			SessionID: m.config.SessionID,
			StagerID:  msg.StagerID,
			PRURL:     msg.IssueURL,
			Outcome:   "pending",
		}
		if msg.Vuln != nil {
			historyEntry.VulnID = msg.Vuln.ID
			historyEntry.Repository = msg.Vuln.Repository
		}
		return m, m.recordHistoryCmd(historyEntry)

	case IssueDeploymentFailedMsg:
		m.pendingCachePoison = nil
		if m.phase == PhaseWaiting {
			m.CancelWaiting()
		}
		friendlyErr := parseDeploymentError(msg.Err)
		m.AddOutput("error", "Issue deployment failed: "+friendlyErr)
		m.AddOutput("hint", "Try option [3] Copy payload for manual deployment")
		m.activityLog.Add(IconError, "Deployment failed: "+friendlyErr)
		historyEntry := counter.HistoryPayload{
			Type:        "exploit.failed",
			SessionID:   m.config.SessionID,
			StagerID:    msg.StagerID,
			ErrorDetail: msg.Err.Error(),
			Outcome:     "failed",
		}
		return m, m.recordHistoryCmd(historyEntry)

	case CommentDeploymentSuccessMsg:
		m.StartWaiting(msg.StagerID, msg.CommentURL, msg.Vuln, "Comment", msg.DwellTime)
		m.AddOutput("success", fmt.Sprintf("Comment created: %s", msg.CommentURL))
		m.activityLog.Add(IconSuccess, "Comment deployed, waiting for callback")
		historyEntry := counter.HistoryPayload{
			Type:      "exploit.attempted",
			SessionID: m.config.SessionID,
			StagerID:  msg.StagerID,
			PRURL:     msg.CommentURL,
			Outcome:   "pending",
		}
		if msg.Vuln != nil {
			historyEntry.VulnID = msg.Vuln.ID
			historyEntry.Repository = msg.Vuln.Repository
		}
		return m, m.recordHistoryCmd(historyEntry)

	case CommentDeploymentFailedMsg:
		m.pendingCachePoison = nil
		if m.phase == PhaseWaiting {
			m.CancelWaiting()
		}
		friendlyErr := parseDeploymentError(msg.Err)
		m.AddOutput("error", "Comment deployment failed: "+friendlyErr)
		m.AddOutput("hint", "Try option [4] Copy payload for manual deployment")
		m.activityLog.Add(IconError, "Deployment failed: "+friendlyErr)
		historyEntry := counter.HistoryPayload{
			Type:        "exploit.failed",
			SessionID:   m.config.SessionID,
			StagerID:    msg.StagerID,
			ErrorDetail: msg.Err.Error(),
			Outcome:     "failed",
		}
		return m, m.recordHistoryCmd(historyEntry)

	case LOTPDeploymentSuccessMsg:
		m.StartWaiting(msg.StagerID, msg.PRURL, msg.Vuln, "LOTP", msg.DwellTime)
		m.AddOutput("success", fmt.Sprintf("LOTP PR created: %s", msg.PRURL))
		m.activityLog.Add(IconSuccess, "LOTP deployed, waiting for npm install")
		historyEntry := counter.HistoryPayload{
			Type:      "exploit.attempted",
			SessionID: m.config.SessionID,
			StagerID:  msg.StagerID,
			PRURL:     msg.PRURL,
			Outcome:   "pending",
		}
		if msg.Vuln != nil {
			historyEntry.VulnID = msg.Vuln.ID
			historyEntry.Repository = msg.Vuln.Repository
		}
		return m, m.recordHistoryCmd(historyEntry)

	case LOTPDeploymentFailedMsg:
		m.pendingCachePoison = nil
		if m.phase == PhaseWaiting {
			m.CancelWaiting()
		}
		friendlyErr := parseDeploymentError(msg.Err)
		m.AddOutput("error", "LOTP deployment failed: "+friendlyErr)
		m.AddOutput("hint", "Try option [4] Copy payload for manual deployment")
		m.activityLog.Add(IconError, "Deployment failed: "+friendlyErr)
		historyEntry := counter.HistoryPayload{
			Type:        "exploit.failed",
			SessionID:   m.config.SessionID,
			StagerID:    msg.StagerID,
			ErrorDetail: msg.Err.Error(),
			Outcome:     "failed",
		}
		return m, m.recordHistoryCmd(historyEntry)

	case AutoDispatchSuccessMsg:
		if msg.StagerID != "" {
			m.StartWaiting(msg.StagerID, "", msg.Vuln, "Dispatch", msg.DwellTime)
		}
		if msg.InputName != "" {
			m.AddOutput("success", fmt.Sprintf("workflow_dispatch triggered (input: %s)", msg.InputName))
		} else {
			m.AddOutput("success", "workflow_dispatch triggered")
		}
		if msg.StagerID != "" {
			m.activityLog.Add(IconSuccess, "Pivot dispatch sent, waiting for agent")
		} else {
			m.activityLog.Add(IconSuccess, "Workflow dispatch sent")
		}
		historyEntry := counter.HistoryPayload{
			Type:      "exploit.attempted",
			SessionID: m.config.SessionID,
			StagerID:  msg.StagerID,
			Outcome:   "pending",
		}
		if msg.Vuln != nil {
			historyEntry.VulnID = msg.Vuln.ID
			historyEntry.Repository = msg.Vuln.Repository
		} else if msg.Repository != "" {
			historyEntry.Repository = msg.Repository
		}
		return m, m.recordHistoryCmd(historyEntry)

	case AutoDispatchFailedMsg:
		m.pendingCachePoison = nil
		if m.phase == PhaseWaiting {
			m.CancelWaiting()
		}
		friendlyErr := parseDeploymentError(msg.Err)
		m.AddOutput("error", "workflow_dispatch failed: "+friendlyErr)
		m.activityLog.Add(IconError, "Dispatch failed: "+friendlyErr)
		historyEntry := counter.HistoryPayload{
			Type:        "exploit.failed",
			SessionID:   m.config.SessionID,
			StagerID:    msg.StagerID,
			ErrorDetail: msg.Err.Error(),
			Outcome:     "failed",
		}
		return m, m.recordHistoryCmd(historyEntry)

	case CloudPivotOrderMsg:
		args := []string{"pivot", msg.Provider}
		for k, v := range msg.Config {
			args = append(args, fmt.Sprintf("--%s=%s", k, v))
		}
		m.AddOutput("info", fmt.Sprintf("Sending OIDC pivot order (%s) with %d config args...", msg.Provider, len(msg.Config)))
		return m, m.sendOrder("oidc", args)

	case CloudShellExitMsg:
		m.focus = FocusInput
		m.input.Focus()
		m.historyIndex = -1
		m.completionHint = ""
		m.updatePlaceholder()
		if msg.Err != nil {
			m.AddOutput("warning", fmt.Sprintf("Cloud shell exited with error: %v", msg.Err))
		} else {
			m.AddOutput("info", "Cloud shell closed. Session preserved - type 'cloud shell' to re-enter.")
		}
		return m, nil

	case SSHShellExitMsg:
		m.focus = FocusInput
		m.input.Focus()
		m.historyIndex = -1
		m.completionHint = ""
		m.updatePlaceholder()
		if msg.Err != nil {
			m.AddOutput("warning", fmt.Sprintf("SSH shell exited with error: %v", msg.Err))
		} else {
			m.AddOutput("info", "SSH shell closed. Session preserved - type 'ssh shell' to re-enter.")
		}
		return m, nil

	case PivotResultMsg:
		if !msg.Success {
			m.AddOutput("error", fmt.Sprintf("Pivot failed: %v", msg.Err))
			return m, nil
		}

		autoAnalyze := false

		switch msg.Type {
		case PivotTypeGitHubToken:
			if len(msg.DispatchWorkflows) > 0 {
				imported := m.importDispatchWorkflowsToPantry(msg.DispatchWorkflows)
				m.AddOutput("success", fmt.Sprintf("Found %d dispatchable workflows", len(msg.DispatchWorkflows)))
				if imported > 0 || len(msg.DispatchWorkflows) > 0 {
					m.RebuildTree()
				}
				m.activityLog.Add(IconSecret, fmt.Sprintf("Pivot found %d dispatchable workflows", len(msg.DispatchWorkflows)))
			}
			if len(msg.NewVulns) > 0 {
				m.vulnerabilities = append(m.vulnerabilities, msg.NewVulns...)
				m.importVulnerabilitiesToPantry(msg.NewVulns)
			}

			if msg.TotalFound > 0 {
				newCount := len(msg.NewRepos)
				knownCount := msg.TotalFound - newCount
				if knownCount > 0 {
					m.AddOutput("info", fmt.Sprintf("Token sees %d repos (%d already known)", msg.TotalFound, knownCount))
				}
			}

			if len(msg.NewPrivateRepos) > 0 {
				m.AddOutput("success", fmt.Sprintf("Discovered %d PRIVATE repos!", len(msg.NewPrivateRepos)))
				for i, repo := range msg.NewPrivateRepos {
					if i >= 10 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more", len(msg.NewPrivateRepos)-10))
						break
					}
					m.AddOutput("info", "  🔒 "+repo)
				}
			}

			if len(msg.NewOrgs) > 0 {
				m.AddOutput("success", fmt.Sprintf("Discovered %d NEW orgs!", len(msg.NewOrgs)))
				for i, org := range msg.NewOrgs {
					if i >= 5 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more orgs", len(msg.NewOrgs)-5))
						break
					}
					m.AddOutput("info", fmt.Sprintf("  + %s", org))
				}
				m.activityLog.Add(IconSecret, fmt.Sprintf("Pivot expanded to %d new orgs", len(msg.NewOrgs)))
			}

			if len(msg.NewRepos) > 0 {
				m.pivotTargets = append(m.pivotTargets, msg.NewRepos...)
				m.AddOutput("success", fmt.Sprintf("Discovered %d NEW repos", len(msg.NewRepos)))
				for i, repo := range msg.NewRepos {
					if i >= 10 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more", len(msg.NewRepos)-10))
						break
					}
					m.AddOutput("info", fmt.Sprintf("  + %s", repo))
				}
				m.activityLog.Add(IconScan, fmt.Sprintf("Auto-analyzing %d pivot repos...", len(msg.NewRepos)))
				autoAnalyze = true
			} else if msg.TotalFound > 0 {
				m.AddOutput("info", "No new repos discovered (all already known)")
			}

		case PivotTypeGitHubApp:
			if msg.TotalFound > 0 {
				newCount := len(msg.NewRepos)
				knownCount := msg.TotalFound - newCount
				if knownCount > 0 {
					m.AddOutput("info", fmt.Sprintf("Installation token sees %d repos (%d already known)", msg.TotalFound, knownCount))
				}
			}

			if len(msg.NewPrivateRepos) > 0 {
				m.AddOutput("success", fmt.Sprintf("Discovered %d PRIVATE repos!", len(msg.NewPrivateRepos)))
				for i, repo := range msg.NewPrivateRepos {
					if i >= 10 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more", len(msg.NewPrivateRepos)-10))
						break
					}
					m.AddOutput("info", "  🔒 "+repo)
				}
			}

			if len(msg.NewOrgs) > 0 {
				m.AddOutput("success", fmt.Sprintf("Discovered %d NEW orgs!", len(msg.NewOrgs)))
				for i, org := range msg.NewOrgs {
					if i >= 5 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more orgs", len(msg.NewOrgs)-5))
						break
					}
					m.AddOutput("info", fmt.Sprintf("  + %s", org))
				}
				m.activityLog.Add(IconSecret, fmt.Sprintf("App pivot expanded to %d new orgs", len(msg.NewOrgs)))
			}

			if len(msg.NewRepos) > 0 {
				m.pivotTargets = append(m.pivotTargets, msg.NewRepos...)
				m.AddOutput("success", fmt.Sprintf("Discovered %d NEW repos", len(msg.NewRepos)))
				autoAnalyze = true
			}

			if len(msg.TokenPermissions) > 0 {
				m.appTokenPermissions = clonePermissionMap(msg.TokenPermissions)
			}

			for _, cred := range msg.Credentials {
				if !cred.CanUseAsToken() {
					continue
				}
				if len(msg.TokenPermissions) > 0 {
					m.storeAppDisplayPermissions(appIDFromPivotSource(cred.Source), msg.TokenPermissions)
				}
				m.pivotToken = &cred
				if m.initialTokenInfo == nil && m.tokenInfo != nil {
					m.initialTokenInfo = m.tokenInfo
					cfg, _ := counter.LoadConfig()
					if cfg != nil {
						cfg.InitialAccessToken = m.tokenInfo.Value
						cfg.InitialAccessTokenSource = m.tokenInfo.Source
						_ = counter.SaveConfig(cfg)
					}
				}
				m.swapActiveToken(cred)

				m.AddOutput("success", fmt.Sprintf("GitHub App pivot successful - %s", cred.Name))
				m.AddOutput("info", fmt.Sprintf("  Token: %s", cred.MaskedValue()))
				if cred.ExpiresAt != nil {
					m.AddOutput("info", fmt.Sprintf("  Expires: %s", cred.ExpiresAt.Format("15:04:05")))
				}
				m.AddOutput("success", "Active token swapped - all commands now use installation token")
				m.flashMessage = "Token swapped → " + cred.Name
				m.flashUntil = time.Now().Add(5 * time.Second)

				if m.target != "" && m.config.KitchenURL != "" {
					m.AddOutput("info", fmt.Sprintf("Auto-analyzing %s with installation token %s...", m.target, cred.MaskedValue()))
					m.activityLog.Add(IconScan, fmt.Sprintf("Re-analyzing %s with installation token", m.target))
					m.GenerateSuggestions()
					return m, m.runAnalysis()
				}
			}
			m.activityLog.Add(IconSecret, "App pivot: installation token obtained")

		case PivotTypeCloudOIDC:
			if len(msg.Credentials) > 0 {
				for _, cred := range msg.Credentials {
					m.AddToLootStash(cred)
				}
				m.AddOutput("success", fmt.Sprintf("OIDC pivot to %s successful", msg.Provider))
				m.activityLog.Add(IconSecret, fmt.Sprintf("Cloud pivot: %d creds extracted", len(msg.Credentials)))
			}

		case PivotTypeSSHKey:
			if m.updateSSHState(msg) {
				m.AddOutput("warning", "Replaced previous SSH shell session for a different key")
			}
			m.updateSSHPivotSecret(msg)
			successes := 0
			writes := 0
			for _, result := range msg.SSHResults {
				if result.Success {
					successes++
					if result.Permission == "write" {
						writes++
					}
				}
			}
			m.AddOutput("success", fmt.Sprintf("SSH pivot tested %d repo(s) with %s", len(msg.SSHResults), msg.KeyName))
			if msg.KeyType != "" || msg.KeyFP != "" {
				details := []string{}
				if msg.KeyType != "" {
					details = append(details, msg.KeyType)
				}
				if msg.KeyFP != "" {
					details = append(details, msg.KeyFP)
				}
				m.AddOutput("info", "  Key: "+strings.Join(details, " · "))
			}
			if successes == 0 {
				m.AddOutput("warning", "  No GitHub repo access confirmed")
				m.activityLog.Add(IconWarning, fmt.Sprintf("SSH probe found no accessible repos for %s", msg.KeyName))
			} else {
				m.AddOutput("success", fmt.Sprintf("  Confirmed %d accessible repos (%d write)", successes, writes))
				m.activityLog.Add(IconSuccess, fmt.Sprintf("SSH probe confirmed %d repo(s) (%d write)", successes, writes))
				shown := 0
				for _, result := range msg.SSHResults {
					if !result.Success {
						continue
					}
					shown++
					if shown > 10 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more", successes-10))
						break
					}
					line := fmt.Sprintf("  + %s (%s)", result.Repo, result.Permission)
					if result.Branch != "" {
						line += " → " + result.Branch
					}
					m.AddOutput("info", line)
				}
			}
			if len(msg.NewPerms) > 0 {
				m.AddOutput("success", fmt.Sprintf("  Gained write access on %d known repos", len(msg.NewPerms)))
			}
			if len(msg.NewRepos) > 0 {
				m.AddOutput("success", fmt.Sprintf("  Added %d operator-supplied repo targets", len(msg.NewRepos)))
				for i, repo := range msg.NewRepos {
					if i >= 10 {
						m.AddOutput("info", fmt.Sprintf("  ... and %d more", len(msg.NewRepos)-10))
						break
					}
					m.AddOutput("info", "  + "+repo)
				}
			}
			if msg.SSHScope != "" {
				m.AddOutput("info", "  Scope: "+msg.SSHScope)
			}
			m.AddOutput("info", "  Type 'ssh shell' to enter an isolated git/ssh shell")
		}
		m.RebuildTree()
		m.lootStashDirty = true
		m.GenerateSuggestions()
		if autoAnalyze && m.tokenInfo != nil && m.config.KitchenURL != "" {
			return m, m.runPivotAnalysis()
		}
		return m, nil

	case SecretValidationMsg:
		var secret *CollectedSecret
		for i := range m.lootStash {
			if m.lootStash[i].Name == msg.SecretName {
				secret = &m.lootStash[i]
				break
			}
		}
		if secret == nil {
			for i := range m.sessionLoot {
				if m.sessionLoot[i].Name == msg.SecretName {
					secret = &m.sessionLoot[i]
					break
				}
			}
		}
		if secret == nil {
			return m, nil
		}

		now := time.Now()
		secret.Validated = true
		secret.ValidatedAt = &now

		if msg.Success {
			secret.ValidStatus = msg.ValidStatus
			secret.Owner = msg.Owner
			secret.Scopes = msg.Scopes
			secret.ExpiresAt = msg.ExpiresAt
			m.activityLog.Add(IconSuccess, fmt.Sprintf("Validated %s (owner: %s)", secret.Name, msg.Owner))
			if len(msg.Scopes) > 0 {
				m.AddOutput("info", fmt.Sprintf("Scopes: %s", strings.Join(msg.Scopes, ", ")))
			}
		} else {
			secret.ValidStatus = msg.ValidStatus
			m.activityLog.Add(IconError, fmt.Sprintf("Validation failed for %s: %s", secret.Name, msg.ValidStatus))
		}
		m.RebuildLootTree()
		return m, nil

	case AnalysisStartedMsg:
		if m.analysisProgress == nil {
			m.beginAnalysisProgress(msg.AnalysisID, msg.Target, msg.TargetType, false)
		}
		m.AddOutput("info", fmt.Sprintf("Analyzing %s (%s)...", msg.Target, msg.TargetType))
		m.AddOutput("info", "This may take a moment - cloning and analyzing workflows.")
		return m, nil

	case AnalysisProgressMsg:
		m.applyAnalysisProgress(msg.Progress)
		if m.setupWizard != nil && m.setupWizard.Step == 7 && m.setupWizard.AnalysisRunning {
			m.setupWizard.Status = ""
		}
		return m, m.listenForAnalysisProgress()

	case AnalysisMetadataSyncMsg:
		switch msg.Sync.Status {
		case counter.AnalysisMetadataSyncStatusStarted:
			if msg.Sync.Message != "" {
				m.activityLog.Add(IconInfo, msg.Sync.Message)
			}
			return m, m.listenForAnalysisMetadataSync()
		case counter.AnalysisMetadataSyncStatusCompleted:
			if msg.Sync.Message != "" {
				m.activityLog.Add(IconSuccess, msg.Sync.Message)
			}
			return m, tea.Batch(m.listenForAnalysisMetadataSync(), m.fetchPantryCmd(), m.fetchKnownEntitiesCmd())
		case counter.AnalysisMetadataSyncStatusFailed:
			if msg.Sync.Message != "" {
				m.activityLog.Add(IconWarning, msg.Sync.Message)
			}
			if msg.Sync.Error != "" {
				m.AddOutput("warning", "Repository access update incomplete: "+msg.Sync.Error)
			}
			return m, tea.Batch(m.listenForAnalysisMetadataSync(), m.fetchPantryCmd(), m.fetchKnownEntitiesCmd())
		default:
			return m, m.listenForAnalysisMetadataSync()
		}

	case AnalysisCompletedMsg:
		if msg.AnalysisID != "" && m.activeAnalysisID != "" && msg.AnalysisID != m.activeAnalysisID {
			return m, nil
		}
		model, cmd := m.handleAnalysisCompleted(msg)
		outcome := fmt.Sprintf("%d repos, %d vulns", msg.Result.ReposAnalyzed, len(msg.Result.Findings))
		if len(msg.Result.SecretFindings) > 0 {
			outcome += fmt.Sprintf(", %d secrets", len(msg.Result.SecretFindings))
		}
		historyType := "analysis.completed"
		if msg.Deep {
			historyType = "deep_analysis.completed"
		}
		historyEntry := counter.HistoryPayload{
			Type:       historyType,
			SessionID:  m.config.SessionID,
			Target:     m.target,
			TargetType: m.targetType,
			Outcome:    outcome,
		}
		if m.tokenInfo != nil {
			historyEntry.TokenType = m.tokenInfo.Type.ShortType()
		}
		return model, tea.Batch(cmd, m.recordHistoryCmd(historyEntry))

	case AnalysisErrorMsg:
		if msg.AnalysisID != "" && m.activeAnalysisID != "" && msg.AnalysisID != m.activeAnalysisID {
			return m, nil
		}
		m.clearAnalysisProgress()
		m.AddOutput("error", fmt.Sprintf("Analysis failed: %v", msg.Err))
		historyEntry := counter.HistoryPayload{
			Type:        "analysis.failed",
			SessionID:   m.config.SessionID,
			Target:      m.target,
			TargetType:  m.targetType,
			ErrorDetail: msg.Err.Error(),
		}
		return m, m.recordHistoryCmd(historyEntry)

	case PurgePreviewMsg:
		scopeSpec := msg.Response.ScopeType + ":" + msg.Response.ScopeValue
		m.AddOutput("info", fmt.Sprintf("Purge preview for %s", scopeSpec))
		m.AddOutput("info", fmt.Sprintf("Would remove %d pantry assets and %d known entity records", msg.Response.PantryAssets, msg.Response.KnownEntities))
		m.AddOutput("info", "Run 'purge confirm "+scopeSpec+"' to execute")
		return m, nil

	case PurgeCompletedMsg:
		scopeSpec := msg.Response.ScopeType + ":" + msg.Response.ScopeValue
		m.replaceKnownEntities(msg.KnownEntities)
		m.applyPurgedPantry(msg.Pantry)
		m.AddOutput("success", fmt.Sprintf("Purged %s", scopeSpec))
		m.AddOutput("info", fmt.Sprintf("Removed %d pantry assets and %d known entity records", msg.Response.PantryAssets, msg.Response.KnownEntities))
		if purgeScopeCoversTarget(msg.Response.ScopeType, msg.Response.ScopeValue, m.targetType, m.target) {
			m.clearPurgedTarget(msg.Response.ScopeType, msg.Response.ScopeValue)
		} else {
			m.activityLog.Add(IconWarning, "Purged "+scopeSpec)
		}
		return m, nil

	case PurgeErrorMsg:
		m.AddOutput("error", fmt.Sprintf("Purge failed: %v", msg.Err))
		m.activityLog.Add(IconError, fmt.Sprintf("Purge failed: %v", msg.Err))
		return m, nil

	case HistoryFetchedMsg:
		m.opHistory.SetEntries(msg.Entries)
		for _, e := range msg.Entries {
			m.activityLog.AddEntry(ActivityEntry{
				Timestamp: e.Timestamp,
				Icon:      iconForHistoryType(e.Type),
				Message:   messageForHistoryEntry(e),
			})
		}
		m.activityLog.Sort()
		return m, nil

	case HistoryFetchErrorMsg:
		m.activityLog.Add(IconWarning, "History fetch failed")
		return m, nil

	case HistoryEntryMsg:
		m.opHistory.Add(msg.Entry)
		m.activityLog.AddEntry(ActivityEntry{
			Timestamp: msg.Entry.Timestamp,
			Icon:      iconForHistoryType(msg.Entry.Type),
			Message:   messageForHistoryEntry(msg.Entry),
		})
		return m, nil

	case HistoryRecordErrorMsg:
		m.activityLog.Add(IconWarning, fmt.Sprintf("History recording failed: %v", msg.Err))
		return m, nil

	case HistoryReceivedMsg:
		ts := msg.History.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		entry := HistoryEntry{
			Type:       msg.History.Type,
			Timestamp:  ts,
			Repository: msg.History.Repository,
			VulnID:     msg.History.VulnID,
			Outcome:    msg.History.Outcome,
		}
		m.opHistory.Add(entry)
		m.activityLog.AddEntry(ActivityEntry{
			Timestamp: entry.Timestamp,
			Icon:      iconForHistoryType(entry.Type),
			Message:   messageForHistoryEntry(entry),
		})
		return m, m.listenForHistory()

	case ExpressDataMsg:
		return m.handleExpressData(msg)

	case LootSyncMsg:
		return m.handleLootSync(msg)

	case TokenAcquiredMsg:
		return m.handleTokenAcquired(msg)

	case TokenErrorMsg:
		return m.handleTokenError(msg)

	case TokenInfoFetchedMsg:
		return m.handleTokenInfoFetched(msg)

	case TokenInfoErrorMsg:
		return m.handleTokenInfoError(msg)

	case WizardPreflightFetchedMsg:
		if m.wizard == nil || msg.Key != m.wizard.PreflightKey {
			return m, nil
		}
		m.wizard.PreflightLoading = false
		m.wizard.PreflightError = ""
		m.wizard.Preflight = msg.Response
		if m.wizard.DeliveryMethod == DeliveryComment {
			m.normalizeCommentTarget()
		}
		return m, nil

	case WizardPreflightErrorMsg:
		if m.wizard == nil || msg.Key != m.wizard.PreflightKey {
			return m, nil
		}
		m.wizard.PreflightLoading = false
		m.wizard.PreflightError = msg.Err.Error()
		return m, nil

	case TargetLoadedMsg:
		m.target = msg.Target
		m.targetType = msg.TargetType
		m.AddOutput("info", fmt.Sprintf("Target loaded from config: %s (%s)", msg.Target, msg.TargetType))

		return m, nil

	case TokenVaultSavedMsg:
		if msg.Err != nil {
			m.AddOutput("warning", fmt.Sprintf("Failed to save token vault: %v", msg.Err))
		}
		return m, nil

	case LootExportedMsg:
		switch {
		case msg.Err != nil:
			m.activityLog.Add(IconError, fmt.Sprintf("Export failed: %v", msg.Err))
		case msg.Count == 0:
			m.activityLog.Add(IconWarning, "No exportable tokens (ephemeral/expired filtered)")
		default:
			m.activityLog.Add(IconSuccess, fmt.Sprintf("Exported %d token(s) to ~/.smokedmeat/tokens.yaml", msg.Count))
		}
		return m, nil

	case UITickMsg:
		if m.lootFlash && time.Now().Before(m.lootFlashUntil) {
			return m, tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return UITickMsg{} })
		}
		m.lootFlash = false
		return m, nil

	case TimerTickMsg:
		return m, timerTickCmd()

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.stickersLayout.Resize(msg.Width, msg.Height)
		m.input.SetWidth(max(m.width-8, 1))

		m.ready = true
		return m, nil
	}

	// Update focused component
	if m.focus == FocusInput {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m Model) handlePasteMsg(msg tea.PasteMsg) (tea.Model, tea.Cmd) {
	sw := m.setupWizard
	if m.view == ViewSetupWizard && sw != nil {
		if (sw.Step == 1) ||
			(sw.Step == 3 && sw.OperatorNameChoice == OperatorNameCustom) ||
			(sw.Step == 5 && sw.TokenSubStep == setupTokenSubStepInput) ||
			(sw.Step == 6 && sw.TargetSubStep == 1) {
			var cmd tea.Cmd
			m.setupInput, cmd = m.setupInput.Update(msg)
			return m, cmd
		}
		return m, nil
	}
	if m.view == ViewWizard {
		prevIssue := m.currentCommentIssueNumber()
		prevPR := m.currentCommentPRNumber()
		var cmd tea.Cmd
		m.wizardInput, cmd = m.wizardInput.Update(msg)
		if prevIssue != m.currentCommentIssueNumber() || prevPR != m.currentCommentPRNumber() {
			return m, tea.Batch(cmd, m.startWizardPreflight(false))
		}
		return m, cmd
	}
	if m.view == ViewOmnibox {
		return m.handleOmniboxPaste(msg)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) handleKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.phase != PhaseSetup && m.focus == FocusInput && !m.view.IsModal() && isStandaloneShiftPress(msg) {
		m.activityLogShiftHeld = true
		return m, nil
	}

	// Handle setup wizard mode
	if m.view == ViewSetupWizard {
		return m.handleSetupWizardKeyMsg(msg)
	}

	// Handle wizard mode separately
	if m.view == ViewWizard {
		return m.handleWizardKeyMsg(msg)
	}

	// Handle license modal
	if m.view == ViewLicense {
		return m.handleLicenseKeyMsg(msg)
	}

	// Handle help modal
	if m.view == ViewHelp {
		return m.handleHelpKeyMsg(msg)
	}

	// Handle kill chain modal
	if m.view == ViewKillChain {
		return m.handleKillChainKeyMsg(msg)
	}

	// Handle theme modal
	if m.view == ViewTheme {
		return m.handleThemeKeyMsg(msg)
	}

	// Handle omnibox modal
	if m.view == ViewOmnibox {
		return m.handleOmniboxKeyMsg(msg)
	}

	if m.view == ViewCallbacks {
		return m.handleCallbacksKeyMsg(msg)
	}

	// Handle re-auth modal
	if m.view == ViewReAuth {
		return m.handleReAuthKeyMsg(msg)
	}

	// Handle waiting phase keys
	if m.phase == PhaseWaiting && m.waiting != nil {
		switch msg.String() {
		case "o":
			if m.waiting.PRURL != "" {
				if err := m.openBrowser(m.waiting.PRURL); err != nil {
					m.AddOutput("info", Hyperlink(m.waiting.PRURL, "Click to open PR →"))
				} else {
					m.AddOutput("success", "Opened PR in browser")
				}
			}
			return m, nil
		case "esc":
			m.AddOutput("info", "Canceled waiting for agent")
			m.activityLog.Add(IconInfo, "Canceled beacon wait")
			m.CancelWaiting()
			return m, nil
		}
	}

	if m.shouldRouteToInput(msg) {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.completionHint = ""
		return m, cmd
	}

	switch msg.String() {
	case "ctrl+c", "q":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit

	case "/":
		if m.view == ViewFindings || m.view == ViewAgent {
			m.openOmnibox()
			return m, nil
		}

	case "1", "2", "3", "4", "5":
		// Number keys select suggestion and open wizard (only when input empty)
		if m.focus != FocusInput || m.input.Value() == "" {
			idx := int(msg.String()[0] - '1')
			if idx >= 0 && idx < len(m.suggestions) {
				suggestion := m.suggestions[idx]
				if suggestion.VulnIndex >= 0 && suggestion.VulnIndex < len(m.vulnerabilities) {
					if err := m.OpenWizard(&m.vulnerabilities[suggestion.VulnIndex]); err != nil {
						m.AddOutput("error", err.Error())
						return m, nil
					}
					return m, m.startWizardPreflight(false)
				}
				// Non-vuln suggestion - just execute the command
				m.input.SetValue(suggestion.Command)
				return m.executeCommand()
			}
		}

	case "f1", "f2", "f3", "f4", "f5":
		if (m.view == ViewFindings || m.view == ViewAgent) && m.paneShortcut(msg.Code) {
			return m, nil
		}

	case "tab":
		if m.focus == FocusInput {
			// Tab completion when already in input
			m.completeInput()
		} else {
			// Focus input when not in input
			m.focusInputPane()
		}
		return m, nil

	case "alt+tab":
		// Cycle focus between panels
		m.focus = (m.focus + 1) % 2
		m.updateFocus()
		return m, nil

	case "shift+tab", "alt+shift+tab":
		// Reverse cycle focus
		m.focus = (m.focus + 1) % 2
		m.updateFocus()
		return m, nil

	case "enter":
		if m.focus == FocusInput {
			if m.input.Value() == "" {
				return m, nil
			}
			if m.opPromptActive {
				secretRef := strings.TrimSpace(m.input.Value())
				secretRef = strings.Trim(secretRef, `"'`)
				m.input.SetValue("")
				m.opPromptActive = false
				m.updatePlaceholder()
				if strings.HasPrefix(secretRef, "op://") {
					m.AddOutput("info", "Reading from 1Password...")
					return m, m.executeOPRead(secretRef)
				}
				m.AddOutput("error", "Invalid secret reference - must start with op://")
				return m, nil
			}
			return m.executeCommand()
		}
		switch m.paneFocus {
		case PaneFocusFindings:
			m.TreeToggleExpand()
		case PaneFocusMenu:
			if m.menuCursor >= 0 && m.menuCursor < len(m.suggestions) {
				suggestion := m.suggestions[m.menuCursor]
				if suggestion.VulnIndex >= 0 && suggestion.VulnIndex < len(m.vulnerabilities) {
					if err := m.OpenWizard(&m.vulnerabilities[suggestion.VulnIndex]); err != nil {
						m.AddOutput("error", err.Error())
						return m, nil
					}
					return m, m.startWizardPreflight(false)
				}
				if suggestion.Command != "" {
					m.input.SetValue(suggestion.Command)
					return m.executeCommand()
				}
			}
		case PaneFocusLoot:
			m.LootTreeToggleExpand()
		}
		return m, nil

	case "j":
		if m.focus != FocusInput {
			switch m.paneFocus {
			case PaneFocusFindings:
				m.TreeCursorDown()
			case PaneFocusMenu:
				m.MenuCursorDown()
			case PaneFocusLoot:
				m.LootTreeCursorDown()
			case PaneFocusActivity:
				m.activityLog.CursorDown()
			}
			return m, nil
		}

	case "k":
		if m.focus != FocusInput {
			switch m.paneFocus {
			case PaneFocusFindings:
				m.TreeCursorUp()
			case PaneFocusMenu:
				m.MenuCursorUp()
			case PaneFocusLoot:
				m.LootTreeCursorUp()
			case PaneFocusActivity:
				m.activityLog.CursorUp()
			}
			return m, nil
		}

	case "d":
		if m.focus != FocusInput && m.paneFocus == PaneFocusFindings {
			scopeType, scope := m.selectedDeepAnalyzeScope()
			if scopeType != "" && scope != "" {
				return m.handleAnalyzeForSelection(scopeType, scope, true)
			}
		}
		return m, nil

	case "f":
		if m.focus != FocusInput {
			m.ToggleTreeFilter()
			return m, nil
		}

	case "g":
		if m.focus != FocusInput || m.input.Value() == "" {
			m.handleGraphCommand()
			return m, nil
		}

	case "L", "shift+l":
		if m.phase != PhaseSetup && !m.view.IsModal() && (m.focus != FocusInput || m.input.Value() == "") {
			m.activityLogManualExpanded = !m.activityLogManualExpanded
			m.activityLogShiftHeld = false
			if m.activityLogManualExpanded {
				m.flashMessage = "Activity log expanded"
			} else {
				m.flashMessage = "Activity log collapsed"
			}
			m.flashUntil = time.Now().Add(2 * time.Second)
			return m, nil
		}

	case "r":
		if m.focus != FocusInput || m.input.Value() == "" {
			if m.phase == PhasePostExploit {
				m.dismissKnownDwellAgents()
				if m.activeAgent != nil {
					m.clearSessionContext(m.activeAgent.ID)
				}
				m.activeAgent = nil
				m.dwellMode = false
				m.jobDeadline = time.Time{}
				if m.initialTokenInfo != nil && m.tokenInfo.Value != m.initialTokenInfo.Value {
					m.tokenInfo = m.initialTokenInfo
					m.pivotToken = nil
					m.refreshAuthDrivenViews()
					m.activityLog.Add(IconSuccess, "Reverted to operator token (agent gone)")
				}
				m.activityLog.Add(IconInfo, "Returned to findings phase")
				m.TransitionToPhase(PhaseRecon)
				return m, nil
			}
		}

	case "?":
		m.prevView = m.view
		m.prevFocus = m.focus
		m.view = ViewHelp
		return m, nil

	case "I", "shift+i", "C", "shift+c":
		if !m.view.IsModal() {
			return m, m.openCallbacksModal()
		}

	case "s":
		if m.focus != FocusInput || m.input.Value() == "" {
			if m.paneFocus == PaneFocusFindings {
				if spec := m.selectedTreeTargetSpec(); spec != "" {
					return m.handleSetCommand("target", spec)
				}
			}
			return m, nil
		}

	case "t":
		if m.focus != FocusInput || m.input.Value() == "" {
			m.prevView = m.view
			m.prevFocus = m.focus
			m.view = ViewTheme
			m.themeOriginal = ActiveTheme()
			names := ThemeNames()
			for i, n := range names {
				if n == m.themeOriginal {
					m.themeCursor = i
					break
				}
			}
			return m, nil
		}

	case "T", "shift+t":
		if m.focus != FocusInput || m.input.Value() == "" {
			m.prevView = m.view
			m.prevFocus = m.focus
			m.view = ViewTheme
			m.themeOriginal = ActiveTheme()
			names := ThemeNames()
			for i, n := range names {
				if n == m.themeOriginal {
					m.themeCursor = i
					break
				}
			}
			return m, nil
		}

	case "up":
		if m.focus == FocusInput {
			m.historyUp()
		} else {
			// Pane navigation
			switch m.paneFocus {
			case PaneFocusFindings:
				m.TreeCursorUp()
			case PaneFocusMenu:
				m.MenuCursorUp()
			case PaneFocusLoot:
				m.LootTreeCursorUp()
			case PaneFocusActivity:
				m.activityLog.CursorUp()
			}
		}
		return m, nil

	case "down":
		if m.focus == FocusInput {
			m.historyDown()
		} else {
			// Pane navigation
			switch m.paneFocus {
			case PaneFocusFindings:
				m.TreeCursorDown()
			case PaneFocusMenu:
				m.MenuCursorDown()
			case PaneFocusLoot:
				m.LootTreeCursorDown()
			case PaneFocusActivity:
				m.activityLog.CursorDown()
			}
		}
		return m, nil

	case "left", "h":
		if m.focus != FocusInput {
			switch m.paneFocus {
			case PaneFocusFindings:
				m.TreeCollapse()
			case PaneFocusLoot:
				m.LootTreeCollapse()
			}
			return m, nil
		}

	case "right", "l":
		if m.focus != FocusInput {
			switch m.paneFocus {
			case PaneFocusFindings:
				m.TreeExpand()
			case PaneFocusLoot:
				m.LootTreeExpand()
			}
			return m, nil
		}

	case "c":
		if m.paneFocus == PaneFocusLoot {
			secret := m.SelectedLootSecret()
			if secret != nil {
				if err := clipboardWriteAll(secret.Value); err != nil {
					m.activityLog.Add(IconError, fmt.Sprintf("Copy failed: %v", err))
				} else {
					m.lootFlash = true
					m.lootFlashUntil = time.Now().Add(800 * time.Millisecond)
					m.activityLog.Add(IconSuccess, fmt.Sprintf("Copied %s", secret.Name))
					return m, tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg { return UITickMsg{} })
				}
			}
			return m, nil
		}

	case "e":
		if m.focus != FocusInput && m.paneFocus == PaneFocusLoot {
			return m, m.exportLootCmd()
		}

	case "x":
		if m.focus != FocusInput && m.paneFocus == PaneFocusFindings {
			node := m.SelectedTreeNode()
			if node == nil {
				m.AddOutput("error", "Action shortcut requires a [WORKFLOW], [VULN], or [SH-RUNNER] node.")
				return m, nil
			}
			switch node.Type {
			case TreeNodeWorkflow:
				target, err := m.workflowDispatchTargetForNode(node)
				if err != nil {
					m.AddOutput("error", err.Error())
					return m, nil
				}
				if err := m.OpenWorkflowDispatchWizard(target); err != nil {
					m.AddOutput("error", err.Error())
				}
				return m, nil
			case TreeNodeVuln:
				cmd, err := m.openSelectedVulnerabilityWizard("")
				if err != nil {
					m.AddOutput("error", err.Error())
				}
				return m, cmd
			case TreeNodeSelfHostedRunner:
				cmd, err := m.openSelectedRunnerTarget()
				if err != nil {
					m.AddOutput("error", err.Error())
				}
				return m, cmd
			default:
				m.AddOutput("error", "Action shortcut requires a [WORKFLOW], [VULN], or [SH-RUNNER] node.")
			}
		}

	case "K":
		if m.focus != FocusInput && m.paneFocus == PaneFocusFindings && m.pantry != nil {
			node := m.SelectedTreeNode()
			if node != nil && node.Type == TreeNodeVuln {
				chain, err := m.pantry.TraceKillChain(node.ID)
				if err == nil {
					m.killChainVM = &KillChainViewModel{
						Chain:     chain,
						VulnLabel: m.killChainVulnLabel(node.ID),
						Prereq:    m.detectPrerequisites(chain),
					}
					m.prevView = m.view
					m.prevFocus = m.focus
					m.view = ViewKillChain
				}
				return m, nil
			}
		}

	case "v":
		if m.paneFocus == PaneFocusLoot {
			secret := m.SelectedLootSecret()
			if secret == nil {
				return m, nil
			}
			if secret.CanUseAsToken() {
				m.activityLog.Add(IconInfo, fmt.Sprintf("Validating %s...", secret.Name))
				return m, m.validateSecretByName(secret.Name, secret.Value)
			}
			m.activityLog.Add(IconWarning, fmt.Sprintf("%s is not a validatable token type", secret.Name))
			return m, nil
		}

	case "p":
		if m.paneFocus == PaneFocusLoot {
			secret := m.SelectedLootSecret()
			if secret == nil {
				return m, nil
			}
			if !m.canPivotSecret(*secret) {
				m.activityLog.Add(IconWarning, m.pivotUnavailableReason(*secret))
				return m, nil
			}
			if secret.CanUseAsSSHKey() {
				return m.startSSHPivot(*secret, "")
			}
			if secret.Type == "github_app_key" || secret.Type == "github_app_id" {
				appID := ""
				if secret.PairedAppID != "" {
					appID = secret.PairedAppID
				} else if secret.Type == "github_app_id" {
					appID = strings.TrimSpace(secret.Value)
				}
				m.activityLog.Add(IconInfo, "Pivoting via GitHub App...")
				return m, m.executePivot(PivotTypeGitHubApp, appID)
			}
			if secret.CanUseAsToken() {
				m.preparePivotToken(*secret)
				m.activityLog.Add(IconInfo, fmt.Sprintf("Pivoting with %s...", secret.Name))
				return m, m.executePivotWithSecret(*secret, "")
			}
			m.activityLog.Add(IconWarning, fmt.Sprintf("%s cannot be used for pivot", secret.Name))
			return m, nil
		}

	case "u":
		if m.paneFocus == PaneFocusLoot {
			secret := m.SelectedLootSecret()
			if secret == nil {
				return m, nil
			}
			if secret.CanUseAsToken() {
				m.swapActiveToken(*secret)
				m.flashMessage = fmt.Sprintf("Now using %s as active token", secret.Name)
				m.flashUntil = time.Now().Add(2 * time.Second)
			} else {
				m.activityLog.Add(IconWarning, fmt.Sprintf("%s is not a usable token type", secret.Name))
			}
			return m, nil
		}

	case "i":
		if m.initialTokenInfo != nil && m.tokenInfo.Value != m.initialTokenInfo.Value {
			m.tokenInfo = m.initialTokenInfo
			m.pivotToken = nil
			m.refreshAuthDrivenViews()
			m.flashMessage = "Reverted to initial access token"
			m.flashUntil = time.Now().Add(2 * time.Second)
			m.activityLog.Add(IconSuccess, "Reverted to initial access token")
			cfg, _ := counter.LoadConfig()
			if cfg != nil {
				cfg.InitialAccessToken = ""
				cfg.InitialAccessTokenSource = ""
				_ = counter.SaveConfig(cfg)
			}
			return m, nil
		}

	case "esc":
		if m.view.IsModal() {
			m.view = m.prevView
			m.focus = m.prevFocus
			return m, nil
		}
		if m.focus == FocusInput && m.input.Value() != "" {
			if m.opPromptActive {
				m.opPromptActive = false
				m.AddOutput("info", "Canceled 1Password token input")
			}
			m.input.SetValue("")
			m.historyIndex = -1
			m.completionHint = ""
			m.updatePlaceholder()
			return m, nil
		}
		// In Setup phase, only command input exists - no pane cycling
		if m.phase == PhaseSetup {
			return m, nil
		}
		// Cycle panes: Findings → Menu → Loot → Activity → Input
		if m.focus == FocusInput {
			m.focusPane(PaneFocusFindings)
		} else {
			switch m.paneFocus {
			case PaneFocusFindings:
				m.paneFocus = PaneFocusMenu
			case PaneFocusMenu:
				m.paneFocus = PaneFocusLoot
			case PaneFocusLoot:
				m.paneFocus = PaneFocusActivity
			case PaneFocusActivity:
				m.focusInputPane()
				return m, nil
			}
			m.updateFocus()
		}
		return m, nil
	}

	// Pass through to focused component
	if m.focus == FocusInput {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		// Clear completion hint on any typing
		m.completionHint = ""
		return m, cmd
	}

	return m, nil
}

// updateFocus updates component focus states
func (m *Model) updateFocus() {
	switch m.focus {
	case FocusInput:
		m.input.Focus()
	default:
		m.input.Blur()
		m.activityLogShiftHeld = false
	}
}

func (m Model) handleKeyReleaseMsg(msg tea.KeyReleaseMsg) (tea.Model, tea.Cmd) {
	if isStandaloneShiftRelease(msg) {
		m.activityLogShiftHeld = false
	}
	return m, nil
}

func isStandaloneShiftPress(msg tea.KeyPressMsg) bool {
	switch msg.Code {
	case tea.KeyLeftShift, tea.KeyRightShift:
		return true
	}
	switch msg.String() {
	case "shift", "left_shift", "right_shift":
		return true
	}
	switch msg.Keystroke() {
	case "shift", "left_shift", "right_shift":
		return true
	}
	return false
}

func isStandaloneShiftRelease(msg tea.KeyReleaseMsg) bool {
	switch msg.Code {
	case tea.KeyLeftShift, tea.KeyRightShift:
		return true
	}
	switch msg.String() {
	case "shift", "left_shift", "right_shift":
		return true
	}
	switch msg.Keystroke() {
	case "shift", "left_shift", "right_shift":
		return true
	}
	return false
}

func (m Model) selectedDeepAnalyzeScope() (scopeType, scope string) {
	node := m.SelectedTreeNode()
	if node == nil {
		return "", ""
	}
	switch node.Type {
	case TreeNodeOrg:
		return "org", m.treeNodeOrg(node)
	case TreeNodeRepo, TreeNodeWorkflow, TreeNodeSelfHostedRunner, TreeNodeJob, TreeNodeVuln:
		return "repo", m.treeNodeRepo(node)
	default:
		return "", ""
	}
}

func (m Model) selectedTreeTargetSpec() string {
	node := m.SelectedTreeNode()
	if node == nil {
		return ""
	}
	switch node.Type {
	case TreeNodeOrg:
		if org := m.treeNodeOrg(node); org != "" {
			return "org:" + org
		}
	case TreeNodeRepo, TreeNodeSelfHostedRunner:
		if repo := m.treeNodeRepo(node); repo != "" {
			return "repo:" + repo
		}
	}
	return ""
}

func (m Model) shouldRouteToInput(msg tea.KeyPressMsg) bool {
	if m.phase == PhaseWaiting && m.waiting != nil {
		return false
	}
	if m.focus != FocusInput {
		return false
	}
	switch msg.String() {
	case "/":
		return strings.TrimSpace(m.input.Value()) != ""
	case "ctrl+c", "?", "esc", "tab", "enter", "up", "down", "alt+tab", "shift+tab", "alt+shift+tab", "f1", "f2", "f3", "f4", "f5":
		return false
	default:
		return true
	}
}

func (m *Model) historyUp() {
	if len(m.history) == 0 {
		return
	}
	if m.historyIndex < len(m.history)-1 {
		m.historyIndex++
		m.input.SetValue(m.history[len(m.history)-1-m.historyIndex])
		m.input.CursorEnd()
	}
}

func (m *Model) historyDown() {
	if len(m.history) == 0 {
		return
	}
	switch {
	case m.historyIndex > 0:
		m.historyIndex--
		m.input.SetValue(m.history[len(m.history)-1-m.historyIndex])
		m.input.CursorEnd()
	case m.historyIndex == 0:
		m.historyIndex = -1
		m.input.SetValue("")
		m.input.CursorEnd()
	}
}

// handleLicenseKeyMsg handles keyboard input when license modal is active
func (m Model) handleLicenseKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc", "enter", "q":
		m.view = m.prevView
		return m, nil
	}
	return m, nil
}

// handleHelpKeyMsg handles keyboard input when help modal is active
func (m Model) handleHelpKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc", "enter", "q", "?":
		m.view = m.prevView
		return m, nil
	}
	return m, nil
}

// handleReAuthKeyMsg handles keyboard input when re-auth modal is active
func (m Model) handleReAuthKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "enter":
		m.needsReAuth = false
		m.view = m.prevView
		m.AddOutput("info", "Re-authenticating with SSH agent...")
		return m, m.connectToKitchen()
	}
	return m, nil
}

func (m Model) handleThemeKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	names := ThemeNames()
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "j", "down":
		if m.themeCursor < len(names)-1 {
			m.themeCursor++
			ApplyTheme(names[m.themeCursor])
		}
		return m, nil
	case "k", "up":
		if m.themeCursor > 0 {
			m.themeCursor--
			ApplyTheme(names[m.themeCursor])
		}
		return m, nil
	case "enter":
		selected := names[m.themeCursor]
		ApplyTheme(selected)
		saveThemeToConfig(selected)
		m.view = m.prevView
		m.focus = m.prevFocus
		return m, nil
	case "esc", "t":
		ApplyTheme(m.themeOriginal)
		m.view = m.prevView
		m.focus = m.prevFocus
		return m, nil
	}
	return m, nil
}

func (m Model) handleKillChainKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc", "K":
		m.view = m.prevView
		m.focus = m.prevFocus
		m.killChainVM = nil
		return m, nil
	case "j", "down":
		if m.killChainVM != nil {
			m.killChainVM.ScrollPos++
		}
		return m, nil
	case "k", "up":
		if m.killChainVM != nil && m.killChainVM.ScrollPos > 0 {
			m.killChainVM.ScrollPos--
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) killChainVulnLabel(vulnID string) string {
	for _, v := range m.vulnerabilities {
		if v.ID == vulnID {
			return m.vulnFirstLineText(v)
		}
	}
	return vulnID
}
