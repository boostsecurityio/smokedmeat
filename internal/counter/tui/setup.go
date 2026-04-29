// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func (m Model) handleSetupWizardKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	sw := m.setupWizard
	if sw == nil {
		m.view = ViewFindings
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "esc":
		m.quitting = true
		return m, tea.Quit

	case "tab":
		if sw.Step == 5 && sw.TokenSubStep > setupTokenSubStepChoice {
			sw.Error = ""
			sw.Status = ""
			sw.TokenSubStep = setupTokenSubStepChoice
			m.setupInput.EchoMode = textinput.EchoNormal
			m.setupInput.Blur()
			return m, nil
		}
		if sw.Step == 6 && sw.TargetSubStep > 0 {
			sw.Error = ""
			sw.Status = ""
			sw.TargetSubStep = 0
			m.setupInput.Blur()
			return m, nil
		}
		if !sw.CanGoBack() {
			return m, nil
		}
		sw.Error = ""
		sw.Status = ""
		sw.Step--
		switch sw.Step {
		case 1:
			m.setupInput.SetValue(sw.KitchenURL)
			m.setupInput.Placeholder = "https://kitchen.example.com"
			m.setupInput.Focus()
		case 2:
			m.setupInput.Blur()
		case 3:
			if sw.OperatorNameChoice == OperatorNameCustom {
				m.setupInput.Focus()
			} else {
				m.setupInput.Blur()
			}
		case 4:
			m.setupInput.Blur()
		case 5:
			sw.TokenSubStep = setupTokenSubStepChoice
			m.setupInput.Blur()
		case 6:
			sw.TargetSubStep = 0
			m.setupInput.Blur()
		}
		return m, nil

	case "r":
		if sw.Step == 4 && sw.Error != "" && !sw.Connecting {
			sw.Error = ""
			sw.AuthAttempt = 0
			sw.Connecting = true
			sw.Status = "Connecting..."
			return m, m.finishSetup()
		}
		if sw.Step == 7 && !sw.AnalysisRunning {
			return m.startSetupAnalysis(true)
		}

	case "enter":
		if sw.AnalysisRunning || sw.AnalysisRetryPending {
			return m, nil
		}
		return m.advanceSetupStep()

	case "up", "k":
		if sw.Step == 2 && len(sw.Keys) > 1 {
			if sw.SelectedKey > 0 {
				sw.SelectedKey--
			}
			return m, nil
		}
		if sw.Step == 3 {
			if sw.OperatorNameChoice > OperatorNameGenerated {
				sw.OperatorNameChoice--
				m.setupInput.Blur()
			}
			return m, nil
		}
		if sw.Step == 4 {
			if sw.DeployMethod > KeyDeployClipboard {
				sw.DeployMethod--
			}
			return m, nil
		}
		if sw.Step == 5 && sw.TokenSubStep == setupTokenSubStepChoice {
			if sw.TokenChoice > SetupTokenPAT {
				sw.TokenChoice--
			}
			return m, nil
		}
		if sw.Step == 6 && sw.TargetSubStep == 0 {
			if sw.TargetChoice > SetupTargetOrg {
				sw.TargetChoice--
			}
			return m, nil
		}

	case "down", "j":
		if sw.Step == 2 && len(sw.Keys) > 1 {
			if sw.SelectedKey < len(sw.Keys)-1 {
				sw.SelectedKey++
			}
			return m, nil
		}
		if sw.Step == 3 {
			if sw.OperatorNameChoice < OperatorNameCustom {
				sw.OperatorNameChoice++
				m.setupInput.Focus()
			}
			return m, nil
		}
		if sw.Step == 4 {
			if sw.DeployMethod < KeyDeploySkip {
				sw.DeployMethod++
			}
			return m, nil
		}
		if sw.Step == 5 && sw.TokenSubStep == setupTokenSubStepChoice {
			if sw.TokenChoice < SetupTokenBrowser {
				sw.TokenChoice++
			}
			return m, nil
		}
		if sw.Step == 6 && sw.TargetSubStep == 0 {
			if sw.TargetChoice < SetupTargetRepo {
				sw.TargetChoice++
			}
			return m, nil
		}

	case "1":
		return m.handleSetupWizardNumber(0)
	case "2":
		return m.handleSetupWizardNumber(1)
	case "3":
		return m.handleSetupWizardNumber(2)
	case "4":
		return m.handleSetupWizardNumber(3)
	}

	if sw.Step == 1 {
		var cmd tea.Cmd
		m.setupInput, cmd = m.setupInput.Update(msg)
		return m, cmd
	}
	if sw.Step == 3 && sw.OperatorNameChoice == OperatorNameCustom {
		var cmd tea.Cmd
		m.setupInput, cmd = m.setupInput.Update(msg)
		return m, cmd
	}
	if sw.Step == 5 && sw.TokenSubStep == setupTokenSubStepInput {
		var cmd tea.Cmd
		m.setupInput, cmd = m.setupInput.Update(msg)
		return m, cmd
	}
	if sw.Step == 6 && sw.TargetSubStep == 1 {
		var cmd tea.Cmd
		m.setupInput, cmd = m.setupInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) handleSetupWizardNumber(idx int) (tea.Model, tea.Cmd) {
	sw := m.setupWizard
	if sw == nil {
		return m, nil
	}

	if sw.Step == 2 && len(sw.Keys) > 0 && idx < len(sw.Keys) {
		sw.SelectedKey = idx
		return m, nil
	}
	if sw.Step == 3 && idx <= int(OperatorNameCustom) {
		sw.OperatorNameChoice = OperatorNameChoice(idx)
		if sw.OperatorNameChoice == OperatorNameCustom {
			m.setupInput.Focus()
		} else {
			m.setupInput.Blur()
		}
		return m, nil
	}
	if sw.Step == 4 && idx <= int(KeyDeploySkip) {
		sw.DeployMethod = KeyDeployMethod(idx)
		return m, nil
	}
	if sw.Step == 5 && sw.TokenSubStep == setupTokenSubStepChoice && idx <= int(SetupTokenBrowser) {
		sw.TokenChoice = SetupTokenChoice(idx)
		return m, nil
	}
	if sw.Step == 6 && sw.TargetSubStep == 0 && idx <= int(SetupTargetRepo) {
		sw.TargetChoice = SetupTargetChoice(idx)
		return m, nil
	}
	return m, nil
}

func (m Model) advanceSetupStep() (tea.Model, tea.Cmd) {
	sw := m.setupWizard

	switch sw.Step {
	case 1:
		url := strings.TrimSpace(m.setupInput.Value())
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			sw.Error = "URL must start with http:// or https://"
			return m, nil
		}
		sw.KitchenURL = url
		sw.Error = ""
		sw.Status = "Checking Kitchen..."

		return m, tea.Batch(verifyKitchenURL(url), loadSSHKeysCmd())

	case 2:
		if len(sw.Keys) == 0 {
			return m, nil
		}
		sw.Step = 3
		sw.GeneratedName = counter.GenerateOperatorName()
		sw.OperatorNameChoice = OperatorNameGenerated
		m.setupInput.SetValue("")
		m.setupInput.Placeholder = "my_operator_name"
		m.setupInput.Blur()
		return m, nil

	case 3:
		var name string
		if sw.OperatorNameChoice == OperatorNameGenerated {
			name = sw.GeneratedName
		} else {
			name = strings.TrimSpace(m.setupInput.Value())
			if !isValidOperatorName(name) {
				sw.Error = "Min 8 chars, lowercase letters and underscores only"
				return m, nil
			}
		}
		sw.OperatorName = name
		sw.Error = ""

		key := sw.Keys[sw.SelectedKey]
		sw.AuthKeysLine = name + " " + key.AuthorizedKey

		sw.Step = 4
		sw.DeployMethod = KeyDeployClipboard
		return m, nil

	case 4:
		if sw.Connecting {
			return m, nil
		}
		sw.Error = ""
		switch sw.DeployMethod {
		case KeyDeploySSH:
			host := extractHost(sw.KitchenURL)
			sw.Status = "Deploying key via SSH..."
			return m, deployKeyViaSSHCmd(host, sw.AuthKeysLine)
		case KeyDeployClipboard:
			if sw.Status != "" && strings.HasPrefix(sw.Status, "Copied") {
				sw.AuthAttempt = 0
				sw.Connecting = true
				sw.Status = "Connecting..."
				return m, m.finishSetup()
			}
			return m, copyToClipboardCmd(sw.AuthKeysLine)
		case KeyDeploySkip:
			sw.AuthAttempt = 0
			sw.Connecting = true
			sw.Status = "Connecting..."
			return m, m.finishSetup()
		}

	case 5:
		if sw.TokenSubStep == setupTokenSubStepChoice {
			sw.TokenSubStep = setupTokenSubStepInput
			sw.Error = ""
			m.setupInput.SetValue("")
			m.setupInput.EchoMode = textinput.EchoNormal
			switch sw.TokenChoice {
			case SetupTokenPAT:
				m.setupInput.Placeholder = "ghp_xxxxxxxxxxxxxxxxxxxx"
				m.setupInput.EchoMode = textinput.EchoPassword
				m.setupInput.EchoCharacter = '•'
				m.setupInput.Focus()
			case SetupTokenGH:
				sw.Status = "Fetching token from GitHub CLI..."
				m.setupInput.Blur()
				return m, m.executeSetupGHAuthToken()
			case SetupTokenOP:
				m.setupInput.Placeholder = "op://Vault/Item/field"
				m.setupInput.Focus()
			case SetupTokenBrowser:
				m.setupInput.Placeholder = "ghp_xxxxxxxxxxxxxxxxxxxx"
				m.setupInput.EchoMode = textinput.EchoPassword
				m.setupInput.EchoCharacter = '•'
				m.setupInput.Blur()
				sw.Status = "Opening browser..."
				return m, tea.Batch(openBrowserCmd(gitHubPATURL), func() tea.Msg {
					return setupBrowserOpenedMsg{}
				})
			}
			return m, nil
		}
		if sw.TokenSubStep == setupTokenSubStepWarning {
			sw.Step = 6
			sw.TargetSubStep = 0
			m.setupInput.Blur()
			return m, nil
		}

		val := strings.TrimSpace(m.setupInput.Value())
		switch sw.TokenChoice {
		case SetupTokenPAT, SetupTokenBrowser:
			if len(val) < 8 {
				sw.Error = "Token too short (minimum 8 characters)"
				return m, nil
			}
			sw.TokenValue = val
			sw.Error = ""
			sw.Status = "Verifying token..."
			return m, m.setupSaveTokenAndFetchInfo(val, "pat", "")
		case SetupTokenOP:
			val = strings.Trim(val, "\"'")
			if !strings.HasPrefix(val, "op://") {
				sw.Error = "Must start with op:// (e.g. op://Vault/Item/field)"
				return m, nil
			}
			parts := strings.SplitN(strings.TrimPrefix(val, "op://"), "/", 3)
			if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
				sw.Error = "Need vault/item/field (e.g. op://Vault/Item/password)"
				return m, nil
			}
			sw.OPSecretRef = val
			sw.Status = "Fetching from 1Password..."
			return m, m.executeSetupOPRead(val)
		}

	case 6:
		if sw.TargetSubStep == 0 {
			sw.TargetSubStep = 1
			sw.Error = ""
			m.setupInput.EchoMode = textinput.EchoNormal
			m.setupInput.SetValue("")
			if sw.TargetChoice == SetupTargetOrg {
				m.setupInput.Placeholder = "acme-corp"
			} else {
				m.setupInput.Placeholder = "acme-corp/app"
			}
			m.setupInput.Focus()
			return m, nil
		}

		val := strings.TrimSpace(m.setupInput.Value())
		if val == "" {
			sw.Error = "Target cannot be empty"
			return m, nil
		}
		sw.TargetValue = val
		sw.Error = ""
		m.setupInput.Blur()

		if sw.TargetChoice == SetupTargetOrg {
			m.setTargetValue("org:"+val, "setup")
		} else {
			m.setTargetValue("repo:"+val, "setup")
		}

		sw.Step = 7
		return m.startSetupAnalysis(true)

	case 7:
		if sw.AnalysisRunning || sw.AnalysisRetryPending {
			return m, nil
		}
		if sw.AnalysisSummary != "" {
			m.setupWizard = nil
			m.TransitionToPhase(PhaseRecon)
			return m, nil
		}
		return m.startSetupAnalysis(true)
	}
	return m, nil
}

func (m Model) startSetupAnalysis(resetAttempt bool) (tea.Model, tea.Cmd) {
	sw := m.setupWizard
	if sw == nil {
		return m, nil
	}
	if resetAttempt {
		sw.AnalysisAttempt = 0
	}
	sw.Error = ""
	sw.Status = ""
	sw.AnalysisSummary = ""
	sw.AnalysisRetryPending = false
	sw.AnalysisRunning = true
	sw.AnalysisStart = time.Now()
	analysisID, err := newAnalysisID()
	if err != nil {
		sw.AnalysisRunning = false
		sw.Error = fmt.Sprintf("Failed to start analysis: %v", err)
		return m, nil
	}
	m.beginAnalysisProgress(analysisID, m.target, m.targetType, false)
	return m, tea.Batch(m.runSetupAnalysis(), timerTickCmd())
}

func setupAnalysisRetryDelays() []time.Duration {
	return []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}
}

func isRetryableSetupAnalysisError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (m *Model) finishSetupTokenVerification() {
	sw := m.setupWizard
	if sw == nil {
		return
	}
	sw.Status = ""
	if DetectTokenType(sw.TokenValue) == TokenTypeFineGrainedPAT {
		sw.TokenSubStep = setupTokenSubStepWarning
		m.setupInput.Blur()
		return
	}
	sw.Step = 6
	sw.TargetSubStep = 0
	m.setupInput.Blur()
}

func isValidOperatorName(name string) bool {
	if len(name) < 8 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

func (m Model) finishSetup() tea.Cmd {
	sw := m.setupWizard
	keyComment := ""
	if sw.SelectedKey >= 0 && sw.SelectedKey < len(sw.Keys) {
		keyComment = sw.Keys[sw.SelectedKey].Comment
	}

	cfg, _ := counter.LoadConfig()
	if cfg == nil {
		cfg = &counter.Config{}
	}
	cfg.KitchenURL = sw.KitchenURL
	cfg.Operator = sw.OperatorName
	cfg.KeyComment = keyComment
	_ = counter.SaveConfig(cfg)

	return m.authenticateSSHCmd()
}

type setupKitchenVerifiedMsg struct {
	OK  bool
	Err string
}

func verifyKitchenURL(kitchenURL string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		url := strings.TrimSuffix(kitchenURL, "/") + "/ws"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return setupKitchenVerifiedMsg{Err: fmt.Sprintf("Invalid URL: %v", err)}
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return setupKitchenVerifiedMsg{Err: fmt.Sprintf("Cannot reach %s — check the URL and ensure Kitchen is running", kitchenURL)}
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			return setupKitchenVerifiedMsg{OK: true}
		}

		return setupKitchenVerifiedMsg{Err: fmt.Sprintf("Unexpected response from %s (HTTP %d) — is this a Kitchen server?", kitchenURL, resp.StatusCode)}
	}
}

type setupBrowserOpenedMsg struct{}

func (m Model) executeSetupGHAuthToken() tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("gh", "auth", "token")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg == "" {
				errMsg = err.Error()
			}
			return SetupTokenErrorMsg{Err: fmt.Errorf("%s", errMsg), Source: "gh"}
		}

		token := strings.TrimSpace(stdout.String())
		if token == "" {
			return SetupTokenErrorMsg{Err: fmt.Errorf("GitHub CLI returned empty token"), Source: "gh"}
		}

		return SetupTokenAcquiredMsg{Token: token, Source: "gh"}
	}
}

func (m Model) executeSetupOPRead(secretRef string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("op", "read", secretRef)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg == "" {
				errMsg = err.Error()
			}
			return SetupTokenErrorMsg{Err: fmt.Errorf("%s", errMsg), Source: "op"}
		}

		token := strings.TrimSpace(stdout.String())
		if token == "" {
			return SetupTokenErrorMsg{Err: fmt.Errorf("1Password returned empty token"), Source: "op"}
		}

		return SetupTokenAcquiredMsg{Token: token, Source: "op", OPSecretRef: secretRef}
	}
}

func (m Model) setupSaveTokenAndFetchInfo(token, source, opRef string) tea.Cmd {
	cfg, _ := counter.LoadConfig()
	if cfg == nil {
		cfg = &counter.Config{}
	}
	cfg.TokenSource = source
	cfg.InitialAccessToken = ""
	cfg.InitialAccessTokenSource = ""
	if source == "pat" {
		cfg.Token = token
		cfg.OPSecretRef = ""
	} else {
		cfg.Token = ""
		cfg.OPSecretRef = opRef
	}
	_ = counter.SaveConfig(cfg)

	return m.fetchSetupTokenInfo(token)
}

func (m Model) fetchSetupTokenInfo(token string) tea.Cmd {
	kitchenURL := m.config.KitchenURL
	if m.setupWizard != nil && m.setupWizard.KitchenURL != "" {
		kitchenURL = m.setupWizard.KitchenURL
	}
	authToken := m.config.AuthToken

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client := counter.NewKitchenClient(counter.KitchenConfig{
			URL:   kitchenURL,
			Token: authToken,
		})
		resp, err := client.FetchTokenInfo(ctx, token, "setup")
		if err != nil {
			return SetupTokenInfoErrorMsg{}
		}
		return SetupTokenInfoMsg{Owner: resp.Owner, Scopes: resp.Scopes}
	}
}

func (m Model) runSetupAnalysis() tea.Cmd {
	token := ""
	if m.tokenInfo != nil {
		token = m.tokenInfo.Value
	}
	if token == "" && m.setupWizard != nil {
		token = m.setupWizard.TokenValue
	}

	kitchenURL := m.config.KitchenURL
	if m.setupWizard != nil && m.setupWizard.KitchenURL != "" {
		kitchenURL = m.setupWizard.KitchenURL
	}
	authToken := m.config.AuthToken
	sessionID := m.config.SessionID
	target := m.target
	targetType := m.targetType

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), analysisRequestTimeout(targetType, false))
		defer cancel()

		client := counter.NewClient(kitchenURL, authToken, sessionID)
		analysisID := ""
		if m.analysisProgress != nil {
			analysisID = m.analysisProgress.AnalysisID
		}
		result, err := client.AnalyzeWithID(ctx, token, target, targetType, analysisID)
		if err != nil {
			if isRecoverableDroppedAnalysisError(err) {
				return AnalysisResponseDroppedMsg{AnalysisID: analysisID, Setup: true, Err: err}
			}
			return SetupAnalysisErrorMsg{AnalysisID: analysisID, Err: err}
		}
		return SetupAnalysisCompletedMsg{AnalysisID: analysisID, Result: result}
	}
}
