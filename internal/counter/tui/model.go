// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
	"github.com/boostsecurityio/smokedmeat/internal/rye"
)

// Focus represents which panel has focus
type Focus int

const (
	FocusSessions Focus = iota
	FocusInput
)

// PaneFocus represents which pane j/k navigation controls
type PaneFocus int

const (
	PaneFocusFindings PaneFocus = iota
	PaneFocusMenu
	PaneFocusLoot
	PaneFocusActivity
)

// Session represents a connected Brisket agent session
type Session struct {
	AgentID   string
	Hostname  string
	OS        string
	Arch      string
	LastSeen  time.Time
	IsOnline  bool
	SessionID string
}

// OutputLine represents a recorded output line
type OutputLine struct {
	Time    time.Time
	Type    string // "info", "success", "error", "warning", "output"
	Content string
}

// Vulnerability represents an injection vulnerability found during scanning
type Vulnerability struct {
	ID          string // V001, V002, etc.
	Fingerprint string
	Repository  string // org/repo
	Workflow    string // .github/workflows/foo.yml
	Job         string // Job name in workflow
	Step        string // Step index or name in workflow
	Line        int    // Line number in workflow
	Title       string // "Injection", "Untrusted Checkout" - human readable
	RuleID      string // "injection", "untrusted_checkout_exec" - poutine rule
	Context     string // "bash", "github_script"
	BashContext string
	Trigger     string // "pull_request", "push", "issues"
	Expression  string // The vulnerable expression
	Severity    string // "critical", "high", "medium", "low"

	InjectionSources   []string
	ReferencedSecrets  []string
	LOTPTool           string
	LOTPAction         string
	LOTPTargets        []string
	CachePoisonWriter  bool
	CachePoisonReason  string
	CachePoisonVictims []cachepoison.VictimCandidate

	GateTriggers   []string
	GateRaw        string
	GateUnsolvable string

	ExploitSupported     bool
	ExploitSupportReason string
}

// Config holds configuration for the TUI
type Config struct {
	SessionID                string
	KitchenURL               string // Internal URL for API calls (may be Docker internal)
	KitchenExternalURL       string // External URL for stagers, graph (reachable from outside)
	KitchenBrowserURL        string // Local browser URL when different from API/external URLs
	AuthToken                string // JWT token for Kitchen authentication
	Operator                 string // Operator name (e.g., "heuristic_stallman")
	KeyComment               string // SSH key comment for filtering
	Token                    string // GitHub PAT (if source is "pat")
	TokenSource              string // "pat", "gh", or "op"
	OPSecretRef              string // 1Password secret reference (if source is "op")
	Target                   string // Target org or repo (e.g., "org:acme" or "repo:acme/app")
	AuthFailed               bool
	InitialAccessToken       string
	InitialAccessTokenSource string
}

// ExternalURL returns the external Kitchen URL for stagers and display.
// Falls back to KitchenURL if no external URL is configured.
func (c Config) ExternalURL() string {
	if c.KitchenExternalURL != "" {
		return c.KitchenExternalURL
	}
	return c.KitchenURL
}

func (c Config) BrowserURL() string {
	if c.KitchenBrowserURL != "" {
		return c.KitchenBrowserURL
	}
	return c.ExternalURL()
}

// Model is the main TUI model
type Model struct {
	// Configuration
	config Config

	// Window dimensions
	width  int
	height int

	// Focus management
	focus     Focus
	paneFocus PaneFocus

	// Sessions panel
	sessions      []Session
	selectedIndex int

	// Input panel
	input       textinput.Model
	wizardInput textinput.Model

	// Output panel
	output []OutputLine

	// Pantry for attack graph data
	pantry *pantry.Pantry

	// Kitchen client (WebSocket via Kitchen)
	kitchenClient counter.KitchenAPI

	// WebSocket message channels (for Bubble Tea subscriptions)
	beaconCh           chan counter.Beacon
	coleslawCh         chan *models.Coleslaw
	historyCh          chan counter.HistoryPayload
	expressDataCh      chan counter.ExpressDataPayload
	analysisProgressCh chan counter.AnalysisProgressPayload
	analysisMetadataCh chan counter.AnalysisMetadataSyncPayload
	authExpiredCh      chan struct{}
	reconnectingCh     chan int
	reconnectedCh      chan struct{}

	// Connection status
	connected        bool
	connectionState  string
	reconnectAttempt int
	needsReAuth      bool

	// Command history
	history      []string
	historyIndex int

	// Quitting flag
	quitting bool

	// Ready flag - set after first WindowSizeMsg is processed
	ready bool

	// Initial access state (pre-agent)
	tokenInfo        *TokenInfo      // GitHub token with type, source, and capabilities
	initialTokenInfo *TokenInfo      // Original token from config (for reverting after pivot)
	target           string          // Target org or repo (e.g., "acme-corp" or "acme-corp/api")
	targetType       string          // "org" or "repo"
	vulnerabilities  []Vulnerability // Found CI/CD vulnerabilities (injection, pwn request)
	selectedVuln     int             // Index of selected vulnerability (-1 = none)
	analysisComplete bool            // True after analysis has run (even with no findings)
	analysisProgress *counter.AnalysisProgressPayload
	activeAnalysisID string
	lastAnalysisID   string
	lightRye         *rye.LightRye // Payload generator

	// Token acquisition state
	opPromptActive bool // Waiting for 1Password secret reference input

	// Completion state
	completionHint string // Shown inline when multiple completions available

	// Phase management (capability state)
	phase      Phase
	phaseStart time.Time

	// View management (presentation state)
	view      View
	prevView  View  // Previous view before modal (for returning from license)
	prevFocus Focus // Previous focus before modal

	// Wizard state (payload configuration)
	wizard *WizardState

	// Waiting state (beacon wait)
	waiting            *WaitingState
	pendingCachePoison *CachePoisonWaitingState

	// Attack tree state
	treeRoot             *TreeNode
	treeNodes            []*TreeNode // Flattened for navigation
	treeCursor           int
	treeFiltered         bool // When true, hide nodes with no vuln-bearing path
	treeRepoCount        int
	treeVisibleRepoCount int
	treeFilterFallback   bool

	// Active agent state
	activeAgent          *AgentState
	jobDeadline          time.Time
	dwellMode            bool
	dismissedDwellAgents map[string]struct{}

	// Loot management
	sessionLoot         []CollectedSecret // Current session
	lootStash           []CollectedSecret // All collected
	lootStashDirty      bool              // Needs saving to vault
	lootTreeRoot        *TreeNode         // Root of loot tree
	lootTreeNodes       []*TreeNode       // Flattened tree for navigation
	lootTreeCursor      int               // Selected node in loot tree
	lootTreeScroll      int               // Scroll offset for visible window
	tokenPermissions    map[string]string // GITHUB_TOKEN permissions from memory dump
	appTokenPermissions map[string]string // GitHub App installation token permissions from pivot
	lootPermissionView  map[string]map[string]string
	appPermissionView   map[string]map[string]string

	// Flash message (temporary notification in status bar)
	flashMessage string
	flashUntil   time.Time

	// Loot flash (highlight loot panel briefly)
	lootFlash      bool
	lootFlashUntil time.Time

	// Runner vars (from gump vars extraction, ${{ vars.X }} values)
	runnerVars map[string]string

	// Cloud pivot state
	cloudState *CloudState
	sshState   *SSHState
	omnibox    *OmniboxState

	// Pivot targets (repos discovered via token pivot)
	pivotTargets []string
	pivotToken   *CollectedSecret // Token being used for pivot (for delivery method checks)

	// Structural secret type map from workflow analysis (env var or secret name → inferred type)
	workflowSecretTypes map[string]string
	hardcodedAppIDs     []string

	// Known entities (repos/orgs we've discovered, for delta computation)
	knownEntities map[string]*KnownEntity

	// Suggestions
	suggestions   []SuggestedAction
	menuCursor    int
	menuScrollPos int

	stickersLayout *StickersLayout

	// Activity log
	activityLog *ActivityLog

	activityLogAutoExpand     bool
	activityLogExpandedUntil  time.Time
	activityLogManualExpanded bool
	activityLogShiftHeld      bool
	analysisFocusRepo         string

	// Operation history (persistent)
	opHistory      *OperationHistory
	callbacks      []counter.CallbackPayload
	callbackAgents map[string][]CallbackAgentLink
	callbackModal  *CallbackModalState

	// Setup wizard state (first-run)
	setupWizard *SetupWizardState
	setupInput  textinput.Model

	// Kill chain modal state
	killChainVM *KillChainViewModel

	// Theme picker state
	themeCursor   int
	themeOriginal ThemeName

	analysisResultPoll *analysisResultPollState
}

type KillChainViewModel struct {
	Chain     pantry.KillChain
	ScrollPos int
	VulnLabel string
	Prereq    *Prerequisite
}

type analysisResultPollState struct {
	AnalysisID  string
	Deep        bool
	Setup       bool
	Attempts    int
	OriginalErr error
}

func (m *Model) updatePlaceholder() {
	m.input.Placeholder = m.getContextualPlaceholder()
}

// NewModel creates a new TUI model
func NewModel(config Config) Model {
	ti := textinput.New()
	ti.Focus()
	ti.CharLimit = 1000
	ti.SetWidth(80)

	wi := textinput.New()
	wi.Placeholder = "Issue # (blank = auto)"
	wi.CharLimit = 10
	wi.SetWidth(20)

	// Initialize LightRye with external URL (for stager callbacks)
	var lr *rye.LightRye
	if config.ExternalURL() != "" {
		lr = rye.NewLightRye(config.ExternalURL())
	}

	// Setup input for setup wizard text fields
	si := textinput.New()
	si.CharLimit = 200
	si.SetWidth(50)

	initialPhase := PhaseSetup
	initialView := ViewSetupWizard

	m := Model{
		config:                config,
		focus:                 FocusInput,
		input:                 ti,
		wizardInput:           wi,
		setupInput:            si,
		sessions:              []Session{},
		output:                []OutputLine{},
		history:               []string{},
		historyIndex:          -1,
		connectionState:       "disconnected",
		selectedVuln:          -1,
		lightRye:              lr,
		phase:                 initialPhase,
		phaseStart:            time.Now(),
		view:                  initialView,
		wizard:                &WizardState{Step: 1, CallbackBudget: 1},
		activityLog:           NewActivityLog(),
		opHistory:             NewOperationHistory(),
		callbacks:             []counter.CallbackPayload{},
		callbackAgents:        make(map[string][]CallbackAgentLink),
		callbackModal:         &CallbackModalState{},
		sessionLoot:           []CollectedSecret{},
		lootStash:             []CollectedSecret{},
		lootPermissionView:    make(map[string]map[string]string),
		appPermissionView:     make(map[string]map[string]string),
		dismissedDwellAgents:  make(map[string]struct{}),
		workflowSecretTypes:   make(map[string]string),
		knownEntities:         make(map[string]*KnownEntity),
		suggestions:           []SuggestedAction{},
		treeFiltered:          false,
		stickersLayout:        NewStickersLayout(),
		activityLogAutoExpand: true,
	}

	needsFullSetup := config.KitchenURL == "" || config.AuthFailed
	startStep := m.computeSetupStartStep(config)

	if startStep > 7 {
		m.phase = PhaseRecon
		m.view = ViewFindings
		m.focus = FocusSessions
		m.paneFocus = PaneFocusFindings
	} else {
		m.setupWizard = &SetupWizardState{
			Step:          startStep,
			BackStepFloor: setupBackStepFloor(startStep),
		}
		if needsFullSetup && config.AuthFailed {
			m.setupWizard.KitchenURL = config.KitchenURL
			m.setupWizard.Error = "Authentication failed. Re-run setup to reconnect."
			m.setupInput.SetValue(config.KitchenURL)
		}
		m.setupInput.Placeholder = "https://kitchen.example.com"
		m.setupInput.Focus()

		switch startStep {
		case 5:
			m.setupInput.Placeholder = "ghp_xxxxxxxxxxxxxxxxxxxx"
			m.setupInput.SetValue("")
			m.setupInput.Blur()
		case 6:
			m.setupInput.Placeholder = "acme-corp"
			m.setupInput.SetValue("")
			m.setupInput.Blur()
		}
	}

	if config.InitialAccessToken != "" {
		m.initialTokenInfo = &TokenInfo{
			Value:     config.InitialAccessToken,
			Type:      DetectTokenType(config.InitialAccessToken),
			Source:    config.InitialAccessTokenSource,
			FetchedAt: time.Now(),
		}
	}

	m.updatePlaceholder()

	return m
}

func (m Model) activityRegionHeight() int {
	if m.activityLogManualExpanded {
		return expandedActivityHeight
	}
	if m.activityLogShiftHeld {
		return expandedActivityHeight
	}
	if m.activityLogAutoExpand && time.Now().Before(m.activityLogExpandedUntil) {
		return expandedActivityHeight
	}
	return defaultActivityHeight
}

func (m *Model) maybeExpandActivityLogAfterCommand(before int) {
	if !m.activityLogAutoExpand || m.activityLog == nil {
		return
	}
	if m.activityLog.Len() <= before {
		return
	}
	m.activityLogExpandedUntil = time.Now().Add(2 * time.Second)
}

func (m *Model) computeSetupStartStep(config Config) int {
	if config.KitchenURL == "" || config.AuthFailed {
		return 1
	}

	hasToken := config.TokenSource != "" || config.Token != ""
	if !hasToken {
		return 5
	}

	hasTarget := config.Target != ""
	if !hasTarget {
		return 6
	}

	// Check if the target was already analyzed
	savedCfg, _ := counter.LoadConfig()
	if savedCfg != nil && savedCfg.LastAnalyzedTarget != "" && savedCfg.LastAnalyzedTarget == savedCfg.Target {
		return 8
	}

	return 7
}

func setupBackStepFloor(startStep int) int {
	if startStep >= 5 {
		return 5
	}
	return 1
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	var cmds []tea.Cmd

	if m.config.KitchenURL != "" && !m.config.AuthFailed {
		cmds = append(cmds, m.connectToKitchen())
	}

	if m.config.TokenSource != "" {
		cmds = append(cmds, m.loadSavedToken())
	}

	if m.config.Target != "" {
		cmds = append(cmds, m.loadSavedTarget())
	}

	cmds = append(cmds, timerTickCmd())

	return tea.Batch(cmds...)
}

func (m Model) loadSavedToken() tea.Cmd {
	switch m.config.TokenSource {
	case "pat":
		if m.config.Token != "" {
			return func() tea.Msg {
				return TokenAcquiredMsg{
					Token:  m.config.Token,
					Source: "config",
				}
			}
		}
	case "gh":
		return m.executeGHAuthToken()
	case "op":
		if m.config.OPSecretRef != "" {
			return m.executeOPRead(m.config.OPSecretRef)
		}
	}
	return nil
}

type TargetLoadedMsg struct {
	Target     string
	TargetType string
}

func (m Model) loadSavedTarget() tea.Cmd {
	if m.config.Target == "" {
		return nil
	}
	return func() tea.Msg {
		value := m.config.Target
		var target, targetType string
		switch {
		case strings.HasPrefix(value, "org:"):
			targetType = "org"
			target = strings.TrimPrefix(value, "org:")
		case strings.HasPrefix(value, "repo:"):
			targetType = "repo"
			target = strings.TrimPrefix(value, "repo:")
		case strings.Contains(value, "/"):
			targetType = "repo"
			target = value
		default:
			targetType = "org"
			target = value
		}
		return TargetLoadedMsg{Target: target, TargetType: targetType}
	}
}

// connectToKitchen returns a command that establishes the Kitchen WebSocket connection
func (m Model) connectToKitchen() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		// Build WebSocket URL from Kitchen URL
		wsURL := m.config.KitchenURL
		if strings.HasPrefix(wsURL, "http://") {
			wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
		} else if strings.HasPrefix(wsURL, "https://") {
			wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
		}
		if !strings.HasSuffix(wsURL, "/ws") {
			wsURL = strings.TrimSuffix(wsURL, "/") + "/ws"
		}

		kitchenConfig := counter.KitchenConfig{
			URL:       wsURL,
			SessionID: m.config.SessionID,
			Token:     m.config.AuthToken,
		}

		client := counter.NewKitchenClient(kitchenConfig)
		if err := client.Connect(ctx); err != nil {
			return KitchenErrorMsg{Err: err}
		}

		return kitchenClientCreatedMsg{client: client}
	}
}

// kitchenClientCreatedMsg is an internal message for passing the Kitchen client
type kitchenClientCreatedMsg struct {
	client counter.KitchenAPI
}

// KitchenErrorMsg represents a Kitchen connection error
type KitchenErrorMsg struct {
	Err error
}

// fetchPantryCmd returns a command that fetches the attack graph from Kitchen
func (m Model) fetchPantryCmd() tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return PantryFetchErrorMsg{Err: fmt.Errorf("not connected to kitchen")}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		p, err := m.kitchenClient.FetchPantry(ctx)
		if err != nil {
			return PantryFetchErrorMsg{Err: err}
		}

		return PantryFetchedMsg{Pantry: p}
	}
}

func (m Model) fetchKnownEntitiesCmd() tea.Cmd {
	return func() tea.Msg {
		if m.kitchenClient == nil {
			return nil
		}
		if strings.TrimSpace(m.config.SessionID) == "" {
			return nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		entities, err := m.kitchenClient.FetchKnownEntities(ctx, m.config.SessionID)
		if err != nil {
			return KnownEntitiesFetchErrorMsg{Err: err}
		}

		return KnownEntitiesFetchedMsg{Entities: entities}
	}
}

func (m *Model) extractVulnerabilitiesFromPantry() []Vulnerability {
	if m.pantry == nil {
		return nil
	}

	pantryVulns := m.pantry.FindVulnerabilities()
	var vulns []Vulnerability

	for _, pv := range pantryVulns {
		cachePoisonVictims := propertyVictimCandidates(pv.Properties, "cache_poison_victims")
		exploitSupported, hasExploitSupport := pv.Properties["exploit_supported"].(bool)
		exploitSupportReason := ""
		if reason, ok := pv.Properties["exploit_support_reason"].(string); ok {
			exploitSupportReason = reason
		}
		if !hasExploitSupport && exploitSupportReason == "" {
			exploitSupported = false
		}

		repo := ""
		if pv.Purl != "" {
			_, org, repoName := pantry.ParsePurl(pv.Purl)
			if org != "" && repoName != "" {
				repo = org + "/" + repoName
			}
		}

		workflow, _ := pv.Properties["path"].(string)
		line := 0
		switch value := pv.Properties["line"].(type) {
		case float64:
			line = int(value)
		case int:
			line = value
		}

		title := formatRuleID(pv.RuleID)
		if value, ok := pv.Properties["title"].(string); ok && value != "" {
			title = value
		}

		vulns = append(vulns, Vulnerability{
			ID:                   pv.ID,
			Fingerprint:          propertyString(pv.Properties, "fingerprint"),
			Repository:           repo,
			Workflow:             workflow,
			Job:                  propertyString(pv.Properties, "job"),
			Step:                 propertyString(pv.Properties, "step"),
			Line:                 line,
			Title:                title,
			RuleID:               pv.RuleID,
			Severity:             pv.Severity,
			Context:              propertyString(pv.Properties, "context"),
			BashContext:          propertyString(pv.Properties, "bash_context"),
			Trigger:              propertyString(pv.Properties, "trigger"),
			Expression:           propertyString(pv.Properties, "expression"),
			InjectionSources:     propertyStringSlice(pv.Properties, "injection_sources"),
			ReferencedSecrets:    propertyStringSlice(pv.Properties, "referenced_secrets"),
			LOTPTool:             propertyString(pv.Properties, "lotp_tool"),
			LOTPAction:           propertyString(pv.Properties, "lotp_action"),
			LOTPTargets:          propertyStringSlice(pv.Properties, "lotp_targets"),
			CachePoisonWriter:    propertyBool(pv.Properties, "cache_poison_writer"),
			CachePoisonReason:    propertyString(pv.Properties, "cache_poison_reason"),
			CachePoisonVictims:   cachePoisonVictims,
			GateTriggers:         propertyStringSlice(pv.Properties, "gate_triggers"),
			GateRaw:              propertyString(pv.Properties, "gate_raw"),
			GateUnsolvable:       propertyString(pv.Properties, "gate_unsolvable"),
			ExploitSupported:     exploitSupported,
			ExploitSupportReason: exploitSupportReason,
		})
	}

	sort.Slice(vulns, func(i, j int) bool {
		return vulnerabilitySortKey(vulns[i]) < vulnerabilitySortKey(vulns[j])
	})

	return vulns
}

func propertyString(props map[string]any, key string) string {
	if props == nil || key == "" {
		return ""
	}
	value, _ := props[key].(string)
	return value
}

func propertyBool(props map[string]any, key string) bool {
	if props == nil || key == "" {
		return false
	}
	value, _ := props[key].(bool)
	return value
}

func vulnerabilitySortKey(vuln Vulnerability) string {
	return strings.Join([]string{
		strings.TrimSpace(vuln.Repository),
		strings.TrimSpace(vuln.Workflow),
		fmt.Sprintf("%09d", vuln.Line),
		strings.TrimSpace(vuln.Job),
		strings.TrimSpace(vuln.Step),
		strings.TrimSpace(vuln.RuleID),
		strings.TrimSpace(vuln.Context),
		strings.TrimSpace(vuln.Expression),
		strings.TrimSpace(vuln.Fingerprint),
		strings.TrimSpace(vuln.ID),
	}, "\x00")
}

// AddOutput records a line and mirrors it to the visible activity log
func (m *Model) AddOutput(lineType, content string) {
	m.output = append(m.output, OutputLine{
		Time:    time.Now(),
		Type:    lineType,
		Content: content,
	})

	// Keep only last 1000 lines
	if len(m.output) > 1000 {
		m.output = m.output[len(m.output)-1000:]
	}

	if m.activityLog != nil {
		if strings.HasPrefix(content, "> ") {
			return
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			m.activityLog.Add(activityIconForOutputType(lineType), line)
		}
	}
}

func activityIconForOutputType(lineType string) string {
	switch lineType {
	case "success":
		return IconSuccess
	case "error":
		return IconError
	case "warning":
		return IconWarning
	default:
		return IconInfo
	}
}

// SelectedSession returns the currently selected session, or nil if none
func (m *Model) SelectedSession() *Session {
	if len(m.sessions) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(m.sessions) {
		return nil
	}
	return &m.sessions[m.selectedIndex]
}

func (m *Model) selectSessionByAgentID(agentID string) bool {
	for i := range m.sessions {
		if m.sessions[i].AgentID == agentID {
			m.selectedIndex = i
			return true
		}
	}
	return false
}

func (m *Model) dismissDwellAgent(agentID string) {
	if agentID == "" {
		return
	}
	m.dismissedDwellAgents[agentID] = struct{}{}
}

func (m *Model) dismissKnownDwellAgents() {
	if m.activeAgent != nil {
		m.dismissDwellAgent(m.activeAgent.ID)
	}
	for _, session := range m.sessions {
		m.dismissDwellAgent(session.AgentID)
	}
}

func (m *Model) restoreDwellAgentAllowed(agentID string) bool {
	if agentID == "" {
		return false
	}
	_, dismissed := m.dismissedDwellAgents[agentID]
	return !dismissed
}

func (m *Model) clearDismissedDwellAgent(agentID string) {
	if agentID == "" {
		return
	}
	delete(m.dismissedDwellAgents, agentID)
}

// SetPantry sets the Pantry instance for attack graph data.
func (m *Model) SetPantry(p *pantry.Pantry) {
	m.pantry = p
	m.RebuildTree()
}

// importReconToPantry imports reconnaissance results into the Pantry attack graph.
// Returns the number of assets imported and any error.
func (m *Model) importReconToPantry(recon *models.ReconResult) (int, error) {
	if m.pantry == nil {
		// Create Pantry if it doesn't exist
		m.pantry = pantry.New()
	}

	imported := 0
	platform := string(recon.Platform)
	hostname := ""
	if recon.Runner != nil {
		hostname = recon.Runner.Hostname
	}

	// Import agent
	agentAsset := pantry.NewAgent(recon.AgentID, hostname, platform)
	agentAsset.State = pantry.StateValidated
	if err := m.pantry.AddAsset(agentAsset); err != nil {
		return imported, fmt.Errorf("failed to add agent: %w", err)
	}
	agentID := agentAsset.ID // Use the generated ID
	imported++

	// Import repository if present
	var repoID string
	if recon.Repository != nil && recon.Repository.FullName != "" {
		org := recon.Repository.Owner
		name := recon.Repository.Name
		if org == "" {
			org = "unknown"
		}
		if name == "" {
			name = recon.Repository.FullName
		}
		repoAsset := pantry.NewRepository(org, name, platform)
		repoAsset.State = pantry.StateValidated
		if err := m.pantry.AddAsset(repoAsset); err == nil {
			repoID = repoAsset.ID
			imported++
			// Link agent discovered repository
			_ = m.pantry.AddRelationship(agentID, repoID, pantry.DiscoveredBy(recon.AgentID))
		}
	}

	// Import workflow if present
	var workflowID string
	if recon.Workflow != nil && recon.Workflow.Name != "" {
		workflowPath := recon.Workflow.Name
		if recon.Workflow.Path != "" {
			workflowPath = recon.Workflow.Path
		}
		workflowRepoID := repoID
		if workflowRepoID == "" {
			workflowRepoID = "unknown"
		}
		workflowAsset := pantry.NewWorkflow(workflowRepoID, workflowPath)
		workflowAsset.State = pantry.StateValidated
		if err := m.pantry.AddAsset(workflowAsset); err == nil {
			workflowID = workflowAsset.ID
			imported++
			// Link workflow to repository
			if repoID != "" {
				_ = m.pantry.AddRelationship(repoID, workflowID, pantry.Contains())
			}
		}
	}

	// Import secrets
	for _, secret := range recon.Secrets {
		scope := "workflow"
		if workflowID != "" {
			scope = workflowID
		}
		secretAsset := pantry.NewSecret(secret.Name, scope, platform)
		if secret.HighValue {
			secretAsset.State = pantry.StateHighValue
		} else {
			secretAsset.State = pantry.StateNew
		}
		if err := m.pantry.AddAsset(secretAsset); err == nil {
			imported++
			// Link secret to workflow (workflow exposes secret)
			if workflowID != "" {
				job := ""
				if recon.Workflow != nil {
					job = recon.Workflow.Job
				}
				_ = m.pantry.AddRelationship(workflowID, secretAsset.ID, pantry.Exposes(job, ""))
			}
		}
	}

	// Import OIDC capability if available
	if recon.OIDC != nil && recon.OIDC.Available {
		tokenAsset := pantry.NewToken("oidc", recon.AgentID, []string{"id_token"})
		tokenAsset.State = pantry.StateHighValue
		if err := m.pantry.AddAsset(tokenAsset); err == nil {
			imported++
			// OIDC grants access to cloud resources
			if workflowID != "" {
				_ = m.pantry.AddRelationship(workflowID, tokenAsset.ID, pantry.Exposes("", ""))
			}
		}
	}

	return imported, nil
}

// importScanToPantry imports poutine scan results into the Pantry attack graph.
// Returns the number of assets imported and any error.
func (m *Model) importScanToPantry(scan *models.ScanResult) (int, error) {
	if m.pantry == nil {
		// Create Pantry if it doesn't exist
		m.pantry = pantry.New()
	}

	if scan.TotalFindings == 0 {
		return 0, nil
	}

	imported := 0

	// Determine repository info from scan metadata
	org := ""
	repoName := ""
	if scan.Repository != "" {
		parts := strings.Split(scan.Repository, "/")
		if len(parts) >= 2 {
			org = parts[0]
			repoName = parts[1]
		} else {
			repoName = scan.Repository
		}
	}

	// Create repository asset if we have info
	var repoID string
	if repoName != "" {
		if org == "" {
			org = "unknown"
		}
		repoAsset := pantry.NewRepository(org, repoName, "github")
		repoAsset.State = pantry.StateValidated
		if err := m.pantry.AddAsset(repoAsset); err == nil {
			repoID = repoAsset.ID
			imported++
		}
	}

	// Track workflows to avoid duplicates
	workflowAssets := make(map[string]pantry.Asset)

	// Import each finding as a vulnerability
	for _, finding := range scan.Findings {
		// Create workflow asset if we have path info and haven't seen it
		var workflowID string
		if finding.Path != "" {
			if _, exists := workflowAssets[finding.Path]; !exists {
				parentID := repoID
				if parentID == "" {
					parentID = "scan"
				}
				workflow := pantry.NewWorkflow(parentID, finding.Path)
				workflow.State = pantry.StateValidated
				if err := m.pantry.AddAsset(workflow); err == nil {
					workflowAssets[finding.Path] = workflow
					imported++
					// Connect repo -> workflow
					if repoID != "" {
						_ = m.pantry.AddRelationship(repoID, workflow.ID, pantry.Contains())
					}
				}
			}
			if wf, exists := workflowAssets[finding.Path]; exists {
				workflowID = wf.ID
			}
		}

		// Create vulnerability asset
		purl := ""
		if repoID != "" {
			purl = fmt.Sprintf("pkg:github/%s/%s", org, repoName)
		}
		vuln := pantry.NewVulnerability(
			finding.RuleID,
			purl,
			finding.Path,
			finding.Line,
		)
		vuln.Provider = "github"

		// Map poutine severity levels
		var severity string
		switch finding.Severity {
		case "error":
			severity = "critical"
			vuln.State = pantry.StateHighValue
		case "warning":
			severity = "high"
			vuln.State = pantry.StateHighValue
		case "note":
			severity = "medium"
			vuln.State = pantry.StateNew
		default:
			severity = "low"
			vuln.State = pantry.StateNew
		}
		vuln.Severity = severity

		// Store additional context
		if finding.Job != "" {
			vuln.SetProperty("job", finding.Job)
		}
		if finding.Step != "" {
			vuln.SetProperty("step", finding.Step)
		}
		if finding.Details != "" {
			vuln.SetProperty("details", finding.Details)
		}
		if finding.Title != "" {
			vuln.SetProperty("title", finding.Title)
		}
		pantry.SetVulnerabilityExploitSupport(&vuln)

		if err := m.pantry.AddAsset(vuln); err != nil {
			continue
		}
		imported++

		// Create relationship: workflow -vulnerable_to-> vulnerability
		if workflowID != "" {
			rel := pantry.VulnerableTo(finding.RuleID, severity)
			_ = m.pantry.AddRelationship(workflowID, vuln.ID, rel)
		} else if repoID != "" {
			// Connect directly to repo if no workflow path
			rel := pantry.VulnerableTo(finding.RuleID, severity)
			_ = m.pantry.AddRelationship(repoID, vuln.ID, rel)
		}
	}

	return imported, nil
}

// importAnalysisToPantry imports poutine analysis results into the Pantry attack graph.
type importSummary struct {
	Orgs      int
	Repos     int
	Workflows int
	Jobs      int
	Vulns     int
	Secrets   int
	Tokens    int
	Cloud     int
	Total     int
}

func (s importSummary) String() string {
	parts := []string{}
	if s.Repos > 0 {
		parts = append(parts, fmt.Sprintf("%d repos", s.Repos))
	}
	if s.Workflows > 0 {
		parts = append(parts, fmt.Sprintf("%d workflows", s.Workflows))
	}
	if s.Vulns > 0 {
		parts = append(parts, fmt.Sprintf("%d vulns", s.Vulns))
	}
	if s.Secrets > 0 {
		parts = append(parts, fmt.Sprintf("%d secrets", s.Secrets))
	}
	if s.Tokens > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens", s.Tokens))
	}
	if s.Cloud > 0 {
		parts = append(parts, fmt.Sprintf("%d cloud targets", s.Cloud))
	}
	if len(parts) == 0 {
		return "0 assets"
	}
	return strings.Join(parts, ", ")
}

func (m *Model) importAnalysisToPantry(result *poutine.AnalysisResult) importSummary {
	summary := importSummary{}
	if m.pantry == nil {
		m.pantry = pantry.New()
	}

	orgAssets := make(map[string]string)
	repoAssets := make(map[string]string)
	workflowAssets := make(map[string]string)

	jobAssets := make(map[string]string)

	for _, wfMeta := range result.Workflows {
		org, repoName := "", ""
		if wfMeta.Repository != "" {
			parts := strings.Split(wfMeta.Repository, "/")
			if len(parts) >= 2 {
				org, repoName = parts[0], parts[1]
			} else {
				repoName = wfMeta.Repository
			}
		}

		var orgID string
		var repoID string
		if repoName != "" {
			key := wfMeta.Repository
			if existing, ok := repoAssets[key]; ok {
				repoID = existing
			} else {
				if org == "" {
					org = "unknown"
				}

				if existingOrg, ok := orgAssets[org]; ok {
					orgID = existingOrg
				} else {
					orgAsset := pantry.NewOrganization(org, "github")
					if err := m.pantry.AddAsset(orgAsset); err == nil {
						orgID = orgAsset.ID
						orgAssets[org] = orgID
						summary.Orgs++
					}
				}

				repo := pantry.NewRepository(org, repoName, "github")
				repo.State = pantry.StateValidated
				if err := m.pantry.AddAsset(repo); err == nil {
					repoID = repo.ID
					repoAssets[key] = repoID
					summary.Repos++
					if orgID != "" {
						_ = m.pantry.AddRelationship(orgID, repoID, pantry.Contains())
					}
				}
			}
		}

		var workflowID string
		if wfMeta.Path != "" {
			key := wfMeta.Repository + ":" + wfMeta.Path
			if existing, ok := workflowAssets[key]; ok {
				workflowID = existing
			} else {
				parentID := repoID
				if parentID == "" {
					parentID = "analysis"
				}
				wf := pantry.NewWorkflow(parentID, wfMeta.Path)
				wf.State = pantry.StateValidated
				if wfMeta.HasOIDC {
					wf.SetProperty("has_oidc", true)
				}
				if wfMeta.HasWrite {
					wf.SetProperty("has_write", true)
				}
				if wfMeta.SelfHosted {
					wf.SetProperty("self_hosted", true)
				}
				if len(wfMeta.CachePoisonVictims) > 0 {
					wf.SetProperty("cache_poison_victims", wfMeta.CachePoisonVictims)
				}
				if err := m.pantry.AddAsset(wf); err == nil {
					workflowID = wf.ID
					workflowAssets[key] = workflowID
					summary.Workflows++
					if repoID != "" {
						_ = m.pantry.AddRelationship(repoID, workflowID, pantry.Contains())
					}
				}
			}
		}

		for _, jobMeta := range wfMeta.Jobs {
			jobKey := wfMeta.Repository + ":" + wfMeta.Path + ":" + jobMeta.ID
			job := pantry.NewJob(workflowID, jobMeta.ID)
			job.State = pantry.StateValidated
			if jobMeta.DisplayName != "" {
				job.SetProperty("display_name", jobMeta.DisplayName)
			}
			if jobMeta.HasOIDC {
				job.SetProperty("has_oidc", true)
			}
			if jobMeta.HasWrite {
				job.SetProperty("has_write", true)
			}
			if jobMeta.SelfHosted {
				job.SetProperty("self_hosted", true)
			}
			if jobMeta.GitHubTokenRW {
				job.SetProperty("github_token_rw", true)
			}
			if err := m.pantry.AddAsset(job); err == nil {
				summary.Jobs++
				jobAssets[jobKey] = job.ID
				if workflowID != "" {
					_ = m.pantry.AddRelationship(workflowID, job.ID, pantry.Contains())
				}

				for _, secretName := range jobMeta.Secrets {
					secret := pantry.NewSecret(secretName, job.ID, "github")
					secret.SetProperty("job", jobMeta.ID)
					if err := m.pantry.AddAsset(secret); err == nil {
						summary.Secrets++
						_ = m.pantry.AddRelationship(job.ID, secret.ID, pantry.Exposes(jobMeta.ID, ""))
					}
				}

				if jobMeta.HasOIDC {
					token := pantry.NewToken("oidc", job.ID, []string{"id_token"})
					token.State = pantry.StateHighValue
					token.SetProperty("job", jobMeta.ID)
					if err := m.pantry.AddAsset(token); err == nil {
						summary.Tokens++
						_ = m.pantry.AddRelationship(job.ID, token.ID, pantry.Exposes(jobMeta.ID, ""))
					}
				}

				if jobMeta.GitHubTokenRW {
					token := pantry.NewToken("github_token", job.ID, []string{"contents:write"})
					token.SetProperty("job", jobMeta.ID)
					if err := m.pantry.AddAsset(token); err == nil {
						summary.Tokens++
						_ = m.pantry.AddRelationship(job.ID, token.ID, pantry.Exposes(jobMeta.ID, ""))
					}
				}
			}
		}
	}

	if len(result.Findings) == 0 {
		summary.Total = summary.Orgs + summary.Repos + summary.Workflows + summary.Jobs + summary.Secrets + summary.Tokens
		return summary
	}

	findings := poutine.ExpandFindings(result.Findings)
	for _, f := range findings {
		org, repoName := "", ""
		if f.Repository != "" {
			parts := strings.Split(f.Repository, "/")
			if len(parts) >= 2 {
				org, repoName = parts[0], parts[1]
			} else {
				repoName = f.Repository
			}
		}

		var orgID string
		var repoID string
		if repoName != "" {
			key := f.Repository
			if existing, ok := repoAssets[key]; ok {
				repoID = existing
			} else {
				if org == "" {
					org = "unknown"
				}

				if existingOrg, ok := orgAssets[org]; ok {
					orgID = existingOrg
				} else {
					orgAsset := pantry.NewOrganization(org, "github")
					if err := m.pantry.AddAsset(orgAsset); err == nil {
						orgID = orgAsset.ID
						orgAssets[org] = orgID
						summary.Orgs++
					}
				}

				repo := pantry.NewRepository(org, repoName, "github")
				repo.State = pantry.StateValidated
				if err := m.pantry.AddAsset(repo); err == nil {
					repoID = repo.ID
					repoAssets[key] = repoID
					summary.Repos++
					if orgID != "" {
						_ = m.pantry.AddRelationship(orgID, repoID, pantry.Contains())
					}
				}
			}
		}

		var workflowID string
		if f.Workflow != "" {
			key := f.Repository + ":" + f.Workflow
			if existing, ok := workflowAssets[key]; ok {
				workflowID = existing
			} else {
				parentID := repoID
				if parentID == "" {
					parentID = "analysis"
				}
				wf := pantry.NewWorkflow(parentID, f.Workflow)
				wf.State = pantry.StateValidated
				if err := m.pantry.AddAsset(wf); err == nil {
					workflowID = wf.ID
					workflowAssets[key] = workflowID
					summary.Workflows++
					if repoID != "" {
						_ = m.pantry.AddRelationship(repoID, workflowID, pantry.Contains())
					}
				}
			}
		}

		var jobID string
		if f.Job != "" {
			jobKey := f.Repository + ":" + f.Workflow + ":" + f.Job
			if existing, ok := jobAssets[jobKey]; ok {
				jobID = existing
			} else if workflowID != "" {
				job := pantry.NewJob(workflowID, f.Job)
				job.State = pantry.StateValidated
				if err := m.pantry.AddAsset(job); err == nil {
					jobID = job.ID
					jobAssets[jobKey] = jobID
					summary.Jobs++
					_ = m.pantry.AddRelationship(workflowID, jobID, pantry.Contains())
				}
			}
		}

		purl := ""
		if repoID != "" {
			purl = fmt.Sprintf("pkg:github/%s/%s", org, repoName)
		}
		vuln := pantry.NewVulnerability(f.RuleID, purl, f.Workflow, f.Line, poutine.FindingVariantDiscriminator(f))
		vuln.Provider = "github"
		vuln.State = pantry.StateHighValue
		vuln.Severity = f.Severity
		if f.Title != "" {
			vuln.SetProperty("title", f.Title)
		}
		if f.Job != "" {
			vuln.SetProperty("job", f.Job)
		}
		if f.Step != "" {
			vuln.SetProperty("step", f.Step)
		}
		if f.Context != "" {
			vuln.SetProperty("context", f.Context)
		}
		if f.BashContext != "" {
			vuln.SetProperty("bash_context", f.BashContext)
		}
		if f.Trigger != "" {
			vuln.SetProperty("trigger", f.Trigger)
		}
		if f.Expression != "" {
			vuln.SetProperty("expression", f.Expression)
		}
		if f.Fingerprint != "" {
			vuln.SetProperty("fingerprint", f.Fingerprint)
		}
		if f.LOTPTool != "" {
			vuln.SetProperty("lotp_tool", f.LOTPTool)
		}
		if f.LOTPAction != "" {
			vuln.SetProperty("lotp_action", f.LOTPAction)
		}
		if len(f.LOTPTargets) > 0 {
			vuln.SetProperty("lotp_targets", f.LOTPTargets)
		}
		if len(f.InjectionSources) > 0 {
			vuln.SetProperty("injection_sources", f.InjectionSources)
		}
		if len(f.ReferencedSecrets) > 0 {
			vuln.SetProperty("referenced_secrets", f.ReferencedSecrets)
		}
		if len(f.GateTriggers) > 0 {
			vuln.SetProperty("gate_triggers", f.GateTriggers)
		}
		if f.GateRaw != "" {
			vuln.SetProperty("gate_raw", f.GateRaw)
		}
		if f.GateUnsolvable != "" {
			vuln.SetProperty("gate_unsolvable", f.GateUnsolvable)
		}
		pantry.SetVulnerabilityExploitSupport(&vuln)
		if f.CachePoisonWriter {
			vuln.SetProperty("cache_poison_writer", true)
		}
		if f.CachePoisonReason != "" {
			vuln.SetProperty("cache_poison_reason", f.CachePoisonReason)
		}
		if len(f.CachePoisonVictims) > 0 {
			vuln.SetProperty("cache_poison_victims", f.CachePoisonVictims)
		}

		if err := m.pantry.AddAsset(vuln); err == nil {
			summary.Vulns++
			rel := pantry.VulnerableTo(f.RuleID, f.Severity)
			switch {
			case jobID != "":
				_ = m.pantry.AddRelationship(jobID, vuln.ID, rel)
			case workflowID != "":
				_ = m.pantry.AddRelationship(workflowID, vuln.ID, rel)
			case repoID != "":
				_ = m.pantry.AddRelationship(repoID, vuln.ID, rel)
			}
		}
	}

	summary.Total = summary.Orgs + summary.Repos + summary.Workflows + summary.Jobs + summary.Vulns + summary.Secrets + summary.Tokens
	return summary
}

func (m *Model) importVulnerabilitiesToPantry(vulns []Vulnerability) importSummary {
	if len(vulns) == 0 {
		return importSummary{}
	}

	findings := make([]poutine.Finding, 0, len(vulns))
	for _, vuln := range vulns {
		findings = append(findings, poutine.Finding{
			ID:                 vuln.ID,
			Repository:         vuln.Repository,
			Workflow:           vuln.Workflow,
			Line:               vuln.Line,
			Job:                vuln.Job,
			RuleID:             vuln.RuleID,
			Title:              vuln.Title,
			Severity:           vuln.Severity,
			Context:            vuln.Context,
			BashContext:        vuln.BashContext,
			Trigger:            vuln.Trigger,
			Expression:         vuln.Expression,
			InjectionSources:   vuln.InjectionSources,
			ReferencedSecrets:  vuln.ReferencedSecrets,
			LOTPTool:           vuln.LOTPTool,
			LOTPAction:         vuln.LOTPAction,
			LOTPTargets:        vuln.LOTPTargets,
			CachePoisonWriter:  vuln.CachePoisonWriter,
			CachePoisonReason:  vuln.CachePoisonReason,
			CachePoisonVictims: vuln.CachePoisonVictims,
			GateTriggers:       vuln.GateTriggers,
			GateRaw:            vuln.GateRaw,
			GateUnsolvable:     vuln.GateUnsolvable,
			Fingerprint:        vuln.Fingerprint,
		})
	}

	return m.importAnalysisToPantry(&poutine.AnalysisResult{Findings: findings})
}

// TransitionToPhase changes the current phase and updates the view accordingly.
func (m *Model) TransitionToPhase(newPhase Phase) {
	m.phase = newPhase
	m.phaseStart = time.Now()

	// Auto-select appropriate view for new phase
	switch newPhase {
	case PhaseSetup:
		m.view = ViewSetupWizard
		m.focus = FocusInput
	case PhaseRecon:
		m.view = ViewFindings
		m.treeFiltered = false
		m.GenerateSuggestions()
		m.RebuildTree()
		m.focus = FocusSessions
		m.paneFocus = PaneFocusFindings
	case PhaseWizard:
		m.view = ViewWizard
		m.focus = FocusInput
	case PhaseWaiting:
		m.view = ViewWaiting
		m.focus = FocusInput
	case PhasePostExploit, PhasePivot:
		m.view = ViewAgent
		m.GenerateSuggestions()
		m.focus = FocusSessions
		m.paneFocus = PaneFocusLoot
	}

	m.updateFocus()
	m.updatePlaceholder()
}

// SetView changes the current view without changing the phase.
func (m *Model) SetView(newView View) {
	m.view = newView
	m.updatePlaceholder()
}

// CanTransitionTo checks if a phase transition is valid.
func (m *Model) CanTransitionTo(newPhase Phase) bool {
	switch newPhase {
	case PhaseSetup:
		return true // Can always go back to setup
	case PhaseRecon:
		return m.analysisComplete
	case PhaseWizard:
		return m.phase.CanSelectVuln() && m.wizard != nil && m.wizard.SelectedVuln != nil
	case PhaseWaiting:
		return m.phase == PhaseWizard && m.waiting != nil
	case PhasePostExploit:
		return m.activeAgent != nil
	case PhasePivot:
		return m.phase == PhasePostExploit && len(m.lootStash) > 0
	}
	return false
}

// OpenWizard starts the payload wizard for a selected vulnerability.
func (m *Model) OpenWizard(vuln *Vulnerability) error {
	if err := vulnerabilityExploitError(vuln); err != nil {
		return err
	}
	if m.wizard == nil {
		m.wizard = &WizardState{}
	}
	m.wizard.Reset()
	m.wizard.SelectedVuln = vuln
	m.wizard.Step = 1

	methods := ApplicableDeliveryMethods(vuln)
	if len(methods) > 0 {
		m.wizard.DeliveryMethod = methods[0]
	}

	m.prevView = m.view
	m.prevFocus = m.focus
	m.TransitionToPhase(PhaseWizard)
	return nil
}

// CloseWizard exits the wizard and returns to the appropriate phase.
func (m *Model) CloseWizard() {
	if m.wizard != nil {
		m.wizard.Reset()
	}
	savedFocus := m.prevFocus
	if m.dwellMode && m.activeAgent != nil {
		m.TransitionToPhase(PhasePostExploit)
		m.view = ViewAgent
		m.focus = savedFocus
		return
	}
	m.TransitionToPhase(PhaseRecon)
	m.focus = savedFocus
}

// StartWaiting begins the beacon wait state after payload deployment.
func (m *Model) StartWaiting(stagerID, prURL string, vuln *Vulnerability, method string, dwellTime time.Duration) {
	repo := ""
	vulnID := ""
	workflow := ""
	job := ""
	if vuln != nil {
		repo = vuln.Repository
		vulnID = vuln.ID
		workflow = vuln.Workflow
		job = vuln.Job
	}
	m.waiting = NewWaitingState(stagerID, repo, vulnID, workflow, job, method, dwellTime)
	if m.pendingCachePoison != nil {
		cachePoison := *m.pendingCachePoison
		m.waiting.CachePoison = &cachePoison
		if m.waiting.CachePoison.Victim.TriggerMode == "scheduled" {
			m.waiting.SoftWarning = 15 * time.Minute
			m.waiting.Timeout = 45 * time.Minute
		}
	}
	m.pendingCachePoison = nil
	m.waiting.PRURL = prURL
	m.TransitionToPhase(PhaseWaiting)
}

// CancelWaiting exits the waiting state and returns to findings.
func (m *Model) CancelWaiting() {
	m.waiting = nil
	m.pendingCachePoison = nil
	if m.activeAgent != nil {
		m.TransitionToPhase(PhasePostExploit)
		return
	}
	m.TransitionToPhase(PhaseRecon)
}

// AgentConnected handles a new agent beacon and transitions to exploit phase.
func (m *Model) AgentConnected(agent *AgentState) {
	m.activeAgent = agent
	m.waiting = nil
	m.TransitionToPhase(PhasePostExploit)
}

// IsInSetup returns true if we're in setup phase with checklist visible.
func (m *Model) IsInSetup() bool {
	return m.phase == PhaseSetup
}

// IsWizardActive returns true if the wizard modal is active.
func (m *Model) IsWizardActive() bool {
	return m.view == ViewWizard
}

// IsWaiting returns true if we're waiting for an agent beacon.
func (m *Model) IsWaiting() bool {
	return m.phase == PhaseWaiting
}

type setupAuthRetryMsg struct{}

type setupAnalysisRetryMsg struct{}

type SetupSSHKeysLoadedMsg struct {
	Keys []SetupKeyInfo
	Err  error
}

type SetupKeyDeployedMsg struct {
	Err error
}

type SetupClipboardCopiedMsg struct {
	Err error
}

type SetupAuthResultMsg struct {
	Token string
	Err   error
}

func loadSSHKeysCmd() tea.Cmd {
	return func() tea.Msg {
		keys, err := counter.GetKeyInfo()
		if err != nil {
			return SetupSSHKeysLoadedMsg{Err: err}
		}
		infos := make([]SetupKeyInfo, len(keys))
		for i, k := range keys {
			infos[i] = SetupKeyInfo{
				Comment:       k.Comment,
				Fingerprint:   k.Fingerprint,
				Type:          k.Type,
				AuthorizedKey: k.AuthorizedKey,
			}
		}
		return SetupSSHKeysLoadedMsg{Keys: infos}
	}
}

func deployKeyViaSSHCmd(host, authKeysLine string) tea.Cmd {
	return func() tea.Msg {
		encoded := base64.StdEncoding.EncodeToString([]byte(authKeysLine))
		script := fmt.Sprintf(`
f="$HOME/.smokedmeat/authorized_keys"
mkdir -p "$HOME/.smokedmeat"
line="$(printf '%%s' '%s' | base64 -d)"
grep -qxF "$line" "$f" 2>/dev/null || printf '%%s\n' "$line" >> "$f"
`, encoded)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "ssh", "-o", "ConnectTimeout=10", host, script)
		if err := c.Run(); err != nil {
			return SetupKeyDeployedMsg{Err: fmt.Errorf("SSH to %s failed: %w (is SSH access available on this host?)", host, err)}
		}
		return SetupKeyDeployedMsg{}
	}
}

func copyToClipboardCmd(text string) tea.Cmd {
	return func() tea.Msg {
		if err := clipboardWriteAll(text); err != nil {
			return SetupClipboardCopiedMsg{Err: err}
		}
		return SetupClipboardCopiedMsg{}
	}
}

func (m Model) authenticateSSHCmd() tea.Cmd {
	return func() tea.Msg {
		sw := m.setupWizard
		keyComment := ""
		if sw.SelectedKey >= 0 && sw.SelectedKey < len(sw.Keys) {
			keyComment = sw.Keys[sw.SelectedKey].Comment
		}
		client := counter.NewSSHAuthClient(counter.SSHAuthConfig{
			KitchenURL: sw.KitchenURL,
			Operator:   sw.OperatorName,
			KeyComment: keyComment,
		})
		token, err := client.Authenticate()
		if err != nil {
			return SetupAuthResultMsg{Err: err}
		}
		return SetupAuthResultMsg{Token: token}
	}
}

func extractHost(kitchenURL string) string {
	u := kitchenURL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	if idx := strings.Index(u, ":"); idx != -1 {
		u = u[:idx]
	}
	return u
}
