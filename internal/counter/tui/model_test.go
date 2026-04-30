// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

// =============================================================================
// Model Creation Tests
// =============================================================================

func TestNewModel(t *testing.T) {
	config := Config{
		SessionID:  "test-session",
		KitchenURL: "http://localhost:8080",
	}

	m := NewModel(config)

	assert.Equal(t, config.SessionID, m.config.SessionID)
	assert.Equal(t, FocusInput, m.focus)
	assert.Empty(t, m.sessions)
	assert.Empty(t, m.output)
	assert.Empty(t, m.history)
	assert.Equal(t, -1, m.historyIndex)
	assert.Equal(t, "disconnected", m.connectionState)
	assert.False(t, m.quitting)
	assert.NotNil(t, m.lightRye) // Should be initialized with KitchenURL
}

func TestNewModel_NoKitchenURL(t *testing.T) {
	config := Config{
		SessionID: "test-session",
		// KitchenURL not set
	}

	m := NewModel(config)

	assert.Nil(t, m.lightRye) // Should be nil without KitchenURL
}

func TestNewModel_ActivityLogAutoExpandEnabled(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})

	assert.True(t, m.activityLogAutoExpand)
	assert.Equal(t, defaultActivityHeight, m.activityRegionHeight())
}

func TestExecuteCommand_ExpandsActivityLogWhenCommandAddsEntries(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.input.SetValue("status")

	result, _ := m.executeCommand()
	model := result.(Model)

	require.False(t, model.activityLogExpandedUntil.IsZero())
	assert.WithinDuration(t, time.Now().Add(2*time.Second), model.activityLogExpandedUntil, time.Second)
	assert.Greater(t, model.activityLog.Len(), 0)
	assert.Equal(t, expandedActivityHeight, model.activityRegionHeight())
}

func TestExecuteCommand_DoesNotExpandActivityLogWithoutNewEntries(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.input.SetValue("help")

	result, _ := m.executeCommand()
	model := result.(Model)

	assert.True(t, model.activityLogExpandedUntil.IsZero())
	assert.Equal(t, 0, model.activityLog.Len())
}

func TestExecuteCommand_DoesNotExpandActivityLogWhenDisabled(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.activityLogAutoExpand = false
	m.input.SetValue("status")

	result, _ := m.executeCommand()
	model := result.(Model)

	assert.True(t, model.activityLogExpandedUntil.IsZero())
	assert.Greater(t, model.activityLog.Len(), 0)
	assert.Equal(t, defaultActivityHeight, model.activityRegionHeight())
}

func TestExecuteCommand_UnknownCommandSuggestsLocalMatch(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.input.SetValue("grahp")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 3)
	assert.Equal(t, "error", model.output[1].Type)
	assert.Equal(t, "Unknown command: grahp", model.output[1].Content)
	assert.Equal(t, "info", model.output[2].Type)
	assert.Equal(t, "Did you mean: graph", model.output[2].Content)
	require.NotEmpty(t, model.activityLog.Entries())
	assert.Equal(t, "Unknown command: grahp", model.activityLog.Entries()[len(model.activityLog.Entries())-2].Message)
	assert.Equal(t, "Did you mean: graph", model.activityLog.Entries()[len(model.activityLog.Entries())-1].Message)
}

func TestExecuteCommand_UnknownCommandWithSelectedSessionBlocksLikelyLocalTypo(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.connected = true
	m.sessions = []Session{{AgentID: "agt_12345678", IsOnline: true}}
	m.selectedIndex = 0
	m.input.SetValue("anlyze")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 3)
	assert.Equal(t, "Unknown command: anlyze", model.output[1].Content)
	assert.Equal(t, "Did you mean: analyze", model.output[2].Content)
}

func TestExecuteCommand_UnknownCommandWithSelectedSessionShowsOrderHint(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.connected = true
	m.sessions = []Session{{AgentID: "agt_12345678", IsOnline: true}}
	m.selectedIndex = 0
	m.input.SetValue("whoami")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 3)
	assert.Equal(t, "Unknown command: whoami", model.output[1].Content)
	assert.Equal(t, "Use 'order exec <cmd>' for agent shell commands, or 'help' for local commands", model.output[2].Content)
}

func TestExecuteCommand_OrderExecPassesThroughToAgent(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.connected = true
	m.sessions = []Session{{AgentID: "agt_12345678", IsOnline: true}}
	m.selectedIndex = 0
	m.input.SetValue("order exec whoami")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.NotNil(t, cmd)
	require.Len(t, model.output, 2)
	assert.Equal(t, "Sending order to agt_12345678...", model.output[1].Content)
}

func TestExecuteCommand_SetTargetWithoutValueShowsTargetedUsage(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.input.SetValue("set target")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 3)
	assert.Equal(t, "Usage: set target <org:owner|repo:owner/repo>", model.output[1].Content)
	assert.Equal(t, "Examples: set target org:acme | set target repo:acme/api", model.output[2].Content)
}

func TestExecuteCommand_OrderWithoutSelectedSessionShowsGuidance(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.input.SetValue("order exec whoami")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 3)
	assert.Equal(t, "No session selected", model.output[1].Content)
	assert.Equal(t, "Use 'sessions' then 'select <agent_id>' before sending agent orders", model.output[2].Content)
}

func TestExecuteCommand_OrderWithoutSubcommandStillShowsSessionGuidance(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.input.SetValue("order")

	result, cmd := m.executeCommand()
	model := result.(Model)

	assert.Nil(t, cmd)
	require.Len(t, model.output, 5)
	assert.Equal(t, "Usage: order <exec|env|recon|cloud-query|oidc|transfer|upload|download> [args...]", model.output[1].Content)
	assert.Equal(t, "Examples: order exec whoami | order env | order recon", model.output[2].Content)
	assert.Equal(t, "No session selected", model.output[3].Content)
	assert.Equal(t, "Use 'sessions' then 'select <agent_id>' before sending agent orders", model.output[4].Content)
}

func TestHandleSetCommand_ActivityLogAutoExpandToggle(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.activityLogExpandedUntil = time.Now().Add(2 * time.Second)

	result, _ := m.handleSetCommand("activity-log", "autoexpand off")
	model := result.(Model)
	assert.False(t, model.activityLogAutoExpand)
	assert.True(t, model.activityLogExpandedUntil.IsZero())

	result, _ = model.handleSetCommand("activity-log", "on")
	model = result.(Model)
	assert.True(t, model.activityLogAutoExpand)
}

func TestHandleSetCommand_TargetAddsActivityLogEntry(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})

	result, _ := m.handleSetCommand("target", "repo:acme/private-infra")
	model := result.(Model)

	require.NotNil(t, model.activityLog)
	require.NotEmpty(t, model.activityLog.Entries())
	found := false
	for _, entry := range model.activityLog.Entries() {
		if strings.Contains(entry.Message, "repo:acme/private-infra") {
			found = true
			break
		}
	}
	assert.True(t, found)
	assert.Equal(t, "acme/private-infra", model.target)
	assert.Equal(t, "repo", model.targetType)
}

func TestUpdate_ShiftPressTemporarilyExpandsActivityLog(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.focus = FocusInput

	result, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyLeftShift})
	model := result.(Model)
	assert.True(t, model.activityLogShiftHeld)
	assert.Equal(t, expandedActivityHeight, model.activityRegionHeight())

	result, _ = model.Update(tea.KeyReleaseMsg{Code: tea.KeyLeftShift})
	model = result.(Model)
	assert.False(t, model.activityLogShiftHeld)
	assert.Equal(t, defaultActivityHeight, model.activityRegionHeight())
}

func TestUpdate_ActivityLogToggleShortcut(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.focus = FocusSessions

	result, _ := m.Update(tea.KeyPressMsg{Text: "L", Code: 'L'})
	model := result.(Model)
	assert.True(t, model.activityLogManualExpanded)
	assert.Equal(t, expandedActivityHeight, model.activityRegionHeight())

	result, _ = model.Update(tea.KeyPressMsg{Text: "L", Code: 'L'})
	model = result.(Model)
	assert.False(t, model.activityLogManualExpanded)
	assert.Equal(t, defaultActivityHeight, model.activityRegionHeight())
}

func TestView_RequestsKeyReleaseEvents(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.ready = true
	m.width = 80
	m.height = 24

	view := m.View()

	assert.True(t, view.KeyboardEnhancements.ReportEventTypes)
}

func TestRenderAgentPanel_ShowsCompactProvenanceAndConnectedBack(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.activeAgent = &AgentState{
		ID:        "agt_1234567890",
		Repo:      "acme/private-infra",
		Workflow:  ".github/workflows/deploy.yml",
		Job:       "deploy",
		StartTime: time.Now().Add(-time.Minute),
	}

	out := stripANSI(m.RenderAgentPanel(120, 4))

	assert.Contains(t, out, "Connected back:")
	assert.Contains(t, out, "acme/private-infra")
	assert.Contains(t, out, ".github/workflows/deploy.yml")
	assert.Contains(t, out, "deploy")
}

func TestRenderAgentPanel_ResidentFootholdShowsResidentStatus(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.activeAgent = &AgentState{
		ID:        "agt_resident",
		Repo:      "whooli/infrastructure-definitions",
		Workflow:  runnerTargetWorkflowPath(),
		Job:       runnerTargetWorkflowJobName(),
		Mode:      agentModeResident,
		StartTime: time.Now().Add(-time.Minute),
	}
	m.dwellMode = true

	out := stripANSI(m.RenderAgentPanel(120, 4))

	assert.Contains(t, out, "Resident foothold online")
	assert.NotContains(t, out, "Express complete")
}

func TestRenderNewHeader_ResidentFootholdShowsResidentStatus(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhasePostExploit
	m.activeAgent = &AgentState{
		ID:   "agt_resident",
		Mode: agentModeResident,
	}
	m.dwellMode = true
	m.connected = true

	out := stripANSI(m.renderNewHeader())

	assert.Contains(t, out, "Resident foothold online")
	assert.NotContains(t, out, "Express complete")
}

func TestStartWaitingForRunnerTarget_AttachesExistingResidentFoothold(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.callbacks = []counter.CallbackPayload{
		{
			ID:          "stg-runner-1",
			Persistent:  true,
			LastAgentID: "agt-runner",
			Metadata: map[string]string{
				"callback_kind":    "self_hosted_runner",
				"persistence_mode": "resident",
				"repository":       "whooli/infrastructure-definitions",
				"workflow":         runnerTargetWorkflowPath(),
				"job":              runnerTargetWorkflowJobName(),
			},
		},
	}
	m.sessions = []Session{
		{
			AgentID:  "agt-runner",
			Hostname: "whooli-gh-runner",
			LastSeen: time.Now(),
			IsOnline: true,
		},
	}

	m.StartWaitingForRunnerTarget("stg-runner-1", &RunnerTargetSelection{Repository: "whooli/infrastructure-definitions"}, "Self-Hosted Workflow Push", 0)

	assert.Equal(t, PhasePostExploit, m.phase)
	require.NotNil(t, m.activeAgent)
	assert.Equal(t, "agt-runner", m.activeAgent.ID)
	assert.Equal(t, agentModeResident, m.activeAgent.Mode)
	assert.Equal(t, "whooli/infrastructure-definitions", m.activeAgent.Repo)
	assert.Nil(t, m.waiting)
}

// =============================================================================
// Focus Enum Tests
// =============================================================================

func TestFocus_Values(t *testing.T) {
	// Verify focus constants exist and are distinct
	focuses := []Focus{FocusSessions, FocusInput}
	seen := make(map[Focus]bool)

	for _, f := range focuses {
		assert.False(t, seen[f], "Focus value should be unique")
		seen[f] = true
	}
}

// =============================================================================
// Session Tests
// =============================================================================

func TestSession_Fields(t *testing.T) {
	now := time.Now()
	s := Session{
		AgentID:   "brisket-001",
		Hostname:  "runner-1",
		OS:        "linux",
		Arch:      "amd64",
		LastSeen:  now,
		IsOnline:  true,
		SessionID: "session-123",
	}

	assert.Equal(t, "brisket-001", s.AgentID)
	assert.Equal(t, "runner-1", s.Hostname)
	assert.Equal(t, "linux", s.OS)
	assert.Equal(t, "amd64", s.Arch)
	assert.Equal(t, now, s.LastSeen)
	assert.True(t, s.IsOnline)
	assert.Equal(t, "session-123", s.SessionID)
}

// =============================================================================
// OutputLine Tests
// =============================================================================

func TestOutputLine_Fields(t *testing.T) {
	now := time.Now()
	o := OutputLine{
		Time:    now,
		Type:    "success",
		Content: "Operation completed",
	}

	assert.Equal(t, now, o.Time)
	assert.Equal(t, "success", o.Type)
	assert.Equal(t, "Operation completed", o.Content)
}

// =============================================================================
// Vulnerability Tests
// =============================================================================

func TestVulnerability_Fields(t *testing.T) {
	v := Vulnerability{
		ID:         "V001",
		Repository: "org/repo",
		Workflow:   ".github/workflows/ci.yml",
		Line:       42,
		Context:    "bash",
		Trigger:    "pull_request",
		Expression: "${{ github.event.issue.title }}",
		Severity:   "critical",
	}

	assert.Equal(t, "V001", v.ID)
	assert.Equal(t, "org/repo", v.Repository)
	assert.Equal(t, ".github/workflows/ci.yml", v.Workflow)
	assert.Equal(t, 42, v.Line)
	assert.Equal(t, "bash", v.Context)
	assert.Equal(t, "pull_request", v.Trigger)
	assert.Equal(t, "${{ github.event.issue.title }}", v.Expression)
	assert.Equal(t, "critical", v.Severity)
}

// =============================================================================
// AddOutput Tests
// =============================================================================

func TestModel_AddOutput(t *testing.T) {
	m := NewModel(Config{})

	m.AddOutput("info", "Test message")

	require.Len(t, m.output, 1)
	assert.Equal(t, "info", m.output[0].Type)
	assert.Equal(t, "Test message", m.output[0].Content)
	assert.False(t, m.output[0].Time.IsZero())
	require.NotNil(t, m.activityLog)
	require.NotEmpty(t, m.activityLog.Entries())
	assert.Equal(t, "Test message", m.activityLog.Entries()[0].Message)
	assert.Equal(t, IconInfo, m.activityLog.Entries()[0].Icon)
}

func TestModel_AddOutput_MultipleTypes(t *testing.T) {
	m := NewModel(Config{})

	m.AddOutput("info", "Info message")
	m.AddOutput("success", "Success message")
	m.AddOutput("error", "Error message")
	m.AddOutput("warning", "Warning message")

	require.Len(t, m.output, 4)
	assert.Equal(t, "info", m.output[0].Type)
	assert.Equal(t, "success", m.output[1].Type)
	assert.Equal(t, "error", m.output[2].Type)
	assert.Equal(t, "warning", m.output[3].Type)
	require.Len(t, m.activityLog.Entries(), 4)
	assert.Equal(t, IconInfo, m.activityLog.Entries()[0].Icon)
	assert.Equal(t, IconSuccess, m.activityLog.Entries()[1].Icon)
	assert.Equal(t, IconError, m.activityLog.Entries()[2].Icon)
	assert.Equal(t, IconWarning, m.activityLog.Entries()[3].Icon)
}

func TestModel_AddOutput_TruncatesAtLimit(t *testing.T) {
	m := NewModel(Config{})

	// Add more than 1000 lines
	for i := 0; i < 1005; i++ {
		m.AddOutput("info", "Line")
	}

	// Should be truncated to 1000
	assert.Len(t, m.output, 1000)
}

func TestModel_AddOutput_SkipsBlankActivityEntries(t *testing.T) {
	m := NewModel(Config{})

	m.AddOutput("info", "")

	require.Empty(t, m.activityLog.Entries())
}

// =============================================================================
// SelectedSession Tests
// =============================================================================

func TestModel_SelectedSession_Empty(t *testing.T) {
	m := NewModel(Config{})

	session := m.SelectedSession()

	assert.Nil(t, session)
}

func TestModel_SelectedSession_WithSessions(t *testing.T) {
	m := NewModel(Config{})
	m.sessions = []Session{
		{AgentID: "agent-1"},
		{AgentID: "agent-2"},
		{AgentID: "agent-3"},
	}
	m.selectedIndex = 1

	session := m.SelectedSession()

	require.NotNil(t, session)
	assert.Equal(t, "agent-2", session.AgentID)
}

func TestModel_SelectedSession_InvalidIndex(t *testing.T) {
	m := NewModel(Config{})
	m.sessions = []Session{
		{AgentID: "agent-1"},
	}
	m.selectedIndex = 5 // Out of bounds

	session := m.SelectedSession()

	assert.Nil(t, session)
}

func TestModel_SelectedSession_NegativeIndex(t *testing.T) {
	m := NewModel(Config{})
	m.sessions = []Session{
		{AgentID: "agent-1"},
	}
	m.selectedIndex = -1

	session := m.SelectedSession()

	assert.Nil(t, session)
}

// =============================================================================
// Pantry Integration Tests
// =============================================================================

func TestModel_SetPantry(t *testing.T) {
	m := NewModel(Config{})
	p := pantry.New()

	m.SetPantry(p)

	assert.Equal(t, p, m.pantry)
}

func TestModel_SetPantry_Nil(t *testing.T) {
	m := NewModel(Config{})

	m.SetPantry(nil)

	assert.Nil(t, m.pantry)
}

// =============================================================================
// Import Recon To Pantry Tests
// =============================================================================

func TestModel_importReconToPantry(t *testing.T) {
	m := NewModel(Config{})

	recon := &models.ReconResult{
		AgentID:  "brisket-001",
		Platform: models.PlatformGitHubActions,
		Runner: &models.RunnerInfo{
			Hostname: "runner-1",
		},
		Repository: &models.RepoInfo{
			FullName: "acme/api",
			Owner:    "acme",
			Name:     "api",
		},
		Workflow: &models.WorkflowInfo{
			Name: "CI",
			Path: ".github/workflows/ci.yml",
			Job:  "build",
		},
		Secrets: []models.DetectedSecret{
			{Name: "AWS_KEY", HighValue: true},
			{Name: "NPM_TOKEN", HighValue: false},
		},
	}

	imported, err := m.importReconToPantry(recon)

	require.NoError(t, err)
	assert.Greater(t, imported, 0)
	assert.NotNil(t, m.pantry)
}

func TestModel_importReconToPantry_CreatesNewPantry(t *testing.T) {
	m := NewModel(Config{})
	assert.Nil(t, m.pantry)

	recon := &models.ReconResult{
		AgentID:  "brisket-001",
		Platform: models.PlatformGitHubActions,
	}

	_, err := m.importReconToPantry(recon)

	require.NoError(t, err)
	assert.NotNil(t, m.pantry) // Should have created pantry
}

func TestModel_importReconToPantry_WithOIDC(t *testing.T) {
	m := NewModel(Config{})

	recon := &models.ReconResult{
		AgentID:  "brisket-001",
		Platform: models.PlatformGitHubActions,
		OIDC: &models.OIDCInfo{
			Available: true,
		},
	}

	imported, err := m.importReconToPantry(recon)

	require.NoError(t, err)
	assert.Greater(t, imported, 1) // Agent + OIDC token
}

// =============================================================================
// Import Scan To Pantry Tests
// =============================================================================

func TestModel_importScanToPantry(t *testing.T) {
	m := NewModel(Config{})

	scan := &models.ScanResult{
		Repository:    "acme/api",
		TotalFindings: 2,
		Findings: []models.ScanFinding{
			{
				RuleID:   "unpinned-action",
				Path:     ".github/workflows/ci.yml",
				Line:     10,
				Severity: "warning",
				Title:    "Unpinned action",
			},
			{
				RuleID:   "dangerous-trigger",
				Path:     ".github/workflows/ci.yml",
				Line:     5,
				Severity: "error",
				Title:    "Dangerous trigger",
			},
		},
	}

	imported, err := m.importScanToPantry(scan)

	require.NoError(t, err)
	assert.Greater(t, imported, 0)
	assert.NotNil(t, m.pantry)
}

func TestModel_importScanToPantry_NoFindings(t *testing.T) {
	m := NewModel(Config{})

	scan := &models.ScanResult{
		Repository:    "acme/api",
		TotalFindings: 0,
		Findings:      []models.ScanFinding{},
	}

	imported, err := m.importScanToPantry(scan)

	require.NoError(t, err)
	assert.Equal(t, 0, imported)
}

func TestModel_importScanToPantry_SeverityMapping(t *testing.T) {
	m := NewModel(Config{})

	scan := &models.ScanResult{
		Repository:    "acme/api",
		TotalFindings: 3,
		Findings: []models.ScanFinding{
			{RuleID: "r1", Path: "a.yml", Severity: "error"},   // -> critical
			{RuleID: "r2", Path: "b.yml", Severity: "warning"}, // -> high
			{RuleID: "r3", Path: "c.yml", Severity: "note"},    // -> medium
		},
	}

	imported, err := m.importScanToPantry(scan)

	require.NoError(t, err)
	assert.Greater(t, imported, 0)
}

// =============================================================================
// Config Tests
// =============================================================================

func TestConfig_Fields(t *testing.T) {
	c := Config{
		SessionID:  "session-123",
		KitchenURL: "http://localhost:8080",
		Operator:   "test-operator",
	}

	assert.Equal(t, "session-123", c.SessionID)
	assert.Equal(t, "http://localhost:8080", c.KitchenURL)
	assert.Equal(t, "test-operator", c.Operator)
}

// =============================================================================
// Attack Tree Tests
// =============================================================================

func TestModel_RebuildTree_EmptyPantry(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	// Should not panic on empty pantry
	m.RebuildTree()

	// Empty pantry results in nil tree root
	assert.Nil(t, m.treeRoot)
	assert.Empty(t, m.treeNodes)
}

func TestModel_RebuildTree_WithData(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()

	// Add some test data
	m.pantry.AddAsset(pantry.Asset{
		ID:   "repo:test/repo",
		Name: "test/repo",
		Type: pantry.AssetRepository,
	})

	m.RebuildTree()

	assert.NotNil(t, m.treeRoot)
	assert.Greater(t, len(m.treeNodes), 0)
}

func TestModel_TreeNavigation(t *testing.T) {
	m := NewModel(Config{})
	m.pantry = pantry.New()
	m.RebuildTree()

	// Navigation on empty tree should not panic
	m.TreeCursorDown()
	m.TreeCursorUp()
	m.TreeToggleExpand()
}

// =============================================================================
// Bug 3: TransitionToPhase(PhaseRecon) resets tree filter
// =============================================================================

func TestTransitionToRecon_ResetsTreeFilter(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.treeFiltered = true

	m.TransitionToPhase(PhaseRecon)

	assert.False(t, m.treeFiltered, "TransitionToPhase(PhaseRecon) should reset treeFiltered to false")
}

func TestTransitionToRecon_FromPostExploit(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.treeFiltered = true

	m.TransitionToPhase(PhaseRecon)

	assert.Equal(t, PhaseRecon, m.phase, "Should transition to PhaseRecon")
	assert.False(t, m.treeFiltered, "treeFiltered should be reset when transitioning from PostExploit to Recon")
}

// =============================================================================
// Bug 4: Init restores initialTokenInfo from config
// =============================================================================

func TestInit_RestoresInitialAccessToken(t *testing.T) {
	m := NewModel(Config{
		SessionID:                "test",
		InitialAccessToken:       "ghp_saved123",
		InitialAccessTokenSource: "op",
	})

	m.Init()

	// NOTE: initialTokenInfo is hydrated in NewModel() based on Config.
	// Init() is a value receiver so it cannot mutate the caller's copy.
	require.NotNil(t, m.initialTokenInfo, "initialTokenInfo should be populated when Config.InitialAccessToken is set")
	assert.Equal(t, "ghp_saved123", m.initialTokenInfo.Value)
	assert.Equal(t, TokenTypeClassicPAT, m.initialTokenInfo.Type)
	assert.Equal(t, "op", m.initialTokenInfo.Source)
	assert.False(t, m.initialTokenInfo.FetchedAt.IsZero())
}

func TestInit_NoInitialAccessToken(t *testing.T) {
	m := NewModel(Config{
		SessionID: "test",
	})

	m.Init()

	assert.Nil(t, m.initialTokenInfo, "initialTokenInfo should stay nil when Config.InitialAccessToken is empty")
}

// =============================================================================
// importAnalysisToPantry → extractVulnerabilitiesFromPantry round-trip
// =============================================================================

func TestImportAnalysis_RoundTrip_PreservesAllFields(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success:    true,
		Target:     "acme/api",
		TargetType: "repo",
		Repository: "acme/api",
		Findings: []poutine.Finding{
			{
				ID:                "V001",
				Repository:        "acme/api",
				Workflow:          ".github/workflows/ci.yml",
				Line:              42,
				Job:               "build",
				RuleID:            "injection",
				Title:             "Code injection via comment body",
				Severity:          "critical",
				Context:           "comment_body",
				BashContext:       "bash_single_quoted",
				Trigger:           "issue_comment",
				Expression:        "${{ github.event.comment.body }}",
				InjectionSources:  []string{"github.event.comment.body"},
				ReferencedSecrets: []string{"AWS_SECRET_KEY"},
				LOTPTool:          "bash",
				LOTPAction:        "run",
				LOTPTargets:       []string{"build-step"},
				GateTriggers:      []string{"/deploy"},
				GateRaw:           "contains(github.event.comment.body, '/deploy')",
				GateUnsolvable:    "",
			},
		},
	}

	m.importAnalysisToPantry(result)

	vulns := m.extractVulnerabilitiesFromPantry()
	require.Len(t, vulns, 1)
	v := vulns[0]

	assert.Equal(t, "acme/api", v.Repository)
	assert.Equal(t, ".github/workflows/ci.yml", v.Workflow)
	assert.Equal(t, "build", v.Job)
	assert.Equal(t, "critical", v.Severity)
	assert.Equal(t, "comment_body", v.Context)
	assert.Equal(t, "bash_single_quoted", v.BashContext)
	assert.Equal(t, "issue_comment", v.Trigger)
	assert.Equal(t, "${{ github.event.comment.body }}", v.Expression)
	assert.Equal(t, []string{"github.event.comment.body"}, v.InjectionSources)
	assert.Equal(t, []string{"AWS_SECRET_KEY"}, v.ReferencedSecrets)
	assert.Equal(t, "bash", v.LOTPTool)
	assert.Equal(t, "run", v.LOTPAction)
	assert.Equal(t, []string{"build-step"}, v.LOTPTargets)
	assert.Equal(t, []string{"/deploy"}, v.GateTriggers)
	assert.Equal(t, "contains(github.event.comment.body, '/deploy')", v.GateRaw)
	assert.Empty(t, v.GateUnsolvable)
	assert.True(t, v.ExploitSupported)
	assert.Empty(t, v.ExploitSupportReason)
}

func TestImportAnalysis_RoundTrip_PreservesAnalyzeOnlySupportReason(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success:    true,
		Target:     "acme/api",
		TargetType: "repo",
		Repository: "acme/api",
		Findings: []poutine.Finding{
			{
				ID:         "V001",
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				RuleID:     "debug_enabled",
				Severity:   "high",
			},
		},
	}

	m.importAnalysisToPantry(result)
	vulns := m.extractVulnerabilitiesFromPantry()
	require.Len(t, vulns, 1)
	assert.False(t, vulns[0].ExploitSupported)
	assert.Equal(t, "This finding is analyze-only in v0.1.0. Exploit actions are only available for injection and pwn-request findings.", vulns[0].ExploitSupportReason)
}

func TestImportAnalysis_SkipsSelfHostedRunnerAnalyzeOnlyVuln(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success:    true,
		Target:     "acme/api",
		TargetType: "repo",
		Repository: "acme/api",
		Findings: []poutine.Finding{
			{
				ID:         "V001",
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				Job:        "build",
				RuleID:     "pr_runs_on_self_hosted",
				Severity:   "critical",
			},
		},
	}

	m.importAnalysisToPantry(result)
	assert.Empty(t, m.extractVulnerabilitiesFromPantry())
	assert.Empty(t, m.pantry.FindVulnerabilities())

	targets := m.pantry.GetAssetsByType(pantry.AssetSelfHostedRunner)
	require.Len(t, targets, 1)
	assert.Equal(t, []string{"build"}, targets[0].StringSliceProperty("observed_job_names"))
}

func TestImportAnalysisToPantry_CreatesSelfHostedRunnerTargets(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success: true,
		Workflows: []poutine.WorkflowMeta{
			{
				Repository: "acme/api",
				Path:       ".github/workflows/pr.yml",
				Jobs: []poutine.JobMeta{
					{
						ID:         "build",
						SelfHosted: true,
						RunsOn:     []string{"x64", "self-hosted", "linux"},
					},
				},
			},
		},
		Findings: []poutine.Finding{
			{
				Repository: "acme/api",
				Workflow:   ".github/workflows/pr.yml",
				Job:        "build",
				Line:       12,
				RuleID:     "injection",
				Severity:   "critical",
				Context:    "issue_body",
			},
		},
	}

	m.importAnalysisToPantry(result)

	targets := m.pantry.GetAssetsByType(pantry.AssetSelfHostedRunner)
	require.Len(t, targets, 1)
	assert.Equal(t, []string{"self-hosted", "linux", "x64"}, targets[0].StringSliceProperty("label_set"))
	assert.Equal(t, []string{"build"}, targets[0].StringSliceProperty("observed_job_names"))
	assert.Equal(t, []string{".github/workflows/pr.yml"}, targets[0].StringSliceProperty("observed_workflow_paths"))
}

func TestImportAnalysis_RoundTrip_QuotedHeredocIsAnalyzeOnly(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success: true,
		Findings: []poutine.Finding{
			{
				ID:          "V001",
				Repository:  "acme/api",
				Workflow:    ".github/workflows/ci.yml",
				Line:        42,
				Job:         "build",
				RuleID:      "injection",
				Title:       "Quoted heredoc injection",
				Severity:    "critical",
				Context:     "comment_body",
				BashContext: "bash_heredoc_quoted",
				Trigger:     "issue_comment",
				Expression:  "${{ github.event.comment.body }}",
			},
		},
	}

	m.importAnalysisToPantry(result)

	vulns := m.extractVulnerabilitiesFromPantry()
	require.Len(t, vulns, 1)
	assert.False(t, vulns[0].ExploitSupported)
	assert.Equal(t, "Quoted heredoc bodies do not evaluate shell substitutions.", vulns[0].ExploitSupportReason)
}

func TestImportAnalysis_RoundTrip_CommentInjectionDetected(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success:    true,
		Target:     "acme/api",
		TargetType: "repo",
		Repository: "acme/api",
		Findings: []poutine.Finding{
			{
				ID:               "V001",
				Repository:       "acme/api",
				Workflow:         ".github/workflows/ci.yml",
				RuleID:           "injection",
				Severity:         "critical",
				Trigger:          "issue_comment",
				InjectionSources: []string{"github.event.comment.body"},
			},
		},
	}

	m.importAnalysisToPantry(result)
	vulns := m.extractVulnerabilitiesFromPantry()
	require.Len(t, vulns, 1)

	assert.True(t, isCommentInjection(&vulns[0]),
		"isCommentInjection should return true after pantry round-trip")
}

func TestImportAnalysis_RoundTrip_ExpandsInjectionSourcesIntoTreeVulns(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success:    true,
		Target:     "whooli/xyz",
		TargetType: "repo",
		Repository: "whooli/xyz",
		Findings: []poutine.Finding{
			{
				ID:               "V001",
				Fingerprint:      "fp-auto-labeler-step-1",
				Repository:       "whooli/xyz",
				Workflow:         ".github/workflows/auto-labeler.yml",
				Line:             23,
				Job:              "whooli-triage",
				Step:             "1",
				RuleID:           "injection",
				Title:            "Auto labeler step 1",
				Severity:         "critical",
				Trigger:          "issues",
				InjectionSources: []string{"github.event.issue.title", "github.event.issue.body"},
			},
			{
				ID:               "V002",
				Fingerprint:      "fp-auto-labeler-step-2",
				Repository:       "whooli/xyz",
				Workflow:         ".github/workflows/auto-labeler.yml",
				Line:             41,
				Job:              "whooli-triage",
				Step:             "2",
				RuleID:           "injection",
				Title:            "Auto labeler step 2",
				Severity:         "critical",
				Trigger:          "issues",
				InjectionSources: []string{"github.event.issue.title", "github.event.issue.body"},
			},
		},
	}

	m.importAnalysisToPantry(result)

	vulns := m.extractVulnerabilitiesFromPantry()
	require.Len(t, vulns, 4)

	m.vulnerabilities = vulns
	m.GenerateSuggestions()
	m.RebuildTree()

	var treeVulnIDs []string
	for _, node := range m.treeNodes {
		if node.Type == TreeNodeVuln {
			treeVulnIDs = append(treeVulnIDs, node.ID)
		}
	}

	assert.Len(t, treeVulnIDs, 4)

	contexts := make([]string, 0, len(vulns))
	steps := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		contexts = append(contexts, vuln.Context)
		steps = append(steps, vuln.Step)
	}

	assert.ElementsMatch(t, []string{"issue_body", "issue_title", "issue_body", "issue_title"}, contexts)
	assert.ElementsMatch(t, []string{"1", "1", "2", "2"}, steps)
}

func TestImportAnalysis_RoundTrip_UnsolvableGate(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result := &poutine.AnalysisResult{
		Success:    true,
		Target:     "acme/api",
		TargetType: "repo",
		Repository: "acme/api",
		Findings: []poutine.Finding{
			{
				ID:             "V001",
				Repository:     "acme/api",
				Workflow:       ".github/workflows/ci.yml",
				RuleID:         "injection",
				Severity:       "high",
				GateRaw:        "github.actor == 'admin'",
				GateUnsolvable: "comparison with non-controllable field: github.actor",
			},
		},
	}

	m.importAnalysisToPantry(result)
	vulns := m.extractVulnerabilitiesFromPantry()
	require.Len(t, vulns, 1)

	assert.Equal(t, "github.actor == 'admin'", vulns[0].GateRaw)
	assert.Equal(t, "comparison with non-controllable field: github.actor", vulns[0].GateUnsolvable)
	assert.Empty(t, vulns[0].GateTriggers)
}
