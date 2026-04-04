// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

// =============================================================================
// Deployment Success Message Tests
// =============================================================================

func TestModel_Update_AutoPRDeploymentSuccess(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(AutoPRDeploymentSuccessMsg{
		StagerID: "stager-123",
		PRURL:    "https://github.com/org/repo/pull/1",
		Vuln: &Vulnerability{
			ID:         "V001",
			Repository: "org/repo",
		},
	})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Equal(t, "stager-123", model.waiting.StagerID)
	assert.Contains(t, model.waiting.PRURL, "github.com")
	require.NotEmpty(t, model.output)
	assert.Equal(t, "success", model.output[len(model.output)-1].Type)
	assert.NotNil(t, cmd, "Should return a history recording command")
}

func TestModel_Update_IssueDeploymentSuccess(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(IssueDeploymentSuccessMsg{
		StagerID: "stager-456",
		IssueURL: "https://github.com/org/repo/issues/1",
		Vuln: &Vulnerability{
			ID:         "V002",
			Repository: "org/repo",
		},
	})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Equal(t, "stager-456", model.waiting.StagerID)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "success", model.output[len(model.output)-1].Type)
	assert.NotNil(t, cmd)
}

func TestModel_Update_LOTPDeploymentSuccess(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(LOTPDeploymentSuccessMsg{
		StagerID: "stager-789",
		PRURL:    "https://github.com/org/repo/pull/2",
		Vuln: &Vulnerability{
			ID:         "V003",
			Repository: "org/repo",
		},
	})

	model := result.(Model)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "LOTP")
	assert.NotNil(t, cmd)
}

// =============================================================================
// Deployment Failure Message Tests
// =============================================================================

func TestModel_Update_AutoPRDeploymentFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWizard

	result, cmd := m.Update(AutoPRDeploymentFailedMsg{
		StagerID: "stager-fail",
		Err:      errors.New("fork failed: rate limited"),
	})

	model := result.(Model)
	require.Len(t, model.output, 2, "Should have error and hint lines")
	assert.Equal(t, "error", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "PR deployment failed")
	assert.Equal(t, "hint", model.output[1].Type)
	assert.Contains(t, model.output[1].Content, "Copy payload")
	assert.NotNil(t, cmd, "Should return a history recording command for failures too")
}

func TestModel_Update_IssueDeploymentFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})

	result, cmd := m.Update(IssueDeploymentFailedMsg{
		StagerID: "stager-fail",
		Err:      errors.New("insufficient permissions"),
	})

	model := result.(Model)
	require.Len(t, model.output, 2, "Should have error and hint lines")
	assert.Equal(t, "error", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "Issue deployment failed")
	assert.Equal(t, "hint", model.output[1].Type)
	assert.NotNil(t, cmd)
}

func TestModel_Update_IssueDeploymentFailed_ExitsWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-1", "org/repo", "V001", "ci.yml", "build", "Issue", 0)

	result, _ := m.Update(IssueDeploymentFailedMsg{
		StagerID: "stg-1",
		Err:      errors.New("insufficient permissions"),
	})

	model := result.(Model)
	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.waiting)
}

func TestModel_Update_CommentDeploymentFailed_ExitsWaitingToActiveAgent(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stg-2", "org/repo", "V002", "ci.yml", "build", "Comment", 0)
	m.activeAgent = &AgentState{ID: "agt-1"}

	result, _ := m.Update(CommentDeploymentFailedMsg{
		StagerID: "stg-2",
		Err:      errors.New("403 Resource not accessible"),
	})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	assert.Nil(t, model.waiting)
}

func TestModel_Update_LOTPDeploymentFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})

	result, cmd := m.Update(LOTPDeploymentFailedMsg{
		StagerID: "stager-fail",
		Err:      errors.New("branch creation failed"),
	})

	model := result.(Model)
	require.Len(t, model.output, 2, "Should have error and hint lines")
	assert.Equal(t, "error", model.output[0].Type)
	assert.Contains(t, model.output[0].Content, "LOTP deployment failed")
	assert.Equal(t, "hint", model.output[1].Type)
	assert.NotNil(t, cmd)
}

// =============================================================================
// Beacon/Coleslaw Message Tests
// =============================================================================

func TestModel_Update_BeaconCreatesSession(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stager-001", "org/repo", "V001", ".github/workflows/ci.yml", "build", "auto_pr", 0)

	result, _ := m.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:  "brisket-001",
			Hostname: "runner-1",
			OS:       "linux",
			Arch:     "amd64",
		},
	})

	model := result.(Model)
	require.Len(t, model.sessions, 1)
	assert.Equal(t, "brisket-001", model.sessions[0].AgentID)
	assert.Equal(t, "runner-1", model.sessions[0].Hostname)
}

func TestModel_Update_BeaconTransitionsFromWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stager-001", "org/repo", "V001", ".github/workflows/ci.yml", "build", "auto_pr", 0)

	result, _ := m.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:  "brisket-001",
			Hostname: "runner-1",
			OS:       "linux",
			Arch:     "amd64",
		},
	})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase, "Should transition to PhasePostExploit when beacon arrives during waiting")
	assert.Equal(t, ViewAgent, model.view, "Should transition to ViewAgent when beacon arrives during waiting")
	assert.Equal(t, PaneFocusLoot, model.paneFocus, "Post-exploit should default focus to loot")
	assert.Nil(t, model.waiting, "Waiting state should be cleared")
	require.NotNil(t, model.activeAgent, "Active agent should be set")
	assert.Equal(t, "brisket-001", model.activeAgent.ID)
	assert.Equal(t, "org/repo", model.activeAgent.Repo)
	assert.Equal(t, "V001", model.activeAgent.EntryVuln)
}

func TestModel_Update_BeaconTransitionsFromWaitingSelectsActiveAgentSession(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stager-001", "org/repo", "V001", ".github/workflows/ci.yml", "build", "auto_pr", 0)
	m.sessions = []Session{{AgentID: "brisket-old"}}
	m.selectedIndex = 0

	result, _ := m.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:  "brisket-001",
			Hostname: "runner-1",
			OS:       "linux",
			Arch:     "amd64",
		},
	})

	model := result.(Model)
	require.NotNil(t, model.activeAgent)
	require.NotNil(t, model.SelectedSession())
	assert.Equal(t, "brisket-001", model.activeAgent.ID)
	assert.Equal(t, "brisket-001", model.SelectedSession().AgentID)
}

func TestModel_Update_BeaconKnownSessionTransitionsFromWaiting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWaiting
	m.waiting = NewWaitingState("stager-001", "org/repo", "V001", ".github/workflows/ci.yml", "build", "auto_pr", 0)
	m.sessions = []Session{{
		AgentID:  "brisket-001",
		Hostname: "runner-old",
	}}
	m.selectedIndex = 0

	result, _ := m.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:  "brisket-001",
			Hostname: "runner-1",
			OS:       "linux",
			Arch:     "amd64",
		},
	})

	model := result.(Model)
	assert.Equal(t, PhasePostExploit, model.phase)
	require.NotNil(t, model.activeAgent)
	require.NotNil(t, model.SelectedSession())
	assert.Equal(t, "brisket-001", model.activeAgent.ID)
	assert.Equal(t, "brisket-001", model.SelectedSession().AgentID)
	assert.Equal(t, "runner-1", model.sessions[0].Hostname)
}

func TestModel_Update_ReturnToReconSuppressesDwellAutoRestore(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.input.Blur()
	m.activeAgent = &AgentState{ID: "agt-1", Runner: "runner-1"}
	m.sessions = []Session{{AgentID: "agt-1", Hostname: "runner-1"}}
	m.selectedIndex = 0
	deadline := time.Now().Add(5 * time.Minute)

	result, _ := m.Update(tea.KeyPressMsg{Text: "r", Code: 'r'})
	model := result.(Model)

	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.activeAgent)
	assert.False(t, model.dwellMode)
	assert.True(t, model.jobDeadline.IsZero())

	result, _ = model.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:       "agt-1",
			Hostname:      "runner-1",
			OS:            "linux",
			Arch:          "amd64",
			DwellDeadline: &deadline,
		},
	})
	model = result.(Model)

	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.activeAgent)
	assert.False(t, model.dwellMode)
	assert.True(t, model.jobDeadline.IsZero())
}

func TestModel_Update_ReturnToReconSuppressesOtherKnownDwellAgents(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.input.Blur()
	m.activeAgent = &AgentState{ID: "agt-1", Runner: "runner-1"}
	m.sessions = []Session{
		{AgentID: "agt-1", Hostname: "runner-1"},
		{AgentID: "agt-2", Hostname: "runner-2"},
	}
	m.selectedIndex = 0
	deadline := time.Now().Add(5 * time.Minute)

	result, _ := m.Update(tea.KeyPressMsg{Text: "r", Code: 'r'})
	model := result.(Model)

	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.activeAgent)

	result, _ = model.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:       "agt-2",
			Hostname:      "runner-2",
			OS:            "linux",
			Arch:          "amd64",
			DwellDeadline: &deadline,
		},
	})
	model = result.(Model)

	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.activeAgent)
	assert.False(t, model.dwellMode)
	assert.True(t, model.jobDeadline.IsZero())
}

func TestModel_Update_DeepAnalyzeShortcutDoesNotChangeTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	m.config.KitchenURL = "https://kitchen.test"
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT}
	m.target = "whooli"
	m.targetType = "org"

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Type: TreeNodeOrg, Label: "whooli", Parent: root, Expanded: true}
	repo := &TreeNode{ID: "repo:whooli/xyz", Type: TreeNodeRepo, Label: "xyz", Parent: org}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	m.treeRoot = root
	m.ReflattenTree()
	m.treeCursor = 1

	result, _ := m.Update(tea.KeyPressMsg{Text: "d", Code: 'd'})

	model := result.(Model)
	assert.Equal(t, "whooli", model.target)
	assert.Equal(t, "org", model.targetType)
	assert.Equal(t, "whooli/xyz", model.analysisFocusRepo)
}

func TestModel_Update_TargetShortcutSetsExplicitTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings

	root := &TreeNode{ID: "root", Expanded: true}
	org := &TreeNode{ID: "org:whooli", Type: TreeNodeOrg, Label: "whooli", Parent: root, Expanded: true}
	repo := &TreeNode{ID: "repo:whooli/xyz", Type: TreeNodeRepo, Label: "xyz", Parent: org}
	root.Children = []*TreeNode{org}
	org.Children = []*TreeNode{repo}
	m.treeRoot = root
	m.ReflattenTree()
	m.treeCursor = 1

	result, _ := m.Update(tea.KeyPressMsg{Text: "s", Code: 's'})

	model := result.(Model)
	assert.Equal(t, "whooli/xyz", model.target)
	assert.Equal(t, "repo", model.targetType)
}

func TestModel_Update_RevertInitialTokenRecalculatesMenu(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseRecon
	m.view = ViewFindings
	m.focus = FocusSessions
	m.initialTokenInfo = &TokenInfo{Value: "ghp_initial", Type: TokenTypeClassicPAT, Source: "config"}
	m.tokenInfo = &TokenInfo{Value: "ghs_app", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN"}
	m.appTokenPermissions = map[string]string{"actions": "write"}
	m.vulnerabilities = []Vulnerability{
		{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/comment.yml",
			Job:        "comment",
			Line:       10,
			RuleID:     "injection",
			Trigger:    "issue_comment",
			Context:    "issue_comment",
		},
		{
			ID:         "V002",
			Repository: "acme/api",
			Workflow:   ".github/workflows/dispatch.yml",
			Job:        "dispatch",
			Line:       20,
			RuleID:     "injection",
			Trigger:    "workflow_dispatch",
			Context:    "workflow_dispatch_input",
		},
	}
	m.GenerateSuggestions()
	require.NotEmpty(t, m.suggestions)
	require.GreaterOrEqual(t, m.suggestions[0].VulnIndex, 0)
	require.Equal(t, "V002", m.vulnerabilities[m.suggestions[0].VulnIndex].ID)

	result, _ := m.Update(tea.KeyPressMsg{Text: "i", Code: 'i'})

	model := result.(Model)
	require.NotEmpty(t, model.suggestions)
	require.GreaterOrEqual(t, model.suggestions[0].VulnIndex, 0)
	assert.Equal(t, "V001", model.vulnerabilities[model.suggestions[0].VulnIndex].ID)
}

func TestModel_Update_BeaconUpdatesExisting(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.sessions = []Session{
		{AgentID: "brisket-001", Hostname: "runner-1", IsOnline: false},
	}

	result, _ := m.Update(BeaconMsg{
		Beacon: counter.Beacon{
			AgentID:  "brisket-001",
			Hostname: "runner-1-updated",
			OS:       "linux",
			Arch:     "amd64",
		},
	})

	model := result.(Model)
	require.Len(t, model.sessions, 1)
	assert.True(t, model.sessions[0].IsOnline)
	assert.Equal(t, "runner-1-updated", model.sessions[0].Hostname)
}

// =============================================================================
// Pivot Message Tests
// =============================================================================

func TestModel_Update_PivotResultSuccess_GitHubToken(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	result, _ := m.Update(PivotResultMsg{
		Success: true,
		Type:    PivotTypeGitHubToken,
		NewVulns: []Vulnerability{
			{ID: "V010", Repository: "new-org/new-repo", Context: "workflow_dispatch"},
		},
	})

	model := result.(Model)
	require.Len(t, model.vulnerabilities, 1)
	assert.Equal(t, "V010", model.vulnerabilities[0].ID)
}

func TestModel_Update_PivotResultSuccess_StoresPivotTargets(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	result, _ := m.Update(PivotResultMsg{
		Success:  true,
		Type:     PivotTypeGitHubToken,
		NewRepos: []string{"org/repo1", "org/repo2", "org/repo3"},
	})

	model := result.(Model)
	require.Len(t, model.pivotTargets, 3)
	assert.Equal(t, "org/repo1", model.pivotTargets[0])
	assert.Equal(t, "org/repo2", model.pivotTargets[1])
	assert.Equal(t, "org/repo3", model.pivotTargets[2])
}

func TestModel_Update_PivotResultSuccess_CloudOIDC(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	result, _ := m.Update(PivotResultMsg{
		Success:  true,
		Type:     PivotTypeCloudOIDC,
		Provider: "aws",
		Credentials: []CollectedSecret{
			{Name: "AWS_ACCESS_KEY_ID", Value: "AKIA..."},
		},
	})

	model := result.(Model)
	require.Len(t, model.lootStash, 1)
	assert.Equal(t, "AWS_ACCESS_KEY_ID", model.lootStash[0].Name)
}

func TestModel_Update_PivotResultSuccess_GitHubApp(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.tokenInfo = &TokenInfo{Value: "ghp_original", Source: "operator"}

	result, _ := m.Update(PivotResultMsg{
		Success: true,
		Type:    PivotTypeGitHubApp,
		Credentials: []CollectedSecret{
			{Name: "APP_TOKEN_acme", Value: "ghs_test123", Type: "github_app_token"},
		},
	})

	model := result.(Model)
	assert.Empty(t, model.lootStash, "installation token should not be added to loot stash — it's regenerable from PEM")
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "installation token")
	assert.Equal(t, "ghs_test123", model.tokenInfo.Value, "should swap to pivoted token")
	assert.Equal(t, "ghp_original", model.initialTokenInfo.Value, "should preserve initial token")
	assert.NotNil(t, model.pivotToken, "should set pivotToken")
}

func TestModel_Update_PivotResultFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(PivotResultMsg{
		Success: false,
		Err:     errors.New("token expired"),
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "error", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "token expired")
}

// =============================================================================
// Order Message Tests
// =============================================================================

func TestModel_Update_OrderSent(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(OrderSentMsg{
		OrderID: "order-12345678",
		AgentID: "brisket-001",
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "success", model.output[len(model.output)-1].Type)
	assert.Contains(t, model.output[len(model.output)-1].Content, "order-12")
	assert.Contains(t, model.output[len(model.output)-1].Content, "brisket-001")
}

func TestModel_Update_OrderFailed(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(OrderFailedMsg{
		OrderID: "order-87654321",
		Err:     errors.New("agent offline"),
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	found := false
	for _, o := range model.output {
		if o.Type == "error" && strings.Contains(o.Content, "agent offline") {
			found = true
			break
		}
	}
	assert.True(t, found, "should contain error about agent offline")
}

// =============================================================================
// Window Size Message Tests
// =============================================================================

func TestModel_Update_WindowSize(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.ready = false

	result, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	model := result.(Model)
	assert.Equal(t, 120, model.width)
	assert.Equal(t, 40, model.height)
	assert.True(t, model.ready)
}

// =============================================================================
// Pantry Message Tests
// =============================================================================

func TestModel_Update_PantryFetched(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	p := createTestPantry()

	result, _ := m.Update(PantryFetchedMsg{Pantry: p})

	model := result.(Model)
	assert.NotNil(t, model.pantry)
}

func TestModel_Update_PantryFetchError(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})

	result, _ := m.Update(PantryFetchErrorMsg{Err: errors.New("network error")})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	assert.Equal(t, "warning", model.output[len(model.output)-1].Type)
}

// =============================================================================
// Bug 2: PivotResultMsg sets appTokenPermissions
// =============================================================================

func TestPivotResult_GitHubApp_SetsAppTokenPermissions(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.tokenInfo = &TokenInfo{Value: "ghp_original", Source: "operator"}

	perms := map[string]string{
		"contents":      "write",
		"pull_requests": "write",
		"metadata":      "read",
	}

	result, _ := m.Update(PivotResultMsg{
		Success: true,
		Type:    PivotTypeGitHubApp,
		Credentials: []CollectedSecret{
			{Name: "APP_TOKEN_acme", Value: "ghs_permstest", Type: "github_app_token"},
		},
		TokenPermissions: perms,
	})

	model := result.(Model)
	require.NotNil(t, model.appTokenPermissions)
	assert.Equal(t, "write", model.appTokenPermissions["contents"])
	assert.Equal(t, "write", model.appTokenPermissions["pull_requests"])
	assert.Equal(t, "read", model.appTokenPermissions["metadata"])
	assert.Nil(t, model.tokenPermissions)
}

func TestPivotResult_GitHubApp_StoresDisplayPermissionsForPairedAppID(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	perms := map[string]string{
		"issues": "write",
		"checks": "read",
	}

	result, _ := m.Update(PivotResultMsg{
		Success: true,
		Type:    PivotTypeGitHubApp,
		Credentials: []CollectedSecret{
			{Name: "APP_TOKEN_acme", Value: "ghs_permstest", Type: "github_app_token", Source: "pivot:app:12345"},
		},
		TokenPermissions: perms,
	})

	model := result.(Model)
	require.NotNil(t, model.appPermissionView["12345"])
	assert.Equal(t, "write", model.appPermissionView["12345"]["issues"])
	assert.Equal(t, "read", model.appPermissionView["12345"]["checks"])
}

// =============================================================================
// Bug 4: PivotResultMsg preserves initialTokenInfo
// =============================================================================

func TestPivotResult_GitHubApp_PersistsInitialAccessToken(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.tokenInfo = &TokenInfo{Value: "ghp_operator123", Source: "op", Type: TokenTypeClassicPAT}
	m.initialTokenInfo = nil

	result, _ := m.Update(PivotResultMsg{
		Success: true,
		Type:    PivotTypeGitHubApp,
		Credentials: []CollectedSecret{
			{Name: "APP_TOKEN_acme", Value: "ghs_pivoted456", Type: "github_app_token"},
		},
	})

	model := result.(Model)
	require.NotNil(t, model.initialTokenInfo, "initialTokenInfo should be set from tokenInfo when first pivot occurs")
	assert.Equal(t, "ghp_operator123", model.initialTokenInfo.Value)
	assert.Equal(t, "op", model.initialTokenInfo.Source)
}

func TestPivotResult_GitHubApp_DoesNotOverwriteInitialAccessToken(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.tokenInfo = &TokenInfo{Value: "ghs_first_pivot", Source: "loot:APP_TOKEN_acme", Type: TokenTypeInstallApp}
	m.initialTokenInfo = &TokenInfo{Value: "ghp_original", Source: "op", Type: TokenTypeClassicPAT}

	result, _ := m.Update(PivotResultMsg{
		Success: true,
		Type:    PivotTypeGitHubApp,
		Credentials: []CollectedSecret{
			{Name: "APP_TOKEN_other", Value: "ghs_second_pivot", Type: "github_app_token"},
		},
	})

	model := result.(Model)
	require.NotNil(t, model.initialTokenInfo, "initialTokenInfo should not be nil after second pivot")
	assert.Equal(t, "ghp_original", model.initialTokenInfo.Value, "initialTokenInfo should not be overwritten by second pivot")
	assert.Equal(t, "op", model.initialTokenInfo.Source, "initialTokenInfo source should remain unchanged")
}

// =============================================================================
// Private Repo Display Tests
// =============================================================================

func TestModel_Update_PivotResultSuccess_GitHubToken_ShowsPrivateRepos(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	result, _ := m.Update(PivotResultMsg{
		Success:         true,
		Type:            PivotTypeGitHubToken,
		NewRepos:        []string{"acme/public", "acme/secret-infra", "acme/internal"},
		NewPrivateRepos: []string{"acme/secret-infra", "acme/internal"},
		TotalFound:      3,
	})

	model := result.(Model)

	var hasPrivateMsg bool
	var lockCount int
	for _, o := range model.output {
		if o.Type == "success" && strings.Contains(o.Content, "PRIVATE repos") {
			hasPrivateMsg = true
		}
		if strings.Contains(o.Content, "🔒") {
			lockCount++
		}
	}
	assert.True(t, hasPrivateMsg, "Should show PRIVATE repos discovery message")
	assert.Equal(t, 2, lockCount, "Should show lock emoji for each private repo")
}

func TestModel_Update_PivotResultSuccess_GitHubToken_NoPrivateRepos(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	result, _ := m.Update(PivotResultMsg{
		Success:    true,
		Type:       PivotTypeGitHubToken,
		NewRepos:   []string{"acme/public"},
		TotalFound: 1,
	})

	model := result.(Model)

	for _, o := range model.output {
		assert.NotContains(t, o.Content, "PRIVATE repos", "Should not show private repos message when none are private")
	}
}

func TestModel_Update_PivotResult_TreeGetsPrivateLabel(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.pantry = pantry.New()

	repo := pantry.NewRepository("acme", "secret-infra", "github")
	require.NoError(t, m.pantry.AddAsset(repo))

	m.knownEntities["repo:acme/secret-infra"] = &KnownEntity{
		ID:         "repo:acme/secret-infra",
		EntityType: "repo",
		Name:       "acme/secret-infra",
		IsPrivate:  true,
	}

	result, _ := m.Update(PivotResultMsg{
		Success:         true,
		Type:            PivotTypeGitHubToken,
		NewPrivateRepos: []string{"acme/secret-infra"},
		TotalFound:      1,
	})

	model := result.(Model)
	require.NotNil(t, model.treeRoot, "tree should be rebuilt after pivot")
	require.Len(t, model.treeRoot.Children, 1)
	repoNode := model.treeRoot.Children[0]
	assert.Equal(t, "secret-infra", repoNode.Label, "label is just repo name")
	assert.Equal(t, TreeStateHighValue, repoNode.State,
		"repo node should be TreeStateHighValue after pivot with private knownEntity")
}

func TestModel_Update_PivotResult_ExistingRepoBecomesPrivate(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit
	m.pantry = pantry.New()

	repo := pantry.NewRepository("acme", "infra", "github")
	require.NoError(t, m.pantry.AddAsset(repo))

	m.knownEntities["repo:acme/infra"] = &KnownEntity{
		ID:         "repo:acme/infra",
		EntityType: "repo",
		Name:       "acme/infra",
		IsPrivate:  false,
	}

	m.RebuildTree()
	require.NotNil(t, m.treeRoot)
	assert.NotEqual(t, TreeStateHighValue, m.treeRoot.Children[0].State,
		"before pivot, repo should NOT be HighValue")

	m.knownEntities["repo:acme/infra"].IsPrivate = true

	result, _ := m.Update(PivotResultMsg{
		Success:    true,
		Type:       PivotTypeGitHubToken,
		TotalFound: 1,
	})

	model := result.(Model)
	require.NotNil(t, model.treeRoot)
	repoNode := model.treeRoot.Children[0]
	assert.Equal(t, TreeStateHighValue, repoNode.State,
		"after pivot updates knownEntity.IsPrivate, tree should reflect it")
}

func TestModel_Update_PivotResult_LootStashMarksDirty(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhasePostExploit

	result, _ := m.Update(PivotResultMsg{
		Success:    true,
		Type:       PivotTypeGitHubToken,
		TotalFound: 1,
	})

	model := result.(Model)
	assert.True(t, model.lootStashDirty, "loot stash should be dirty after pivot so it picks up private labels")
}

func TestModel_Update_CallbackControlFailedMsg_IncludesCallbackID(t *testing.T) {
	m := NewModel(Config{SessionID: "test-session"})
	m.phase = PhaseRecon

	result, _ := m.Update(CallbackControlFailedMsg{
		CallbackID: "cb-abc123",
		Action:     "revoke",
		Err:        errors.New("connection refused"),
	})

	model := result.(Model)
	require.NotEmpty(t, model.output)
	last := model.output[len(model.output)-1]
	assert.Equal(t, "error", last.Type)
	assert.Contains(t, last.Content, "cb-abc123", "output should include the callback ID")
	assert.Contains(t, last.Content, "revoke", "output should include the action")
	assert.Contains(t, last.Content, "connection refused", "output should include the error")
}

func TestHandleKeyMsg_CopyLoot_GitHubAppKeyCopiesPEM(t *testing.T) {
	m := NewModel(Config{})
	m.phase = PhasePostExploit
	m.view = ViewAgent
	m.focus = FocusSessions
	m.paneFocus = PaneFocusLoot
	m.lootStash = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			Type:        "github_app_key",
			PairedAppID: "12345",
			Repository:  "whooli/xyz",
			Workflow:    "whooli-analyzer.yml",
			Job:         "analyze",
		},
	}
	m.RebuildLootTree()
	require.True(t, m.LootTreeSelectByID("loot:secret:WHOOLI_BOT_APP_PRIVATE_KEY:whooli/xyz"))

	original := clipboardWriteAll
	defer func() {
		clipboardWriteAll = original
	}()

	var copied string
	clipboardWriteAll = func(text string) error {
		copied = text
		return nil
	}

	result, _ := m.Update(tea.KeyPressMsg{Text: "c", Code: 'c'})
	model := result.(Model)

	assert.Equal(t, "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----", copied)
	assert.True(t, model.lootFlash)
}
