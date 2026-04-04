// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindMenuVulnIgnoresTreeIndices(t *testing.T) {
	capture := `
 │          ★ [4] Pwn Request [VULN]                           │┃  [1] 💉 Bash injection (comment)
 │    ▼ ◌ .github/workflows/auto-labeler.yml [WORKFLOW]       │┃      xyz
 │      ▼ ◌ whooli-triage (AI Triage & Sanitation) [JOB]      │┃
 │          ★ [2] Bash injection (issue body) [VULN]          ││  [2] 💉 Bash injection (issue body)
 │                                                            ││      xyz
 │                                                            ││      .github/workflows/auto-labeler.yml→whooli-triage:20
 │          ★ [5] Bash injection (dispatch input) [VULN]      ││
 │                                                            ││  Press 1-5 to order
`

	key := findMenuVuln(capture, "issue body")
	if key != "2" {
		t.Fatalf("findMenuVuln returned %q, want 2", key)
	}
}

func TestGetEnvOrFilePrefersFile(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_shell")

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("GITHUB_TOKEN=ghp_file\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	token := getEnvOrFile("GITHUB_TOKEN", envPath)
	if token != "ghp_file" {
		t.Fatalf("getEnvOrFile returned %q, want ghp_file", token)
	}
}

func TestTmuxArgsUseDedicatedSocket(t *testing.T) {
	assert.Equal(t,
		[]string{"-L", tmuxSocketName, "capture-pane", "-t", tmuxSessionName, "-p"},
		tmuxArgs("capture-pane", "-t", tmuxSessionName, "-p"),
	)
}

func TestCleanupCounterPaneLogs_RemovesOnlyMatchingSession(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, ".claude/e2e")
	require.NoError(t, os.MkdirAll(logDir, 0o755))
	keep := filepath.Join(logDir, "counter-pane-e2e-smoke-20260327-000000.000000000.log")
	removeA := filepath.Join(logDir, "counter-pane-e2e-goat-20260327-000000.000000000.log")
	removeB := filepath.Join(logDir, "counter-pane-e2e-goat-20260327-000001.000000000.log")
	for _, path := range []string{keep, removeA, removeB} {
		require.NoError(t, os.WriteFile(path, []byte("log"), 0o644))
	}

	require.NoError(t, cleanupCounterPaneLogs(root, "e2e-goat"))
	assert.FileExists(t, keep)
	assert.NoFileExists(t, removeA)
	assert.NoFileExists(t, removeB)
}

func TestCleanupCounterPaneLogs_EmptySessionRemovesAll(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, ".claude/e2e")
	require.NoError(t, os.MkdirAll(logDir, 0o755))
	smoke := filepath.Join(logDir, "counter-pane-e2e-smoke-20260327-000000.000000000.log")
	goat := filepath.Join(logDir, "counter-pane-e2e-goat-20260327-000001.000000000.log")
	for _, path := range []string{smoke, goat} {
		require.NoError(t, os.WriteFile(path, []byte("log"), 0o644))
	}

	require.NoError(t, cleanupCounterPaneLogs(root, ""))
	assert.NoFileExists(t, smoke)
	assert.NoFileExists(t, goat)
}

func TestCurrentWizardVictimWorkflow(t *testing.T) {
	capture := `
 Cache Poisoning: On [c] to toggle
 Victim: setup-go [v] to cycle
 Workflow: .github/workflows/release.yml
 Execute: checkout post
`

	assert.Equal(t, ".github/workflows/release.yml", currentWizardVictimWorkflow(capture))
}

func TestCounterPromptNeedle(t *testing.T) {
	assert.Equal(t, "❯ status", counterPromptNeedle("status"))
	assert.Equal(t, "❯ set token 12345678901234", counterPromptNeedle("set token 12345678901234567890"))
}

func TestCurrentWizardVictimWorkflowFromBorderedModalLine(t *testing.T) {
	capture := `
 │  Victim:  actions/cache · manual [v] to cycle                                          │
 │  Workflow:  .github/workflows/deploy.yml (Sync to Nucleus Data Lake)                   │
 │  Trigger:  manual                                                                      │
 `

	assert.Equal(t, ".github/workflows/deploy.yml", currentWizardVictimWorkflow(capture))
}

func TestCurrentSelectedCallbackWorkflow(t *testing.T) {
	capture := `
 Persistent implants
 > Cache poison victim · .github/workflows/deploy.yml
 Repo: whooli/infrastructure-definitions
 Workflow: .github/workflows/deploy.yml
 Job: sync
 `

	assert.Equal(t, ".github/workflows/deploy.yml", currentSelectedCallbackWorkflow(capture))
}

func TestCurrentSelectedCallbackWorkflowFromBorderedModalLine(t *testing.T) {
	capture := `
 │  Repo:  whooli/infrastructure-definitions                                              │
 │  Workflow:  .github/workflows/deploy.yml                                               │
 │  Job:  sync                                                                            │
 `

	assert.Equal(t, ".github/workflows/deploy.yml", currentSelectedCallbackWorkflow(capture))
}

func TestCycleWizardVictimWorkflowFindsTargetsBeyondEightOptions(t *testing.T) {
	workflows := []string{
		".github/workflows/01.yml",
		".github/workflows/02.yml",
		".github/workflows/03.yml",
		".github/workflows/04.yml",
		".github/workflows/05.yml",
		".github/workflows/06.yml",
		".github/workflows/07.yml",
		".github/workflows/08.yml",
		".github/workflows/09.yml",
		".github/workflows/10.yml",
	}
	index := 0
	steps := 0

	err := cycleWizardVictimWorkflow(func() string {
		return "Workflow: " + workflows[index]
	}, func() error {
		steps++
		index = (index + 1) % len(workflows)
		return nil
	}, ".github/workflows/10.yml")

	require.NoError(t, err)
	assert.Equal(t, 9, steps)
}

func TestCycleWizardVictimWorkflowStopsAfterFullCycle(t *testing.T) {
	workflows := []string{
		".github/workflows/build.yml",
		".github/workflows/release.yml",
		".github/workflows/deploy.yml",
	}
	index := 0

	err := cycleWizardVictimWorkflow(func() string {
		return "Workflow: " + workflows[index]
	}, func() error {
		index = (index + 1) % len(workflows)
		return nil
	}, ".github/workflows/missing.yml")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not visible after cycling all victims")
}

func TestCycleWizardVictimWorkflowIgnoresUnselectedWorkflowMentions(t *testing.T) {
	workflows := []string{
		".github/workflows/benchmark-bot.yml",
		".github/workflows/deploy.yml",
	}
	index := 0
	steps := 0

	err := cycleWizardVictimWorkflow(func() string {
		return "Victim list contains .github/workflows/deploy.yml\nWorkflow: " + workflows[index]
	}, func() error {
		steps++
		index = (index + 1) % len(workflows)
		return nil
	}, ".github/workflows/deploy.yml")

	require.NoError(t, err)
	assert.Equal(t, 1, steps)
}

func TestCycleWizardVictimWorkflowWaitsForRenderedSelectionChange(t *testing.T) {
	workflows := []string{".github/workflows/benchmark-bot.yml", ".github/workflows/deploy.yml"}
	visible := 0
	pending := -1
	staleReads := 0
	steps := 0

	err := cycleWizardVictimWorkflow(func() string {
		if pending >= 0 && staleReads == 0 {
			visible = pending
			pending = -1
		}
		if staleReads > 0 {
			staleReads--
		}
		return "Workflow: " + workflows[visible]
	}, func() error {
		steps++
		if visible < len(workflows)-1 {
			pending = visible + 1
			staleReads = 1
		}
		return nil
	}, ".github/workflows/deploy.yml")

	require.NoError(t, err)
	assert.Equal(t, 1, steps)
}

func TestCycleWizardVictimWorkflowRetriesWhenSelectionDoesNotMove(t *testing.T) {
	workflows := []string{".github/workflows/benchmark-bot.yml", ".github/workflows/deploy.yml"}
	visible := 0
	steps := 0

	err := cycleWizardVictimWorkflow(func() string {
		return "Workflow: " + workflows[visible]
	}, func() error {
		steps++
		if steps >= 2 {
			visible = 1
		}
		return nil
	}, ".github/workflows/deploy.yml")

	require.NoError(t, err)
	assert.Equal(t, 2, steps)
}

func TestMatchingActionsCaches_FiltersByPrefixAndRef(t *testing.T) {
	now := time.Now()
	caches := []actionsCache{
		{ID: 1, Key: "setup-go-aaa", Ref: "refs/heads/main", CreatedAt: now},
		{ID: 2, Key: "setup-go-bbb", Ref: "refs/heads/feature", CreatedAt: now.Add(-time.Minute)},
		{ID: 3, Key: "other-cache", Ref: "refs/heads/main", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: 4, Key: "setup-go-ccc", Ref: "refs/heads/main", CreatedAt: now.Add(-3 * time.Minute)},
	}

	assert.Equal(t, []actionsCache{
		{ID: 1, Key: "setup-go-aaa", Ref: "refs/heads/main", CreatedAt: now},
		{ID: 4, Key: "setup-go-ccc", Ref: "refs/heads/main", CreatedAt: now.Add(-3 * time.Minute)},
	}, matchingActionsCaches(caches, "setup-go-", "refs/heads/main"))
}

func TestMatchingActionsCaches_AllowsEmptyPrefixOrRef(t *testing.T) {
	now := time.Now()
	caches := []actionsCache{
		{ID: 1, Key: "setup-go-aaa", Ref: "refs/heads/main", CreatedAt: now},
		{ID: 2, Key: "other-cache", Ref: "refs/heads/main", CreatedAt: now.Add(-time.Minute)},
		{ID: 3, Key: "setup-go-bbb", Ref: "refs/heads/feature", CreatedAt: now.Add(-2 * time.Minute)},
	}

	assert.Equal(t, caches[:2], matchingActionsCaches(caches, "", "refs/heads/main"))
	assert.Equal(t, []actionsCache{
		{ID: 1, Key: "setup-go-aaa", Ref: "refs/heads/main", CreatedAt: now},
		{ID: 3, Key: "setup-go-bbb", Ref: "refs/heads/feature", CreatedAt: now.Add(-2 * time.Minute)},
	}, matchingActionsCaches(caches, "setup-go-", ""))
}

func TestCycleCallbackWorkflowFindsTarget(t *testing.T) {
	workflows := []string{
		".github/workflows/release.yml",
		".github/workflows/deploy.yml",
		".github/workflows/benchmark-bot.yml",
	}
	index := 0
	steps := 0

	err := cycleCallbackWorkflow(func() string {
		return "Workflow: " + workflows[index]
	}, func() error {
		steps++
		index = (index + 1) % len(workflows)
		return nil
	}, ".github/workflows/benchmark-bot.yml")

	require.NoError(t, err)
	assert.Equal(t, 2, steps)
}

func TestCycleCallbackWorkflowStopsAfterFullCycle(t *testing.T) {
	workflows := []string{
		".github/workflows/release.yml",
		".github/workflows/deploy.yml",
	}
	index := 0

	err := cycleCallbackWorkflow(func() string {
		return "Workflow: " + workflows[index]
	}, func() error {
		index = (index + 1) % len(workflows)
		return nil
	}, ".github/workflows/missing.yml")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not visible after cycling all implants")
}

func TestCycleCallbackWorkflowWaitsForRenderedSelectionChange(t *testing.T) {
	workflows := []string{".github/workflows/release.yml", ".github/workflows/deploy.yml"}
	visible := 0
	pending := -1
	staleReads := 0
	steps := 0

	err := cycleCallbackWorkflow(func() string {
		if pending >= 0 && staleReads == 0 {
			visible = pending
			pending = -1
		}
		if staleReads > 0 {
			staleReads--
		}
		return "Workflow: " + workflows[visible]
	}, func() error {
		steps++
		if visible < len(workflows)-1 {
			pending = visible + 1
			staleReads = 1
		}
		return nil
	}, ".github/workflows/deploy.yml")

	require.NoError(t, err)
	assert.Equal(t, 1, steps)
}

func TestCycleCallbackWorkflowRetriesWhenSelectionDoesNotMove(t *testing.T) {
	workflows := []string{".github/workflows/release.yml", ".github/workflows/deploy.yml"}
	visible := 0
	steps := 0

	err := cycleCallbackWorkflow(func() string {
		return "Workflow: " + workflows[visible]
	}, func() error {
		steps++
		if steps >= 2 {
			visible = 1
		}
		return nil
	}, ".github/workflows/deploy.yml")

	require.NoError(t, err)
	assert.Equal(t, 2, steps)
}
