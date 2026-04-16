// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	e2eEnvPath      = ".claude/e2e/.env"
	e2eConfig       = ".claude/e2e/config.yaml"
	e2eVault        = ".claude/e2e/tokens.yaml"
	tmuxSocketName  = "smokedmeat-e2e"
	tmuxSessionName = "smokedmeat-e2e"
	targetOrg       = "whooli"
	targetRepo      = "whooli/xyz"
)

var workflowPathRe = regexp.MustCompile(`Workflow:\s*(\.github/workflows/\S+)`)

type TmuxController struct {
	session string
}

var blockingModalNeedles = []string{
	"THEME",
	"Persistent implants",
	"JUMP",
	"HELP",
	"LICENSE",
}

func newTmuxController(session string) *TmuxController {
	return &TmuxController{session: session}
}

func tmuxArgs(args ...string) []string {
	return append([]string{"-L", tmuxSocketName}, args...)
}

func (t *TmuxController) SendKeys(keys string) error {
	cmd := exec.Command("tmux", tmuxArgs("send-keys", "-t", t.session, keys)...)
	return cmd.Run()
}

func (t *TmuxController) TypeText(text string) error {
	for text != "" {
		chunk := text
		if len(chunk) > 12 {
			chunk = text[:12]
		}
		cmd := exec.Command("tmux", tmuxArgs("send-keys", "-l", "-t", t.session, "--", chunk)...)
		if err := cmd.Run(); err != nil {
			return err
		}
		text = text[len(chunk):]
		if text != "" {
			time.Sleep(40 * time.Millisecond)
		}
	}
	return nil
}

func (t *TmuxController) Capture() string {
	cmd := exec.Command("tmux", tmuxArgs("capture-pane", "-t", t.session, "-p", "-e")...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func (t *TmuxController) CaptureClean() string {
	cmd := exec.Command("tmux", tmuxArgs("capture-pane", "-t", t.session, "-p")...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func waitForContent(tc *TmuxController, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(tc.CaptureClean(), needle) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func requireContent(t *testing.T, tc *TmuxController, needle string, timeout time.Duration, msg string) {
	t.Helper()
	if !waitForContent(tc, needle, timeout) {
		capture := tc.CaptureClean()
		t.Fatalf("%s: %q not found after %s. Capture:\n%s", msg, needle, timeout, capture)
	}
}

func waitForContentGone(tc *TmuxController, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !strings.Contains(tc.CaptureClean(), needle) {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func requireContentGone(t *testing.T, tc *TmuxController, needle string, timeout time.Duration, msg string) {
	t.Helper()
	if !waitForContentGone(tc, needle, timeout) {
		capture := tc.CaptureClean()
		t.Fatalf("%s: %q still present after %s. Capture:\n%s", msg, needle, timeout, capture)
	}
}

func waitForAny(tc *TmuxController, needles []string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		capture := tc.CaptureClean()
		for _, needle := range needles {
			if strings.Contains(capture, needle) {
				return needle
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

func waitForStableCapture(tc *TmuxController, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	last := tc.CaptureClean()
	stable := 0
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		current := tc.CaptureClean()
		if current == last {
			stable++
			if stable >= 2 {
				return current
			}
			continue
		}
		last = current
		stable = 0
	}
	return tc.CaptureClean()
}

func ghCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("gh", args...)
	token := getEnvOrFile("GITHUB_TOKEN", e2eEnvPath)
	if token != "" {
		cmd.Env = append(os.Environ(), "GH_TOKEN="+token)
	}
	return cmd
}

type ghIssueComment struct {
	Body string `json:"body"`
}

type ghIssue struct {
	Number      int              `json:"number"`
	Title       string           `json:"title"`
	URL         string           `json:"url"`
	Body        string           `json:"body"`
	State       string           `json:"state"`
	Comments    []ghIssueComment `json:"comments"`
	CommentMode bool             `json:"-"`
}

func (i *ghIssue) hasPayload() bool {
	return strings.Contains(i.Title, "curl") ||
		strings.Contains(i.Body, "curl")
}

func (i *ghIssue) hasPayloadComment() bool {
	for _, c := range i.Comments {
		if strings.Contains(c.Body, "curl") {
			return true
		}
	}
	return false
}

func findDeployedIssue(t *testing.T, timeout time.Duration, excludeNumbers ...int) *ghIssue {
	t.Helper()
	excluded := make(map[int]struct{}, len(excludeNumbers))
	for _, number := range excludeNumbers {
		excluded[number] = struct{}{}
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, state := range []string{"open", "closed"} {
			out, err := ghCommand(
				"issue", "list", "-R", targetRepo,
				"--state", state, "-L", "3",
				"--json", "number,title,url,body,state,comments",
			).Output()
			if err != nil {
				continue
			}
			var issues []ghIssue
			if err := json.Unmarshal(out, &issues); err != nil {
				continue
			}
			for i := range issues {
				issue := &issues[i]
				if _, skip := excluded[issue.Number]; skip {
					continue
				}
				if issue.hasPayload() {
					return issue
				}
				if strings.Contains(issue.Body, "SmokedMeat") && issue.hasPayloadComment() {
					issue.CommentMode = true
					return issue
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func closeIssueByNumber(t *testing.T, number int) {
	t.Helper()
	out, err := ghCommand("issue", "close", fmt.Sprintf("%d", number), "-R", targetRepo).CombinedOutput()
	if err != nil {
		t.Logf("gh issue close #%d failed: %v: %s", number, err, string(out))
		return
	}
	t.Logf("Closed issue #%d on %s", number, targetRepo)
}

func registerIssueFailureCleanup(t *testing.T, number int) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		closeIssueByNumber(t, number)
	})
}

func issueByNumber(t *testing.T, number int) *ghIssue {
	t.Helper()
	out, err := ghCommand(
		"issue", "view", fmt.Sprintf("%d", number), "-R", targetRepo,
		"--json", "number,title,url,body,state,comments",
	).Output()
	if err != nil {
		return nil
	}
	var issue ghIssue
	if err := json.Unmarshal(out, &issue); err != nil {
		return nil
	}
	return &issue
}

func waitForIssueState(t *testing.T, number int, wantState string, timeout time.Duration) *ghIssue {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		issue := issueByNumber(t, number)
		if issue != nil && strings.EqualFold(issue.State, wantState) {
			return issue
		}
		time.Sleep(2 * time.Second)
	}

	issue := issueByNumber(t, number)
	if issue == nil {
		t.Fatalf("issue #%d on %s could not be loaded while waiting for state %s", number, targetRepo, wantState)
	}
	t.Fatalf("issue #%d on %s did not reach state %s within %s (last state %s)", number, targetRepo, wantState, timeout, issue.State)
	return nil
}

func ensureInputFocus(t *testing.T, tmux *TmuxController) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		capture := tmux.CaptureClean()
		if hasBlockingModal(capture) {
			require.NoError(t, tmux.SendKeys("Escape"))
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if strings.Contains(capture, "Tab:complete") {
			return
		}
		require.NoError(t, tmux.SendKeys("F5"))
		time.Sleep(300 * time.Millisecond)
	}
}

func ensureShortcutFocus(t *testing.T, tmux *TmuxController) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		capture := tmux.CaptureClean()
		if hasBlockingModal(capture) {
			require.NoError(t, tmux.SendKeys("Escape"))
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if !strings.Contains(capture, "Tab:complete") && !strings.Contains(capture, counterPromptNeedle("")) {
			return
		}
		require.NoError(t, tmux.SendKeys("F2"))
		time.Sleep(300 * time.Millisecond)
	}
}

func hasBlockingModal(capture string) bool {
	for _, needle := range blockingModalNeedles {
		if strings.Contains(capture, needle) {
			return true
		}
	}
	return false
}

func ensureLootFocus(t *testing.T, tmux *TmuxController) {
	t.Helper()

	require.NoError(t, tmux.SendKeys("F3"))
	time.Sleep(300 * time.Millisecond)
}

func jumpOmnibox(t *testing.T, tmux *TmuxController, query, want string, timeout time.Duration) {
	t.Helper()

	ensureInputFocus(t, tmux)
	require.NoError(t, tmux.SendKeys("/"))
	requireContent(t, tmux, "JUMP", 5*time.Second, "Omnibox should open")
	require.NoError(t, tmux.TypeText(query))
	requireContent(t, tmux, "> "+query, 5*time.Second, "Omnibox input should reflect the query")
	time.Sleep(300 * time.Millisecond)
	if want != "" {
		requireContent(t, tmux, want, timeout, "Omnibox should surface the requested result")
	}
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContentGone(t, tmux, "JUMP", 5*time.Second, "Omnibox should close after selection")
	time.Sleep(300 * time.Millisecond)
}

func runCounterCommand(t *testing.T, tmux *TmuxController, command string) {
	t.Helper()

	ensureInputFocus(t, tmux)
	require.NoError(t, tmux.SendKeys("C-u"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.TypeText(command))
	time.Sleep(300 * time.Millisecond)

	capture := tmux.CaptureClean()
	if strings.Contains(capture, "JUMP") {
		require.NoError(t, tmux.SendKeys("Escape"))
		requireContentGone(t, tmux, "JUMP", 5*time.Second, "Omnibox should close before retrying command entry")
		ensureInputFocus(t, tmux)
		require.NoError(t, tmux.SendKeys("C-u"))
		time.Sleep(200 * time.Millisecond)
		require.NoError(t, tmux.TypeText(command))
		time.Sleep(300 * time.Millisecond)
	}

	require.NoError(t, tmux.SendKeys("Enter"))
	time.Sleep(400 * time.Millisecond)
}

func counterPromptNeedle(command string) string {
	promptPrefix := command
	if len(promptPrefix) > 24 {
		promptPrefix = promptPrefix[:24]
	}
	return "❯ " + promptPrefix
}

func waitForReconPhase(t *testing.T, tmux *TmuxController) {
	t.Helper()

	startState := waitForAny(tmux, []string{"Step 7", "Phase:Recon"}, 60*time.Second)
	require.NotEmpty(t, startState, "Counter should reach setup Step 7 or Recon")

	if startState != "Step 7" {
		return
	}

	t.Log("Pressing Enter to start analysis...")
	require.NoError(t, tmux.SendKeys("Enter"))

	t.Log("Waiting for analysis to complete...")
	for attempt := 0; attempt < 3; attempt++ {
		analysisResult := waitForAny(tmux, []string{"Analysis complete", "Phase:Recon", "Analysis failed"}, 120*time.Second)
		require.NotEmpty(t, analysisResult, "Analysis should complete within 2 minutes")

		if analysisResult == "Phase:Recon" {
			return
		}
		if analysisResult == "Analysis complete" {
			require.NoError(t, tmux.SendKeys("Enter"))
			requireContent(t, tmux, "Phase:Recon", 10*time.Second, "Should transition to Recon phase")
			return
		}
		if attempt == 2 {
			capture := tmux.CaptureClean()
			t.Fatalf("analysis failed repeatedly during setup. Capture:\n%s", capture)
		}
		t.Logf("Analysis failed on attempt %d, retrying...", attempt+1)
		require.NoError(t, tmux.SendKeys("r"))
	}
}

func openDeployWizardFromMenu(t *testing.T, tmux *TmuxController, vulnKey string) {
	t.Helper()

	ensureShortcutFocus(t, tmux)
	require.NoError(t, tmux.SendKeys(vulnKey))
	requireContent(t, tmux, "Step 1/3", 10*time.Second, "Wizard Step 1/3 should appear")
}

func completeIssueDeployWizard(t *testing.T, tmux *TmuxController, dwellAdjustments int) {
	t.Helper()

	t.Log("Step 1/3: Confirming vuln → Enter")
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 2/3", 10*time.Second, "Wizard Step 2/3 should appear")

	t.Log("Step 2/3: Selecting Create Issue (1) → Enter")
	require.NoError(t, tmux.SendKeys("1"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 3/3", 10*time.Second, "Wizard Step 3/3 should appear")

	if dwellAdjustments > 0 {
		t.Log("Step 3/3: Setting dwell time...")
		for i := 0; i < dwellAdjustments; i++ {
			require.NoError(t, tmux.SendKeys("d"))
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func completeIssueDeployWizardWithCachePoison(t *testing.T, tmux *TmuxController, dwellAdjustments int, victimWorkflow string) {
	t.Helper()

	completeIssueDeployWizard(t, tmux, dwellAdjustments)
	requireContent(t, tmux, "Cache Poisoning:", 5*time.Second, "Wizard should show cache poisoning controls")
	require.NoError(t, tmux.SendKeys("c"))
	requireContent(t, tmux, "Cache Poisoning:", 5*time.Second, "Cache poisoning should remain visible after toggle")
	requireContent(t, tmux, "Victim:", 5*time.Second, "Cache poisoning should show a victim selection")
	requireContent(t, tmux, "Replace Cache:", 5*time.Second, "Cache poisoning should expose cache replacement controls")
	require.NotContains(t, tmux.CaptureClean(), "Unavailable (token lacks actions:write)", "Cache replacement should be available for this flow")
	require.NoError(t, tmux.SendKeys("r"))
	require.NotEmpty(t, waitForAny(tmux, []string{"Replace Cache:  On", "Replace Cache: On"}, 5*time.Second), "Cache replacement should turn on")

	if victimWorkflow == "" {
		return
	}

	err := cycleWizardVictimWorkflow(tmux.CaptureClean, func() error {
		if err := tmux.SendKeys("v"); err != nil {
			return err
		}
		time.Sleep(250 * time.Millisecond)
		return nil
	}, victimWorkflow)
	if err != nil {
		capture := tmux.CaptureClean()
		t.Fatalf("%s. Capture:\n%s", err, capture)
	}
}

func completeCommentDeployWizard(t *testing.T, tmux *TmuxController, issueNumber, dwellAdjustments int, commentTarget string) {
	t.Helper()

	t.Log("Step 1/3: Confirming vuln → Enter")
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 2/3", 10*time.Second, "Wizard Step 2/3 should appear")

	t.Log("Step 2/3: Selecting Add Comment (2) → Enter")
	require.NoError(t, tmux.SendKeys("2"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 3/3", 10*time.Second, "Wizard Step 3/3 should appear")

	switch commentTarget {
	case "pull_request":
		require.NoError(t, tmux.SendKeys("t"))
		requireContent(t, tmux, "PR #:", 5*time.Second, "Comment deployment should prompt for a PR number")
	case "stub_pull_request":
		require.NoError(t, tmux.SendKeys("t"))
		require.NoError(t, tmux.SendKeys("t"))
		requireContent(t, tmux, "Create stub PR", 5*time.Second, "Comment deployment should expose the stub PR target")
	default:
		requireContent(t, tmux, "Issue #:", 5*time.Second, "Comment deployment should prompt for an issue number")
	}

	if commentTarget != "stub_pull_request" && issueNumber > 0 {
		require.NoError(t, tmux.TypeText(strconv.Itoa(issueNumber)))
	}

	if dwellAdjustments > 0 {
		t.Log("Step 3/3: Setting dwell time...")
		for i := 0; i < dwellAdjustments; i++ {
			require.NoError(t, tmux.SendKeys("d"))
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func completeCommentDeployWizardWithCachePoison(t *testing.T, tmux *TmuxController, issueNumber, dwellAdjustments int, victimWorkflow, commentTarget string) {
	t.Helper()

	completeCommentDeployWizard(t, tmux, issueNumber, dwellAdjustments, commentTarget)
	requireContent(t, tmux, "Cache Poisoning:", 5*time.Second, "Wizard should show cache poisoning controls")
	require.NoError(t, tmux.SendKeys("c"))
	requireContent(t, tmux, "Cache Poisoning:", 5*time.Second, "Cache poisoning should remain visible after toggle")
	requireContent(t, tmux, "Victim:", 5*time.Second, "Cache poisoning should show a victim selection")
	requireContent(t, tmux, "Replace Cache:", 5*time.Second, "Cache poisoning should expose cache replacement controls")
	require.NotContains(t, tmux.CaptureClean(), "Unavailable (token lacks actions:write)", "Cache replacement should be available for this flow")
	require.NoError(t, tmux.SendKeys("r"))
	require.NotEmpty(t, waitForAny(tmux, []string{"Replace Cache:  On", "Replace Cache: On"}, 5*time.Second), "Cache replacement should turn on")

	if victimWorkflow == "" {
		return
	}

	err := cycleWizardVictimWorkflow(tmux.CaptureClean, func() error {
		if err := tmux.SendKeys("v"); err != nil {
			return err
		}
		time.Sleep(250 * time.Millisecond)
		return nil
	}, victimWorkflow)
	if err != nil {
		capture := tmux.CaptureClean()
		t.Fatalf("%s. Capture:\n%s", err, capture)
	}
}

func completeAutoPRDeployWizard(t *testing.T, tmux *TmuxController, dwellAdjustments int) {
	t.Helper()

	t.Log("Step 1/3: Confirming vuln → Enter")
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 2/3", 10*time.Second, "Wizard Step 2/3 should appear")

	t.Log("Step 2/3: Selecting Create PR (1) → Enter")
	require.NoError(t, tmux.SendKeys("1"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 3/3", 10*time.Second, "Wizard Step 3/3 should appear")

	if dwellAdjustments > 0 {
		t.Log("Step 3/3: Setting dwell time...")
		for i := 0; i < dwellAdjustments; i++ {
			require.NoError(t, tmux.SendKeys("d"))
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func completeDispatchDeployWizard(t *testing.T, tmux *TmuxController, dwellAdjustments int) {
	t.Helper()

	t.Log("Step 1/3: Confirming vuln → Enter")
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 2/3", 10*time.Second, "Wizard Step 2/3 should appear")

	t.Log("Step 2/3: Selecting Trigger Dispatch (1) → Enter")
	require.NoError(t, tmux.SendKeys("1"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "Step 3/3", 10*time.Second, "Wizard Step 3/3 should appear")

	if dwellAdjustments > 0 {
		t.Log("Step 3/3: Setting dwell time...")
		for i := 0; i < dwellAdjustments; i++ {
			require.NoError(t, tmux.SendKeys("d"))
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func currentWizardVictimWorkflow(capture string) string {
	for _, line := range strings.Split(capture, "\n") {
		if workflow := workflowPathFromLine(line); workflow != "" {
			return workflow
		}
	}
	return ""
}

func cycleWizardVictimWorkflow(capture func() string, advance func() error, victimWorkflow string) error {
	if victimWorkflow == "" {
		return nil
	}

	seen := make(map[string]struct{})
	for {
		current := capture()
		if currentWizardVictimWorkflow(current) == victimWorkflow {
			return nil
		}

		visible := currentWizardVictimWorkflow(current)
		if visible == "" {
			visible = current
		}
		if _, ok := seen[visible]; ok {
			return fmt.Errorf("cache poison victim %q not visible after cycling all victims", victimWorkflow)
		}
		seen[visible] = struct{}{}

		if err := advanceWorkflowSelection(capture, advance, visible, currentWizardVictimWorkflow); err != nil {
			return err
		}
	}
}

func waitForWorkflowSelectionChange(capture func() string, current string, selected func(string) string, timeout time.Duration) bool {
	if current == "" {
		return false
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		next := selected(capture())
		if next != "" && next != current {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func advanceWorkflowSelection(capture func() string, advance func() error, current string, selected func(string) string) error {
	for attempts := 0; attempts < 3; attempts++ {
		if err := advance(); err != nil {
			return err
		}
		if waitForWorkflowSelectionChange(capture, current, selected, time.Second) {
			return nil
		}
	}
	return fmt.Errorf("selection %q did not advance after repeated cycle attempts", current)
}

func analyzeCurrentTarget(t *testing.T, tmux *TmuxController) {
	t.Helper()

	runCounterCommand(t, tmux, "analyze")
	analysisResult := waitForAny(tmux, []string{"Analysis complete", "Analysis failed", "Imported ", "Analyzed "}, 120*time.Second)
	require.NotEmpty(t, analysisResult, "Analysis should complete within 2 minutes")
	require.NotEqual(t, "Analysis failed", analysisResult, "Analysis should succeed")
}

func currentSelectedCallbackWorkflow(capture string) string {
	for _, line := range strings.Split(capture, "\n") {
		if workflow := workflowPathFromLine(line); workflow != "" {
			return workflow
		}
	}
	return ""
}

func workflowPathFromLine(line string) string {
	match := workflowPathRe.FindStringSubmatch(line)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func cycleCallbackWorkflow(capture func() string, advance func() error, workflow string) error {
	if workflow == "" {
		return nil
	}

	seen := make(map[string]struct{})
	for {
		current := capture()
		if strings.Contains(current, "Workflow: "+workflow) {
			return nil
		}

		visible := currentSelectedCallbackWorkflow(current)
		if visible == "" {
			visible = current
		}
		if _, ok := seen[visible]; ok {
			return fmt.Errorf("callback workflow %q not visible after cycling all implants", workflow)
		}
		seen[visible] = struct{}{}

		if err := advanceWorkflowSelection(capture, advance, visible, currentSelectedCallbackWorkflow); err != nil {
			return err
		}
	}
}

func armNextImplantWithDwell(t *testing.T, tmux *TmuxController, workflow string) {
	t.Helper()

	require.NoError(t, tmux.SendKeys("I"))
	requireContent(t, tmux, "Persistent implants", 10*time.Second, "Implants modal should appear")
	if err := cycleCallbackWorkflow(tmux.CaptureClean, func() error {
		if err := tmux.SendKeys("j"); err != nil {
			return err
		}
		time.Sleep(250 * time.Millisecond)
		return nil
	}, workflow); err != nil {
		capture := tmux.CaptureClean()
		t.Fatalf("%s. Capture:\n%s", err, capture)
	}
	require.NoError(t, tmux.SendKeys("n"))
	requireContent(t, tmux, "next dwell", 10*time.Second, "Selected implant should show the next dwell override")
	require.NoError(t, tmux.SendKeys("Escape"))
	requireContentGone(t, tmux, "Persistent implants", 10*time.Second, "Implants modal should close")
}

func deployIssueFromMenu(t *testing.T, tmux *TmuxController, vulnKey string, dwellAdjustments int) string {
	t.Helper()

	openDeployWizardFromMenu(t, tmux, vulnKey)
	completeIssueDeployWizard(t, tmux, dwellAdjustments)
	require.NoError(t, tmux.SendKeys("Enter"))

	deployPhase := waitForAny(tmux, []string{"Phase:Waiting", "Phase:Post-Exploit"}, 30*time.Second)
	require.NotEmpty(t, deployPhase, "Phase should transition after deploy")
	return deployPhase
}

func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func loadEnvFile(path string) map[string]string {
	env := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return env
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}
	return env
}

func getEnvOrFile(key, filePath string) string {
	absPath := filePath
	if !filepath.IsAbs(filePath) {
		if root := findProjectRoot(); root != "" {
			absPath = filepath.Join(root, filePath)
		}
	}
	if val := loadEnvFile(absPath)[key]; val != "" {
		return val
	}
	return os.Getenv(key)
}

func writeConfig(token, target string) error {
	root := findProjectRoot()
	if root == "" {
		return fmt.Errorf("could not find project root")
	}
	kitchenURL := getEnvOrFile("KITCHEN_URL", e2eEnvPath)
	content := fmt.Sprintf("kitchen_url: %s\ntoken: %s\ntoken_source: pat\ntarget: %s\n", kitchenURL, token, target)
	return os.WriteFile(filepath.Join(root, e2eConfig), []byte(content), 0o600)
}

func resetE2EWorkspace() error {
	root := findProjectRoot()
	if root == "" {
		return fmt.Errorf("could not find project root")
	}
	if err := cleanupCounterPaneLogs(root, ""); err != nil {
		return err
	}
	for _, rel := range []string{
		e2eVault,
		".claude/e2e/cloud-shell",
		".claude/e2e/ssh-shell",
	} {
		if err := os.RemoveAll(filepath.Join(root, rel)); err != nil {
			return err
		}
	}
	return nil
}

func restartCounter(sessionID string) error {
	_ = exec.Command("tmux", "kill-session", "-t", tmuxSessionName).Run()
	_ = exec.Command("tmux", tmuxArgs("kill-server")...).Run()
	time.Sleep(500 * time.Millisecond)

	root := findProjectRoot()
	if root == "" {
		return fmt.Errorf("could not find project root")
	}
	cmd := exec.Command("make", "e2e-counter")
	cmd.Dir = root
	if sessionID != "" {
		cmd.Env = append(os.Environ(), "SESSION_ID="+sessionID)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("make e2e-counter failed: %w", err)
	}

	if err := cleanupCounterPaneLogs(root, sessionID); err != nil {
		return err
	}
	paneLog := filepath.Join(root, ".claude/e2e", fmt.Sprintf("counter-pane-%s-%s.log", sessionID, time.Now().UTC().Format("20060102-150405.000000000")))
	if err := exec.Command("tmux", tmuxArgs("pipe-pane", "-o", "-t", tmuxSessionName, "cat > "+shellQuote(paneLog))...).Run(); err != nil {
		return fmt.Errorf("tmux pipe-pane failed: %w", err)
	}

	tc := newTmuxController(tmuxSessionName)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		capture := strings.TrimSpace(tc.CaptureClean())
		if capture != "" {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("counter did not produce output within 60s")
}

func cleanupCounterPaneLogs(root, sessionID string) error {
	pattern := filepath.Join(root, ".claude/e2e", "counter-pane-*.log")
	if sessionID != "" {
		pattern = filepath.Join(root, ".claude/e2e", fmt.Sprintf("counter-pane-%s-*.log", sessionID))
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob pane logs: %w", err)
	}
	for _, match := range matches {
		if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale pane log %s: %w", filepath.Base(match), err)
		}
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func newInsecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // E2E uses the disposable local Kitchen tunnel.
		},
	}
}

func waitForKitchenHealth(root string, timeout time.Duration) error {
	envPath := filepath.Join(root, e2eEnvPath)
	env := loadEnvFile(envPath)
	kitchenURL := env["KITCHEN_URL"]
	authToken := env["AUTH_TOKEN"]
	if kitchenURL == "" || authToken == "" {
		return fmt.Errorf("KITCHEN_URL or AUTH_TOKEN missing from %s", envPath)
	}

	client := newInsecureHTTPClient(5 * time.Second)
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", kitchenURL+"/health", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+authToken)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("health returned %d", resp.StatusCode)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("kitchen not healthy after %s at %s: %v", timeout, kitchenURL, lastErr)
}

var menuItemRe = regexp.MustCompile(`[┃│]\s*\[(\d)\]\s+(.*)$`)
var menuContinuationRe = regexp.MustCompile(`[┃│]\s{4,}(.+)$`)

func findMenuVuln(capture string, keywords ...string) string {
	return findMenuVulnWithMatch(capture, false, keywords...)
}

func findMenuVulnAll(capture string, keywords ...string) string {
	return findMenuVulnWithMatch(capture, true, keywords...)
}

func waitForMenuVulnKey(t *testing.T, tmux *TmuxController, timeout time.Duration, keywordSets ...[]string) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	capture := ""
	for time.Now().Before(deadline) {
		capture = tmux.CaptureClean()
		for _, keywords := range keywordSets {
			if key := findMenuVulnAll(capture, keywords...); key != "" {
				return key
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("menu vulnerability not found for any keyword set %v after %s. Capture:\n%s", keywordSets, timeout, capture)
	return ""
}

func requireMenuVulnKey(t *testing.T, capture string, keywordSets ...[]string) string {
	t.Helper()
	for _, keywords := range keywordSets {
		if key := findMenuVulnAll(capture, keywords...); key != "" {
			return key
		}
	}
	t.Fatalf("menu vulnerability not found for any keyword set %v. Capture:\n%s", keywordSets, capture)
	return ""
}

func findMenuVulnWithMatch(capture string, requireAll bool, keywords ...string) string {
	lines := strings.Split(capture, "\n")
	for i, line := range lines {
		key, item := menuItemLine(line)
		if key == "" {
			continue
		}
		ctx := strings.ToLower(item)
		for j := i + 1; j < len(lines); j++ {
			if nextKey, _ := menuItemLine(lines[j]); nextKey != "" {
				break
			}
			continuation := menuContinuationLine(lines[j])
			if continuation == "" {
				if strings.Contains(lines[j], "Press 1-5") {
					break
				}
				continue
			}
			ctx += " " + strings.ToLower(continuation)
		}
		if requireAll {
			matchedAll := true
			for _, kw := range keywords {
				if !strings.Contains(ctx, strings.ToLower(kw)) {
					matchedAll = false
					break
				}
			}
			if matchedAll {
				return key
			}
			continue
		}
		for _, kw := range keywords {
			if strings.Contains(ctx, strings.ToLower(kw)) {
				return key
			}
		}
	}
	return ""
}

func menuItemLine(line string) (key, text string) {
	matches := menuItemRe.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return "", ""
	}
	last := matches[len(matches)-1]
	if len(last) < 3 {
		return "", ""
	}
	return last[1], strings.TrimSpace(last[2])
}

func menuContinuationLine(line string) string {
	matches := menuContinuationRe.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return ""
	}
	last := matches[len(matches)-1]
	if len(last) < 2 {
		return ""
	}
	return strings.TrimSpace(last[1])
}
