// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	infraRepo            = "whooli/infrastructure-definitions"
	benchmarkBotWorkflow = ".github/workflows/benchmark-bot.yml"
	deployWorkflow       = ".github/workflows/deploy.yml"
	flagBucket           = "whooli-newcleus-benchmarks"
)

var (
	flagRe = regexp.MustCompile(`(?i)(SM\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\})`)
)

type vaultToken struct {
	Name        string `yaml:"name"`
	Value       string `yaml:"value"`
	Type        string `yaml:"type,omitempty"`
	PairedAppID string `yaml:"paired_app_id,omitempty"`
	Repository  string `yaml:"repository,omitempty"`
	Workflow    string `yaml:"workflow,omitempty"`
	Job         string `yaml:"job,omitempty"`
}

type vaultFile struct {
	Tokens []vaultToken `yaml:"tokens"`
}

type actionsCache struct {
	ID        int64     `json:"id"`
	Ref       string    `json:"ref"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

func TestGOATFlagPath(t *testing.T) {
	token := getEnvOrFile("GITHUB_TOKEN", e2eEnvPath)
	require.NotEmpty(t, token, "GITHUB_TOKEN required (set in .claude/e2e/.env)")

	kitchenURL := getEnvOrFile("KITCHEN_URL", e2eEnvPath)
	require.NotEmpty(t, kitchenURL, "KITCHEN_URL required")
	authToken := getEnvOrFile("AUTH_TOKEN", e2eEnvPath)
	require.NotEmpty(t, authToken, "AUTH_TOKEN required")

	root := findProjectRoot()
	require.NotEmpty(t, root, "could not find project root")

	sessionID := "e2e-goat"

	require.NoError(t, resetE2EWorkspace())
	require.NoError(t, waitForKitchenHealth(root, 90*time.Second))
	require.NoError(t, writeConfig(token, targetRepo))
	require.NoError(t, restartCounter(sessionID))

	tmux := newTmuxController(tmuxSessionName)

	waitForReconPhase(t, tmux)
	requireContent(t, tmux, "whooli", 15*time.Second, "Attack tree should show target org")
	requireContent(t, tmux, "xyz", 15*time.Second, "Attack tree should show target repo")

	vulnKey := "2"
	if capture := tmux.CaptureClean(); capture != "" {
		if key := findMenuVulnAll(capture, "issue body", "auto-labeler"); key != "" {
			vulnKey = key
		}
	}

	openDeployWizardFromMenu(t, tmux, vulnKey)
	completeIssueDeployWizard(t, tmux, 4)
	requireContent(t, tmux, "5m0s", 2*time.Second, "Dwell time should be 5m0s")
	require.NoError(t, tmux.SendKeys("Enter"))

	deployPhase := waitForAny(tmux, []string{"Phase:Waiting", "Phase:Post-Exploit"}, 30*time.Second)
	require.NotEmpty(t, deployPhase, "Phase should transition after deploy")

	issue := findDeployedIssue(t, 30*time.Second)
	require.NotNil(t, issue, "Should find deployed issue on "+targetRepo)
	t.Logf("Found issue #%d: %s", issue.Number, issue.URL)
	registerIssueFailureCleanup(t, issue.Number)

	if deployPhase == "Phase:Waiting" {
		require.True(t, waitForContent(tmux, "Phase:Post-Exploit", 5*time.Minute),
			"Brisket should connect and transition to Post-Exploit")
	}

	requireContent(t, tmux, "Agent:", 10*time.Second, "Should have active agent")
	waitForIssueState(t, issue.Number, "closed", 2*time.Minute)

	ensureShortcutFocus(t, tmux)
	require.NoError(t, tmux.SendKeys("r"))
	requireContent(t, tmux, "Phase:Recon", 10*time.Second, "Should return to Recon phase")

	runCounterCommand(t, tmux, "exploit comment")
	requireContent(t, tmux, "Step 1/3", 10*time.Second, "Comment foothold wizard should appear")
	completeIssueDeployWizard(t, tmux, 4)
	requireContent(t, tmux, "5m0s", 2*time.Second, "Comment foothold dwell time should be 5m0s")
	require.NoError(t, tmux.SendKeys("Enter"))

	deployPhase = waitForAny(tmux, []string{"Phase:Waiting", "Phase:Post-Exploit"}, 30*time.Second)
	require.NotEmpty(t, deployPhase, "Comment foothold should transition after deploy")

	appIssue := findDeployedIssue(t, 30*time.Second, issue.Number)
	require.NotNil(t, appIssue, "Should find second deployed issue on "+targetRepo)
	t.Logf("Found app issue #%d: %s", appIssue.Number, appIssue.URL)
	registerIssueFailureCleanup(t, appIssue.Number)

	if deployPhase == "Phase:Waiting" {
		require.True(t, waitForContent(tmux, "Phase:Post-Exploit", 5*time.Minute),
			"Second foothold should transition to Post-Exploit")
	}

	secondFootholdMarker := waitForAny(tmux, []string{
		".github/workflows/whooli-analyzer.yml",
		"GitHub App (WHOOLI_BOT_APP_PRIVATE_KEY)",
		"WHOOLI_BOT_APP_PRIVATE_KEY",
	}, 30*time.Second)
	require.NotEmpty(t, secondFootholdMarker, "Second foothold should land on whooli-analyzer")
	ensureLootFocus(t, tmux)
	requireContent(t, tmux, "GitHub App (WHOOLI_BOT_APP_PRIVATE_KEY)", 2*time.Minute, "Collected App key should land in the loot stash before export")
	require.NoError(t, tmux.SendKeys("e"))
	requireContent(t, tmux, "Exported", 10*time.Second, "App-key export should succeed")
	appKey := requireVaultAppKey(t, root)
	waitForIssueState(t, appIssue.Number, "closed", 2*time.Minute)
	ensureShortcutFocus(t, tmux)
	require.NoError(t, tmux.SendKeys("r"))
	requireContent(t, tmux, "Phase:Recon", 10*time.Second, "Should return to Recon phase for private repo exploitation")

	runCounterCommand(t, tmux, "set target repo:"+infraRepo)
	runCounterCommand(t, tmux, "status")
	requireContent(t, tmux, "Target: repo:"+infraRepo, 10*time.Second, "Target should switch to infrastructure repo")
	runCounterCommand(t, tmux, "pivot app "+appKey.PairedAppID)
	requireContent(t, tmux, "GitHub App pivot successful", 30*time.Second, "App pivot should succeed")
	requireContent(t, tmux, "Active token swapped", 30*time.Second, "App pivot should swap the active token")
	requireContent(t, tmux, benchmarkBotWorkflow, 60*time.Second, "Infrastructure analysis should surface the issue-comment writer workflow")

	infraWriterKey := waitForMenuVulnKey(t, tmux, 30*time.Second,
		[]string{"benchmark-bot", "review", "comment"},
		[]string{"benchmark-bot", benchmarkBotWorkflow},
	)
	openDeployWizardFromMenu(t, tmux, infraWriterKey)
	completeCommentDeployWizardWithCachePoison(t, tmux, 0, 4, deployWorkflow, "")
	requireContent(t, tmux, benchmarkBotWorkflow, 5*time.Second, "Writer workflow should be the benchmark bot workflow")
	requireContent(t, tmux, deployWorkflow, 5*time.Second, "Deploy workflow should be selectable as the cache poison victim")
	require.NoError(t, tmux.SendKeys("Enter"))

	requireContent(t, tmux, "Phase:Waiting", 30*time.Second, "Cache poison deployment should enter waiting phase")
	cacheActivity := waitForAny(tmux, []string{"Purged ", "No matching Actions caches", "Writer cache: armed"}, 2*time.Minute)
	require.NotEmpty(t, cacheActivity, "Cache poison deployment should report cache replacement activity or arm the writer cache")
	requireContent(t, tmux, "Writer cache: armed", 2*time.Minute, "Cache poison flow should arm the writer cache before the victim workflow runs")
	requireContent(t, tmux, "Victim callback: waiting", 5*time.Second, "Victim callback should still be pending before the victim workflow runs")
	armNextImplantWithDwell(t, tmux, deployWorkflow)
	require.NoError(t, tmux.SendKeys("Escape"))
	requireContent(t, tmux, "Phase:Recon", 10*time.Second, "Should return to Recon phase before triggering the victim workflow through Counter")

	runCounterCommand(t, tmux, "pivot github "+infraRepo)
	require.NotEmpty(t, waitForAny(tmux, []string{"Found ", "Token sees ", "No new repos discovered"}, 30*time.Second), "Dispatch pivot should produce output")

	runCounterCommand(t, tmux, "exploit "+infraRepo+" "+deployWorkflow+" workflow_dispatch")
	requireContent(t, tmux, "Step 1/3", 10*time.Second, "Dispatch exploit wizard should appear")
	completeDispatchDeployWizard(t, tmux, 0)
	require.NoError(t, tmux.SendKeys("Enter"))
	require.NotEmpty(t, waitForAny(tmux, []string{"workflow_dispatch triggered", "Phase:Waiting"}, 30*time.Second), "Counter should trigger the victim workflow through the dispatch exploit path")

	requireContent(t, tmux, "Phase:Post-Exploit", 8*time.Minute, "Victim callback should enter post-exploit mode after dwell is armed")
	runCounterCommand(t, tmux, "status")
	requireContent(t, tmux, "Agent:", 10*time.Second, "Status should show an active agent")

	runCounterCommand(t, tmux, "pivot gcp")
	cloudPivot := waitForAny(tmux, []string{
		"Cloud pivot to gcp succeeded",
		"OIDC pivot to gcp successful",
		"Cloud pivot: gcp via oidc",
		"pivot to gcp failed",
		"Cloud pivot to gcp failed",
	}, 90*time.Second)
	require.NotEmpty(t, cloudPivot, "Cloud pivot should produce output")
	require.NotEqual(t, "pivot to gcp failed", cloudPivot, "GCP pivot should succeed")
	require.NotEqual(t, "Cloud pivot to gcp failed", cloudPivot, "GCP pivot should succeed")

	verifyPantryHasCloudResources(t, kitchenURL, authToken)

	runCounterCommand(t, tmux, "cloud shell")
	cloudShellReady := waitForAny(tmux, []string{
		"SmokedMeat Cloud Shell",
		"[sm:gcp/",
	}, 30*time.Second)
	require.NotEmpty(t, cloudShellReady, "cloud shell banner or prompt must appear")

	require.NoError(t, tmux.TypeText("gsutil ls gs://"+flagBucket+"/"))
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	requireContent(t, tmux, "flag.txt", 30*time.Second, "Bucket listing should show flag.txt")

	require.NoError(t, tmux.TypeText("gsutil cat gs://"+flagBucket+"/flag.txt"))
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	require.True(t, waitForFlag(tmux, 30*time.Second), "flag content should appear in cloud shell output")

	flagContent := extractFlagContent(tmux.CaptureClean())
	require.NotEmpty(t, flagContent, "flag content should be extractable from cloud shell output")
	t.Logf("FLAG CAPTURED: %s", flagContent)

	require.NoError(t, tmux.TypeText("exit"))
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tmux.SendKeys("Enter"))
	waitForAny(tmux, []string{"❯", "Phase:Post-Exploit", "SmokedMeat Counter"}, 20*time.Second)
}

func requireVaultAppKey(t *testing.T, root string) vaultToken {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(root, e2eVault))
	require.NoError(t, err)

	var vault vaultFile
	require.NoError(t, yaml.Unmarshal(data, &vault))

	for _, token := range vault.Tokens {
		if token.Name == "WHOOLI_BOT_APP_PRIVATE_KEY" && token.Value != "" && token.PairedAppID != "" {
			return token
		}
	}

	t.Fatalf("vault did not contain a paired WHOOLI_BOT_APP_PRIVATE_KEY")
	return vaultToken{}
}

func matchingActionsCaches(caches []actionsCache, prefix, ref string) []actionsCache {
	matches := make([]actionsCache, 0, len(caches))
	for _, cache := range caches {
		if prefix != "" && !strings.HasPrefix(cache.Key, prefix) {
			continue
		}
		if ref != "" && cache.Ref != ref {
			continue
		}
		matches = append(matches, cache)
	}
	return matches
}

func kitchenRequest(t *testing.T, kitchenURL, authToken, method, path string, body any, out any, wantStatuses ...int) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, strings.TrimRight(kitchenURL, "/")+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := newInsecureHTTPClient(30 * time.Second).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	statusOK := false
	for _, want := range wantStatuses {
		if resp.StatusCode == want {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Fatalf("%s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		require.NoError(t, json.Unmarshal(respBody, out))
	}
}

func waitForFlag(tc *TmuxController, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if flagRe.MatchString(tc.CaptureClean()) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func extractFlagContent(capture string) string {
	return flagRe.FindString(capture)
}

func verifyPantryHasCloudResources(t *testing.T, kitchenURL, authToken string) {
	t.Helper()

	var graphData struct {
		Nodes []struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Label string `json:"label"`
			State string `json:"state"`
		} `json:"nodes"`
	}

	kitchenRequest(t, kitchenURL, authToken, http.MethodGet, "/graph/data", nil, &graphData, http.StatusOK)

	var cloudNodes []string
	for _, node := range graphData.Nodes {
		nodeType := strings.ToLower(node.Type)
		label := strings.ToLower(node.Label)
		if nodeType == "cloud" || nodeType == "token" ||
			strings.Contains(label, "oidc") || strings.Contains(label, "gcs_bucket") ||
			strings.Contains(label, "gcp") || strings.Contains(label, "deployer") {
			cloudNodes = append(cloudNodes, fmt.Sprintf("%s [%s] (%s)", node.Label, node.Type, node.State))
		}
	}

	assert.NotEmpty(t, cloudNodes, "Pantry graph should contain cloud-related nodes after the GCP pivot")
}
