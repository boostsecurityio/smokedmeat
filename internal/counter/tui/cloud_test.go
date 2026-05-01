// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func TestLookupCloudConfig_AWS(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("aws_oidc", "job:deploy", []string{"sts:AssumeRoleWithWebIdentity"})
	token.SetProperty("role_arn", "arn:aws:iam::123456789:role/deploy-role")
	_ = p.AddAsset(token)

	m := Model{pantry: p}
	config := m.lookupCloudConfig("aws")

	assert.Equal(t, "arn:aws:iam::123456789:role/deploy-role", config["role-arn"])
}

func TestLookupCloudConfig_GCP(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("gcp_oidc", "job:build", []string{"iam.serviceAccounts.getAccessToken"})
	token.SetProperty("workload_provider", "projects/123/locations/global/workloadIdentityPools/pool/providers/gh")
	token.SetProperty("service_account", "sa@project.iam.gserviceaccount.com")
	_ = p.AddAsset(token)

	m := Model{pantry: p}
	config := m.lookupCloudConfig("gcp")

	assert.Contains(t, config["workload-identity-provider"], "workloadIdentityPools")
	assert.Equal(t, "sa@project.iam.gserviceaccount.com", config["service-account"])
}

func TestLookupCloudConfig_GCPPrefersActiveJobToken(t *testing.T) {
	p := pantry.New()
	repo := pantry.NewRepository("whooli", "infrastructure-definitions", "github")
	require.NoError(t, p.AddAsset(repo))
	workflow := pantry.NewWorkflow(repo.ID, ".github/workflows/deploy.yml")
	require.NoError(t, p.AddAsset(workflow))
	require.NoError(t, p.AddRelationship(repo.ID, workflow.ID, pantry.Contains()))
	job := pantry.NewJob(workflow.ID, "sync")
	require.NoError(t, p.AddAsset(job))
	require.NoError(t, p.AddRelationship(workflow.ID, job.ID, pantry.Contains()))

	cloud := pantry.NewCloud("gcp", "oidc_trust", "deploy@whooli.iam.gserviceaccount.com")
	require.NoError(t, p.AddAsset(cloud))
	require.NoError(t, p.AddRelationship(job.ID, cloud.ID, pantry.Exposes("sync", "")))
	targetToken := pantry.NewToken("gcp_oidc", cloud.ID, []string{"iam.serviceAccounts.getAccessToken"})
	targetToken.SetProperty("workload_provider", "projects/123/locations/global/workloadIdentityPools/pool/providers/deploy")
	targetToken.SetProperty("service_account", "deploy@whooli.iam.gserviceaccount.com")
	require.NoError(t, p.AddAsset(targetToken))
	require.NoError(t, p.AddRelationship(cloud.ID, targetToken.ID, pantry.Contains()))

	otherToken := pantry.NewToken("gcp_oidc", "gcp:oidc_trust:bootstrap@whooli.iam.gserviceaccount.com", []string{"iam.serviceAccounts.getAccessToken"})
	otherToken.SetProperty("workload_provider", "projects/999/locations/global/workloadIdentityPools/pool/providers/bootstrap")
	otherToken.SetProperty("service_account", "bootstrap@whooli.iam.gserviceaccount.com")
	require.NoError(t, p.AddAsset(otherToken))

	m := Model{
		pantry: p,
		activeAgent: &AgentState{
			ID:       "agt-1",
			Repo:     "whooli/infrastructure-definitions",
			Workflow: ".github/workflows/deploy.yml",
			Job:      "sync",
		},
	}

	config := m.lookupCloudConfig("gcp")

	assert.Equal(t, "projects/123/locations/global/workloadIdentityPools/pool/providers/deploy", config["workload-identity-provider"])
	assert.Equal(t, "deploy@whooli.iam.gserviceaccount.com", config["service-account"])
}

func TestLookupCloudConfig_Azure(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("azure_oidc", "job:deploy", []string{"Application.Read.All"})
	token.SetProperty("tenant_id", "tenant-uuid")
	token.SetProperty("client_id", "client-uuid")
	_ = p.AddAsset(token)

	m := Model{pantry: p}
	config := m.lookupCloudConfig("azure")

	assert.Equal(t, "tenant-uuid", config["tenant-id"])
	assert.Equal(t, "client-uuid", config["client-id"])
}

func TestLookupCloudConfig_NoPantry(t *testing.T) {
	m := Model{}
	config := m.lookupCloudConfig("aws")
	assert.Empty(t, config)
}

func TestLookupCloudConfig_GCPFallsBackToRunnerVarsWithoutPantry(t *testing.T) {
	m := Model{
		runnerVars: map[string]string{
			"GCP_PROJECT_ID": "whooli",
		},
	}

	config := m.lookupCloudConfig("gcp")

	assert.Equal(t, "whooli", config["project-id"])
}

func TestLookupCloudConfig_ResolvesSecretRefs(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("aws_oidc", "job:deploy", []string{"sts:AssumeRoleWithWebIdentity"})
	token.SetProperty("role_arn", "${{ secrets.AWS_ROLE }}")
	_ = p.AddAsset(token)

	m := Model{
		pantry: p,
		lootStash: []CollectedSecret{
			{Name: "AWS_ROLE", Value: "arn:aws:iam::999:role/stolen"},
		},
	}
	config := m.lookupCloudConfig("aws")

	assert.Equal(t, "arn:aws:iam::999:role/stolen", config["role-arn"])
}

func TestLookupCloudConfig_UnresolvableSecretRefPassthrough(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("aws_oidc", "job:deploy", []string{"sts:AssumeRoleWithWebIdentity"})
	token.SetProperty("role_arn", "${{ secrets.MISSING }}")
	_ = p.AddAsset(token)

	m := Model{pantry: p}
	config := m.lookupCloudConfig("aws")

	assert.Equal(t, "${{ secrets.MISSING }}", config["role-arn"])
}

func TestLookupCloudConfig_ResolvesVarRefs(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("gcp_oidc", "job:deploy", []string{"iam.serviceAccounts.getAccessToken"})
	token.SetProperty("workload_provider", "projects/${{ vars.GCP_PROJECT_NUMBER }}/locations/global/workloadIdentityPools/github-pool/providers/github-provider")
	token.SetProperty("service_account", "github-deployer@${{ vars.GCP_PROJECT_ID }}.iam.gserviceaccount.com")
	_ = p.AddAsset(token)

	m := Model{
		pantry: p,
		runnerVars: map[string]string{
			"GCP_PROJECT_NUMBER": "123456789",
			"GCP_PROJECT_ID":     "whooli",
		},
	}
	config := m.lookupCloudConfig("gcp")

	assert.Equal(t, "projects/123456789/locations/global/workloadIdentityPools/github-pool/providers/github-provider", config["workload-identity-provider"])
	assert.Equal(t, "github-deployer@whooli.iam.gserviceaccount.com", config["service-account"])
}

func TestLookupCloudConfig_UnresolvableVarRefPassthrough(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("gcp_oidc", "job:deploy", []string{"iam.serviceAccounts.getAccessToken"})
	token.SetProperty("workload_provider", "projects/${{ vars.MISSING }}/locations/global/pools/p/providers/gh")
	_ = p.AddAsset(token)

	m := Model{pantry: p}
	config := m.lookupCloudConfig("gcp")

	assert.Equal(t, "projects/${{ vars.MISSING }}/locations/global/pools/p/providers/gh", config["workload-identity-provider"])
}

func TestLookupCloudConfig_MixedSecretAndVarRefs(t *testing.T) {
	p := pantry.New()
	token := pantry.NewToken("gcp_oidc", "job:deploy", []string{"iam.serviceAccounts.getAccessToken"})
	token.SetProperty("workload_provider", "projects/${{ vars.GCP_PROJECT_NUMBER }}/locations/global/pools/${{ secrets.POOL_NAME }}/providers/gh")
	_ = p.AddAsset(token)

	m := Model{
		pantry: p,
		runnerVars: map[string]string{
			"GCP_PROJECT_NUMBER": "123456789",
		},
		lootStash: []CollectedSecret{
			{Name: "POOL_NAME", Value: "my-pool"},
		},
	}
	config := m.lookupCloudConfig("gcp")

	assert.Equal(t, "projects/123456789/locations/global/pools/my-pool/providers/gh", config["workload-identity-provider"])
}

func TestHandlePivotResult_Success(t *testing.T) {
	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
	}

	result := &models.PivotResult{
		Success:  true,
		Provider: "aws",
		Method:   "oidc",
		Credentials: map[string]string{
			"AssumedRole": "arn:aws:iam::123:role/test",
		},
		Resources: []models.CloudResource{
			{Type: "s3_bucket", Name: "bucket-1"},
			{Type: "identity", ID: "arn:aws:sts::123:assumed-role"},
		},
		Duration: 100.0,
	}

	m.handlePivotResult(result)

	assert.NotNil(t, m.cloudState)
	assert.Equal(t, "aws", m.cloudState.Provider)
	assert.Equal(t, "oidc", m.cloudState.Method)
	assert.Equal(t, 2, m.cloudState.ResourceCount)
}

func TestHandlePivotResult_Failure(t *testing.T) {
	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
	}

	result := &models.PivotResult{
		Success:  false,
		Provider: "gcp",
		Errors:   []string{"token exchange failed"},
	}

	m.handlePivotResult(result)

	assert.Nil(t, m.cloudState)
}

func TestHandlePivotResult_StoresRawCredentials(t *testing.T) {
	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
	}

	result := &models.PivotResult{
		Success:  true,
		Provider: "aws",
		Method:   "oidc",
		Credentials: map[string]string{
			"AWS_ACCESS_KEY_ID":     "AKIA",
			"AWS_SECRET_ACCESS_KEY": "XXXX•••YYYY",
		},
		RawCredentials: map[string]string{
			"AWS_ACCESS_KEY_ID":     "AKIA",
			"AWS_SECRET_ACCESS_KEY": "realsecret",
			"Expiration":            "2026-02-23T23:00:00Z",
		},
		Duration: 100,
	}

	m.handlePivotResult(result)

	require.NotNil(t, m.cloudState)
	assert.Equal(t, "realsecret", m.cloudState.RawCredentials["AWS_SECRET_ACCESS_KEY"])
	assert.False(t, m.cloudState.Expiry.IsZero(), "should parse expiry from RawCredentials")

	found := false
	for _, o := range m.output {
		if strings.Contains(o.Content, "cloud shell") {
			found = true
			break
		}
	}
	assert.True(t, found, "should hint about cloud shell when raw creds available")
}

func TestHandlePivotResult_GCPDerivesProject(t *testing.T) {
	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
		runnerVars: map[string]string{
			"GCP_PROJECT_ID": "whooli",
		},
	}

	result := &models.PivotResult{
		Success:  true,
		Provider: "gcp",
		Method:   "oidc",
		RawCredentials: map[string]string{
			"ACCESS_TOKEN":    "ya29.token",
			"SERVICE_ACCOUNT": "runner@other-project.iam.gserviceaccount.com",
		},
		Duration: 100,
	}

	m.handlePivotResult(result)

	require.NotNil(t, m.cloudState)
	assert.Equal(t, "whooli", m.cloudState.RawCredentials["PROJECT"])
}

func TestExecuteCloudCommand_NoCloudState(t *testing.T) {
	m := Model{output: []OutputLine{}}
	result, _ := m.executeCloudCommand(nil)
	rm := result.(Model)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "No active cloud session")
}

func TestExecuteCloudCommand_NoAgent(t *testing.T) {
	m := Model{
		output:     []OutputLine{},
		cloudState: &CloudState{Provider: "aws"},
	}
	result, _ := m.executeCloudCommand([]string{"buckets"})
	rm := result.(Model)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "No active agent for cloud queries")
}

func TestExecuteCloudCommand_Status(t *testing.T) {
	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
		cloudState: &CloudState{
			Provider:      "aws",
			Method:        "oidc",
			PivotTime:     time.Now(),
			ResourceCount: 5,
			Credentials:   map[string]string{"AssumedRole": "test"},
		},
		activeAgent: &AgentState{ID: "test-agent"},
	}
	result, _ := m.executeCloudCommand(nil)
	rm := result.(Model)
	found := false
	for _, e := range rm.activityLog.Entries() {
		if e.Message == "Cloud Session: aws (via oidc)" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should show cloud session status")
}

func TestExecuteCloudOIDCPivot_PassesProvider(t *testing.T) {
	for _, provider := range []string{"aws", "gcp", "azure"} {
		t.Run(provider, func(t *testing.T) {
			m := Model{output: []OutputLine{}}
			msg := m.executeCloudOIDCPivot(provider)
			result, ok := msg.(PivotResultMsg)
			require.True(t, ok, "should return PivotResultMsg when no agent")
			assert.Equal(t, provider, result.Provider, "provider must be passed through")
		})
	}
}

func TestPivotCommand_CloudOIDC_PassesProvider(t *testing.T) {
	m := Model{output: []OutputLine{}}
	cmd := m.executePivot(PivotTypeCloudOIDC, "aws")
	msg := cmd()
	result, ok := msg.(PivotResultMsg)
	require.True(t, ok)
	assert.Equal(t, "aws", result.Provider, "executePivot must pass provider to executeCloudOIDCPivot")
}

func TestImportCloudResourcesToPantry(t *testing.T) {
	m := Model{}
	result := &models.PivotResult{
		Provider: "aws",
		Resources: []models.CloudResource{
			{Type: "s3_bucket", Name: "my-bucket", Region: "us-east-1"},
			{Type: "ecr_repository", ID: "arn:aws:ecr:us-east-1:123:repo/app", Name: "app"},
		},
	}

	m.importCloudResourcesToPantry(result)

	assert.NotNil(t, m.pantry)
	clouds := m.pantry.GetAssetsByType(pantry.AssetCloud)
	assert.Len(t, clouds, 2)
}

func TestExecuteCloudShell_NoCloudState(t *testing.T) {
	m := Model{output: []OutputLine{}}
	result, cmd := m.executeCloudShell()
	rm := result.(Model)
	assert.Nil(t, cmd)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "No active cloud session")
}

func TestExecuteCloudShell_NoRawCredentials(t *testing.T) {
	m := Model{
		output: []OutputLine{},
		cloudState: &CloudState{
			Provider:    "aws",
			Credentials: map[string]string{"AssumedRole": "test"},
		},
	}
	result, cmd := m.executeCloudShell()
	rm := result.(Model)
	assert.Nil(t, cmd)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "no usable credentials")
}

func TestExecuteCloudShell_NoAgentNotRequired(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	dockerHasImageFn = func(string) bool { return true }
	embeddedCloudShellAvailableFn = func() bool { return false }
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
	})

	m := Model{
		output: []OutputLine{},
		cloudState: &CloudState{
			Provider: "aws",
			RawCredentials: map[string]string{
				"AWS_ACCESS_KEY_ID":     "AKIA",
				"AWS_SECRET_ACCESS_KEY": "secret",
				"AWS_SESSION_TOKEN":     "token",
			},
		},
	}
	_, cmd := m.executeCloudShell()
	assert.NotNil(t, cmd, "cloud shell should not require activeAgent")
	if m.cloudState.TempDir != "" {
		os.RemoveAll(m.cloudState.TempDir)
	}
}

func TestExecuteCloudShell_RequiresDockerImage(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	oldVersion := buildinfo.Version
	dockerHasImageFn = func(string) bool { return false }
	embeddedCloudShellAvailableFn = func() bool { return false }
	buildinfo.Version = "dev"
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
		buildinfo.Version = oldVersion
	})

	m := Model{
		output: []OutputLine{},
		cloudState: &CloudState{
			Provider: "aws",
			RawCredentials: map[string]string{
				"AWS_ACCESS_KEY_ID":     "AKIA",
				"AWS_SECRET_ACCESS_KEY": "secret",
			},
		},
	}

	result, cmd := m.executeCloudShell()
	rm := result.(Model)

	assert.Nil(t, cmd)
	assert.Empty(t, rm.cloudState.TempDir)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "requires the Docker image")
}

func TestCloudShellImageRef_DevUsesLatest(t *testing.T) {
	oldVersion := buildinfo.Version
	buildinfo.Version = "dev"
	t.Cleanup(func() {
		buildinfo.Version = oldVersion
	})

	t.Setenv(cloudShellImageOverrideEnv, "")

	assert.Equal(t, "smokedmeat-cloud-shell:latest", cloudShellImageRef())
	assert.True(t, cloudShellNeedsLocalImage())
}

func TestCloudShellImageRef_ReleaseUsesVersionTag(t *testing.T) {
	oldVersion := buildinfo.Version
	buildinfo.Version = "1.2.3"
	t.Cleanup(func() {
		buildinfo.Version = oldVersion
	})

	t.Setenv(cloudShellImageOverrideEnv, "")

	assert.Equal(t, "ghcr.io/boostsecurityio/smokedmeat-cloud-shell:1.2.3", cloudShellImageRef())
	assert.False(t, cloudShellNeedsLocalImage())
}

func TestCloudShellImageRef_OverrideWins(t *testing.T) {
	oldVersion := buildinfo.Version
	buildinfo.Version = "1.2.3"
	t.Setenv(cloudShellImageOverrideEnv, "registry.example.com/smokedmeat-cloud-shell:test")
	t.Cleanup(func() {
		buildinfo.Version = oldVersion
	})

	assert.Equal(t, "registry.example.com/smokedmeat-cloud-shell:test", cloudShellImageRef())
	assert.False(t, cloudShellNeedsLocalImage())
}

func TestExecuteCloudShell_ReleasePullsMatchingImage(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	oldVersion := buildinfo.Version
	dockerHasImageFn = func(string) bool { return false }
	embeddedCloudShellAvailableFn = func() bool { return false }
	buildinfo.Version = "1.2.3"
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
		buildinfo.Version = oldVersion
	})

	m := Model{
		output: []OutputLine{},
		cloudState: &CloudState{
			Provider: "aws",
			RawCredentials: map[string]string{
				"AWS_ACCESS_KEY_ID":     "AKIA",
				"AWS_SECRET_ACCESS_KEY": "secret",
			},
		},
	}

	result, cmd := m.executeCloudShell()
	rm := result.(Model)

	require.NotNil(t, cmd)
	require.NotNil(t, rm.cloudState)
	assert.NotEmpty(t, rm.cloudState.TempDir)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "Entering aws cloud shell")
}

func TestExecuteCloudShell_UsesEmbeddedEntrypointWhenAvailable(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	dockerHasImageFn = func(string) bool { return false }
	embeddedCloudShellAvailableFn = func() bool { return true }
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
	})

	m := Model{
		output: []OutputLine{},
		cloudState: &CloudState{
			Provider: "gcp",
			Method:   "oidc",
			RawCredentials: map[string]string{
				"ACCESS_TOKEN": "ya29.token",
				"PROJECT":      "whooli",
			},
		},
	}

	result, cmd := m.executeCloudShell()
	rm := result.(Model)

	assert.NotNil(t, cmd)
	assert.NotEmpty(t, rm.cloudState.TempDir)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "Entering gcp cloud shell")
}

func TestCloudShellExitRestoresInputFocus(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.focus = FocusSessions
	m.paneFocus = PaneFocusActivity

	result, _ := m.Update(CloudShellExitMsg{})
	rm := result.(Model)

	assert.Equal(t, FocusInput, rm.focus)
	assert.True(t, rm.input.Focused())
	assert.Equal(t, -1, rm.historyIndex)
	assert.Empty(t, rm.completionHint)
	assert.Contains(t, rm.output[len(rm.output)-1].Content, "Session preserved")
}

func TestSetupLocalCloudShell_AWS(t *testing.T) {
	tmpDir := t.TempDir()
	cs := &CloudState{
		Provider: "aws",
		Method:   "oidc",
		TempDir:  tmpDir,
		RawCredentials: map[string]string{
			"AWS_ACCESS_KEY_ID":     "ASIAEXAMPLE",
			"AWS_SECRET_ACCESS_KEY": "secretkey",
			"AWS_SESSION_TOKEN":     "sessiontoken",
			"AWS_DEFAULT_REGION":    "us-east-1",
		},
	}

	require.NoError(t, setupLocalCloudShell(cs))

	bashrc, err := os.ReadFile(filepath.Join(tmpDir, ".bashrc"))
	require.NoError(t, err)
	content := string(bashrc)

	assert.Contains(t, content, "export AWS_ACCESS_KEY_ID='ASIAEXAMPLE'")
	assert.Contains(t, content, "export AWS_SECRET_ACCESS_KEY='secretkey'")
	assert.Contains(t, content, "export AWS_SESSION_TOKEN='sessiontoken'")
	assert.Contains(t, content, "export AWS_DEFAULT_REGION='us-east-1'")
	assert.Contains(t, content, "[sm:aws/oidc]")
}

func TestSetupLocalCloudShell_GCP(t *testing.T) {
	tmpDir := t.TempDir()
	cs := &CloudState{
		Provider: "gcp",
		Method:   "oidc",
		TempDir:  tmpDir,
		RawCredentials: map[string]string{
			"ACCESS_TOKEN":    "ya29.token",
			"PROJECT":         "my-project",
			"SERVICE_ACCOUNT": "sa@my-project.iam.gserviceaccount.com",
		},
	}

	require.NoError(t, setupLocalCloudShell(cs))

	bashrc, err := os.ReadFile(filepath.Join(tmpDir, ".bashrc"))
	require.NoError(t, err)
	content := string(bashrc)

	assert.Contains(t, content, "export CLOUDSDK_AUTH_ACCESS_TOKEN='ya29.token'")
	assert.Contains(t, content, "export GOOGLE_OAUTH_ACCESS_TOKEN='ya29.token'")
	assert.Contains(t, content, "export CLOUDSDK_CORE_PROJECT='my-project'")
	assert.Contains(t, content, "export GCLOUD_PROJECT='my-project'")
	assert.Contains(t, content, "export GOOGLE_CLOUD_PROJECT='my-project'")
	assert.Contains(t, content, "export SM_GCP_ACCOUNT='sa@my-project.iam.gserviceaccount.com'")
	assert.Contains(t, content, "[sm:gcp/oidc]")
	assert.NotContains(t, content, "gsutil()")
	assert.NotContains(t, content, "_init_creds.py")
}

func TestSetupLocalCloudShell_Azure(t *testing.T) {
	tmpDir := t.TempDir()
	cs := &CloudState{
		Provider: "azure",
		Method:   "oidc",
		TempDir:  tmpDir,
		RawCredentials: map[string]string{
			"ACCESS_TOKEN":    "eyJ.azure.token",
			"TENANT_ID":       "tenant-uuid",
			"SUBSCRIPTION_ID": "sub-uuid",
		},
	}

	require.NoError(t, setupLocalCloudShell(cs))

	bashrc, err := os.ReadFile(filepath.Join(tmpDir, ".bashrc"))
	require.NoError(t, err)
	content := string(bashrc)

	assert.Contains(t, content, "export ARM_ACCESS_TOKEN='eyJ.azure.token'")
	assert.Contains(t, content, "export ARM_TENANT_ID='tenant-uuid'")
	assert.Contains(t, content, "export ARM_SUBSCRIPTION_ID='sub-uuid'")
	assert.Contains(t, content, "[sm:azure/oidc]")
}

func TestSetupLocalK8sShell(t *testing.T) {
	tmpDir := t.TempDir()
	cs := &CloudState{
		Provider: "k8s",
		Method:   "oidc",
		TempDir:  tmpDir,
		RawCredentials: map[string]string{
			"BEARER_TOKEN": "eyJ.k8s.token",
			"SERVER":       "https://10.0.0.1:6443",
		},
	}

	require.NoError(t, setupLocalCloudShell(cs))

	bashrc, err := os.ReadFile(filepath.Join(tmpDir, ".bashrc"))
	require.NoError(t, err)
	assert.Contains(t, string(bashrc), "export KUBECONFIG=")

	kubeconfigPath := filepath.Join(tmpDir, "kube", "config")
	kubeconfigData, err := os.ReadFile(kubeconfigPath)
	require.NoError(t, err)

	var kc map[string]interface{}
	require.NoError(t, json.Unmarshal(kubeconfigData, &kc))
	assert.Equal(t, "sm-context", kc["current-context"])

	clusters := kc["clusters"].([]interface{})
	cluster := clusters[0].(map[string]interface{})["cluster"].(map[string]interface{})
	assert.Equal(t, "https://10.0.0.1:6443", cluster["server"])
}

func TestSetupLocalK8sShell_NoAbsolutePaths(t *testing.T) {
	tmpDir := t.TempDir()
	cs := &CloudState{
		Provider: "k8s",
		Method:   "oidc",
		TempDir:  tmpDir,
		RawCredentials: map[string]string{
			"BEARER_TOKEN": "tok",
			"SERVER":       "https://10.0.0.1:6443",
		},
	}

	require.NoError(t, setupLocalCloudShell(cs))

	bashrc, err := os.ReadFile(filepath.Join(tmpDir, ".bashrc"))
	require.NoError(t, err)
	assert.Contains(t, string(bashrc), `KUBECONFIG='$HOME/kube/config'`)
	assert.NotContains(t, string(bashrc), tmpDir+"/kube")
}

func TestDockerRunUserArgs_NumericUIDGID(t *testing.T) {
	oldCurrentUser := currentUserFn
	currentUserFn = func() (*user.User, error) {
		return &user.User{Uid: "501", Gid: "20"}, nil
	}
	t.Cleanup(func() {
		currentUserFn = oldCurrentUser
	})

	if runtime.GOOS == "windows" {
		assert.Nil(t, dockerRunUserArgs())
		return
	}

	assert.Equal(t, []string{"--user", "501:20"}, dockerRunUserArgs())
}

func TestDockerRunUserArgs_NonNumericUIDGID(t *testing.T) {
	oldCurrentUser := currentUserFn
	currentUserFn = func() (*user.User, error) {
		return &user.User{Uid: "sid-user", Gid: "sid-group"}, nil
	}
	t.Cleanup(func() {
		currentUserFn = oldCurrentUser
	})

	assert.Nil(t, dockerRunUserArgs())
}

func TestDockerBindMountArgs_UnixPath(t *testing.T) {
	assert.Equal(t,
		[]string{"--mount", "type=bind,source=/tmp/smokedmeat shell,target=/shell"},
		dockerBindMountArgs("/tmp/smokedmeat shell", "/shell"),
	)
}

func TestDockerBindMountArgs_WindowsPath(t *testing.T) {
	assert.Equal(t,
		[]string{"--mount", `type=bind,source=C:\Users\operator\AppData\Local\Temp\smokedmeat,target=/shell`},
		dockerBindMountArgs(`C:\Users\operator\AppData\Local\Temp\smokedmeat`, "/shell"),
	)
}

func TestCloudShellReEntry(t *testing.T) {
	oldDockerHasImage := dockerHasImageFn
	oldEmbeddedAvailable := embeddedCloudShellAvailableFn
	dockerHasImageFn = func(string) bool { return true }
	embeddedCloudShellAvailableFn = func() bool { return false }
	t.Cleanup(func() {
		dockerHasImageFn = oldDockerHasImage
		embeddedCloudShellAvailableFn = oldEmbeddedAvailable
	})

	tmpDir := t.TempDir()

	cs := &CloudState{
		Provider:  "aws",
		Method:    "oidc",
		PivotTime: time.Now().Add(-5 * time.Minute),
		TempDir:   tmpDir,
		RawCredentials: map[string]string{
			"AWS_ACCESS_KEY_ID":     "AKIA",
			"AWS_SECRET_ACCESS_KEY": "secret",
		},
	}

	m := Model{output: []OutputLine{}, cloudState: cs}
	result, cmd := m.executeCloudShell()
	rm := result.(Model)

	assert.NotNil(t, cmd, "re-entry should produce a shell command")
	assert.Equal(t, tmpDir, rm.cloudState.TempDir, "should reuse existing temp dir")

	found := false
	for _, o := range rm.output {
		if strings.Contains(o.Content, "Resuming") {
			found = true
			break
		}
	}
	assert.True(t, found, "should print resuming message")
}

func TestCloudShellSessionReplace(t *testing.T) {
	oldDir := t.TempDir()
	marker := filepath.Join(oldDir, "marker")
	os.WriteFile(marker, []byte("old"), 0o600)

	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
		cloudState: &CloudState{
			Provider: "gcp",
			TempDir:  oldDir,
		},
	}

	result := &models.PivotResult{
		Success:        true,
		Provider:       "aws",
		Method:         "oidc",
		RawCredentials: map[string]string{"AWS_ACCESS_KEY_ID": "new"},
		Duration:       50,
	}

	m.handlePivotResult(result)

	assert.Equal(t, "aws", m.cloudState.Provider)
	assert.Empty(t, m.cloudState.TempDir, "new session should not inherit old temp dir")

	found := false
	for _, o := range m.output {
		if strings.Contains(o.Content, "Replacing previous") {
			found = true
			break
		}
	}
	assert.True(t, found, "should warn about replacing session")
}

func TestCloudExportUsesRawCreds(t *testing.T) {
	m := Model{
		activityLog: NewActivityLog(),
		cloudState: &CloudState{
			Provider: "aws",
			Credentials: map[string]string{
				"AWS_SECRET_ACCESS_KEY": "XXXX•••YYYY",
			},
			RawCredentials: map[string]string{
				"AWS_ACCESS_KEY_ID":     "ASIAEXAMPLE",
				"AWS_SECRET_ACCESS_KEY": "realsecretkey",
				"AWS_SESSION_TOKEN":     "realtoken",
			},
		},
	}

	m.showCloudExport()

	var exported []string
	for _, e := range m.activityLog.Entries() {
		if strings.HasPrefix(e.Message, "export ") {
			exported = append(exported, e.Message)
		}
	}

	found := false
	for _, line := range exported {
		if strings.Contains(line, "realsecretkey") {
			found = true
		}
		assert.NotContains(t, line, "•••", "export should use raw creds, not redacted")
	}
	assert.True(t, found, "should export the real secret key from RawCredentials")
}

func TestCleanupCloudSession(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "creds")
	os.WriteFile(testFile, []byte("secret"), 0o600)

	m := Model{
		cloudState: &CloudState{
			Provider: "aws",
			TempDir:  tmpDir,
		},
	}

	m.cleanupCloudSession()
	assert.Empty(t, m.cloudState.TempDir)

	_, err := os.Stat(testFile)
	assert.True(t, os.IsNotExist(err), "temp dir contents should be cleaned up")
}

func TestShellEscape(t *testing.T) {
	assert.Equal(t, "hello", shellEscape("hello"))
	assert.Equal(t, "it'\"'\"'s", shellEscape("it's"))
	assert.Equal(t, "no'\"'\"'quotes'\"'\"'here", shellEscape("no'quotes'here"))
}

func TestSmokedmeatDir_Default(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", "")
	dir := smokedmeatDir()
	assert.Contains(t, dir, ".smokedmeat")
}

func TestSmokedmeatDir_EnvOverride(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", "/custom/config")
	assert.Equal(t, "/custom/config", smokedmeatDir())
}

func TestCloudShellEnv_AWS(t *testing.T) {
	cs := &CloudState{
		Provider: "aws",
		Method:   "oidc",
		RawCredentials: map[string]string{
			"AWS_ACCESS_KEY_ID":     "AKIA",
			"AWS_SECRET_ACCESS_KEY": "secret",
			"AWS_SESSION_TOKEN":     "token",
			"AWS_DEFAULT_REGION":    "us-east-1",
		},
	}
	env := cloudShellEnv(cs, "/shell", "/shared")
	assert.Contains(t, env, "HOME=/shell")
	assert.Contains(t, env, "SM_SHARED=/shared")
	assert.Contains(t, env, "SM_PROVIDER=aws")
	assert.Contains(t, env, "SM_METHOD=oidc")
	assert.Contains(t, env, "AWS_ACCESS_KEY_ID=AKIA")
	assert.Contains(t, env, "AWS_DEFAULT_REGION=us-east-1")
}

func TestCloudShellEnv_GCP(t *testing.T) {
	cs := &CloudState{
		Provider: "gcp",
		Method:   "oidc",
		RawCredentials: map[string]string{
			"ACCESS_TOKEN":    "ya29.tok",
			"PROJECT":         "my-proj",
			"SERVICE_ACCOUNT": "sa@proj.iam.gserviceaccount.com",
		},
	}
	env := cloudShellEnv(cs, "/shell", "/shared")
	assert.Contains(t, env, "SM_PROVIDER=gcp")
	assert.Contains(t, env, "CLOUDSDK_AUTH_ACCESS_TOKEN=ya29.tok")
	assert.Contains(t, env, "CLOUDSDK_CORE_PROJECT=my-proj")
	assert.Contains(t, env, "GCLOUD_PROJECT=my-proj")
	assert.Contains(t, env, "GOOGLE_CLOUD_PROJECT=my-proj")
	assert.Contains(t, env, "SM_GCP_ACCOUNT=sa@proj.iam.gserviceaccount.com")
	assert.Contains(t, env, "CLOUDSDK_CONFIG=/shell/gcloud")
	assert.Contains(t, env, "BOTO_CONFIG=/shell/.boto")
}

func TestCloudShellEnv_Azure(t *testing.T) {
	cs := &CloudState{
		Provider: "azure",
		Method:   "oidc",
		RawCredentials: map[string]string{
			"ACCESS_TOKEN":    "eyJ.tok",
			"TENANT_ID":       "tid",
			"SUBSCRIPTION_ID": "sid",
		},
	}
	env := cloudShellEnv(cs, "/shell", "/shared")
	assert.Contains(t, env, "SM_PROVIDER=azure")
	assert.Contains(t, env, "ARM_ACCESS_TOKEN=eyJ.tok")
	assert.Contains(t, env, "ARM_TENANT_ID=tid")
	assert.Contains(t, env, "ARM_SUBSCRIPTION_ID=sid")
}

func TestCloudShellEnv_Expiry(t *testing.T) {
	cs := &CloudState{
		Provider: "aws",
		Expiry:   time.Now().Add(30 * time.Minute),
	}
	env := cloudShellEnv(cs, "/shell", "/shared")
	found := false
	for _, a := range env {
		if strings.HasPrefix(a, "SM_EXPIRY=") {
			found = true
			assert.NotContains(t, a, "EXPIRED")
		}
	}
	assert.True(t, found, "should include SM_EXPIRY for non-expired creds")
}

func TestLocalEnvVars_Generic(t *testing.T) {
	cs := &CloudState{
		Provider: "custom",
		RawCredentials: map[string]string{
			"TOKEN":      "abc",
			"Expiration": "2026-01-01",
		},
	}
	env := localEnvVars(cs)
	assert.Equal(t, "abc", env["TOKEN"])
	assert.NotContains(t, env, "Expiration")
}

func TestGCPProjectFromCreds_FallsBackToServiceAccount(t *testing.T) {
	project := gcpProjectFromCreds(map[string]string{
		"SERVICE_ACCOUNT": "builder@whooli.iam.gserviceaccount.com",
	})

	assert.Equal(t, "whooli", project)
}

func TestHandleColeslaw_CloudQueryDoesNotOverwriteCloudState(t *testing.T) {
	queryResult := &models.CloudQueryResult{
		Provider:  "gcp",
		QueryType: "buckets",
		Success:   true,
		Resources: []models.CloudResource{
			{Type: "bucket", Name: "loot-bucket"},
		},
	}
	stdout, err := queryResult.Marshal()
	require.NoError(t, err)

	coleslaw := models.NewColeslaw("order-12345678", "session-12345678", "agent-12345678")
	coleslaw.SetOutput(stdout, nil, 0)

	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
		cloudState: &CloudState{
			Provider: "gcp",
			Method:   "oidc",
			RawCredentials: map[string]string{
				"ACCESS_TOKEN": "ya29.real-token",
			},
		},
	}

	result, _ := m.handleColeslaw(ColeslawMsg{Coleslaw: coleslaw})
	rm := result.(Model)

	require.NotNil(t, rm.cloudState)
	assert.Equal(t, "oidc", rm.cloudState.Method)
	assert.Equal(t, "ya29.real-token", rm.cloudState.RawCredentials["ACCESS_TOKEN"])

	found := false
	for _, entry := range rm.activityLog.Entries() {
		if strings.Contains(entry.Message, "Cloud query: gcp/buckets") {
			found = true
			break
		}
	}
	assert.True(t, found, "cloud query result should be handled as a query, not a pivot")
}

func TestHandleCloudQueryResult_CondensesMultilineErrors(t *testing.T) {
	m := Model{
		output:      []OutputLine{},
		activityLog: NewActivityLog(),
	}

	m.handleCloudQueryResult(&models.CloudQueryResult{
		Provider:  "gcp",
		QueryType: "identity",
		Success:   false,
		Error: "GCP project info returned 403: {\n" +
			`  "error": {` + "\n" +
			`    "code": 403,` + "\n" +
			`    "message": "permission denied"` + "\n" +
			`  }` + "\n" +
			`}`,
	})

	lastOutput := m.output[len(m.output)-1].Content
	assert.NotContains(t, lastOutput, "\n")
	assert.Contains(t, lastOutput, "cloud identity failed:")
	assert.Contains(t, lastOutput, "permission denied")

	entries := m.activityLog.Entries()
	lastEntry := entries[len(entries)-1].Message
	assert.NotContains(t, lastEntry, "\n")
}

func TestCloudCompletionsExcludeRemovedCommands(t *testing.T) {
	m := Model{
		phase: PhasePostExploit,
		cloudState: &CloudState{
			Provider: "gcp",
		},
	}

	completions := m.getCompletions("cloud ")

	assert.Contains(t, completions, "cloud status")
	assert.Contains(t, completions, "cloud shell")
	assert.Contains(t, completions, "cloud export")
	assert.Contains(t, completions, "cloud identity")
	assert.Contains(t, completions, "cloud projects")
	assert.NotContains(t, completions, "cloud buckets")
	assert.NotContains(t, completions, "cloud exec")
	assert.NotContains(t, completions, "cloud wipe")
}
