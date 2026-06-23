// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux
// +build linux

package brisket

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

func TestResidentMemDumpHasData(t *testing.T) {
	assert.False(t, residentMemDumpHasData(nil))
	assert.False(t, residentMemDumpHasData(&MemDumpResult{}))
	assert.True(t, residentMemDumpHasData(&MemDumpResult{Secrets: []string{"secret"}}))
	assert.True(t, residentMemDumpHasData(&MemDumpResult{Vars: []string{"VAR=value"}}))
	assert.False(t, residentMemDumpHasData(&MemDumpResult{Endpoints: []gump.Endpoint{{EnvName: "ACTIONS_RUNTIME_TOKEN"}}}))
}

func TestResidentMemDumpFallback_PrefersEmptyScanOverLaterExit(t *testing.T) {
	empty := &MemDumpResult{ProcessID: 123, RegionsScanned: 10}
	failed := &MemDumpResult{ProcessID: 123, Error: "read /proc/123/maps: no such process"}

	result := residentMemDumpFallback(123, empty, failed)

	assert.Equal(t, empty, result)
	assert.Equal(t, "runner memory scan found no secrets", result.Error)
}

func TestResidentMemDumpFallback_TreatsProcessExitAsTimingMiss(t *testing.T) {
	failed := &MemDumpResult{ProcessID: 123, Error: "read /proc/123/maps: no such process", ScanAttempts: 3}

	result := residentMemDumpFallback(123, nil, failed)

	assert.Equal(t, failed, result)
	assert.Equal(t, "runner memory scan found no secrets", result.Error)
	assert.Equal(t, 3, result.ScanAttempts)
}

func TestResidentMemDumpFallback_PreservesPermissionDenied(t *testing.T) {
	failed := &MemDumpResult{ProcessID: 123, Error: "open /proc/123/mem: permission denied"}

	result := residentMemDumpFallback(123, nil, failed)

	assert.Equal(t, failed, result)
	assert.Equal(t, "open /proc/123/mem: permission denied", result.Error)
}

func TestResidentMemDumpHardFailure_IgnoresNoSecrets(t *testing.T) {
	assert.False(t, residentMemDumpHardFailure(&MemDumpResult{Error: "runner memory scan found no secrets"}))
	assert.False(t, residentMemDumpHardFailure(&MemDumpResult{Error: "read /proc/123/maps: no such process"}))
	assert.False(t, residentMemDumpHardFailure(&MemDumpResult{}))
	assert.False(t, residentMemDumpHardFailure(nil))
	assert.True(t, residentMemDumpHardFailure(&MemDumpResult{Error: "open /proc/123/mem: permission denied"}))
}

func TestResidentHarvestAttemptIncludesRootAfterHydrationDelay(t *testing.T) {
	assert.False(t, residentHarvestAttemptIncludesRoot(250*time.Millisecond))
	assert.False(t, residentHarvestAttemptIncludesRoot(time.Second))
	assert.True(t, residentHarvestAttemptIncludesRoot(2*time.Second))
	assert.True(t, residentHarvestAttemptIncludesRoot(3*time.Second))
}

func TestDumpResidentGCPWorkloadCredentials(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.Mkdir(filepath.Join(root, "_diag"), 0o700))
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o700))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "bin", "Runner.Listener"), []byte(""), 0o600))
	workDir := filepath.Join(root, "_work", "repo", "repo")
	assert.NoError(t, os.MkdirAll(workDir, 0o700))
	credential := `{
	  "type": "external_account",
	  "token_url": "https://sts.googleapis.com/v1/token",
	  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/newcleus-runner-trusted%40whooli.iam.gserviceaccount.com:generateAccessToken",
	  "credential_source": {
	    "url": "https://token.actions.githubusercontent.com/_services/token",
	    "headers": {"Authorization": "Bearer request-token"}
	  }
	}`
	assert.NoError(t, os.WriteFile(filepath.Join(workDir, "gha-creds-test.json"), []byte(credential), 0o600))

	oldExchange := residentExchangeGCPExternalAccount
	defer func() { residentExchangeGCPExternalAccount = oldExchange }()
	residentExchangeGCPExternalAccount = func(_ context.Context, data []byte) (residentGCPAccessToken, error) {
		assert.Contains(t, string(data), "external_account")
		return residentGCPAccessToken{
			AccessToken:    "ya29.token",
			Project:        "whooli",
			ServiceAccount: "newcleus-runner-trusted@whooli.iam.gserviceaccount.com",
			Expiry:         time.Date(2026, 6, 23, 14, 0, 0, 0, time.UTC),
		}, nil
	}

	result := (&Agent{}).dumpResidentGCPWorkloadCredentials(context.Background(), root)

	assert.NotNil(t, result)
	assert.Len(t, result.Secrets, 2)
	assert.Contains(t, result.Secrets[0], `"GCP_EXTERNAL_ACCOUNT_JSON_B64"`)
	assert.Contains(t, result.Secrets[0], base64.StdEncoding.EncodeToString([]byte(credential)))
	assert.Contains(t, result.Secrets[1], `"GCP_ACCESS_TOKEN"`)
	assert.Contains(t, result.Secrets[1], "ya29.token")
	assert.Contains(t, result.Vars, residentRunnerVarRaw("CLOUDSDK_CORE_PROJECT", "whooli"))
	assert.Contains(t, result.Vars, residentRunnerVarRaw("GCP_SERVICE_ACCOUNT", "newcleus-runner-trusted@whooli.iam.gserviceaccount.com"))
	assert.Contains(t, result.Vars, residentRunnerVarRaw("GCP_ACCESS_TOKEN_EXPIRES_AT", "2026-06-23T14:00:00Z"))
}

func TestWaitResidentGCPWorkloadCredentialsCatchesLateFile(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.Mkdir(filepath.Join(root, "_diag"), 0o700))
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o700))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "bin", "Runner.Listener"), []byte(""), 0o600))
	workDir := filepath.Join(root, "_work", "repo", "repo")
	assert.NoError(t, os.MkdirAll(workDir, 0o700))

	oldExchange := residentExchangeGCPExternalAccount
	defer func() { residentExchangeGCPExternalAccount = oldExchange }()
	residentExchangeGCPExternalAccount = func(context.Context, []byte) (residentGCPAccessToken, error) {
		return residentGCPAccessToken{AccessToken: "ya29.late", Project: "whooli"}, nil
	}

	go func() {
		time.Sleep(2 * residentWatchInterval)
		_ = os.WriteFile(filepath.Join(workDir, "gha-creds-late.json"), []byte(`{
		  "type": "external_account",
		  "token_url": "https://sts.googleapis.com/v1/token",
		  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/newcleus-runner-trusted%40whooli.iam.gserviceaccount.com:generateAccessToken",
		  "credential_source": {
		    "url": "https://token.actions.githubusercontent.com/_services/token",
		    "headers": {"Authorization": "Bearer request-token"}
		  }
		}`), 0o600)
	}()

	result := (&Agent{}).waitResidentGCPWorkloadCredentials(context.Background(), root, time.Second)

	assert.NotNil(t, result)
	assert.Len(t, result.Secrets, 1)
	assert.Contains(t, result.Secrets[0], "ya29.late")
}

func TestNewestResidentGCPCredentialFileUsesWorkspaceGlobBeforeBoundedWalk(t *testing.T) {
	root := t.TempDir()
	assert.NoError(t, os.Mkdir(filepath.Join(root, "_diag"), 0o700))
	assert.NoError(t, os.MkdirAll(filepath.Join(root, "bin"), 0o700))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "bin", "Runner.Listener"), []byte(""), 0o600))
	bulkDir := filepath.Join(root, "_work", "000", "bulk")
	assert.NoError(t, os.MkdirAll(bulkDir, 0o700))
	for i := range 5100 {
		assert.NoError(t, os.WriteFile(filepath.Join(bulkDir, fmt.Sprintf("file-%04d.txt", i)), nil, 0o600))
	}
	workDir := filepath.Join(root, "_work", "repo", "repo")
	assert.NoError(t, os.MkdirAll(workDir, 0o700))
	credentialPath := filepath.Join(workDir, "gha-creds-target.json")
	assert.NoError(t, os.WriteFile(credentialPath, []byte(`{"type":"external_account"}`), 0o600))

	assert.Equal(t, credentialPath, newestResidentGCPCredentialFile(root))
}

func TestResidentGCPExternalAccountMetadataFromJSON(t *testing.T) {
	data := []byte(`{
	  "type": "external_account",
	  "token_url": "https://sts.googleapis.com/v1/token",
	  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/newcleus-runner-trusted%40whooli.iam.gserviceaccount.com:generateAccessToken",
	  "credential_source": {
	    "url": "https://token.actions.githubusercontent.com/_services/token",
	    "headers": {"Authorization": "Bearer request-token"}
	  }
	}`)

	metadata, err := residentGCPExternalAccountMetadataFromJSON(data)

	assert.NoError(t, err)
	assert.Equal(t, "whooli", metadata.Project)
	assert.Equal(t, "newcleus-runner-trusted@whooli.iam.gserviceaccount.com", metadata.ServiceAccount)
}

func TestResidentGCPExternalAccountMetadataRejectsNonGitHubSource(t *testing.T) {
	data := []byte(`{
	  "type": "external_account",
	  "token_url": "https://sts.googleapis.com/v1/token",
	  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/newcleus-runner-trusted%40whooli.iam.gserviceaccount.com:generateAccessToken",
	  "credential_source": {
	    "url": "https://example.com/token",
	    "headers": {"Authorization": "Bearer request-token"}
	  }
	}`)

	_, err := residentGCPExternalAccountMetadataFromJSON(data)

	assert.Error(t, err)
}

func TestResidentGCPExternalAccountMetadataAcceptsRegionalGitHubSource(t *testing.T) {
	data := []byte(`{
	  "type": "external_account",
	  "token_url": "https://sts.googleapis.com/v1/token",
	  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/newcleus-runner-trusted%40whooli.iam.gserviceaccount.com:generateAccessToken",
	  "credential_source": {
	    "url": "https://pipelinesghubeus7.actions.githubusercontent.com/_apis/pipelines/workflows/1/oidctoken",
	    "headers": {"Authorization": "Bearer request-token"}
	  }
	}`)

	metadata, err := residentGCPExternalAccountMetadataFromJSON(data)

	assert.NoError(t, err)
	assert.Equal(t, "newcleus-runner-trusted@whooli.iam.gserviceaccount.com", metadata.ServiceAccount)
}

func TestResidentGCPSubjectTokenFromResponse(t *testing.T) {
	token, err := residentGCPSubjectTokenFromResponse([]byte(`{"value":"jwt-value"}`), "json", "value")
	assert.NoError(t, err)
	assert.Equal(t, "jwt-value", token)

	token, err = residentGCPSubjectTokenFromResponse([]byte(`plain-jwt`), "text", "")
	assert.NoError(t, err)
	assert.Equal(t, "plain-jwt", token)
}

func TestMergeResidentMemDumpStats(t *testing.T) {
	result := mergeResidentMemDumpStats(123, nil, &MemDumpResult{
		ProcessID:      456,
		RegionsScanned: 3,
		BytesRead:      1024,
		ReadErrors:     1,
		ScanAttempts:   1,
		ProcessTargets: 1,
	})
	result = mergeResidentMemDumpStats(123, result, &MemDumpResult{
		ProcessID:      789,
		RegionsScanned: 4,
		BytesRead:      2048,
		ReadErrors:     2,
		ScanAttempts:   1,
		ProcessTargets: 2,
	})

	assert.Equal(t, 123, result.ProcessID)
	assert.Equal(t, 7, result.RegionsScanned)
	assert.Equal(t, int64(3072), result.BytesRead)
	assert.Equal(t, 3, result.ReadErrors)
	assert.Equal(t, 2, result.ScanAttempts)
	assert.Equal(t, 3, result.ProcessTargets)
}

func TestMergeResidentMemDumpStats_PreservesFirstError(t *testing.T) {
	result := mergeResidentMemDumpStats(123, nil, &MemDumpResult{
		ProcessID:      456,
		Error:          "first failure",
		ScanAttempts:   1,
		ProcessTargets: 1,
	})
	result = mergeResidentMemDumpStats(123, result, &MemDumpResult{
		ProcessID:      789,
		Error:          "second failure",
		ScanAttempts:   1,
		ProcessTargets: 1,
	})

	assert.Equal(t, "first failure", result.Error)
	assert.Equal(t, 2, result.ScanAttempts)
	assert.Equal(t, 2, result.ProcessTargets)
}

func TestNormalizeResidentMemDumpResult_SetsCounters(t *testing.T) {
	result := normalizeResidentMemDumpResult(123, &MemDumpResult{})

	assert.Equal(t, 123, result.ProcessID)
	assert.Equal(t, 1, result.ScanAttempts)
	assert.Equal(t, 1, result.ProcessTargets)
}

func TestResidentWorkerKey_FallsBackToPIDWhenStartTickMissing(t *testing.T) {
	first := residentWorkerKey(residentWorkerProcess{PID: 101, Root: "/runner", StartTick: ""})
	second := residentWorkerKey(residentWorkerProcess{PID: 202, Root: "/runner", StartTick: ""})

	assert.Equal(t, "/runner:101", first)
	assert.Equal(t, "/runner:202", second)
}

func TestWaitForResidentWorkerLog_IgnoresLogBeforeWorkerSeen(t *testing.T) {
	root := t.TempDir()
	diag := filepath.Join(root, "_diag")
	assert.NoError(t, os.Mkdir(diag, 0o700))
	stale := filepath.Join(diag, "Worker_stale.log")
	assert.NoError(t, os.WriteFile(stale, []byte(`{
	  "github": {"d": [
	    {"k": "repository", "v": "owner/repo"},
	    {"k": "workflow_ref", "v": "owner/repo/.github/workflows/ci.yml@refs/heads/main"}
	  ]},
	  "job": {"d": [{"k": "workflow_file_path", "v": ".github/workflows/ci.yml"}]}
	}`), 0o600))
	since := time.Now().UTC()
	assert.NoError(t, os.Chtimes(stale, since.Add(-time.Second), since.Add(-time.Second)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	path := waitForResidentWorkerLog(ctx, residentWorkerProcess{PID: -1, Root: root, SeenAt: since})

	assert.Empty(t, path)
}

func TestResidentWorkerLogPathMatches(t *testing.T) {
	assert.True(t, residentWorkerLogPathMatches("/runner", "/runner/_diag/Worker_20260501-164156-utc.log"))
	assert.False(t, residentWorkerLogPathMatches("/runner", "/runner/_diag/Runner_20260501-164156-utc.log"))
	assert.False(t, residentWorkerLogPathMatches("/runner", "/runner/other/Worker_20260501-164156-utc.log"))
}

func TestResidentProcessStartTickFromStat_HandlesCommWithSpaces(t *testing.T) {
	stat := residentTestProcStat("Runner Worker", "42", "123456789")

	parent, ok := residentProcessParentFromStat(stat)

	assert.Equal(t, "123456789", residentProcessStartTickFromStat(stat))
	assert.True(t, ok)
	assert.Equal(t, 42, parent)
}

func TestResidentProcessTreeFromParents(t *testing.T) {
	parents := map[int]int{
		10: 1,
		11: 10,
		12: 10,
		13: 11,
		20: 1,
	}

	assert.Equal(t, []int{11, 12, 13, 10}, residentProcessTreeFromParents(10, parents, true))
	assert.Equal(t, []int{11, 12, 13}, residentProcessTreeFromParents(10, parents, false))
	assert.Empty(t, residentProcessTreeFromParents(10, nil, false))
	assert.Equal(t, []int{10}, residentProcessTreeFromParents(10, nil, true))
}

func residentTestProcStat(comm, ppid, startTick string) string {
	fields := []string{
		"S",
		ppid,
		"43",
		"44",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"1",
		"0",
		startTick,
	}
	return "99 (" + comm + ") " + strings.Join(fields, " ")
}
