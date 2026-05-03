// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func TestParseResidentWorkerLog_StrongAttribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Worker_20260501-164156-utc.log")
	content := `[2026-05-01 16:41:57Z INFO Worker] Job message:
{
  "variables": {
    "system.github.job": {
      "value": "test"
    },
    "system.orchestrationId": {
      "value": "40747663-9a16.test.__default"
    }
  },
  "github": {
    "d": [
      {
        "k": "repository",
        "v": "owner/repo"
      },
      {
        "k": "run_id",
        "v": "25223159810"
      },
      {
        "k": "run_number",
        "v": "2"
      },
      {
        "k": "run_attempt",
        "v": "1"
      },
      {
        "k": "workflow_ref",
        "v": "owner/repo/.github/workflows/dispatch.yml@refs/heads/zip-zip"
      },
      {
        "k": "workflow_sha",
        "v": "11a6d2e5f665b43c5c71e86bb00fd2304e8fa5c8"
      }
    ]
  },
  "job": {
    "d": [
      {
        "k": "check_run_id",
        "v": 73960130388.0
      },
      {
        "k": "workflow_file_path",
        "v": ".github/workflows/dispatch.yml"
      }
    ]
  }
}
[2026-05-01 16:41:57Z INFO JobRunner] Job ID 77800a3f-badc-5d2f-894f-6254c9b4f6d3`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	observed := parseResidentWorkerLog(path, models.ResidentJobObservation{
		Event:      models.ResidentJobEventObserved,
		ObservedAt: time.Date(2026, 5, 1, 16, 41, 57, 0, time.UTC),
	})

	assert.Equal(t, "owner/repo", observed.Repository)
	assert.Equal(t, ".github/workflows/dispatch.yml", observed.Workflow)
	assert.Equal(t, "test", observed.Job)
	assert.Equal(t, "25223159810", observed.RunID)
	assert.Equal(t, "2", observed.RunNumber)
	assert.Equal(t, "1", observed.RunAttempt)
	assert.Equal(t, "73960130388", observed.CheckRunID)
	assert.Equal(t, "40747663-9a16.test.__default", observed.OrchestrationID)
	assert.Equal(t, "77800a3f-badc-5d2f-894f-6254c9b4f6d3", observed.GitHubJobID)
	assert.Equal(t, models.ResidentJobConfidenceStrong, observed.AttributionConfidence)
	assert.Contains(t, observed.JobKey, "25223159810")
}

func TestResidentWorkerLogHasAttribution(t *testing.T) {
	dir := t.TempDir()
	incomplete := filepath.Join(dir, "Worker_incomplete.log")
	complete := filepath.Join(dir, "Worker_complete.log")
	require.NoError(t, os.WriteFile(incomplete, []byte(`"system.github.job": {"value": "test"}`), 0o600))
	require.NoError(t, os.WriteFile(complete, []byte(`{
  "github": {"d": [
    {"k": "repository", "v": "owner/repo"},
    {"k": "workflow_ref", "v": "owner/repo/.github/workflows/dispatch.yml@refs/heads/main"}
  ]},
  "job": {"d": [{"k": "workflow_file_path", "v": ".github/workflows/dispatch.yml"}]}
}`), 0o600))

	assert.False(t, residentWorkerLogHasAttribution(incomplete))
	assert.True(t, residentWorkerLogHasAttribution(complete))
}

func TestResidentJobKey_StrongAttributionUsesRunIdentity(t *testing.T) {
	key := residentJobKey(models.ResidentJobObservation{
		Repository:           "owner/repo",
		Workflow:             ".github/workflows/ci.yml",
		Job:                  "test",
		RunID:                "25223159810",
		RunnerRoot:           "/runner",
		WorkerProcessStarted: "123456789",
	})

	assert.Contains(t, key, "25223159810")
	assert.Contains(t, key, "owner/repo")
	assert.NotContains(t, key, "/runner")
}

func TestResidentJobKey_CheckRunIDCountsAsRunIdentity(t *testing.T) {
	key := residentJobKey(models.ResidentJobObservation{
		Job:                  "test",
		CheckRunID:           "73960130388",
		RunnerRoot:           "/runner",
		WorkerProcessStarted: "123456789",
	})

	assert.Contains(t, key, "73960130388")
	assert.NotContains(t, key, "/runner")
}

func TestResidentJobKey_WeakAttributionIncludesWorkerIdentity(t *testing.T) {
	first := residentJobKey(models.ResidentJobObservation{
		Job:                  "test",
		RunnerRoot:           "/runner",
		WorkerProcessStarted: "123456789",
	})
	second := residentJobKey(models.ResidentJobObservation{
		Job:                  "test",
		RunnerRoot:           "/runner",
		WorkerProcessStarted: "987654321",
	})

	assert.NotEqual(t, first, second)
	assert.Contains(t, first, "/runner:123456789")
	assert.Contains(t, second, "/runner:987654321")
}

func TestResidentJobKey_WeakAttributionFallsBackToWorkerLog(t *testing.T) {
	key := residentJobKey(models.ResidentJobObservation{
		Job:       "test",
		WorkerLog: "/runner/_diag/Worker_current.log",
	})

	assert.Contains(t, key, "/runner/_diag/Worker_current.log")
}

func TestSplitWorkflowRef(t *testing.T) {
	repo, workflow := splitWorkflowRef("owner/repo/.github/workflows/ci.yml@refs/heads/main")

	assert.Equal(t, "owner/repo", repo)
	assert.Equal(t, ".github/workflows/ci.yml", workflow)
}
