// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

const (
	ResidentJobEventObserved      = "observed"
	ResidentJobEventHarvested     = "harvested"
	ResidentJobEventHarvestFailed = "harvest_failed"

	ResidentJobConfidenceStrong  = "strong"
	ResidentJobConfidencePartial = "partial"
	ResidentJobConfidenceWeak    = "weak"
	ResidentJobConfidenceUnknown = "unknown"

	ResidentJobHarvestProfileLite = "resident-lite"
)

type ResidentJobObservation struct {
	Event                 string    `json:"event"`
	JobKey                string    `json:"job_key,omitempty"`
	SignalSource          string    `json:"signal_source,omitempty"`
	RunnerRoot            string    `json:"runner_root,omitempty"`
	WorkerPID             int       `json:"worker_pid,omitempty"`
	WorkerLog             string    `json:"worker_log,omitempty"`
	WorkerProcessStarted  string    `json:"worker_process_started,omitempty"`
	ObservedAt            time.Time `json:"observed_at,omitempty"`
	HarvestedAt           time.Time `json:"harvested_at,omitempty"`
	HarvestProfile        string    `json:"harvest_profile,omitempty"`
	AttributionConfidence string    `json:"attribution_confidence,omitempty"`
	Repository            string    `json:"repository,omitempty"`
	Workflow              string    `json:"workflow,omitempty"`
	WorkflowRef           string    `json:"workflow_ref,omitempty"`
	WorkflowSHA           string    `json:"workflow_sha,omitempty"`
	Job                   string    `json:"job,omitempty"`
	RunID                 string    `json:"run_id,omitempty"`
	RunNumber             string    `json:"run_number,omitempty"`
	RunAttempt            string    `json:"run_attempt,omitempty"`
	CheckRunID            string    `json:"check_run_id,omitempty"`
	OrchestrationID       string    `json:"orchestration_id,omitempty"`
	GitHubJobID           string    `json:"github_job_id,omitempty"`
	Error                 string    `json:"error,omitempty"`
}
