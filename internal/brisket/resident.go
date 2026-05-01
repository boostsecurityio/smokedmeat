// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package brisket

import (
	"os"
	"regexp"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/models"
)

var (
	residentKVRe          = regexp.MustCompile(`(?s)"k"\s*:\s*"([^"]+)"\s*,\s*"v"\s*:\s*("[^"]*"|-?[0-9]+(?:\.[0-9]+)?|true|false|null)`)
	residentSystemValueRe = regexp.MustCompile(`(?s)"(system\.[^"]+)"\s*:\s*\{\s*"value"\s*:\s*("[^"]*"|-?[0-9]+(?:\.[0-9]+)?|true|false|null)`)
	residentJobIDRe       = regexp.MustCompile(`Job ID ([0-9a-fA-F-]+)`)
)

func parseResidentWorkerLog(path string, observed models.ResidentJobObservation) models.ResidentJobObservation {
	data, err := os.ReadFile(path)
	if err != nil {
		return observed
	}
	text := string(data)
	observed.WorkerLog = path

	values := make(map[string]string)
	for _, match := range residentKVRe.FindAllStringSubmatch(text, -1) {
		values[match[1]] = trimResidentValue(match[2])
	}
	for _, match := range residentSystemValueRe.FindAllStringSubmatch(text, -1) {
		values[match[1]] = trimResidentValue(match[2])
	}

	observed.Repository = firstNonEmpty(values["repository"], values["workflow_repository"], observed.Repository)
	observed.Workflow = firstNonEmpty(values["workflow_file_path"], values["workflow"], observed.Workflow)
	observed.WorkflowRef = firstNonEmpty(values["workflow_ref"], observed.WorkflowRef)
	observed.WorkflowSHA = firstNonEmpty(values["workflow_sha"], observed.WorkflowSHA)
	observed.Job = firstNonEmpty(values["system.github.job"], values["system.phaseDisplayName"], observed.Job)
	observed.RunID = firstNonEmpty(values["run_id"], observed.RunID)
	observed.RunNumber = firstNonEmpty(values["run_number"], observed.RunNumber)
	observed.RunAttempt = firstNonEmpty(values["run_attempt"], observed.RunAttempt)
	observed.CheckRunID = trimNumericID(firstNonEmpty(values["check_run_id"], observed.CheckRunID))
	observed.OrchestrationID = firstNonEmpty(values["system.orchestrationId"], observed.OrchestrationID)
	if match := residentJobIDRe.FindStringSubmatch(text); len(match) == 2 {
		observed.GitHubJobID = match[1]
	}

	if observed.Repository == "" || observed.Workflow == "" {
		repo, workflow := splitWorkflowRef(observed.WorkflowRef)
		observed.Repository = firstNonEmpty(observed.Repository, repo)
		observed.Workflow = firstNonEmpty(observed.Workflow, workflow)
	}
	observed.AttributionConfidence = residentAttributionConfidence(observed)
	observed.JobKey = residentJobKey(observed)
	return observed
}

func residentJobKey(observed models.ResidentJobObservation) string {
	parts := []string{
		observed.Repository,
		observed.Workflow,
		observed.Job,
		observed.RunID,
		observed.RunAttempt,
		observed.GitHubJobID,
	}
	joined := strings.Join(parts, ":")
	if strings.Trim(joined, ":") != "" {
		return joined
	}
	if observed.WorkerLog != "" {
		return observed.WorkerLog
	}
	return observed.RunnerRoot + ":" + observed.WorkerProcessStarted
}

func residentAttributionConfidence(observed models.ResidentJobObservation) string {
	switch {
	case observed.Repository != "" && observed.Workflow != "" && observed.Job != "" && observed.RunID != "":
		return models.ResidentJobConfidenceStrong
	case observed.Repository != "" && observed.Workflow != "":
		return models.ResidentJobConfidencePartial
	case observed.Job != "" || observed.WorkerLog != "":
		return models.ResidentJobConfidenceWeak
	default:
		return models.ResidentJobConfidenceUnknown
	}
}

func splitWorkflowRef(ref string) (repo, workflow string) {
	if ref == "" {
		return "", ""
	}
	before, _, _ := strings.Cut(ref, "@")
	idx := strings.Index(before, "/.github/workflows/")
	if idx < 0 {
		return "", ""
	}
	return before[:idx], before[idx+1:]
}

func trimResidentValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "null" {
		return ""
	}
	value = strings.Trim(value, `"`)
	value = strings.ReplaceAll(value, `\"`, `"`)
	return value
}

func trimNumericID(value string) string {
	return strings.TrimSuffix(value, ".0")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
