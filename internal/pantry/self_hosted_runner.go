// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
)

func NormalizeSelfHostedRunnerLabels(labels []string) []string {
	seen := make(map[string]struct{}, len(labels))
	normalized := make([]string, 0, len(labels))
	for _, raw := range labels {
		label := strings.ToLower(strings.TrimSpace(raw))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		normalized = append(normalized, label)
	}
	if len(normalized) == 0 {
		return []string{"self-hosted"}
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i] == "self-hosted" {
			return true
		}
		if normalized[j] == "self-hosted" {
			return false
		}
		return normalized[i] < normalized[j]
	})
	return normalized
}

func SplitSelfHostedRunnerLabels(labels []string) (static, dynamic []string) {
	for _, label := range NormalizeSelfHostedRunnerLabels(labels) {
		if isDynamicSelfHostedRunnerLabel(label) {
			dynamic = append(dynamic, label)
			continue
		}
		static = append(static, label)
	}
	return static, dynamic
}

func SelfHostedRunnerLabelDisplay(labels []string) string {
	staticLabels, dynamicLabels := SplitSelfHostedRunnerLabels(labels)
	display := make([]string, 0, len(staticLabels))
	for _, label := range staticLabels {
		if label == "self-hosted" {
			continue
		}
		display = append(display, label)
	}
	if len(display) == 0 {
		if len(dynamicLabels) > 0 {
			return "dynamic-label-set"
		}
		return "unknown-label-set"
	}
	if len(dynamicLabels) > 0 {
		return strings.Join(display, "-") + " +dynamic"
	}
	return strings.Join(display, "-")
}

func isDynamicSelfHostedRunnerLabel(label string) bool {
	return strings.Contains(label, "${{") && strings.Contains(label, "}}")
}

func selfHostedRunnerTargetID(repoID string, labels []string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(strings.Join(labels, "\x00")))
	return fmt.Sprintf("%s:runner:%016x", repoID, hasher.Sum64())
}

type selfHostedRunnerObservation struct {
	RepoID             string
	WorkflowIDs        map[string]struct{}
	WorkflowPaths      map[string]struct{}
	JobIDs             map[string]struct{}
	JobNames           map[string]struct{}
	NormalizedLabelSet []string
}

func SyncObservedSelfHostedRunnerTargets(p *Pantry) int {
	if p == nil {
		return 0
	}

	workflows := make(map[string]Asset)
	for _, workflow := range p.GetAssetsByType(AssetWorkflow) {
		workflows[workflow.ID] = workflow
	}

	observations := make(map[string]*selfHostedRunnerObservation)
	for _, job := range p.GetAssetsByType(AssetJob) {
		selfHosted, _ := job.Properties["self_hosted"].(bool)
		if !selfHosted {
			continue
		}

		workflowID, _ := job.Properties["workflow_id"].(string)
		if workflowID == "" {
			continue
		}
		workflow, ok := workflows[workflowID]
		if !ok {
			continue
		}
		repoID, _ := workflow.Properties["repo_id"].(string)
		if repoID == "" {
			continue
		}

		labelSet := NormalizeSelfHostedRunnerLabels(job.StringSliceProperty("runs_on"))
		targetID := selfHostedRunnerTargetID(repoID, labelSet)
		observation := observations[targetID]
		if observation == nil {
			observation = &selfHostedRunnerObservation{
				RepoID:             repoID,
				WorkflowIDs:        make(map[string]struct{}),
				WorkflowPaths:      make(map[string]struct{}),
				JobIDs:             make(map[string]struct{}),
				JobNames:           make(map[string]struct{}),
				NormalizedLabelSet: labelSet,
			}
			observations[targetID] = observation
		}

		observation.WorkflowIDs[workflowID] = struct{}{}
		if path, _ := workflow.Properties["path"].(string); path != "" {
			observation.WorkflowPaths[path] = struct{}{}
		}
		observation.JobIDs[job.ID] = struct{}{}
		if job.Name != "" {
			observation.JobNames[job.Name] = struct{}{}
		}
	}

	created := 0
	for _, observation := range observations {
		target := NewSelfHostedRunnerTarget(observation.RepoID, observation.NormalizedLabelSet)
		if !p.HasAsset(target.ID) {
			created++
		}

		target.SetProperty("observed_workflow_ids", stringSetValues(observation.WorkflowIDs))
		target.SetProperty("observed_workflow_paths", stringSetValues(observation.WorkflowPaths))
		target.SetProperty("observed_job_ids", stringSetValues(observation.JobIDs))
		target.SetProperty("observed_job_names", stringSetValues(observation.JobNames))
		target.State = StateValidated

		if err := p.AddAsset(target); err != nil {
			continue
		}
		_ = p.AddRelationship(observation.RepoID, target.ID, Contains())
		for workflowID := range observation.WorkflowIDs {
			_ = p.AddRelationship(workflowID, target.ID, ObservedOn())
		}
		for jobID := range observation.JobIDs {
			_ = p.AddRelationship(jobID, target.ID, ObservedOn())
		}
	}

	return created
}

func stringSetValues(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
