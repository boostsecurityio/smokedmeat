// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func (m Model) runnerTargetActionable(node *TreeNode) bool {
	return node != nil && node.Type == TreeNodeSelfHostedRunner
}

func (m Model) selectedRunnerTarget() *RunnerTargetSelection {
	node := m.SelectedTreeNode()
	if node == nil || node.Type != TreeNodeSelfHostedRunner {
		return nil
	}

	target := &RunnerTargetSelection{
		ID:                    node.ID,
		Repository:            m.treeNodeRepo(node),
		RepositoryID:          propertyString(node.Properties, "repo_id"),
		LabelDisplay:          propertyString(node.Properties, "label_display"),
		LabelSet:              nodeStringSliceProperty(node, "label_set"),
		DynamicLabelSet:       nodeStringSliceProperty(node, "dynamic_label_set"),
		ObservedWorkflowPaths: nodeStringSliceProperty(node, "observed_workflow_paths"),
		ObservedJobNames:      nodeStringSliceProperty(node, "observed_job_names"),
	}
	if target.LabelDisplay == "" {
		target.LabelDisplay = node.Label
	}
	if vuln := m.preferredSelfHostedVulnerabilityForTarget(target); vuln != nil {
		target.PreferredPath = vuln.ID
	}
	return target
}

func (m *Model) openSelectedRunnerTarget() (tea.Cmd, error) {
	target := m.selectedRunnerTarget()
	if target == nil {
		return nil, fmt.Errorf("no self-hosted runner target selected")
	}
	if err := m.OpenRunnerTargetWizard(target); err != nil {
		return nil, err
	}
	return m.startWizardPreflight(false), nil
}

func (m Model) preferredSelfHostedVulnerabilityForTarget(target *RunnerTargetSelection) *Vulnerability {
	if target == nil {
		return nil
	}

	workflowPaths := make(map[string]struct{}, len(target.ObservedWorkflowPaths))
	for _, path := range target.ObservedWorkflowPaths {
		workflowPaths[path] = struct{}{}
	}
	jobNames := make(map[string]struct{}, len(target.ObservedJobNames))
	for _, name := range target.ObservedJobNames {
		jobNames[name] = struct{}{}
	}

	for i := range m.vulnerabilities {
		vuln := &m.vulnerabilities[i]
		if !vulnerabilitySupportsExploit(vuln) {
			continue
		}
		if target.Repository != "" && vuln.Repository != target.Repository {
			continue
		}
		if len(workflowPaths) > 0 {
			if _, ok := workflowPaths[vuln.Workflow]; !ok {
				continue
			}
		}
		if len(jobNames) > 0 && vuln.Job != "" {
			if _, ok := jobNames[vuln.Job]; !ok {
				continue
			}
		}
		return vuln
	}

	return nil
}

func (m Model) selfHostedContextForVulnerability(vuln *Vulnerability) *RunnerTargetSelection {
	if vuln == nil || m.pantry == nil {
		return nil
	}

	repoID := "github:" + strings.TrimSpace(vuln.Repository)
	for _, asset := range m.pantry.GetAssetsByType(pantry.AssetSelfHostedRunner) {
		if propertyString(asset.Properties, "repo_id") != repoID {
			continue
		}

		workflowPaths := propertyStringSlice(asset.Properties, "observed_workflow_paths")
		jobNames := propertyStringSlice(asset.Properties, "observed_job_names")
		workflowMatch := len(workflowPaths) == 0
		for _, path := range workflowPaths {
			if path == vuln.Workflow {
				workflowMatch = true
				break
			}
		}
		if !workflowMatch {
			continue
		}

		jobMatch := len(jobNames) == 0 || vuln.Job == ""
		for _, name := range jobNames {
			if name == vuln.Job {
				jobMatch = true
				break
			}
		}
		if !jobMatch {
			continue
		}

		target := &RunnerTargetSelection{
			ID:                    asset.ID,
			Repository:            vuln.Repository,
			RepositoryID:          repoID,
			LabelDisplay:          propertyString(asset.Properties, "label_display"),
			LabelSet:              propertyStringSlice(asset.Properties, "label_set"),
			DynamicLabelSet:       propertyStringSlice(asset.Properties, "dynamic_label_set"),
			ObservedWorkflowPaths: workflowPaths,
			ObservedJobNames:      jobNames,
		}
		if preferred := m.preferredSelfHostedVulnerabilityForTarget(target); preferred != nil {
			target.PreferredPath = preferred.ID
		}
		return target
	}

	return m.selfHostedContextFromWorkflowJob(vuln, repoID)
}

func (m Model) selfHostedContextFromWorkflowJob(vuln *Vulnerability, repoID string) *RunnerTargetSelection {
	workflowPath := strings.TrimSpace(vuln.Workflow)
	if workflowPath == "" || repoID == "" {
		return nil
	}

	workflowIDs := make(map[string]string)
	for _, workflow := range m.pantry.GetAssetsByType(pantry.AssetWorkflow) {
		if propertyString(workflow.Properties, "repo_id") != repoID {
			continue
		}
		if propertyString(workflow.Properties, "path") != workflowPath {
			continue
		}
		workflowIDs[workflow.ID] = workflowPath
	}
	if len(workflowIDs) == 0 {
		return nil
	}

	for _, job := range m.pantry.GetAssetsByType(pantry.AssetJob) {
		workflowID := propertyString(job.Properties, "workflow_id")
		observedWorkflowPath, ok := workflowIDs[workflowID]
		if !ok {
			continue
		}
		if vuln.Job != "" && job.Name != vuln.Job {
			continue
		}
		if !propertyBool(job.Properties, "self_hosted") {
			continue
		}
		return m.runnerTargetSelectionFromJob(vuln, repoID, observedWorkflowPath, job)
	}

	return nil
}

func (m Model) runnerTargetSelectionFromJob(vuln *Vulnerability, repoID, workflowPath string, job pantry.Asset) *RunnerTargetSelection {
	labels := pantry.NormalizeSelfHostedRunnerLabels(job.StringSliceProperty("runs_on"))
	labelSet, dynamicLabelSet := pantry.SplitSelfHostedRunnerLabels(labels)
	targetAsset := pantry.NewSelfHostedRunnerTarget(repoID, labels)
	jobNames := []string(nil)
	if job.Name != "" {
		jobNames = []string{job.Name}
	}
	target := &RunnerTargetSelection{
		ID:                    targetAsset.ID,
		Repository:            vuln.Repository,
		RepositoryID:          repoID,
		LabelDisplay:          pantry.SelfHostedRunnerLabelDisplay(labels),
		LabelSet:              labelSet,
		DynamicLabelSet:       dynamicLabelSet,
		ObservedWorkflowPaths: []string{workflowPath},
		ObservedJobNames:      jobNames,
	}
	if preferred := m.preferredSelfHostedVulnerabilityForTarget(target); preferred != nil {
		target.PreferredPath = preferred.ID
	}
	return target
}

func (m Model) runnerTargetSSHWriteResult() *SSHTrialResult {
	if m.wizard == nil || m.wizard.SelectedRunnerTarget == nil || m.sshState == nil {
		return nil
	}
	repo := strings.TrimSpace(m.wizard.SelectedRunnerTarget.Repository)
	if repo == "" {
		return nil
	}
	for i := range m.sshState.Results {
		result := &m.sshState.Results[i]
		if !result.Success || result.Permission != "write" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(result.Repo), repo) {
			return result
		}
	}
	return nil
}

func nodeStringSliceProperty(node *TreeNode, key string) []string {
	if node == nil || node.Properties == nil {
		return nil
	}
	return propertyStringSlice(node.Properties, key)
}
