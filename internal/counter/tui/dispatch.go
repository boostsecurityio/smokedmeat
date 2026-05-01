// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

func (m Model) workflowDispatchTargetForNode(node *TreeNode) (*WorkflowDispatchSelection, error) {
	if node == nil || node.Type != TreeNodeWorkflow {
		return nil, fmt.Errorf("workflow_dispatch requires a [WORKFLOW] node")
	}
	if !workflowNodeDispatchable(node) {
		return nil, fmt.Errorf("workflow does not define workflow_dispatch")
	}
	repo := m.treeNodeRepo(node)
	workflow := nodeStringProperty(node, "path")
	if workflow == "" {
		workflow = node.Label
	}
	target := &WorkflowDispatchSelection{
		Repository: repo,
		Workflow:   workflow,
		Ref:        nodeStringProperty(node, "default_branch"),
		Inputs:     workflowDispatchInputs(node.Properties["dispatch_inputs"]),
	}
	target.Values = workflowDispatchDefaultValues(target.Inputs)
	return target, nil
}

func (m Model) workflowDispatchTargetForQuery(query string) (*WorkflowDispatchSelection, error) {
	tokens := strings.Fields(query)
	hasDispatch := false
	repo := ""
	workflow := ""
	for _, token := range tokens {
		switch {
		case token == "workflow_dispatch":
			hasDispatch = true
		case strings.Contains(token, "/") && !strings.HasPrefix(token, ".github/workflows/"):
			repo = token
		case strings.HasPrefix(token, ".github/workflows/"):
			workflow = token
		}
	}
	if !hasDispatch || repo == "" || workflow == "" {
		return nil, fmt.Errorf("workflow_dispatch target not found: %s", query)
	}
	if node := m.findWorkflowNode(repo, workflow); node != nil {
		return m.workflowDispatchTargetForNode(node)
	}
	return &WorkflowDispatchSelection{
		Repository: repo,
		Workflow:   workflow,
		Values:     map[string]string{},
	}, nil
}

func (m Model) findWorkflowNode(repo, workflow string) *TreeNode {
	var found *TreeNode
	var walk func(*TreeNode)
	walk = func(node *TreeNode) {
		if node == nil || found != nil {
			return
		}
		if node.Type == TreeNodeWorkflow && m.treeNodeRepo(node) == repo {
			path := nodeStringProperty(node, "path")
			if path == "" {
				path = node.Label
			}
			if path == workflow {
				found = node
				return
			}
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(m.treeRoot)
	return found
}

func workflowNodeDispatchable(node *TreeNode) bool {
	if node == nil {
		return false
	}
	for _, trigger := range propertyStringSlice(node.Properties, "event_triggers") {
		if strings.TrimSpace(trigger) == "workflow_dispatch" {
			return true
		}
	}
	if trigger := nodeStringProperty(node, "trigger"); strings.Contains(trigger, "workflow_dispatch") {
		return true
	}
	return node.Properties["dispatchable"] == true
}

func workflowDispatchInputs(value interface{}) []counter.WorkflowDispatchInput {
	if value == nil {
		return nil
	}
	if inputs, ok := value.([]counter.WorkflowDispatchInput); ok {
		return inputs
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var inputs []counter.WorkflowDispatchInput
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil
	}
	return inputs
}

func workflowDispatchDefaultValues(inputs []counter.WorkflowDispatchInput) map[string]string {
	values := make(map[string]string, len(inputs))
	for _, input := range inputs {
		values[input.Name] = input.Default
	}
	return values
}

func workflowDispatchInputPayload(target *WorkflowDispatchSelection) map[string]interface{} {
	if target == nil || len(target.Values) == 0 {
		return nil
	}
	payload := make(map[string]interface{})
	for _, input := range target.Inputs {
		value := strings.TrimSpace(target.Values[input.Name])
		if value == "" {
			continue
		}
		payload[input.Name] = value
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func validateWorkflowDispatchInputs(target *WorkflowDispatchSelection) error {
	if target == nil {
		return fmt.Errorf("workflow_dispatch target is missing")
	}
	for _, input := range target.Inputs {
		value := strings.TrimSpace(target.Values[input.Name])
		if input.Required && value == "" {
			return fmt.Errorf("required input %s is empty", input.Name)
		}
		if value != "" && len(input.Options) > 0 && !stringInSlice(value, input.Options) {
			return fmt.Errorf("input %s must be one of %s", input.Name, strings.Join(input.Options, ", "))
		}
	}
	return nil
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func (m Model) deployWorkflowDispatch(target WorkflowDispatchSelection, stagerID string, token *CollectedSecret, inputs map[string]interface{}, dwellTime time.Duration) tea.Cmd {
	return func() tea.Msg {
		if token == nil {
			return AutoDispatchFailedMsg{StagerID: stagerID, Err: fmt.Errorf("no workflow_dispatch token available")}
		}
		parts := strings.SplitN(target.Repository, "/", 2)
		if len(parts) != 2 {
			return AutoDispatchFailedMsg{StagerID: stagerID, Err: fmt.Errorf("invalid repository format")}
		}
		err := m.kitchenClient.TriggerDispatch(context.Background(), counter.DeployDispatchRequest{
			Token:        token.Value,
			Owner:        parts[0],
			Repo:         parts[1],
			WorkflowFile: strings.TrimPrefix(target.Workflow, ".github/workflows/"),
			Ref:          target.Ref,
			Inputs:       inputs,
		})
		if err != nil {
			return AutoDispatchFailedMsg{StagerID: stagerID, Err: err}
		}
		return AutoDispatchSuccessMsg{
			StagerID:   stagerID,
			Repository: target.Repository,
			Workflow:   target.Workflow,
			InputName:  dispatchInputSummary(inputs),
			DwellTime:  dwellTime,
		}
	}
}

func (m *Model) importDispatchWorkflowsToPantry(targets []WorkflowDispatchSelection) int {
	if len(targets) == 0 {
		return 0
	}
	if m.pantry == nil {
		m.pantry = pantry.New()
	}
	orgAssets := make(map[string]string)
	repoAssets := make(map[string]string)
	imported := 0
	for _, target := range targets {
		repoID, _ := m.ensurePantryRepository(target.Repository, orgAssets, repoAssets)
		if repoID == "" || target.Workflow == "" {
			continue
		}
		workflow := pantry.NewWorkflow(repoID, target.Workflow)
		workflow.State = pantry.StateValidated
		workflow.SetProperty("event_triggers", []string{"workflow_dispatch"})
		workflow.SetProperty("dispatchable", true)
		if target.Ref != "" {
			workflow.SetProperty("default_branch", target.Ref)
		}
		if len(target.Inputs) > 0 {
			workflow.SetProperty("dispatch_inputs", target.Inputs)
		}
		existed := m.pantry.HasAsset(workflow.ID)
		if err := m.pantry.AddAsset(workflow); err != nil {
			continue
		}
		if !existed {
			imported++
		}
		_ = m.pantry.AddRelationship(repoID, workflow.ID, pantry.Contains())
	}
	return imported
}

func dispatchInputSummary(inputs map[string]interface{}) string {
	if len(inputs) == 0 {
		return ""
	}
	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
