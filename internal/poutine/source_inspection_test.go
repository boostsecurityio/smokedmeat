// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectGitHubActionsSourceWorkflowRisks(t *testing.T) {
	content := `name: CI
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  build:
    runs-on: [self-hosted, linux]
    permissions:
      actions: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: dangerous
        run: npm test -- --title "${{ github.event.pull_request.title }}"
`

	inspection := InspectGitHubActionsSource("acme/api", "main", ".github/workflows/ci.yml", content)

	require.Equal(t, SourceKindWorkflow, inspection.Kind)
	require.NotNil(t, inspection.Workflow)
	require.Len(t, inspection.Workflow.Jobs, 1)
	assert.Equal(t, "build", inspection.Workflow.Jobs[0].ID)
	assert.Contains(t, inspection.Workflow.Events, "pull_request_target")
	assert.Equal(t, 3, requireSourceRisk(t, inspection.Risks, "attackable-trigger").Line)
	assertSourceRisk(t, inspection.Risks, "self-hosted")
	assertSourceRisk(t, inspection.Risks, "write-token")
	assertSourceRisk(t, inspection.Risks, "oidc-token")
	assertSourceRisk(t, inspection.Risks, "weak-gate")
	assertSourceRisk(t, inspection.Risks, "untrusted-checkout")
	assert.Contains(t, requireSourceRisk(t, inspection.Risks, "lotp-tool").Message, `Step "dangerous" invokes LOTP-capable tool "npm"`)
	assertSourceRisk(t, inspection.Risks, "tainted-input")
}

func TestInspectGitHubActionsSourceActionRisks(t *testing.T) {
	content := `name: Build action
inputs:
  api-token:
    required: true
runs:
  using: composite
  steps:
    - uses: actions/setup-go@main
    - run: echo "${{ inputs.api-token }}"
`

	inspection := InspectGitHubActionsSource("acme/api", "main", "actions/build/action.yml", content)

	require.Equal(t, SourceKindAction, inspection.Kind)
	require.NotNil(t, inspection.Action)
	assert.Equal(t, "Build action", inspection.Action.Name)
	assertSourceRisk(t, inspection.Risks, "sensitive-input")
	assertSourceRisk(t, inspection.Risks, "unpinned-action")
	assertSourceRisk(t, inspection.Risks, "tainted-input")
}

func assertSourceRisk(t *testing.T, risks []SourceRisk, kind string) {
	t.Helper()
	_ = requireSourceRisk(t, risks, kind)
}

func requireSourceRisk(t *testing.T, risks []SourceRisk, kind string) SourceRisk {
	t.Helper()
	for _, risk := range risks {
		if risk.Kind == kind {
			return risk
		}
	}
	assert.Failf(t, "missing risk", "missing %s in %#v", kind, risks)
	return SourceRisk{}
}
