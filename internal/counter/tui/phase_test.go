// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPhase_CanSelectVuln(t *testing.T) {
	tests := []struct {
		phase Phase
		can   bool
	}{
		{PhaseSetup, false},
		{PhaseRecon, true},
		{PhaseWizard, false},
		{PhaseWaiting, false},
		{PhasePostExploit, true},
		{PhasePivot, true},
	}
	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			assert.Equal(t, tt.can, tt.phase.CanSelectVuln(),
				"%s.CanSelectVuln() should be %v", tt.phase, tt.can)
		})
	}
}

func TestPhase_CanCommandAgent(t *testing.T) {
	tests := []struct {
		phase Phase
		can   bool
	}{
		{PhaseSetup, false},
		{PhaseRecon, false},
		{PhaseWizard, false},
		{PhaseWaiting, false},
		{PhasePostExploit, true},
		{PhasePivot, true},
	}
	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			assert.Equal(t, tt.can, tt.phase.CanCommandAgent(),
				"%s.CanCommandAgent() should be %v", tt.phase, tt.can)
		})
	}
}

func TestWizardState_Reset(t *testing.T) {
	w := &WizardState{
		Step:           3,
		SelectedVuln:   &Vulnerability{ID: "V001"},
		DeliveryMethod: DeliveryCopyOnly,
		StagerID:       "stg-123",
		Payload:        "curl http://...",
	}

	w.Reset()

	assert.Equal(t, 1, w.Step, "Reset should set step to 1")
	assert.Nil(t, w.SelectedVuln, "Reset should clear selected vuln")
	assert.Equal(t, DeliveryIssue, w.DeliveryMethod, "Reset should default to Issue (simplest)")
	assert.Empty(t, w.StagerID)
	assert.Empty(t, w.Payload)
	assert.False(t, w.CachePoisonReplace)
}

func TestWaitingState_TimeoutBehavior(t *testing.T) {
	t.Run("fresh state is not warning or timed out", func(t *testing.T) {
		w := NewWaitingState("stg-1", "org/repo", "V001", ".github/workflows/ci.yml", "build", "PR", 0)

		assert.False(t, w.IsWarning())
		assert.False(t, w.IsTimedOut())
		assert.Less(t, w.Elapsed(), time.Second)
	})

	t.Run("warning triggers after 5 minutes", func(t *testing.T) {
		w := &WaitingState{
			StartTime:   time.Now().Add(-6 * time.Minute),
			SoftWarning: 5 * time.Minute,
			Timeout:     15 * time.Minute,
		}

		assert.True(t, w.IsWarning(), "Should be warning after 5 min")
		assert.False(t, w.IsTimedOut(), "Should not timeout until 15 min")
	})

	t.Run("timeout triggers after 15 minutes", func(t *testing.T) {
		w := &WaitingState{
			StartTime:   time.Now().Add(-16 * time.Minute),
			SoftWarning: 5 * time.Minute,
			Timeout:     15 * time.Minute,
		}

		assert.True(t, w.IsWarning())
		assert.True(t, w.IsTimedOut())
	})

	t.Run("default timeout values are correct", func(t *testing.T) {
		w := NewWaitingState("stg-1", "org/repo", "V001", ".github/workflows/ci.yml", "build", "PR", 0)

		assert.Equal(t, 15*time.Minute, w.Timeout, "Default timeout should be 15 min")
		assert.Equal(t, 5*time.Minute, w.SoftWarning, "Default warning should be 5 min")
	})
}

func TestCollectedSecret_IsEphemeral(t *testing.T) {
	tests := []struct {
		name      string
		secret    CollectedSecret
		ephemeral bool
	}{
		{
			name:      "explicitly ephemeral",
			secret:    CollectedSecret{Name: "CUSTOM_TOKEN", Ephemeral: true},
			ephemeral: true,
		},
		{
			name:      "GITHUB_TOKEN is always ephemeral",
			secret:    CollectedSecret{Name: "GITHUB_TOKEN", Ephemeral: false},
			ephemeral: true,
		},
		{
			name:      "ACTIONS_ID_TOKEN_REQUEST_TOKEN is ephemeral",
			secret:    CollectedSecret{Name: "ACTIONS_ID_TOKEN_REQUEST_TOKEN", Ephemeral: false},
			ephemeral: true,
		},
		{
			name:      "ACTIONS_ID_TOKEN_REQUEST_URL is ephemeral",
			secret:    CollectedSecret{Name: "ACTIONS_ID_TOKEN_REQUEST_URL", Ephemeral: false},
			ephemeral: true,
		},
		{
			name:      "ACTIONS_RUNTIME_TOKEN is ephemeral",
			secret:    CollectedSecret{Name: "ACTIONS_RUNTIME_TOKEN", Ephemeral: false},
			ephemeral: true,
		},
		{
			name:      "ACTIONS_CACHE_URL is ephemeral",
			secret:    CollectedSecret{Name: "ACTIONS_CACHE_URL", Ephemeral: false},
			ephemeral: true,
		},
		{
			name:      "AWS_SECRET_KEY is persistent",
			secret:    CollectedSecret{Name: "AWS_SECRET_KEY", Ephemeral: false},
			ephemeral: false,
		},
		{
			name:      "NPM_TOKEN is persistent",
			secret:    CollectedSecret{Name: "NPM_TOKEN", Ephemeral: false},
			ephemeral: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.ephemeral, tt.secret.IsEphemeral())
		})
	}
}

func TestCollectedSecret_MaskedValue(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		masked string
	}{
		{"empty value", "", "•••"},
		{"short value", "abc", "•••"},
		{"exactly 8 chars", "12345678", "1234•••678"},
		{"long token", "ghp_xxxxxxxxxxxxxxxxxxxx", "ghp_•••xxx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := CollectedSecret{Value: tt.value}
			assert.Equal(t, tt.masked, s.MaskedValue())
		})
	}
}

func TestDeliveryMethod_String(t *testing.T) {
	assert.Equal(t, "Create Issue", DeliveryIssue.String())
	assert.Equal(t, "Add Comment", DeliveryComment.String())
	assert.Equal(t, "Create PR", DeliveryAutoPR.String())
	assert.Equal(t, "Copy Only", DeliveryCopyOnly.String())
	assert.Equal(t, "Manual Steps", DeliveryManualSteps.String())
	assert.Equal(t, "Unknown", DeliveryMethod(99).String())
}

func TestView_IsModal(t *testing.T) {
	assert.False(t, ViewSetupWizard.IsModal())
	assert.False(t, ViewFindings.IsModal())
	assert.True(t, ViewWizard.IsModal(), "Wizard should be modal overlay")
	assert.False(t, ViewWaiting.IsModal())
	assert.False(t, ViewAgent.IsModal())
	assert.True(t, ViewLicense.IsModal())
	assert.True(t, ViewHelp.IsModal())
	assert.True(t, ViewReAuth.IsModal())
	assert.True(t, ViewOmnibox.IsModal())
	assert.True(t, ViewCallbacks.IsModal())
}

func TestPhase_String(t *testing.T) {
	tests := []struct {
		phase Phase
		want  string
	}{
		{PhaseSetup, "Setup"},
		{PhaseRecon, "Recon"},
		{PhaseWizard, "Wizard"},
		{PhaseWaiting, "Waiting"},
		{PhasePostExploit, "Post-Exploit"},
		{PhasePivot, "Pivot"},
		{Phase(99), "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.phase.String())
		})
	}
}

func TestPhase_HasActiveAgent(t *testing.T) {
	tests := []struct {
		phase Phase
		has   bool
	}{
		{PhaseSetup, false},
		{PhaseRecon, false},
		{PhaseWizard, false},
		{PhaseWaiting, false},
		{PhasePostExploit, true},
		{PhasePivot, true},
	}
	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			assert.Equal(t, tt.has, tt.phase.HasActiveAgent())
		})
	}
}

func TestView_String(t *testing.T) {
	tests := []struct {
		view View
		want string
	}{
		{ViewSetupWizard, "SetupWizard"},
		{ViewFindings, "Findings"},
		{ViewWizard, "Wizard"},
		{ViewWaiting, "Waiting"},
		{ViewAgent, "Agent"},
		{ViewLicense, "License"},
		{ViewHelp, "Help"},
		{ViewReAuth, "ReAuth"},
		{ViewOmnibox, "Omnibox"},
		{ViewCallbacks, "Implants"},
		{View(99), "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.view.String())
		})
	}
}

func TestCollectedSecret_CanUseAsToken(t *testing.T) {
	tests := []struct {
		name   string
		secret CollectedSecret
		can    bool
	}{
		{"github_pat type", CollectedSecret{Type: "github_pat"}, true},
		{"github_fine_grained_pat type", CollectedSecret{Type: "github_fine_grained_pat"}, true},
		{"github_token type", CollectedSecret{Type: "github_token"}, true},
		{"github_app_token type", CollectedSecret{Type: "github_app_token"}, true},
		{"github_oauth type", CollectedSecret{Type: "github_oauth"}, true},
		{"ghp_ prefix", CollectedSecret{Value: "ghp_xxxxxxxxxxxx"}, true},
		{"ghs_ prefix", CollectedSecret{Value: "ghs_xxxxxxxxxxxx"}, true},
		{"gho_ prefix", CollectedSecret{Value: "gho_xxxxxxxxxxxx"}, true},
		{"ghu_ prefix", CollectedSecret{Value: "ghu_xxxxxxxxxxxx"}, true},
		{"github_pat_ prefix", CollectedSecret{Value: "github_pat_xxxxxxxxxxxx"}, true},
		{"aws key", CollectedSecret{Type: "aws_access_key", Value: "AKIA..."}, false},
		{"random value", CollectedSecret{Value: "some-random-value"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.can, tt.secret.CanUseAsToken())
		})
	}
}

func TestCollectedSecret_TypeIcon(t *testing.T) {
	tests := []struct {
		name   string
		secret CollectedSecret
		icon   string
	}{
		{"github_pat", CollectedSecret{Type: "github_pat"}, "🔑"},
		{"github_fine_grained_pat", CollectedSecret{Type: "github_fine_grained_pat"}, "🔑"},
		{"github_token", CollectedSecret{Type: "github_token"}, "⏱"},
		{"github_app_token", CollectedSecret{Type: "github_app_token"}, "🤖"},
		{"github_oauth", CollectedSecret{Type: "github_oauth"}, "🔗"},
		{"aws_access_key", CollectedSecret{Type: "aws_access_key"}, "☁️"},
		{"aws_secret", CollectedSecret{Type: "aws_secret"}, "☁️"},
		{"azure", CollectedSecret{Type: "azure"}, "🔷"},
		{"gcp", CollectedSecret{Type: "gcp"}, "🌐"},
		{"npm", CollectedSecret{Type: "npm"}, "📦"},
		{"container_registry", CollectedSecret{Type: "container_registry"}, "🐳"},
		{"database", CollectedSecret{Type: "database"}, "🗄️"},
		{"signing_key", CollectedSecret{Type: "signing_key"}, "✍️"},
		{"ephemeral unknown", CollectedSecret{Name: "GITHUB_TOKEN"}, "⏱"},
		{"persistent unknown", CollectedSecret{Name: "MY_SECRET"}, "🔑"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.icon, tt.secret.TypeIcon())
		})
	}
}

func TestApplicableDeliveryMethods_ContextFallback(t *testing.T) {
	tests := []struct {
		name          string
		context       string
		expectedFirst DeliveryMethod
	}{
		{"issue_body context", "issue_body", DeliveryIssue},
		{"issue_title context", "issue_title", DeliveryIssue},
		{"comment_body context", "comment_body", DeliveryIssue},
		{"pr_body context", "pr_body", DeliveryAutoPR},
		{"pr_title context", "pr_title", DeliveryAutoPR},
		{"head_ref context", "head_ref", DeliveryAutoPR},
		{"commit_message context", "commit_message", DeliveryAutoPR},
		{"git_branch context", "git_branch", DeliveryAutoPR},
		{"unknown context", "bash_run", DeliveryIssue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := &Vulnerability{Trigger: "", Context: tt.context}
			methods := ApplicableDeliveryMethods(vuln)
			assert.Equal(t, tt.expectedFirst, methods[0])
		})
	}
}

func TestApplicableDeliveryMethods_TriggerFirst(t *testing.T) {
	tests := []struct {
		name          string
		vuln          *Vulnerability
		expectedFirst DeliveryMethod
		shouldNotHave []DeliveryMethod
	}{
		{
			name:          "nil vuln returns all options",
			vuln:          nil,
			expectedFirst: DeliveryIssue,
		},
		{
			name: "issue_comment trigger prioritizes Issue",
			vuln: &Vulnerability{
				Trigger: "issues, issue_comment, pull_request_target",
				Context: "pr_body",
			},
			expectedFirst: DeliveryIssue,
			shouldNotHave: []DeliveryMethod{},
		},
		{
			name: "issues trigger prioritizes Issue",
			vuln: &Vulnerability{
				Trigger: "issues",
				Context: "issue_body",
			},
			expectedFirst: DeliveryIssue,
		},
		{
			name: "workflow_dispatch prioritizes AutoDispatch",
			vuln: &Vulnerability{
				Trigger: "workflow_dispatch",
				Context: "bash_run",
			},
			expectedFirst: DeliveryAutoDispatch,
		},
		{
			name: "pull_request trigger prioritizes PR",
			vuln: &Vulnerability{
				Trigger: "pull_request",
				Context: "pr_body",
			},
			expectedFirst: DeliveryAutoPR,
		},
		{
			name: "push trigger prioritizes PR",
			vuln: &Vulnerability{
				Trigger: "push",
				Context: "commit_message",
			},
			expectedFirst: DeliveryAutoPR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			methods := ApplicableDeliveryMethods(tt.vuln)

			assert.NotEmpty(t, methods, "Should return at least one method")
			assert.Equal(t, tt.expectedFirst, methods[0],
				"First method should be %s, got %s", tt.expectedFirst, methods[0])

			hasManualOptions := false
			for _, m := range methods {
				if m == DeliveryCopyOnly || m == DeliveryManualSteps {
					hasManualOptions = true
					break
				}
			}
			assert.True(t, hasManualOptions, "Should always have manual options")
		})
	}
}

func TestApplicableDeliveryMethods_LOTP(t *testing.T) {
	hasMethod := func(methods []DeliveryMethod, want DeliveryMethod) bool {
		for _, m := range methods {
			if m == want {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name      string
		vuln      *Vulnerability
		wantLOTP  bool
		wantFirst DeliveryMethod
	}{
		{
			name: "tool detection (e.g. npm install in run: step)",
			vuln: &Vulnerability{
				RuleID:   "untrusted_checkout_exec",
				LOTPTool: "npm",
			},
			wantLOTP:  true,
			wantFirst: DeliveryLOTP,
		},
		{
			name: "action detection (e.g. actions/setup-node in uses: step)",
			vuln: &Vulnerability{
				RuleID:     "untrusted_checkout_exec",
				LOTPAction: "actions/setup-node",
			},
			wantLOTP:  true,
			wantFirst: DeliveryLOTP,
		},
		{
			name: "neither tool nor action falls back to manual only",
			vuln: &Vulnerability{
				RuleID: "untrusted_checkout_exec",
			},
			wantLOTP:  false,
			wantFirst: DeliveryManualSteps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			methods := ApplicableDeliveryMethods(tt.vuln)
			assert.Equal(t, tt.wantFirst, methods[0])
			assert.Equal(t, tt.wantLOTP, hasMethod(methods, DeliveryLOTP))
			assert.True(t, hasMethod(methods, DeliveryManualSteps))
		})
	}
}

func TestVulnerabilitySupportsExploit(t *testing.T) {
	tests := []struct {
		name     string
		vuln     *Vulnerability
		supports bool
	}{
		{
			name: "github injection is supported",
			vuln: &Vulnerability{
				Workflow: ".github/workflows/ci.yml",
				RuleID:   "injection",
			},
			supports: true,
		},
		{
			name: "github pwn request is supported",
			vuln: &Vulnerability{
				Workflow: ".github/workflows/pr.yml",
				RuleID:   "untrusted_checkout_exec",
			},
			supports: true,
		},
		{
			name: "self hosted finding is analyze only",
			vuln: &Vulnerability{
				Workflow: ".github/workflows/pr.yml",
				RuleID:   "pr_runs_on_self_hosted",
			},
			supports: false,
		},
		{
			name: "non github workflow is analyze only",
			vuln: &Vulnerability{
				Workflow: "azure-pipelines.yml",
				RuleID:   "injection",
			},
			supports: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.supports, vulnerabilitySupportsExploit(tt.vuln))
		})
	}
}
