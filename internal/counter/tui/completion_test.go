// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandsForPhase(t *testing.T) {
	tests := []struct {
		phase    Phase
		included []string
		excluded []string
	}{
		{
			PhaseSetup,
			[]string{"help", "quit", "license", "set", "analyze", "status"},
			[]string{"sessions", "select", "ls", "graph"},
		},
		{
			PhaseRecon,
			[]string{"help", "exploit", "graph", "implants", "set", "analyze", "status"},
			[]string{"sessions", "select", "ls"},
		},
		{
			PhaseWizard,
			[]string{"help", "license", "quit"},
			[]string{"sessions", "analyze", "set"},
		},
		{
			PhaseWaiting,
			[]string{"help", "license", "quit"},
			[]string{"sessions", "analyze"},
		},
		{
			PhasePostExploit,
			[]string{"help", "exploit", "implants", "order", "select", "sessions", "graph", "set", "status", "analyze", "deep-analyze", "ssh", "pivot", "use"},
			[]string{"ls", "exfil", "recon"},
		},
		{
			PhasePivot,
			[]string{"help", "exploit", "implants", "order", "select", "sessions", "graph", "set", "status", "analyze", "deep-analyze", "ssh", "pivot", "use"},
			[]string{"ls", "exfil", "recon"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			cmds := commandsForPhase(tt.phase)
			for _, want := range tt.included {
				assert.Contains(t, cmds, want, "phase %s should include %q", tt.phase, want)
			}
			for _, unwant := range tt.excluded {
				assert.NotContains(t, cmds, unwant, "phase %s should not include %q", tt.phase, unwant)
			}
		})
	}
}

func TestGetCompletions_PhaseLimited(t *testing.T) {
	tests := []struct {
		name    string
		phase   Phase
		input   string
		present []string
		absent  []string
	}{
		{
			"setup phase empty input shows setup commands",
			PhaseSetup,
			"",
			[]string{"set", "analyze", "help"},
			[]string{"graph", "sessions"},
		},
		{
			"recon phase prefix 'i' matches implants",
			PhaseRecon,
			"i",
			[]string{"implants"},
			[]string{"callbacks", "sessions"},
		},
		{
			"recon phase prefix 'g' matches graph",
			PhaseRecon,
			"g",
			[]string{"graph"},
			[]string{"sessions"},
		},
		{
			"wizard phase only shows always commands",
			PhaseWizard,
			"",
			[]string{"help", "quit", "license"},
			[]string{"analyze", "set"},
		},
		{
			"post-exploit prefix 's' matches select and sessions and set and status",
			PhasePostExploit,
			"s",
			[]string{"select", "sessions", "set", "status"},
			[]string{"analyze"},
		},
		{
			"post-exploit prefix 'e' matches exploit only",
			PhasePostExploit,
			"e",
			[]string{"exploit"},
			[]string{"exfil"},
		},
		{
			"post-exploit prefix 'a' matches analyze",
			PhasePostExploit,
			"a",
			[]string{"analyze"},
			[]string{"status"},
		},
		{
			"post-exploit prefix 'd' matches deep-analyze",
			PhasePostExploit,
			"d",
			[]string{"deep-analyze"},
			[]string{"ls"},
		},
		{
			"post-exploit prefix 'o' matches order",
			PhasePostExploit,
			"o",
			[]string{"order"},
			[]string{"exploit"},
		},
		{
			"set activity-log subcommand completes",
			PhaseRecon,
			"set a",
			[]string{"set activity-log"},
			[]string{"set target"},
		},
		{
			"set activity-log autoexpand values complete",
			PhaseRecon,
			"set activity-log autoexpand o",
			[]string{"set activity-log autoexpand on", "set activity-log autoexpand off"},
			[]string{"set target org:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel(Config{})
			m.phase = tt.phase
			completions := m.getCompletions(tt.input)
			for _, want := range tt.present {
				assert.Contains(t, completions, want)
			}
			for _, unwant := range tt.absent {
				assert.NotContains(t, completions, unwant)
			}
		})
	}
}

func TestGetCompletions_SetTargetUsesDiscoveredRepos(t *testing.T) {
	m := NewModel(Config{})
	m.phase = PhaseRecon
	m.knownEntities["repo:whooli/xyz"] = &KnownEntity{Name: "whooli/xyz", EntityType: "repo"}
	m.knownEntities["repo:whooli/infrastructure-definitions"] = &KnownEntity{Name: "whooli/infrastructure-definitions", EntityType: "repo"}

	completions := m.getCompletions("set target repo:w")

	assert.Contains(t, completions, "set target repo:whooli/xyz")
	assert.Contains(t, completions, "set target repo:whooli/infrastructure-definitions")
}

func TestGetCompletions_OrderSubcommands(t *testing.T) {
	m := NewModel(Config{})
	m.phase = PhasePostExploit

	completions := m.getCompletions("order ")

	assert.Contains(t, completions, "order exec")
	assert.Contains(t, completions, "order env")
	assert.Contains(t, completions, "order recon")
	assert.Contains(t, completions, "order cloud-query")
	assert.Contains(t, completions, "order oidc")
	assert.Contains(t, completions, "order transfer")
	assert.Contains(t, completions, "order upload")
	assert.Contains(t, completions, "order download")
}

func TestCompleteInput_OrderHints(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue string
		wantHint  string
	}{
		{
			name:      "order root completes",
			input:     "ord",
			wantValue: "order ",
			wantHint:  "",
		},
		{
			name:      "order subcommands show compact hints",
			input:     "order ",
			wantValue: "order ",
			wantHint:  "exec <cmd>  env  recon  cloud-query <provider> <query-type>  oidc pivot <provider> [args...] | oidc audience=<value>  transfer <upload|download|list> <path> [base64_data]  upload <remote_path> <base64_data>  download <path>",
		},
		{
			name:      "order exec shows subcommand hint",
			input:     "order exec ",
			wantValue: "order exec ",
			wantHint:  "exec <cmd>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel(Config{})
			m.phase = PhasePostExploit
			m.input.SetValue(tt.input)

			ok := m.completeInput()

			assert.True(t, ok)
			assert.Equal(t, tt.wantValue, m.input.Value())
			assert.Equal(t, tt.wantHint, m.completionHint)
		})
	}
}
