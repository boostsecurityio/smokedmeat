// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"testing"

	"github.com/boostsecurityio/poutine/models"
	"github.com/stretchr/testify/assert"
)

func TestDetermineBashContextForFinding(t *testing.T) {
	tests := []struct {
		name     string
		run      string
		expected string
	}{
		{
			name:     "unquoted",
			run:      "echo ${{ github.head_ref }}",
			expected: bashContextUnquoted,
		},
		{
			name:     "double quoted",
			run:      `echo "${{ github.head_ref }}"`,
			expected: bashContextDoubleQuoted,
		},
		{
			name:     "unquoted no spaces",
			run:      "echo ${{github.head_ref}}",
			expected: bashContextUnquoted,
		},
		{
			name:     "double quoted mixed spaces",
			run:      `echo "${{ github.head_ref}}"`,
			expected: bashContextDoubleQuoted,
		},
		{
			name:     "single quoted",
			run:      "echo '${{ github.event.comment.body }}'",
			expected: bashContextSingleQuoted,
		},
		{
			name:     "single quoted with surrounding text",
			run:      "echo 'prefix ${{ github.event.comment.body }} suffix'",
			expected: bashContextSingleQuoted,
		},
		{
			name:     "double quoted with surrounding text",
			run:      `echo "prefix ${{ github.head_ref }} suffix"`,
			expected: bashContextDoubleQuoted,
		},
		{
			name:     "double quoted in concatenated word",
			run:      `ref=prefix"${{ github.head_ref }}"suffix`,
			expected: bashContextDoubleQuoted,
		},
		{
			name: "unquoted heredoc",
			run: `cat <<EOF
${{ github.head_ref }}
EOF`,
			expected: bashContextHeredoc,
		},
		{
			name:     "tab stripping heredoc",
			run:      "cat <<-EOF\n\t${{ github.head_ref }}\n\tEOF",
			expected: bashContextHeredoc,
		},
		{
			name: "quoted heredoc",
			run: `cat <<'EOF'
${{ github.event.comment.body }}
EOF`,
			expected: bashContextQuotedHeredoc,
		},
		{
			name: "double quoted heredoc delimiter",
			run: `cat <<"EOF"
${{ github.event.comment.body }}
EOF`,
			expected: bashContextQuotedHeredoc,
		},
		{
			name: "escaped heredoc delimiter",
			run: `cat <<\EOF
${{ github.event.comment.body }}
EOF`,
			expected: bashContextQuotedHeredoc,
		},
		{
			name: "recover incomplete bash",
			run: `if true; then
  echo "${{ github.head_ref }}"`,
			expected: bashContextDoubleQuoted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := "github.head_ref"
			if tt.expected == bashContextSingleQuoted || tt.expected == bashContextQuotedHeredoc {
				source = "github.event.comment.body"
			}
			workflows := []models.GithubActionsWorkflow{{
				Path: ".github/workflows/ci.yml",
				Jobs: models.GithubActionsJobs{{
					ID: "build",
					Steps: models.GithubActionsSteps{{
						Name: "run",
						Run:  tt.run,
						Line: 12,
						Lines: map[string]int{
							"run": 12,
						},
					}},
				}},
			}}

			got := determineBashContextForFinding(workflows, ".github/workflows/ci.yml", "build", "run", 12, []string{source})
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestDetermineBashContextForFinding_NoMatch(t *testing.T) {
	workflows := []models.GithubActionsWorkflow{{
		Path: ".github/workflows/ci.yml",
		Jobs: models.GithubActionsJobs{{
			ID: "build",
			Steps: models.GithubActionsSteps{{
				Name: "run",
				Run:  "echo hello",
				Line: 12,
				Lines: map[string]int{
					"run": 12,
				},
			}},
		}},
	}}

	got := determineBashContextForFinding(workflows, ".github/workflows/ci.yml", "build", "run", 12, []string{"github.head_ref"})
	assert.Empty(t, got)
}

func TestDetermineBashContextForFinding_LeavesBashContextUnsetWhenPrimarySourceIsAbsent(t *testing.T) {
	workflows := []models.GithubActionsWorkflow{{
		Path: ".github/workflows/ci.yml",
		Jobs: models.GithubActionsJobs{{
			ID: "build",
			Steps: models.GithubActionsSteps{{
				Name: "run",
				Run:  `echo "${{github.head_ref}}"`,
				Line: 12,
				Lines: map[string]int{
					"run": 12,
				},
			}},
		}},
	}}

	got := determineBashContextForFinding(
		workflows,
		".github/workflows/ci.yml",
		"build",
		"run",
		12,
		[]string{"github.event.comment.body", "github.head_ref"},
	)
	assert.Empty(t, got)
}

func TestDetermineBashContextForFinding_ReplacesAllExpressionsBeforeParsing(t *testing.T) {
	workflows := []models.GithubActionsWorkflow{{
		Path: ".github/workflows/ci.yml",
		Jobs: models.GithubActionsJobs{{
			ID: "build",
			Steps: models.GithubActionsSteps{{
				Name: "run",
				Run:  `echo "${{ github.base_ref }}" "${{ github.head_ref }}"`,
				Line: 12,
				Lines: map[string]int{
					"run": 12,
				},
			}},
		}},
	}}

	got := determineBashContextForFinding(
		workflows,
		".github/workflows/ci.yml",
		"build",
		"run",
		12,
		[]string{"github.head_ref", "github.base_ref"},
	)
	assert.Equal(t, bashContextDoubleQuoted, got)
}

func TestDetermineBashContextForFinding_UsesPrimaryInjectionSourceContext(t *testing.T) {
	workflows := []models.GithubActionsWorkflow{{
		Path: ".github/workflows/ci.yml",
		Jobs: models.GithubActionsJobs{{
			ID: "build",
			Steps: models.GithubActionsSteps{{
				Name: "run",
				Run:  `echo '${{ github.event.comment.body }}' "${{ github.head_ref }}"`,
				Line: 12,
				Lines: map[string]int{
					"run": 12,
				},
			}},
		}},
	}}

	got := determineBashContextForFinding(
		workflows,
		".github/workflows/ci.yml",
		"build",
		"run",
		12,
		[]string{"github.head_ref", "github.event.comment.body"},
	)
	assert.Equal(t, bashContextDoubleQuoted, got)
}

func TestDetermineBashContextForFinding_IgnoresHereString(t *testing.T) {
	workflows := []models.GithubActionsWorkflow{{
		Path: ".github/workflows/ci.yml",
		Jobs: models.GithubActionsJobs{{
			ID: "build",
			Steps: models.GithubActionsSteps{{
				Name: "run",
				Run: `cat <<< "banner"
echo 'prefix ${{ github.event.comment.body }} suffix'`,
				Line: 12,
				Lines: map[string]int{
					"run": 12,
				},
			}},
		}},
	}}

	got := determineBashContextForFinding(
		workflows,
		".github/workflows/ci.yml",
		"build",
		"run",
		12,
		[]string{"github.event.comment.body"},
	)
	assert.Equal(t, bashContextSingleQuoted, got)
}
