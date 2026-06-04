// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"context"
	"testing"

	poutinemodels "github.com/boostsecurityio/poutine/models"
	poutineresults "github.com/boostsecurityio/poutine/results"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomRuleOptions_DisableBuiltinsLoadsCustomHelpersInMemory(t *testing.T) {
	files := []CustomRuleFile{
		{
			Path: "utils2.rego",
			Content: `package custom_helpers

import rego.v1

enabled if true
`,
		},
		{
			Path: "custom.rego",
			Content: `# METADATA
# title: Custom Test Rule
# description: Custom test rule
# custom:
#   level: error
package rules.custom_test_rule

import data.custom_helpers
import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

results contains poutine.finding(rule, pkg.purl, {
	"path": ".github/workflows/ci.yml",
	"line": 1,
}) if {
	custom_helpers.enabled
	pkg := input.packages[_]
}
`,
		},
	}

	config := poutinemodels.DefaultConfig()
	opts := AnalysisOptions{CustomRulePack: &CustomRulePack{Files: files, DisableBuiltinRules: true}}
	applyAnalysisOptions(config, opts)

	opaClient, err := newOpaWithAnalysisOptions(context.Background(), config, opts)
	require.NoError(t, err)

	input := map[string]interface{}{
		"packages": []map[string]interface{}{
			{"purl": "pkg:github/acme/api"},
		},
	}
	var result poutineresults.FindingsResult
	err = opaClient.Eval(context.Background(), "data.poutine.queries.findings.result", input, &result)
	require.NoError(t, err)

	require.Len(t, result.Findings, 1)
	assert.Equal(t, "custom_test_rule", result.Findings[0].RuleId)
	assert.Contains(t, result.Rules, "custom_test_rule")
	assert.NotContains(t, result.Rules, "injection")
}

func TestExploitClassForRule_UsesMappings(t *testing.T) {
	mappings := map[string]CustomRuleMapping{
		"custom_test_rule": {ExploitClass: ExploitClassInjection},
	}

	assert.Equal(t, ExploitClassInjection, ExploitClassForRule("custom_test_rule", mappings))
	assert.Equal(t, ExploitClassUntrustedCheckoutExec, ExploitClassForRule("untrusted_checkout_exec", nil))
	assert.Equal(t, ExploitClassAnalyzeOnly, ExploitClassForRule("custom_audit_rule", nil))
}

func TestExploitClassForRuleWithDefault_PreservesBuiltinsWhenEnabled(t *testing.T) {
	assert.Equal(t, ExploitClassInjection, ExploitClassForRuleWithDefault("injection", nil, false))
	assert.Equal(t, ExploitClassUntrustedCheckoutExec, ExploitClassForRuleWithDefault("untrusted_checkout_exec", nil, false))
	assert.Equal(t, ExploitClassAnalyzeOnly, ExploitClassForRuleWithDefault("custom_audit_rule", nil, false))
}

func TestExploitClassForRuleWithDefault_CustomModeDefaultsUnmappedToAnalyzeOnly(t *testing.T) {
	mappings := map[string]CustomRuleMapping{
		"custom_injection_rule": {ExploitClass: ExploitClassInjection},
	}

	assert.Equal(t, ExploitClassAnalyzeOnly, ExploitClassForRuleWithDefault("injection", mappings, true))
	assert.Equal(t, ExploitClassAnalyzeOnly, ExploitClassForRuleWithDefault("untrusted_checkout_exec", mappings, true))
	assert.Equal(t, ExploitClassAnalyzeOnly, ExploitClassForRuleWithDefault("custom_audit_rule", mappings, true))
	assert.Equal(t, ExploitClassInjection, ExploitClassForRuleWithDefault("custom_injection_rule", mappings, true))
}
