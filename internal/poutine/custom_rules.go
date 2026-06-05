// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

const (
	ExploitClassAnalyzeOnly           = "analyze_only"
	ExploitClassInjection             = "injection"
	ExploitClassUntrustedCheckoutExec = "untrusted_checkout_exec"
)

type CustomRuleFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CustomRuleMapping struct {
	ExploitClass string `json:"exploit_class" yaml:"exploit_class,omitempty"`
}

type CustomRulePack struct {
	Files               []CustomRuleFile             `json:"files,omitempty"`
	DisableBuiltinRules bool                         `json:"disable_builtin_rules,omitempty"`
	RuleMappings        map[string]CustomRuleMapping `json:"rule_mappings,omitempty"`
}

type AnalysisOptions struct {
	CustomRulePack *CustomRulePack
}

func ValidExploitClass(class string) bool {
	switch class {
	case "", ExploitClassAnalyzeOnly, ExploitClassInjection, ExploitClassUntrustedCheckoutExec:
		return true
	default:
		return false
	}
}

func DefaultExploitClass(ruleID string) string {
	switch ruleID {
	case "injection":
		return ExploitClassInjection
	case "untrusted_checkout_exec":
		return ExploitClassUntrustedCheckoutExec
	default:
		return ExploitClassAnalyzeOnly
	}
}

func ExploitClassForRule(ruleID string, mappings map[string]CustomRuleMapping) string {
	return ExploitClassForRuleWithDefault(ruleID, mappings, false)
}

func ExploitClassForRuleWithDefault(ruleID string, mappings map[string]CustomRuleMapping, defaultAnalyzeOnly bool) string {
	if mapping, ok := mappings[ruleID]; ok {
		if ValidExploitClass(mapping.ExploitClass) && mapping.ExploitClass != "" {
			return mapping.ExploitClass
		}
	}
	if defaultAnalyzeOnly {
		return ExploitClassAnalyzeOnly
	}
	return DefaultExploitClass(ruleID)
}
