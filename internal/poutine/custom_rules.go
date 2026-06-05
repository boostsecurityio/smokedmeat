// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

const (
	ExploitClassAnalyzeOnly           = "analyze_only"
	ExploitClassInjection             = "injection"
	ExploitClassUntrustedCheckoutExec = "untrusted_checkout_exec"
	DefaultCustomRuleMaxFiles         = 256
	DefaultCustomRuleMaxFileBytes     = 512 * 1024
	DefaultCustomRuleMaxPackBytes     = 5 * 1024 * 1024
	HardCustomRuleMaxFiles            = 4096
	HardCustomRuleMaxFileBytes        = 5 * 1024 * 1024
	HardCustomRuleMaxPackBytes        = 50 * 1024 * 1024
)

type CustomRuleFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CustomRuleMapping struct {
	ExploitClass string `json:"exploit_class" yaml:"exploit_class,omitempty"`
}

type CustomRuleLimits struct {
	MaxFiles     int   `json:"max_files,omitempty" yaml:"max_files,omitempty"`
	MaxFileBytes int64 `json:"max_file_bytes,omitempty" yaml:"max_file_bytes,omitempty"`
	MaxPackBytes int64 `json:"max_pack_bytes,omitempty" yaml:"max_pack_bytes,omitempty"`
}

type CustomRulePack struct {
	Files               []CustomRuleFile             `json:"files,omitempty"`
	DisableBuiltinRules bool                         `json:"disable_builtin_rules,omitempty"`
	RuleMappings        map[string]CustomRuleMapping `json:"rule_mappings,omitempty"`
	Limits              CustomRuleLimits             `json:"limits,omitempty"`
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

func NormalizeCustomRuleLimits(limits CustomRuleLimits) CustomRuleLimits {
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = DefaultCustomRuleMaxFiles
	}
	if limits.MaxFileBytes <= 0 {
		limits.MaxFileBytes = DefaultCustomRuleMaxFileBytes
	}
	if limits.MaxPackBytes <= 0 {
		limits.MaxPackBytes = DefaultCustomRuleMaxPackBytes
	}
	return limits
}

func CustomRuleLimitsValid(limits CustomRuleLimits) bool {
	limits = NormalizeCustomRuleLimits(limits)
	return limits.MaxFiles <= HardCustomRuleMaxFiles &&
		limits.MaxFileBytes <= HardCustomRuleMaxFileBytes &&
		limits.MaxPackBytes <= HardCustomRuleMaxPackBytes
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
