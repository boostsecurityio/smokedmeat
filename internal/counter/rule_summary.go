// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

type RuleMappingSummary struct {
	RuleID       string
	ExploitClass string
}

type RuleSummary struct {
	ConfigPath             string
	CustomRulesEnabled     bool
	CustomRulesPath        string
	CustomRulesDefaultPath bool
	CustomRulesPathExists  bool
	DisableBuiltinRules    bool
	BuiltinRules           []string
	CustomRuleFiles        []string
	RuleMappings           []RuleMappingSummary
	UnmappedRuleDefault    string
}

func BuildRuleSummary(cfg PoutineConfig) (RuleSummary, error) {
	custom := cfg.CustomRules
	enabled := custom.Enabled == nil || *custom.Enabled

	path, usedDefault, err := customRulesPath(custom.Path)
	if err != nil {
		return RuleSummary{}, err
	}

	summary := RuleSummary{
		ConfigPath:             ConfigPath(),
		CustomRulesEnabled:     enabled,
		CustomRulesPath:        path,
		CustomRulesDefaultPath: usedDefault,
		DisableBuiltinRules:    enabled && custom.DisableBuiltinRules,
		UnmappedRuleDefault:    poutine.ExploitClassAnalyzeOnly,
	}
	if !summary.DisableBuiltinRules {
		summary.BuiltinRules = append([]string(nil), poutine.OffensiveRules...)
		summary.UnmappedRuleDefault = "built-in defaults"
	}
	if !enabled {
		return summary, nil
	}
	if validateErr := validateRuleMappings(custom.RuleMappings); validateErr != nil {
		return RuleSummary{}, validateErr
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) && usedDefault {
			summary.RuleMappings = summarizeRuleMappings(custom.RuleMappings)
			return summary, nil
		}
		return RuleSummary{}, err
	}
	if !info.IsDir() {
		return RuleSummary{}, &notDirectoryError{path: path}
	}
	summary.CustomRulesPathExists = true

	files, err := loadCustomRuleFiles(path)
	if err != nil {
		return RuleSummary{}, err
	}
	summary.CustomRuleFiles = make([]string, 0, len(files))
	for _, file := range files {
		summary.CustomRuleFiles = append(summary.CustomRuleFiles, filepath.ToSlash(file.Path))
	}
	summary.RuleMappings = summarizeRuleMappings(custom.RuleMappings)

	return summary, nil
}

type notDirectoryError struct {
	path string
}

func (e *notDirectoryError) Error() string {
	return "custom rules path is not a directory: " + e.path
}

func summarizeRuleMappings(mappings map[string]poutine.CustomRuleMapping) []RuleMappingSummary {
	if len(mappings) == 0 {
		return nil
	}
	out := make([]RuleMappingSummary, 0, len(mappings))
	for ruleID, mapping := range mappings {
		out = append(out, RuleMappingSummary{
			RuleID:       strings.TrimSpace(ruleID),
			ExploitClass: strings.TrimSpace(mapping.ExploitClass),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
