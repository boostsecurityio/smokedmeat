// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

const (
	defaultCustomRulesDirName = "rules"
	maxCustomRuleFiles        = 256
	maxCustomRuleFileBytes    = 512 * 1024
	maxCustomRulePackBytes    = 5 * 1024 * 1024
)

func BuildCustomRulePack(cfg PoutineConfig) (*poutine.CustomRulePack, error) {
	custom := cfg.CustomRules
	if custom.Enabled != nil && !*custom.Enabled {
		return nil, nil
	}
	if err := validateRuleMappings(custom.RuleMappings); err != nil {
		return nil, err
	}

	path, usedDefault, err := customRulesPath(custom.Path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) && usedDefault {
			if len(custom.RuleMappings) == 0 && !custom.DisableBuiltinRules {
				return nil, nil
			}
			return &poutine.CustomRulePack{
				DisableBuiltinRules: custom.DisableBuiltinRules,
				RuleMappings:        cloneRuleMappings(custom.RuleMappings),
			}, nil
		}
		return nil, fmt.Errorf("custom rules path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("custom rules path is not a directory: %s", path)
	}

	files, err := loadCustomRuleFiles(path)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 && len(custom.RuleMappings) == 0 && !custom.DisableBuiltinRules {
		return nil, nil
	}

	return &poutine.CustomRulePack{
		Files:               files,
		DisableBuiltinRules: custom.DisableBuiltinRules,
		RuleMappings:        cloneRuleMappings(custom.RuleMappings),
	}, nil
}

func customRulesPath(path string) (rulePath string, usedDefault bool, err error) {
	if strings.TrimSpace(path) == "" {
		dir := configDir()
		return filepath.Join(dir, defaultCustomRulesDirName), true, nil
	}
	expanded, err := expandUserPath(path)
	if err != nil {
		return "", false, err
	}
	return expanded, false, nil
}

func configDir() string {
	if dir := os.Getenv("SMOKEDMEAT_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".smokedmeat")
}

func expandUserPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func loadCustomRuleFiles(root string) ([]poutine.CustomRuleFile, error) {
	var files []poutine.CustomRuleFile
	totalBytes := int64(0)

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".rego" {
			return nil
		}
		if len(files) >= maxCustomRuleFiles {
			return fmt.Errorf("custom rule pack exceeds %d files", maxCustomRuleFiles)
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxCustomRuleFileBytes {
			return fmt.Errorf("custom rule file %s exceeds %d bytes", path, maxCustomRuleFileBytes)
		}
		totalBytes += info.Size()
		if totalBytes > maxCustomRulePackBytes {
			return fmt.Errorf("custom rule pack exceeds %d bytes", maxCustomRulePackBytes)
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !safeRulePath(rel) {
			return fmt.Errorf("unsafe custom rule path: %s", rel)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, poutine.CustomRuleFile{
			Path:    rel,
			Content: string(data),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	return files, nil
}

func safeRulePath(path string) bool {
	if path == "" || strings.ContainsRune(path, 0) || strings.HasPrefix(path, "/") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validateRuleMappings(mappings map[string]poutine.CustomRuleMapping) error {
	for ruleID, mapping := range mappings {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			return fmt.Errorf("custom rule mapping has an empty rule ID")
		}
		if !poutine.ValidExploitClass(strings.TrimSpace(mapping.ExploitClass)) {
			return fmt.Errorf("custom rule mapping %s has invalid exploit_class %q", ruleID, mapping.ExploitClass)
		}
	}
	return nil
}

func cloneRuleMappings(mappings map[string]poutine.CustomRuleMapping) map[string]poutine.CustomRuleMapping {
	if len(mappings) == 0 {
		return nil
	}
	clone := make(map[string]poutine.CustomRuleMapping, len(mappings))
	for key, value := range mappings {
		clone[strings.TrimSpace(key)] = poutine.CustomRuleMapping{
			ExploitClass: strings.TrimSpace(value.ExploitClass),
		}
	}
	return clone
}
