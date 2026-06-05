// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func TestBuildCustomRulePack_LoadsRecursiveRegoFiles(t *testing.T) {
	root := t.TempDir()
	enabled := true
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.rego"), []byte("package rules.one\n"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(root, "nested"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "two.rego"), []byte("package rules.two\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "notes.txt"), []byte("ignored\n"), 0o600))

	pack, err := BuildCustomRulePack(PoutineConfig{
		CustomRules: CustomRulesConfig{
			Enabled:             &enabled,
			Path:                root,
			DisableBuiltinRules: true,
			RuleMappings: map[string]poutine.CustomRuleMapping{
				"one": {ExploitClass: poutine.ExploitClassInjection},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, pack)

	assert.True(t, pack.DisableBuiltinRules)
	assert.Len(t, pack.Files, 2)
	assert.Equal(t, "nested/two.rego", pack.Files[0].Path)
	assert.Equal(t, "one.rego", pack.Files[1].Path)
	assert.Equal(t, poutine.ExploitClassInjection, pack.RuleMappings["one"].ExploitClass)
}

func TestBuildCustomRulePack_DefaultMissingDirectoryReturnsNil(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", t.TempDir())

	pack, err := BuildCustomRulePack(PoutineConfig{})
	require.NoError(t, err)
	assert.Nil(t, pack)
}

func TestBuildCustomRulePack_DefaultDirectoryRequiresExplicitEnable(t *testing.T) {
	configDir := t.TempDir()
	rulesDir := filepath.Join(configDir, "rules")
	require.NoError(t, os.Mkdir(rulesDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "custom.rego"), []byte("package rules.custom\n"), 0o600))
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", configDir)

	pack, err := BuildCustomRulePack(PoutineConfig{})
	require.NoError(t, err)
	assert.Nil(t, pack)
}

func TestBuildCustomRulePack_LoadsSymlinkedRuleFile(t *testing.T) {
	root := t.TempDir()
	enabled := true
	target := filepath.Join(t.TempDir(), "target.rego")
	require.NoError(t, os.WriteFile(target, []byte("package rules.target\n"), 0o600))
	err := os.Symlink(target, filepath.Join(root, "linked.rego"))
	if err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	pack, err := BuildCustomRulePack(PoutineConfig{
		CustomRules: CustomRulesConfig{Enabled: &enabled, Path: root},
	})
	require.NoError(t, err)
	require.NotNil(t, pack)
	require.Len(t, pack.Files, 1)
	assert.Equal(t, "linked.rego", pack.Files[0].Path)
	assert.Equal(t, "package rules.target\n", pack.Files[0].Content)
}

func TestBuildCustomRulePack_UsesConfiguredFileSizeLimit(t *testing.T) {
	root := t.TempDir()
	enabled := true
	content := strings.Repeat("a", poutine.DefaultCustomRuleMaxFileBytes+1)
	require.NoError(t, os.WriteFile(filepath.Join(root, "large.rego"), []byte(content), 0o600))

	pack, err := BuildCustomRulePack(PoutineConfig{
		CustomRules: CustomRulesConfig{
			Enabled: &enabled,
			Path:    root,
			Limits: poutine.CustomRuleLimits{
				MaxFileBytes: poutine.DefaultCustomRuleMaxFileBytes + 1,
			},
		},
	})

	require.NoError(t, err)
	require.NotNil(t, pack)
	require.Len(t, pack.Files, 1)
	assert.Equal(t, poutine.DefaultCustomRuleMaxFiles, pack.Limits.MaxFiles)
	assert.Equal(t, int64(poutine.DefaultCustomRuleMaxFileBytes+1), pack.Limits.MaxFileBytes)
}

func TestBuildCustomRulePack_InvalidMapping(t *testing.T) {
	enabled := true

	_, err := BuildCustomRulePack(PoutineConfig{
		CustomRules: CustomRulesConfig{
			Enabled: &enabled,
			RuleMappings: map[string]poutine.CustomRuleMapping{
				"custom": {ExploitClass: "invalid"},
			},
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid exploit_class")
}

func TestBuildRuleSummary_DefaultBuiltinRules(t *testing.T) {
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", t.TempDir())

	summary, err := BuildRuleSummary(PoutineConfig{})

	require.NoError(t, err)
	assert.False(t, summary.CustomRulesEnabled)
	assert.False(t, summary.CustomRulesExplicit)
	assert.False(t, summary.CustomRulesPathExists)
	assert.False(t, summary.DisableBuiltinRules)
	assert.Equal(t, poutine.OffensiveRules, summary.BuiltinRules)
	assert.Empty(t, summary.CustomRuleFiles)
	assert.Empty(t, summary.RuleMappings)
	assert.Equal(t, "built-in defaults", summary.UnmappedRuleDefault)
}

func TestBuildRuleSummary_CustomRulesDisableBuiltins(t *testing.T) {
	root := t.TempDir()
	enabled := true
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.rego"), []byte("package rules.one\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "two.rego"), []byte("package rules.two\n"), 0o600))

	summary, err := BuildRuleSummary(PoutineConfig{
		CustomRules: CustomRulesConfig{
			Enabled:             &enabled,
			Path:                root,
			DisableBuiltinRules: true,
			RuleMappings: map[string]poutine.CustomRuleMapping{
				"two": {ExploitClass: poutine.ExploitClassInjection},
				"one": {ExploitClass: poutine.ExploitClassAnalyzeOnly},
			},
		},
	})

	require.NoError(t, err)
	assert.True(t, summary.CustomRulesPathExists)
	assert.True(t, summary.DisableBuiltinRules)
	assert.Empty(t, summary.BuiltinRules)
	assert.Equal(t, []string{"one.rego", "two.rego"}, summary.CustomRuleFiles)
	require.Len(t, summary.RuleMappings, 2)
	assert.Equal(t, "one", summary.RuleMappings[0].RuleID)
	assert.Equal(t, poutine.ExploitClassAnalyzeOnly, summary.RuleMappings[0].ExploitClass)
	assert.Equal(t, "two", summary.RuleMappings[1].RuleID)
	assert.Equal(t, poutine.ExploitClassInjection, summary.RuleMappings[1].ExploitClass)
	assert.Equal(t, poutine.ExploitClassAnalyzeOnly, summary.UnmappedRuleDefault)
}
