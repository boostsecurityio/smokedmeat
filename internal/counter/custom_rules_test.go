// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package counter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func TestBuildCustomRulePack_LoadsRecursiveRegoFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.rego"), []byte("package rules.one\n"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(root, "nested"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "two.rego"), []byte("package rules.two\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "notes.txt"), []byte("ignored\n"), 0o600))

	pack, err := BuildCustomRulePack(PoutineConfig{
		CustomRules: CustomRulesConfig{
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

func TestBuildCustomRulePack_InvalidMapping(t *testing.T) {
	_, err := BuildCustomRulePack(PoutineConfig{
		CustomRules: CustomRulesConfig{
			RuleMappings: map[string]poutine.CustomRuleMapping{
				"custom": {ExploitClass: "invalid"},
			},
		},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid exploit_class")
}
