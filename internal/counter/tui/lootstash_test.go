// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func TestModel_RenderLootStash_Empty(t *testing.T) {
	m := NewModel(Config{})

	output := m.RenderLootStash(40, 10)

	assert.Contains(t, output, "Loot Stash")
	assert.Contains(t, output, "No loot collected yet")
}

func TestModel_RenderLootStash_WithLoot(t *testing.T) {
	m := NewModel(Config{})
	m.lootStash = []CollectedSecret{
		{Name: "AWS_KEY", Value: "AKIA...", Source: "env"},
		{Name: "NPM_TOKEN", Value: "npm_...", Source: "env"},
	}

	output := m.RenderLootStash(50, 15)

	assert.Contains(t, output, "Loot Stash")
	assert.Contains(t, output, "AWS_KEY")
	assert.Contains(t, output, "NPM_TOKEN")
}

func TestModel_AddToLootStash(t *testing.T) {
	m := NewModel(Config{})

	secret := CollectedSecret{Name: "TEST_KEY", Value: "secret123"}
	m.AddToLootStash(secret)

	assert.Len(t, m.lootStash, 1)
	assert.Equal(t, "TEST_KEY", m.lootStash[0].Name)
}

func TestModel_AddToLootStash_NoDuplicates(t *testing.T) {
	m := NewModel(Config{})

	secret := CollectedSecret{Name: "TEST_KEY", Value: "secret123", Type: "generic"}
	m.AddToLootStash(secret)
	m.AddToLootStash(secret)

	// Should only have one entry (dedupe on name+type+value)
	assert.Len(t, m.lootStash, 1)
}

func TestModel_AddToLootStash_DifferentValueNotDupe(t *testing.T) {
	m := NewModel(Config{})

	secret1 := CollectedSecret{Name: "API_KEY", Value: "key1", Type: "generic"}
	secret2 := CollectedSecret{Name: "API_KEY", Value: "key2", Type: "generic"}
	m.AddToLootStash(secret1)
	m.AddToLootStash(secret2)

	// Different values should both be kept
	assert.Len(t, m.lootStash, 2)
}

func TestModel_AddToLootStash_SameOriginReplacesOlderValue(t *testing.T) {
	m := NewModel(Config{})

	oldSecret := CollectedSecret{
		Name:        "GOOGLE_APPLICATION_CREDENTIALS",
		Value:       "/tmp/old-creds.json",
		Type:        "gcp",
		Repository:  "whooli/xyz",
		Workflow:    ".github/workflows/oidc-test.yml",
		Job:         "process",
		CollectedAt: time.Now().Add(-2 * time.Minute),
		Source:      "agent:old:env",
	}
	newSecret := CollectedSecret{
		Name:        "GOOGLE_APPLICATION_CREDENTIALS",
		Value:       "/tmp/new-creds.json",
		Type:        "gcp",
		Repository:  "whooli/xyz",
		Workflow:    ".github/workflows/oidc-test.yml",
		Job:         "process",
		CollectedAt: time.Now(),
		Source:      "agent:new:env",
	}

	m.AddToLootStash(oldSecret)
	m.AddToLootStash(newSecret)

	require.Len(t, m.lootStash, 1)
	assert.Equal(t, "/tmp/new-creds.json", m.lootStash[0].Value)
	assert.Equal(t, "whooli/xyz", m.lootStash[0].Repository)
}

func TestModel_AddToLootStash_SameValueDifferentSourceIsDupe(t *testing.T) {
	m := NewModel(Config{})

	secret1 := CollectedSecret{Name: "GRAB_ME", Value: "flag123", Type: "generic", Source: "agent:agt_1:env"}
	secret2 := CollectedSecret{Name: "GRAB_ME", Value: "flag123", Type: "generic", Source: "agent:agt_2:env"}
	m.AddToLootStash(secret1)
	m.AddToLootStash(secret2)

	// Same name+type+value from different sources should be deduped
	assert.Len(t, m.lootStash, 1)
}

func TestModel_AddToSessionLoot(t *testing.T) {
	m := NewModel(Config{})

	secret := CollectedSecret{Name: "SESSION_KEY", Value: "temp123"}
	m.AddToSessionLoot(secret)

	assert.Len(t, m.sessionLoot, 1)
	assert.Equal(t, "SESSION_KEY", m.sessionLoot[0].Name)
}

func TestModel_AddToSessionLoot_MergeRebuildsLootTreeWhenPlacementChanges(t *testing.T) {
	m := NewModel(Config{})

	m.AddToSessionLoot(CollectedSecret{
		Name:  "GITHUB_TOKEN",
		Value: "ghs_123",
		Type:  "github_token",
	})

	require.NotNil(t, findNodeByID(m.lootTreeRoot, "loot:repo:(unknown)"))

	m.AddToSessionLoot(CollectedSecret{
		Name:       "GITHUB_TOKEN",
		Value:      "ghs_123",
		Type:       "github_token",
		Repository: "acme/api",
		Workflow:   ".github/workflows/ci.yml",
		Job:        "build",
	})

	require.NotNil(t, findNodeByID(m.lootTreeRoot, "loot:repo:acme/api"))
	require.NotNil(t, findNodeByID(m.lootTreeRoot, "loot:wf:acme/api:.github/workflows/ci.yml:build"))
	assert.Nil(t, findNodeByID(m.lootTreeRoot, "loot:repo:(unknown)"))
}

func TestModel_AddToLootStash_MergeRebuildsLootTreeWhenPlacementChanges(t *testing.T) {
	m := NewModel(Config{})

	m.AddToLootStash(CollectedSecret{
		Name:  "PRIVATE_KEY",
		Value: "pem-data",
		Type:  "private_key",
	})

	require.NotNil(t, findNodeByID(m.lootTreeRoot, "loot:repo:(unknown)"))

	m.AddToLootStash(CollectedSecret{
		Name:       "PRIVATE_KEY",
		Value:      "pem-data",
		Type:       "private_key",
		Repository: "acme/api",
		Workflow:   "README.md",
		Job:        "extract",
	})

	require.NotNil(t, findNodeByID(m.lootTreeRoot, "loot:repo:acme/api"))
	require.NotNil(t, findNodeByID(m.lootTreeRoot, "loot:wf:acme/api:README.md:extract"))
	assert.Nil(t, findNodeByID(m.lootTreeRoot, "loot:repo:(unknown)"))
}

func TestModel_HandleLootSync_RestoresStoredLoot(t *testing.T) {
	m := NewModel(Config{})
	key := testSSHPrivateKey(t)

	result, cmd := m.handleLootSync(LootSyncMsg{Sync: counter.LootSyncPayload{
		Entries: []counter.LootSyncEntry{
			{
				Origin:     "analysis",
				Timestamp:  time.Now(),
				Name:       "Private Key detected (README.md:12)",
				Value:      key,
				Type:       "private_key",
				Source:     "acme/newcleus-core-v3:README.md:12",
				HighValue:  true,
				Repository: "acme/newcleus-core-v3",
				Workflow:   "README.md",
			},
			{
				Origin:           "express",
				AgentID:          "agent-1234567890",
				Timestamp:        time.Now(),
				Name:             "GITHUB_TOKEN",
				Value:            "ghs_1234567890",
				Type:             "github_token",
				Source:           "env",
				HighValue:        false,
				Repository:       "acme/newcleus-core-v3",
				Workflow:         ".github/workflows/ci.yml",
				Job:              "build",
				TokenPermissions: map[string]string{"contents": "read"},
			},
		},
	}})

	model := result.(Model)
	require.NotNil(t, cmd)
	require.Len(t, model.lootStash, 1)
	assert.Equal(t, "Private Key detected (README.md:12)", model.lootStash[0].Name)
	assert.Equal(t, "private_key", model.lootStash[0].Type)
	assert.Equal(t, "acme/newcleus-core-v3", model.lootStash[0].Repository)
	assert.Equal(t, "README.md", model.lootStash[0].Workflow)
	assert.NotEmpty(t, model.lootStash[0].KeyFingerprint)

	require.Len(t, model.sessionLoot, 1)
	assert.Equal(t, "GITHUB_TOKEN", model.sessionLoot[0].Name)
	assert.True(t, model.sessionLoot[0].ExpressMode)
	assert.True(t, model.sessionLoot[0].Ephemeral)
	assert.Equal(t, "agent:agent-12:env", model.sessionLoot[0].Source)
	assert.Equal(t, "read", model.displayPermissionsForSecret(model.sessionLoot[0])["contents"])
}

func TestRenderSelectedLootDetail_UsesKitchenTokenPermissionsForGitHubToken(t *testing.T) {
	m := NewModel(Config{})
	m.tokenPermissions = map[string]string{"actions": "write"}
	m.appTokenPermissions = map[string]string{"issues": "write"}

	secret := CollectedSecret{
		Name:       "GITHUB_TOKEN",
		Value:      "ghs_repo_token_123456",
		Type:       "github_token",
		Repository: "acme/api",
		Workflow:   ".github/workflows/ci.yml",
		Job:        "build",
		AgentID:    "agt12345",
	}
	m.storeTokenDisplayPermissions(secret, map[string]string{"contents": "read"})

	out := strings.Join(m.renderSelectedLootDetail(secret), "\n")

	assert.Contains(t, out, "contents: read")
	assert.NotContains(t, out, "actions: write")
	assert.NotContains(t, out, "issues: write")
}

func TestRenderCompactLootDetail_UsesKitchenAppPermissionsForPairedKey(t *testing.T) {
	m := NewModel(Config{})
	m.appTokenPermissions = map[string]string{"metadata": "read"}

	secret := CollectedSecret{
		Name:        "APP_PRIVATE_KEY",
		Value:       "-----BEGIN RSA PRIVATE KEY-----",
		Type:        "github_app_key",
		PairedAppID: "12345",
	}
	m.storeAppDisplayPermissions("12345", map[string]string{"issues": "write"})

	out := strings.Join(m.renderCompactLootDetail(secret, 80), "\n")

	assert.Contains(t, out, "issues: write")
	assert.NotContains(t, out, "metadata: read")
}

func TestRenderCompactLootDetail_GitHubTokenNameBeatsMisclassifiedAppType(t *testing.T) {
	m := NewModel(Config{})
	m.appTokenPermissions = map[string]string{"issues": "write"}

	secret := CollectedSecret{
		Name:       "GITHUB_TOKEN",
		Value:      "ghs_repo_token_123456",
		Type:       "github_app_token",
		Repository: "acme/api",
		Workflow:   ".github/workflows/ci.yml",
		Job:        "build",
		AgentID:    "agt12345",
	}
	m.storeTokenDisplayPermissions(secret, map[string]string{"contents": "read"})

	out := strings.Join(m.renderCompactLootDetail(secret, 80), "\n")

	assert.Contains(t, out, "contents: read")
	assert.NotContains(t, out, "issues: write")
}

func TestModel_RenderLootStash_Height(t *testing.T) {
	m := NewModel(Config{})

	output := m.RenderLootStash(40, 8)
	lines := strings.Split(output, "\n")

	assert.Equal(t, 8, len(lines), "Should produce exact height")
}

func TestBuildLootTree_PairsGitHubApp(t *testing.T) {
	m := NewModel(Config{})
	m.lootStash = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			Type:        "github_app_key",
			PairedAppID: "12345",
			Repository:  "whooli/xyz",
			Workflow:    "whooli-analyzer.yml",
			Job:         "analyze",
		},
	}

	root := m.BuildLootTree()

	var secretNodes []*TreeNode
	var walk func(n *TreeNode)
	walk = func(n *TreeNode) {
		if n.Type == TreeNodeSecret {
			secretNodes = append(secretNodes, n)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(root)

	assert.Len(t, secretNodes, 1, "paired App should produce a single secret node")
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", secretNodes[0].Label)
}

func TestSelectedLootSecret_PairedGitHubAppUsesCanonicalLootEntry(t *testing.T) {
	m := NewModel(Config{})
	m.lootStash = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "pem-before",
			Type:        "github_app_key",
			PairedAppID: "12345",
			Repository:  "whooli/xyz",
			Workflow:    "whooli-analyzer.yml",
			Job:         "analyze",
		},
	}

	m.RebuildLootTree()
	require.True(t, m.LootTreeSelectByID("loot:secret:WHOOLI_BOT_APP_PRIVATE_KEY:whooli/xyz"))

	m.lootStash[0].Value = "pem-after"

	require.NotNil(t, m.SelectedLootSecret())
	assert.Equal(t, "pem-after", m.SelectedLootSecret().Value)
}

func TestBuildLootTree_UnpairedSecretsUnchanged(t *testing.T) {
	m := NewModel(Config{})
	m.lootStash = []CollectedSecret{
		{Name: "AWS_KEY", Value: "AKIA...", Repository: "org/repo", Workflow: "ci.yml"},
		{Name: "NPM_TOKEN", Value: "npm_...", Repository: "org/repo", Workflow: "ci.yml"},
	}

	root := m.BuildLootTree()

	var secretNodes []*TreeNode
	var walk func(n *TreeNode)
	walk = func(n *TreeNode) {
		if n.Type == TreeNodeSecret {
			secretNodes = append(secretNodes, n)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(root)

	assert.Len(t, secretNodes, 2, "unpaired secrets should each produce their own node")
}

func TestBuildLootTree_ExpandsAnalysisFocusRepo(t *testing.T) {
	m := NewModel(Config{})
	m.target = "whooli"
	m.targetType = "org"
	m.analysisFocusRepo = "whooli/newcleus-core-v3"
	m.lootStash = []CollectedSecret{
		{Name: "A", Value: "a", Repository: "whooli/xyz"},
		{Name: "B", Value: "b", Repository: "whooli/newcleus-core-v3"},
	}

	root := m.BuildLootTree()

	require.Len(t, root.Children, 2)
	var focused *TreeNode
	for _, child := range root.Children {
		if child.Label == "whooli/newcleus-core-v3" {
			focused = child
			break
		}
	}
	require.NotNil(t, focused)
	assert.True(t, focused.Expanded)
}

func TestRenderLootNode_PairedGitHubApp(t *testing.T) {
	m := NewModel(Config{})
	secret := &CollectedSecret{
		Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
		Value:       "-----BEGIN RSA PRIVATE KEY-----",
		Type:        "github_app_key",
		PairedAppID: "12345",
	}
	node := &TreeNode{
		ID:    "loot:secret:test",
		Label: secret.Name,
		Type:  TreeNodeSecret,
		Depth: 2,
		Properties: map[string]interface{}{
			"secret": secret,
		},
	}

	line := m.renderLootNode(node, 80, false)

	assert.Contains(t, line, "GitHub App")
	assert.Contains(t, line, "WHOOLI_BOT_APP_PRIVATE_KEY")
	assert.Contains(t, line, "[pivot]")
}

func TestRenderLootNode_AddsGitHubHyperlinks(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	repo := &TreeNode{ID: "repo:whooli/xyz", Label: "whooli/xyz", Type: TreeNodeRepo}
	workflow := &TreeNode{ID: "wf:ci", Label: ".github/workflows/ci.yml", Type: TreeNodeWorkflow, Parent: repo}

	repoLine := m.renderLootNode(repo, 80, false)
	workflowLine := m.renderLootNode(workflow, 100, false)

	assert.Contains(t, repoLine, "https://github.com/whooli/xyz")
	assert.Contains(t, workflowLine, "https://github.com/whooli/xyz/blob/HEAD/.github/workflows/ci.yml")
}

func TestBuildLootTree_PrivateRepoFromKnownEntities(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.lootStash = []CollectedSecret{
		{Name: "GITHUB_TOKEN", Value: "ghs_xxx", Repository: "acme/secret-infra", Workflow: "ci.yml"},
	}
	m.knownEntities["repo:acme/secret-infra"] = &KnownEntity{
		ID:         "repo:acme/secret-infra",
		EntityType: "repo",
		Name:       "acme/secret-infra",
		IsPrivate:  true,
	}

	root := m.BuildLootTree()

	require.Len(t, root.Children, 1)
	repoNode := root.Children[0]
	assert.Equal(t, "acme/secret-infra", repoNode.Label)
	assert.Equal(t, TreeStateHighValue, repoNode.State,
		"loot tree repo node should be marked HighValue when knownEntity.IsPrivate is true")
}

func TestBuildLootTree_ExpandsCurrentTargetRepo(t *testing.T) {
	m := NewModel(Config{SessionID: "test"})
	m.targetType = "repo"
	m.target = "acme/private-infra"
	m.lootStash = []CollectedSecret{
		{Name: "DEPLOY_KEY", Value: "key", Repository: "acme/private-infra", Workflow: "ci.yml"},
		{Name: "OTHER_KEY", Value: "other", Repository: "acme/other-repo", Workflow: "ci.yml"},
	}

	root := m.BuildLootTree()

	require.Len(t, root.Children, 2)
	for _, repoNode := range root.Children {
		if repoNode.Label == "acme/private-infra" {
			assert.True(t, repoNode.Expanded)
			return
		}
	}
	t.Fatalf("target repo node not found")
}

func TestBuildLootTree_StableOrdering(t *testing.T) {
	m := NewModel(Config{})
	m.lootStash = []CollectedSecret{
		{Name: "KEY_A", Value: "a", Repository: "zebra/repo"},
		{Name: "KEY_B", Value: "b", Repository: "alpha/repo"},
		{Name: "KEY_C", Value: "c", Repository: "middle/repo"},
	}

	first := m.BuildLootTree()
	firstOrder := make([]string, len(first.Children))
	for i, c := range first.Children {
		firstOrder[i] = c.Label
	}

	for i := 0; i < 20; i++ {
		rebuilt := m.BuildLootTree()
		for j, c := range rebuilt.Children {
			assert.Equal(t, firstOrder[j], c.Label,
				"iteration %d: repo order should be stable", i)
		}
	}

	assert.Equal(t, "alpha/repo", firstOrder[0], "repos should be sorted alphabetically")
	assert.Equal(t, "middle/repo", firstOrder[1])
	assert.Equal(t, "zebra/repo", firstOrder[2])
}

func TestModel_ExportableLoot_IncludesSessionLoot(t *testing.T) {
	m := NewModel(Config{})
	now := time.Now()
	m.lootStash = []CollectedSecret{
		{Name: "PAT", Value: "ghp_abc", Type: "github_pat", CollectedAt: now},
	}
	m.sessionLoot = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "pem-data",
			Type:        "github_app_key",
			PairedAppID: "12345",
			CollectedAt: now,
		},
		{Name: "GITHUB_TOKEN", Value: "ghs_short", Type: "github_token", CollectedAt: now},
	}

	exportable := m.exportableLoot()

	require.Len(t, exportable, 2)
	assert.Equal(t, "PAT", exportable[0].Name)
	assert.Equal(t, "WHOOLI_BOT_APP_PRIVATE_KEY", exportable[1].Name)
	assert.Equal(t, "12345", exportable[1].PairedAppID)
}

func TestModel_ExportLootCmd_PersistsSessionLoot(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SMOKEDMEAT_CONFIG_DIR", tempDir)

	m := NewModel(Config{})
	m.sessionLoot = []CollectedSecret{
		{
			Name:        "WHOOLI_BOT_APP_PRIVATE_KEY",
			Value:       "pem-data",
			Type:        "github_app_key",
			PairedAppID: "12345",
			CollectedAt: time.Now(),
		},
	}

	msg := m.exportLootCmd()()
	exported, ok := msg.(LootExportedMsg)
	require.True(t, ok)
	require.NoError(t, exported.Err)
	assert.Equal(t, 1, exported.Count)

	data, err := os.ReadFile(filepath.Join(tempDir, "tokens.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "WHOOLI_BOT_APP_PRIVATE_KEY")
	assert.Contains(t, string(data), "paired_app_id: \"12345\"")
}

func TestMergeCollectedSecretMetadata_PrefersNewerOrigin(t *testing.T) {
	m := NewModel(Config{})
	older := CollectedSecret{
		Name:           "Private Key detected (test.md:4)",
		Value:          "same-secret",
		Type:           "private_key",
		Repository:     "whooli/xyz",
		Workflow:       "test.md",
		Source:         "whooli/xyz:test.md:4",
		KeyFingerprint: "SHA256:old",
		CollectedAt:    time.Now().Add(-time.Minute),
	}
	newer := CollectedSecret{
		Name:           "Private Key detected (README.md:12)",
		Value:          "same-secret",
		Type:           "private_key",
		Repository:     "whooli/newcleus-core-v3",
		Workflow:       "README.md",
		Source:         "whooli/newcleus-core-v3:README.md:12",
		KeyFingerprint: "SHA256:new",
		CollectedAt:    time.Now(),
	}

	m.AddToLootStash(older)
	m.AddToLootStash(newer)

	require.Len(t, m.lootStash, 1)
	assert.Equal(t, "Private Key detected (README.md:12)", m.lootStash[0].Name)
	assert.Equal(t, "whooli/newcleus-core-v3", m.lootStash[0].Repository)
	assert.Equal(t, "README.md", m.lootStash[0].Workflow)
	assert.Equal(t, "whooli/newcleus-core-v3:README.md:12", m.lootStash[0].Source)
	assert.Equal(t, "SHA256:new", m.lootStash[0].KeyFingerprint)
}

func TestMergeCollectedSecretMetadata_PrefersIncomingOriginDespiteClockSkew(t *testing.T) {
	m := NewModel(Config{})
	existing := CollectedSecret{
		Name:           "Private Key detected (test.md:4)",
		Value:          "same-secret",
		Type:           "private_key",
		Repository:     "whooli/xyz",
		Workflow:       "test.md",
		Source:         "whooli/xyz:test.md:4",
		KeyFingerprint: "SHA256:old",
		CollectedAt:    time.Now().Add(30 * time.Second),
	}
	incoming := CollectedSecret{
		Name:           "Private Key detected (README.md:12)",
		Value:          "same-secret",
		Type:           "private_key",
		Repository:     "whooli/newcleus-core-v3",
		Workflow:       "README.md",
		Source:         "whooli/newcleus-core-v3:README.md:12",
		KeyFingerprint: "SHA256:new",
		CollectedAt:    time.Now(),
	}

	m.AddToLootStash(existing)
	m.AddToLootStash(incoming)

	require.Len(t, m.lootStash, 1)
	assert.Equal(t, "Private Key detected (README.md:12)", m.lootStash[0].Name)
	assert.Equal(t, "whooli/newcleus-core-v3", m.lootStash[0].Repository)
	assert.Equal(t, "README.md", m.lootStash[0].Workflow)
	assert.Equal(t, "whooli/newcleus-core-v3:README.md:12", m.lootStash[0].Source)
	assert.Equal(t, "SHA256:new", m.lootStash[0].KeyFingerprint)
}

func TestFormatLootSecretBadges_HidesPivotForExpiredExpressToken(t *testing.T) {
	m := NewModel(Config{})
	secret := &CollectedSecret{
		Name:        "GITHUB_TOKEN",
		Value:       "ghs_deadbeef",
		Type:        "github_token",
		Ephemeral:   true,
		ExpressMode: true,
	}

	badges := m.formatLootSecretBadges(secret)

	assert.Contains(t, badges, "[expired]")
	assert.NotContains(t, badges, "[pivot]")
}
