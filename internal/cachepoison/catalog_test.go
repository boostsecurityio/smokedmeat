// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package cachepoison

import (
	"os"
	"path/filepath"
	"testing"

	poutinemodels "github.com/boostsecurityio/poutine/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCollectVictimCandidates_FindsCatalogedConsumers(t *testing.T) {
	workflow := poutinemodels.GithubActionsWorkflow{
		Path: ".github/workflows/deploy.yml",
		Events: poutinemodels.GithubActionsEvents{
			{Name: "schedule"},
		},
		Jobs: poutinemodels.GithubActionsJobs{
			{
				ID:   "deploy",
				Name: "Deploy",
				Steps: poutinemodels.GithubActionsSteps{
					{
						Uses: "actions/checkout@v4",
					},
					{
						Uses: "actions/setup-node@v4",
						With: poutinemodels.GithubActionsWith{
							{Name: "cache", Value: "npm"},
						},
					},
					{
						Uses: "actions/cache@v4",
						With: poutinemodels.GithubActionsWith{
							{Name: "key", Value: "node-${{ runner.os }}-${{ hashFiles('package-lock.json') }}"},
							{Name: "path", Value: "~/.npm\nnode_modules"},
						},
					},
				},
			},
		},
	}

	victims := CollectVictimCandidates("acme/api", "", workflow)
	require.Len(t, victims, 2)

	assert.Equal(t, StrategySetupNode, victims[0].Strategy)
	assert.Equal(t, "scheduled", victims[0].TriggerMode)
	assert.True(t, victims[0].Ready)
	assert.Equal(t, ExecutionKindCheckoutPost, victims[0].Execution.Kind)
	assert.Equal(t, StrategyActionsCache, victims[1].Strategy)
	assert.True(t, victims[1].Ready)
	assert.Equal(t, "ready", victims[1].Readiness)
	assert.Equal(t, ExecutionKindCheckoutPost, victims[1].Execution.Kind)
	assert.Equal(t, []string{"~/.npm", "node_modules"}, victims[1].PathPatterns)
}

func TestClassifyWriterEligible(t *testing.T) {
	assert.Contains(t, SupportedVictimActions(), "actions/setup-go")

	eligible, reason := ClassifyWriterEligible("injection", "issue_comment")
	assert.True(t, eligible)
	assert.Empty(t, reason)

	eligible, reason = ClassifyWriterEligible("shell_injection", "issue_comment")
	assert.False(t, eligible)
	assert.NotEmpty(t, reason)

	eligible, reason = ClassifyWriterEligible("injection", "pull_request")
	assert.False(t, eligible)
	assert.NotEmpty(t, reason)
}

func TestCollectVictimCandidates_HooliInfrastructureDefinitionsDeploy(t *testing.T) {
	const workflowYAML = `
name: Sync Compression Benchmarks

on:
  push:
    branches: [main]
    paths:
      - 'benchmarks/**'
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

jobs:
  sync:
    name: "Sync to Nucleus Data Lake"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Restore build cache
        uses: actions/cache@v4
        with:
          path: ./build-cache
          key: nucleus-build-${{ hashFiles('benchmarks/**') }}
          restore-keys: |
            nucleus-build-

      - name: Setup build environment
        run: |
          chmod +x build-cache/setup.sh
          source build-cache/setup.sh

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: "projects/${{ vars.GCP_PROJECT_NUMBER }}/locations/global/workloadIdentityPools/github-pool/providers/github-provider"
          service_account: "nucleus-deployer@${{ vars.GCP_PROJECT_ID }}.iam.gserviceaccount.com"
`

	var workflow poutinemodels.GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(workflowYAML), &workflow))
	workflow.Path = ".github/workflows/deploy.yml"

	victims := CollectVictimCandidates("whooli/infrastructure-definitions", "", workflow)
	require.Len(t, victims, 1)

	victim := victims[0]
	assert.Equal(t, StrategyActionsCache, victim.Strategy)
	assert.Equal(t, "actions/cache", victim.ConsumerAction)
	assert.Equal(t, ".github/workflows/deploy.yml", victim.Workflow)
	assert.Equal(t, "sync", victim.Job)
	assert.Equal(t, "scheduled", victim.TriggerMode)
	assert.Equal(t, "nucleus-build-${{ hashFiles('benchmarks/**') }}", victim.KeyTemplate)
	assert.Equal(t, []string{"./build-cache"}, victim.PathPatterns)
	assert.Equal(t, "actions/cache@v4", victim.CacheEntry.ActionUses)
	assert.Equal(t, "v4", victim.CacheEntry.ActionRef)
	assert.Equal(t, "actions/checkout post", victim.OverwriteTarget)
	assert.True(t, victim.Ready)
	assert.Equal(t, "ready", victim.Readiness)
	assert.True(t, victim.HasOIDC)
	assert.Equal(t, ExecutionKindCheckoutPost, victim.Execution.Kind)
	assert.Equal(t, "actions/checkout@v4", victim.Execution.GadgetUses)
	require.Len(t, victim.Execution.Checkouts, 1)
	assert.Equal(t, "actions/checkout@v4", victim.Execution.Checkouts[0].Uses)
	assert.Equal(t, "v4", victim.Execution.Checkouts[0].Ref)
}

func TestCollectVictimCandidates_ActionsCacheFallsBackToDirectExecWithoutCheckout(t *testing.T) {
	const workflowYAML = `
name: Cache Job

on:
  workflow_dispatch:

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - name: Restore build cache
        uses: actions/cache@v4
        with:
          path: ./build-cache
          key: nucleus-build-${{ hashFiles('benchmarks/**') }}

      - name: Setup build environment
        run: |
          chmod +x build-cache/setup.sh
          source build-cache/setup.sh
`

	var workflow poutinemodels.GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(workflowYAML), &workflow))
	workflow.Path = ".github/workflows/deploy.yml"

	victims := CollectVictimCandidates("whooli/infrastructure-definitions", "", workflow)
	require.Len(t, victims, 1)

	victim := victims[0]
	assert.Equal(t, ExecutionKindDirectCache, victim.Execution.Kind)
	assert.Equal(t, "build-cache/setup.sh", victim.Execution.TargetPath)
	assert.Equal(t, "direct cache exec · build-cache/setup.sh", victim.OverwriteTarget)
}

func TestClassifyWriterEligible_HooliInfrastructureDefinitionsLint(t *testing.T) {
	eligible, reason := ClassifyWriterEligible("untrusted_checkout_exec", "pull_request_target")
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestClassifyWriterEligible_HooliInfrastructureDefinitionsBenchmarkIntake(t *testing.T) {
	eligible, reason := ClassifyWriterEligible("injection", "issues, issue_comment")
	assert.True(t, eligible)
	assert.Empty(t, reason)
}

func TestCollectVictimCandidates_HooliInfrastructureDefinitionsRelease(t *testing.T) {
	const workflowYAML = `
name: Bench Tool Release

on:
  push:
    tags:
      - 'bench-v*'

permissions:
  contents: read

jobs:
  release:
    name: "Build Bench Tool Snapshot"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24.3'
          cache: true

      - name: Build release snapshot
        uses: goreleaser/goreleaser-action@v6
`

	var workflow poutinemodels.GithubActionsWorkflow
	require.NoError(t, yaml.Unmarshal([]byte(workflowYAML), &workflow))
	workflow.Path = ".github/workflows/release.yml"

	victims := CollectVictimCandidates("whooli/infrastructure-definitions", "", workflow)
	require.Len(t, victims, 1)

	victim := victims[0]
	assert.Equal(t, StrategySetupGo, victim.Strategy)
	assert.Equal(t, ".github/workflows/release.yml", victim.Workflow)
	assert.Equal(t, "release", victim.Job)
	assert.Equal(t, "automatic", victim.TriggerMode)
	assert.True(t, victim.Ready)
	assert.Equal(t, "ready", victim.Readiness)
	assert.Equal(t, ExecutionKindCheckoutPost, victim.Execution.Kind)
	assert.Equal(t, "actions/setup-go@v5", victim.Execution.GadgetUses)
	require.Len(t, victim.Execution.Checkouts, 1)
	assert.Equal(t, "actions/checkout@v4", victim.Execution.Checkouts[0].Uses)
	assert.Equal(t, "v4", victim.Execution.Checkouts[0].Ref)
	assert.Equal(t, CacheEntryModePredicted, victim.CacheEntry.Mode)
	assert.Equal(t, StrategySetupGo, victim.CacheEntry.Strategy)
	assert.Equal(t, "1.24.3", victim.CacheEntry.VersionSpec)
}

func TestCollectVictimCandidates_SetupGoPinnedVersionIsReady(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	workflow := poutinemodels.GithubActionsWorkflow{
		Path: ".github/workflows/release.yml",
		Events: poutinemodels.GithubActionsEvents{
			{Name: "push"},
		},
		Jobs: poutinemodels.GithubActionsJobs{
			{
				ID:   "release",
				Name: "Release",
				Steps: poutinemodels.GithubActionsSteps{
					{
						Uses: "actions/checkout@v6",
					},
					{
						Uses: "actions/setup-go@v5",
						With: poutinemodels.GithubActionsWith{
							{Name: "go-version", Value: "1.24.3"},
							{Name: "cache-dependency-path", Value: "go.sum"},
						},
					},
				},
			},
		},
	}

	victims := CollectVictimCandidates("acme/release", root, workflow)
	require.Len(t, victims, 1)

	victim := victims[0]
	assert.Equal(t, StrategySetupGo, victim.Strategy)
	assert.True(t, victim.Ready)
	assert.Equal(t, "ready", victim.Readiness)
	assert.Equal(t, "1.24.3", victim.VersionSpec)
	assert.Equal(t, "go.sum", victim.CacheDependencyPath)
	assert.Equal(t, "actions/setup-go@v5", victim.CacheEntry.ActionUses)
	assert.Equal(t, "v5", victim.CacheEntry.ActionRef)
	expectedKey, _, err := ComputeSetupGoEntry(root, "1.24.3", "go.sum")
	require.NoError(t, err)
	assert.Equal(t, expectedKey, victim.CacheEntry.PredictedKey)
	assert.Equal(t, ExecutionKindCheckoutPost, victim.Execution.Kind)
	require.Len(t, victim.Execution.Checkouts, 1)
	assert.Equal(t, "actions/checkout@v6", victim.Execution.Checkouts[0].Uses)
	assert.Equal(t, "v6", victim.Execution.Checkouts[0].Ref)
}

func TestCollectVictimCandidates_SetupGoImplicitCacheWithPinnedCheckoutSHAIsReady(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\ngo 1.24.3\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	workflow := poutinemodels.GithubActionsWorkflow{
		Path: ".github/workflows/deploy.yml",
		Events: poutinemodels.GithubActionsEvents{
			{Name: "workflow_dispatch"},
		},
		Jobs: poutinemodels.GithubActionsJobs{
			{
				ID:   "sync",
				Name: "Sync",
				Steps: poutinemodels.GithubActionsSteps{
					{
						Uses: "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
					},
					{
						Uses: "actions/setup-go@v5",
						With: poutinemodels.GithubActionsWith{
							{Name: "go-version-file", Value: "go.mod"},
						},
					},
				},
			},
		},
	}

	victims := CollectVictimCandidates("acme/deploy", root, workflow)
	require.Len(t, victims, 1)

	victim := victims[0]
	assert.Equal(t, StrategySetupGo, victim.Strategy)
	assert.True(t, victim.Ready)
	assert.Equal(t, "ready", victim.Readiness)
	assert.Equal(t, "1.24.3", victim.VersionSpec)
	assert.Equal(t, "go.mod", victim.VersionFilePath)
	assert.Equal(t, ExecutionKindCheckoutPost, victim.Execution.Kind)
	require.Len(t, victim.Execution.Checkouts, 1)
	assert.Equal(t, "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5", victim.Execution.Checkouts[0].Uses)
	assert.Equal(t, "34e114876b0b11c390a56381ad16ebd13914f8d5", victim.Execution.Checkouts[0].Ref)
}

func TestCollectVictimCandidates_SetupGoVersionFileWithoutRootIsRuntimeReady(t *testing.T) {
	workflow := poutinemodels.GithubActionsWorkflow{
		Path: ".github/workflows/deploy.yml",
		Events: poutinemodels.GithubActionsEvents{
			{Name: "workflow_dispatch"},
		},
		Jobs: poutinemodels.GithubActionsJobs{
			{
				ID:   "sync",
				Name: "Sync",
				Steps: poutinemodels.GithubActionsSteps{
					{
						Uses: "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
					},
					{
						Uses: "actions/setup-go@v5",
						With: poutinemodels.GithubActionsWith{
							{Name: "go-version-file", Value: "go.mod"},
						},
					},
				},
			},
		},
	}

	victims := CollectVictimCandidates("acme/deploy", "", workflow)
	require.Len(t, victims, 1)

	victim := victims[0]
	assert.Equal(t, StrategySetupGo, victim.Strategy)
	assert.True(t, victim.Ready)
	assert.Equal(t, "ready", victim.Readiness)
	assert.Empty(t, victim.VersionSpec)
	assert.Equal(t, "go.mod", victim.VersionFilePath)
	assert.Equal(t, CacheEntryModePredicted, victim.CacheEntry.Mode)
	assert.Equal(t, StrategySetupGo, victim.CacheEntry.Strategy)
	assert.Empty(t, victim.CacheEntry.VersionSpec)
	assert.Equal(t, "go.mod", victim.CacheEntry.VersionFilePath)
	assert.Empty(t, victim.CacheEntry.PredictedKey)
}

func TestComputeSetupGoEntry(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	moduleCache := filepath.Join(root, "gomodcache")
	buildCache := filepath.Join(root, "gocache")
	require.NoError(t, os.MkdirAll(moduleCache, 0o755))
	require.NoError(t, os.MkdirAll(buildCache, 0o755))
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("RUNNER_ARCH", "x64")
	t.Setenv("ImageOS", "ubuntu24")
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOCACHE", buildCache)

	key, version, err := ComputeSetupGoEntry(root, "1.24.3", "go.sum")
	require.NoError(t, err)

	fileHash, err := HashFiles(root, []string{"go.sum"})
	require.NoError(t, err)
	assert.Equal(t, "setup-go-Linux-x64-ubuntu24-go-1.24.3-"+fileHash, key)
	assert.Equal(t, CalculateCacheVersion([]string{moduleCache, buildCache}), version)
}

func TestComputeSetupGoEntry_LinuxWithoutImageOS(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	moduleCache := filepath.Join(root, "gomodcache")
	buildCache := filepath.Join(root, "gocache")
	require.NoError(t, os.MkdirAll(moduleCache, 0o755))
	require.NoError(t, os.MkdirAll(buildCache, 0o755))
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("RUNNER_ARCH", "x64")
	t.Setenv("ImageOS", "")
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOCACHE", buildCache)

	key, version, err := ComputeSetupGoEntry(root, "1.24.3", "go.sum")
	require.NoError(t, err)

	fileHash, err := HashFiles(root, []string{"go.sum"})
	require.NoError(t, err)
	assert.Equal(t, "setup-go-Linux-x64--go-1.24.3-"+fileHash, key)
	assert.Equal(t, CalculateCacheVersion([]string{moduleCache, buildCache}), version)
}

func TestComputeSetupGoEntry_DefaultsToGoSum(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\ngo 1.24.3\n"), 0o644))

	moduleCache := filepath.Join(root, "gomodcache")
	buildCache := filepath.Join(root, "gocache")
	require.NoError(t, os.MkdirAll(moduleCache, 0o755))
	require.NoError(t, os.MkdirAll(buildCache, 0o755))
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("RUNNER_ARCH", "x64")
	t.Setenv("ImageOS", "ubuntu24")
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOCACHE", buildCache)

	key, version, err := ComputeSetupGoEntry(root, "1.24.3", "")
	require.NoError(t, err)

	fileHash, err := HashFiles(root, []string{"go.sum"})
	require.NoError(t, err)
	assert.Equal(t, "setup-go-Linux-x64-ubuntu24-go-1.24.3-"+fileHash, key)
	assert.Equal(t, CalculateCacheVersion([]string{moduleCache, buildCache}), version)
}

func TestComputeCacheEntry_SetupGoVersionFileFallback(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\ngo 1.24.3\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	moduleCache := filepath.Join(root, "gomodcache")
	buildCache := filepath.Join(root, "gocache")
	require.NoError(t, os.MkdirAll(moduleCache, 0o755))
	require.NoError(t, os.MkdirAll(buildCache, 0o755))
	t.Setenv("RUNNER_OS", "Linux")
	t.Setenv("RUNNER_ARCH", "x64")
	t.Setenv("ImageOS", "ubuntu24")
	t.Setenv("GOMODCACHE", moduleCache)
	t.Setenv("GOCACHE", buildCache)

	key, version, err := ComputeCacheEntry(root, VictimCandidate{
		CacheEntry: CacheEntryPlan{
			Mode:                CacheEntryModePredicted,
			Strategy:            StrategySetupGo,
			VersionFilePath:     "go.mod",
			CacheDependencyPath: "go.sum",
		},
	})
	require.NoError(t, err)

	fileHash, err := HashFiles(root, []string{"go.sum"})
	require.NoError(t, err)
	assert.Equal(t, "setup-go-Linux-x64-ubuntu24-go-1.24.3-"+fileHash, key)
	assert.Equal(t, CalculateCacheVersion([]string{moduleCache, buildCache}), version)
}

func TestDeploymentConfigEncodeDecode(t *testing.T) {
	cfg := DeploymentConfig{
		Candidate: VictimCandidate{
			Repository: "acme/demo",
			Workflow:   ".github/workflows/release.yml",
			Job:        "release",
			Strategy:   StrategySetupGo,
			CacheEntry: CacheEntryPlan{
				Mode:                CacheEntryModePredicted,
				Strategy:            StrategySetupGo,
				CacheDependencyPath: "go.sum",
				VersionSpec:         "1.24.3",
			},
			Execution: ExecutionPlan{
				Kind:       ExecutionKindCheckoutPost,
				GadgetUses: "actions/setup-go@v5",
				Checkouts: []CheckoutTarget{
					{Uses: "actions/checkout@v6", Ref: "v6"},
				},
			},
		},
		VictimStagerURL:  "https://kitchen.example/r/cb-1",
		VictimCallbackID: "cb-1",
	}

	encoded, err := cfg.Encode()
	require.NoError(t, err)

	decoded, err := DecodeDeploymentConfig(encoded)
	require.NoError(t, err)
	assert.Equal(t, cfg, decoded)
}

func TestComputeCacheEntry_ActionsCache(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	expectedHash, err := HashFiles(root, []string{"go.sum"})
	require.NoError(t, err)

	key, version, err := ComputeCacheEntry(root, VictimCandidate{
		CacheEntry: CacheEntryPlan{
			Mode:         CacheEntryModePredicted,
			Strategy:     StrategyActionsCache,
			KeyTemplate:  "demo-${{ hashFiles('go.sum') }}",
			PathPatterns: []string{"./build-cache"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "demo-"+expectedHash, key)
	assert.NotEmpty(t, version)
}

func TestResolveCachePaths_PreservesLiteralDotSlash(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))

	paths, err := ResolveCachePaths(root, []string{"./build-cache"})
	require.NoError(t, err)
	assert.Equal(t, []string{"./build-cache"}, paths)
}

func TestCalculateVersionFromPatterns_ActionsCacheLiteralPathMatchesObservedGitHubVersion(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build-cache"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "build-cache", "seed.txt"), []byte("seed"), 0o644))

	version, err := CalculateVersionFromPatterns(root, []string{"./build-cache"}, false)
	require.NoError(t, err)
	assert.Equal(t, "aeec744d5307adc2b0cc09487b75728eedf8790e2d4ca1491f41c1e9553de1a5", version)
}

func TestParseSetupGoVersionFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\ngo 1.24.3\n"), 0o644))

	version, err := parseSetupGoVersionFile(root, "go.mod")
	require.NoError(t, err)
	assert.Equal(t, "1.24.3", version)
}

func TestCollectVictimCandidates_SetupGoWithoutCheckoutIsNotReady(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644))

	workflow := poutinemodels.GithubActionsWorkflow{
		Path:   ".github/workflows/release.yml",
		Events: poutinemodels.GithubActionsEvents{{Name: "push"}},
		Jobs: poutinemodels.GithubActionsJobs{
			{
				ID: "release",
				Steps: poutinemodels.GithubActionsSteps{
					{
						Uses: "actions/setup-go@v5",
						With: poutinemodels.GithubActionsWith{
							{Name: "go-version", Value: "1.24.3"},
							{Name: "cache-dependency-path", Value: "go.sum"},
						},
					},
				},
			},
		},
	}

	victims := CollectVictimCandidates("acme/release", root, workflow)
	require.Len(t, victims, 1)
	assert.False(t, victims[0].Ready)
	assert.Equal(t, "job has no actions/checkout step", victims[0].Readiness)
}
