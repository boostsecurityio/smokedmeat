# Whooli - CI/CD Attack Playground

`whooli` is SmokedMeat's end-to-end CI/CD attack playground. It is a deliberately vulnerable GitHub organization designed to exercise real product workflows: public footholds, runner secret recovery, GitHub pivots, private-repo analysis, cache poisoning, OIDC federation, and cloud post-exploit work.

This document is the canonical guide for the Whooli goat environment. It merges the old challenge guide and the old architecture note into one source of truth.

## The Scenario

Whooli is a Silicon Valley giant led by Galvin Belsin. Publicly, the company insists that `xyz` is its own moonshot compression breakthrough and that NewCleus was built independently in-house.

Internally, the story is messier. After failing to reproduce Ritcherd Hendricks's middle-out compression, Whooli rage-acqui-hired Nelson Bigetti from Nip Alert and started scavenging old repo clones, notes, and deployment material from his laptop backups. That is why the private repos read like a panicked reverse-engineering effort and still contain stray references to Danesh and Jilfoyle.

## The Objective

Read `flag.txt` from the GCP Cloud Storage benchmark bucket. The flag looks like `SM{...}`.

The shortest validated path starts from a public repo, pivots through a GitHub App key, compromises a private workflow through cache poisoning, federates into GCP with OIDC, and reads the flag from:

- `gs://whooli-newcleus-benchmarks/flag.txt`

## Getting Started

```bash
make quickstart
```

When the setup wizard asks for a target, enter `whooli`.

A classic GitHub PAT with `public_repo` scope is enough to start the main public path. You do not need private-repo access up front because the environment is meant to make you earn it.

⚠ Prefer a classic PAT. Fine-grained PATs can be too restrictive and may block public cross-org testing, including `whooli`.

If you are working on SmokedMeat itself, `make dev-quickstart` uses the local source tree instead.

## Organization Layout

The `whooli` org contains three repositories:

| Repository | Visibility | Role |
|-----------|-----------|------|
| `xyz` | Public | Initial foothold and GitHub App-key recovery |
| `infrastructure-definitions` | Private | Main cache-poison target and GCP pivot repo |
| `newcleus-core-v3` | Private | Alternate challenge path containing the SSH deploy key |

Start at [https://github.com/whooli/xyz](https://github.com/whooli/xyz). The README there hints at how Whooli's public automation is wired into the private NewCleus effort.

```text
                          github.com/whooli
                                  |
                    +-------------+-------------+
                    |                           |
             xyz (public)              newcleus-core-v3 (private)
                    |                           |
         public footholds + App key            |  SSH deploy key
                    |                           |
                    +-------------+-------------+
                                  |
                    infrastructure-definitions (private)
                                  |
              benchmark-bot.yml   -> cache writer
              deploy.yml          -> main victim + GCP OIDC
              release.yml         -> SSH tag bonus victim
                                  |
                                  v
                             GCP project
                                  |
                                  v
                    gs://whooli-newcleus-benchmarks/flag.txt
```

## Hard-Validated Main Path

The path below is the one currently hard-validated by `make e2e-goat`. If you want the exact chain SmokedMeat proves end to end today, this is it.

### 1. Analyze `whooli` and foothold `xyz`

SmokedMeat starts with the public `xyz` repo and surfaces the vulnerable public workflows. The current goat E2E uses an issue-body foothold on:

- `xyz/.github/workflows/auto-labeler.yml`

That gets you runner execution and a first callback.

### 2. Take the App-key foothold

From Recon, the current goat E2E takes a second public foothold through a comment-driven path that lands in:

- `xyz/.github/workflows/whooli-analyzer.yml`

That second foothold is where the test expects to recover:

- `WHOOLI_BOT_APP_PRIVATE_KEY`

Export the key from the loot stash, then use `pivot app` to mint an installation token. That App token is the main bridge into the private repos because it has the repo visibility and `actions:write` needed for the next phase.

### 3. Analyze `infrastructure-definitions`

Switch the active token to the installation token, then retarget:

- `whooli/infrastructure-definitions`

SmokedMeat analyzes the private repo and surfaces the writer workflow used in the validated chain:

- `infrastructure-definitions/.github/workflows/benchmark-bot.yml`

This is the current cache-writer foothold used by `make e2e-goat`.

### 4. Poison the victim cache

Open the exploit wizard for the writer vuln and enable `Cache Poisoning`. In the validated path, the victim is:

- `infrastructure-definitions/.github/workflows/deploy.yml`

The writer callback is immediate. Brisket uses the runner's cache-capable runtime token to stage the poisoned cache entry without needing to modify repo history.

### 5. Arm dwell, then trigger `deploy.yml`

Victim implants are persistent and default to express mode. Before the victim workflow runs, arm the next implant with dwell so the callback stays available after the poisoned cache restores.

The validated path then triggers:

- `workflow_dispatch` on `deploy.yml`

using the GitHub App installation token. This is the shortest stable path because it stays on the App-token leg and does not require reviving the alternate PAT branch.

### 6. Pivot to GCP and read the flag

Once the poisoned victim callback lands, the current goat E2E does:

1. `pivot gcp`
2. `cloud shell`
3. `gsutil ls gs://whooli-newcleus-benchmarks/`
4. `gsutil cat gs://whooli-newcleus-benchmarks/flag.txt`

If you can do that chain manually, you have reproduced the validated goat path.

## Workflow Map

These are the important workflows in the current environment.

### `xyz/.github/workflows/auto-labeler.yml`

- Trigger: public issue and comment activity
- Role: first public foothold
- Validation status: part of the hard-validated goat path
- Key property: direct shell injection from attacker-controlled issue data

### `xyz/.github/workflows/whooli-analyzer.yml`

- Trigger: public comment-driven path
- Role: second foothold used to recover the GitHub App key
- Validation status: part of the hard-validated goat path
- Key property: lands the runner context where `WHOOLI_BOT_APP_PRIVATE_KEY` is recoverable

### `xyz/.github/workflows/internal-sync.yml`

- Trigger: `workflow_dispatch`
- Role: alternate bridge into the private repos through `WHOOLI_INT_PAT`
- Validation status: described challenge path, not part of the hard-validated main goat chain

### `infrastructure-definitions/.github/workflows/benchmark-bot.yml`

- Trigger: `issue_comment`
- Role: main cache writer in the validated path
- Validation status: part of the hard-validated goat path
- Key property: issue-comment injection in a default-branch workflow

### `infrastructure-definitions/.github/workflows/deploy.yml`

- Trigger: `push` on `main`, `workflow_dispatch`
- Role: main victim workflow and GCP OIDC bridge
- Validation status: part of the hard-validated goat path
- Key properties:
  - uses `actions/setup-go@v5` with dependency caching
  - reaches the `actions/checkout` post-run gadget after cache restore
  - has `id-token: write`
  - runs under the hardened workload identity policy

### `infrastructure-definitions/.github/workflows/release.yml`

- Trigger: tag push such as `bench-v*`
- Role: bonus SSH-tag victim path
- Validation status: alternate path, not part of the hard-validated main goat chain

## Why the Main Path Works

The important design point is that Whooli does not need a PR-based writer for the main path. A default-branch issue or comment workflow is already enough to act as a privileged cache writer.

The writer foothold stages a poisoned `setup-go` cache entry. The victim `deploy.yml` run is legitimate and still satisfies the OIDC identity checks. What changes is the cached data restored into that legitimate workflow context, not the workflow file itself.

That is why the hardened workload identity provider does not save the environment from the validated attack. The workload identity policy is strict, but it is evaluating a valid workflow identity that is running compromised restored content.

## OIDC Hardening

The Whooli GCP workload identity provider is intentionally locked to `deploy.yml` on `main`:

```text
assertion.job_workflow_ref == 'whooli/infrastructure-definitions/.github/workflows/deploy.yml@refs/heads/main'
&& assertion.ref == 'refs/heads/main'
&& assertion.ref_protected == 'true'
&& assertion.runner_environment == 'github-hosted'
```

This matters because it explains why a direct off-branch runner pivot is not enough, and why the validated goat path uses cache poisoning to inherit the trusted victim workflow's identity.

## Alternate Paths

These routes are part of the challenge design and are still meaningful, but they are not the currently hard-validated `make e2e-goat` chain.

### Alternate PAT Path

`xyz/.github/workflows/internal-sync.yml` can still expose:

- `WHOOLI_INT_PAT`

That PAT gives an alternate route into the private repos. It is useful challenge material, but the shortest validated path does not need it.

### Alternate SSH Path

`newcleus-core-v3` still contains the SSH deploy key for `infrastructure-definitions`.

The intended bonus path is:

1. extract the deploy key from `newcleus-core-v3`
2. poison the `release.yml` cache from the main writer foothold
3. push a tag such as `bench-v2026.03.24` over SSH
4. let `release.yml` restore the poisoned cache and execute in the tagged-release context

This is still described here because it is part of the environment design, even though the main E2E goat test does not use it.

## Practical Operator Notes

- Run `analyze` first. The Whooli environment is designed to be discovered through the product, not by memorizing file names.
- Check the loot stash after each callback. The important pivot material changes as you move from public foothold to private infra.
- Use the wizard for cache poisoning. The product already handles writer-victim pairing, cache prediction, implant staging, and victim arming.
- If `pivot gcp` fails, confirm you are in the `deploy.yml` victim callback, not just in the writer callback.

## Defensive Lessons

1. Never interpolate issue or comment content directly into `run:` blocks.
2. Treat default-branch issue and comment workflows as privileged cache writers.
3. Do not assume OIDC hardening protects against poisoned restored cache content.
4. Keep GitHub App scope minimal across repositories.
5. Treat SSH deploy keys as high-value credentials even when they are no longer part of the shortest attack path.

## Rules of Engagement

- `whooli` is a shared test environment. Issues and PRs created during your run are automatically cleaned up by the E2E harness where possible.
- If you are running manually, clean up after yourself and close anything you created.
- The flag rotates. Prove the path, not the flag value.
- The hard-validated path above is authoritative for product regression checking. The alternate paths are intentionally left as challenge material and may evolve independently.
