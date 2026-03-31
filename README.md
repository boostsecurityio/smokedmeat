<img src="smokedmeat-logo.png" alt="SmokedMeat Logo" width="400">

# SmokedMeat

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**CI/CD Red Team Framework**

> Like Metasploit, but for CI/CD pipelines.

*From the makers of the [poutine](https://github.com/boostsecurityio/poutine) Build Pipeline SAST scanner at [BoostSecurity Labs](https://labs.boostsecurity.io).*

---

> **Warning: This tool is for authorized security testing only.**
>
> SmokedMeat exists because CI/CD pipeline threats are deeply underestimated. Traditional security training rarely covers supply chain attacks, leaving defenders unprepared for techniques that adversaries actively exploit in the wild.
>
> We built this to give security teams the ability to learn, practice, and validate defenses against advanced CI/CD attack techniques through realistic red team exercises.
>
> **Only use against systems you own or have explicit written permission to test.**

---

## What is SmokedMeat?

SmokedMeat is a post-exploitation framework for CI/CD pipelines. Point it at a GitHub organization, let it find vulnerable workflows, deploy an implant to a compromised runner, then pivot through cloud providers, extract secrets, and map the blast radius  - all from a terminal UI.

**What it does:**

1. **Analyze**  - Scan an org's GitHub Actions workflows for injection vulnerabilities, dangerous triggers, and unsafe checkout patterns (powered by [poutine](https://github.com/boostsecurityio/poutine))
2. **Exploit**  - Deploy a stager via PR, issue, comment, or workflow dispatch. When the vulnerable workflow runs, it downloads and executes the implant on the CI runner.
3. **Post-exploit**  - Extract secrets from runner memory, enumerate GitHub token permissions, scan for private keys, and collect loot
4. **Pivot**  - Use captured credentials to move laterally: discover private repos, mint GitHub App tokens, exchange OIDC tokens for AWS/GCP/Azure access, probe SSH deploy keys

**Philosophy:** Bold and noisy. This isn't an EDR evasion tool. It's a demonstration framework that shows how deep a CI/CD compromise goes before anything triggers an alert.

**Who is it for:**
- Red teams validating CI/CD security posture in enterprise environments
- Pentesters demonstrating supply chain attack paths to stakeholders
- Security engineers testing detection and response for pipeline attacks
- Researchers developing new CI/CD exploitation techniques
- Bug bounty hunters exploring supply chain attack surface

## Core Components

SmokedMeat uses a few project-specific names throughout the codebase and UI. For a first read, map them to the standard roles:

| Standard term | SmokedMeat name | Description |
|---------------|-----------------|-------------|
| **Operator TUI** | `Counter` | Bubbletea-based terminal interface that operators use to analyze targets, launch payloads, and drive post-exploitation workflows. |
| **C2 teamserver** | `Kitchen` | HTTP API and WebSocket server that handles operator sessions, implant delivery, attack graph state, and GitHub API proxying. |
| **Implant** | `Brisket` | Static Go agent delivered to compromised CI runners for beaconing, command execution, loot collection, and pivoting. |
| **Browser graph view** | `Browser View` | Cytoscape.js visualization of the attack graph served by the C2 teamserver. |

## Quick Start

Try SmokedMeat from source with Docker, Go 1.25+, and `make`.

```bash
git clone https://github.com/boostsecurityio/smokedmeat.git
cd smokedmeat
make dev-quickstart
```

This builds the `smokedmeat-cloud-shell` image, starts the quickstart infrastructure in Docker, and launches the operator TUI (`Counter`) locally via `go run ./cmd/counter`. If the quickstart stack is already healthy, rerunning `make dev-quickstart` reuses the existing tunnel and NATS, refreshes the C2 teamserver (`Kitchen`), and jumps straight back into the operator TUI:

| Component | What it does |
|-----------|-------------|
| **cloudflared** | Creates a temporary Cloudflare tunnel so GitHub runners can reach your C2 teamserver over HTTPS  - no domain or DNS setup needed |
| **nats** | NATS JetStream message bus for C2 teamserver-to-implant communication |
| **kitchen** | C2 teamserver (`Kitchen`) with shared-token auth and embedded implant (`Brisket`) binaries |
| **smokedmeat-cloud-shell** | Docker runtime for `cloud shell` and `ssh shell` when the operator TUI (`Counter`) runs locally |

The setup wizard walks you through:
1. **GitHub PAT**  - A classic PAT with `public_repo` scope is enough to try it against the `whooli` test org. For private repos, you'll need `repo` scope.
2. **Target**  - Enter `whooli` (our public CI/CD attack playground) or your own org/repo
3. **Analysis**  - Scans workflows for vulnerabilities and presents exploitable findings

When done:
```bash
make dev-quickstart-down   # Stop containers
make dev-quickstart-purge  # Stop and delete all data
```

`make quickstart` now targets an explicitly pinned released version instead of following the newest tag automatically. That keeps quickstart stable and breaks the recursion between "just published" and "good enough to pin". Use `make quickstart-version` to inspect the current pin. Maintainers advance it with `make quickstart-pin VERSION=v0.0.1-rc1`, which verifies the immutable GitHub release, records the published operator TUI (`Counter`) asset digests, and pins the signed C2 teamserver (`Kitchen`) and `smokedmeat-cloud-shell` image digests before updating `configs/quickstart-release.mk`. The first release-backed path is expected to embed only `brisket-linux-amd64` in the C2 teamserver, so quickstart releases will initially target Linux x86_64 runners for agent delivery.

### Dev Quickstart Notes

| Feature | `make dev-quickstart` |
|---------|-----------------------|
| Clipboard (copy payloads) | Works on the host |
| Open browser links | Opens directly on the host |
| Cloud shell (gcloud, aws, az) | Uses the `smokedmeat-cloud-shell` Docker image that `make dev-quickstart` prebuilds |
| Tunnel URL | Random, changes on restart |
| Auth | Shared token |

If you want to start the infrastructure first and launch the operator TUI later:

```bash
# Start just the infrastructure in Docker
make dev-quickstart-up

# Launch the operator TUI with the quickstart token and C2 teamserver URLs
make dev-quickstart-counter
```

## Deployment Modes

### Development Quickstart (Local Evaluation)

`make dev-quickstart` is the current fastest path from source. It uses Docker for cloudflared, NATS, and the C2 teamserver (`Kitchen`), shared-token auth, local `go run ./cmd/counter`, and a prebuilt `smokedmeat-cloud-shell:latest` image for `cloud shell` and `ssh shell`. When the stack is already healthy, rerunning it keeps the existing tunnel and NATS but refreshes the C2 teamserver before launching the operator TUI again.

### Quickstart (Release-backed)

`make quickstart` uses the pinned release in `configs/quickstart-release.mk`. It verifies the cached operator TUI (`Counter`) archive against the pinned GitHub release digest, runs Docker with the pinned C2 teamserver (`Kitchen`) image digest, and overrides the compiled operator TUI to use the pinned `smokedmeat-cloud-shell` image digest.

This means quickstart can intentionally stay one version behind the newest release until that release has been validated. Maintainers update the pin with `make quickstart-pin VERSION=v...`, inspect it with `make quickstart-version`, and then use `make quickstart`. `make quickstart-pin` requires `gh`, `cosign`, and `docker` in `PATH`.

### Self-Hosted (Engagements)

For a real red team engagement, deploy the C2 teamserver (`Kitchen`) on a dedicated host with a stable domain. Stager callbacks from compromised CI runners will land on this host, so it needs a routable IP and DNS.

This mode uses:
- **Caddy** reverse proxy with automatic Let's Encrypt TLS
- **SSH challenge-response auth**  - each operator authenticates with their SSH key, giving per-operator audit trails
- **Docker Compose** for the C2 teamserver + NATS
- The operator TUI (`Counter`) runs **natively** on each operator's workstation

See the [deployment guide](docs/deployment.md) for setup instructions.

### Prerequisites

| What | Dev Quickstart | Self-Hosted | Standalone Operator TUI |
|------|----------------|-------------|--------------------|
| Docker | Required | Required | Not needed |
| Go 1.25+ | Required | Required on operator workstation | Required |
| Domain + DNS | Not needed | Required | Not needed |
| SSH agent | Not needed | Required | Required |

## Architecture

At a high level, the operator TUI (`Counter`) talks to the C2 teamserver (`Kitchen`), which manages implants (`Brisket`) running on compromised CI runners and serves the live attack graph.

```
┌──────────────┐
│  SSH AGENT   │
│   (Auth)     │
└──────┬───────┘
       │
       ▼
┌──────────────┐                 ┌──────────────┐
│  THE COUNTER │ ───────────────▶│  THE KITCHEN │
│  (Operator)  │    WebSocket    │ (Teamserver) │
│  Bubbletea   │◀─────────────── │              │
│     TUI      │   Events/Graph  │ ┌──────────┐ │
└──────────────┘                 │ │ Database │ │
                                 │ └──────────┘ │
┌──────────────┐                 │              │
│   BROWSER    │ ───────────────▶│              │
│  Graph View  │    WebSocket    │              │
│  Visualizer  │◀─────────────── │              │
└──────────────┘   Live Updates  └──────────────┘
                                   │         ▲
                                   │         │
                        Creates PR │         │ Stager fetches implant binary
                                   │         │ Implant HTTP Beacon/Commands
                                   ▼         │
┌────────────────────────────────────────────┴──────────────────────────────────┐
│  GITHUB.COM                                                                   │
│                                                                               │
│  ┌─────────────────────┐          ┌─────────────────────────────────────────┐ │
│  │  Malicious PR       │ triggers │  GitHub Actions Runner                  │ │
│  │  (Vulnerable        │─────────▶│                                         │ │
│  │   Workflow)         │          │  ┌────────────┐      ┌────────────────┐ │ │
│  └─────────────────────┘          │  │  Stager    │─────▶│  THE BRISKET   │ │ │
│                                   │  │            │      │  (Implant)     │ │ │
│                                   │  └────────────┘      └────────────────┘ │ │
│                                   └─────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Features

Full details in [docs/FEATURES.md](docs/FEATURES.md).

| Category | Capabilities |
|----------|-------------|
| **Reconnaissance** | Auto-detect 6 CI platforms (GitHub Actions, GitLab CI, Azure DevOps, CircleCI, Jenkins, Bitbucket). Classify secrets, probe OIDC availability, gather runner metadata. |
| **Secret Extraction** | Scan Runner.Worker process memory via `/proc` to recover unmasked `secrets.*`, `vars.*`, and `GITHUB_TOKEN` permission maps that GitHub hides from logs. |
| **Vulnerability Analysis** | Embedded [poutine](https://github.com/boostsecurityio/poutine) SAST for injection vulnerabilities, dangerous triggers, and workflow `if:` gate classification. Gitleaks deep scan for private keys and PATs in git history. |
| **Delivery** | 5 automated methods: PR, issue, comment, LOTP, workflow dispatch  - plus copy-only and manual. Draft PR support, auto-close on callback, server-side dispatch preflight. |
| **Injection Payloads** | Context-aware payload generation for 8 injection vectors (branch name, PR title/body, commit message, issue title/body, github-script, bash run) with constraint-aware techniques. |
| **LOTP** | Living Off The Pipeline catalog: 15 build tools (npm, pip, cargo, make, docker, gradle, maven, and more) with config-file payloads for code execution during install/build/test. |
| **Cache Poisoning** | Writer/victim classification, exact cache key prediction, archive staging via the Actions Cache API. Wizard-driven flow with implant arming. |
| **Token Enumeration** | Probe GitHub tokens against API endpoints to enumerate 10 permission scopes, identify token type, and list accessible repos and orgs. |
| **Cloud Pivots** | OIDC token exchange for AWS (`sts:AssumeRoleWithWebIdentity`), GCP (Workload Identity Federation), Azure (AAD), and Kubernetes. Post-pivot resource enumeration. |
| **Cloud Shell** | Durable local sessions with `cloud shell` (pre-configured gcloud/aws/az), `cloud export`, and provider quick checks. |
| **SSH Pivoting** | Probe repos for SSH deploy key access (read/write), `ssh shell` with temporary agent, confirmed access persisted to graph. |
| **GitHub Pivoting** | `pivot github` for repo discovery, `pivot app` for GitHub App PEM-to-installation-token exchange. Discovered repos auto-queued for analysis. |
| **Attack Graph** | Persistent directed graph (BBolt) with org/repo/workflow/job/vuln/token/cloud nodes. Live Cytoscape.js browser visualization at `/graph`. |
| **Operator TUI** | Phase-aware workflow, 7-step setup wizard, attack tree navigation, exploit wizard, loot stash, omnibox search, tab completion, OSC 8 hyperlinks. |
| **Teamserver** | SSH or token auth, NATS JetStream message bus, GitHub API proxy (tokens stay server-side), auto-TLS via Caddy, operation history. |

## Try It on a Vulnerable Target

The [`whooli`](docs/WHOOLI.md) GitHub organization is a deliberately vulnerable CI/CD attack playground  - think Juice Shop for pipelines. It has planted vulnerabilities, exposed secrets, cache poisoning chains, and OIDC federation to a GCP bucket with a flag.

Start with `make dev-quickstart`, enter `whooli` as your target, and see how far you get. The [challenge guide](docs/WHOOLI.md) explains the setup without giving away the solutions.

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Go 1.25 |
| TUI Framework | [Bubbletea v2](https://github.com/charmbracelet/bubbletea) + [Lipgloss v2](https://github.com/charmbracelet/lipgloss) |
| TUI Layout | [Ultraviolet](https://github.com/charmbracelet/ultraviolet) layout + ANSI-safe screen compositing |
| Message Bus | [NATS JetStream](https://nats.io/) |
| Attack Graph | [hmdsefi/gograph](https://github.com/hmdsefi/gograph) |
| Graph Visualization | [Cytoscape.js](https://js.cytoscape.org/) |
| Database | [BBolt](https://github.com/etcd-io/bbolt) |
| CI/CD Scanner | [poutine](https://github.com/boostsecurityio/poutine) (embedded) |
| Secret Scanner | [gitleaks](https://github.com/gitleaks/gitleaks) (embedded, custom rules) |
| Runner Secret Extraction | gump (embedded, `/proc` memory scanning) |
| Cloud SDKs | AWS SDK v2, Google Cloud, Azure SDK for Go |
| Reverse Proxy | [Caddy](https://caddyserver.com/) (auto-TLS) |

## Testing

```bash
make test          # Unit tests
make lint          # Linter
make e2e-smoke     # Fast public exploit smoke path
make e2e-goat      # Full goat chain to the cloud flag
```

## Prior Art

SmokedMeat builds on research from:

- [poutine](https://github.com/boostsecurityio/poutine)  - Build Pipeline SAST scanner
- [LOTP](https://boostsecurityio.github.io/lotp/)  - Living Off The Pipeline techniques
- [Gato-X](https://github.com/AdnaneKhan/Gato-X)  - GitHub Actions enumeration
- [Nord-Stream](https://github.com/synacktiv/nord-stream)  - CI/CD secret extraction
- [Sliver](https://github.com/BishopFox/sliver)  - Go C2 architecture patterns
- [Mythic](https://docs.mythic-c2.net/)  - Collaborative workflow design

## License

GNU Affero General Public License v3.0  - see [LICENSE](LICENSE) for details.

---

*Built for defenders who want to understand attacker techniques.*
