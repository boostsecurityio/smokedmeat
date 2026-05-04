# SmokedMeat Deployment Guide

## Modes

### Development Quickstart

Use this when you want the fastest local path:

```bash
make dev-quickstart
```

Development quickstart uses:

- Docker for cloudflared, NATS, and Kitchen
- a Cloudflare tunnel for a public Kitchen URL
- shared-token auth (`AUTH_MODE=token`)
- local `go run ./cmd/counter`
- the `smokedmeat-cloud-shell` image for `cloud shell` and `ssh shell`

This is the right path for demos, local testing, and validating the full workflow without standing up a domain.

`make quickstart` uses the pinned release in `configs/quickstart-release.mk`. That pin can intentionally lag the newest tag until a release has been validated. Use `make quickstart-version` to inspect it. Maintainers update it with `make quickstart-pin VERSION=v...`, which verifies the immutable GitHub release plus the signed GHCR image digests before writing the pin. `make quickstart-pin` requires `gh`, `cosign`, and `docker` in `PATH`. Use `make quickstart-up` / `make quickstart-counter` if you want to split infrastructure startup from the Counter launch.

Counter checks for newer SmokedMeat releases at startup. It can be disabled by setting the `SMOKEDMEAT_DISABLE_VERSION_CHECK` environment variable.

### Self-Hosted Kitchen

Use this when you want a stable Kitchen with your own domain and SSH challenge-response auth.

#### Prerequisites

- Docker and Docker Compose on the Kitchen host
- a DNS record pointing your Kitchen hostname to that host
- an SSH agent on the operator workstation
- this repository checked out on the Kitchen host

#### 1. Register an operator key

From the operator workstation, list keys from the local SSH agent:

```bash
go run ./cmd/counter --list-keys
```

Pick one entry and copy the printed `authorized_keys` line.

On the Kitchen host, add that line to:

```bash
~/.smokedmeat/authorized_keys
```

Kitchen reads that file from the host and mounts it into the container.

#### 2. Start Kitchen

From the repo root on the Kitchen host:

```bash
export DOMAIN=kitchen.example.com
docker compose -f deployments/docker-compose.yml up -d --build
```

This stack starts:

- Caddy on ports `80` and `443`
- Kitchen behind Caddy
- NATS JetStream
- BBolt persistence under the Docker volume

By default this path uses:

- `AUTH_MODE=ssh`
- automatic TLS via Caddy
- `~/.smokedmeat/authorized_keys` for operator auth

#### 3. Connect Counter

From the operator workstation:

```bash
go run ./cmd/counter -kitchen https://kitchen.example.com -operator <name>
```

If the Kitchen URL and operator name are already stored in `~/.smokedmeat/config.yaml`, `make counter` is enough:

```bash
make counter
```

Counter will request a challenge from Kitchen and sign it with the SSH key in the local agent.

#### 4. Cloud Shell Support

If Counter runs as a local Go binary on the operator workstation, build the cloud shell image once:

```bash
make cloud-shell-image
```

`make dev-quickstart` already builds this image for you. `make quickstart` uses the pinned released image that matches the downloaded Counter binary.

## Local Development Compose

If you want Kitchen exposed directly on localhost instead of going through Caddy:

```bash
docker compose -f deployments/docker-compose.yml -f deployments/docker-compose.dev.yml up -d --build
```

That exposes:

- Kitchen on `http://localhost:8080`
- NATS on `localhost:4222`

Auth still defaults to SSH mode unless you explicitly override `AUTH_MODE`.
