.PHONY: help help-more quickstart quickstart-up quickstart-counter quickstart-down quickstart-purge quickstart-version quickstart-pin quickstart-cache quickstart-drop-cache tag \
        dev-quickstart dev-quickstart-up dev-quickstart-refresh dev-quickstart-counter dev-quickstart-down dev-quickstart-purge \
        counter cloud-base-image cloud-shell-image \
        build-release-embed-brisket \
        test test-verbose test-race lint lint-fix tidy pinact \
        build-brisket build-brisket-all clean \
        e2e-up e2e-down e2e-purge e2e-counter e2e-capture e2e-keys e2e-kitchen-rebuild analyze-perf \
        e2e-smoke e2e-goat

.DEFAULT_GOAL := help

define print_brand_header
	@printf "\033[38;5;208m"
	@echo "   ___            _            _ __  __           _   "
	@echo "  / __|_ __  ___ | |_____ _ __| |  \/  |___ __ _ | |_ "
	@echo "  \__ \ '  \/ _ \| / / -_) _  | | |\/| / -_) _\` ||  _|"
	@echo "  |___/_|_|_\___/|_\_\___\__,_|_|_|  |_\___\__,_| \__|"
	@printf "\033[0m"
	@printf "  \033[1mCI/CD Red Team Framework\033[0m - \033[3m\"Like Metasploit, but for CI/CD\"\033[0m\n"
	@printf "  \033[90mCrafted with ❤️ in Montréal, Québec, Canada 🇨🇦\033[0m\n"
	@printf "  \033[90mFrom the makers of the \033[38;5;208mpoutine\033[0m\033[90m Build Pipeline SAST · \033[1;36mBoost Security Labs\033[0m\n"
	@echo ""
	@printf "  \033[90mSmoked meat: Montréal's legendary deli staple. Beef brisket, cured & smoked.\033[0m\n"
	@printf "  \033[36mCounter\033[0m = Operator TUI  \033[35mKitchen\033[0m = C2 Team-Server  \033[31mBrisket\033[0m = Implant\n"
	@echo ""
endef

help:
	$(call print_brand_header)
	@printf "\033[1;33mQuick Start:\033[0m\n"
	@printf "  \033[36mmake quickstart\033[0m             Start the stable release quickstart and launch Counter TUI\n"
	@printf "  \033[36mmake quickstart-up\033[0m          Start the stable release infrastructure only\n"
	@printf "  \033[36mmake quickstart-counter\033[0m     Launch Counter from the stable release cache\n"
	@printf "  \033[36mmake quickstart-down\033[0m        Stop the stable release containers\n"
	@printf "  \033[36mmake quickstart-purge\033[0m       Stop the stable release containers and delete data\n"
	@printf "  \033[36mmake quickstart-version\033[0m     Show the stable release used by quickstart\n"
	@printf "  \033[36mmake quickstart-pin VERSION=v...\033[0m Maintainer only - verify release and update the quickstart pin\n"
	@printf "  \033[36mmake quickstart-cache\033[0m       Download and cache the stable Counter release\n"
	@printf "  \033[36mmake quickstart-drop-cache\033[0m  Delete the cached stable Counter release\n"
	@echo ""
	@printf "\033[1;33mDevelopment Quick Start:\033[0m\n"
	@printf "  \033[36mmake dev-quickstart\033[0m         Reuse tunnel + MQ, refresh Kitchen, launch Counter via go run\n"
	@printf "  \033[36mmake dev-quickstart-up\033[0m      Start tunnel + MQ + Kitchen and prewarm cloud shell image\n"
	@printf "  \033[36mmake dev-quickstart-counter\033[0m Launch Counter TUI (after dev-quickstart-up)\n"
	@printf "  \033[36mmake dev-quickstart-down\033[0m    Stop containers\n"
	@printf "  \033[36mmake dev-quickstart-purge\033[0m   Stop and delete all data\n"
	@echo ""
	@printf "\033[1;33mCounter (Remote Kitchen):\033[0m\n"
	@printf "  \033[36mmake counter\033[0m            Run Counter TUI (uses ~/.smokedmeat config)\n"
	@echo ""
	@printf "\033[1;33mBuild Briskets (CI/CD Job Runner Implants):\033[0m\n"
	@printf "  \033[36mmake build-brisket\033[0m      Build Brisket for Linux amd64\n"
	@printf "  \033[36mmake build-brisket-all\033[0m  Build Brisket for all platforms\n"
	@echo ""
	@printf "\033[1;33mTesting:\033[0m\n"
	@printf "  \033[36mmake test\033[0m               Run all tests\n"
	@printf "  \033[36mmake lint\033[0m               Run golangci-lint\n"
	@echo ""
	@printf "\033[90mRun 'make help-more' for advanced commands (E2E, staging, etc).\033[0m\n"

help-more:
	@echo "SmokedMeat - Advanced Commands"
	@echo ""
	@echo "Testing (additional):"
	@echo "  test-verbose     Run tests with verbose output"
	@echo "  test-race        Run tests with race detector"
	@echo "  lint-fix         Run golangci-lint with auto-fix"
	@echo ""
	@echo "E2E Testing (Docker + tmux):"
	@echo "  e2e-up                Start infrastructure (generates AUTH_TOKEN)"
	@echo "  e2e-down              Stop all containers"
	@echo "  e2e-purge             Stop and delete all data"
	@echo "  e2e-counter           Launch Counter in tmux (140x50)"
	@echo "  e2e-capture           Capture tmux pane with ANSI codes"
	@echo "  e2e-keys KEYS='...'   Send keystrokes to tmux"
	@echo "  e2e-kitchen-rebuild   Rebuild Kitchen only (tunnel stays)"
	@echo "  analyze-perf          Profile real-org analysis timings with .claude/e2e/.env"
	@echo "  e2e-smoke             Run the fast public exploit smoke path"
	@echo "  e2e-goat              Run the full GOAT chain to the cloud flag"
	@echo ""
	@echo "Build Briskets:"
	@echo "  build-brisket    Build Brisket for Linux amd64"
	@echo "  build-brisket-all Build Brisket for all platforms"
	@echo ""
	@echo "Other:"
	@echo "  tidy             Run go mod tidy"
	@echo "  pinact           Pin GitHub Actions versions"
	@echo "  tag VERSION=v... Create, sign, and push a release tag"
	@echo "  clean            Remove dist/ directory"

define print_release_quickstart_banner
$(if $(strip $(SMOKEDMEAT_QUICKSTART_BANNER_SHOWN)),,$(call print_brand_header))
endef

define print_quickstart_step
	@printf "\033[1;33m[quickstart]\033[0m \033[36m%s\033[0m\n" "$(1)"
endef

define print_quickstart_note
	@printf "  \033[90m%s\033[0m\n" "$(1)"
endef

define print_quickstart_hint
	@printf "  \033[1;34m%s\033[0m\n" "$(1)"
endef

define start_release_quickstart_services
	@COMPOSE_OUTPUT=$$(mktemp); \
	$(QUICKSTART_RELEASE_COMPOSE) up -d --quiet-pull cloudflared nats kitchen-init kitchen >"$$COMPOSE_OUTPUT" 2>&1 & \
	COMPOSE_PID=$$!; \
	FRAME=0; \
	while kill -0 $$COMPOSE_PID >/dev/null 2>&1; do \
		case $$FRAME in \
			0) ICON="|"; MSG="Pulling verified images and creating containers" ;; \
			1) ICON="/"; MSG="Pulling verified images and creating containers" ;; \
			2) ICON="-"; MSG="Pulling verified images and creating containers" ;; \
			*) ICON="\\"; MSG="Pulling verified images and creating containers" ;; \
		esac; \
		printf "\r\033[2K  \033[1;33m[%s]\033[0m \033[90m%s...\033[0m" "$$ICON" "$$MSG"; \
		FRAME=$$((($$FRAME + 1) % 4)); \
		sleep 0.2; \
	done; \
	wait $$COMPOSE_PID; \
	STATUS=$$?; \
	if [ "$$STATUS" = "0" ]; then \
		printf "\r\033[2K"; \
		printf "  \033[1;32m✓\033[0m Pulled any missing images\n"; \
		printf "  \033[1;32m✓\033[0m Created nats and Kitchen containers\n"; \
		printf "  \033[1;32m✓\033[0m Started the cloudflared tunnel helper\n"; \
		printf "  \033[1;32m✓\033[0m Docker services are running\n"; \
		rm -f "$$COMPOSE_OUTPUT"; \
	else \
		printf "\r\033[2K"; \
		if grep -Eqi 'ghcr\.io/boostsecurityio/smokedmeat-kitchen|smokedmeat-kitchen' "$$COMPOSE_OUTPUT" && \
			grep -Eqi 'pull access denied|requested access to the resource is denied|insufficient_scope|unauthorized|authentication required|denied' "$$COMPOSE_OUTPUT"; then \
			printf "\033[1;31m[auth]\033[0m \033[1mQuickstart could not pull the pinned Kitchen image from GHCR.\033[0m\n"; \
			printf "  \033[90mThis private beta release still uses private GHCR packages.\033[0m\n"; \
			printf "  \033[90mDocker is not presenting usable credentials for \033[36mghcr.io\033[90m.\033[0m\n"; \
			printf "\n"; \
			printf "\033[1;33m[fix]\033[0m Refresh GitHub auth with package scope\n"; \
			printf "  \033[36mgh auth refresh -h github.com -s read:packages\033[0m\n"; \
			printf "\033[1;33m[fix]\033[0m Log Docker into GHCR with the same account\n"; \
			printf '  \033[36mecho "$$(gh auth token)" | docker login ghcr.io -u "$$(gh api user -q .login)" --password-stdin\033[0m\n'; \
			printf "\n"; \
			printf "\033[1;34m[check]\033[0m Confirm \033[36m~/.docker/config.json\033[0m has a GHCR credential source\n"; \
			printf "  \033[90mLook for \033[36mauths.ghcr.io\033[90m, \033[36mcredHelpers.ghcr.io\033[90m, or \033[36mcredsStore\033[90m.\033[0m\n"; \
			printf "  \033[90mA credential helper is preferred, but a plain \033[36mauths.ghcr.io\033[90m entry also works.\033[0m\n"; \
			printf "  \033[90mExample:\033[0m\n"; \
			printf '    \033[90m{\033[0m\n'; \
			printf '      \033[90m"credHelpers": {\033[0m\n'; \
			printf '        \033[90m"ghcr.io": \033[36m"<helper-name>"\033[90m\033[0m\n'; \
			printf '      \033[90m}\033[0m\n'; \
			printf '    \033[90m}\033[0m\n'; \
			printf "\n"; \
			printf "\033[1;35m[fallback]\033[0m No GHCR package access yet? Use \033[36mmake dev-quickstart\033[0m\n"; \
			rm -f "$$COMPOSE_OUTPUT"; \
			exit 1; \
		else \
			echo "ERROR: Failed to start the quickstart Docker services."; \
			cat "$$COMPOSE_OUTPUT"; \
		fi; \
		rm -f "$$COMPOSE_OUTPUT"; \
		exit 1; \
	fi
endef

# =============================================================================
# Dev Quick Start (Docker infra + local Counter)
# =============================================================================

QUICKSTART_BROWSER_PORT_DEFAULT := 18180
QUICKSTART_BROWSER_PORT_FILE := /tmp/smokedmeat-kitchen-browser-port
QUICKSTART_TUNNEL_URL_FILE := /tmp/smokedmeat-quickstart-tunnel-url
QUICKSTART_COMPOSE := KITCHEN_BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)) DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p smokedmeat-qs -f deployments/docker-compose.quickstart.yml
QUICKSTART_RELEASE_CONFIG := configs/quickstart-release.mk
-include $(QUICKSTART_RELEASE_CONFIG)
QUICKSTART_RELEASE_VERSION ?=
QUICKSTART_RELEASE_REGISTRY ?= ghcr.io/boostsecurityio
QUICKSTART_RELEASE_REPOSITORY ?= boostsecurityio/smokedmeat
QUICKSTART_RELEASE_TAG := v$(QUICKSTART_RELEASE_VERSION)
COUNTER_ASSET_DARWIN_ARM64 := counter_Darwin_arm64.tar.gz
COUNTER_ASSET_DARWIN_X86_64 := counter_Darwin_x86_64.tar.gz
COUNTER_ASSET_LINUX_ARM64 := counter_Linux_arm64.tar.gz
COUNTER_ASSET_LINUX_X86_64 := counter_Linux_x86_64.tar.gz
COUNTER_ASSET_WINDOWS_ARM64 := counter_Windows_arm64.zip
COUNTER_ASSET_WINDOWS_X86_64 := counter_Windows_x86_64.zip
QUICKSTART_RELEASE_CACHE_DIR := $(HOME)/.smokedmeat/releases/$(QUICKSTART_RELEASE_VERSION)
QUICKSTART_RELEASE_DOWNLOAD_DIR := $(QUICKSTART_RELEASE_CACHE_DIR)/downloads
QUICKSTART_RELEASE_BIN_DIR := $(QUICKSTART_RELEASE_CACHE_DIR)/counter
QUICKSTART_RELEASE_COUNTER_BIN := $(QUICKSTART_RELEASE_BIN_DIR)/counter
QUICKSTART_ACTIVE_VERSION_FILE := /tmp/smokedmeat-quickstart-release-version
QUICKSTART_AUTH_TOKEN_FILE := $(HOME)/.smokedmeat/quickstart-auth-token
QUICKSTART_CLOUD_SHELL_PULL_PID_FILE := /tmp/smokedmeat-quickstart-cloud-shell-pull.pid
QUICKSTART_COUNTER_DARWIN_ARM64_SHA256 ?=
QUICKSTART_COUNTER_DARWIN_X86_64_SHA256 ?=
QUICKSTART_COUNTER_LINUX_ARM64_SHA256 ?=
QUICKSTART_COUNTER_LINUX_X86_64_SHA256 ?=
QUICKSTART_COUNTER_WINDOWS_ARM64_SHA256 ?=
QUICKSTART_COUNTER_WINDOWS_X86_64_SHA256 ?=
QUICKSTART_KITCHEN_IMAGE_REF ?=
QUICKSTART_CLOUD_SHELL_IMAGE_REF ?=
QUICKSTART_KITCHEN_IMAGE := $(if $(strip $(QUICKSTART_KITCHEN_IMAGE_REF)),$(QUICKSTART_KITCHEN_IMAGE_REF),$(QUICKSTART_RELEASE_REGISTRY)/smokedmeat-kitchen:$(QUICKSTART_RELEASE_VERSION))
QUICKSTART_CLOUD_SHELL_IMAGE := $(if $(strip $(QUICKSTART_CLOUD_SHELL_IMAGE_REF)),$(QUICKSTART_CLOUD_SHELL_IMAGE_REF),$(QUICKSTART_RELEASE_REGISTRY)/smokedmeat-cloud-shell:$(QUICKSTART_RELEASE_VERSION))
QUICKSTART_RELEASE_COMPOSE := AUTH_TOKEN=$$(cat $(QUICKSTART_AUTH_TOKEN_FILE) 2>/dev/null || true) SMOKEDMEAT_KITCHEN_IMAGE=$(QUICKSTART_KITCHEN_IMAGE) KITCHEN_BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)) docker compose -p smokedmeat-qs -f deployments/docker-compose.quickstart.release.yml
SEMVER_TAG_PATTERN := ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$$
RELEASE_VERSION ?= dev
RELEASE_COMMIT ?= none
RELEASE_DATE ?= unknown
KITCHEN_AGENTS_DIR := internal/kitchen/agents
RELEASE_ARTIFACTS_DIR := bin/release
RELEASE_BRISKET_BINARY := $(RELEASE_ARTIFACTS_DIR)/brisket-linux-amd64
KITCHEN_RELEASE_BRISKET_BINARY := $(KITCHEN_AGENTS_DIR)/brisket-linux-amd64
DIST_BRISKET_LINUX_AMD64 := dist/brisket-linux-amd64
DIST_BRISKET_LINUX_ARM64 := dist/brisket-linux-arm64
DIST_BRISKET_WINDOWS_AMD64 := dist/brisket-windows-amd64.exe
DIST_BRISKET_WINDOWS_ARM64 := dist/brisket-windows-arm64.exe
UPX_TOOL_IMAGE := smokedmeat-upx:5.1.1-r1
UPX_DOCKERFILE := deployments/Dockerfile.upx
RELEASE_KITCHEN_AGENT_LDFLAGS := -w -s -extldflags "-static" -X github.com/boostsecurityio/smokedmeat/internal/buildinfo.Version=$(RELEASE_VERSION) -X github.com/boostsecurityio/smokedmeat/internal/buildinfo.Commit=$(RELEASE_COMMIT) -X github.com/boostsecurityio/smokedmeat/internal/buildinfo.Date=$(RELEASE_DATE)
E2E_BROWSER_PORT_DEFAULT := 18280
E2E_BROWSER_PORT_FILE := /tmp/smokedmeat-e2e-kitchen-browser-port
E2E_TUNNEL_URL_FILE := /tmp/smokedmeat-e2e-tunnel-url
E2E_COMPOSE := KITCHEN_BROWSER_PORT=$$(cat $(E2E_BROWSER_PORT_FILE) 2>/dev/null || echo $(E2E_BROWSER_PORT_DEFAULT)) DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p smokedmeat-e2e -f deployments/docker-compose.e2e.yml
E2E_ENV := .claude/e2e/.env
E2E_TMUX_SOCKET := smokedmeat-e2e
E2E_TMUX := tmux -L $(E2E_TMUX_SOCKET)
define ensure_auth_token
	@mkdir -p .claude/e2e
	@if ! grep -qE '^AUTH_TOKEN=[0-9a-f]{64}$$' $(E2E_ENV) 2>/dev/null; then \
		TOKEN=$$(openssl rand -hex 32 2>/dev/null) || true; \
		if ! echo "$$TOKEN" | grep -qE '^[0-9a-f]{64}$$'; then \
			echo "ERROR: Failed to generate secure token (is openssl installed?)"; \
			exit 1; \
		fi; \
		grep -v '^AUTH_TOKEN=' $(E2E_ENV) > $(E2E_ENV).tmp 2>/dev/null || true; \
		echo "AUTH_TOKEN=$$TOKEN" >> $(E2E_ENV).tmp; \
		mv $(E2E_ENV).tmp $(E2E_ENV); \
		echo "Generated AUTH_TOKEN in $(E2E_ENV)"; \
	fi
endef

define pack_with_upx
	@docker build -q -t $(UPX_TOOL_IMAGE) -f $(UPX_DOCKERFILE) deployments >/dev/null
	@docker run --rm \
		-u $$(id -u):$$(id -g) \
		-v "$$(pwd)":/src \
		-w /src \
		$(UPX_TOOL_IMAGE) \
		-qq $(1)
endef

define ensure_quickstart_release_pin
	@if [ -z "$(strip $(QUICKSTART_RELEASE_VERSION))" ]; then \
		echo "ERROR: No quickstart release is pinned."; \
		echo "Run 'make quickstart-pin VERSION=v0.0.1-rc1' after validating a release."; \
		exit 1; \
	fi; \
	if [ -z "$(strip $(QUICKSTART_KITCHEN_IMAGE_REF))" ] || [ -z "$(strip $(QUICKSTART_CLOUD_SHELL_IMAGE_REF))" ]; then \
		echo "ERROR: Quickstart pin is incomplete."; \
		echo "Run 'make quickstart-pin VERSION=v$(QUICKSTART_RELEASE_VERSION)' to regenerate the verified pin."; \
		exit 1; \
	fi; \
	OS=$$(uname -s); \
	ARCH=$$(uname -m); \
	case "$$OS/$$ARCH" in \
		Darwin/arm64) EXPECTED_DIGEST='$(QUICKSTART_COUNTER_DARWIN_ARM64_SHA256)' ;; \
		Darwin/x86_64) EXPECTED_DIGEST='$(QUICKSTART_COUNTER_DARWIN_X86_64_SHA256)' ;; \
		Linux/aarch64|Linux/arm64) EXPECTED_DIGEST='$(QUICKSTART_COUNTER_LINUX_ARM64_SHA256)' ;; \
		Linux/x86_64|Linux/amd64) EXPECTED_DIGEST='$(QUICKSTART_COUNTER_LINUX_X86_64_SHA256)' ;; \
		MSYS_NT*/*|MINGW*/*|CYGWIN_NT*/*) \
			case "$$ARCH" in \
				arm64|aarch64) EXPECTED_DIGEST='$(QUICKSTART_COUNTER_WINDOWS_ARM64_SHA256)' ;; \
				x86_64|amd64) EXPECTED_DIGEST='$(QUICKSTART_COUNTER_WINDOWS_X86_64_SHA256)' ;; \
				*) EXPECTED_DIGEST="" ;; \
			esac ;; \
		*) EXPECTED_DIGEST="" ;; \
	esac; \
	if [ -z "$$EXPECTED_DIGEST" ]; then \
		echo "ERROR: Quickstart pin is missing the Counter digest for $$OS/$$ARCH."; \
		echo "Run 'make quickstart-pin VERSION=v$(QUICKSTART_RELEASE_VERSION)' to regenerate the verified pin."; \
		exit 1; \
	fi
endef

define require_quickstart_pin_tools
	@if ! command -v gh >/dev/null 2>&1; then \
		echo "ERROR: quickstart-pin requires 'gh' in PATH."; \
		exit 1; \
	fi; \
	if ! command -v cosign >/dev/null 2>&1; then \
		echo "ERROR: quickstart-pin requires 'cosign' in PATH."; \
		exit 1; \
	fi; \
	if ! command -v docker >/dev/null 2>&1; then \
		echo "ERROR: quickstart-pin requires 'docker' in PATH."; \
		exit 1; \
	fi
endef

define require_semver_tag_version
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make $(1) VERSION=v0.0.1-rc1"; \
		exit 1; \
	fi; \
	if ! printf '%s\n' "$(VERSION)" | grep -Eq '$(SEMVER_TAG_PATTERN)'; then \
		echo "ERROR: VERSION must be a v-prefixed semver tag, like v0.0.1-rc1."; \
		exit 1; \
	fi
endef

define ensure_quickstart_auth_token
	@mkdir -p $(HOME)/.smokedmeat
	@if ! grep -qE '^[0-9a-f]{64}$$' $(QUICKSTART_AUTH_TOKEN_FILE) 2>/dev/null; then \
		TOKEN=$$(openssl rand -hex 32 2>/dev/null) || true; \
		if ! echo "$$TOKEN" | grep -qE '^[0-9a-f]{64}$$'; then \
			echo "ERROR: Failed to generate secure quickstart token (is openssl installed?)"; \
			exit 1; \
		fi; \
		echo "$$TOKEN" > $(QUICKSTART_AUTH_TOKEN_FILE); \
		chmod 600 $(QUICKSTART_AUTH_TOKEN_FILE); \
		printf "\033[1;34m[auth]\033[0m Generated quickstart auth token in \033[36m%s\033[0m\n" "$(QUICKSTART_AUTH_TOKEN_FILE)"; \
	fi
endef

define warm_quickstart_release_image
	@IMAGE_REF="$(1)"; \
	IMAGE_LABEL="$(2)"; \
	if docker image inspect "$$IMAGE_REF" >/dev/null 2>&1; then \
		:; \
	elif [ -f "$(QUICKSTART_CLOUD_SHELL_PULL_PID_FILE)" ] && \
		kill -0 "$$(cat "$(QUICKSTART_CLOUD_SHELL_PULL_PID_FILE)" 2>/dev/null)" >/dev/null 2>&1; then \
		:; \
	else \
		rm -f "$(QUICKSTART_CLOUD_SHELL_PULL_PID_FILE)"; \
		printf "  \033[90mWarming optional %s image in background while Counter starts.\033[0m\n" "$$IMAGE_LABEL"; \
		nohup sh -c 'docker pull "$$1" >/dev/null 2>&1 || true; rm -f "$$2"' \
			sh "$$IMAGE_REF" "$(QUICKSTART_CLOUD_SHELL_PULL_PID_FILE)" \
			>/dev/null 2>&1 & \
		PULL_PID=$$!; \
		echo "$$PULL_PID" > "$(QUICKSTART_CLOUD_SHELL_PULL_PID_FILE)"; \
	fi
endef

define wait_for_release_quickstart_tunnel_health
	@LAST_KITCHEN=""; \
	LAST_CODE=""; \
	BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)); \
	for i in $$(seq 1 60); do \
		if [ "$$i" = "1" ]; then \
			printf "\033[1;33m[quickstart]\033[0m \033[36mWaiting for quickstart Kitchen and tunnel readiness...\033[0m\n"; \
		fi; \
		KITCHEN_READY=$$($(QUICKSTART_RELEASE_COMPOSE) logs kitchen 2>&1 | grep -c 'kitchen listening port=8080' || true); \
		TUNNEL_READY=$$($(QUICKSTART_RELEASE_COMPOSE) logs cloudflared 2>&1 | grep -c 'Registered tunnel connection' || true); \
		LAST_KITCHEN="$$KITCHEN_READY"; \
		if [ "$$KITCHEN_READY" -gt 0 ] && [ "$$TUNNEL_READY" -gt 0 ]; then \
			CODE=$$(curl -sk --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$$BROWSER_PORT/health" || true); \
			LAST_CODE="$$CODE"; \
			if [ "$$CODE" = "200" ]; then \
				printf "\033[1;32m[ready]\033[0m Quickstart tunnel is registered.\n"; \
				printf "\033[1;34m[local]\033[0m Quickstart Kitchen is reachable at \033[36mhttp://127.0.0.1:$$BROWSER_PORT\033[0m\n"; \
				printf "  \033[90mExternal callbacks may still take a moment while the tunnel hostname propagates.\033[0m\n"; \
				exit 0; \
			fi; \
		fi; \
		sleep 2; \
	done; \
	echo "ERROR: quickstart tunnel never became ready (kitchen ready count: $$LAST_KITCHEN, local health code: $$LAST_CODE)"; \
	$(QUICKSTART_RELEASE_COMPOSE) ps; \
	$(QUICKSTART_RELEASE_COMPOSE) logs --tail=50 cloudflared kitchen; \
	exit 1
endef

define wait_for_tunnel_health
	@KITCHEN_URL=$$(grep '^KITCHEN_URL=' $(E2E_ENV) | cut -d= -f2); \
	if [ -z "$$KITCHEN_URL" ]; then \
		echo "ERROR: KITCHEN_URL missing from $(E2E_ENV)"; \
		exit 1; \
	fi; \
	LAST_CODE=""; \
	for i in $$(seq 1 60); do \
		if [ "$$i" = "1" ]; then \
			echo "Waiting for local Kitchen health at $$KITCHEN_URL/health..."; \
		fi; \
		CODE=$$(curl -sk --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' \
			"$$KITCHEN_URL/health" || true); \
		LAST_CODE="$$CODE"; \
		TUNNEL_READY=$$($(E2E_COMPOSE) logs cloudflared 2>&1 | grep -c 'Registered tunnel connection' || true); \
		if [ "$$CODE" = "200" ] && [ "$$TUNNEL_READY" -gt 0 ]; then \
			echo "Kitchen and tunnel are ready."; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "ERROR: Kitchen/tunnel never became ready (local URL: $$KITCHEN_URL, last HTTP code: $$LAST_CODE)"; \
	$(E2E_COMPOSE) ps; \
	$(E2E_COMPOSE) logs --tail=50 cloudflared kitchen; \
	exit 1
endef

define wait_for_quickstart_tunnel_health
	@LAST_KITCHEN=""; \
	LAST_CODE=""; \
	BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)); \
	for i in $$(seq 1 60); do \
		if [ "$$i" = "1" ]; then \
			echo "Waiting for quickstart Kitchen and tunnel readiness..."; \
		fi; \
		KITCHEN_READY=$$($(QUICKSTART_COMPOSE) logs kitchen 2>&1 | grep -c 'kitchen listening port=8080' || true); \
		TUNNEL_READY=$$($(QUICKSTART_COMPOSE) logs cloudflared 2>&1 | grep -c 'Registered tunnel connection' || true); \
		LAST_KITCHEN="$$KITCHEN_READY"; \
		if [ "$$KITCHEN_READY" -gt 0 ] && [ "$$TUNNEL_READY" -gt 0 ]; then \
			CODE=$$(curl -sk --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$$BROWSER_PORT/health" || true); \
			LAST_CODE="$$CODE"; \
			if [ "$$CODE" = "200" ]; then \
				echo "Quickstart tunnel is registered."; \
				echo "Quickstart Kitchen is reachable locally at http://127.0.0.1:$$BROWSER_PORT."; \
				echo "External callbacks may still take a moment while the tunnel hostname propagates."; \
				exit 0; \
			fi; \
		fi; \
		sleep 2; \
	done; \
	echo "ERROR: quickstart tunnel never became ready (kitchen ready count: $$LAST_KITCHEN, local health code: $$LAST_CODE)"; \
	$(QUICKSTART_COMPOSE) ps; \
	$(QUICKSTART_COMPOSE) logs --tail=50 cloudflared kitchen; \
	exit 1
endef

define select_quickstart_browser_port
	@BROWSER_PORT=$${KITCHEN_BROWSER_PORT:-$(QUICKSTART_BROWSER_PORT_DEFAULT)}; \
	while nc -z 127.0.0.1 $$BROWSER_PORT >/dev/null 2>&1; do \
		BROWSER_PORT=$$((BROWSER_PORT + 1)); \
		if [ "$$BROWSER_PORT" -gt $$(( $(QUICKSTART_BROWSER_PORT_DEFAULT) + 40 )) ]; then \
			echo "ERROR: Could not find a free local Kitchen browser port"; \
			exit 1; \
		fi; \
	done; \
	echo "$$BROWSER_PORT" > $(QUICKSTART_BROWSER_PORT_FILE); \
	printf "\033[1;34m[local]\033[0m Kitchen browser URL \033[36mhttp://127.0.0.1:$$BROWSER_PORT\033[0m\n"
endef

define select_e2e_browser_port
	@BROWSER_PORT=$${KITCHEN_BROWSER_PORT:-$(E2E_BROWSER_PORT_DEFAULT)}; \
	while nc -z 127.0.0.1 $$BROWSER_PORT >/dev/null 2>&1; do \
		BROWSER_PORT=$$((BROWSER_PORT + 1)); \
		if [ "$$BROWSER_PORT" -gt $$(( $(E2E_BROWSER_PORT_DEFAULT) + 40 )) ]; then \
			echo "ERROR: Could not find a free local E2E Kitchen port"; \
			exit 1; \
		fi; \
	done; \
	echo "$$BROWSER_PORT" > $(E2E_BROWSER_PORT_FILE); \
	echo "Local E2E Kitchen URL: http://127.0.0.1:$$BROWSER_PORT"
endef

define run_dev_quickstart_counter
	@mkdir -p $(HOME)/.smokedmeat
	@OPERATOR_TOKEN=$$(grep '^AUTH_TOKEN=' $(E2E_ENV) | cut -d= -f2) \
	KITCHEN_URL=http://127.0.0.1:$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)) \
	KITCHEN_EXTERNAL_URL=$$(cat $(QUICKSTART_TUNNEL_URL_FILE)) \
	KITCHEN_BROWSER_URL=http://127.0.0.1:$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)) \
	COLORTERM=$${COLORTERM:-truecolor} \
	env -u NO_COLOR go run ./cmd/counter
endef

define ensure_quickstart_release_binaries
	@mkdir -p $(QUICKSTART_RELEASE_DOWNLOAD_DIR) $(QUICKSTART_RELEASE_BIN_DIR)
	@OS=$$(uname -s); \
	ARCH=$$(uname -m); \
	case "$$OS/$$ARCH" in \
		Darwin/arm64) COUNTER_ASSET=$(COUNTER_ASSET_DARWIN_ARM64); EXPECTED_DIGEST='$(QUICKSTART_COUNTER_DARWIN_ARM64_SHA256)' ;; \
		Darwin/x86_64) COUNTER_ASSET=$(COUNTER_ASSET_DARWIN_X86_64); EXPECTED_DIGEST='$(QUICKSTART_COUNTER_DARWIN_X86_64_SHA256)' ;; \
		Linux/aarch64|Linux/arm64) COUNTER_ASSET=$(COUNTER_ASSET_LINUX_ARM64); EXPECTED_DIGEST='$(QUICKSTART_COUNTER_LINUX_ARM64_SHA256)' ;; \
		Linux/x86_64|Linux/amd64) COUNTER_ASSET=$(COUNTER_ASSET_LINUX_X86_64); EXPECTED_DIGEST='$(QUICKSTART_COUNTER_LINUX_X86_64_SHA256)' ;; \
		MSYS_NT*/*|MINGW*/*|CYGWIN_NT*/*) \
			case "$$ARCH" in \
				arm64|aarch64) COUNTER_ASSET=$(COUNTER_ASSET_WINDOWS_ARM64); EXPECTED_DIGEST='$(QUICKSTART_COUNTER_WINDOWS_ARM64_SHA256)' ;; \
				x86_64|amd64) COUNTER_ASSET=$(COUNTER_ASSET_WINDOWS_X86_64); EXPECTED_DIGEST='$(QUICKSTART_COUNTER_WINDOWS_X86_64_SHA256)' ;; \
				*) echo "ERROR: Unsupported Windows architecture: $$ARCH"; exit 1 ;; \
			esac ;; \
		*) echo "ERROR: Unsupported host for quickstart Counter: $$OS/$$ARCH"; exit 1 ;; \
	esac; \
	if [ -z "$$EXPECTED_DIGEST" ]; then \
		echo "ERROR: Quickstart pin is missing the Counter digest for $$OS/$$ARCH."; \
		exit 1; \
	fi; \
	COUNTER_ARCHIVE="$(QUICKSTART_RELEASE_DOWNLOAD_DIR)/$$COUNTER_ASSET"; \
	NEEDS_DOWNLOAD=0; \
	NEEDS_EXTRACT=0; \
	if [ ! -f "$$COUNTER_ARCHIVE" ]; then \
		NEEDS_DOWNLOAD=1; \
		NEEDS_EXTRACT=1; \
	else \
		ACTUAL_DIGEST="sha256:$$(shasum -a 256 "$$COUNTER_ARCHIVE" | awk '{print $$1}')"; \
		if [ "$$ACTUAL_DIGEST" != "$$EXPECTED_DIGEST" ]; then \
			echo "Refreshing cached Counter archive due to digest mismatch."; \
			rm -f "$$COUNTER_ARCHIVE"; \
			NEEDS_DOWNLOAD=1; \
			NEEDS_EXTRACT=1; \
		fi; \
	fi; \
	if [ ! -x "$(QUICKSTART_RELEASE_COUNTER_BIN)" ] && [ ! -x "$(QUICKSTART_RELEASE_COUNTER_BIN).exe" ]; then \
		NEEDS_EXTRACT=1; \
	fi; \
	if [ "$$NEEDS_DOWNLOAD" = "1" ]; then \
		printf "\033[1;33m[cache]\033[0m Downloading Counter $(QUICKSTART_RELEASE_TAG) (\033[36m%s\033[0m)...\n" "$$COUNTER_ASSET"; \
		if command -v gh >/dev/null 2>&1; then \
			if ! gh release download $(QUICKSTART_RELEASE_TAG) --repo $(QUICKSTART_RELEASE_REPOSITORY) --pattern "$$COUNTER_ASSET" --output "$$COUNTER_ARCHIVE"; then \
				echo "ERROR: Failed to download $$COUNTER_ASSET with gh."; \
				echo "Authenticate gh or set GH_TOKEN before running 'make quickstart'."; \
				exit 1; \
			fi; \
		else \
			if ! curl -fsSL -o "$$COUNTER_ARCHIVE" "https://github.com/$(QUICKSTART_RELEASE_REPOSITORY)/releases/download/$(QUICKSTART_RELEASE_TAG)/$$COUNTER_ASSET"; then \
				echo "ERROR: Failed to download $$COUNTER_ASSET with curl."; \
				echo "Install gh and authenticate it if the release repository is not public."; \
				exit 1; \
			fi; \
		fi; \
	fi; \
	ACTUAL_DIGEST="sha256:$$(shasum -a 256 "$$COUNTER_ARCHIVE" | awk '{print $$1}')"; \
	if [ "$$ACTUAL_DIGEST" != "$$EXPECTED_DIGEST" ]; then \
		echo "ERROR: Counter digest mismatch for $$COUNTER_ASSET."; \
		echo "Expected: $$EXPECTED_DIGEST"; \
		echo "Actual:   $$ACTUAL_DIGEST"; \
		rm -f "$$COUNTER_ARCHIVE"; \
		exit 1; \
	fi; \
	if [ "$$NEEDS_EXTRACT" = "1" ]; then \
		rm -f "$(QUICKSTART_RELEASE_BIN_DIR)/counter" "$(QUICKSTART_RELEASE_BIN_DIR)/counter.exe"; \
		case "$$COUNTER_ASSET" in \
			*.tar.gz) tar -xzf "$$COUNTER_ARCHIVE" -C "$(QUICKSTART_RELEASE_BIN_DIR)" ;; \
			*.zip) unzip -oq "$$COUNTER_ARCHIVE" -d "$(QUICKSTART_RELEASE_BIN_DIR)" ;; \
		esac; \
	else \
		printf "\033[1;33m[cache]\033[0m Counter %s already cached.\n" "$(QUICKSTART_RELEASE_TAG)"; \
	fi; \
	printf "  \033[90mCache lives in \033[36m%s\033[90m - use \033[36m%s\033[90m to remove it.\033[0m\n" "~/.smokedmeat/releases/$(QUICKSTART_RELEASE_VERSION)" "make quickstart-drop-cache"; \
	printf "  \033[90mKitchen and tunnel stay up after Counter exits - use \033[36m%s\033[90m to stop them.\033[0m\n" "make quickstart-down"; \
	printf "  \033[90mOperator config lives in \033[36m%s\033[90m.\033[0m\n" "~/.smokedmeat"
endef

define run_quickstart_counter
	@mkdir -p $(HOME)/.smokedmeat
	@COUNTER_BIN="$(QUICKSTART_RELEASE_COUNTER_BIN)"; \
	if [ ! -x "$$COUNTER_BIN" ] && [ -x "$$COUNTER_BIN.exe" ]; then \
		COUNTER_BIN="$$COUNTER_BIN.exe"; \
	fi; \
	OPERATOR_TOKEN=$$(cat $(QUICKSTART_AUTH_TOKEN_FILE)) \
	KITCHEN_URL=http://127.0.0.1:$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)) \
	KITCHEN_EXTERNAL_URL=$$(cat $(QUICKSTART_TUNNEL_URL_FILE)) \
	KITCHEN_BROWSER_URL=http://127.0.0.1:$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)) \
	SMOKEDMEAT_CLOUD_SHELL_IMAGE=$(QUICKSTART_CLOUD_SHELL_IMAGE) \
	COLORTERM=$${COLORTERM:-truecolor} \
	env -u NO_COLOR "$$COUNTER_BIN"
endef

define ensure_cloud_shell_image
	if docker image inspect smokedmeat-cloud-shell >/dev/null 2>&1; then \
		echo "Cloud shell image already available."; \
	else \
		echo "Building cloud shell image..."; \
		$(MAKE) cloud-shell-image; \
	fi
endef

define refresh_dev_quickstart_kitchen
	@AUTH_TOKEN=$$(grep '^AUTH_TOKEN=' $(E2E_ENV) | cut -d= -f2) \
	$(QUICKSTART_COMPOSE) up -d --build kitchen-init kitchen
endef

define wait_for_quickstart_kitchen_health
	@LAST_CODE=""; \
	BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)); \
	for i in $$(seq 1 30); do \
		if [ "$$i" = "1" ]; then \
			echo "Waiting for quickstart Kitchen readiness..."; \
		fi; \
		CODE=$$(curl -sk --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$$BROWSER_PORT/health" || true); \
		LAST_CODE="$$CODE"; \
		if [ "$$CODE" = "200" ]; then \
			echo "Quickstart Kitchen is reachable locally at http://127.0.0.1:$$BROWSER_PORT."; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "ERROR: quickstart Kitchen never became ready (local health code: $$LAST_CODE)"; \
	$(QUICKSTART_COMPOSE) ps; \
	$(QUICKSTART_COMPOSE) logs --tail=50 kitchen; \
	exit 1
endef

quickstart:
	$(call ensure_quickstart_release_pin)
	$(call print_release_quickstart_banner)
	@BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)); \
	TUNNEL_URL=$$(cat $(QUICKSTART_TUNNEL_URL_FILE) 2>/dev/null || true); \
	ACTIVE_VERSION=$$(cat $(QUICKSTART_ACTIVE_VERSION_FILE) 2>/dev/null || true); \
	CODE=$$(curl -sk --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$$BROWSER_PORT/health" || true); \
	if [ -n "$$TUNNEL_URL" ] && [ "$$CODE" = "200" ] && [ "$$ACTIVE_VERSION" = "$(QUICKSTART_RELEASE_VERSION)" ]; then \
		printf "\033[1;35m[reuse]\033[0m Reusing running SmokedMeat quick start %s.\n" "$(QUICKSTART_RELEASE_TAG)"; \
	else \
		$(MAKE) --no-print-directory quickstart-up SMOKEDMEAT_QUICKSTART_BANNER_SHOWN=1; \
	fi
	$(call print_quickstart_step,Preparing Counter runtime...)
	$(call ensure_quickstart_release_binaries)
	$(call warm_quickstart_release_image,$(QUICKSTART_CLOUD_SHELL_IMAGE),cloud shell)
	$(call print_quickstart_step,Starting Counter TUI...)
	$(call run_quickstart_counter)

quickstart-up:
	$(call ensure_quickstart_release_pin)
	$(call ensure_quickstart_auth_token)
	$(call print_release_quickstart_banner)
	$(call print_quickstart_step,Starting SmokedMeat quick start $(QUICKSTART_RELEASE_TAG)...)
	@mkdir -p $(HOME)/.smokedmeat
	@rm -f $(QUICKSTART_TUNNEL_URL_FILE)
	$(call select_quickstart_browser_port)
	$(call print_quickstart_step,Preparing Docker services...)
	$(call print_quickstart_note,nats carries orders and beacons between Kitchen and agents.)
	$(call print_quickstart_note,kitchen serves the operator API and callback endpoints.)
	$(call print_quickstart_note,cloudflared publishes a temporary HTTPS callback URL.)
	$(call print_quickstart_hint,First run usually takes about 15 seconds while Docker pulls and starts the stack.)
	$(call start_release_quickstart_services)
	$(call print_quickstart_step,Waiting for tunnel URL...)
	@TUNNEL_URL=""; \
	for attempt in 1 2 3; do \
		for i in $$(seq 1 20); do \
			TUNNEL_URL=$$($(QUICKSTART_RELEASE_COMPOSE) logs cloudflared 2>&1 | \
				grep -Eo 'https://[[:alnum:]-]+\.trycloudflare\.com' | \
				grep -v '^https://api\.trycloudflare\.com$$' | tail -1); \
			if [ -n "$$TUNNEL_URL" ]; then break 2; fi; \
			sleep 1; \
		done; \
		if [ "$$attempt" -lt 3 ]; then \
			printf "  \033[90mRetrying cloudflared quick tunnel...\033[0m\n"; \
			$(QUICKSTART_RELEASE_COMPOSE) restart cloudflared >/dev/null; \
		fi; \
	done; \
	if [ -n "$$TUNNEL_URL" ]; then \
		printf "\033[1;32m[tunnel]\033[0m \033[36m%s\033[0m\n" "$$TUNNEL_URL"; \
		echo ""; \
		echo "$$TUNNEL_URL" > $(QUICKSTART_TUNNEL_URL_FILE); \
		echo "$(QUICKSTART_RELEASE_VERSION)" > $(QUICKSTART_ACTIVE_VERSION_FILE); \
	else \
		echo "ERROR: Could not find tunnel URL"; \
		$(QUICKSTART_RELEASE_COMPOSE) logs cloudflared; \
		exit 1; \
	fi
	$(call wait_for_release_quickstart_tunnel_health)

quickstart-counter:
	$(call ensure_quickstart_release_pin)
	$(call print_release_quickstart_banner)
	@if [ ! -f $(QUICKSTART_TUNNEL_URL_FILE) ]; then \
		echo "Run 'make quickstart-up' first"; \
		exit 1; \
	fi
	$(call ensure_quickstart_auth_token)
	$(call print_quickstart_step,Preparing Counter runtime...)
	$(call ensure_quickstart_release_binaries)
	$(call warm_quickstart_release_image,$(QUICKSTART_CLOUD_SHELL_IMAGE),cloud shell)
	$(call print_quickstart_step,Starting Counter TUI...)
	$(call run_quickstart_counter)

quickstart-down:
	$(call ensure_quickstart_release_pin)
	$(QUICKSTART_RELEASE_COMPOSE) down
	rm -f $(QUICKSTART_TUNNEL_URL_FILE)
	rm -f $(QUICKSTART_BROWSER_PORT_FILE)
	rm -f $(QUICKSTART_ACTIVE_VERSION_FILE)

quickstart-purge:
	$(call ensure_quickstart_release_pin)
	$(QUICKSTART_RELEASE_COMPOSE) down -v
	rm -f $(QUICKSTART_TUNNEL_URL_FILE)
	rm -f $(QUICKSTART_BROWSER_PORT_FILE)
	rm -f $(QUICKSTART_ACTIVE_VERSION_FILE)

quickstart-version:
	@if [ -z "$(strip $(QUICKSTART_RELEASE_VERSION))" ]; then \
		echo "Quickstart release pin: <unset>"; \
		echo "Run 'make quickstart-pin VERSION=v0.0.1-rc1' after validating a release."; \
		echo "Maintainer only - requires 'gh', 'cosign', and 'docker' in PATH."; \
	else \
		echo "Quickstart release version: $(QUICKSTART_RELEASE_VERSION)"; \
		echo "Quickstart release tag: $(QUICKSTART_RELEASE_TAG)"; \
		echo "Counter release repo: $(QUICKSTART_RELEASE_REPOSITORY)"; \
		echo "Kitchen image ref: $(QUICKSTART_KITCHEN_IMAGE)"; \
		echo "Cloud shell image ref: $(QUICKSTART_CLOUD_SHELL_IMAGE)"; \
	fi

quickstart-pin:
	$(call require_semver_tag_version,quickstart-pin)
	$(call require_quickstart_pin_tools)
	@mkdir -p configs; \
	PIN_TAG="$(VERSION)"; \
	PIN_VERSION=$${PIN_TAG#v}; \
	RELEASE_REPO="$(QUICKSTART_RELEASE_REPOSITORY)"; \
	RELEASE_REGISTRY="$(QUICKSTART_RELEASE_REGISTRY)"; \
	DOCKER_CONFIG_DIR=$$(mktemp -d); \
	cleanup() { rm -rf "$$DOCKER_CONFIG_DIR"; }; \
	trap cleanup EXIT INT TERM; \
	export DOCKER_CONFIG="$$DOCKER_CONFIG_DIR"; \
	GHCR_AUTH_READY=""; \
	KITCHEN_REPO="$$RELEASE_REGISTRY/smokedmeat-kitchen"; \
	CLOUD_SHELL_REPO="$$RELEASE_REGISTRY/smokedmeat-cloud-shell"; \
	KITCHEN_TAG_REF="$$KITCHEN_REPO:$$PIN_VERSION"; \
	CLOUD_SHELL_TAG_REF="$$CLOUD_SHELL_REPO:$$PIN_VERSION"; \
	WORKFLOW_IDENTITY="https://github.com/$$RELEASE_REPO/.github/workflows/release.yml@refs/tags/$$PIN_TAG"; \
	if [ "$$(gh release view "$$PIN_TAG" --repo "$$RELEASE_REPO" --json isImmutable --jq '.isImmutable')" != "true" ]; then \
		echo "ERROR: Release $$PIN_TAG is not immutable on GitHub."; \
		exit 1; \
	fi; \
	echo "Verifying GitHub release attestation for $$PIN_TAG..."; \
	gh release verify "$$PIN_TAG" --repo "$$RELEASE_REPO" >/dev/null; \
	ASSET_LINES="$$(gh api -H 'Accept: application/vnd.github+json' "repos/$$RELEASE_REPO/releases/tags/$$PIN_TAG" --jq '.assets[] | [.name, (.digest // "")] | @tsv')"; \
	asset_digest() { \
		printf '%s\n' "$$ASSET_LINES" | awk -F '\t' -v asset="$$1" '$$1 == asset { print $$2; exit }'; \
	}; \
	COUNTER_DARWIN_ARM64_SHA256=$$(asset_digest "$(COUNTER_ASSET_DARWIN_ARM64)"); \
	COUNTER_DARWIN_X86_64_SHA256=$$(asset_digest "$(COUNTER_ASSET_DARWIN_X86_64)"); \
	COUNTER_LINUX_ARM64_SHA256=$$(asset_digest "$(COUNTER_ASSET_LINUX_ARM64)"); \
	COUNTER_LINUX_X86_64_SHA256=$$(asset_digest "$(COUNTER_ASSET_LINUX_X86_64)"); \
	COUNTER_WINDOWS_ARM64_SHA256=$$(asset_digest "$(COUNTER_ASSET_WINDOWS_ARM64)"); \
	COUNTER_WINDOWS_X86_64_SHA256=$$(asset_digest "$(COUNTER_ASSET_WINDOWS_X86_64)"); \
	if [ -z "$$COUNTER_DARWIN_ARM64_SHA256" ]; then echo "ERROR: Release $$PIN_TAG is missing a digest for $(COUNTER_ASSET_DARWIN_ARM64)."; exit 1; fi; \
	if [ -z "$$COUNTER_DARWIN_X86_64_SHA256" ]; then echo "ERROR: Release $$PIN_TAG is missing a digest for $(COUNTER_ASSET_DARWIN_X86_64)."; exit 1; fi; \
	if [ -z "$$COUNTER_LINUX_ARM64_SHA256" ]; then echo "ERROR: Release $$PIN_TAG is missing a digest for $(COUNTER_ASSET_LINUX_ARM64)."; exit 1; fi; \
	if [ -z "$$COUNTER_LINUX_X86_64_SHA256" ]; then echo "ERROR: Release $$PIN_TAG is missing a digest for $(COUNTER_ASSET_LINUX_X86_64)."; exit 1; fi; \
	if [ -z "$$COUNTER_WINDOWS_ARM64_SHA256" ]; then echo "ERROR: Release $$PIN_TAG is missing a digest for $(COUNTER_ASSET_WINDOWS_ARM64)."; exit 1; fi; \
	if [ -z "$$COUNTER_WINDOWS_X86_64_SHA256" ]; then echo "ERROR: Release $$PIN_TAG is missing a digest for $(COUNTER_ASSET_WINDOWS_X86_64)."; exit 1; fi; \
	login_ghcr() { \
		if [ -n "$$GHCR_AUTH_READY" ]; then \
			return 0; \
		fi; \
		GH_USER=$$(gh api user --jq '.login' 2>/dev/null || true); \
		GH_TOKEN=$$(gh auth token 2>/dev/null || true); \
		if [ -z "$$GH_USER" ] || [ -z "$$GH_TOKEN" ]; then \
			return 1; \
		fi; \
		if ! printf '%s\n' "$$GH_TOKEN" | docker login ghcr.io -u "$$GH_USER" --password-stdin >/dev/null 2>&1; then \
			return 1; \
		fi; \
		GHCR_AUTH_READY=1; \
		return 0; \
	}; \
	resolve_image_digest() { \
		if ! login_ghcr; then \
			return 1; \
		fi; \
		IMAGE_REF="$$1"; \
		IMAGE_REPO=$${IMAGE_REF%:*}; \
		IMAGE_TAG=$${IMAGE_REF##*:}; \
		IMAGE_SCOPE=$${IMAGE_REPO#*/}; \
		REGISTRY_TOKEN=$$(curl -fsS -u "$$GH_USER:$$GH_TOKEN" "https://ghcr.io/token?service=ghcr.io&scope=repository:$$IMAGE_SCOPE:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'); \
		if [ -z "$$REGISTRY_TOKEN" ]; then \
			return 1; \
		fi; \
		HEADERS_FILE=$$(mktemp); \
		if ! curl -fsS -D "$$HEADERS_FILE" -o /dev/null -H "Authorization: Bearer $$REGISTRY_TOKEN" -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' "https://ghcr.io/v2/$$IMAGE_SCOPE/manifests/$$IMAGE_TAG"; then \
			rm -f "$$HEADERS_FILE"; \
			return 1; \
		fi; \
		DIGEST=$$(awk 'tolower($$1) == "docker-content-digest:" { gsub("\\r", "", $$2); print $$2; exit }' "$$HEADERS_FILE"); \
		rm -f "$$HEADERS_FILE"; \
		printf '%s\n' "$$DIGEST"; \
	}; \
	KITCHEN_DIGEST=$$(resolve_image_digest "$$KITCHEN_TAG_REF"); \
	CLOUD_SHELL_DIGEST=$$(resolve_image_digest "$$CLOUD_SHELL_TAG_REF"); \
	if [ -z "$$KITCHEN_DIGEST" ]; then \
		echo "ERROR: Failed to resolve a manifest digest for $$KITCHEN_TAG_REF."; \
		echo "Ensure 'gh' is authenticated for an account that can read GHCR packages."; \
		exit 1; \
	fi; \
	if [ -z "$$CLOUD_SHELL_DIGEST" ]; then \
		echo "ERROR: Failed to resolve a manifest digest for $$CLOUD_SHELL_TAG_REF."; \
		echo "Ensure 'gh' is authenticated for an account that can read GHCR packages."; \
		exit 1; \
	fi; \
	KITCHEN_IMAGE_REF="$$KITCHEN_REPO@$$KITCHEN_DIGEST"; \
	CLOUD_SHELL_IMAGE_REF="$$CLOUD_SHELL_REPO@$$CLOUD_SHELL_DIGEST"; \
	if [ -z "$$GHCR_AUTH_READY" ]; then \
		login_ghcr >/dev/null 2>&1 || true; \
	fi; \
	echo "Verifying signed Kitchen image $$KITCHEN_IMAGE_REF..."; \
	cosign verify --output json --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity "$$WORKFLOW_IDENTITY" "$$KITCHEN_IMAGE_REF" >/dev/null; \
	echo "Verifying signed cloud shell image $$CLOUD_SHELL_IMAGE_REF..."; \
	cosign verify --output json --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity "$$WORKFLOW_IDENTITY" "$$CLOUD_SHELL_IMAGE_REF" >/dev/null; \
	printf '# Copyright (C) 2026 boostsecurity.io\n# SPDX-License-Identifier: AGPL-3.0-or-later\n\nQUICKSTART_RELEASE_VERSION := %s\nQUICKSTART_RELEASE_REGISTRY := %s\nQUICKSTART_RELEASE_REPOSITORY := %s\nQUICKSTART_KITCHEN_IMAGE_REF := %s\nQUICKSTART_CLOUD_SHELL_IMAGE_REF := %s\nQUICKSTART_COUNTER_DARWIN_ARM64_SHA256 := %s\nQUICKSTART_COUNTER_DARWIN_X86_64_SHA256 := %s\nQUICKSTART_COUNTER_LINUX_ARM64_SHA256 := %s\nQUICKSTART_COUNTER_LINUX_X86_64_SHA256 := %s\nQUICKSTART_COUNTER_WINDOWS_ARM64_SHA256 := %s\nQUICKSTART_COUNTER_WINDOWS_X86_64_SHA256 := %s\n' "$$PIN_VERSION" "$$RELEASE_REGISTRY" "$$RELEASE_REPO" "$$KITCHEN_IMAGE_REF" "$$CLOUD_SHELL_IMAGE_REF" "$$COUNTER_DARWIN_ARM64_SHA256" "$$COUNTER_DARWIN_X86_64_SHA256" "$$COUNTER_LINUX_ARM64_SHA256" "$$COUNTER_LINUX_X86_64_SHA256" "$$COUNTER_WINDOWS_ARM64_SHA256" "$$COUNTER_WINDOWS_X86_64_SHA256" > $(QUICKSTART_RELEASE_CONFIG); \
	echo "Pinned verified quickstart release $$PIN_TAG"; \
	$(MAKE) quickstart-version

quickstart-cache:
	$(call ensure_quickstart_release_pin)
	$(call ensure_quickstart_release_binaries)

quickstart-drop-cache:
	$(call ensure_quickstart_release_pin)
	@if [ -d "$(QUICKSTART_RELEASE_CACHE_DIR)" ]; then \
		rm -rf "$(QUICKSTART_RELEASE_CACHE_DIR)"; \
		echo "Removed quickstart cache $(QUICKSTART_RELEASE_CACHE_DIR)"; \
	else \
		echo "Quickstart cache already absent: $(QUICKSTART_RELEASE_CACHE_DIR)"; \
	fi

tag:
	$(call require_semver_tag_version,tag)
	@if git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null 2>&1; then \
		echo "ERROR: Tag $(VERSION) already exists locally."; \
		exit 1; \
	fi
	@git tag -s "$(VERSION)" -m "Release $(VERSION)"
	@git push origin "$(VERSION)"
	@echo "Tagged, signed, and pushed $(VERSION)"

dev-quickstart:
	@BROWSER_PORT=$$(cat $(QUICKSTART_BROWSER_PORT_FILE) 2>/dev/null || echo $(QUICKSTART_BROWSER_PORT_DEFAULT)); \
	TUNNEL_URL=$$(cat $(QUICKSTART_TUNNEL_URL_FILE) 2>/dev/null || true); \
	CODE=$$(curl -sk --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$$BROWSER_PORT/health" || true); \
	if [ -n "$$TUNNEL_URL" ] && [ "$$CODE" = "200" ]; then \
		echo "Reusing running SmokedMeat dev quick start."; \
		$(MAKE) dev-quickstart-refresh; \
	else \
		$(MAKE) dev-quickstart-up; \
	fi
	@echo "Starting Counter TUI..."
	$(call run_dev_quickstart_counter)

dev-quickstart-up:
	@$(call ensure_cloud_shell_image)
	@echo "Starting SmokedMeat dev quick start..."
	$(call ensure_auth_token)
	@mkdir -p $(HOME)/.smokedmeat
	@rm -f $(QUICKSTART_TUNNEL_URL_FILE)
	$(call select_quickstart_browser_port)
	@AUTH_TOKEN=$$(grep '^AUTH_TOKEN=' $(E2E_ENV) | cut -d= -f2) \
	$(QUICKSTART_COMPOSE) up -d --build cloudflared nats
	$(call refresh_dev_quickstart_kitchen)
	@echo "Waiting for tunnel URL..."
	@TUNNEL_URL=""; \
	for attempt in 1 2 3; do \
		for i in $$(seq 1 20); do \
			TUNNEL_URL=$$($(QUICKSTART_COMPOSE) logs cloudflared 2>&1 | \
				grep -Eo 'https://[[:alnum:]-]+\.trycloudflare\.com' | \
				grep -v '^https://api\.trycloudflare\.com$$' | tail -1); \
			if [ -n "$$TUNNEL_URL" ]; then break 2; fi; \
			sleep 1; \
		done; \
		if [ "$$attempt" -lt 3 ]; then \
			echo "Retrying cloudflared quick tunnel..."; \
			$(QUICKSTART_COMPOSE) restart cloudflared >/dev/null; \
		fi; \
	done; \
	if [ -n "$$TUNNEL_URL" ]; then \
		echo ""; \
		echo "Tunnel URL: $$TUNNEL_URL"; \
		echo ""; \
		echo "$$TUNNEL_URL" > $(QUICKSTART_TUNNEL_URL_FILE); \
	else \
		echo "ERROR: Could not find tunnel URL"; \
		$(QUICKSTART_COMPOSE) logs cloudflared; \
		exit 1; \
	fi
	$(call wait_for_quickstart_tunnel_health)

dev-quickstart-refresh:
	@$(call ensure_cloud_shell_image)
	$(call refresh_dev_quickstart_kitchen)
	$(call wait_for_quickstart_kitchen_health)

dev-quickstart-counter:
	@if [ ! -f $(QUICKSTART_TUNNEL_URL_FILE) ]; then \
		echo "Run 'make dev-quickstart-up' first"; \
		exit 1; \
	fi
	$(MAKE) dev-quickstart-refresh
	$(call run_dev_quickstart_counter)

dev-quickstart-down:
	$(QUICKSTART_COMPOSE) down
	rm -f $(QUICKSTART_TUNNEL_URL_FILE)
	rm -f $(QUICKSTART_BROWSER_PORT_FILE)

dev-quickstart-purge:
	$(QUICKSTART_COMPOSE) down -v
	rm -f $(QUICKSTART_TUNNEL_URL_FILE)
	rm -f $(QUICKSTART_BROWSER_PORT_FILE)

# =============================================================================
# Counter (Remote Kitchen)
# =============================================================================

counter:
	@go run ./cmd/counter

# =============================================================================
# Testing
# =============================================================================

test:
	go test -cover ./...

test-verbose:
	go test -cover -v ./...

test-race:
	go test -race -cover ./...

# =============================================================================
# Linting
# =============================================================================

lint:
	golangci-lint run ./...

lint-fix:
	golangci-lint run --fix ./...

# =============================================================================
# Dependencies
# =============================================================================

tidy:
	go mod tidy

pinact:
	pinact run

# =============================================================================
# Build Briskets
# =============================================================================

build-release-embed-brisket:
	@mkdir -p $(RELEASE_ARTIFACTS_DIR) $(KITCHEN_AGENTS_DIR)
	@rm -f $(RELEASE_BRISKET_BINARY)
	@rm -f $(KITCHEN_AGENTS_DIR)/brisket-*
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-tags netgo \
		-ldflags='$(RELEASE_KITCHEN_AGENT_LDFLAGS)' \
		-trimpath \
		-o $(RELEASE_BRISKET_BINARY) ./cmd/brisket
	$(call pack_with_upx,$(RELEASE_BRISKET_BINARY))
	@cp $(RELEASE_BRISKET_BINARY) $(KITCHEN_RELEASE_BRISKET_BINARY)
	@cmp -s $(RELEASE_BRISKET_BINARY) $(KITCHEN_RELEASE_BRISKET_BINARY)

build-brisket:
	@mkdir -p dist $(KITCHEN_AGENTS_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a \
		-tags netgo \
		-ldflags='-w -s -extldflags "-static"' \
		-trimpath \
		-o $(DIST_BRISKET_LINUX_AMD64) ./cmd/brisket
	$(call pack_with_upx,$(DIST_BRISKET_LINUX_AMD64))
	@cp $(DIST_BRISKET_LINUX_AMD64) $(KITCHEN_AGENTS_DIR)/

build-brisket-all:
	@mkdir -p dist $(KITCHEN_AGENTS_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags='-w -s' -trimpath -o $(DIST_BRISKET_LINUX_AMD64) ./cmd/brisket
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -tags netgo -ldflags='-w -s' -trimpath -o $(DIST_BRISKET_LINUX_ARM64) ./cmd/brisket
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -a -tags netgo -ldflags='-w -s' -trimpath -o dist/brisket-darwin-amd64 ./cmd/brisket
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -a -tags netgo -ldflags='-w -s' -trimpath -o dist/brisket-darwin-arm64 ./cmd/brisket
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -a -tags netgo -ldflags='-w -s' -trimpath -o $(DIST_BRISKET_WINDOWS_AMD64) ./cmd/brisket
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -a -tags netgo -ldflags='-w -s' -trimpath -o $(DIST_BRISKET_WINDOWS_ARM64) ./cmd/brisket
	$(call pack_with_upx,$(DIST_BRISKET_LINUX_AMD64) $(DIST_BRISKET_LINUX_ARM64) $(DIST_BRISKET_WINDOWS_AMD64))
	@cp dist/brisket-linux-* $(KITCHEN_AGENTS_DIR)/

# =============================================================================
# Cloud Shell Image
# =============================================================================

cloud-base-image:
	docker build -t smokedmeat-cloud-base:latest -t smokedmeat-cloud-base -f deployments/Dockerfile.cloud-base .

cloud-shell-image: cloud-base-image
	docker build -t smokedmeat-cloud-shell:latest -t smokedmeat-cloud-shell -f deployments/Dockerfile.cloud-shell .

# =============================================================================
# E2E Testing (Claude Code automation)
# =============================================================================

E2E_SESSION := smokedmeat-e2e

e2e-up:
	@echo "Starting E2E services..."
	$(MAKE) cloud-shell-image
	$(call ensure_auth_token)
	$(call select_e2e_browser_port)
	@AUTH_TOKEN=$$(grep '^AUTH_TOKEN=' $(E2E_ENV) | cut -d= -f2) \
	$(E2E_COMPOSE) up -d --build cloudflared nats kitchen-init kitchen
	@echo "Waiting for tunnel URL..."
	@TUNNEL_URL=""; \
	for attempt in 1 2 3; do \
		for i in $$(seq 1 20); do \
			TUNNEL_URL=$$($(E2E_COMPOSE) logs cloudflared 2>&1 | \
				grep -Eo 'https://[[:alnum:]-]+\.trycloudflare\.com' | \
				grep -v '^https://api\.trycloudflare\.com$$' | tail -1); \
			if [ -n "$$TUNNEL_URL" ]; then break 2; fi; \
			sleep 1; \
		done; \
		if [ "$$attempt" -lt 3 ]; then \
			echo "Retrying cloudflared quick tunnel..."; \
			$(E2E_COMPOSE) restart cloudflared >/dev/null; \
		fi; \
	done; \
	if [ -z "$$TUNNEL_URL" ]; then \
		echo "ERROR: Could not find tunnel URL"; \
		$(E2E_COMPOSE) logs cloudflared; \
		exit 1; \
	fi; \
	E2E_KITCHEN_URL=http://127.0.0.1:$$(cat $(E2E_BROWSER_PORT_FILE) 2>/dev/null || echo $(E2E_BROWSER_PORT_DEFAULT)); \
	grep -v '^KITCHEN_URL=' $(E2E_ENV) | grep -v '^KITCHEN_EXTERNAL_URL=' > $(E2E_ENV).tmp 2>/dev/null || true; \
	echo "KITCHEN_URL=$$E2E_KITCHEN_URL" >> $(E2E_ENV).tmp; \
	echo "KITCHEN_EXTERNAL_URL=$$TUNNEL_URL" >> $(E2E_ENV).tmp; \
	mv $(E2E_ENV).tmp $(E2E_ENV); \
	echo ""; \
	echo "Kitchen URL: $$E2E_KITCHEN_URL"; \
	echo "Tunnel URL: $$TUNNEL_URL"; \
	echo "$$TUNNEL_URL" > $(E2E_TUNNEL_URL_FILE)
	$(call wait_for_tunnel_health)
	@echo "E2E infrastructure ready. Tunnel URL:"
	@cat $(E2E_TUNNEL_URL_FILE)

e2e-down:
	$(E2E_COMPOSE) down
	@tmux kill-session -t $(E2E_SESSION) 2>/dev/null || true
	@$(E2E_TMUX) kill-server 2>/dev/null || true
	rm -f $(E2E_TUNNEL_URL_FILE)
	rm -f $(E2E_BROWSER_PORT_FILE)

e2e-purge:
	$(E2E_COMPOSE) down -v
	@tmux kill-session -t $(E2E_SESSION) 2>/dev/null || true
	@$(E2E_TMUX) kill-server 2>/dev/null || true
	rm -f $(E2E_TUNNEL_URL_FILE)
	rm -f $(E2E_BROWSER_PORT_FILE)
	@rm -rf ./data/kitchen.db

e2e-counter:
	@if [ ! -f $(E2E_ENV) ]; then \
		echo "ERROR: $(E2E_ENV) not found. Run 'make e2e-up' first"; \
		exit 1; \
	fi
	@if ! grep -qE '^AUTH_TOKEN=' $(E2E_ENV); then \
		echo "ERROR: AUTH_TOKEN not in $(E2E_ENV). Run 'make e2e-up' first"; \
		exit 1; \
	fi
	@if ! grep -qE '^KITCHEN_URL=' $(E2E_ENV); then \
		echo "ERROR: KITCHEN_URL not in $(E2E_ENV). Run 'make e2e-up' first"; \
		exit 1; \
	fi
	@tmux kill-session -t $(E2E_SESSION) 2>/dev/null || true
	@$(E2E_TMUX) kill-server 2>/dev/null || true
	@$(E2E_TMUX) new-session -d -s $(E2E_SESSION) -x 140 -y 50
	@$(E2E_TMUX) send-keys -t $(E2E_SESSION) "source $(E2E_ENV) && \
		OPERATOR_TOKEN=\$$AUTH_TOKEN \
		KITCHEN_URL=\$$KITCHEN_URL \
		KITCHEN_EXTERNAL_URL=\$$KITCHEN_EXTERNAL_URL \
		SESSION_ID='$(SESSION_ID)' \
		SMOKEDMEAT_CONFIG_DIR=.claude/e2e \
		env -u NO_COLOR COLORTERM=truecolor go run ./cmd/counter -kitchen \$$KITCHEN_URL -operator ''" Enter
	@echo "Counter running in tmux session '$(E2E_SESSION)'"
	@echo "  Capture: make e2e-capture"
	@echo "  Attach:  $(E2E_TMUX) attach -t $(E2E_SESSION)"

e2e-capture:
	@$(E2E_TMUX) capture-pane -t $(E2E_SESSION) -p -e 2>/dev/null || echo "Session not running"

e2e-keys:
	@if [ -z "$(KEYS)" ]; then echo "Usage: make e2e-keys KEYS='text to send'"; exit 1; fi
	@$(E2E_TMUX) send-keys -t $(E2E_SESSION) "$(KEYS)"

e2e-kitchen-rebuild:
	@echo "Rebuilding Kitchen (tunnel stays up)..."
	@AUTH_TOKEN=$$(grep '^AUTH_TOKEN=' $(E2E_ENV) | cut -d= -f2) \
	$(E2E_COMPOSE) up -d --build kitchen
	@echo "Kitchen rebuilt. Restart Counter with: make e2e-counter"

analyze-perf:
	@mkdir -p .claude/e2e
	@if [ ! -f $(E2E_ENV) ]; then \
		echo "ERROR: $(E2E_ENV) not found"; \
		exit 1; \
	fi
	@TARGET_VALUE="$(TARGET)"; \
	if [ -z "$$TARGET_VALUE" ]; then \
		TARGET_VALUE=$$(grep '^SM_ANALYZE_PERF_TARGET=' $(E2E_ENV) | cut -d= -f2-); \
	fi; \
	if [ -z "$$TARGET_VALUE" ]; then \
		echo "ERROR: set TARGET=<org-or-owner/repo> or add SM_ANALYZE_PERF_TARGET to $(E2E_ENV)"; \
		exit 1; \
	fi; \
	TARGET_TYPE_VALUE="$(TARGET_TYPE)"; \
	if [ -z "$$TARGET_TYPE_VALUE" ]; then \
		TARGET_TYPE_VALUE=$$(grep '^SM_ANALYZE_PERF_TARGET_TYPE=' $(E2E_ENV) | cut -d= -f2-); \
	fi; \
	if [ -z "$$TARGET_TYPE_VALUE" ]; then \
		TARGET_TYPE_VALUE=org; \
	fi; \
	SM_ANALYZE_PERF_TARGET="$$TARGET_VALUE" \
	SM_ANALYZE_PERF_TARGET_TYPE="$$TARGET_TYPE_VALUE" \
	env GOCACHE=/tmp/smokedmeat-go-cache GOMODCACHE=/tmp/smokedmeat-go-mod-cache \
	go test -v -tags=analysisperf ./internal/kitchen -run TestAnalyzePerformanceProfile -timeout 90m

e2e-smoke:
	@echo "Running quick exploit smoke test..."
	@mkdir -p .claude/e2e
	@if ! grep -qE '^GITHUB_TOKEN=ghp_' $(E2E_ENV) 2>/dev/null; then \
		printf "  Enter GitHub token (ghp_...): "; \
		read TOKEN; \
		if echo "$$TOKEN" | grep -qE '^ghp_'; then \
			grep -v '^GITHUB_TOKEN=' $(E2E_ENV) > $(E2E_ENV).tmp 2>/dev/null || true; \
			echo "GITHUB_TOKEN=$$TOKEN" >> $(E2E_ENV).tmp; \
			mv $(E2E_ENV).tmp $(E2E_ENV); \
		else \
			echo "ERROR: Token must start with ghp_"; exit 1; \
		fi; \
	fi
	@$(MAKE) e2e-down
	@$(MAKE) e2e-purge
	@$(MAKE) e2e-up
	go test -v -tags=e2e ./.claude/e2e/... -run TestPublicExploitSmoke -timeout 8m

e2e-goat:
	@echo "Running full GOAT chain E2E test..."
	@mkdir -p .claude/e2e
	@if ! grep -qE '^GITHUB_TOKEN=ghp_' $(E2E_ENV) 2>/dev/null; then \
		printf "  Enter GitHub token (ghp_...): "; \
		read TOKEN; \
		if echo "$$TOKEN" | grep -qE '^ghp_'; then \
			grep -v '^GITHUB_TOKEN=' $(E2E_ENV) > $(E2E_ENV).tmp 2>/dev/null || true; \
			echo "GITHUB_TOKEN=$$TOKEN" >> $(E2E_ENV).tmp; \
			mv $(E2E_ENV).tmp $(E2E_ENV); \
		else \
			echo "ERROR: Token must start with ghp_"; exit 1; \
		fi; \
	fi
	@$(MAKE) e2e-down
	@$(MAKE) e2e-purge
	@$(MAKE) e2e-up
	go test -v -tags=e2e ./.claude/e2e/... -run TestGOATFlagPath -timeout 30m

# =============================================================================
# Cleanup
# =============================================================================

clean:
	rm -rf dist/ $(RELEASE_ARTIFACTS_DIR)/
	rm -f $(KITCHEN_AGENTS_DIR)/brisket-*
	@rmdir $(dir $(RELEASE_ARTIFACTS_DIR)) 2>/dev/null || true
