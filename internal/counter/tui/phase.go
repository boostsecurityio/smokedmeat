// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"strings"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/lotp"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

type Phase int

const (
	PhaseSetup       Phase = iota // Initial configuration, checklist
	PhaseRecon                    // Analysis complete, viewing findings
	PhaseWizard                   // Configuring payload via wizard
	PhaseWaiting                  // Payload deployed, waiting for beacon
	PhasePostExploit              // Agent active, commanding
	PhasePivot                    // Using discovered creds for new scans
)

func (p Phase) String() string {
	switch p {
	case PhaseSetup:
		return "Setup"
	case PhaseRecon:
		return "Recon"
	case PhaseWizard:
		return "Wizard"
	case PhaseWaiting:
		return "Waiting"
	case PhasePostExploit:
		return "Post-Exploit"
	case PhasePivot:
		return "Pivot"
	default:
		return "Unknown"
	}
}

func (p Phase) CanSelectVuln() bool {
	return p == PhaseRecon || p == PhasePostExploit || p == PhasePivot
}

func (p Phase) CanCommandAgent() bool {
	return p == PhasePostExploit || p == PhasePivot
}

func (p Phase) HasActiveAgent() bool {
	return p == PhasePostExploit || p == PhasePivot
}

type View int

const (
	ViewSetupWizard View = iota // Setup wizard (guided, no command input)
	ViewFindings                // Tree + NEXT + LOOT panels
	ViewWizard                  // Modal overlay for payload config
	ViewWaiting                 // Beacon wait screen
	ViewAgent                   // 3-column with agent panel
	ViewLicense                 // License modal overlay
	ViewHelp                    // Help modal overlay
	ViewReAuth                  // Re-authentication modal overlay
	ViewKillChain               // Kill chain preview modal overlay
	ViewTheme                   // Theme picker modal overlay
	ViewOmnibox                 // Search/jump modal overlay
	ViewCallbacks               // Callback inventory modal overlay
)

func (v View) String() string {
	switch v {
	case ViewSetupWizard:
		return "SetupWizard"
	case ViewFindings:
		return "Findings"
	case ViewWizard:
		return "Wizard"
	case ViewWaiting:
		return "Waiting"
	case ViewAgent:
		return "Agent"
	case ViewLicense:
		return "License"
	case ViewHelp:
		return "Help"
	case ViewReAuth:
		return "ReAuth"
	case ViewKillChain:
		return "KillChain"
	case ViewTheme:
		return "Theme"
	case ViewOmnibox:
		return "Omnibox"
	case ViewCallbacks:
		return "Implants"
	default:
		return "Unknown"
	}
}

func (v View) IsModal() bool {
	return v == ViewWizard || v == ViewLicense || v == ViewHelp || v == ViewReAuth || v == ViewKillChain || v == ViewTheme || v == ViewOmnibox || v == ViewCallbacks
}

type DeliveryMethod int

const (
	DeliveryIssue        DeliveryMethod = iota // Simplest: gh issue create
	DeliveryComment                            // Easy: gh issue comment
	DeliveryAutoPR                             // Complex: fork + branch + PR
	DeliveryLOTP                               // LOTP: npm install hook
	DeliveryAutoDispatch                       // Trigger workflow_dispatch with ephemeral token
	DeliveryCopyOnly
	DeliveryManualSteps
)

func (d DeliveryMethod) String() string {
	switch d {
	case DeliveryIssue:
		return "Create Issue"
	case DeliveryComment:
		return "Add Comment"
	case DeliveryAutoPR:
		return "Create PR"
	case DeliveryLOTP:
		return "LOTP"
	case DeliveryAutoDispatch:
		return "Trigger Dispatch"
	case DeliveryCopyOnly:
		return "Copy Only"
	case DeliveryManualSteps:
		return "Manual Steps"
	default:
		return "Unknown"
	}
}

type CommentTarget int

const (
	CommentTargetIssue CommentTarget = iota
	CommentTargetPullRequest
	CommentTargetStubPullRequest
)

func (t CommentTarget) String() string {
	switch t {
	case CommentTargetIssue:
		return "Existing issue"
	case CommentTargetPullRequest:
		return "Existing PR"
	case CommentTargetStubPullRequest:
		return "Create stub PR"
	default:
		return "Existing issue"
	}
}

func (t CommentTarget) RequestValue() string {
	switch t {
	case CommentTargetPullRequest:
		return "pull_request"
	case CommentTargetStubPullRequest:
		return "stub_pull_request"
	default:
		return "issue"
	}
}

type analyzeOnlyFindingError struct {
	message string
}

func (e analyzeOnlyFindingError) Error() string {
	return e.message
}

func exploitSupportBlockReason(v *Vulnerability) string {
	if v == nil {
		return ""
	}
	if v.ExploitSupported {
		return ""
	}
	if strings.TrimSpace(v.ExploitSupportReason) != "" {
		return v.ExploitSupportReason
	}
	_, reason := pantry.VulnerabilityExploitSupportWithBashContext("github", v.Workflow, v.RuleID, v.BashContext)
	return reason
}

func vulnerabilitySupportsExploit(v *Vulnerability) bool {
	return v != nil && exploitSupportBlockReason(v) == ""
}

func vulnerabilityExploitError(v *Vulnerability) error {
	if v == nil {
		return nil
	}
	if reason := exploitSupportBlockReason(v); reason != "" {
		return analyzeOnlyFindingError{message: reason}
	}
	return nil
}

func deliveryMethodBlockReason(v *Vulnerability, method DeliveryMethod) string {
	if v == nil {
		return ""
	}
	if method != DeliveryLOTP || v.RuleID != "untrusted_checkout_exec" {
		return ""
	}
	status := lotp.AutoDeployStatusFor(v.LOTPTool, v.LOTPAction)
	if status.Supported {
		return ""
	}
	return status.Reason
}

func ApplicableDeliveryMethods(v *Vulnerability) []DeliveryMethod {
	if v == nil {
		return []DeliveryMethod{DeliveryIssue, DeliveryComment, DeliveryAutoPR, DeliveryCopyOnly, DeliveryManualSteps}
	}

	var methods []DeliveryMethod
	trigger := strings.ToLower(v.Trigger)

	// TRIGGER-FIRST: How to activate the workflow
	// Order matters: issue_comment contains "issue", so check it first
	switch {
	case strings.Contains(trigger, "issue_comment"):
		// Create Issue first (creates fresh issue + auto-comment), Add Comment for existing issues
		methods = append(methods, DeliveryIssue, DeliveryComment)
	case strings.Contains(trigger, "issues"):
		methods = append(methods, DeliveryIssue)
	case strings.Contains(trigger, "workflow_dispatch"):
		methods = append(methods, DeliveryAutoDispatch)
	case strings.Contains(trigger, "pull_request"):
		methods = append(methods, DeliveryAutoPR)
	case trigger == "push":
		methods = append(methods, DeliveryAutoPR)
	default:
		// Unknown trigger - use CONTEXT as fallback
		switch v.Context {
		case "issue_body", "issue_title":
			methods = append(methods, DeliveryIssue)
		case "comment_body":
			methods = append(methods, DeliveryIssue, DeliveryComment)
		case "pr_body", "pr_title", "head_ref", "commit_message", "git_branch":
			methods = append(methods, DeliveryAutoPR)
		default:
			methods = append(methods, DeliveryIssue, DeliveryComment, DeliveryAutoPR)
		}
	}

	// LOTP for untrusted checkout (pwn request) — replace injection methods entirely
	if v.RuleID == "untrusted_checkout_exec" {
		if v.LOTPTool != "" || v.LOTPAction != "" {
			return []DeliveryMethod{DeliveryLOTP, DeliveryManualSteps}
		}
		return []DeliveryMethod{DeliveryManualSteps}
	}

	// Always offer manual options last
	methods = append(methods, DeliveryCopyOnly, DeliveryManualSteps)
	return methods
}

type WizardState struct {
	Step                   int
	SelectedVuln           *Vulnerability
	DeliveryMethod         DeliveryMethod
	CommentTarget          CommentTarget
	StagerID               string
	VictimStagerID         string
	Payload                string
	PayloadPreview         string
	IssueNumber            int
	DwellTime              time.Duration
	CallbackBudget         int
	Draft                  *bool
	AutoClose              *bool
	CachePoisonEnabled     bool
	CachePoisonReplace     bool
	CachePoisonVictimIndex int
	PreflightKey           string
	PreflightLoading       bool
	PreflightError         string
	Preflight              *counter.DeployPreflightResponse
}

func (w *WizardState) Reset() {
	w.Step = 1
	w.SelectedVuln = nil
	w.DeliveryMethod = DeliveryIssue
	w.CommentTarget = CommentTargetIssue
	w.StagerID = ""
	w.VictimStagerID = ""
	w.Payload = ""
	w.PayloadPreview = ""
	w.IssueNumber = 0
	w.DwellTime = 0
	w.CallbackBudget = 1
	w.Draft = nil
	w.AutoClose = nil
	w.CachePoisonEnabled = false
	w.CachePoisonReplace = false
	w.CachePoisonVictimIndex = 0
	w.PreflightKey = ""
	w.PreflightLoading = false
	w.PreflightError = ""
	w.Preflight = nil
}

func boolPtr(v bool) *bool { return &v }

type WaitingState struct {
	StagerID       string
	StartTime      time.Time
	PRURL          string
	Timeout        time.Duration
	SoftWarning    time.Duration
	TargetRepo     string
	TargetVuln     string
	TargetWorkflow string
	TargetJob      string
	Method         string
	DwellTime      time.Duration
	CachePoison    *CachePoisonWaitingState
	PendingAgents  map[string]time.Time
}

func NewWaitingState(stagerID, repo, vuln, workflow, job, method string, dwellTime time.Duration) *WaitingState {
	return &WaitingState{
		StagerID:       stagerID,
		StartTime:      time.Now(),
		Timeout:        15 * time.Minute,
		SoftWarning:    5 * time.Minute,
		TargetRepo:     repo,
		TargetVuln:     vuln,
		TargetWorkflow: workflow,
		TargetJob:      job,
		Method:         method,
		DwellTime:      dwellTime,
		PendingAgents:  make(map[string]time.Time),
	}
}

func (w *WaitingState) Elapsed() time.Duration {
	return time.Since(w.StartTime)
}

func (w *WaitingState) IsWarning() bool {
	return w.Elapsed() >= w.SoftWarning
}

func (w *WaitingState) IsTimedOut() bool {
	return w.Elapsed() >= w.Timeout
}

type CachePoisonWaitingState struct {
	Victim         cachepoison.VictimCandidate
	WriterStagerID string
	VictimStagerID string
	WriterAgentID  string
	VictimAgentID  string
	PendingVictim  string
	PendingDwell   map[string]struct{}
	WriterStatus   *models.CachePoisonStatus
}

type CallbackModalState struct {
	Cursor int
}

type CallbackAgentLink struct {
	AgentID    string
	Hostname   string
	LastSeen   time.Time
	Mode       string
	SecretHits int
}

type AgentState struct {
	ID        string
	Runner    string
	Repo      string
	Workflow  string
	Job       string
	EntryVuln string
	StartTime time.Time
}

type CollectedSecret struct {
	Name        string
	Value       string
	Source      string
	Ephemeral   bool
	Scopes      []string
	CollectedAt time.Time

	// Origin tracking for tree display
	Repository string   // e.g., "owner/repo"
	Workflow   string   // e.g., ".github/workflows/ci.yml"
	Job        string   // e.g., "build"
	AgentID    string   // e.g., "agt_abc123"
	Sources    []string // All sources where found (for dedup display)

	// Validation fields
	Type        string     // "github_pat", "github_token", "aws", etc.
	Validated   bool       // True if validation has been attempted
	ValidatedAt *time.Time // When validation was performed
	ValidStatus string     // "valid", "invalid", "expired", "error"
	Owner       string     // GitHub username for PATs
	ExpiresAt   *time.Time // Token expiration time

	// Ephemeral token bounds
	BoundToRepo string // For GITHUB_TOKEN - which repo it's bound to

	// Express vs Dwell mode tracking
	ExpressMode   bool       // True if captured via express (not dwell)
	DwellDeadline *time.Time // For dwell mode: when GITHUB_TOKEN expires

	// GitHub App pairing
	PairedAppID string // App ID value when this PEM is part of a GitHub App pair

	KeyFingerprint string
	KeyType        string
	TrialResults   []SSHTrialResult
	TrialsComplete bool
}

func (s CollectedSecret) IsEphemeral() bool {
	if s.Ephemeral {
		return true
	}
	if s.Name == "GITHUB_TOKEN" {
		return true
	}
	ephemeralPrefixes := []string{
		"ACTIONS_RUNTIME_TOKEN",
		"ACTIONS_ID_TOKEN_REQUEST_",
		"ACTIONS_CACHE_URL",
	}
	for _, prefix := range ephemeralPrefixes {
		if strings.HasPrefix(s.Name, prefix) {
			return true
		}
	}
	return false
}

func (s CollectedSecret) MaskedValue() string {
	if s.Value == "" || len(s.Value) < 8 {
		return "•••"
	}
	return s.Value[:4] + "•••" + s.Value[len(s.Value)-3:]
}

func (s CollectedSecret) CanUseAsToken() bool {
	switch s.Type {
	case "github_pat", "github_fine_grained_pat", "github_token", "github_app_token", "github_oauth":
		return true
	default:
		return strings.HasPrefix(s.Value, "ghp_") ||
			strings.HasPrefix(s.Value, "ghs_") ||
			strings.HasPrefix(s.Value, "gho_") ||
			strings.HasPrefix(s.Value, "ghu_") ||
			strings.HasPrefix(s.Value, "github_pat_")
	}
}

func (s CollectedSecret) CanUseAsSSHKey() bool {
	if s.Type == "github_app_key" || strings.TrimSpace(s.Value) == "" {
		return false
	}
	_, _, err := sshPrivateKeyMetadata(s.Value)
	return err == nil
}

func (s CollectedSecret) TypeIcon() string {
	switch s.Type {
	case "github_pat", "github_fine_grained_pat":
		return "🔑"
	case "github_token":
		return "⏱"
	case "github_app_token":
		return "🤖"
	case "github_app_key":
		return "🔐"
	case "github_oauth":
		return "🔗"
	case "aws_access_key", "aws_secret":
		return "☁️"
	case "azure":
		return "🔷"
	case "gcp":
		return "🌐"
	case "npm":
		return "📦"
	case "container_registry":
		return "🐳"
	case "database":
		return "🗄️"
	case "signing_key":
		return "✍️"
	case "private_key":
		return "🗝️"
	default:
		if s.IsEphemeral() {
			return "⏱"
		}
		return "🔑"
	}
}

// KnownEntity represents a repo or org that we've discovered and tracked.
// Used for delta computation during pivots - only surface what's NEW.
type KnownEntity struct {
	ID            string    // "repo:org/name" or "org:name"
	EntityType    string    // "repo" or "org"
	Name          string    // "org/repo" or "org"
	DiscoveredAt  time.Time // When we first saw it
	DiscoveredVia string    // "initial_analysis", "pivot:GITHUB_TOKEN", "pivot:PAT:masked"
	IsPrivate     bool      // Private repo/org
	Permissions   []string  // ["contents:read", "contents:write", "workflows:write"]
	SSHPermission string
}

type SSHTrialResult struct {
	Host       string
	Repo       string
	Permission string
	Branch     string
	Success    bool
	Error      string
	Latency    time.Duration
}

type SuggestedAction struct {
	Label       string
	Description string
	Command     string
	Priority    int
	VulnIndex   int // Index into m.vulnerabilities (-1 if not a vuln)
}

type ActivityEntry struct {
	Timestamp time.Time
	Icon      string
	Message   string
	IsError   bool
}

type KeyDeployMethod int

const (
	KeyDeployClipboard KeyDeployMethod = iota
	KeyDeploySSH
	KeyDeploySkip
)

type OperatorNameChoice int

const (
	OperatorNameGenerated OperatorNameChoice = iota
	OperatorNameCustom
)

type SetupTokenChoice int

const (
	SetupTokenPAT SetupTokenChoice = iota
	SetupTokenGH
	SetupTokenOP
	SetupTokenBrowser
)

const (
	setupTokenSubStepChoice = iota
	setupTokenSubStepInput
	setupTokenSubStepWarning
)

type SetupTargetChoice int

const (
	SetupTargetOrg SetupTargetChoice = iota
	SetupTargetRepo
)

type SetupWizardState struct {
	Step               int
	BackStepFloor      int
	KitchenURL         string
	Keys               []SetupKeyInfo
	SelectedKey        int
	GeneratedName      string
	OperatorNameChoice OperatorNameChoice
	OperatorName       string
	DeployMethod       KeyDeployMethod
	AuthKeysLine       string
	Status             string
	Error              string
	AuthAttempt        int
	Connecting         bool

	TokenChoice  SetupTokenChoice
	TokenSubStep int
	TokenValue   string
	TokenOwner   string
	TokenScopes  string
	OPSecretRef  string

	TargetChoice  SetupTargetChoice
	TargetSubStep int
	TargetValue   string

	AnalysisRunning      bool
	AnalysisStart        time.Time
	AnalysisAttempt      int
	AnalysisRetryPending bool
	AnalysisSummary      string
	ReposAnalyzed        int
	VulnsFound           int
	SecretsFound         int
}

type SetupKeyInfo struct {
	Comment       string
	Fingerprint   string
	Type          string
	AuthorizedKey string
}

func (sw *SetupWizardState) backStepFloor() int {
	if sw == nil || sw.BackStepFloor < 1 {
		return 1
	}
	return sw.BackStepFloor
}

func (sw *SetupWizardState) CanGoBack() bool {
	if sw == nil {
		return false
	}
	if sw.Step == 5 && sw.TokenSubStep > setupTokenSubStepChoice {
		return true
	}
	if sw.Step == 6 && sw.TargetSubStep > 0 {
		return true
	}
	return sw.Step > sw.backStepFloor()
}
