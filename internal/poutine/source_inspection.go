// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	poutineModels "github.com/boostsecurityio/poutine/models"
	"github.com/boostsecurityio/poutine/scanner"
	"gopkg.in/yaml.v3"
)

type SourceInspection struct {
	Kind     string                 `json:"kind"`
	Workflow *WorkflowSourceInsight `json:"workflow,omitempty"`
	Action   *ActionSourceInsight   `json:"action,omitempty"`
	Risks    []SourceRisk           `json:"risks,omitempty"`
	Warnings []string               `json:"warnings,omitempty"`
}

type WorkflowSourceInsight struct {
	Name        string                              `json:"name,omitempty"`
	Events      []string                            `json:"events,omitempty"`
	EventLines  map[string]int                      `json:"event_lines,omitempty"`
	Permissions []SourcePermission                  `json:"permissions,omitempty"`
	Jobs        []WorkflowJobInsight                `json:"jobs,omitempty"`
	Meta        *WorkflowMeta                       `json:"meta,omitempty"`
	Raw         poutineModels.GithubActionsWorkflow `json:"raw,omitempty"`
}

type WorkflowJobInsight struct {
	ID          string                `json:"id"`
	Name        string                `json:"name,omitempty"`
	Line        int                   `json:"line,omitempty"`
	RunsOn      []string              `json:"runs_on,omitempty"`
	Needs       []string              `json:"needs,omitempty"`
	If          string                `json:"if,omitempty"`
	Secrets     []string              `json:"secrets,omitempty"`
	Permissions []SourcePermission    `json:"permissions,omitempty"`
	Steps       []WorkflowStepInsight `json:"steps,omitempty"`
	Meta        *JobMeta              `json:"meta,omitempty"`
}

type WorkflowStepInsight struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	Line           int    `json:"line,omitempty"`
	If             string `json:"if,omitempty"`
	IfLine         int    `json:"if_line,omitempty"`
	Uses           string `json:"uses,omitempty"`
	UsesLine       int    `json:"uses_line,omitempty"`
	Run            string `json:"run,omitempty"`
	RunLine        int    `json:"run_line,omitempty"`
	Shell          string `json:"shell,omitempty"`
	Action         string `json:"action,omitempty"`
	WithRef        string `json:"with_ref,omitempty"`
	WithRefLine    int    `json:"with_ref_line,omitempty"`
	WithScript     string `json:"with_script,omitempty"`
	WithScriptLine int    `json:"with_script_line,omitempty"`
}

type ActionSourceInsight struct {
	Name        string                              `json:"name,omitempty"`
	Description string                              `json:"description,omitempty"`
	Author      string                              `json:"author,omitempty"`
	Inputs      []ActionIOInsight                   `json:"inputs,omitempty"`
	Outputs     []ActionIOInsight                   `json:"outputs,omitempty"`
	RunsUsing   string                              `json:"runs_using,omitempty"`
	Main        string                              `json:"main,omitempty"`
	Image       string                              `json:"image,omitempty"`
	Entrypoint  string                              `json:"entrypoint,omitempty"`
	Steps       []WorkflowStepInsight               `json:"steps,omitempty"`
	Raw         poutineModels.GithubActionsMetadata `json:"raw,omitempty"`
}

type ActionIOInsight struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Default     string `json:"default,omitempty"`
	Type        string `json:"type,omitempty"`
	Value       string `json:"value,omitempty"`
}

type SourcePermission struct {
	Scope      string `json:"scope"`
	Permission string `json:"permission"`
}

type SourceRisk struct {
	Severity string   `json:"severity"`
	Kind     string   `json:"kind"`
	Message  string   `json:"message"`
	Sources  []string `json:"sources,omitempty"`
	Line     int      `json:"line,omitempty"`
	Job      string   `json:"job,omitempty"`
	Step     string   `json:"step,omitempty"`
	Order    int      `json:"order,omitempty"`
}

const (
	SourceKindWorkflow = "workflow"
	SourceKindAction   = "action"
	SourceKindPlain    = "plain"
)

var sourceSecretRefPattern = regexp.MustCompile(`(?i)\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}`)
var sourceTaintedExpressionPattern = regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
var sourceLOTPToolPattern = regexp.MustCompile(`(?m)(^|[^a-z0-9_.-])(npm|npx|yarn|pnpm|pip|pip3|poetry|bundle|make|mvn|gradle|bash|sh|pwsh|powershell)($|[^a-z0-9_.-])`)

const (
	sourceAuditOrderTrigger   = 10
	sourceAuditOrderAuthority = 20
	sourceAuditOrderGate      = 30
	sourceAuditOrderCheckout  = 40
	sourceAuditOrderLOTP      = 50
	sourceAuditOrderInjection = 60
	sourceAuditOrderHygiene   = 90
)

func InspectGitHubActionsSource(repository, ref, path, content string) SourceInspection {
	path = filepath.ToSlash(strings.Trim(strings.TrimSpace(path), "/"))
	if sourcePathIsWorkflow(path) {
		return inspectWorkflowSource(repository, ref, path, content)
	}
	if sourcePathIsAction(path) {
		return inspectActionSource(path, content)
	}
	return SourceInspection{Kind: SourceKindPlain}
}

func sourcePathIsWorkflow(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasPrefix(lower, ".github/workflows/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml"))
}

func sourcePathIsAction(path string) bool {
	return strings.EqualFold(filepath.Base(path), "action.yml") || strings.EqualFold(filepath.Base(path), "action.yaml")
}

func inspectWorkflowSource(repository, ref, path, content string) SourceInspection {
	pkg := &poutineModels.PackageInsights{
		Purl:          "pkg:github/" + strings.TrimSpace(repository),
		SourceScmType: "github",
		SourceGitRepo: strings.TrimSpace(repository),
		DefaultBranch: strings.TrimSpace(ref),
	}
	_ = scanner.NewGithubActionWorkflowParser().ParseFromMemory([]byte(content), path, pkg)
	if len(pkg.GithubActionsWorkflows) == 0 {
		return SourceInspection{
			Kind:     SourceKindWorkflow,
			Warnings: []string{"The file is under .github/workflows but could not be parsed as a valid GitHub Actions workflow."},
		}
	}

	workflow := pkg.GithubActionsWorkflows[0]
	result := &AnalysisResult{}
	extractWorkflowMeta(result, pkg, strings.TrimSpace(repository))
	var meta *WorkflowMeta
	for i := range result.Workflows {
		if result.Workflows[i].Path == path {
			meta = &result.Workflows[i]
			break
		}
	}

	insight := WorkflowSourceInsight{
		Name:        workflow.Name,
		Events:      sourceEventNames(workflow.Events),
		EventLines:  sourceWorkflowEventLines(content),
		Permissions: sourcePermissions(workflow.Permissions),
		Raw:         workflow,
		Meta:        meta,
	}
	for _, job := range workflow.Jobs {
		jobInsight := WorkflowJobInsight{
			ID:          job.ID,
			Name:        job.Name,
			Line:        job.Line,
			RunsOn:      stringList(job.RunsOn),
			Needs:       stringList(job.Needs),
			If:          job.If,
			Secrets:     sourceJobSecrets(job),
			Permissions: sourcePermissions(job.Permissions),
			Meta:        sourceJobMeta(meta, job.ID),
		}
		for _, step := range job.Steps {
			jobInsight.Steps = append(jobInsight.Steps, WorkflowStepInsight{
				ID:             step.ID,
				Name:           sourceStepName(step),
				Line:           step.Line,
				If:             step.If,
				IfLine:         step.Lines["if"],
				Uses:           step.Uses,
				UsesLine:       step.Lines["uses"],
				Run:            step.Run,
				RunLine:        step.Lines["run"],
				Shell:          step.Shell,
				Action:         step.Action,
				WithRef:        step.WithRef,
				WithRefLine:    step.Lines["with_ref"],
				WithScript:     step.WithScript,
				WithScriptLine: step.Lines["with_script"],
			})
		}
		insight.Jobs = append(insight.Jobs, jobInsight)
	}

	risks := workflowSourceRisks(insight)
	sortSourceRisks(risks)
	return SourceInspection{Kind: SourceKindWorkflow, Workflow: &insight, Risks: risks}
}

func inspectActionSource(path, content string) SourceInspection {
	pkg := &poutineModels.PackageInsights{}
	_ = scanner.NewGithubActionsMetadataParser().ParseFromMemory([]byte(content), path, pkg)
	if len(pkg.GithubActionsMetadata) == 0 {
		return SourceInspection{
			Kind:     SourceKindAction,
			Warnings: []string{"The file is named action.yml or action.yaml but could not be parsed as valid GitHub Action metadata."},
		}
	}

	action := pkg.GithubActionsMetadata[0]
	insight := ActionSourceInsight{
		Name:        action.Name,
		Description: action.Description,
		Author:      action.Author,
		RunsUsing:   action.Runs.Using,
		Main:        action.Runs.Main,
		Image:       action.Runs.Image,
		Entrypoint:  action.Runs.Entrypoint,
		Raw:         action,
	}
	for _, input := range action.Inputs {
		insight.Inputs = append(insight.Inputs, ActionIOInsight{
			Name:        input.Name,
			Description: input.Description,
			Required:    bool(input.Required),
			Type:        input.Type,
		})
	}
	for _, output := range action.Outputs {
		insight.Outputs = append(insight.Outputs, ActionIOInsight{
			Name:        output.Name,
			Description: output.Description,
			Value:       output.Value,
		})
	}
	for _, step := range action.Runs.Steps {
		insight.Steps = append(insight.Steps, WorkflowStepInsight{
			ID:             step.ID,
			Name:           sourceStepName(step),
			Line:           step.Line,
			If:             step.If,
			IfLine:         step.Lines["if"],
			Uses:           step.Uses,
			UsesLine:       step.Lines["uses"],
			Run:            step.Run,
			RunLine:        step.Lines["run"],
			Shell:          step.Shell,
			Action:         step.Action,
			WithRef:        step.WithRef,
			WithRefLine:    step.Lines["with_ref"],
			WithScript:     step.WithScript,
			WithScriptLine: step.Lines["with_script"],
		})
	}

	risks := actionSourceRisks(insight)
	sortSourceRisks(risks)
	return SourceInspection{Kind: SourceKindAction, Action: &insight, Risks: risks}
}

func sourceEventNames(events poutineModels.GithubActionsEvents) []string {
	names := make([]string, 0, len(events))
	for _, event := range events {
		if event.Name != "" {
			names = append(names, event.Name)
		}
	}
	return names
}

func sourceWorkflowEventLines(content string) map[string]int {
	lines := make(map[string]int)
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return lines
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return lines
	}
	doc := root.Content[0]
	for i := 0; i < len(doc.Content); i += 2 {
		key := doc.Content[i]
		value := doc.Content[i+1]
		if key.Value != "on" {
			continue
		}
		sourceWorkflowEventLinesFromNode(value, lines)
		return lines
	}
	return lines
}

func sourceWorkflowEventLinesFromNode(node *yaml.Node, lines map[string]int) {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value != "" {
			lines[node.Value] = node.Line
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Value != "" {
				lines[item.Value] = item.Line
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Value != "" {
				lines[key.Value] = key.Line
			}
		}
	}
}

func sourcePermissions(perms poutineModels.GithubActionsPermissions) []SourcePermission {
	out := make([]SourcePermission, 0, len(perms))
	for _, perm := range perms {
		if perm.Scope == "" && perm.Permission == "" {
			continue
		}
		out = append(out, SourcePermission{Scope: perm.Scope, Permission: perm.Permission})
	}
	return out
}

func stringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func sourceJobSecrets(job poutineModels.GithubActionsJob) []string {
	values := make([]string, 0, len(job.Secrets)+len(job.ReferencesSecrets))
	for _, secret := range job.Secrets {
		if secret.Name != "" {
			values = append(values, secret.Name)
		}
		if match := sourceSecretRefPattern.FindStringSubmatch(secret.Value); len(match) == 2 {
			values = append(values, match[1])
		}
	}
	values = append(values, job.ReferencesSecrets...)
	return uniqueSortedStrings(values)
}

func sourceJobMeta(meta *WorkflowMeta, jobID string) *JobMeta {
	if meta == nil {
		return nil
	}
	for i := range meta.Jobs {
		if meta.Jobs[i].ID == jobID {
			return &meta.Jobs[i]
		}
	}
	return nil
}

func sourceStepName(step poutineModels.GithubActionsStep) string {
	if strings.TrimSpace(step.Name) != "" {
		return step.Name
	}
	if strings.TrimSpace(step.ID) != "" {
		return step.ID
	}
	if strings.TrimSpace(step.Uses) != "" {
		return step.Uses
	}
	if strings.TrimSpace(step.Run) != "" {
		return "run"
	}
	return "step"
}

func workflowSourceRisks(workflow WorkflowSourceInsight) []SourceRisk {
	var risks []SourceRisk
	attackableEvents := sourceAttackableSecretEvents(workflow.Events)
	for _, event := range attackableEvents {
		risks = append(risks, SourceRisk{
			Severity: "high",
			Kind:     "attackable-trigger",
			Message:  fmt.Sprintf("%s can be influenced by external users and may run with repository token or secret access in a public repository threat model.", event),
			Line:     workflow.EventLines[event],
			Order:    sourceAuditOrderTrigger,
		})
	}
	for _, job := range workflow.Jobs {
		authorityRisks := sourceJobAuthorityRisks(workflow.Permissions, job)
		risks = append(risks, authorityRisks...)
		secrets := sourceEffectiveJobSecrets(job)
		if len(secrets) > 0 {
			risks = append(risks, SourceRisk{
				Severity: "high",
				Kind:     "secrets-access",
				Message:  fmt.Sprintf("Job %s references secrets: %s.", job.ID, strings.Join(secrets, ", ")),
				Line:     job.Line,
				Job:      job.ID,
				Order:    sourceAuditOrderAuthority,
			})
		}
		if len(attackableEvents) > 0 && (len(authorityRisks) > 0 || len(secrets) > 0) && sourceIfGateWeak(job.If) {
			risks = append(risks, SourceRisk{
				Severity: "medium",
				Kind:     "weak-gate",
				Message:  fmt.Sprintf("Job %s has no meaningful if gate before privileged work.", job.ID),
				Line:     job.Line,
				Job:      job.ID,
				Order:    sourceAuditOrderGate,
			})
		}
		hasUntrustedCheckout := false
		for _, step := range job.Steps {
			checkoutRisk, ok := sourceUntrustedCheckoutRisk(job.ID, step)
			if ok {
				hasUntrustedCheckout = true
				risks = append(risks, checkoutRisk)
			}
		}
		for _, step := range job.Steps {
			risks = append(risks, sourceStepLOTPRisks(job.ID, step, len(attackableEvents) > 0 || hasUntrustedCheckout)...)
			risks = append(risks, sourceStepTaintedInputRisks(job.ID, step)...)
			risks = appendStepRisks(risks, job.ID, step)
		}
	}
	return dedupeSourceRisks(risks)
}

func actionSourceRisks(action ActionSourceInsight) []SourceRisk {
	var risks []SourceRisk
	for _, input := range action.Inputs {
		if sourceNameLooksSensitive(input.Name) {
			risks = append(risks, SourceRisk{Severity: "medium", Kind: "sensitive-input", Message: fmt.Sprintf("Input %s looks like it may receive sensitive data.", input.Name), Order: sourceAuditOrderAuthority})
		}
	}
	switch strings.ToLower(action.RunsUsing) {
	case "composite":
		for _, step := range action.Steps {
			risks = append(risks, sourceStepTaintedInputRisks("", step)...)
			risks = appendStepRisks(risks, "", step)
		}
	case "docker":
		risks = append(risks, SourceRisk{Severity: "medium", Kind: "docker-action", Message: "Docker actions execute the referenced image and entrypoint.", Order: sourceAuditOrderHygiene})
	case "node12", "node16":
		risks = append(risks, SourceRisk{Severity: "medium", Kind: "old-runtime", Message: fmt.Sprintf("Action uses deprecated %s runtime.", action.RunsUsing), Order: sourceAuditOrderHygiene})
	}
	return dedupeSourceRisks(risks)
}

func appendStepRisks(risks []SourceRisk, job string, step WorkflowStepInsight) []SourceRisk {
	if strings.TrimSpace(step.Uses) != "" && !sourceActionReferencePinned(step.Uses) {
		risks = append(risks, SourceRisk{Severity: "low", Kind: "unpinned-action", Message: fmt.Sprintf("Action %s is not pinned to an immutable commit SHA.", step.Uses), Line: sourceFirstPositive(step.UsesLine, step.Line), Job: job, Step: step.Name, Order: sourceAuditOrderHygiene})
	}
	if sourceSecretRefPattern.MatchString(step.Run) || sourceSecretRefPattern.MatchString(step.If) {
		risks = append(risks, SourceRisk{Severity: "medium", Kind: "secret-reference", Message: "Step references GitHub secrets.", Line: step.Line, Job: job, Step: step.Name, Order: sourceAuditOrderAuthority})
	}
	return risks
}

func sourceAttackableSecretEvents(events []string) []string {
	var out []string
	for _, event := range events {
		switch strings.TrimSpace(event) {
		case "pull_request_target", "issues", "issue_comment", "workflow_run":
			out = append(out, event)
		}
	}
	return uniqueSortedStrings(out)
}

func sourceJobAuthorityRisks(workflowPermissions []SourcePermission, job WorkflowJobInsight) []SourceRisk {
	var risks []SourceRisk
	writeScopes := sourceWriteScopes(sourceEffectivePermissions(workflowPermissions, job.Permissions))
	tokenWriteScopes := sourceWithoutValue(writeScopes, "id-token")
	if len(tokenWriteScopes) > 0 {
		severity := "medium"
		if stringSliceContains(tokenWriteScopes, "contents") || stringSliceContains(tokenWriteScopes, "actions") {
			severity = "high"
		}
		risks = append(risks, SourceRisk{
			Severity: severity,
			Kind:     "write-token",
			Message:  fmt.Sprintf("Job %s grants GITHUB_TOKEN write scopes: %s.", job.ID, strings.Join(tokenWriteScopes, ", ")),
			Line:     job.Line,
			Job:      job.ID,
			Order:    sourceAuditOrderAuthority,
		})
	}
	if job.Meta != nil {
		if job.Meta.SelfHosted {
			risks = append(risks, SourceRisk{Severity: "critical", Kind: "self-hosted", Message: fmt.Sprintf("Job %s targets a self-hosted runner.", job.ID), Line: job.Line, Job: job.ID, Order: sourceAuditOrderAuthority})
		}
		for _, app := range job.Meta.AppActions {
			risks = append(risks, SourceRisk{Severity: "high", Kind: "github-app-token", Message: fmt.Sprintf("Job %s creates a GitHub App token with %s.", job.ID, app.Action), Line: job.Line, Job: job.ID, Order: sourceAuditOrderAuthority})
		}
		for _, cloud := range job.Meta.CloudActions {
			risks = append(risks, SourceRisk{Severity: "high", Kind: "cloud-login", Message: fmt.Sprintf("Job %s authenticates to %s using %s.", job.ID, cloud.Provider, cloud.Action), Line: job.Line, Job: job.ID, Order: sourceAuditOrderAuthority})
		}
	}
	if stringSliceContains(writeScopes, "id-token") || job.Meta != nil && job.Meta.HasOIDC {
		risks = append(risks, SourceRisk{Severity: "high", Kind: "oidc-token", Message: fmt.Sprintf("Job %s can request OIDC tokens.", job.ID), Line: job.Line, Job: job.ID, Order: sourceAuditOrderAuthority})
	}
	return risks
}

func sourceEffectivePermissions(workflowPermissions, jobPermissions []SourcePermission) []SourcePermission {
	if len(jobPermissions) > 0 {
		return jobPermissions
	}
	return workflowPermissions
}

func sourceWriteScopes(permissions []SourcePermission) []string {
	var scopes []string
	for _, perm := range permissions {
		if strings.TrimSpace(perm.Permission) == "write" && strings.TrimSpace(perm.Scope) != "" {
			scopes = append(scopes, strings.TrimSpace(perm.Scope))
		}
	}
	return uniqueSortedStrings(scopes)
}

func sourceEffectiveJobSecrets(job WorkflowJobInsight) []string {
	values := append([]string(nil), job.Secrets...)
	if job.Meta != nil {
		values = append(values, job.Meta.Secrets...)
	}
	return uniqueSortedStrings(values)
}

func sourceIfGateWeak(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "${{")
	normalized = strings.TrimSuffix(normalized, "}}")
	normalized = strings.TrimSpace(normalized)
	switch normalized {
	case "", "true", "success()", "always()":
		return true
	default:
		return false
	}
}

func sourceUntrustedCheckoutRisk(job string, step WorkflowStepInsight) (SourceRisk, bool) {
	if !strings.EqualFold(strings.TrimSpace(step.Action), "actions/checkout") {
		return SourceRisk{}, false
	}
	sources := sourceTaintedSourcesInString(step.WithRef)
	if len(sources) == 0 {
		return SourceRisk{}, false
	}
	for _, source := range sources {
		if sourceCheckoutSourceUntrusted(source) {
			return SourceRisk{
				Severity: "critical",
				Kind:     "untrusted-checkout",
				Message:  fmt.Sprintf("actions/checkout loads untrusted ref %s.", source),
				Line:     sourceFirstPositive(step.WithRefLine, step.Line),
				Job:      job,
				Step:     step.Name,
				Order:    sourceAuditOrderCheckout,
			}, true
		}
	}
	return SourceRisk{}, false
}

func sourceCheckoutSourceUntrusted(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return strings.Contains(source, "head_ref") ||
		strings.Contains(source, "pull_request.head") ||
		strings.Contains(source, "workflow_run.head") ||
		strings.Contains(source, "client_payload")
}

func sourceStepLOTPRisks(job string, step WorkflowStepInsight, relevant bool) []SourceRisk {
	if !relevant {
		return nil
	}
	tool := sourceStepLOTPTool(step)
	if tool == "" {
		return nil
	}
	return []SourceRisk{{
		Severity: "medium",
		Kind:     "lotp-tool",
		Message:  sourceStepLOTPMessage(step, tool),
		Line:     sourceFirstPositive(step.RunLine, step.WithScriptLine, step.Line),
		Job:      job,
		Step:     step.Name,
		Order:    sourceAuditOrderLOTP,
	}}
}

func sourceStepLOTPMessage(step WorkflowStepInsight, tool string) string {
	name := strings.TrimSpace(step.Name)
	if name == "" || name == "run" || name == "step" {
		return fmt.Sprintf("Run block invokes LOTP-capable tool %q; inspect whether untrusted files or arguments can affect it.", tool)
	}
	return fmt.Sprintf("Step %q invokes LOTP-capable tool %q; inspect whether untrusted files or arguments can affect it.", name, tool)
}

func sourceStepLOTPTool(step WorkflowStepInsight) string {
	action := strings.ToLower(strings.TrimSpace(step.Action))
	if action == "actions/github-script" {
		return "github-script"
	}
	run := strings.ToLower(step.Run + "\n" + step.WithScript)
	if match := sourceLOTPToolPattern.FindStringSubmatch(run); len(match) >= 3 {
		return match[2]
	}
	return ""
}

func sourceStepTaintedInputRisks(job string, step WorkflowStepInsight) []SourceRisk {
	var risks []SourceRisk
	if sources := sourceTaintedSourcesInString(step.Run); len(sources) > 0 {
		risks = append(risks, SourceRisk{
			Severity: "high",
			Kind:     "tainted-input",
			Message:  "Shell command uses attacker-controlled GitHub context.",
			Sources:  sources,
			Line:     sourceFirstPositive(step.RunLine, step.Line),
			Job:      job,
			Step:     step.Name,
			Order:    sourceAuditOrderInjection,
		})
	}
	if sources := sourceTaintedSourcesInString(step.WithScript); len(sources) > 0 {
		risks = append(risks, SourceRisk{
			Severity: "high",
			Kind:     "tainted-input",
			Message:  "github-script uses attacker-controlled GitHub context.",
			Sources:  sources,
			Line:     sourceFirstPositive(step.WithScriptLine, step.Line),
			Job:      job,
			Step:     step.Name,
			Order:    sourceAuditOrderInjection,
		})
	}
	return risks
}

func sourceTaintedSourcesInString(value string) []string {
	var out []string
	for _, match := range sourceTaintedExpressionPattern.FindAllStringSubmatch(value, -1) {
		if len(match) != 2 {
			continue
		}
		expr := strings.ToLower(match[1])
		for _, source := range []string{
			"github.head_ref",
			"github.event.issue.title",
			"github.event.issue.body",
			"github.event.comment.body",
			"github.event.pull_request.title",
			"github.event.pull_request.body",
			"github.event.pull_request.head.ref",
			"github.event.pull_request.head.sha",
			"github.event.workflow_run.head_branch",
			"github.event.workflow_run.head_sha",
			"github.event.client_payload",
			"github.event.inputs.",
			"inputs.",
		} {
			if strings.Contains(expr, source) {
				out = append(out, strings.TrimSuffix(source, "."))
			}
		}
	}
	return uniqueSortedStrings(out)
}

func sourceActionReferencePinned(uses string) bool {
	_, version, ok := strings.Cut(strings.TrimSpace(uses), "@")
	if !ok || strings.TrimSpace(version) == "" {
		return false
	}
	version = strings.TrimSpace(version)
	if len(version) == 40 {
		for _, c := range version {
			if (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && (c < '0' || c > '9') {
				return false
			}
		}
		return true
	}
	switch strings.ToLower(version) {
	case "main", "master", "head", "latest":
		return false
	default:
		return strings.HasPrefix(strings.ToLower(version), "v")
	}
}

func sourceNameLooksSensitive(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "key")
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "GITHUB_TOKEN" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sourceWithoutValue(values []string, unwanted string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != unwanted {
			out = append(out, value)
		}
	}
	return out
}

func sourceFirstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func dedupeSourceRisks(risks []SourceRisk) []SourceRisk {
	seen := make(map[string]struct{})
	out := make([]SourceRisk, 0, len(risks))
	for _, risk := range risks {
		key := strings.Join([]string{risk.Severity, risk.Kind, risk.Message, strings.Join(risk.Sources, ","), fmt.Sprint(risk.Line), risk.Job, risk.Step, fmt.Sprint(risk.Order)}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, risk)
	}
	return out
}

func sortSourceRisks(risks []SourceRisk) {
	sort.SliceStable(risks, func(i, j int) bool {
		if risks[i].Order != risks[j].Order {
			return risks[i].Order < risks[j].Order
		}
		if risks[i].Line == 0 && risks[j].Line != 0 {
			return false
		}
		if risks[j].Line == 0 && risks[i].Line != 0 {
			return true
		}
		if risks[i].Line != risks[j].Line {
			return risks[i].Line < risks[j].Line
		}
		return sourceRiskWeight(risks[i].Severity) > sourceRiskWeight(risks[j].Severity)
	})
}

func sourceRiskWeight(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
