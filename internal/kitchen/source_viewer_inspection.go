// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

func (h *Handler) sourceViewerInspectionFor(resp SourceContentResponse) *sourceViewerInspectionView {
	inspection := poutine.InspectGitHubActionsSource(resp.Repository, resp.Ref, resp.Path, resp.Content)
	if inspection.Kind == poutine.SourceKindPlain {
		return nil
	}
	view := sourceViewerInspectionViewFor(inspection)
	view.Risks = append(view.Risks, h.sourceViewerPantryRisks(resp)...)
	view.Risks = sourceViewerDedupRisks(view.Risks)
	sourceViewerSortRisks(view.Risks)
	view.Summary = sourceViewerInspectionSummary(view)
	return view
}

func sourceViewerSortRisks(risks []sourceViewerRiskView) {
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
		return sourceViewerSeverityWeight(risks[i].Severity) > sourceViewerSeverityWeight(risks[j].Severity)
	})
}

func sourceViewerInspectionViewFor(inspection poutine.SourceInspection) *sourceViewerInspectionView {
	view := &sourceViewerInspectionView{
		Kind:     inspection.Kind,
		Warnings: append([]string(nil), inspection.Warnings...),
		Risks:    sourceViewerRiskViews(inspection.Risks),
	}
	switch {
	case inspection.Workflow != nil:
		view.Sections = sourceViewerWorkflowSections(*inspection.Workflow)
	case inspection.Action != nil:
		view.Sections = sourceViewerActionSections(*inspection.Action)
	}
	view.Summary = sourceViewerInspectionSummary(view)
	return view
}

func sourceViewerWorkflowSections(workflow poutine.WorkflowSourceInsight) []sourceViewerInspectionSectionView {
	sections := []sourceViewerInspectionSectionView{
		{Title: "Triggers", Items: sourceViewerStringItems(workflow.Events, "")},
		{Title: "Workflow permissions", Items: sourceViewerPermissionItems(workflow.Permissions, "")},
	}
	jobItems := make([]sourceViewerInspectionItemView, 0, len(workflow.Jobs))
	for _, job := range workflow.Jobs {
		label := job.ID
		if job.Name != "" {
			label += " - " + job.Name
		}
		item := sourceViewerInspectionItemView{
			Label:       label,
			Detail:      strings.Join(job.RunsOn, ", "),
			Href:        sourceLineHref(job.Line),
			Badges:      sourceViewerJobBadges(job),
			Collapsible: true,
		}
		for _, step := range job.Steps {
			stepItem := sourceViewerInspectionItemView{
				Label:  step.Name,
				Detail: sourceViewerStepDetail(step),
				Href:   sourceLineHref(step.Line),
			}
			if step.Uses != "" && !strings.Contains(step.Uses, "@") {
				stepItem.Badges = append(stepItem.Badges, sourceViewerBadgeView{Kind: "medium", Label: "unpinned"})
			}
			item.Children = append(item.Children, stepItem)
		}
		jobItems = append(jobItems, item)
	}
	sections = append(sections, sourceViewerInspectionSectionView{Title: "Jobs and steps", Items: jobItems})
	return sourceViewerNonEmptySections(sections)
}

func sourceViewerActionSections(action poutine.ActionSourceInsight) []sourceViewerInspectionSectionView {
	sections := []sourceViewerInspectionSectionView{
		{Title: "Action", Items: []sourceViewerInspectionItemView{{
			Label:  sourceViewerFallback(action.Name, "Unnamed action"),
			Detail: strings.TrimSpace(action.RunsUsing),
			Badges: sourceViewerActionBadges(action),
		}}},
		{Title: "Inputs", Items: sourceViewerActionIOItems(action.Inputs)},
		{Title: "Outputs", Items: sourceViewerActionIOItems(action.Outputs)},
	}
	if len(action.Steps) > 0 {
		stepItems := make([]sourceViewerInspectionItemView, 0, len(action.Steps))
		for _, step := range action.Steps {
			stepItems = append(stepItems, sourceViewerInspectionItemView{
				Label:  step.Name,
				Detail: sourceViewerStepDetail(step),
				Href:   sourceLineHref(step.Line),
			})
		}
		sections = append(sections, sourceViewerInspectionSectionView{Title: "Composite steps", Items: stepItems})
	}
	return sourceViewerNonEmptySections(sections)
}

func sourceViewerStringItems(values []string, empty string) []sourceViewerInspectionItemView {
	items := make([]sourceViewerInspectionItemView, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, sourceViewerInspectionItemView{Label: value})
		}
	}
	if len(items) == 0 && empty != "" {
		items = append(items, sourceViewerInspectionItemView{Label: empty})
	}
	return items
}

func sourceViewerPermissionItems(values []poutine.SourcePermission, empty string) []sourceViewerInspectionItemView {
	items := make([]sourceViewerInspectionItemView, 0, len(values))
	for _, value := range values {
		if value.Scope == "" && value.Permission == "" {
			continue
		}
		badges := []sourceViewerBadgeView{{Kind: sourceViewerPermissionKind(value.Permission), Label: value.Permission}}
		items = append(items, sourceViewerInspectionItemView{Label: value.Scope, Badges: badges})
	}
	if len(items) == 0 && empty != "" {
		items = append(items, sourceViewerInspectionItemView{Label: empty})
	}
	return items
}

func sourceViewerActionIOItems(values []poutine.ActionIOInsight) []sourceViewerInspectionItemView {
	items := make([]sourceViewerInspectionItemView, 0, len(values))
	for _, value := range values {
		badges := []sourceViewerBadgeView{}
		if value.Required {
			badges = append(badges, sourceViewerBadgeView{Kind: "medium", Label: "required"})
		}
		if strings.Contains(strings.ToLower(value.Name), "token") || strings.Contains(strings.ToLower(value.Name), "secret") {
			badges = append(badges, sourceViewerBadgeView{Kind: "high", Label: "sensitive"})
		}
		items = append(items, sourceViewerInspectionItemView{
			Label:  value.Name,
			Detail: sourceViewerFallback(value.Description, value.Type),
			Badges: badges,
		})
	}
	return items
}

func sourceViewerJobBadges(job poutine.WorkflowJobInsight) []sourceViewerBadgeView {
	var badges []sourceViewerBadgeView
	if job.Meta != nil {
		if job.Meta.SelfHosted {
			badges = append(badges, sourceViewerBadgeView{Kind: "critical", Label: "self-hosted"})
		}
		if job.Meta.HasOIDC {
			badges = append(badges, sourceViewerBadgeView{Kind: "high", Label: "OIDC"})
		}
		if job.Meta.GitHubTokenRW {
			badges = append(badges, sourceViewerBadgeView{Kind: "high", Label: "contents:write"})
		} else if job.Meta.HasWrite {
			badges = append(badges, sourceViewerBadgeView{Kind: "medium", Label: "write token"})
		}
	}
	return badges
}

func sourceViewerActionBadges(action poutine.ActionSourceInsight) []sourceViewerBadgeView {
	if action.RunsUsing == "" {
		return nil
	}
	kind := "neutral"
	switch strings.ToLower(action.RunsUsing) {
	case "composite":
		kind = "medium"
	case "docker":
		kind = "medium"
	case "node12", "node16":
		kind = "medium"
	}
	return []sourceViewerBadgeView{{Kind: kind, Label: action.RunsUsing}}
}

func sourceViewerStepDetail(step poutine.WorkflowStepInsight) string {
	switch {
	case step.Uses != "":
		return step.Uses
	case step.Shell != "":
		return step.Shell
	case step.Run != "":
		firstLine, _, _ := strings.Cut(strings.TrimSpace(step.Run), "\n")
		return firstLine
	default:
		return ""
	}
}

func sourceViewerRiskViews(risks []poutine.SourceRisk) []sourceViewerRiskView {
	out := make([]sourceViewerRiskView, 0, len(risks))
	for _, risk := range risks {
		label, order := sourceViewerRiskDisplay(risk.Kind, risk.Order)
		out = append(out, sourceViewerRiskView{
			Severity: risk.Severity,
			Kind:     risk.Kind,
			Label:    label,
			Message:  risk.Message,
			Details:  append([]string(nil), risk.Sources...),
			Line:     risk.Line,
			Href:     sourceLineHref(risk.Line),
			Order:    order,
		})
	}
	return out
}

func (h *Handler) sourceViewerPantryRisks(resp SourceContentResponse) []sourceViewerRiskView {
	p := h.Pantry()
	if p == nil {
		return nil
	}
	var risks []sourceViewerRiskView
	for _, asset := range p.GetAssetsByType(pantry.AssetVulnerability) {
		path := sourceAssetStringProperty(asset, "path")
		if path != resp.Path {
			continue
		}
		_, org, repo := pantry.ParsePurl(asset.Purl)
		if org != "" && repo != "" && org+"/"+repo != resp.Repository {
			continue
		}
		line := sourceAssetIntProperty(asset, "line")
		risks = append(risks, sourceViewerRiskForAsset(asset, line))
	}
	return risks
}

func sourceViewerRiskForAsset(asset pantry.Asset, line int) sourceViewerRiskView {
	kind := asset.RuleID
	message := sourceViewerRuleMessage(asset)
	switch asset.RuleID {
	case "injection":
		kind = "tainted-input"
	case "untrusted_checkout_exec":
		if sourceAssetStringProperty(asset, "lotp_tool") != "" || sourceAssetStringProperty(asset, "lotp_action") != "" {
			kind = "lotp-tool"
		} else {
			kind = "untrusted-checkout"
		}
	case "workflow_dispatch":
		kind = "manual-entrypoint"
	}
	label, order := sourceViewerRiskDisplay(kind, 0)
	return sourceViewerRiskView{
		Severity: sourceViewerFallback(asset.Severity, "medium"),
		Kind:     kind,
		Label:    label,
		Message:  message,
		Details:  sourceViewerRuleDetails(asset),
		Line:     line,
		Href:     sourceLineHref(line),
		Order:    order,
	}
}

func sourceViewerRuleMessage(asset pantry.Asset) string {
	switch asset.RuleID {
	case "injection":
		return "User-controlled workflow input reaches command execution."
	case "untrusted_checkout_exec":
		tool := sourceViewerFallback(sourceAssetStringProperty(asset, "lotp_tool"), sourceAssetStringProperty(asset, "lotp_action"))
		targets := sourceAssetStringSliceProperty(asset, "lotp_targets")
		if tool != "" && len(targets) > 0 {
			return fmt.Sprintf("Untrusted checkout can influence %s through %s.", strings.Join(targets, ", "), tool)
		}
		if tool != "" {
			return "Untrusted checkout can influence execution through " + tool + "."
		}
		return "Workflow checks out untrusted code before executing pipeline code."
	case "workflow_dispatch":
		return "Manual dispatch input can drive this workflow."
	default:
		title := sourceAssetStringProperty(asset, "title")
		if title != "" {
			return title
		}
		return "Analyzer reported " + strings.ReplaceAll(asset.RuleID, "_", " ") + "."
	}
}

func sourceViewerRuleDetails(asset pantry.Asset) []string {
	switch asset.RuleID {
	case "injection":
		return sourceAssetStringSliceProperty(asset, "injection_sources")
	default:
		return nil
	}
}

func sourceViewerDedupRisks(risks []sourceViewerRiskView) []sourceViewerRiskView {
	seen := make(map[string]struct{})
	out := make([]sourceViewerRiskView, 0, len(risks))
	for _, risk := range risks {
		if risk.Kind == "tainted-input" {
			risk.Message = sourceViewerTaintedRiskMessage(risk.Message)
			risk.Details = sourceViewerRiskDetails(risk)
		}
		key := strings.Join([]string{risk.Kind, risk.Label, risk.Message, fmt.Sprint(risk.Line)}, "\x00")
		if _, ok := seen[key]; ok {
			for i := range out {
				if strings.Join([]string{out[i].Kind, out[i].Label, out[i].Message, fmt.Sprint(out[i].Line)}, "\x00") == key {
					out[i].Details = sourceViewerUniqueSortedStrings(append(out[i].Details, risk.Details...))
					break
				}
			}
			continue
		}
		seen[key] = struct{}{}
		risk.Details = sourceViewerUniqueSortedStrings(risk.Details)
		out = append(out, risk)
	}
	return out
}

func sourceViewerTaintedRiskMessage(message string) string {
	message = strings.TrimSpace(message)
	switch {
	case strings.Contains(message, "github-script"):
		return "github-script uses attacker-controlled GitHub context."
	case strings.Contains(message, "Shell command"):
		return "Shell command uses attacker-controlled GitHub context."
	case strings.Contains(message, "command execution"):
		return "User-controlled workflow input reaches command execution."
	default:
		return sourceViewerFallback(message, "Attacker-controlled GitHub context reaches execution.")
	}
}

func sourceViewerRiskDetails(risk sourceViewerRiskView) []string {
	details := append([]string(nil), risk.Details...)
	message := strings.TrimSpace(risk.Message)
	for _, prefix := range []string{
		"Shell command uses attacker-controlled GitHub context:",
		"github-script uses attacker-controlled GitHub context:",
		"User-controlled workflow input reaches command execution:",
	} {
		_, value, ok := strings.Cut(message, prefix)
		if !ok {
			continue
		}
		value = strings.TrimSuffix(strings.TrimSpace(value), ".")
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				details = append(details, part)
			}
		}
	}
	return details
}

func sourceViewerUniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
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

func sourceViewerRiskDisplay(kind string, order int) (label string, displayOrder int) {
	label = strings.ReplaceAll(kind, "-", " ")
	displayOrder = order
	if displayOrder == 0 {
		displayOrder = 80
	}
	switch kind {
	case "attackable-trigger":
		label, displayOrder = "trigger", 10
	case "write-token":
		label, displayOrder = "write token", 20
	case "secrets-access", "secret-reference":
		label, displayOrder = "secrets", 20
	case "self-hosted":
		label, displayOrder = "self-hosted", 20
	case "oidc-token":
		label, displayOrder = "OIDC", 20
	case "github-app-token":
		label, displayOrder = "app token", 20
	case "cloud-login":
		label, displayOrder = "cloud login", 20
	case "weak-gate":
		label, displayOrder = "missing gate", 30
	case "untrusted-checkout":
		label, displayOrder = "untrusted checkout", 40
	case "lotp-tool":
		label, displayOrder = "LOTP", 50
	case "tainted-input":
		label, displayOrder = "tainted input", 60
	case "sensitive-input":
		label, displayOrder = "sensitive input", 20
	case "manual-entrypoint":
		label, displayOrder = "manual input", 30
	case "unpinned-action":
		label, displayOrder = "unpinned", 90
	case "docker-action":
		label, displayOrder = "docker action", 90
	case "old-runtime":
		label, displayOrder = "old runtime", 90
	case "log-error":
		label, displayOrder = "error", 10
	case "log-warning":
		label, displayOrder = "warning", 20
	case "masked-secret":
		label, displayOrder = "masked secret", 30
	case "truncated-log":
		label, displayOrder = "truncated", 40
	}
	return label, displayOrder
}

func sourceViewerInspectionSummary(view *sourceViewerInspectionView) []sourceViewerBadgeView {
	if view == nil {
		return nil
	}
	counts := make(map[string]int)
	for _, risk := range view.Risks {
		counts[risk.Severity]++
	}
	var badges []sourceViewerBadgeView
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if count := counts[severity]; count > 0 {
			badges = append(badges, sourceViewerBadgeView{Kind: severity, Label: fmt.Sprintf("%d %s", count, severity)})
		}
	}
	if len(badges) == 0 {
		badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: "no obvious risk"})
	}
	return badges
}

func sourceViewerNonEmptySections(sections []sourceViewerInspectionSectionView) []sourceViewerInspectionSectionView {
	out := make([]sourceViewerInspectionSectionView, 0, len(sections))
	for _, section := range sections {
		if len(section.Items) > 0 {
			out = append(out, section)
		}
	}
	return out
}

func sourceViewerPermissionKind(permission string) string {
	switch permission {
	case "write":
		return "medium"
	case "read":
		return "neutral"
	default:
		return "low"
	}
}

func sourceViewerFallback(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}

func sourceLineHref(line int) string {
	if line <= 0 {
		return ""
	}
	return fmt.Sprintf("#L%d", line)
}

func sourceViewerSeverityWeight(severity string) int {
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

func sourceAssetIntProperty(asset pantry.Asset, key string) int {
	if asset.Properties == nil {
		return 0
	}
	value, ok := asset.Properties[key]
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func sourceAssetStringSliceProperty(asset pantry.Asset, key string) []string {
	if asset.Properties == nil {
		return nil
	}
	value, ok := asset.Properties[key]
	if !ok || value == nil {
		return nil
	}
	var out []string
	switch v := value.(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, item := range v {
			if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
				out = append(out, s)
			}
		}
	default:
		if s := strings.TrimSpace(fmt.Sprint(v)); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
