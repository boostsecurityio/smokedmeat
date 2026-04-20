// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/boostsecurityio/poutine/models"
)

func ExpandFindings(findings []Finding) []Finding {
	expanded := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		expanded = append(expanded, ExpandFindingVariants(finding)...)
	}
	return expanded
}

func ExpandFindingVariantsWithWorkflows(workflows []models.GithubActionsWorkflow, finding Finding) []Finding {
	return expandFindingVariants(finding, workflows)
}

func ExpandFindingVariants(finding Finding) []Finding {
	return expandFindingVariants(finding, nil)
}

func FindingVariantDiscriminator(finding Finding) string {
	if fingerprint := strings.TrimSpace(finding.Fingerprint); fingerprint != "" {
		return fingerprint
	}

	return strings.Join([]string{
		strings.TrimSpace(finding.Repository),
		strings.TrimSpace(finding.Workflow),
		fmt.Sprintf("%09d", finding.Line),
		strings.TrimSpace(finding.Job),
		strings.TrimSpace(finding.Step),
		strings.TrimSpace(finding.RuleID),
		strings.Join(normalizedStringValues(finding.InjectionSources), "\x01"),
		strings.TrimSpace(finding.Context),
		strings.TrimSpace(finding.Expression),
	}, "\x00")
}

func expandFindingVariants(finding Finding, workflows []models.GithubActionsWorkflow) []Finding {
	sources := normalizedStringValues(finding.InjectionSources)
	if len(sources) <= 1 {
		return []Finding{finding}
	}

	variants := make([]Finding, 0, len(sources))
	for i, source := range sources {
		variant := finding
		variant.ID = variantID(finding.ID, i+1)
		variant.Context = determineContextFromSources([]string{source})
		variant.Expression = "${{ " + source + " }}"
		variant.InjectionSources = []string{source}
		if len(workflows) > 0 {
			variant.BashContext = determineBashContextForSource(
				workflows,
				finding.Workflow,
				finding.Job,
				finding.Step,
				finding.Line,
				finding.InjectionSources,
				source,
			)
		}
		if variant.Fingerprint != "" {
			variant.Fingerprint = variant.Fingerprint + "\x00" + source
		}
		variants = append(variants, variant)
	}

	return variants
}

func variantID(id string, ordinal int) string {
	if strings.TrimSpace(id) == "" || ordinal <= 0 {
		return id
	}
	return id + "." + strconv.Itoa(ordinal)
}

func normalizedStringValues(values []string) []string {
	valueSet := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, seen := valueSet[value]; seen {
			continue
		}
		valueSet[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}
