// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package poutine

import (
	"regexp"
	"sort"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/bashctx"

	"github.com/boostsecurityio/poutine/models"
	"mvdan.cc/sh/v3/syntax"
)

const (
	bashContextUnquoted      = bashctx.Unquoted
	bashContextSingleQuoted  = bashctx.SingleQuoted
	bashContextDoubleQuoted  = bashctx.DoubleQuoted
	bashContextHeredoc       = bashctx.Heredoc
	bashContextQuotedHeredoc = bashctx.QuotedHeredoc
)

type bashExpressionPattern struct {
	expr *regexp.Regexp
}

type bashExpressionSpan struct {
	start int
	end   int
}

func determineBashContextForFinding(
	workflows []models.GithubActionsWorkflow,
	findingPath, findingJob, findingStep string,
	line int,
	injectionSources []string,
) string {
	patterns := expressionPatternsFromInjectionSources(injectionSources)
	if len(patterns) == 0 {
		return ""
	}

	run := findRunForFinding(workflows, findingPath, findingJob, findingStep, line, patterns)
	if run == "" {
		return ""
	}

	spans := findExpressionSpans(run, patterns)
	if len(spans) == 0 {
		return ""
	}
	primarySpans := findExpressionSpans(run, patterns[:1])
	if len(primarySpans) == 0 {
		return ""
	}

	return classifyBashRunContext(run, spans, primarySpans[0])
}

func expressionPatternsFromInjectionSources(injectionSources []string) []bashExpressionPattern {
	patterns := make([]bashExpressionPattern, 0, len(injectionSources))
	seen := make(map[string]struct{}, len(injectionSources))

	for _, source := range injectionSources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		patterns = append(patterns, bashExpressionPattern{
			expr: regexp.MustCompile(`\$\{\{\s*` + regexp.QuoteMeta(source) + `\s*\}\}`),
		})
	}

	return patterns
}

func findRunForFinding(
	workflows []models.GithubActionsWorkflow,
	findingPath, findingJob, findingStep string,
	line int,
	patterns []bashExpressionPattern,
) string {
	for _, wf := range workflows {
		if !pathMatch(wf.Path, findingPath) {
			continue
		}
		for _, job := range wf.Jobs {
			if !jobMatch(job.ID, job.Name, findingJob) {
				continue
			}
			for _, step := range job.Steps {
				if step.Run == "" {
					continue
				}
				if stepMatch(step.ID, step.Name, findingStep) {
					return step.Run
				}
				if line > 0 && (step.Line == line || step.Lines["run"] == line) {
					return step.Run
				}
				for _, pattern := range patterns {
					if pattern.expr.FindStringIndex(step.Run) != nil {
						return step.Run
					}
				}
			}
			break
		}
		break
	}

	return ""
}

func findExpressionSpans(run string, patterns []bashExpressionPattern) []bashExpressionSpan {
	spans := make([]bashExpressionSpan, 0, len(patterns))

	for _, pattern := range patterns {
		for _, loc := range pattern.expr.FindAllStringIndex(run, -1) {
			spans = append(spans, bashExpressionSpan{start: loc[0], end: loc[1]})
		}
	}

	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})

	deduped := spans[:0]
	for _, span := range spans {
		if len(deduped) > 0 && deduped[len(deduped)-1] == span {
			continue
		}
		deduped = append(deduped, span)
	}

	return deduped
}

func classifyBashRunContext(run string, spans []bashExpressionSpan, targetSpan bashExpressionSpan) string {
	file, _ := syntax.NewParser(
		syntax.Variant(syntax.LangBash),
		syntax.RecoverErrors(8),
	).Parse(strings.NewReader(replaceExpressionSpans(run, spans)), "")
	if file == nil {
		return ""
	}

	if ctx := bashContextForSpan(file, run, targetSpan); ctx != "" {
		return ctx
	}

	return bashContextUnquoted
}

func bashContextForSpan(file *syntax.File, src string, span bashExpressionSpan) string {
	var ctx string

	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			return true
		}
		if ctx != "" {
			return false
		}

		switch n := node.(type) {
		case *syntax.Redirect:
			if n.Hdoc == nil || !isHeredocRedirect(n.Op) {
				return true
			}
			if !spanWithinNode(span, n.Hdoc) {
				return true
			}
			if isQuotedHeredocDelimiter(src, n.Word) {
				ctx = bashContextQuotedHeredoc
			} else {
				ctx = bashContextHeredoc
			}
			return false
		case *syntax.SglQuoted:
			if spanWithinNode(span, n) {
				ctx = bashContextSingleQuoted
				return false
			}
		case *syntax.DblQuoted:
			if spanWithinNode(span, n) {
				ctx = bashContextDoubleQuoted
				return false
			}
		}

		return true
	})

	return ctx
}

func isHeredocRedirect(op syntax.RedirOperator) bool {
	return op == syntax.Hdoc || op == syntax.DashHdoc
}

func isQuotedHeredocDelimiter(src string, word *syntax.Word) bool {
	return strings.ContainsAny(nodeSource(src, word), `'"\\`)
}

func spanWithinNode(span bashExpressionSpan, node syntax.Node) bool {
	start := int(node.Pos().Offset())
	end := int(node.End().Offset())

	return start <= span.start && span.end <= end
}

func nodeSource(src string, node syntax.Node) string {
	return sliceByOffset(src, int(node.Pos().Offset()), int(node.End().Offset()))
}

func sliceByOffset(src string, start, end int) string {
	if start < 0 || end < start || len(src) < end {
		return ""
	}

	return src[start:end]
}

func replaceExpressionSpans(run string, spans []bashExpressionSpan) string {
	if len(spans) == 0 {
		return run
	}

	var b strings.Builder
	b.Grow(len(run))

	last := 0
	for _, span := range spans {
		if span.start < last || len(run) < span.end {
			continue
		}
		b.WriteString(run[last:span.start])
		b.WriteString(parseableExpression(run[span.start:span.end]))
		last = span.end
	}
	b.WriteString(run[last:])

	return b.String()
}

func parseableExpression(expr string) string {
	buf := []byte(expr)
	for i := range buf {
		if buf[i] == '\n' || buf[i] == '\r' {
			continue
		}
		buf[i] = 'x'
	}
	return string(buf)
}
