// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "slices"

type interfaceDesign struct {
	name       string
	signature  []string
	caller     []string
	callerMust []string
	tradeoff   string
}

var interfaceDesigns = []interfaceDesign{
	{
		name: "Minimal completed-result commit",
		signature: []string{
			"type AnalysisIngestor struct { ... }",
			"func (i *AnalysisIngestor) Ingest(",
			"    ctx context.Context,",
			"    completed poutine.AnalysisResult,",
			") error",
		},
		caller: []string{
			"err := h.analysisIngestor.Ingest(ctx, *result)",
			"recordReconciliation(err)",
		},
		callerMust: []string{
			"completed Analysis result",
			"committed or failed",
		},
		tradeoff: "Deepest Pantry seam; notice wording must come from later publication or contract work.",
	},
	{
		name: "Prepared command lifecycle",
		signature: []string{
			"type AnalysisIngestor interface {",
			"    Prepare(context.Context, PrepareAnalysis) (*PreparedAnalysis, error)",
			"    Commit(context.Context, *PreparedAnalysis) (AnalysisCommit, error)",
			"}",
		},
		caller: []string{
			"prepared, err := ingestor.Prepare(ctx, command)",
			"summary := prepared.Summary()",
			"commit, err := ingestor.Commit(ctx, prepared)",
		},
		callerMust: []string{
			"prepare-before-commit ordering",
			"opaque capability lifetime",
			"plan summary and commit disposition",
			"revision and removal notice",
		},
		tradeoff: "Supports preview and audit detail; exposes a lifecycle no current caller needs.",
	},
	{
		name: "Caller-shaped Analysis flow",
		signature: []string{
			"type analysisFlow struct { ... }",
			"func (f *analysisFlow) Run(",
			"    ctx context.Context,",
			"    req AnalyzeRequest,",
			") (analysisCompletion, error)",
		},
		caller: []string{
			"completion, err := h.analysis.Run(ctx, req)",
			"writeAnalysisResponse(completion, err)",
		},
		callerMust: []string{
			"request-level failure",
			"completed result plus Pantry outcome",
		},
		tradeoff: "Makes handleAnalyze trivial; couples ingestion to remote execution and progress flow.",
	},
}

type prototypeState struct {
	designIndex       int
	liveRevision      int
	persistedRevision int
	publishedRevision int
	assets            []string
	loot              []string
	lastScenario      string
	lastOutcome       string
	notice            string
	trace             []string
}

func newPrototypeState(designIndex int) prototypeState {
	return prototypeState{
		designIndex:       designIndex,
		liveRevision:      12,
		persistedRevision: 12,
		publishedRevision: 12,
		assets: []string{
			"organization acme",
			"repository acme/api",
			"workflow old.yml",
			"job old.yml/deploy",
			"vulnerability old-injection",
			"detected secret old-key",
		},
		loot: []string{
			"AWS_ACCESS_KEY_ID from old.yml/deploy",
		},
		lastScenario: "initial committed Pantry",
		lastOutcome:  "ready",
	}
}

func (s prototypeState) withDesign(index int) prototypeState {
	next := newPrototypeState(index)
	next.lastScenario = "interface selected"
	return next
}

func (s prototypeState) run(action rune) prototypeState {
	next := s
	next.assets = slices.Clone(s.assets)
	next.loot = slices.Clone(s.loot)
	next.trace = interfaceTrace(s.designIndex)
	next.notice = ""

	switch action {
	case 'c':
		next.lastScenario = "successful workflow and secret replacement"
		next.assets = []string{
			"organization acme",
			"repository acme/api",
			"workflow current.yml",
			"job current.yml/build",
			"vulnerability current-injection",
			"detected secret current-key",
		}
		next.commit("committed current Analysis evidence")
	case 'p':
		next.lastScenario = "workflow succeeded; secret detection failed"
		next.assets = []string{
			"organization acme",
			"repository acme/api",
			"workflow current.yml",
			"job current.yml/build",
			"vulnerability current-injection",
			"detected secret old-key",
		}
		next.commit("committed workflow evidence; preserved prior secret evidence")
	case 'g':
		next.lastScenario = "repository confirmed gone"
		next.assets = []string{"organization acme"}
		next.notice = "Repository acme/api removed; Loot and History preserved"
		next.commit("committed confirmed-gone cleanup")
	case 'n':
		next.lastScenario = "trustworthy result with no authoritative change"
		next.lastOutcome = "successful no-op; no persistence or publication"
		next.trace = append(next.trace, "candidate equals committed Pantry", "return success")
	case 'f':
		next.lastScenario = "persistence failure"
		next.lastOutcome = "failed; prior durable and live Pantry remain authoritative"
		next.trace = append(next.trace,
			"validate completed Analysis",
			"build detached candidate",
			"serialize candidate once",
			"persistence returns error",
			"do not replace live Pantry",
			"do not publish",
		)
	}

	return next
}

func (s *prototypeState) commit(outcome string) {
	s.liveRevision++
	s.persistedRevision = s.liveRevision
	s.publishedRevision = s.liveRevision
	s.lastOutcome = outcome
	s.trace = append(s.trace,
		"validate completed Analysis",
		"build detached candidate",
		"persist candidate",
		"replace live Pantry internals",
		"publish one committed revision",
	)
}

func interfaceTrace(designIndex int) []string {
	switch designIndex {
	case 1:
		return []string{
			"caller: Prepare(command)",
			"caller: inspect Summary",
			"caller: Commit(prepared)",
		}
	case 2:
		return []string{
			"caller: Run(AnalyzeRequest)",
			"module: execute workflow Analysis and secret detection",
			"module: complete repository outcomes",
		}
	default:
		return []string{"caller: Ingest(completed AnalysisResult)"}
	}
}
