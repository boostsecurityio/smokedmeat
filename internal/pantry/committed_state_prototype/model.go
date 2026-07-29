// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "fmt"

type interfaceDesign struct {
	name       string
	signature  []string
	caller     []string
	callerMust []string
	tradeoff   string
}

var interfaceDesigns = []interfaceDesign{
	{
		name: "Raw candidate callback",
		signature: []string{
			"func (p *Pantry) UpdateCommitted(",
			"    ctx context.Context,",
			"    store SnapshotCommitter,",
			"    update func(context.Context, *Pantry) error,",
			") error",
		},
		caller: []string{
			"return p.UpdateCommitted(ctx, store, func(ctx context.Context, candidate *Pantry) error {",
			"    return reconcileAnalysis(ctx, candidate, completed)",
			"})",
		},
		callerMust: []string{
			"candidate is detached",
			"do not retain it",
			"do not perform side effects",
		},
		tradeoff: "Smallest seam; the raw Pantry callback carries lifetime rules the type cannot enforce.",
	},
	{
		name: "Explicit transaction capability",
		signature: []string{
			"tx, err := p.BeginWrite(ctx, TransactionOptions{Publication: PublishCommittedState})",
			"candidate := tx.Candidate()",
			"result, err := tx.Commit(ctx)",
			"tx.Abort()",
		},
		caller: []string{
			"tx, err := p.BeginWrite(ctx, options)",
			"defer tx.Abort()",
			"reconcileAnalysis(tx.Candidate(), completed)",
			"_, err = tx.Commit(ctx)",
		},
		callerMust: []string{
			"always abort",
			"choose publication mode",
			"never call live mutators",
			"never retain the capability",
		},
		tradeoff: "Most flexible; exposes gate lifetime and makes a leaked capability block every Pantry writer.",
	},
	{
		name: "Bound committed-state module with Draft",
		signature: []string{
			"type CommittedState struct { live *Pantry; store SnapshotStore }",
			"func (s *CommittedState) Update(",
			"    ctx context.Context,",
			"    update func(*Draft) error,",
			") error",
		},
		caller: []string{
			"return committed.Update(ctx, func(candidate *pantry.Draft) error {",
			"    return reconcileAnalysis(candidate, completed)",
			"})",
		},
		callerMust: []string{
			"Draft supports exact replacement",
			"Draft closes after callback",
		},
		tradeoff: "Makes the common caller safest; pays for a second graph-editing surface beside Pantry.",
	},
}

type graphState struct {
	revision int
	workflow string
	metadata string
}

func (g graphState) summary() string {
	return fmt.Sprintf("rev=%d workflow=%s metadata=%s", g.revision, g.workflow, g.metadata)
}

type prototypeState struct {
	designIndex        int
	phase              string
	gateHeld           bool
	baseRevision       int
	candidate          graphState
	candidateEdits     int
	live               graphState
	durable            graphState
	pendingWriter      bool
	granularEvents     int
	committedSignals   []string
	readerObservations []string
	lastOutcome        string
	trace              []string
}

func newPrototypeState(designIndex int) prototypeState {
	initial := graphState{
		revision: 12,
		workflow: "old.yml",
		metadata: "visibility=private",
	}
	return prototypeState{
		designIndex: designIndex,
		phase:       "idle",
		live:        initial,
		durable:     initial,
		lastOutcome: "ready",
	}
}

func (s prototypeState) withDesign(index int) prototypeState {
	next := newPrototypeState(index)
	next.lastOutcome = "interface selected"
	return next
}

func (s prototypeState) run(action rune) prototypeState {
	next := s
	next.trace = append([]string(nil), s.trace...)
	next.committedSignals = append([]string(nil), s.committedSignals...)
	next.readerObservations = append([]string(nil), s.readerObservations...)

	switch action {
	case 'b':
		next.begin()
	case 'm':
		next.mutateCandidate()
	case 'r':
		next.read()
	case 'w':
		next.writeMetadata()
	case 'v':
		next.prepare()
	case 'n':
		next.noop()
	case 'p':
		next.commit(false)
	case 'a':
		next.commit(true)
	case 'f':
		next.failPersistence()
	case 'c':
		next.cancel()
	case 'l':
		next.leak()
	}

	return next
}

func (s *prototypeState) begin() {
	if s.phase != "idle" {
		s.lastOutcome = "begin rejected: transaction already active or terminal"
		return
	}

	s.gateHeld = true
	s.baseRevision = s.live.revision
	s.candidate = s.live
	s.phase = "building"
	s.lastOutcome = "writer gate acquired; candidate cloned from latest committed Pantry"

	switch s.designIndex {
	case 1:
		s.trace = append(s.trace,
			"caller: BeginWrite(ctx, publication mode)",
			"caller: defer Abort()",
			"Pantry: acquire writer gate",
			"Pantry: return transaction capability and Candidate",
		)
	case 2:
		s.trace = append(s.trace,
			"caller: CommittedState.Update(ctx, Draft callback)",
			"module: acquire writer gate",
			"module: clone latest committed state into a scoped Draft",
		)
	default:
		s.trace = append(s.trace,
			"caller: Pantry.UpdateCommitted(ctx, store, callback)",
			"Pantry: acquire writer gate",
			"Pantry: clone latest committed state into a detached Pantry",
		)
	}
}

func (s *prototypeState) mutateCandidate() {
	if s.phase != "building" && s.phase != "candidate_ready" {
		s.lastOutcome = "candidate mutation rejected: begin first"
		return
	}
	s.candidate.workflow = "current.yml"
	s.candidateEdits++
	s.phase = "candidate_ready"
	s.lastOutcome = "candidate changed; live and durable Pantry remain old"
	s.trace = append(s.trace, "AnalysisIngestor: replace Analysis-owned workflow in candidate")
}

func (s *prototypeState) read() {
	observation := s.live.summary()
	s.readerObservations = append(s.readerObservations, observation)
	s.lastOutcome = "reader observed " + observation
	s.trace = append(s.trace, "reader: load one complete committed state")
}

func (s *prototypeState) writeMetadata() {
	if s.gateHeld {
		s.pendingWriter = true
		s.lastOutcome = "metadata-sync writer waits at the shared writer gate"
		s.trace = append(s.trace, "metadata-sync: wait without changing live Pantry")
		return
	}
	s.applyMetadataWriter()
	s.lastOutcome = "metadata-sync committed as an ordinary granular write"
}

func (s *prototypeState) prepare() {
	if s.phase != "candidate_ready" {
		s.lastOutcome = "prepare rejected: mutate the candidate first"
		return
	}
	s.phase = "serialized"
	s.lastOutcome = "candidate validated and serialized exactly once"
	s.trace = append(s.trace,
		"module: validate complete candidate",
		"module: serialize complete candidate once",
		"module: final cancellation check",
	)
}

func (s *prototypeState) noop() {
	if !s.gateHeld || s.candidateEdits != 0 {
		s.lastOutcome = "no-op rejected: requires an unchanged active candidate"
		return
	}
	s.trace = append(s.trace,
		"module: candidate equals committed Pantry",
		"module: release writer gate without persistence, revision change, or publication",
	)
	s.gateHeld = false
	s.phase = "no_op"
	s.lastOutcome = "trustworthy no-op; live and durable revision remain unchanged"
	s.finishWaitingWriter()
}

func (s *prototypeState) commit(cancelAfterStore bool) {
	if s.phase != "serialized" {
		s.lastOutcome = "commit rejected: validate and serialize first"
		return
	}

	nextRevision := s.baseRevision + 1
	s.candidate.revision = nextRevision
	s.durable = s.candidate
	s.trace = append(s.trace, "store: atomically persist supplied bytes")
	if cancelAfterStore {
		s.trace = append(s.trace,
			"context: canceled after store returned success",
			"module: ignore cancellation after the durable commit point",
		)
	}

	s.live = s.candidate
	s.committedSignals = append(s.committedSignals, fmt.Sprintf("committed-state rev=%d", nextRevision))
	s.trace = append(s.trace,
		"module: replace live internals through the stable Pantry pointer",
		"module: queue one committed-state signal before another writer passes",
		"module: release writer gate",
	)
	s.gateHeld = false
	s.phase = "committed"
	if cancelAfterStore {
		s.lastOutcome = "committed successfully; cancellation cannot report failure after persistence"
	} else {
		s.lastOutcome = "new Pantry is durable, live, and ordered for publication"
	}
	s.finishWaitingWriter()
}

func (s *prototypeState) failPersistence() {
	if s.phase != "serialized" {
		s.lastOutcome = "failure injection rejected: validate and serialize first"
		return
	}
	s.trace = append(s.trace,
		"store: persistence fails and proves old durable bytes remain",
		"module: discard candidate",
		"module: release writer gate without replacement or publication",
	)
	s.gateHeld = false
	s.phase = "failed"
	s.lastOutcome = "persistence failed; old live and durable Pantry remain authoritative"
	s.finishWaitingWriter()
}

func (s *prototypeState) cancel() {
	if !s.gateHeld || s.phase == "committed" {
		s.lastOutcome = "nothing cancellable is active"
		return
	}
	s.trace = append(s.trace,
		"context: canceled before persistence",
		"module: discard candidate and release writer gate",
	)
	s.gateHeld = false
	s.phase = "canceled"
	s.lastOutcome = "canceled before persistence; old live and durable Pantry remain authoritative"
	s.finishWaitingWriter()
}

func (s *prototypeState) leak() {
	switch s.designIndex {
	case 1:
		if s.gateHeld {
			s.phase = "leaked"
			s.lastOutcome = "caller leaked the transaction; writer gate remains held until Abort"
			s.trace = append(s.trace,
				"caller: returns without Commit or Abort",
				"metadata-sync and every later Pantry writer remain blocked",
			)
			return
		}
		s.lastOutcome = "closed transaction rejects Candidate use"
		s.trace = append(s.trace, "Candidate: ErrTransactionClosed")
	case 2:
		s.lastOutcome = "retained Draft rejects use after callback"
		s.trace = append(s.trace, "Draft: ErrDraftClosed")
	default:
		s.lastOutcome = "retained raw candidate remains mutable but detached from live Pantry"
		s.trace = append(s.trace,
			"retained candidate: mutation succeeds on detached state",
			"live Pantry: unchanged, but lifetime misuse is not type-enforced",
		)
	}
}

func (s *prototypeState) finishWaitingWriter() {
	if !s.pendingWriter {
		return
	}
	s.pendingWriter = false
	s.trace = append(s.trace, "metadata-sync: acquire gate after transaction terminal state")
	s.applyMetadataWriter()
}

func (s *prototypeState) applyMetadataWriter() {
	s.live.metadata = "visibility=internal"
	s.live.revision++
	s.durable = s.live
	s.granularEvents++
	s.trace = append(s.trace,
		fmt.Sprintf("ordinary writer: persist rev=%d and emit one granular event", s.live.revision),
	)
}
