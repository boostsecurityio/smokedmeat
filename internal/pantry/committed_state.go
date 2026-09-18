// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"sort"
	"time"
)

type SnapshotStore interface {
	Replace(serialized []byte) error
}

type Snapshot struct {
	Revision uint64  `json:"revision"`
	Assets   []Asset `json:"assets"`
	Edges    []Edge  `json:"edges"`
}

type ChangeKind string

const (
	ChangeGranular       ChangeKind = "granular"
	ChangeCommittedState ChangeKind = "committed_state"
)

type AssetChange struct {
	Before Asset
	After  Asset
}

type EdgeRef struct {
	From string
	To   string
}

type GranularChanges struct {
	AddedAssets          []Asset
	UpdatedAssets        []AssetChange
	RemovedAssetIDs      []string
	AddedRelationships   []Edge
	RemovedRelationships []EdgeRef
}

func (c GranularChanges) count() int {
	return len(c.AddedAssets) + len(c.UpdatedAssets) + len(c.RemovedAssetIDs) + len(c.AddedRelationships) + len(c.RemovedRelationships)
}

type ChangeSet struct {
	Kind         ChangeKind
	BaseRevision uint64
	Revision     uint64
	Granular     GranularChanges
}

type Observer interface {
	OnPantryChange(change ChangeSet)
}

type CommittedState struct {
	live  *Pantry
	store SnapshotStore
	gate  chan struct{}
}

func NewCommittedState(live *Pantry, store SnapshotStore) *CommittedState {
	if live == nil {
		panic("pantry: committed state requires a live Pantry")
	}
	if store == nil {
		panic("pantry: committed state requires a SnapshotStore")
	}
	return &CommittedState{live: live, store: store, gate: live.committedWriterGate()}
}

func (s *CommittedState) Update(ctx context.Context, change func(candidate *Pantry) error) error {
	return s.commit(ctx, ChangeGranular, change)
}

func (s *CommittedState) Replace(ctx context.Context, change func(candidate *Pantry) error) error {
	return s.commit(ctx, ChangeCommittedState, change)
}

func (s *CommittedState) commit(ctx context.Context, kind ChangeKind, change func(candidate *Pantry) error) error {
	if change == nil {
		return fmt.Errorf("pantry: committed state change callback is required")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()

	totalStarted := time.Now()
	candidateStarted := time.Now()
	base := s.live.Snapshot()
	candidate := pantryFromSnapshot(base)
	candidateDuration := time.Since(candidateStarted)

	if err := change(candidate); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	diffStarted := time.Now()
	next := candidate.Snapshot()
	granular := diffSnapshots(base, next)
	diffDuration := time.Since(diffStarted)
	if granular.count() == 0 {
		slog.Debug("pantry state unchanged",
			"revision", base.Revision,
			"candidate_duration", candidateDuration,
			"diff_duration", diffDuration,
			"total_duration", time.Since(totalStarted))
		return nil
	}
	if base.Revision == math.MaxUint64 {
		return fmt.Errorf("pantry: committed revision exhausted")
	}

	next.Revision = base.Revision + 1
	candidate.setRevision(next.Revision)

	validationStarted := time.Now()
	if err := validateSnapshot(next); err != nil {
		return err
	}
	validationDuration := time.Since(validationStarted)

	serializationStarted := time.Now()
	serialized, err := json.Marshal(next)
	serializationDuration := time.Since(serializationStarted)
	if err != nil {
		return fmt.Errorf("serialize Pantry snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	persistenceStarted := time.Now()
	if err := s.store.Replace(serialized); err != nil {
		return fmt.Errorf("persist Pantry snapshot: %w", err)
	}
	persistenceDuration := time.Since(persistenceStarted)

	replacementStarted := time.Now()
	s.live.replaceWith(candidate)
	replacementDuration := time.Since(replacementStarted)

	publicationStarted := time.Now()
	changeSet := ChangeSet{
		Kind:         kind,
		BaseRevision: base.Revision,
		Revision:     next.Revision,
	}
	if kind == ChangeGranular {
		changeSet.Granular = granular
	}
	s.live.notifyChange(changeSet)
	publicationDuration := time.Since(publicationStarted)

	slog.Debug("pantry state committed",
		"kind", kind,
		"base_revision", base.Revision,
		"revision", next.Revision,
		"assets", len(next.Assets),
		"relationships", len(next.Edges),
		"granular_changes", granular.count(),
		"serialized_bytes", len(serialized),
		"candidate_duration", candidateDuration,
		"diff_duration", diffDuration,
		"validation_duration", validationDuration,
		"serialization_duration", serializationDuration,
		"persistence_duration", persistenceDuration,
		"replacement_duration", replacementDuration,
		"publication_duration", publicationDuration,
		"total_duration", time.Since(totalStarted))
	return nil
}

func validateSnapshot(snapshot Snapshot) error {
	assets := make(map[string]struct{}, len(snapshot.Assets))
	for _, asset := range snapshot.Assets {
		if asset.ID == "" {
			return fmt.Errorf("validate Pantry snapshot: asset ID is empty")
		}
		if _, exists := assets[asset.ID]; exists {
			return fmt.Errorf("validate Pantry snapshot: duplicate asset %q", asset.ID)
		}
		assets[asset.ID] = struct{}{}
	}
	edges := make(map[string]struct{}, len(snapshot.Edges))
	for _, edge := range snapshot.Edges {
		if _, exists := assets[edge.From]; !exists {
			return fmt.Errorf("validate Pantry snapshot: relationship source %q is missing", edge.From)
		}
		if _, exists := assets[edge.To]; !exists {
			return fmt.Errorf("validate Pantry snapshot: relationship target %q is missing", edge.To)
		}
		key := edgeKey(edge.From, edge.To)
		if _, exists := edges[key]; exists {
			return fmt.Errorf("validate Pantry snapshot: duplicate relationship %q", key)
		}
		edges[key] = struct{}{}
	}
	return nil
}

func diffSnapshots(before, after Snapshot) GranularChanges {
	beforeAssets := make(map[string]Asset, len(before.Assets))
	afterAssets := make(map[string]Asset, len(after.Assets))
	for _, asset := range before.Assets {
		beforeAssets[asset.ID] = asset
	}
	for _, asset := range after.Assets {
		afterAssets[asset.ID] = asset
	}

	changes := GranularChanges{}
	for id, asset := range afterAssets {
		previous, exists := beforeAssets[id]
		switch {
		case !exists:
			changes.AddedAssets = append(changes.AddedAssets, cloneAsset(asset))
		case !reflect.DeepEqual(previous, asset):
			changes.UpdatedAssets = append(changes.UpdatedAssets, AssetChange{Before: cloneAsset(previous), After: cloneAsset(asset)})
		}
	}
	for id := range beforeAssets {
		if _, exists := afterAssets[id]; !exists {
			changes.RemovedAssetIDs = append(changes.RemovedAssetIDs, id)
		}
	}

	beforeEdges := make(map[string]Edge, len(before.Edges))
	afterEdges := make(map[string]Edge, len(after.Edges))
	for _, edge := range before.Edges {
		beforeEdges[edgeKey(edge.From, edge.To)] = edge
	}
	for _, edge := range after.Edges {
		afterEdges[edgeKey(edge.From, edge.To)] = edge
	}
	for key, edge := range afterEdges {
		previous, exists := beforeEdges[key]
		if !exists {
			changes.AddedRelationships = append(changes.AddedRelationships, cloneEdge(edge))
			continue
		}
		if !reflect.DeepEqual(previous.Relationship, edge.Relationship) {
			changes.RemovedRelationships = append(changes.RemovedRelationships, EdgeRef{From: previous.From, To: previous.To})
			changes.AddedRelationships = append(changes.AddedRelationships, cloneEdge(edge))
		}
	}
	for key, edge := range beforeEdges {
		if _, exists := afterEdges[key]; !exists {
			changes.RemovedRelationships = append(changes.RemovedRelationships, EdgeRef{From: edge.From, To: edge.To})
		}
	}

	sort.Slice(changes.AddedAssets, func(i, j int) bool { return changes.AddedAssets[i].ID < changes.AddedAssets[j].ID })
	sort.Slice(changes.UpdatedAssets, func(i, j int) bool { return changes.UpdatedAssets[i].After.ID < changes.UpdatedAssets[j].After.ID })
	sort.Strings(changes.RemovedAssetIDs)
	sort.Slice(changes.AddedRelationships, func(i, j int) bool {
		return edgeKey(changes.AddedRelationships[i].From, changes.AddedRelationships[i].To) < edgeKey(changes.AddedRelationships[j].From, changes.AddedRelationships[j].To)
	})
	sort.Slice(changes.RemovedRelationships, func(i, j int) bool {
		return edgeKey(changes.RemovedRelationships[i].From, changes.RemovedRelationships[i].To) < edgeKey(changes.RemovedRelationships[j].From, changes.RemovedRelationships[j].To)
	})
	return changes
}
