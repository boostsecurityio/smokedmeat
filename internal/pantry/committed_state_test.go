// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memorySnapshotStore struct {
	mu      sync.Mutex
	data    []byte
	err     error
	before  func()
	writes  int
	started chan struct{}
	release chan struct{}
}

func (s *memorySnapshotStore) Replace(serialized []byte) error {
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		<-s.release
	}
	if s.before != nil {
		s.before()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.data = append([]byte(nil), serialized...)
	s.writes++
	return nil
}

func (s *memorySnapshotStore) snapshot(t *testing.T) Snapshot {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var snapshot Snapshot
	require.NoError(t, json.Unmarshal(s.data, &snapshot))
	return snapshot
}

func (s *memorySnapshotStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

type recordingObserver struct {
	mu      sync.Mutex
	changes []ChangeSet
}

type observerFunc func(ChangeSet)

func (f observerFunc) OnPantryChange(change ChangeSet) {
	f(change)
}

type countingJSONValue struct {
	calls *atomic.Int32
}

func (v countingJSONValue) MarshalJSON() ([]byte, error) {
	v.calls.Add(1)
	return []byte(`"counted"`), nil
}

func (o *recordingObserver) OnPantryChange(change ChangeSet) {
	o.mu.Lock()
	o.changes = append(o.changes, change)
	o.mu.Unlock()
}

func (o *recordingObserver) all() []ChangeSet {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]ChangeSet(nil), o.changes...)
}

func TestCommittedStateUpdatePersistsBeforeOneGranularPublication(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)
	pointer := live

	err := state.Update(context.Background(), func(candidate *Pantry) error {
		repo := NewRepository("acme", "api", "github")
		workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
		require.NoError(t, candidate.AddAsset(repo))
		require.NoError(t, candidate.AddAsset(workflow))
		return candidate.AddRelationship(repo.ID, workflow.ID, Contains())
	})
	require.NoError(t, err)

	assert.Same(t, pointer, live)
	assert.Equal(t, uint64(1), live.Revision())
	assert.Equal(t, uint64(1), store.snapshot(t).Revision)
	changes := observer.all()
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeGranular, changes[0].Kind)
	assert.Equal(t, uint64(0), changes[0].BaseRevision)
	assert.Equal(t, uint64(1), changes[0].Revision)
	assert.Len(t, changes[0].Granular.AddedAssets, 2)
	assert.Len(t, changes[0].Granular.AddedRelationships, 1)
}

func TestCommittedStateIsolatesObserverChangeSets(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	live.AddObserver(observerFunc(func(change ChangeSet) {
		change.Granular.AddedAssets[0].ID = "mutated"
		change.Granular.AddedAssets[0].Properties["nested"].(map[string]any)["value"] = "mutated"
		change.Granular.AddedRelationships[0].Relationship.Properties["nested"].(map[string]any)["value"] = "mutated"
	}))
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)

	repo := NewRepository("acme", "api", "github")
	repo.Properties["nested"] = map[string]any{"value": "original"}
	workflow := NewWorkflow(repo.ID, ".github/workflows/ci.yml")
	relationship := Contains().WithProperty("nested", map[string]any{"value": "original"})
	require.NoError(t, state.Update(context.Background(), func(candidate *Pantry) error {
		require.NoError(t, candidate.AddAsset(repo))
		require.NoError(t, candidate.AddAsset(workflow))
		return candidate.AddRelationship(repo.ID, workflow.ID, relationship)
	}))

	changes := observer.all()
	require.Len(t, changes, 1)
	require.Len(t, changes[0].Granular.AddedAssets, 2)
	assert.Equal(t, repo.ID, changes[0].Granular.AddedAssets[0].ID)
	assert.Equal(t, "original", changes[0].Granular.AddedAssets[0].Properties["nested"].(map[string]any)["value"])
	require.Len(t, changes[0].Granular.AddedRelationships, 1)
	assert.Equal(t, "original", changes[0].Granular.AddedRelationships[0].Relationship.Properties["nested"].(map[string]any)["value"])
}

func TestCommittedStateReplacePublishesOnlyCommittedStateMarker(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)

	require.NoError(t, state.Replace(context.Background(), func(candidate *Pantry) error {
		return candidate.AddAsset(NewOrganization("acme", "github"))
	}))

	changes := observer.all()
	require.Len(t, changes, 1)
	assert.Equal(t, ChangeCommittedState, changes[0].Kind)
	assert.Equal(t, 0, changes[0].Granular.count())
}

func TestCommittedStateNoOpDoesNotPersistAdvanceOrPublish(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)

	require.NoError(t, state.Update(context.Background(), func(*Pantry) error { return nil }))

	assert.Zero(t, live.Revision())
	assert.Zero(t, store.writeCount())
	assert.Empty(t, observer.all())
}

func TestCommittedStateSerializesChangedCandidateOnce(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	state := NewCommittedState(live, store)
	var calls atomic.Int32

	require.NoError(t, state.Update(context.Background(), func(candidate *Pantry) error {
		asset := NewOrganization("acme", "github")
		asset.SetProperty("counted", countingJSONValue{calls: &calls})
		return candidate.AddAsset(asset)
	}))

	assert.Equal(t, int32(1), calls.Load())
}

func TestCommittedStateRejectsRevisionOverflowBeforePersistence(t *testing.T) {
	live := New()
	live.revision = ^uint64(0)
	store := &memorySnapshotStore{}
	state := NewCommittedState(live, store)

	err := state.Update(context.Background(), func(candidate *Pantry) error {
		return candidate.AddAsset(NewOrganization("acme", "github"))
	})

	require.ErrorContains(t, err, "revision exhausted")
	assert.Equal(t, ^uint64(0), live.Revision())
	assert.Zero(t, store.writeCount())
}

func TestCommittedStateFailuresLeavePriorStateAuthoritative(t *testing.T) {
	tests := []struct {
		name   string
		store  *memorySnapshotStore
		change func(context.Context, context.CancelFunc, *Pantry) error
		want   error
	}{
		{
			name:  "callback",
			store: &memorySnapshotStore{},
			change: func(_ context.Context, _ context.CancelFunc, candidate *Pantry) error {
				require.NoError(t, candidate.AddAsset(NewOrganization("acme", "github")))
				return errors.New("callback failed")
			},
			want: errors.New("callback failed"),
		},
		{
			name:  "serialization",
			store: &memorySnapshotStore{},
			change: func(_ context.Context, _ context.CancelFunc, candidate *Pantry) error {
				asset := NewOrganization("acme", "github")
				asset.SetProperty("invalid", make(chan int))
				return candidate.AddAsset(asset)
			},
		},
		{
			name:  "persistence",
			store: &memorySnapshotStore{err: errors.New("disk full")},
			change: func(_ context.Context, _ context.CancelFunc, candidate *Pantry) error {
				return candidate.AddAsset(NewOrganization("acme", "github"))
			},
			want: errors.New("disk full"),
		},
		{
			name:  "cancellation",
			store: &memorySnapshotStore{},
			change: func(_ context.Context, cancel context.CancelFunc, candidate *Pantry) error {
				require.NoError(t, candidate.AddAsset(NewOrganization("acme", "github")))
				cancel()
				return nil
			},
			want: context.Canceled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			live := New()
			observer := &recordingObserver{}
			live.AddObserver(observer)
			state := NewCommittedState(live, test.store)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err := state.Update(ctx, func(candidate *Pantry) error {
				return test.change(ctx, cancel, candidate)
			})
			require.Error(t, err)
			if test.want != nil {
				assert.Contains(t, err.Error(), test.want.Error())
			}
			assert.Zero(t, live.Revision())
			assert.Zero(t, live.Size())
			assert.Zero(t, test.store.writeCount())
			assert.Empty(t, observer.all())
		})
	}
}

func TestCommittedStateIgnoresCancellationAfterPersistence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &memorySnapshotStore{before: cancel}
	live := New()
	state := NewCommittedState(live, store)

	err := state.Update(ctx, func(candidate *Pantry) error {
		return candidate.AddAsset(NewOrganization("acme", "github"))
	})

	require.NoError(t, err)
	assert.Equal(t, uint64(1), live.Revision())
	assert.True(t, live.HasAsset("github:org:acme"))
}

func TestCommittedStateReadersSeeOldStateUntilPersistenceCompletes(t *testing.T) {
	store := &memorySnapshotStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	live := New()
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)
	done := make(chan error, 1)

	go func() {
		done <- state.Update(context.Background(), func(candidate *Pantry) error {
			return candidate.AddAsset(NewOrganization("acme", "github"))
		})
	}()

	<-store.started
	assert.Zero(t, live.Revision())
	assert.False(t, live.HasAsset("github:org:acme"))
	assert.Empty(t, observer.all())
	close(store.release)
	require.NoError(t, <-done)
	assert.Equal(t, uint64(1), live.Revision())
	assert.True(t, live.HasAsset("github:org:acme"))
	assert.Len(t, observer.all(), 1)
}

func TestCommittedStateSerializesWritersAgainstLatestRevision(t *testing.T) {
	store := &memorySnapshotStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	live := New()
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)

	go func() {
		firstDone <- state.Update(context.Background(), func(candidate *Pantry) error {
			return candidate.AddAsset(NewOrganization("acme", "github"))
		})
	}()
	<-store.started
	go func() {
		secondDone <- state.Update(context.Background(), func(candidate *Pantry) error {
			return candidate.AddAsset(NewOrganization("globex", "github"))
		})
	}()
	close(store.release)

	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
	assert.Equal(t, uint64(2), live.Revision())
	assert.True(t, live.HasAsset("github:org:acme"))
	assert.True(t, live.HasAsset("github:org:globex"))
	changes := observer.all()
	require.Len(t, changes, 2)
	assert.Equal(t, uint64(1), changes[0].Revision)
	assert.Equal(t, uint64(1), changes[1].BaseRevision)
	assert.Equal(t, uint64(2), changes[1].Revision)
}

func TestCommittedStateInstancesShareContextAwareWriterGate(t *testing.T) {
	store := &memorySnapshotStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	live := New()
	first := NewCommittedState(live, store)
	second := NewCommittedState(live, store)
	firstDone := make(chan error, 1)

	go func() {
		firstDone <- first.Update(context.Background(), func(candidate *Pantry) error {
			return candidate.AddAsset(NewOrganization("acme", "github"))
		})
	}()
	<-store.started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := second.Update(ctx, func(candidate *Pantry) error {
		return candidate.AddAsset(NewOrganization("globex", "github"))
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, live.HasAsset("github:org:globex"))
	close(store.release)
	require.NoError(t, <-firstDone)
}

func TestCommittedStateDetachesRetainedCandidateAfterCommit(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	observer := &recordingObserver{}
	live.AddObserver(observer)
	state := NewCommittedState(live, store)
	var retained *Pantry

	require.NoError(t, state.Update(context.Background(), func(candidate *Pantry) error {
		retained = candidate
		return candidate.AddAsset(NewOrganization("acme", "github"))
	}))
	require.NoError(t, retained.AddAsset(NewOrganization("globex", "github")))

	assert.False(t, live.HasAsset("github:org:globex"))
	assert.Len(t, observer.all(), 1)
}

func TestPantryDefensivelyCopiesProperties(t *testing.T) {
	type nestedProperty struct {
		Values []string
	}
	p := New()
	labels := []string{"self-hosted", "linux"}
	nested := nestedProperty{Values: []string{"one", "two"}}
	asset := NewOrganization("acme", "github")
	asset.SetProperty("labels", labels)
	asset.SetProperty("nested", nested)
	require.NoError(t, p.AddAsset(asset))

	labels[0] = "mutated"
	nested.Values[0] = "mutated"
	asset.Properties["org"] = "mutated"
	stored, err := p.GetAsset(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"self-hosted", "linux"}, stored.Properties["labels"])
	assert.Equal(t, []string{"one", "two"}, stored.Properties["nested"].(nestedProperty).Values)
	assert.Equal(t, "acme", stored.Properties["org"])

	stored.Properties["org"] = "changed through read"
	again, err := p.GetAsset(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "acme", again.Properties["org"])
}

func TestPantrySnapshotRoundTripPreservesRevision(t *testing.T) {
	live := New()
	store := &memorySnapshotStore{}
	state := NewCommittedState(live, store)
	require.NoError(t, state.Update(context.Background(), func(candidate *Pantry) error {
		return candidate.AddAsset(NewOrganization("acme", "github"))
	}))

	serialized, err := json.Marshal(live)
	require.NoError(t, err)
	restored := New()
	require.NoError(t, json.Unmarshal(serialized, restored))

	assert.Equal(t, uint64(1), restored.Revision())
	assert.True(t, restored.HasAsset("github:org:acme"))
}

func TestCommittedStateLargeGraphReplacement(t *testing.T) {
	if testing.Short() {
		t.Skip("large graph performance check")
	}
	live := largeTestPantry(t, 2_000)
	store := &memorySnapshotStore{}
	state := NewCommittedState(live, store)
	started := time.Now()

	require.NoError(t, state.Replace(context.Background(), func(candidate *Pantry) error {
		asset, err := candidate.GetAsset("github:acme/repo-1999")
		if err != nil {
			return err
		}
		asset.State = StateValidated
		return candidate.AddAsset(asset)
	}))

	t.Logf("committed 2,000 assets and 1,999 relationships in %s", time.Since(started))
	assert.Equal(t, uint64(1), live.Revision())
	assert.Equal(t, 2_000, live.Size())
}

func BenchmarkCommittedStateReplaceLargeGraph(b *testing.B) {
	for _, size := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("assets-%d", size), func(b *testing.B) {
			for range b.N {
				live := largeTestPantry(b, size)
				state := NewCommittedState(live, &memorySnapshotStore{})
				require.NoError(b, state.Replace(context.Background(), func(candidate *Pantry) error {
					asset, err := candidate.GetAsset(fmt.Sprintf("github:acme/repo-%d", size-1))
					if err != nil {
						return err
					}
					asset.State = StateValidated
					return candidate.AddAsset(asset)
				}))
			}
		})
	}
}

func largeTestPantry(tb testing.TB, size int) *Pantry {
	tb.Helper()
	p := New()
	for index := 0; index < size; index++ {
		repo := NewRepository("acme", fmt.Sprintf("repo-%d", index), "github")
		require.NoError(tb, p.AddAsset(repo))
		if index > 0 {
			require.NoError(tb, p.AddRelationship(
				fmt.Sprintf("github:acme/repo-%d", index-1),
				repo.ID,
				LeadsTo("synthetic"),
			))
		}
	}
	return p
}
