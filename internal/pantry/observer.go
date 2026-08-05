// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

// AddObserver registers an observer to receive change notifications.
func (p *Pantry) AddObserver(obs Observer) {
	p.obsMu.Lock()
	defer p.obsMu.Unlock()
	p.observers = append(p.observers, obs)
}

// RemoveObserver unregisters an observer.
func (p *Pantry) RemoveObserver(obs Observer) {
	p.obsMu.Lock()
	defer p.obsMu.Unlock()
	for i, o := range p.observers {
		if o == obs {
			p.observers = append(p.observers[:i], p.observers[i+1:]...)
			return
		}
	}
}

func (p *Pantry) notifyChange(change ChangeSet) {
	p.obsMu.RLock()
	observers := make([]Observer, len(p.observers))
	copy(observers, p.observers)
	p.obsMu.RUnlock()

	for _, obs := range observers {
		obs.OnPantryChange(cloneChangeSet(change))
	}
}

func cloneChangeSet(change ChangeSet) ChangeSet {
	cloned := change
	cloned.Granular.AddedAssets = make([]Asset, len(change.Granular.AddedAssets))
	for index, asset := range change.Granular.AddedAssets {
		cloned.Granular.AddedAssets[index] = cloneAsset(asset)
	}
	cloned.Granular.UpdatedAssets = make([]AssetChange, len(change.Granular.UpdatedAssets))
	for index, update := range change.Granular.UpdatedAssets {
		cloned.Granular.UpdatedAssets[index] = AssetChange{
			Before: cloneAsset(update.Before),
			After:  cloneAsset(update.After),
		}
	}
	cloned.Granular.RemovedAssetIDs = append([]string(nil), change.Granular.RemovedAssetIDs...)
	cloned.Granular.AddedRelationships = make([]Edge, len(change.Granular.AddedRelationships))
	for index, edge := range change.Granular.AddedRelationships {
		cloned.Granular.AddedRelationships[index] = cloneEdge(edge)
	}
	cloned.Granular.RemovedRelationships = append([]EdgeRef(nil), change.Granular.RemovedRelationships...)
	return cloned
}
