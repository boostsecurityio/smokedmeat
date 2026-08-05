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
		obs.OnPantryChange(change)
	}
}
