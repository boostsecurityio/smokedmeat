// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

func (p *Pantry) VulnBearingSubgraph() *Pantry {
	if p == nil {
		return New()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	subgraph := New()
	subgraph.version = p.version

	vulnIDs := p.byType[AssetVulnerability]
	if len(vulnIDs) == 0 {
		return subgraph
	}

	childMap := make(map[string][]string, len(p.edges))
	for key := range p.edges {
		fromID, toID := parseEdgeKey(key)
		childMap[fromID] = append(childMap[fromID], toID)
	}

	selected := make(map[string]struct{}, len(vulnIDs))
	forwardRoots := make(map[string]struct{})
	backwardSeen := make(map[string]struct{}, len(vulnIDs))
	backwardQueue := make([]string, 0, len(vulnIDs))

	for vulnID := range vulnIDs {
		backwardQueue = append(backwardQueue, vulnID)
		forwardRoots[vulnID] = struct{}{}
	}

	for len(backwardQueue) > 0 {
		current := backwardQueue[0]
		backwardQueue = backwardQueue[1:]

		if _, seen := backwardSeen[current]; seen {
			continue
		}
		backwardSeen[current] = struct{}{}

		if _, ok := p.assets[current]; !ok {
			continue
		}
		selected[current] = struct{}{}

		for _, parentID := range p.reverseEdges[current] {
			if _, ok := p.assets[parentID]; !ok {
				continue
			}
			selected[parentID] = struct{}{}
			backwardQueue = append(backwardQueue, parentID)
			if p.assets[current].Type == AssetVulnerability && isVulnBearingForwardRoot(p.assets[parentID].Type) {
				forwardRoots[parentID] = struct{}{}
			}
		}
	}

	forwardSeen := make(map[string]struct{}, len(forwardRoots))
	forwardQueue := make([]string, 0, len(forwardRoots))
	for rootID := range forwardRoots {
		forwardQueue = append(forwardQueue, rootID)
	}

	for len(forwardQueue) > 0 {
		current := forwardQueue[0]
		forwardQueue = forwardQueue[1:]

		if _, seen := forwardSeen[current]; seen {
			continue
		}
		forwardSeen[current] = struct{}{}

		if _, ok := p.assets[current]; !ok {
			continue
		}
		selected[current] = struct{}{}

		for _, childID := range childMap[current] {
			if _, ok := p.assets[childID]; !ok {
				continue
			}
			selected[childID] = struct{}{}
			forwardQueue = append(forwardQueue, childID)
		}
	}

	for assetID := range selected {
		asset, ok := p.assets[assetID]
		if !ok {
			continue
		}
		_ = subgraph.AddAsset(asset)
	}

	for key, rel := range p.edges {
		fromID, toID := parseEdgeKey(key)
		if _, ok := selected[fromID]; !ok {
			continue
		}
		if _, ok := selected[toID]; !ok {
			continue
		}
		_ = subgraph.AddRelationship(fromID, toID, rel)
	}

	subgraph.version = p.version
	return subgraph
}

func isVulnBearingForwardRoot(assetType AssetType) bool {
	switch assetType {
	case AssetWorkflow, AssetJob, AssetSecret, AssetToken, AssetCloud, AssetVulnerability:
		return true
	default:
		return false
	}
}
