// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

const (
	graphModeAuto     = "auto"
	graphModeFiltered = "filtered"
	graphModeFull     = "full"

	graphLargeNodeThreshold = 1000
	graphLargeEdgeThreshold = 1200
)

// GraphMessage is the envelope for all graph WebSocket messages.
type GraphMessage struct {
	Type string `json:"type"` // "snapshot", "delta", "ping", "pong"
	Data any    `json:"data,omitempty"`
}

// GraphSnapshot is the initial full graph state sent on connect.
type GraphSnapshot struct {
	Version           int64       `json:"version"`
	Mode              string      `json:"mode"`
	LargeGraph        bool        `json:"large_graph"`
	TotalNodes        int         `json:"total_nodes"`
	TotalEdges        int         `json:"total_edges"`
	FilterDescription string      `json:"filter_description,omitempty"`
	Nodes             []GraphNode `json:"nodes"`
	Edges             []GraphEdge `json:"edges"`
}

// GraphDelta contains incremental changes to the graph.
type GraphDelta struct {
	Version      int64        `json:"version"`
	AddedNodes   []GraphNode  `json:"added_nodes,omitempty"`
	UpdatedNodes []NodeUpdate `json:"updated_nodes,omitempty"`
	AddedEdges   []GraphEdge  `json:"added_edges,omitempty"`
	RemovedNodes []string     `json:"removed_nodes,omitempty"`
	RemovedEdges []EdgeRef    `json:"removed_edges,omitempty"`
}

// EdgeRef identifies an edge by its source and target.
type EdgeRef struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// GraphNode represents a node in the graph visualization.
type GraphNode struct {
	ID                string            `json:"id"`
	Type              string            `json:"type"`
	Label             string            `json:"label"`
	State             string            `json:"state"`
	Properties        map[string]any    `json:"properties,omitempty"`
	TooltipProperties map[string]string `json:"tooltip_properties,omitempty"`
}

// NodeUpdate represents a change to an existing node (state, properties, or label).
type NodeUpdate struct {
	ID                string            `json:"id"`
	OldState          string            `json:"old_state"`
	NewState          string            `json:"new_state"`
	Label             string            `json:"label,omitempty"`
	Properties        map[string]any    `json:"properties,omitempty"`
	TooltipProperties map[string]string `json:"tooltip_properties,omitempty"`
}

// GraphEdge represents an edge in the graph visualization.
type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	Label  string `json:"label,omitempty"`
}

type graphSelection struct {
	mode              string
	largeGraph        bool
	totalNodes        int
	totalEdges        int
	filterDescription string
	nodes             []GraphNode
	edges             []GraphEdge
}

func normalizeGraphMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case graphModeFiltered:
		return graphModeFiltered
	case graphModeFull:
		return graphModeFull
	default:
		return graphModeAuto
	}
}

func graphModeFromData(data any, fallback string) string {
	switch typed := data.(type) {
	case string:
		return normalizeGraphMode(typed)
	case map[string]any:
		if mode, ok := typed["mode"].(string); ok {
			return normalizeGraphMode(mode)
		}
	}
	return normalizeGraphMode(fallback)
}

func buildGraphSelection(p *pantry.Pantry, requestedMode string) graphSelection {
	mode := normalizeGraphMode(requestedMode)
	if p == nil {
		return graphSelection{mode: graphModeFull}
	}

	totalNodes := p.Size()
	totalEdges := p.EdgeCount()
	largeGraph := totalNodes >= graphLargeNodeThreshold || totalEdges >= graphLargeEdgeThreshold

	resolvedMode := graphModeFull
	switch mode {
	case graphModeFiltered:
		resolvedMode = graphModeFiltered
	case graphModeAuto:
		if largeGraph {
			resolvedMode = graphModeFiltered
		}
	}

	source := p
	filterDescription := ""
	if resolvedMode == graphModeFiltered {
		filtered := p.VulnBearingSubgraph()
		if filtered.Size() > 0 {
			source = filtered
		} else {
			resolvedMode = graphModeFull
			switch mode {
			case graphModeFiltered:
				filterDescription = "No vuln-bearing paths found. Showing full graph."
			case graphModeAuto:
				if largeGraph {
					filterDescription = "Large graph detected. Showing full graph because no vuln-bearing paths are available."
				}
			}
		}
	}

	if filterDescription == "" && resolvedMode == graphModeFiltered {
		if mode == graphModeAuto && largeGraph {
			filterDescription = "Large graph detected. Showing vuln-bearing paths only."
		} else {
			filterDescription = "Showing vuln-bearing paths only."
		}
	}

	assets := source.AllAssets()
	relationships := source.AllRelationships()

	nodes := make([]GraphNode, 0, len(assets))
	for _, asset := range assets {
		nodes = append(nodes, AssetToGraphNode(asset))
	}

	edges := make([]GraphEdge, 0, len(relationships))
	for _, edge := range relationships {
		edges = append(edges, EdgeToGraphEdge(edge))
	}

	return graphSelection{
		mode:              resolvedMode,
		largeGraph:        largeGraph,
		totalNodes:        totalNodes,
		totalEdges:        totalEdges,
		filterDescription: filterDescription,
		nodes:             nodes,
		edges:             edges,
	}
}

func buildGraphSnapshot(p *pantry.Pantry, version int64, requestedMode string) GraphSnapshot {
	selection := buildGraphSelection(p, requestedMode)
	return GraphSnapshot{
		Version:           version,
		Mode:              selection.mode,
		LargeGraph:        selection.largeGraph,
		TotalNodes:        selection.totalNodes,
		TotalEdges:        selection.totalEdges,
		FilterDescription: selection.filterDescription,
		Nodes:             selection.nodes,
		Edges:             selection.edges,
	}
}

// AssetToGraphNode converts a pantry Asset to a GraphNode.
func AssetToGraphNode(asset pantry.Asset) GraphNode {
	label := asset.Name
	if asset.Type == pantry.AssetJob {
		if displayName, ok := asset.Properties["display_name"].(string); ok && displayName != "" {
			label = asset.Name + " (" + displayName + ")"
		}
	}
	if asset.Type == pantry.AssetRepository {
		if private, ok := asset.Properties["private"].(bool); ok && private {
			label = "🔒 " + label
		}
		if sshAccess, ok := asset.Properties["ssh_access"].(string); ok {
			switch sshAccess {
			case "write":
				label += " [ssh:w]"
			case "read":
				label += " [ssh:r]"
			}
		}
	}
	return GraphNode{
		ID:                asset.ID,
		Type:              string(asset.Type),
		Label:             label,
		State:             string(asset.State),
		Properties:        asset.Properties,
		TooltipProperties: formatTooltipProperties(asset.Properties),
	}
}

func formatTooltipProperties(props map[string]any) map[string]string {
	if len(props) == 0 {
		return nil
	}

	formatted := make(map[string]string, len(props))
	for key, value := range props {
		if isOmittableTooltipValue(normalizeTooltipValue(value)) {
			continue
		}
		formatted[key] = formatTooltipValue(value)
	}
	if len(formatted) == 0 {
		return nil
	}
	return formatted
}

func formatTooltipValue(value any) string {
	normalized := normalizeTooltipValue(value)
	return renderTooltipValue(normalized, 0)
}

func normalizeTooltipValue(value any) any {
	if value == nil {
		return nil
	}

	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}

	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return value
	}
	return normalized
}

func renderTooltipValue(value any, depth int) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		return normalizeTooltipText(v)
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if v == math.Trunc(v) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		items := make([]any, 0, len(v))
		for _, item := range v {
			if isOmittableTooltipValue(item) {
				continue
			}
			items = append(items, item)
		}
		if len(items) == 0 {
			return "[]"
		}
		if depth >= 2 {
			return fmt.Sprintf("[%d items]", len(items))
		}

		limit := len(items)
		if limit > 4 {
			limit = 4
		}
		parts := make([]string, 0, limit+1)
		for i := 0; i < limit; i++ {
			parts = append(parts, renderTooltipValue(items[i], depth+1))
		}
		if len(items) > limit {
			parts = append(parts, fmt.Sprintf("... +%d more", len(items)-limit))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key, item := range v {
			if isOmittableTooltipValue(item) {
				continue
			}
			keys = append(keys, key)
		}
		if len(keys) == 0 {
			return "{}"
		}
		if depth >= 2 {
			return fmt.Sprintf("{%d fields}", len(keys))
		}

		sort.Strings(keys)

		limit := len(keys)
		if limit > 6 {
			limit = 6
		}
		parts := make([]string, 0, limit+1)
		for i := 0; i < limit; i++ {
			key := keys[i]
			parts = append(parts, fmt.Sprintf("%s: %s", key, renderTooltipValue(v[key], depth+1)))
		}
		if len(keys) > limit {
			parts = append(parts, fmt.Sprintf("... +%d more", len(keys)-limit))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return normalizeTooltipText(fmt.Sprint(v))
	}
}

func normalizeTooltipText(text string) string {
	text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if len(text) <= 160 {
		return text
	}
	return text[:157] + "..."
}

func isOmittableTooltipValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		for _, item := range v {
			if !isOmittableTooltipValue(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, item := range v {
			if !isOmittableTooltipValue(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// EdgeToGraphEdge converts a pantry Edge to a GraphEdge.
func EdgeToGraphEdge(edge pantry.Edge) GraphEdge {
	return GraphEdge{
		Source: edge.From,
		Target: edge.To,
		Type:   string(edge.Relationship.Type),
	}
}
