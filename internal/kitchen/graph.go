// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"encoding/json"
	"net/http"
)

type graphData struct {
	Mode              string      `json:"mode"`
	LargeGraph        bool        `json:"large_graph"`
	TotalNodes        int         `json:"total_nodes"`
	TotalEdges        int         `json:"total_edges"`
	FilterDescription string      `json:"filter_description,omitempty"`
	Nodes             []GraphNode `json:"nodes"`
	Links             []GraphEdge `json:"links"`
}

func (h *Handler) handleGraph(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(graphCytoscapeHTML))
}

func (h *Handler) handleGraphData(w http.ResponseWriter, r *http.Request) {
	p := h.Pantry()
	snapshot := buildGraphSnapshot(p, p.Version(), r.URL.Query().Get("mode"))
	data := graphData{
		Mode:              snapshot.Mode,
		LargeGraph:        snapshot.LargeGraph,
		TotalNodes:        snapshot.TotalNodes,
		TotalEdges:        snapshot.TotalEdges,
		FilterDescription: snapshot.FilterDescription,
		Nodes:             snapshot.Nodes,
		Links:             snapshot.Edges,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}
