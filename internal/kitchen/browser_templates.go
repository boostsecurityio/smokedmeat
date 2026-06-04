// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed browser_assets/*
var browserAssetFS embed.FS

var browserTemplates = template.Must(template.ParseFS(browserAssetFS, "browser_assets/*.tmpl"))

func renderBrowserTemplate(name string, data any) (string, error) {
	var b bytes.Buffer
	if err := browserTemplates.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderGraphPage() (string, error) {
	return renderBrowserTemplate("graph.html.tmpl", nil)
}

func renderSourceViewerPage(page sourceViewerPage) (string, error) {
	return renderBrowserTemplate("source_viewer.html.tmpl", page)
}

type browserAsset struct {
	Path        string
	ContentType string
}

var browserAssetRoutes = map[string]browserAsset{
	"source-viewer.css": {Path: "browser_assets/source_viewer.css", ContentType: "text/css; charset=utf-8"},
	"source-viewer.js":  {Path: "browser_assets/source_viewer.js", ContentType: "text/javascript; charset=utf-8"},
	"graph.css":         {Path: "browser_assets/graph.css", ContentType: "text/css; charset=utf-8"},
	"graph.js":          {Path: "browser_assets/graph.js", ContentType: "text/javascript; charset=utf-8"},
}

func (h *Handler) handleBrowserAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !browserAssetAllowed(r.URL.Path, name) {
		writeBrowserSecurityHeaders(w, browserAssetCSP)
		http.NotFound(w, r)
		return
	}

	asset, ok := browserAssetRoutes[name]
	if !ok {
		writeBrowserSecurityHeaders(w, browserAssetCSP)
		http.NotFound(w, r)
		return
	}

	body, err := browserAssetFS.ReadFile(asset.Path)
	if err != nil {
		writeBrowserSecurityHeaders(w, browserAssetCSP)
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}

	writeBrowserSecurityHeaders(w, browserAssetCSP)
	w.Header().Set("Content-Type", asset.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func browserAssetAllowed(path, name string) bool {
	switch {
	case strings.HasPrefix(path, "/viewer/assets/"):
		return name == "source-viewer.css" || name == "source-viewer.js"
	case strings.HasPrefix(path, "/graph/assets/"):
		return name == "graph.css" || name == "graph.js"
	default:
		return false
	}
}
