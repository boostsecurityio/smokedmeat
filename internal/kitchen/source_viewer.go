// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"

	"github.com/boostsecurityio/smokedmeat/internal/kitchen/auth"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

const (
	sourceViewerMaxBytes          = 1024 * 1024
	sourceTokenTTL                = 2 * time.Hour
	sourceCacheTTL                = 5 * time.Minute
	sourceViewerMaxPathCandidates = 8
)

const (
	browserSessionCookieMaxAge = 8 * time.Hour
	sourceSessionCookie        = "smokedmeat_source_session"
	browserAssetCSP            = "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
	sourceViewerCSP            = "default-src 'none'; style-src 'self'; img-src 'self' data: https:; script-src 'none'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
	graphViewerCSP             = "default-src 'none'; script-src 'self' https://unpkg.com; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)

var (
	sourceMarkdown       = goldmark.New(goldmark.WithExtensions(extension.GFM))
	sourceMarkdownPolicy = bluemonday.UGCPolicy()
)

type SourceTokenRequest struct {
	Token     string `json:"token"`
	Source    string `json:"source,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

type SourceTokenResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type SourceContentRequest struct {
	Token     string `json:"token,omitempty"`
	Host      string `json:"host,omitempty"`
	Owner     string `json:"owner"`
	Repo      string `json:"repo"`
	Ref       string `json:"ref,omitempty"`
	Path      string `json:"path"`
	Line      int    `json:"line,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

type SourceContentResponse struct {
	Host       string    `json:"host"`
	Repository string    `json:"repository"`
	Owner      string    `json:"owner"`
	Repo       string    `json:"repo"`
	Ref        string    `json:"ref"`
	Path       string    `json:"path"`
	SHA        string    `json:"sha,omitempty"`
	HTMLURL    string    `json:"html_url,omitempty"`
	Content    string    `json:"content"`
	Size       int       `json:"size"`
	FetchedAt  time.Time `json:"fetched_at"`
	CacheHit   bool      `json:"cache_hit"`
}

type sourceDirectoryResponse struct {
	Host          string
	Repository    string
	Owner         string
	Repo          string
	Ref           string
	Path          string
	HTMLURL       string
	Description   string
	DefaultBranch string
	Entries       []sourceDirectoryEntry
	Readme        *SourceContentResponse
}

type sourceDirectoryEntry struct {
	Name    string
	Path    string
	Type    string
	SHA     string
	HTMLURL string
	Size    int
}

type sourceOwnerResponse struct {
	Owner   string
	HTMLURL string
	Repos   []sourceOwnerRepository
}

type sourceOwnerRepository struct {
	Name          string
	FullName      string
	Description   string
	Private       bool
	DefaultBranch string
	HTMLURL       string
}

type sourceGraphRootResponse struct {
	Owners []sourceGraphOwner
}

type sourceGraphOwner struct {
	Name      string
	RepoCount int
}

type sourceCacheEntry struct {
	Host       string    `json:"host"`
	Repository string    `json:"repository"`
	Owner      string    `json:"owner"`
	Repo       string    `json:"repo"`
	Ref        string    `json:"ref"`
	Path       string    `json:"path"`
	SHA        string    `json:"sha,omitempty"`
	HTMLURL    string    `json:"html_url,omitempty"`
	Content    string    `json:"content"`
	Size       int       `json:"size"`
	FetchedAt  time.Time `json:"fetched_at"`
}

type sourceCache struct {
	mu      sync.RWMutex
	entries map[string]sourceCacheEntry
	dir     string
}

type sourceTokenEntry struct {
	Token     string
	Source    string
	ExpiresAt time.Time
}

type sourceTokenCache struct {
	mu      sync.Mutex
	entries map[string]sourceTokenEntry
}

func newMemorySourceCache() *sourceCache {
	return &sourceCache{entries: make(map[string]sourceCacheEntry)}
}

func newDiskSourceCache(dir string) *sourceCache {
	return &sourceCache{entries: make(map[string]sourceCacheEntry), dir: dir}
}

func newSourceTokenCache() *sourceTokenCache {
	return &sourceTokenCache{entries: make(map[string]sourceTokenEntry)}
}

func sourceCacheDirForDBPath(dbPath string) string {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" || dbPath == ":memory:" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), "source-cache")
}

func (h *Handler) SetSourceCacheDir(dir string) {
	if strings.TrimSpace(dir) == "" {
		h.sourceCache = newMemorySourceCache()
		return
	}
	h.sourceCache = newDiskSourceCache(dir)
}

func (c *sourceCache) get(key string, now time.Time) (sourceCacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		if sourceCacheEntryFresh(entry, now) {
			return entry, true
		}
		c.delete(key)
		return sourceCacheEntry{}, false
	}
	if c.dir == "" {
		return sourceCacheEntry{}, false
	}

	path := filepath.Join(c.dir, key+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return sourceCacheEntry{}, false
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return sourceCacheEntry{}, false
	}
	if !sourceCacheEntryFresh(entry, now) {
		_ = os.Remove(path)
		return sourceCacheEntry{}, false
	}

	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
	return entry, true
}

func (c *sourceCache) delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	if c.dir != "" {
		_ = os.Remove(filepath.Join(c.dir, key+".json"))
	}
}

func sourceCacheEntryFresh(entry sourceCacheEntry, now time.Time) bool {
	return !entry.FetchedAt.IsZero() && !now.After(entry.FetchedAt.Add(sourceCacheTTL))
}

func (c *sourceCache) put(key string, entry sourceCacheEntry) error {
	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
	if c.dir == "" {
		return nil
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return writeSourceCacheFile(filepath.Join(c.dir, key+".json"), data)
}

func writeSourceCacheFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	remove = false
	return nil
}

func (c *sourceTokenCache) put(keys []string, token, source string, now time.Time) time.Time {
	expiresAt := now.Add(sourceTokenTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		if key == "" {
			continue
		}
		c.entries[key] = sourceTokenEntry{Token: token, Source: source, ExpiresAt: expiresAt}
	}
	return expiresAt
}

func (c *sourceTokenCache) get(keys []string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		if key == "" {
			continue
		}
		entry, ok := c.entries[key]
		if !ok {
			continue
		}
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			continue
		}
		return entry.Token, true
	}
	return "", false
}

func (h *Handler) handleGitHubSourceToken(w http.ResponseWriter, r *http.Request) {
	var req SourceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSourceJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer r.Body.Close()

	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		writeSourceJSONError(w, http.StatusBadRequest, "token is required")
		return
	}

	now := time.Now().UTC()
	expiresAt := h.sourceTokens.put(sourceTokenKeys(r, req.SessionID), req.Token, req.Source, now)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SourceTokenResponse{ExpiresAt: expiresAt})
}

func (h *Handler) handleGitHubSourceContent(w http.ResponseWriter, r *http.Request) {
	var req SourceContentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSourceJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		if token, ok := h.sourceTokens.get(sourceTokenKeys(r, req.SessionID), time.Now().UTC()); ok {
			req.Token = token
		}
	}

	resp, err := h.getSourceContent(r.Context(), req)
	if err != nil {
		writeSourceJSONError(w, sourceHTTPStatus(err), err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleBrowserSession(w http.ResponseWriter, r *http.Request) {
	writeSourceSecurityHeaders(w)
	next, err := sanitizeBrowserSessionNext(r.URL.Query().Get("next"))
	if err != nil {
		http.Error(w, "invalid redirect target", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	setBrowserCookie(w, r, auth.OperatorTokenCookie, token, "/viewer")
	setBrowserCookie(w, r, auth.OperatorTokenCookie, token, "/graph")
	if sessionID := strings.TrimSpace(r.URL.Query().Get("session_id")); sessionID != "" {
		setBrowserCookie(w, r, sourceSessionCookie, sessionID, "/viewer")
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *Handler) handleSourceViewerSession(w http.ResponseWriter, r *http.Request) {
	h.handleBrowserSession(w, r)
}

func (h *Handler) handleSourceGraphRootViewer(w http.ResponseWriter, r *http.Request) {
	resp := h.sourceGraphRoot()
	h.writeSourceGraphRootPage(w, resp, sourceViewerQueryForLinks(r.URL.Query(), true))
}

func (h *Handler) handleSourceViewer(w http.ResponseWriter, r *http.Request) {
	req := SourceContentRequest{
		Host:      "github.com",
		Owner:     r.PathValue("owner"),
		Repo:      r.PathValue("repo"),
		Ref:       r.PathValue("ref"),
		Path:      r.PathValue("path"),
		SessionID: sourceViewerSessionID(r),
	}
	if line := strings.TrimSpace(r.URL.Query().Get("line")); line != "" {
		req.Line, _ = strconv.Atoi(line)
	}
	if token, ok := h.sourceTokens.get(sourceTokenKeys(r, req.SessionID), time.Now().UTC()); ok {
		req.Token = token
	}

	linkQuery := sourceViewerQueryForLinks(r.URL.Query(), false)
	resp, err := h.getSourceViewerContent(r.Context(), req)
	if err != nil {
		if sourceRequestErrorIs(err, "source viewer only supports files") {
			dirResp, dirErr := h.getSourceViewerDirectory(r.Context(), req)
			if dirErr == nil {
				h.writeSourceDirectoryPage(w, dirResp, linkQuery)
				return
			}
		}
		h.writeSourceViewerError(w, req, sourceHTTPStatus(err), err)
		return
	}
	h.writeSourceViewerPage(w, resp, req.Line, linkQuery)
}

func (h *Handler) handleSourceOwnerViewer(w http.ResponseWriter, r *http.Request) {
	req := SourceContentRequest{
		Host:      "github.com",
		Owner:     r.PathValue("owner"),
		SessionID: sourceViewerSessionID(r),
	}
	if token, ok := h.sourceTokens.get(sourceTokenKeys(r, req.SessionID), time.Now().UTC()); ok {
		req.Token = token
	}

	resp, err := h.getSourceOwner(r.Context(), req)
	if err != nil {
		h.writeSourceViewerError(w, req, sourceHTTPStatus(err), err)
		return
	}
	h.writeSourceOwnerPage(w, resp, sourceViewerQueryForLinks(r.URL.Query(), true))
}

func (h *Handler) handleSourceRepositoryViewer(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	req := SourceContentRequest{
		Host:      "github.com",
		Owner:     r.PathValue("owner"),
		Repo:      r.PathValue("repo"),
		Ref:       ref,
		SessionID: sourceViewerSessionID(r),
	}
	if token, ok := h.sourceTokens.get(sourceTokenKeys(r, req.SessionID), time.Now().UTC()); ok {
		req.Token = token
	}

	resp, err := h.getSourceDirectory(r.Context(), req)
	if err != nil {
		h.writeSourceViewerError(w, req, sourceHTTPStatus(err), err)
		return
	}
	h.writeSourceDirectoryPage(w, resp, sourceViewerQueryForLinks(r.URL.Query(), ref == ""))
}

func (h *Handler) handleSourceTreeViewer(w http.ResponseWriter, r *http.Request) {
	req := SourceContentRequest{
		Host:      "github.com",
		Owner:     r.PathValue("owner"),
		Repo:      r.PathValue("repo"),
		Ref:       r.PathValue("ref"),
		Path:      r.PathValue("path"),
		SessionID: sourceViewerSessionID(r),
	}
	if token, ok := h.sourceTokens.get(sourceTokenKeys(r, req.SessionID), time.Now().UTC()); ok {
		req.Token = token
	}

	resp, err := h.getSourceViewerDirectory(r.Context(), req)
	if err != nil {
		if sourceRequestErrorIs(err, "source viewer only supports directories") {
			fileResp, fileErr := h.getSourceViewerContent(r.Context(), req)
			if fileErr == nil {
				h.writeSourceViewerPage(w, fileResp, req.Line, sourceViewerQueryForLinks(r.URL.Query(), false))
				return
			}
		}
		h.writeSourceViewerError(w, req, sourceHTTPStatus(err), err)
		return
	}
	h.writeSourceDirectoryPage(w, resp, sourceViewerQueryForLinks(r.URL.Query(), false))
}

func (h *Handler) getSourceContent(ctx context.Context, req SourceContentRequest) (SourceContentResponse, error) {
	req.Host = normalizeSourceHost(req.Host)
	req.Owner = strings.TrimSpace(req.Owner)
	req.Repo = strings.TrimSpace(req.Repo)
	req.Ref = normalizeSourceRef(req.Ref)
	rawPath := strings.Trim(strings.TrimSpace(req.Path), "/")
	req.Path = normalizeSourcePath(rawPath)
	if req.Host != "github.com" {
		return SourceContentResponse{}, sourceRequestError("only github.com source viewing is supported")
	}
	if req.Owner == "" || req.Repo == "" {
		return SourceContentResponse{}, sourceRequestError("owner and repo are required")
	}
	if rawPath == "" {
		return SourceContentResponse{}, sourceRequestError("path is required")
	}
	if sourcePathInvalid(req.Path) {
		return SourceContentResponse{}, sourceRequestError("invalid path")
	}

	key := sourceContentCacheKey(req.Host, req.Owner, req.Repo, req.Ref, req.Path)
	cacheable := sourceCacheableRef(req.Ref)
	if h.sourceCache == nil {
		h.sourceCache = newMemorySourceCache()
	}
	if cacheable {
		if entry, ok := h.sourceCache.get(key, time.Now().UTC()); ok {
			return sourceContentResponse(entry, true), nil
		}
	}

	entry, err := fetchGitHubSourceContent(ctx, req)
	if err != nil {
		return SourceContentResponse{}, err
	}
	if !cacheable {
		return sourceContentResponse(entry, false), nil
	}
	if err := h.sourceCache.put(key, entry); err != nil {
		return SourceContentResponse{}, fmt.Errorf("cache source content: %w", err)
	}
	return sourceContentResponse(entry, false), nil
}

func (h *Handler) getSourceOwner(ctx context.Context, req SourceContentRequest) (sourceOwnerResponse, error) {
	req.Host = normalizeSourceHost(req.Host)
	req.Owner = strings.TrimSpace(req.Owner)
	if req.Host != "github.com" {
		return sourceOwnerResponse{}, sourceRequestError("only github.com source viewing is supported")
	}
	if req.Owner == "" {
		return sourceOwnerResponse{}, sourceRequestError("owner is required")
	}
	if resp, ok := h.sourceOwnerFromGraph(req.Owner); ok {
		return resp, nil
	}
	return fetchGitHubSourceOwner(ctx, req)
}

func (h *Handler) sourceGraphRoot() sourceGraphRootResponse {
	p := h.Pantry()
	counts := make(map[string]int)
	for _, org := range p.GetAssetsByType(pantry.AssetOrganization) {
		owner := sourceAssetStringProperty(org, "org")
		if owner == "" {
			owner = org.Name
		}
		if owner != "" {
			counts[owner] += 0
		}
	}
	for _, repo := range p.GetAssetsByType(pantry.AssetRepository) {
		owner, _, ok := sourceRepositoryAssetOwnerRepo(repo)
		if ok {
			counts[owner]++
		}
	}

	owners := make([]sourceGraphOwner, 0, len(counts))
	for owner, repoCount := range counts {
		owners = append(owners, sourceGraphOwner{Name: owner, RepoCount: repoCount})
	}
	sort.Slice(owners, func(i, j int) bool {
		return strings.ToLower(owners[i].Name) < strings.ToLower(owners[j].Name)
	})
	return sourceGraphRootResponse{Owners: owners}
}

func (h *Handler) sourceOwnerFromGraph(owner string) (sourceOwnerResponse, bool) {
	p := h.Pantry()
	repos := make([]sourceOwnerRepository, 0)
	for _, repoAsset := range p.GetAssetsByType(pantry.AssetRepository) {
		repoOwner, repoName, ok := sourceRepositoryAssetOwnerRepo(repoAsset)
		if !ok || repoOwner != owner {
			continue
		}
		repos = append(repos, sourceOwnerRepository{
			Name:          repoName,
			FullName:      repoOwner + "/" + repoName,
			Description:   sourceAssetStringProperty(repoAsset, "description"),
			Private:       sourceAssetBoolProperty(repoAsset, "private"),
			DefaultBranch: sourceAssetStringProperty(repoAsset, "default_branch"),
			HTMLURL:       "https://github.com/" + repoOwner + "/" + repoName,
		})
	}
	if len(repos) == 0 {
		return sourceOwnerResponse{}, false
	}
	sort.Slice(repos, func(i, j int) bool {
		return strings.ToLower(repos[i].Name) < strings.ToLower(repos[j].Name)
	})
	return sourceOwnerResponse{
		Owner:   owner,
		HTMLURL: "https://github.com/" + owner,
		Repos:   repos,
	}, true
}

func (h *Handler) getSourceDirectory(ctx context.Context, req SourceContentRequest) (sourceDirectoryResponse, error) {
	req.Host = normalizeSourceHost(req.Host)
	req.Owner = strings.TrimSpace(req.Owner)
	req.Repo = strings.TrimSpace(req.Repo)
	req.Ref = normalizeSourceRef(req.Ref)
	rawPath := strings.Trim(strings.TrimSpace(req.Path), "/")
	req.Path = normalizeSourcePath(rawPath)
	if req.Host != "github.com" {
		return sourceDirectoryResponse{}, sourceRequestError("only github.com source viewing is supported")
	}
	if req.Owner == "" || req.Repo == "" {
		return sourceDirectoryResponse{}, sourceRequestError("owner and repo are required")
	}
	if sourcePathInvalid(req.Path) {
		return sourceDirectoryResponse{}, sourceRequestError("invalid path")
	}

	info, err := fetchGitHubSourceRepository(ctx, req)
	if err != nil {
		return sourceDirectoryResponse{}, err
	}
	displayRef := req.Ref
	if req.Ref == "HEAD" {
		displayRef = info.DefaultBranch
	}

	resp, err := fetchGitHubSourceDirectory(ctx, req)
	if err != nil {
		return sourceDirectoryResponse{}, err
	}
	resp.Ref = displayRef
	resp.HTMLURL = info.HTMLURL
	resp.Description = info.Description
	resp.DefaultBranch = info.DefaultBranch
	resp.Readme = h.sourceDirectoryReadme(ctx, req, resp.Entries)
	return resp, nil
}

func (h *Handler) getSourceViewerContent(ctx context.Context, req SourceContentRequest) (SourceContentResponse, error) {
	candidates := sourceViewerPathCandidates(req)
	var fallback error
	for i, candidate := range candidates {
		resp, err := h.getSourceContent(ctx, candidate)
		if err == nil {
			return resp, nil
		}
		if i == 0 {
			fallback = err
		}
		if !sourceViewerCandidateRetryable(err) {
			return SourceContentResponse{}, err
		}
	}
	if fallback != nil {
		return SourceContentResponse{}, fallback
	}
	return SourceContentResponse{}, sourceRequestError("path is required")
}

func (h *Handler) getSourceViewerDirectory(ctx context.Context, req SourceContentRequest) (sourceDirectoryResponse, error) {
	candidates := sourceViewerPathCandidates(req)
	var fallback error
	for i, candidate := range candidates {
		resp, err := h.getSourceDirectory(ctx, candidate)
		if err == nil {
			return resp, nil
		}
		if i == 0 {
			fallback = err
		}
		if !sourceViewerDirectoryCandidateRetryable(err) {
			return sourceDirectoryResponse{}, err
		}
	}
	if fallback != nil {
		return sourceDirectoryResponse{}, fallback
	}
	return sourceDirectoryResponse{}, sourceRequestError("path is required")
}

func sourceViewerPathCandidates(req SourceContentRequest) []SourceContentRequest {
	ref := normalizeSourceRef(req.Ref)
	path := strings.Trim(strings.TrimSpace(req.Path), "/")
	if path == "" {
		req.Ref = ref
		req.Path = path
		return []SourceContentRequest{req}
	}

	segments := strings.Split(path, "/")
	candidates := make([]SourceContentRequest, 0, min(len(segments), sourceViewerMaxPathCandidates))
	for i := 0; i < len(segments) && i < sourceViewerMaxPathCandidates; i++ {
		candidate := req
		if i == 0 {
			candidate.Ref = ref
		} else {
			candidate.Ref = ref + "/" + strings.Join(segments[:i], "/")
		}
		candidate.Path = strings.Join(segments[i:], "/")
		candidates = append(candidates, candidate)
	}
	return candidates
}

func sourceViewerCandidateRetryable(err error) bool {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusNotFound
	}
	var reqErr sourceRequestError
	if errors.As(err, &reqErr) {
		return string(reqErr) == "source viewer only supports files"
	}
	return false
}

func sourceViewerDirectoryCandidateRetryable(err error) bool {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusNotFound
	}
	var reqErr sourceRequestError
	if errors.As(err, &reqErr) {
		return string(reqErr) == "source viewer only supports directories"
	}
	return false
}

func sourceRequestErrorIs(err error, message string) bool {
	var reqErr sourceRequestError
	return errors.As(err, &reqErr) && string(reqErr) == message
}

func sourceCacheableRef(ref string) bool {
	return normalizeSourceRef(ref) != "HEAD"
}

func sourcePathInvalid(path string) bool {
	return path == "." || path == ".." || strings.HasPrefix(path, "../")
}

func sourceRepositoryAssetOwnerRepo(asset pantry.Asset) (owner, repo string, ok bool) {
	owner = sourceAssetStringProperty(asset, "org")
	repo = sourceAssetStringProperty(asset, "repo")
	if owner != "" && repo != "" {
		return owner, repo, true
	}
	if owner != "" && asset.Name != "" {
		return owner, asset.Name, true
	}
	if idx := strings.Index(asset.ID, ":"); idx >= 0 && idx+1 < len(asset.ID) {
		return splitSourceFullName(asset.ID[idx+1:])
	}
	return "", "", false
}

func sourceAssetStringProperty(asset pantry.Asset, key string) string {
	if asset.Properties == nil {
		return ""
	}
	value, ok := asset.Properties[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func sourceAssetBoolProperty(asset pantry.Asset, key string) bool {
	if asset.Properties == nil {
		return false
	}
	value, ok := asset.Properties[key]
	if !ok {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

type sourceRepositoryInfo struct {
	DefaultBranch string
	HTMLURL       string
	Description   string
}

func fetchGitHubSourceOwner(ctx context.Context, req SourceContentRequest) (sourceOwnerResponse, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	repos, err := fetchGitHubSourceOrgRepos(ctx, client.client, req.Owner)
	if err != nil {
		var ghErr *github.ErrorResponse
		if !errors.As(err, &ghErr) || ghErr.Response == nil || ghErr.Response.StatusCode != http.StatusNotFound {
			return sourceOwnerResponse{}, err
		}
		repos, err = fetchGitHubSourceUserRepos(ctx, client.client, req.Owner)
		if err != nil {
			return sourceOwnerResponse{}, err
		}
	}

	entries := make([]sourceOwnerRepository, 0, len(repos))
	for _, repo := range repos {
		entries = append(entries, sourceOwnerRepository{
			Name:          repo.GetName(),
			FullName:      repo.GetFullName(),
			Description:   repo.GetDescription(),
			Private:       repo.GetPrivate(),
			DefaultBranch: repo.GetDefaultBranch(),
			HTMLURL:       repo.GetHTMLURL(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return sourceOwnerResponse{
		Owner:   req.Owner,
		HTMLURL: "https://github.com/" + req.Owner,
		Repos:   entries,
	}, nil
}

func fetchGitHubSourceOrgRepos(ctx context.Context, client *github.Client, owner string) ([]*github.Repository, error) {
	opts := &github.RepositoryListByOrgOptions{
		Type:        "all",
		Sort:        "full_name",
		Direction:   "asc",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var all []*github.Repository
	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, owner, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, repos...)
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceUserRepos(ctx context.Context, client *github.Client, owner string) ([]*github.Repository, error) {
	opts := &github.RepositoryListByUserOptions{
		Type:        "all",
		Sort:        "full_name",
		Direction:   "asc",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var all []*github.Repository
	for {
		repos, resp, err := client.Repositories.ListByUser(ctx, owner, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, repos...)
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceRepository(ctx context.Context, req SourceContentRequest) (sourceRepositoryInfo, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	repo, _, err := client.client.Repositories.Get(ctx, req.Owner, req.Repo)
	if err != nil {
		return sourceRepositoryInfo{}, err
	}
	defaultBranch := repo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "HEAD"
	}
	return sourceRepositoryInfo{
		DefaultBranch: defaultBranch,
		HTMLURL:       repo.GetHTMLURL(),
		Description:   repo.GetDescription(),
	}, nil
}

func fetchGitHubSourceContent(ctx context.Context, req SourceContentRequest) (sourceCacheEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	content, directory, _, err := client.client.Repositories.GetContents(ctx, req.Owner, req.Repo, req.Path, &github.RepositoryContentGetOptions{Ref: githubSourceRef(req.Ref)})
	if err != nil {
		return sourceCacheEntry{}, err
	}
	if len(directory) > 0 || content == nil || content.GetType() == "dir" {
		return sourceCacheEntry{}, sourceRequestError("source viewer only supports files")
	}

	decoded, err := content.GetContent()
	if err != nil {
		return sourceCacheEntry{}, fmt.Errorf("decode source content: %w", err)
	}
	if len([]byte(decoded)) > sourceViewerMaxBytes {
		return sourceCacheEntry{}, sourceRequestError("source file is too large")
	}

	return sourceCacheEntry{
		Host:       "github.com",
		Repository: req.Owner + "/" + req.Repo,
		Owner:      req.Owner,
		Repo:       req.Repo,
		Ref:        req.Ref,
		Path:       req.Path,
		SHA:        content.GetSHA(),
		HTMLURL:    content.GetHTMLURL(),
		Content:    decoded,
		Size:       len([]byte(decoded)),
		FetchedAt:  time.Now().UTC(),
	}, nil
}

func fetchGitHubSourceDirectory(ctx context.Context, req SourceContentRequest) (sourceDirectoryResponse, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	content, directory, _, err := client.client.Repositories.GetContents(ctx, req.Owner, req.Repo, req.Path, &github.RepositoryContentGetOptions{Ref: githubSourceRef(req.Ref)})
	if err != nil {
		return sourceDirectoryResponse{}, err
	}
	if content != nil && content.GetType() != "dir" {
		return sourceDirectoryResponse{}, sourceRequestError("source viewer only supports directories")
	}

	entries := make([]sourceDirectoryEntry, 0, len(directory))
	for _, item := range directory {
		entries = append(entries, sourceDirectoryEntry{
			Name:    item.GetName(),
			Path:    item.GetPath(),
			Type:    item.GetType(),
			SHA:     item.GetSHA(),
			HTMLURL: item.GetHTMLURL(),
			Size:    item.GetSize(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		leftDir := entries[i].Type == "dir"
		rightDir := entries[j].Type == "dir"
		if leftDir != rightDir {
			return leftDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})

	return sourceDirectoryResponse{
		Host:       "github.com",
		Repository: req.Owner + "/" + req.Repo,
		Owner:      req.Owner,
		Repo:       req.Repo,
		Ref:        req.Ref,
		Path:       req.Path,
		Entries:    entries,
	}, nil
}

func (h *Handler) sourceDirectoryReadme(ctx context.Context, req SourceContentRequest, entries []sourceDirectoryEntry) *SourceContentResponse {
	for _, entry := range entries {
		if entry.Type != "file" || !sourceEntryIsReadme(entry.Name) {
			continue
		}
		readmeReq := req
		readmeReq.Path = entry.Path
		resp, err := h.getSourceContent(ctx, readmeReq)
		if err != nil {
			return nil
		}
		return &resp
	}
	return nil
}

func sourceEntryIsReadme(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "readme" || strings.HasPrefix(name, "readme.")
}

func sourceContentResponse(entry sourceCacheEntry, cacheHit bool) SourceContentResponse {
	return SourceContentResponse{
		Host:       entry.Host,
		Repository: entry.Repository,
		Owner:      entry.Owner,
		Repo:       entry.Repo,
		Ref:        entry.Ref,
		Path:       entry.Path,
		SHA:        entry.SHA,
		HTMLURL:    entry.HTMLURL,
		Content:    entry.Content,
		Size:       entry.Size,
		FetchedAt:  entry.FetchedAt,
		CacheHit:   cacheHit,
	}
}

func normalizeSourceHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return "github.com"
	}
	return host
}

func normalizeSourceRef(ref string) string {
	ref = strings.Trim(strings.TrimSpace(ref), "/")
	if ref == "" {
		return "HEAD"
	}
	return ref
}

func normalizeSourcePath(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(path))
}

func githubSourceRef(ref string) string {
	if ref == "HEAD" {
		return ""
	}
	return ref
}

func sourceContentCacheKey(host, owner, repo, ref, path string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(host)),
		strings.TrimSpace(owner),
		strings.TrimSpace(repo),
		normalizeSourceRef(ref),
		normalizeSourcePath(path),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func sourceTokenKeys(r *http.Request, sessionID string) []string {
	operatorID := "operator"
	if claims, ok := r.Context().Value(auth.ClaimsKey).(*auth.Claims); ok && claims != nil && claims.OperatorID != "" {
		operatorID = claims.OperatorID
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return []string{operatorID}
	}
	return []string{operatorID + ":" + sessionID, operatorID}
}

func sourceViewerSessionID(r *http.Request) string {
	if sessionID := strings.TrimSpace(r.URL.Query().Get("session_id")); sessionID != "" {
		return sessionID
	}
	if cookie, err := r.Cookie(sourceSessionCookie); err == nil {
		return strings.TrimSpace(cookie.Value)
	}
	return ""
}

func setBrowserCookie(w http.ResponseWriter, r *http.Request, name, value, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   sourceSecureCookie(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(browserSessionCookieMaxAge.Seconds()),
	})
}

func sourceSecureCookie(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func sanitizeBrowserSessionNext(next string) (string, error) {
	next = strings.TrimSpace(next)
	if next == "" {
		return "/viewer/github.com/", nil
	}
	u, err := url.Parse(next)
	if err != nil {
		return "", err
	}
	if u.IsAbs() || u.Host != "" || !browserSessionNextAllowed(u.Path) {
		return "", sourceRequestError("invalid redirect target")
	}
	return u.String(), nil
}

func browserSessionNextAllowed(path string) bool {
	return path == "/graph" || path == "/viewer/github.com" || strings.HasPrefix(path, "/viewer/github.com/")
}

func writeBrowserSecurityHeaders(w http.ResponseWriter, csp string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", csp)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
}

func writeSourceSecurityHeaders(w http.ResponseWriter) {
	writeBrowserSecurityHeaders(w, sourceViewerCSP)
}

func writeGraphSecurityHeaders(w http.ResponseWriter) {
	writeBrowserSecurityHeaders(w, graphViewerCSP)
}

func writeSourceJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(gitHubErrorResponse{Error: message})
}

type sourceRequestError string

func (e sourceRequestError) Error() string {
	return string(e)
}

func sourceHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var reqErr sourceRequestError
	if errors.As(err, &reqErr) {
		return http.StatusBadRequest
	}
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		switch ghErr.Response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return ghErr.Response.StatusCode
		}
	}
	return http.StatusInternalServerError
}

func (h *Handler) writeSourceViewerError(w http.ResponseWriter, req SourceContentRequest, status int, err error) {
	h.writeSourceHTMLPage(w, status, sourceViewerErrorPage(req, err.Error()))
}

func (h *Handler) writeSourceViewerPage(w http.ResponseWriter, resp SourceContentResponse, line int, linkQuery string) {
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerFilePage(resp, line, linkQuery))
}

func (h *Handler) writeSourceGraphRootPage(w http.ResponseWriter, resp sourceGraphRootResponse, linkQuery string) {
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerGraphRootPage(resp, linkQuery))
}

func (h *Handler) writeSourceOwnerPage(w http.ResponseWriter, resp sourceOwnerResponse, linkQuery string) {
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerOwnerPage(resp, linkQuery))
}

func (h *Handler) writeSourceDirectoryPage(w http.ResponseWriter, resp sourceDirectoryResponse, rawQuery string) {
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerDirectoryPage(resp, rawQuery))
}

func (h *Handler) writeSourceHTMLPage(w http.ResponseWriter, status int, page sourceViewerPage) {
	body, err := renderSourceViewerPage(page)
	if err != nil {
		writeSourceSecurityHeaders(w)
		http.Error(w, "failed to render source viewer", http.StatusInternalServerError)
		return
	}
	writeSourceSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

type sourceViewerPage struct {
	Title  string
	Header sourceViewerHeaderView
	Error  string
	Table  *sourceViewerTableView
	File   *sourceViewerFileView
}

type sourceViewerHeaderView struct {
	AriaLabel   string
	RepoName    sourceViewerRepoNameView
	Description string
	Ref         string
	PathText    string
	SizeText    string
	ParentHref  string
	GitHubURL   string
}

type sourceViewerRepoNameView struct {
	RootHref  string
	OwnerHref string
	RepoHref  string
	Owner     string
	Repo      string
}

type sourceViewerTableView struct {
	Rows   []sourceViewerTableRow
	Readme *sourceViewerReadmeView
}

type sourceViewerTableRow struct {
	Type        string
	Name        string
	NameClass   string
	Href        string
	Description string
	Size        string
}

type sourceViewerReadmeView struct {
	Title        string
	Text         string
	MarkdownHTML template.HTML
}

type sourceViewerFileView struct {
	MarkdownHTML template.HTML
	Lines        []sourceViewerLineView
}

type sourceViewerLineView struct {
	Number    int
	Text      string
	Highlight bool
}

func sourceViewerErrorPage(req SourceContentRequest, message string) sourceViewerPage {
	return sourceViewerPage{
		Title:  "Source unavailable",
		Header: sourceViewerFileHeader(req.Owner, req.Repo, req.Ref, req.Path, "", 0, ""),
		Error:  message,
	}
}

func sourceViewerFilePage(resp SourceContentResponse, line int, linkQuery string) sourceViewerPage {
	return sourceViewerPage{
		Title:  resp.Repository + "/" + resp.Path,
		Header: sourceViewerFileHeader(resp.Owner, resp.Repo, resp.Ref, resp.Path, resp.HTMLURL, resp.Size, linkQuery),
		File:   sourceViewerFileViewFor(resp, line),
	}
}

func sourceViewerGraphRootPage(resp sourceGraphRootResponse, linkQuery string) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(resp.Owners))
	for _, owner := range resp.Owners {
		rows = append(rows, sourceViewerTableRow{
			Type: "org",
			Name: owner.Name,
			Href: sourceViewerOwnerHref(owner.Name, linkQuery),
			Size: sourceRepoCount(owner.RepoCount),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No GitHub organizations found in the graph."))
	}
	return sourceViewerPage{
		Title: "github.com",
		Header: sourceViewerHeaderView{
			AriaLabel: "GitHub",
			RepoName:  sourceViewerRepoNameView{RootHref: sourceViewerRootHref()},
			PathText:  "Organizations in graph",
		},
		Table: &sourceViewerTableView{Rows: rows},
	}
}

func sourceViewerOwnerPage(resp sourceOwnerResponse, linkQuery string) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(resp.Repos))
	for _, repo := range resp.Repos {
		owner, repoName, ok := splitSourceFullName(repo.FullName)
		if !ok {
			owner = resp.Owner
			repoName = repo.Name
		}
		visibility := "public"
		if repo.Private {
			visibility = "private"
		}
		name := repo.Name
		if name == "" {
			name = repoName
		}
		rows = append(rows, sourceViewerTableRow{
			Type:        visibility,
			Name:        name,
			Href:        sourceViewerRepoHref(owner, repoName, linkQuery),
			Description: repo.Description,
			Size:        repo.DefaultBranch,
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No repositories found."))
	}
	return sourceViewerPage{
		Title: resp.Owner,
		Header: sourceViewerHeaderView{
			AriaLabel: "Owner",
			RepoName:  sourceViewerOwnerNameView(resp.Owner),
			PathText:  "Repositories",
			GitHubURL: resp.HTMLURL,
		},
		Table: &sourceViewerTableView{Rows: rows},
	}
}

func sourceViewerDirectoryPage(resp sourceDirectoryResponse, linkQuery string) sourceViewerPage {
	title := resp.Repository
	if resp.Path != "" {
		title += "/" + resp.Path
	}
	return sourceViewerPage{
		Title:  title,
		Header: sourceViewerDirectoryHeader(resp),
		Table:  sourceViewerDirectoryTable(resp, linkQuery),
	}
}

func sourceViewerFileHeader(owner, repo, ref, path, githubURL string, size int, linkQuery string) sourceViewerHeaderView {
	repoQuery := linkQuery
	if ref != "" {
		repoQuery = sourceViewerQueryWithRef(linkQuery, ref)
	}
	header := sourceViewerHeaderView{
		AriaLabel: "Repository",
		RepoName:  sourceViewerRepoNameViewFor(owner, repo, repoQuery),
		Ref:       ref,
		PathText:  path,
		GitHubURL: githubURL,
	}
	if size > 0 {
		header.SizeText = fmt.Sprintf("%d bytes", size)
	}
	if owner != "" && repo != "" && path != "" {
		header.ParentHref = sourceViewerPathHref(owner, repo, "tree", ref, sourceParentPath(path), linkQuery)
	}
	return header
}

func sourceViewerDirectoryHeader(resp sourceDirectoryResponse) sourceViewerHeaderView {
	pathText := "/"
	if resp.Path != "" {
		pathText = resp.Path
	}
	return sourceViewerHeaderView{
		AriaLabel:   "Repository",
		RepoName:    sourceViewerRepoNameViewFor(resp.Owner, resp.Repo, sourceViewerQueryWithRef("", resp.Ref)),
		Description: resp.Description,
		Ref:         resp.Ref,
		PathText:    pathText,
		GitHubURL:   resp.HTMLURL,
	}
}

func sourceViewerRepoNameViewFor(owner, repo, rawQuery string) sourceViewerRepoNameView {
	return sourceViewerRepoNameView{
		RootHref:  sourceViewerRootHref(),
		OwnerHref: sourceViewerOwnerHref(owner, ""),
		RepoHref:  sourceViewerRepoHref(owner, repo, rawQuery),
		Owner:     owner,
		Repo:      repo,
	}
}

func sourceViewerOwnerNameView(owner string) sourceViewerRepoNameView {
	return sourceViewerRepoNameView{
		RootHref: sourceViewerRootHref(),
		Owner:    owner,
	}
}

func sourceViewerDirectoryTable(resp sourceDirectoryResponse, linkQuery string) *sourceViewerTableView {
	rows := make([]sourceViewerTableRow, 0, len(resp.Entries)+1)
	if resp.Path != "" {
		parent := sourceParentPath(resp.Path)
		rows = append(rows, sourceViewerTableRow{
			Type: "dir",
			Name: "..",
			Href: sourceViewerPathHref(resp.Owner, resp.Repo, "tree", resp.Ref, parent, linkQuery),
		})
	}
	for _, entry := range resp.Entries {
		kind := "blob"
		typeLabel := "file"
		if entry.Type == "dir" {
			kind = "tree"
			typeLabel = "dir"
		}
		rows = append(rows, sourceViewerTableRow{
			Type: typeLabel,
			Name: entry.Name,
			Href: sourceViewerPathHref(resp.Owner, resp.Repo, kind, resp.Ref, entry.Path, linkQuery),
			Size: sourceEntrySize(entry),
		})
	}
	if len(resp.Entries) == 0 {
		rows = append(rows, sourceViewerEmptyRow("This directory is empty."))
	}
	table := &sourceViewerTableView{Rows: rows}
	if resp.Readme != nil {
		table.Readme = sourceViewerReadmeViewFor(*resp.Readme)
	}
	return table
}

func sourceViewerEmptyRow(message string) sourceViewerTableRow {
	return sourceViewerTableRow{Name: message, NameClass: "empty-directory"}
}

func sourceRepoCount(count int) string {
	if count == 1 {
		return "1 repo"
	}
	return fmt.Sprintf("%d repos", count)
}

func splitSourceFullName(fullName string) (owner, repo string, ok bool) {
	owner, repo, ok = strings.Cut(strings.TrimSpace(fullName), "/")
	return owner, repo, ok && owner != "" && repo != ""
}

func sourceViewerMarkdownPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown":
		return true
	default:
		return false
	}
}

func sourceViewerReadmeViewFor(readme SourceContentResponse) *sourceViewerReadmeView {
	view := &sourceViewerReadmeView{Title: filepath.Base(readme.Path)}
	if sourceViewerMarkdownPath(readme.Path) {
		view.MarkdownHTML = sourceViewerMarkdownHTML(readme.Content)
		return view
	}
	view.Text = readme.Content
	return view
}

func sourceViewerFileViewFor(resp SourceContentResponse, highlightLine int) *sourceViewerFileView {
	if sourceViewerMarkdownPath(resp.Path) {
		return &sourceViewerFileView{MarkdownHTML: sourceViewerMarkdownHTML(resp.Content)}
	}
	return &sourceViewerFileView{Lines: sourceViewerLines(resp.Content, highlightLine)}
}

func sourceViewerMarkdownHTML(content string) template.HTML {
	var rendered bytes.Buffer
	if err := sourceMarkdown.Convert([]byte(content), &rendered); err != nil {
		return template.HTML(`<pre>` + html.EscapeString(content) + `</pre>`)
	}
	return template.HTML(sourceMarkdownPolicy.SanitizeBytes(rendered.Bytes()))
}

func sourceViewerLines(content string, highlightLine int) []sourceViewerLineView {
	lines := strings.Split(content, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	views := make([]sourceViewerLineView, 0, len(lines))
	for i, line := range lines {
		lineNo := i + 1
		if line == "" {
			line = " "
		}
		views = append(views, sourceViewerLineView{
			Number:    lineNo,
			Text:      line,
			Highlight: lineNo == highlightLine,
		})
	}
	return views
}

func sourceViewerPathHref(owner, repo, kind, ref, path, rawQuery string) string {
	href := "/viewer/github.com/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
	if kind == "tree" && path == "" {
		rawQuery = sourceViewerQueryWithRef(rawQuery, ref)
	} else {
		href += "/" + kind + "/" + url.PathEscape(ref) + "/" + escapeSourceViewerPath(path)
	}
	if rawQuery != "" {
		href += "?" + rawQuery
	}
	return href
}

func sourceViewerRepoHref(owner, repo, rawQuery string) string {
	href := "/viewer/github.com/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
	if rawQuery != "" {
		href += "?" + rawQuery
	}
	return href
}

func sourceViewerOwnerHref(owner, rawQuery string) string {
	href := "/viewer/github.com/" + url.PathEscape(owner)
	if rawQuery != "" {
		href += "?" + rawQuery
	}
	return href
}

func sourceViewerRootHref() string {
	return "/viewer/github.com/"
}

func escapeSourceViewerPath(path string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(path), "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func sourceParentPath(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	parent := filepath.Dir(path)
	if parent == "." {
		return ""
	}
	return filepath.ToSlash(parent)
}

func sourceEntrySize(entry sourceDirectoryEntry) string {
	if entry.Type == "dir" || entry.Size <= 0 {
		return ""
	}
	return fmt.Sprintf("%d bytes", entry.Size)
}

func sourceViewerQueryWithRef(rawQuery, ref string) string {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		values = make(url.Values)
	}
	values.Set("ref", ref)
	return values.Encode()
}

func sourceViewerQueryForLinks(values url.Values, dropRef bool) string {
	next := make(url.Values)
	for key, vals := range values {
		if key == "line" || key == "token" || key == "session_id" {
			continue
		}
		if dropRef && key == "ref" {
			continue
		}
		for _, value := range vals {
			next.Add(key, value)
		}
	}
	return next.Encode()
}
