// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

type sourceBrowserTarget struct {
	Owner     string
	Repo      string
	Ref       string
	Path      string
	Line      int
	ViewerURL string
}

func (m Model) registerActiveSourceTokenCmd() tea.Cmd {
	if m.kitchenClient == nil || m.tokenInfo == nil || strings.TrimSpace(m.tokenInfo.Value) == "" {
		return nil
	}
	token := m.tokenInfo.Value
	source := m.tokenInfo.Source
	sessionID := m.config.SessionID
	appID := m.activeSourceTokenAppID(token)
	return func() tea.Msg {
		_, err := m.kitchenClient.RegisterSourceToken(context.Background(), counter.SourceTokenRequest{
			Token:     token,
			Source:    source,
			SessionID: sessionID,
			AppID:     appID,
		})
		if err != nil {
			return SourceTokenRegisterErrorMsg{Err: fmt.Errorf("register source token: %w", err)}
		}
		return SourceTokenRegisteredMsg{}
	}
}

func (m Model) openSelectedSourceViewer() (Model, tea.Cmd) {
	node := m.SelectedTreeNode()
	if node == nil {
		m.AddOutput("error", "select an org, repo, workflow or vulnerability first")
		return m, nil
	}
	return m.openSelectedSourceBrowser(node)
}

func (m Model) openSelectedSourceBrowser(node *TreeNode) (Model, tea.Cmd) {
	viewerURL, err := m.selectedSourceBrowserURL(node)
	if err != nil {
		m.AddOutput("error", err.Error())
		return m, nil
	}
	m.AddOutput("info", Hyperlink(viewerURL, "Open source viewer ->"))
	m.activityLog.Add(IconInfo, "Opening source viewer in browser")
	return m, m.openSourceBrowserCmd(viewerURL, m.browserSessionURL(viewerURL))
}

func (m Model) selectedSourceTarget() (*sourceBrowserTarget, error) {
	return m.sourceTargetForNode(m.SelectedTreeNode())
}

func (m Model) sourceTargetForNode(node *TreeNode) (*sourceBrowserTarget, error) {
	if node == nil {
		return nil, fmt.Errorf("select an org, repo, workflow or vulnerability first")
	}
	switch node.Type {
	case TreeNodeWorkflow:
		repository := m.treeNodeRepo(node)
		owner, repo, ok := splitGitHubRepository(repository)
		if !ok {
			return nil, fmt.Errorf("selected workflow has no GitHub repository")
		}
		path := nodeStringProperty(node, "path")
		if path == "" {
			path = node.Label
		}
		return m.newSourceBrowserTarget(owner, repo, path, nodeStringProperty(node, "default_branch"), 1), nil
	case TreeNodeVuln:
		vuln := m.vulnerabilityForNode(node)
		if vuln == nil {
			return nil, fmt.Errorf("selected vulnerability is not available")
		}
		owner, repo, ok := splitGitHubRepository(vuln.Repository)
		if !ok {
			return nil, fmt.Errorf("selected vulnerability has no GitHub repository")
		}
		line := vuln.Line
		if line <= 0 {
			line = nodeIntProperty(node, "line")
		}
		return m.newSourceBrowserTarget(owner, repo, vuln.Workflow, "", line), nil
	default:
		return nil, fmt.Errorf("select an org, repo, workflow or vulnerability first")
	}
}

func (m Model) selectedSourceBrowserURL(node *TreeNode) (string, error) {
	switch node.Type {
	case TreeNodeOrg:
		owner := m.treeNodeOrg(node)
		if owner == "" || node.Parent == nil {
			return "", fmt.Errorf("selected org has no GitHub owner")
		}
		viewerURL := m.sourceOwnerViewerURL(owner)
		if viewerURL == "" {
			return "", fmt.Errorf("kitchen browser URL is not set")
		}
		return viewerURL, nil
	case TreeNodeRepo:
		owner, repo, ok := splitGitHubRepository(m.treeNodeRepo(node))
		if !ok {
			return "", fmt.Errorf("selected repo has no GitHub repository")
		}
		viewerURL := m.sourceRepositoryViewerURL(owner, repo)
		if viewerURL == "" {
			return "", fmt.Errorf("kitchen browser URL is not set")
		}
		return viewerURL, nil
	case TreeNodeWorkflow, TreeNodeVuln:
		target, err := m.sourceTargetForNode(node)
		if err != nil {
			return "", err
		}
		if target.ViewerURL == "" {
			return "", fmt.Errorf("kitchen browser URL is not set")
		}
		return target.ViewerURL, nil
	default:
		return "", fmt.Errorf("select an org, repo, workflow or vulnerability first")
	}
}

func (m Model) sourceViewerAvailableForNode(node *TreeNode) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case TreeNodeOrg:
		return node.Parent != nil && m.treeNodeOrg(node) != ""
	case TreeNodeRepo:
		return m.treeNodeRepo(node) != ""
	case TreeNodeWorkflow:
		_, _, ok := splitGitHubRepository(m.treeNodeRepo(node))
		path := nodeStringProperty(node, "path")
		if path == "" {
			path = node.Label
		}
		return ok && strings.TrimSpace(path) != ""
	case TreeNodeVuln:
		vuln := m.vulnerabilityForNode(node)
		if vuln == nil {
			return false
		}
		_, _, ok := splitGitHubRepository(vuln.Repository)
		return ok && strings.TrimSpace(vuln.Workflow) != ""
	default:
		return false
	}
}

func (m Model) newSourceBrowserTarget(owner, repo, path, ref string, line int) *sourceBrowserTarget {
	if ref == "" {
		ref = "HEAD"
	}
	state := &sourceBrowserTarget{
		Owner: owner,
		Repo:  repo,
		Ref:   ref,
		Path:  strings.Trim(strings.TrimSpace(path), "/"),
		Line:  line,
	}
	state.ViewerURL = m.sourceViewerURL(state)
	return state
}

func (m Model) openSourceBrowserCmd(viewerURL, launchURL string) tea.Cmd {
	client := m.kitchenClient
	sessionID := m.config.SessionID
	var token, source string
	var appID string
	if m.tokenInfo != nil {
		token = m.tokenInfo.Value
		source = m.tokenInfo.Source
		appID = m.activeSourceTokenAppID(token)
	}
	return func() tea.Msg {
		if client != nil && strings.TrimSpace(token) != "" {
			_, err := client.RegisterSourceToken(context.Background(), counter.SourceTokenRequest{
				Token:     token,
				Source:    source,
				SessionID: sessionID,
				AppID:     appID,
			})
			if err != nil {
				return SourceBrowserOpenedMsg{URL: viewerURL, Err: fmt.Errorf("register source token: %w", err)}
			}
		}
		if err := m.openBrowser(launchURL); err != nil {
			return SourceBrowserOpenedMsg{URL: viewerURL, Err: err}
		}
		return SourceBrowserOpenedMsg{URL: viewerURL}
	}
}

func (m Model) activeSourceTokenAppID(token string) string {
	if m.pivotToken == nil || strings.TrimSpace(token) == "" || strings.TrimSpace(m.pivotToken.Value) != strings.TrimSpace(token) {
		return ""
	}
	return appIDFromPivotSource(m.pivotToken.Source)
}

func (m Model) sourceViewerURL(state *sourceBrowserTarget) string {
	if state == nil {
		return ""
	}
	baseURL := strings.TrimRight(strings.TrimSpace(m.config.BrowserURL()), "/")
	if baseURL == "" {
		return ""
	}
	u := baseURL + "/viewer/github.com/" + url.PathEscape(state.Owner) + "/" + url.PathEscape(state.Repo) + "/blob/" + url.PathEscape(state.Ref) + "/" + escapeViewerPath(state.Path)
	if state.Line > 0 {
		u += "#L" + strconv.Itoa(state.Line)
	}
	return u
}

func (m Model) sourceOwnerViewerURL(owner string) string {
	baseURL := strings.TrimRight(strings.TrimSpace(m.config.BrowserURL()), "/")
	if baseURL == "" || owner == "" {
		return ""
	}
	return baseURL + "/viewer/github.com/" + url.PathEscape(owner)
}

func (m Model) sourceRepositoryViewerURL(owner, repo string) string {
	baseURL := strings.TrimRight(strings.TrimSpace(m.config.BrowserURL()), "/")
	if baseURL == "" || owner == "" || repo == "" {
		return ""
	}
	return baseURL + "/viewer/github.com/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

func (m Model) browserSessionURL(cleanURL string) string {
	if cleanURL == "" || m.config.AuthToken == "" {
		return cleanURL
	}
	u, err := url.Parse(cleanURL)
	if err != nil {
		return cleanURL
	}
	next := u.EscapedPath()
	if u.RawQuery != "" {
		next += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		next += "#" + u.EscapedFragment()
	}
	var query []string
	query = append(query, "token="+url.QueryEscape(m.config.AuthToken))
	if m.config.SessionID != "" {
		query = append(query, "session_id="+url.QueryEscape(m.config.SessionID))
	}
	query = append(query, "next="+url.QueryEscape(next))

	baseURL := strings.TrimRight(strings.TrimSpace(m.config.BrowserURL()), "/")
	if baseURL == "" {
		return cleanURL
	}
	return baseURL + "/browser/session?" + strings.Join(query, "&")
}

func escapeViewerPath(path string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(path), "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
