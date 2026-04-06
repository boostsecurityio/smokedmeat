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
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v59/github"
)

const (
	deployCapabilityIssue        = "delivery.issue"
	deployCapabilityCommentAny   = "delivery.comment.any"
	deployCapabilityCommentIssue = "delivery.comment.issue"
	deployCapabilityCommentPR    = "delivery.comment.pr"
	deployCapabilityCommentStub  = "delivery.comment.stub_pr"
	deployCapabilityPR           = "delivery.pr"
	deployCapabilityLOTP         = "delivery.lotp"
	deployCapabilityDispatch     = "delivery.dispatch"

	deployStatePass      = "pass"
	deployStateFail      = "fail"
	deployStateUnknown   = "unknown"
	deployStateConfirmed = "confirmed"
	deployStateDenied    = "denied"

	preflightTTL = time.Hour
)

type DeployPreflightRequest struct {
	Token            string            `json:"token"`
	Vuln             VulnerabilityInfo `json:"vuln"`
	TokenType        string            `json:"token_type,omitempty"`
	TokenOwner       string            `json:"token_owner,omitempty"`
	Scopes           []string          `json:"scopes,omitempty"`
	KnownPermissions map[string]string `json:"known_permissions,omitempty"`
	IssueNumber      int               `json:"issue_number,omitempty"`
	PRNumber         int               `json:"pr_number,omitempty"`
}

type DeployPreflightCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type DeployPreflightCapability struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type DeployPreflightResponse struct {
	CacheHit     bool                                 `json:"cache_hit"`
	Capabilities map[string]DeployPreflightCapability `json:"capabilities"`
	Checks       []DeployPreflightCheck               `json:"checks,omitempty"`
}

type deployPreflightCache struct {
	mu        sync.RWMutex
	preflight map[string]deployPreflightCacheEntry
	observed  map[string]deployObservedCapability
}

type deployPreflightCacheEntry struct {
	expiresAt time.Time
	response  DeployPreflightResponse
}

type deployObservedCapability struct {
	state     string
	reason    string
	expiresAt time.Time
}

type deployPreflightSignals struct {
	repoAccessible      bool
	repoPrivate         bool
	issuesEnabled       bool
	pullRequestsEnabled bool
	allowForking        bool
	workflowVisible     bool
	workflowKnown       bool
	issueExists         bool
	issueChecked        bool
	prExists            bool
	prChecked           bool
}

type repoPreflightMetadata struct {
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	AllowForking  bool   `json:"allow_forking"`
	HasIssues     bool   `json:"has_issues"`
}

type deployPreflightEvidence struct {
	tokenType        string
	tokenOwner       string
	scopes           []string
	knownPermissions map[string]string
}

type graphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type graphQLError struct {
	Type    string `json:"type,omitempty"`
	Message string `json:"message"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors"`
}

func newDeployPreflightCache() *deployPreflightCache {
	return &deployPreflightCache{
		preflight: make(map[string]deployPreflightCacheEntry),
		observed:  make(map[string]deployObservedCapability),
	}
}

func (c *deployPreflightCache) getPreflight(key string, now time.Time) (DeployPreflightResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.preflight[key]
	if !ok {
		return DeployPreflightResponse{}, false
	}
	if now.After(entry.expiresAt) {
		delete(c.preflight, key)
		return DeployPreflightResponse{}, false
	}
	return cloneDeployPreflightResponse(entry.response), true
}

func (c *deployPreflightCache) putPreflight(key string, response DeployPreflightResponse, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.preflight[key] = deployPreflightCacheEntry{
		expiresAt: now.Add(preflightTTL),
		response:  cloneDeployPreflightResponse(response),
	}
}

func (c *deployPreflightCache) getObserved(key string, now time.Time) (deployObservedCapability, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.observed[key]
	if !ok {
		return deployObservedCapability{}, false
	}
	if now.After(entry.expiresAt) {
		delete(c.observed, key)
		return deployObservedCapability{}, false
	}
	return entry, true
}

func (c *deployPreflightCache) putObserved(key, state, reason string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed[key] = deployObservedCapability{
		state:     state,
		reason:    reason,
		expiresAt: now.Add(preflightTTL),
	}
}

func cloneDeployPreflightResponse(in DeployPreflightResponse) DeployPreflightResponse {
	out := DeployPreflightResponse{
		CacheHit:     in.CacheHit,
		Capabilities: make(map[string]DeployPreflightCapability, len(in.Capabilities)),
	}
	for key, value := range in.Capabilities {
		out.Capabilities[key] = value
	}
	if len(in.Checks) > 0 {
		out.Checks = append([]DeployPreflightCheck(nil), in.Checks...)
	}
	return out
}

func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:8])
}

func deployPreflightCacheKey(req DeployPreflightRequest) string {
	scopes := append([]string(nil), req.Scopes...)
	sort.Strings(scopes)
	keyBody := struct {
		TokenFingerprint string            `json:"token_fingerprint"`
		TokenType        string            `json:"token_type,omitempty"`
		TokenOwner       string            `json:"token_owner,omitempty"`
		Scopes           []string          `json:"scopes,omitempty"`
		KnownPermissions map[string]string `json:"known_permissions,omitempty"`
		Repository       string            `json:"repository"`
		Workflow         string            `json:"workflow,omitempty"`
		Context          string            `json:"context,omitempty"`
		IssueNumber      int               `json:"issue_number,omitempty"`
		PRNumber         int               `json:"pr_number,omitempty"`
	}{
		TokenFingerprint: tokenFingerprint(req.Token),
		TokenType:        req.TokenType,
		TokenOwner:       req.TokenOwner,
		Scopes:           scopes,
		KnownPermissions: mapsClone(req.KnownPermissions),
		Repository:       req.Vuln.Repository,
		Workflow:         req.Vuln.Workflow,
		Context:          req.Vuln.Context,
		IssueNumber:      req.IssueNumber,
		PRNumber:         req.PRNumber,
	}
	body, _ := json.Marshal(keyBody)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:16])
}

func observedCapabilityCacheKey(token, repository, capability string) string {
	return strings.Join([]string{tokenFingerprint(token), repository, capability}, "|")
}

func normalizeDispatchWorkflow(workflow string) string {
	workflow = strings.TrimSpace(workflow)
	workflow = strings.TrimPrefix(workflow, ".github/workflows/")
	return workflow
}

func dispatchObservedCapability(workflow string) string {
	workflow = normalizeDispatchWorkflow(workflow)
	if workflow == "" {
		return deployCapabilityDispatch
	}
	return deployCapabilityDispatch + ":" + workflow
}

func observedCapabilityLookup(req DeployPreflightRequest, capability string) string {
	switch capability {
	case deployCapabilityDispatch:
		return dispatchObservedCapability(req.Vuln.Workflow)
	default:
		return capability
	}
}

func normalizePermissionValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizePermissionName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

func (e deployPreflightEvidence) permissionAllowsWrite(name string) bool {
	want := normalizePermissionName(name)
	for key, value := range e.knownPermissions {
		if normalizePermissionName(key) == want && normalizePermissionValue(value) == "write" {
			return true
		}
	}
	return false
}

func (e deployPreflightEvidence) hasScope(scope string) bool {
	for _, candidate := range e.scopes {
		if strings.TrimSpace(candidate) == scope {
			return true
		}
	}
	return false
}

func (e deployPreflightEvidence) hasRepoWrite(repoPrivate bool) bool {
	if e.hasScope("repo") {
		return true
	}
	if !repoPrivate && e.hasScope("public_repo") {
		return true
	}
	return false
}

func (e deployPreflightEvidence) issueCapability(repoPrivate bool) DeployPreflightCapability {
	if e.permissionAllowsWrite("issues") {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if e.hasRepoWrite(repoPrivate) {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if len(e.knownPermissions) > 0 && (e.tokenType == "fine_grained_pat" || e.tokenType == "install_app" || e.tokenType == "actions") {
		return DeployPreflightCapability{State: deployStateFail, Reason: "token lacks issue-write permission"}
	}
	if e.tokenType == "fine_grained_pat" {
		return DeployPreflightCapability{State: deployStateUnknown, Reason: "Issue access could not be pre-verified"}
	}
	return DeployPreflightCapability{State: deployStateUnknown, Reason: "Issue access could not be pre-verified"}
}

func (e deployPreflightEvidence) commentCapability(repoPrivate bool) DeployPreflightCapability {
	if e.permissionAllowsWrite("issues") || e.permissionAllowsWrite("pull_requests") {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if e.hasRepoWrite(repoPrivate) {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if len(e.knownPermissions) > 0 && (e.tokenType == "fine_grained_pat" || e.tokenType == "install_app" || e.tokenType == "actions") {
		return DeployPreflightCapability{State: deployStateFail, Reason: "token lacks comment-write permission"}
	}
	if e.tokenType == "fine_grained_pat" {
		return DeployPreflightCapability{State: deployStateUnknown, Reason: "Comment access could not be pre-verified"}
	}
	return DeployPreflightCapability{State: deployStateUnknown, Reason: "Comment access could not be pre-verified"}
}

func (e deployPreflightEvidence) pullRequestCapability(repoPrivate bool) DeployPreflightCapability {
	if e.permissionAllowsWrite("contents") && e.permissionAllowsWrite("pull_requests") {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if e.hasRepoWrite(repoPrivate) {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if len(e.knownPermissions) > 0 && (e.tokenType == "fine_grained_pat" || e.tokenType == "install_app" || e.tokenType == "actions") {
		return DeployPreflightCapability{State: deployStateFail, Reason: "token lacks PR creation permission"}
	}
	if e.tokenType == "fine_grained_pat" {
		return DeployPreflightCapability{State: deployStateUnknown, Reason: "PR access could not be pre-verified"}
	}
	return DeployPreflightCapability{State: deployStateUnknown, Reason: "PR access could not be pre-verified"}
}

func (e deployPreflightEvidence) dispatchCapability(repoPrivate bool) DeployPreflightCapability {
	if e.permissionAllowsWrite("actions") || e.permissionAllowsWrite("workflows") {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if e.hasRepoWrite(repoPrivate) {
		return DeployPreflightCapability{State: deployStatePass}
	}
	if len(e.knownPermissions) > 0 && (e.tokenType == "fine_grained_pat" || e.tokenType == "install_app" || e.tokenType == "actions") {
		return DeployPreflightCapability{State: deployStateFail, Reason: "token lacks workflow-dispatch permission"}
	}
	if e.tokenType == "fine_grained_pat" {
		return DeployPreflightCapability{State: deployStateUnknown, Reason: "Workflow dispatch access could not be pre-verified"}
	}
	return DeployPreflightCapability{State: deployStateUnknown, Reason: "Workflow dispatch access could not be pre-verified"}
}

func newDeployCheck(name, state, reason string) DeployPreflightCheck {
	return DeployPreflightCheck{Name: name, State: state, Reason: reason}
}

func capabilityFromChecks(base DeployPreflightCapability, checks ...DeployPreflightCheck) DeployPreflightCapability {
	for _, check := range checks {
		if check.State == deployStateFail {
			reason := check.Reason
			if reason == "" {
				reason = check.Name
			}
			return DeployPreflightCapability{State: deployStateFail, Reason: reason}
		}
	}
	return base
}

func mergeCommentAny(issue, pr, stub DeployPreflightCapability) DeployPreflightCapability {
	states := []DeployPreflightCapability{issue, pr, stub}
	for _, candidate := range states {
		if candidate.State == deployStateConfirmed {
			return DeployPreflightCapability{State: deployStateConfirmed}
		}
	}
	for _, candidate := range states {
		if candidate.State == deployStatePass {
			return DeployPreflightCapability{State: deployStatePass}
		}
	}
	for _, candidate := range states {
		if candidate.State == deployStateUnknown {
			return DeployPreflightCapability{State: deployStateUnknown, Reason: candidate.Reason}
		}
	}
	for _, candidate := range states {
		if candidate.State == deployStateDenied {
			if candidate.Reason != "" {
				return DeployPreflightCapability{State: deployStateDenied, Reason: candidate.Reason}
			}
			return DeployPreflightCapability{State: deployStateDenied}
		}
	}
	for _, candidate := range states {
		if candidate.Reason != "" {
			return DeployPreflightCapability{State: deployStateFail, Reason: candidate.Reason}
		}
	}
	return DeployPreflightCapability{State: deployStateFail, Reason: "no comment target is currently viable"}
}

func graphQLErrorsContainNotFound(graphQLErrors []graphQLError) bool {
	for _, err := range graphQLErrors {
		if err.Type == "NOT_FOUND" || strings.Contains(strings.ToLower(err.Message), "could not resolve") {
			return true
		}
	}
	return false
}

func (c *gitHubClient) executeGraphQL(ctx context.Context, query string, variables map[string]interface{}, data interface{}) ([]graphQLError, error) {
	body, err := json.Marshal(graphQLRequest{Query: query, Variables: variables})
	if err != nil {
		return nil, fmt.Errorf("marshal graphql request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphqlURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create graphql request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	httpClient := c.client.Client()
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clientCopy := *httpClient
	clientCopy.Timeout = 30 * time.Second
	resp, err := clientCopy.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute graphql request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("graphql returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result graphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode graphql response: %w", err)
	}
	if data != nil && len(result.Data) > 0 {
		if err := json.Unmarshal(result.Data, data); err != nil {
			return result.Errors, fmt.Errorf("decode graphql data: %w", err)
		}
	}
	return result.Errors, nil
}

func (c *gitHubClient) getRepoGraphQLFlags(ctx context.Context, owner, repo string) (hasIssues, hasPullRequests bool, err error) {
	const query = `query RepoFlags($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { hasIssuesEnabled hasPullRequestsEnabled } }`
	var data struct {
		Repository *struct {
			HasIssuesEnabled       bool `json:"hasIssuesEnabled"`
			HasPullRequestsEnabled bool `json:"hasPullRequestsEnabled"`
		} `json:"repository"`
	}
	gqlErrors, err := c.executeGraphQL(ctx, query, map[string]interface{}{"owner": owner, "repo": repo}, &data)
	if err != nil {
		return false, false, err
	}
	if len(gqlErrors) > 0 {
		return false, false, errors.New(gqlErrors[0].Message)
	}
	if data.Repository == nil {
		return false, false, fmt.Errorf("repository not found")
	}
	return data.Repository.HasIssuesEnabled, data.Repository.HasPullRequestsEnabled, nil
}

func (c *gitHubClient) getRepoPreflightMetadata(ctx context.Context, owner, repo string) (*repoPreflightMetadata, error) {
	req, err := c.client.NewRequest(http.MethodGet, fmt.Sprintf("repos/%s/%s", owner, repo), nil)
	if err != nil {
		return nil, fmt.Errorf("build repository metadata request: %w", err)
	}
	var metadata repoPreflightMetadata
	_, err = c.client.Do(ctx, req, &metadata)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (c *gitHubClient) issueExists(ctx context.Context, owner, repo string, number int) (bool, error) {
	const query = `query IssueExists($owner: String!, $repo: String!, $issueNumber: Int!) { repository(owner: $owner, name: $repo) { issue(number: $issueNumber) { number } } }`
	var data struct {
		Repository *struct {
			Issue *struct {
				Number int `json:"number"`
			} `json:"issue"`
		} `json:"repository"`
	}
	gqlErrors, err := c.executeGraphQL(ctx, query, map[string]interface{}{"owner": owner, "repo": repo, "issueNumber": number}, &data)
	if err != nil {
		return false, err
	}
	if graphQLErrorsContainNotFound(gqlErrors) {
		return false, nil
	}
	if len(gqlErrors) > 0 {
		return false, errors.New(gqlErrors[0].Message)
	}
	return data.Repository != nil && data.Repository.Issue != nil, nil
}

func (c *gitHubClient) pullRequestExists(ctx context.Context, owner, repo string, number int) (bool, error) {
	const query = `query PullRequestExists($owner: String!, $repo: String!, $prNumber: Int!) { repository(owner: $owner, name: $repo) { pullRequest(number: $prNumber) { number } } }`
	var data struct {
		Repository *struct {
			PullRequest *struct {
				Number int `json:"number"`
			} `json:"pullRequest"`
		} `json:"repository"`
	}
	gqlErrors, err := c.executeGraphQL(ctx, query, map[string]interface{}{"owner": owner, "repo": repo, "prNumber": number}, &data)
	if err != nil {
		return false, err
	}
	if graphQLErrorsContainNotFound(gqlErrors) {
		return false, nil
	}
	if len(gqlErrors) > 0 {
		return false, errors.New(gqlErrors[0].Message)
	}
	return data.Repository != nil && data.Repository.PullRequest != nil, nil
}

func buildDeployPreflightChecks(signals deployPreflightSignals) []DeployPreflightCheck {
	if !signals.repoAccessible {
		return []DeployPreflightCheck{
			newDeployCheck("repo_access", deployStateFail, "repository is not accessible with this token"),
		}
	}
	checks := []DeployPreflightCheck{
		newDeployCheck("repo_access", deployStatePass, ""),
	}
	if signals.issuesEnabled {
		checks = append(checks, newDeployCheck("issues_enabled", deployStatePass, ""))
	} else {
		checks = append(checks, newDeployCheck("issues_enabled", deployStateFail, "issues are disabled on this repository"))
	}
	if signals.pullRequestsEnabled {
		checks = append(checks, newDeployCheck("pull_requests_enabled", deployStatePass, ""))
	} else {
		checks = append(checks, newDeployCheck("pull_requests_enabled", deployStateFail, "pull requests are disabled on this repository"))
	}
	if signals.allowForking {
		checks = append(checks, newDeployCheck("forking_allowed", deployStatePass, ""))
	} else {
		checks = append(checks, newDeployCheck("forking_allowed", deployStateFail, "forking is disabled on this repository"))
	}
	if signals.workflowKnown {
		if signals.workflowVisible {
			checks = append(checks, newDeployCheck("workflow_visible", deployStatePass, ""))
		} else {
			checks = append(checks, newDeployCheck("workflow_visible", deployStateFail, "workflow file is not accessible with this token"))
		}
	}
	if signals.issueChecked {
		if signals.issueExists {
			checks = append(checks, newDeployCheck("issue_exists", deployStatePass, ""))
		} else {
			checks = append(checks, newDeployCheck("issue_exists", deployStateFail, "issue target does not exist"))
		}
	}
	if signals.prChecked {
		if signals.prExists {
			checks = append(checks, newDeployCheck("pull_request_exists", deployStatePass, ""))
		} else {
			checks = append(checks, newDeployCheck("pull_request_exists", deployStateFail, "pull request target does not exist"))
		}
	}
	return checks
}

func buildDeployPreflightCapabilities(req DeployPreflightRequest, signals deployPreflightSignals, evidence deployPreflightEvidence) map[string]DeployPreflightCapability {
	capabilities := make(map[string]DeployPreflightCapability)
	if !signals.repoAccessible {
		reason := "repository is not accessible with this token"
		capabilities[deployCapabilityIssue] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityCommentIssue] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityCommentPR] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityCommentStub] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityCommentAny] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityPR] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityLOTP] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		capabilities[deployCapabilityDispatch] = DeployPreflightCapability{State: deployStateFail, Reason: reason}
		return capabilities
	}

	issueCheck := newDeployCheck("issues_enabled", deployStatePass, "")
	if !signals.issuesEnabled {
		issueCheck = newDeployCheck("issues_enabled", deployStateFail, "issues are disabled on this repository")
	}
	prsCheck := newDeployCheck("pull_requests_enabled", deployStatePass, "")
	if !signals.pullRequestsEnabled {
		prsCheck = newDeployCheck("pull_requests_enabled", deployStateFail, "pull requests are disabled on this repository")
	}
	workflowCheck := newDeployCheck("workflow_visible", deployStatePass, "")
	if signals.workflowKnown && !signals.workflowVisible {
		workflowCheck = newDeployCheck("workflow_visible", deployStateFail, "workflow file is not accessible with this token")
	}
	issueExistsCheck := newDeployCheck("issue_exists", deployStatePass, "")
	if signals.issueChecked && !signals.issueExists {
		issueExistsCheck = newDeployCheck("issue_exists", deployStateFail, "issue target does not exist")
	}
	prExistsCheck := newDeployCheck("pull_request_exists", deployStatePass, "")
	if signals.prChecked && !signals.prExists {
		prExistsCheck = newDeployCheck("pull_request_exists", deployStateFail, "pull request target does not exist")
	}

	issueBase := capabilityFromChecks(evidence.issueCapability(signals.repoPrivate), issueCheck)
	capabilities[deployCapabilityIssue] = issueBase

	commentIssue := capabilityFromChecks(evidence.commentCapability(signals.repoPrivate), issueCheck, issueExistsCheck)
	commentPR := capabilityFromChecks(evidence.commentCapability(signals.repoPrivate), prsCheck, prExistsCheck)
	commentStub := capabilityFromChecks(evidence.pullRequestCapability(signals.repoPrivate), prsCheck)
	capabilities[deployCapabilityCommentIssue] = commentIssue
	capabilities[deployCapabilityCommentPR] = commentPR
	capabilities[deployCapabilityCommentStub] = commentStub
	capabilities[deployCapabilityCommentAny] = mergeCommentAny(commentIssue, commentPR, commentStub)

	capabilities[deployCapabilityPR] = applyForkingCapability(req, evidence, signals, capabilityFromChecks(evidence.pullRequestCapability(signals.repoPrivate), prsCheck))
	capabilities[deployCapabilityLOTP] = applyForkingCapability(req, evidence, signals, capabilityFromChecks(evidence.pullRequestCapability(signals.repoPrivate), prsCheck))
	capabilities[deployCapabilityDispatch] = capabilityFromChecks(evidence.dispatchCapability(signals.repoPrivate), workflowCheck)

	return capabilities
}

func applyForkingCapability(req DeployPreflightRequest, evidence deployPreflightEvidence, signals deployPreflightSignals, capability DeployPreflightCapability) DeployPreflightCapability {
	if signals.allowForking {
		return capability
	}
	repoOwner, _, _ := strings.Cut(req.Vuln.Repository, "/")
	tokenOwner := strings.TrimSpace(evidence.tokenOwner)
	if tokenOwner == "" {
		switch capability.State {
		case deployStatePass, deployStateConfirmed:
			return DeployPreflightCapability{State: deployStateUnknown, Reason: "Direct push access could not be pre-verified"}
		default:
			return capability
		}
	}
	if strings.EqualFold(tokenOwner, repoOwner) {
		return capability
	}
	return capabilityFromChecks(capability, newDeployCheck("forking_allowed", deployStateFail, "forking is disabled on this repository"))
}

func (h *Handler) evaluateDeployPreflight(ctx context.Context, req DeployPreflightRequest) (DeployPreflightResponse, error) {
	owner, repo, err := parseRepoFullName(req.Vuln.Repository)
	if err != nil {
		return DeployPreflightResponse{}, fmt.Errorf("invalid repository: %w", err)
	}

	client := newGitHubClient(req.Token)
	repoInfo, err := client.getRepoPreflightMetadata(ctx, owner, repo)
	if err != nil {
		if isGitHubRepoAccessFailure(err) {
			signals := deployPreflightSignals{}
			evidence := deployPreflightEvidence{
				tokenType:        req.TokenType,
				tokenOwner:       req.TokenOwner,
				scopes:           append([]string(nil), req.Scopes...),
				knownPermissions: mapsClone(req.KnownPermissions),
			}
			if evidence.tokenType == "" {
				evidence.tokenType = detectTokenTypePrefix(req.Token)
			}
			return DeployPreflightResponse{
				Capabilities: buildDeployPreflightCapabilities(req, signals, evidence),
				Checks:       buildDeployPreflightChecks(signals),
			}, nil
		}
		return DeployPreflightResponse{}, fmt.Errorf("failed to access repository: %w", err)
	}

	signals := deployPreflightSignals{
		repoAccessible:      true,
		repoPrivate:         repoInfo.Private,
		issuesEnabled:       repoInfo.HasIssues,
		pullRequestsEnabled: true,
		allowForking:        repoInfo.AllowForking,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	recordErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		hasIssues, hasPRs, err := client.getRepoGraphQLFlags(ctx, owner, repo)
		if err != nil {
			recordErr(fmt.Errorf("failed to query repository flags: %w", err))
			return
		}
		mu.Lock()
		signals.issuesEnabled = signals.issuesEnabled && hasIssues
		signals.pullRequestsEnabled = hasPRs
		mu.Unlock()
	}()

	workflowFile := normalizeDispatchWorkflow(req.Vuln.Workflow)
	if workflowFile != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := client.getWorkflowByFileName(ctx, owner, repo, workflowFile)
			if err != nil && !isGitHubForbiddenOrNotFound(err) {
				recordErr(fmt.Errorf("failed to query workflow target: %w", err))
				return
			}
			mu.Lock()
			signals.workflowKnown = true
			signals.workflowVisible = err == nil
			mu.Unlock()
		}()
	}

	if req.IssueNumber > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exists, err := client.issueExists(ctx, owner, repo, req.IssueNumber)
			if err != nil {
				recordErr(fmt.Errorf("failed to query issue target: %w", err))
				return
			}
			mu.Lock()
			signals.issueChecked = true
			signals.issueExists = exists
			mu.Unlock()
		}()
	}

	if req.PRNumber > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exists, err := client.pullRequestExists(ctx, owner, repo, req.PRNumber)
			if err != nil {
				recordErr(fmt.Errorf("failed to query pull request target: %w", err))
				return
			}
			mu.Lock()
			signals.prChecked = true
			signals.prExists = exists
			mu.Unlock()
		}()
	}

	wg.Wait()
	if firstErr != nil {
		return DeployPreflightResponse{}, firstErr
	}

	evidence := deployPreflightEvidence{
		tokenType:        req.TokenType,
		tokenOwner:       req.TokenOwner,
		scopes:           append([]string(nil), req.Scopes...),
		knownPermissions: mapsClone(req.KnownPermissions),
	}
	if evidence.tokenType == "" {
		evidence.tokenType = detectTokenTypePrefix(req.Token)
	}

	response := DeployPreflightResponse{
		Capabilities: buildDeployPreflightCapabilities(req, signals, evidence),
		Checks:       buildDeployPreflightChecks(signals),
	}
	return response, nil
}

func isGitHubForbiddenOrNotFound(err error) bool {
	var ghErr *github.ErrorResponse
	if !errors.As(err, &ghErr) || ghErr.Response == nil {
		return false
	}
	switch ghErr.Response.StatusCode {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func mapsClone(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func mergeObservedCapabilities(req DeployPreflightRequest, response DeployPreflightResponse, cache *deployPreflightCache, now time.Time) DeployPreflightResponse {
	merged := cloneDeployPreflightResponse(response)
	for capability, current := range merged.Capabilities {
		if shouldPreserveCurrentCapability(req, capability, current) {
			continue
		}
		lookup := observedCapabilityLookup(req, capability)
		if observed, ok := cache.getObserved(observedCapabilityCacheKey(req.Token, req.Vuln.Repository, lookup), now); ok {
			current.State = observed.state
			current.Reason = observed.reason
			merged.Capabilities[capability] = current
		}
	}
	commentIssue := merged.Capabilities[deployCapabilityCommentIssue]
	commentPR := merged.Capabilities[deployCapabilityCommentPR]
	commentStub := merged.Capabilities[deployCapabilityCommentStub]
	merged.Capabilities[deployCapabilityCommentAny] = mergeCommentAny(commentIssue, commentPR, commentStub)
	return merged
}

func shouldPreserveCurrentCapability(req DeployPreflightRequest, capability string, current DeployPreflightCapability) bool {
	if current.State != deployStateFail {
		return false
	}
	switch capability {
	case deployCapabilityCommentIssue:
		return req.IssueNumber > 0 && current.Reason == "issue target does not exist"
	case deployCapabilityCommentPR:
		return req.PRNumber > 0 && current.Reason == "pull request target does not exist"
	default:
		return false
	}
}

func shouldRecordObservedDenied(err error) bool {
	var ghErr *github.ErrorResponse
	if !errors.As(err, &ghErr) || ghErr.Response == nil {
		return false
	}
	switch ghErr.Response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

func shouldRecordObservedSuccess(err error) bool {
	return err == nil
}

func isGitHubRepoAccessFailure(err error) bool {
	var ghErr *github.ErrorResponse
	if !errors.As(err, &ghErr) || ghErr.Response == nil {
		return false
	}
	switch ghErr.Response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func commentObservedCapability(target string) string {
	switch strings.TrimSpace(target) {
	case "pull_request":
		return deployCapabilityCommentPR
	case "stub_pull_request":
		return deployCapabilityCommentStub
	default:
		return deployCapabilityCommentIssue
	}
}

func (h *Handler) recordObservedCapability(token, repository, capability string, err error) {
	if token == "" || repository == "" || capability == "" {
		return
	}
	now := time.Now()
	cache := h.preflightCache
	switch {
	case shouldRecordObservedDenied(err):
		cache.putObserved(observedCapabilityCacheKey(token, repository, capability), deployStateDenied, err.Error(), now)
	case shouldRecordObservedSuccess(err):
		cache.putObserved(observedCapabilityCacheKey(token, repository, capability), deployStateConfirmed, "", now)
	}
}

func (h *Handler) handleGitHubDeployPreflight(w http.ResponseWriter, r *http.Request) {
	var req DeployPreflightRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	if req.Vuln.Repository == "" {
		http.Error(w, "vuln.repository is required", http.StatusBadRequest)
		return
	}

	now := time.Now()
	cache := h.preflightCache
	cacheKey := deployPreflightCacheKey(req)
	if cached, ok := cache.getPreflight(cacheKey, now); ok {
		cached.CacheHit = true
		cached = mergeObservedCapabilities(req, cached, cache, now)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cached)
		return
	}

	response, err := h.evaluateDeployPreflight(r.Context(), req)
	if err != nil {
		writeGitHubError(w, fmt.Errorf("preflight: %w", err))
		return
	}

	cache.putPreflight(cacheKey, response, now)
	response = mergeObservedCapabilities(req, response, cache, now)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
