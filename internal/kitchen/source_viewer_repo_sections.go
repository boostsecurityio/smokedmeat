// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v59/github"
)

const (
	sourceViewerMaxLogBytes      = 256 * 1024
	sourceViewerRepoListPageSize = 30
)

type sourceBranchEntry struct {
	Name      string
	SHA       string
	Protected bool
}

type sourceTagEntry struct {
	Name string
	SHA  string
}

type sourceReleaseEntry struct {
	Name       string
	TagName    string
	Draft      bool
	Prerelease bool
	HTMLURL    string
	Published  time.Time
}

type sourceRunEntry struct {
	ID         int64
	Name       string
	Title      string
	Branch     string
	Event      string
	Status     string
	Conclusion string
	Actor      string
	RunNumber  int
	RunAttempt int
	HTMLURL    string
	CreatedAt  time.Time
	StartedAt  time.Time
}

type sourceRunnerEntry struct {
	ID     int64
	Name   string
	OS     string
	Status string
	Busy   bool
	Labels []string
}

type sourceActionCacheEntry struct {
	ID             int64
	Key            string
	Ref            string
	Version        string
	SizeInBytes    int64
	CreatedAt      time.Time
	LastAccessedAt time.Time
}

type sourceCacheUsageEntry struct {
	ActiveSizeInBytes int64
	ActiveCount       int
}

type sourceIssueEntry struct {
	Number      int
	Title       string
	State       string
	StateReason string
	Author      string
	Comments    int
	Labels      []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type sourceIssueDetail struct {
	Issue        sourceIssueEntry
	Body         string
	HTMLURL      string
	Comments     []sourceDiscussionEntry
	CommentError string
}

type sourcePullRequestEntry struct {
	Number         int
	Title          string
	State          string
	Author         string
	Draft          bool
	Merged         bool
	Comments       int
	ReviewComments int
	Commits        int
	ChangedFiles   int
	Additions      int
	Deletions      int
	BaseRef        string
	HeadRef        string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type sourcePullRequestDetail struct {
	Pull               sourcePullRequestEntry
	Body               string
	HTMLURL            string
	IssueComments      []sourceDiscussionEntry
	Reviews            []sourceDiscussionEntry
	ReviewComments     []sourceDiscussionEntry
	IssueCommentError  string
	ReviewError        string
	ReviewCommentError string
}

type sourceDiscussionEntry struct {
	Type        string
	Name        string
	Body        string
	Href        string
	State       string
	Author      string
	Path        string
	Line        int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Association string
}

type sourcePagination struct {
	Page     int
	PrevPage int
	NextPage int
}

type sourceEnvironmentEntry struct {
	Name                 string
	HTMLURL              string
	WaitTimer            int
	Reviewers            int
	ProtectionRules      int
	ProtectedBranches    bool
	CustomBranchPolicies bool
	AdminsBypass         string
	BranchPolicy         string
	ReviewerDetails      []string
	ProtectionDetails    []string
	UpdatedAt            time.Time
}

type sourceRulesetEntry struct {
	ID            int64
	Name          string
	Source        string
	SourceType    string
	Target        string
	Enforcement   string
	Rules         int
	Includes      []string
	Excludes      []string
	RepoIncludes  []string
	RepoExcludes  []string
	RepoProtected string
	RepositoryIDs []int64
	BypassActors  []string
	RuleDetails   []string
}

type sourceJobEntry struct {
	ID          int64
	Name        string
	Status      string
	Conclusion  string
	HTMLURL     string
	Labels      []string
	StartedAt   time.Time
	CompletedAt time.Time
	Steps       []sourceJobStepEntry
}

type sourceJobStepEntry struct {
	Name       string
	Status     string
	Conclusion string
	Number     int64
}

type sourceLogResponse struct {
	Owner     string
	Repo      string
	JobID     int64
	Content   string
	Truncated bool
}

func (h *Handler) handleSourceBranchesViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	branches, err := fetchGitHubSourceBranches(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Branches", "branches", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerBranchesPage(req, branches))
}

func (h *Handler) handleSourceTagsViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	tags, err := fetchGitHubSourceTags(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Tags", "tags", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerTagsPage(req, tags))
}

func (h *Handler) handleSourceReleasesViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	releases, err := fetchGitHubSourceReleases(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Releases", "releases", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerReleasesPage(req, releases))
}

func (h *Handler) handleSourceActionsViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	h.attachSourceActionFilters(r, &req)
	runs, err := fetchGitHubSourceRuns(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Actions", "actions", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerActionsPage(req, runs))
}

func (h *Handler) handleSourceActionRunnersViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	runners, err := fetchGitHubSourceRunners(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Runners", "actions", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerActionRunnersPage(req, runners))
}

func (h *Handler) handleSourceActionCachesViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	caches, usage, err := fetchGitHubSourceCaches(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Caches", "actions", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerActionCachesPage(req, caches, usage))
}

func (h *Handler) handleSourceIssuesViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	state := sourceViewerListState(r)
	page := sourceViewerListPage(r)
	issues, pagination, err := fetchGitHubSourceIssues(r.Context(), req, state, page)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Issues", "issues", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerIssuesPage(req, issues, state, pagination))
}

func (h *Handler) handleSourceIssueViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	number, err := strconv.Atoi(r.PathValue("issue_number"))
	if err != nil || number <= 0 {
		h.writeSourceHTMLPage(w, http.StatusBadRequest, sourceViewerErrorPage(req, "invalid issue number"))
		return
	}
	issue, err := fetchGitHubSourceIssue(r.Context(), req, number)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, fmt.Sprintf("Issue #%d", number), "issues", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerIssuePage(req, issue))
}

func (h *Handler) handleSourcePullRequestsViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	state := sourceViewerListState(r)
	page := sourceViewerListPage(r)
	pulls, pagination, err := fetchGitHubSourcePullRequests(r.Context(), req, state, page)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Pull requests", "pulls", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerPullRequestsPage(req, pulls, state, pagination))
}

func (h *Handler) handleSourcePullRequestViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	number, err := strconv.Atoi(r.PathValue("pull_number"))
	if err != nil || number <= 0 {
		h.writeSourceHTMLPage(w, http.StatusBadRequest, sourceViewerErrorPage(req, "invalid pull request number"))
		return
	}
	pull, err := fetchGitHubSourcePullRequest(r.Context(), req, number)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, fmt.Sprintf("Pull request #%d", number), "pulls", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerPullRequestPage(req, pull))
}

func (h *Handler) handleSourceEnvironmentsViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	environments, err := fetchGitHubSourceEnvironments(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Environments", "environments", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerEnvironmentsPage(req, environments))
}

func (h *Handler) handleSourceRulesetsViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	rulesets, err := fetchGitHubSourceRulesets(r.Context(), req)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Rulesets", "rulesets", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerRulesetsPage(req, rulesets))
}

func (h *Handler) handleSourceActionRunViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	runID, err := strconv.ParseInt(r.PathValue("run_id"), 10, 64)
	if err != nil || runID <= 0 {
		h.writeSourceHTMLPage(w, http.StatusBadRequest, sourceViewerErrorPage(req, "invalid workflow run id"))
		return
	}
	run, jobs, err := fetchGitHubSourceRun(r.Context(), req, runID)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Workflow run", "actions", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerActionRunPage(req, run, jobs))
}

func (h *Handler) handleSourceActionJobLogViewer(w http.ResponseWriter, r *http.Request) {
	req := h.sourceViewerRepoRequest(r)
	jobID, err := strconv.ParseInt(r.PathValue("job_id"), 10, 64)
	if err != nil || jobID <= 0 {
		h.writeSourceHTMLPage(w, http.StatusBadRequest, sourceViewerErrorPage(req, "invalid workflow job id"))
		return
	}
	logs, err := fetchGitHubSourceJobLogs(r.Context(), req, jobID)
	if err != nil {
		h.writeSourceHTMLPage(w, http.StatusOK, h.sourceViewerUnavailablePage(req, "Job logs", "actions", err))
		return
	}
	h.writeSourceHTMLPage(w, http.StatusOK, sourceViewerJobLogPage(req, logs))
}

func (h *Handler) sourceViewerRepoRequest(r *http.Request) SourceContentRequest {
	req := SourceContentRequest{
		Host:      "github.com",
		Owner:     r.PathValue("owner"),
		Repo:      r.PathValue("repo"),
		SessionID: sourceViewerSessionID(r),
	}
	h.attachSourceToken(r, &req)
	return req
}

func (h *Handler) attachSourceActionFilters(r *http.Request, req *SourceContentRequest) {
	query := r.URL.Query()
	req.ActionActor = strings.TrimSpace(query.Get("actor"))
	req.ActionBranch = strings.TrimSpace(query.Get("branch"))
	req.ActionCreated = strings.TrimSpace(query.Get("created"))
	req.ActionEvent = strings.TrimSpace(query.Get("event"))
	req.ActionStatus = strings.TrimSpace(query.Get("status"))
}

func fetchGitHubSourceBranches(ctx context.Context, req SourceContentRequest) ([]sourceBranchEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.BranchListOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var all []sourceBranchEntry
	for {
		branches, resp, err := client.client.Repositories.ListBranches(ctx, req.Owner, req.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, branch := range branches {
			entry := sourceBranchEntry{Name: branch.GetName(), Protected: branch.GetProtected()}
			if branch.Commit != nil {
				entry.SHA = branch.Commit.GetSHA()
			}
			all = append(all, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceTags(ctx context.Context, req SourceContentRequest) ([]sourceTagEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.ListOptions{PerPage: 100}
	var all []sourceTagEntry
	for {
		tags, resp, err := client.client.Repositories.ListTags(ctx, req.Owner, req.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, tag := range tags {
			entry := sourceTagEntry{Name: tag.GetName()}
			if tag.Commit != nil {
				entry.SHA = tag.Commit.GetSHA()
			}
			all = append(all, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceReleases(ctx context.Context, req SourceContentRequest) ([]sourceReleaseEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.ListOptions{PerPage: 50}
	var all []sourceReleaseEntry
	for {
		releases, resp, err := client.client.Repositories.ListReleases(ctx, req.Owner, req.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, release := range releases {
			entry := sourceReleaseEntry{
				Name:       sourceViewerFallback(release.GetName(), release.GetTagName()),
				TagName:    release.GetTagName(),
				Draft:      release.GetDraft(),
				Prerelease: release.GetPrerelease(),
				HTMLURL:    release.GetHTMLURL(),
			}
			if release.PublishedAt != nil {
				entry.Published = release.PublishedAt.Time
			}
			all = append(all, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceRuns(ctx context.Context, req SourceContentRequest) ([]sourceRunEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.ListWorkflowRunsOptions{
		Actor:       req.ActionActor,
		Branch:      req.ActionBranch,
		Created:     req.ActionCreated,
		Event:       req.ActionEvent,
		Status:      req.ActionStatus,
		ListOptions: github.ListOptions{PerPage: 50},
	}
	runs, _, err := client.client.Actions.ListRepositoryWorkflowRuns(ctx, req.Owner, req.Repo, opts)
	if err != nil {
		return nil, err
	}
	return sourceRunEntries(runs.WorkflowRuns), nil
}

func fetchGitHubSourceRunners(ctx context.Context, req SourceContentRequest) ([]sourceRunnerEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.ListOptions{PerPage: 100}
	var all []sourceRunnerEntry
	for {
		runners, resp, err := client.client.Actions.ListRunners(ctx, req.Owner, req.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, runner := range runners.Runners {
			all = append(all, sourceRunnerEntry{
				ID:     runner.GetID(),
				Name:   runner.GetName(),
				OS:     runner.GetOS(),
				Status: runner.GetStatus(),
				Busy:   runner.GetBusy(),
				Labels: sourceRunnerLabels(runner.Labels),
			})
		}
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceCaches(ctx context.Context, req SourceContentRequest) ([]sourceActionCacheEntry, sourceCacheUsageEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	sortBy := "last_accessed_at"
	direction := "desc"
	opts := &github.ActionsCacheListOptions{Sort: &sortBy, Direction: &direction, ListOptions: github.ListOptions{PerPage: 100}}
	caches, _, err := client.client.Actions.ListCaches(ctx, req.Owner, req.Repo, opts)
	if err != nil {
		return nil, sourceCacheUsageEntry{}, err
	}
	entries := make([]sourceActionCacheEntry, 0, len(caches.ActionsCaches))
	for _, cache := range caches.ActionsCaches {
		entry := sourceActionCacheEntry{
			ID:          cache.GetID(),
			Key:         cache.GetKey(),
			Ref:         cache.GetRef(),
			Version:     cache.GetVersion(),
			SizeInBytes: cache.GetSizeInBytes(),
		}
		if cache.CreatedAt != nil {
			entry.CreatedAt = cache.CreatedAt.Time
		}
		if cache.LastAccessedAt != nil {
			entry.LastAccessedAt = cache.LastAccessedAt.Time
		}
		entries = append(entries, entry)
	}
	usage := sourceCacheUsageEntry{}
	if cacheUsage, _, usageErr := client.client.Actions.GetCacheUsageForRepo(ctx, req.Owner, req.Repo); usageErr == nil {
		usage.ActiveCount = cacheUsage.ActiveCachesCount
		usage.ActiveSizeInBytes = cacheUsage.ActiveCachesSizeInBytes
	}
	return entries, usage, nil
}

func fetchGitHubSourceIssues(ctx context.Context, req SourceContentRequest, state string, page int) ([]sourceIssueEntry, sourcePagination, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * sourceViewerRepoListPageSize
	end := start + sourceViewerRepoListPageSize
	opts := &github.IssueListByRepoOptions{
		State:       state,
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	entries := make([]sourceIssueEntry, 0, end+1)
	for {
		issues, resp, err := client.client.Issues.ListByRepo(ctx, req.Owner, req.Repo, opts)
		if err != nil {
			return nil, sourcePagination{}, err
		}
		for _, issue := range issues {
			if issue.IsPullRequest() {
				continue
			}
			entries = append(entries, sourceIssueEntryFromGitHub(issue))
			if len(entries) > end {
				return sourceIssuePage(entries, start, end), sourceIssuePagination(page, true), nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			return sourceIssuePage(entries, start, end), sourceIssuePagination(page, false), nil
		}
		opts.Page = resp.NextPage
	}
}

func sourceIssuePage(entries []sourceIssueEntry, start, end int) []sourceIssueEntry {
	if start >= len(entries) {
		return nil
	}
	if end > len(entries) {
		end = len(entries)
	}
	return entries[start:end]
}

func sourceIssuePagination(page int, hasNext bool) sourcePagination {
	pagination := sourcePagination{Page: page}
	if page > 1 {
		pagination.PrevPage = page - 1
	}
	if hasNext {
		pagination.NextPage = page + 1
	}
	return pagination
}

func fetchGitHubSourceIssue(ctx context.Context, req SourceContentRequest, number int) (sourceIssueDetail, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	issue, _, err := client.client.Issues.Get(ctx, req.Owner, req.Repo, number)
	if err != nil {
		return sourceIssueDetail{}, err
	}
	detail := sourceIssueDetail{
		Issue:   sourceIssueEntryFromGitHub(issue),
		Body:    issue.GetBody(),
		HTMLURL: issue.GetHTMLURL(),
	}
	detail.Comments, err = fetchGitHubSourceIssueComments(ctx, client, req, number)
	if err != nil {
		detail.CommentError = err.Error()
	}
	return detail, nil
}

func fetchGitHubSourcePullRequests(ctx context.Context, req SourceContentRequest, state string, page int) ([]sourcePullRequestEntry, sourcePagination, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.PullRequestListOptions{
		State:       state,
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: github.ListOptions{PerPage: sourceViewerRepoListPageSize, Page: page},
	}
	pulls, resp, err := client.client.PullRequests.List(ctx, req.Owner, req.Repo, opts)
	if err != nil {
		return nil, sourcePagination{}, err
	}
	entries := make([]sourcePullRequestEntry, 0, len(pulls))
	for _, pull := range pulls {
		entries = append(entries, sourcePullRequestEntryFromGitHub(pull))
	}
	return entries, sourcePaginationFromResponse(page, resp), nil
}

func fetchGitHubSourcePullRequest(ctx context.Context, req SourceContentRequest, number int) (sourcePullRequestDetail, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	pull, _, err := client.client.PullRequests.Get(ctx, req.Owner, req.Repo, number)
	if err != nil {
		return sourcePullRequestDetail{}, err
	}
	detail := sourcePullRequestDetail{
		Pull:    sourcePullRequestEntryFromGitHub(pull),
		Body:    pull.GetBody(),
		HTMLURL: pull.GetHTMLURL(),
	}
	detail.IssueComments, err = fetchGitHubSourceIssueComments(ctx, client, req, number)
	if err != nil {
		detail.IssueCommentError = err.Error()
	}
	detail.Reviews, err = fetchGitHubSourcePullReviews(ctx, client, req, number)
	if err != nil {
		detail.ReviewError = err.Error()
	}
	detail.ReviewComments, err = fetchGitHubSourcePullReviewComments(ctx, client, req, number)
	if err != nil {
		detail.ReviewCommentError = err.Error()
	}
	return detail, nil
}

func fetchGitHubSourceIssueComments(ctx context.Context, client *gitHubClient, req SourceContentRequest, number int) ([]sourceDiscussionEntry, error) {
	sortBy := "created"
	direction := "asc"
	opts := &github.IssueListCommentsOptions{Sort: &sortBy, Direction: &direction, ListOptions: github.ListOptions{PerPage: 100}}
	var entries []sourceDiscussionEntry
	for {
		comments, resp, err := client.client.Issues.ListComments(ctx, req.Owner, req.Repo, number, opts)
		if err != nil {
			return entries, err
		}
		for _, comment := range comments {
			entry := sourceDiscussionEntry{
				Type:        "comment",
				Name:        sourceViewerFallback(sourceGitHubUserLogin(comment.User), "comment"),
				Body:        comment.GetBody(),
				Href:        comment.GetHTMLURL(),
				Author:      sourceGitHubUserLogin(comment.User),
				Association: comment.GetAuthorAssociation(),
			}
			if comment.CreatedAt != nil {
				entry.CreatedAt = comment.CreatedAt.Time
			}
			if comment.UpdatedAt != nil {
				entry.UpdatedAt = comment.UpdatedAt.Time
			}
			entries = append(entries, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return entries, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourcePullReviews(ctx context.Context, client *gitHubClient, req SourceContentRequest, number int) ([]sourceDiscussionEntry, error) {
	opts := &github.ListOptions{PerPage: 100}
	var entries []sourceDiscussionEntry
	for {
		reviews, resp, err := client.client.PullRequests.ListReviews(ctx, req.Owner, req.Repo, number, opts)
		if err != nil {
			return entries, err
		}
		for _, review := range reviews {
			entry := sourceDiscussionEntry{
				Type:        "review",
				Name:        sourceViewerFallback(sourceGitHubUserLogin(review.User), "review"),
				Body:        review.GetBody(),
				Href:        review.GetHTMLURL(),
				State:       strings.ToLower(review.GetState()),
				Author:      sourceGitHubUserLogin(review.User),
				Association: review.GetAuthorAssociation(),
			}
			if review.SubmittedAt != nil {
				entry.CreatedAt = review.SubmittedAt.Time
			}
			entries = append(entries, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return entries, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourcePullReviewComments(ctx context.Context, client *gitHubClient, req SourceContentRequest, number int) ([]sourceDiscussionEntry, error) {
	opts := &github.PullRequestListCommentsOptions{Sort: "created", Direction: "asc", ListOptions: github.ListOptions{PerPage: 100}}
	var entries []sourceDiscussionEntry
	for {
		comments, resp, err := client.client.PullRequests.ListComments(ctx, req.Owner, req.Repo, number, opts)
		if err != nil {
			return entries, err
		}
		for _, comment := range comments {
			entry := sourceDiscussionEntry{
				Type:        "review comment",
				Name:        sourceViewerFallback(sourceGitHubUserLogin(comment.User), "review comment"),
				Body:        comment.GetBody(),
				Href:        comment.GetHTMLURL(),
				Author:      sourceGitHubUserLogin(comment.User),
				Path:        comment.GetPath(),
				Line:        comment.GetLine(),
				Association: comment.GetAuthorAssociation(),
			}
			if comment.CreatedAt != nil {
				entry.CreatedAt = comment.CreatedAt.Time
			}
			if comment.UpdatedAt != nil {
				entry.UpdatedAt = comment.UpdatedAt.Time
			}
			entries = append(entries, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return entries, nil
		}
		opts.Page = resp.NextPage
	}
}

func sourceIssueEntryFromGitHub(issue *github.Issue) sourceIssueEntry {
	entry := sourceIssueEntry{
		Number:      issue.GetNumber(),
		Title:       issue.GetTitle(),
		State:       issue.GetState(),
		StateReason: issue.GetStateReason(),
		Comments:    issue.GetComments(),
		Labels:      sourceIssueLabels(issue.Labels),
	}
	if issue.User != nil {
		entry.Author = issue.User.GetLogin()
	}
	if issue.CreatedAt != nil {
		entry.CreatedAt = issue.CreatedAt.Time
	}
	if issue.UpdatedAt != nil {
		entry.UpdatedAt = issue.UpdatedAt.Time
	}
	return entry
}

func sourcePullRequestEntryFromGitHub(pull *github.PullRequest) sourcePullRequestEntry {
	entry := sourcePullRequestEntry{
		Number:         pull.GetNumber(),
		Title:          pull.GetTitle(),
		State:          pull.GetState(),
		Draft:          pull.GetDraft(),
		Merged:         pull.GetMerged(),
		Comments:       pull.GetComments(),
		ReviewComments: pull.GetReviewComments(),
		Commits:        pull.GetCommits(),
		ChangedFiles:   pull.GetChangedFiles(),
		Additions:      pull.GetAdditions(),
		Deletions:      pull.GetDeletions(),
	}
	if pull.User != nil {
		entry.Author = pull.User.GetLogin()
	}
	if pull.Base != nil {
		entry.BaseRef = pull.Base.GetRef()
	}
	if pull.Head != nil {
		entry.HeadRef = pull.Head.GetLabel()
		if entry.HeadRef == "" {
			entry.HeadRef = pull.Head.GetRef()
		}
	}
	if pull.CreatedAt != nil {
		entry.CreatedAt = pull.CreatedAt.Time
	}
	if pull.UpdatedAt != nil {
		entry.UpdatedAt = pull.UpdatedAt.Time
	}
	return entry
}

func sourcePaginationFromResponse(page int, resp *github.Response) sourcePagination {
	pagination := sourcePagination{Page: page}
	if pagination.Page <= 0 {
		pagination.Page = 1
	}
	if resp != nil {
		pagination.PrevPage = resp.PrevPage
		pagination.NextPage = resp.NextPage
	}
	if pagination.PrevPage == 0 && pagination.Page > 1 {
		pagination.PrevPage = pagination.Page - 1
	}
	return pagination
}

func sourceGitHubUserLogin(user *github.User) string {
	if user == nil {
		return ""
	}
	return user.GetLogin()
}

func fetchGitHubSourceEnvironments(ctx context.Context, req SourceContentRequest) ([]sourceEnvironmentEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	opts := &github.EnvironmentListOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var all []sourceEnvironmentEntry
	for {
		envs, resp, err := client.client.Repositories.ListEnvironments(ctx, req.Owner, req.Repo, opts)
		if err != nil {
			return nil, err
		}
		for _, env := range envs.Environments {
			entry := sourceEnvironmentEntry{
				Name:            env.GetName(),
				HTMLURL:         env.GetHTMLURL(),
				WaitTimer:       env.GetWaitTimer(),
				Reviewers:       len(env.Reviewers),
				ProtectionRules: len(env.ProtectionRules),
				AdminsBypass:    sourceBoolSetting(env.CanAdminsBypass),
			}
			if entry.Name == "" {
				entry.Name = env.GetEnvironmentName()
			}
			if env.DeploymentBranchPolicy != nil {
				entry.ProtectedBranches = env.DeploymentBranchPolicy.GetProtectedBranches()
				entry.CustomBranchPolicies = env.DeploymentBranchPolicy.GetCustomBranchPolicies()
				entry.BranchPolicy = sourceEnvironmentBranchPolicy(entry)
			}
			entry.ReviewerDetails = sourceEnvironmentReviewerDetails(env.Reviewers)
			entry.ProtectionDetails = sourceEnvironmentProtectionDetails(env.ProtectionRules)
			if env.UpdatedAt != nil {
				entry.UpdatedAt = env.UpdatedAt.Time
			}
			all = append(all, entry)
		}
		if resp == nil || resp.NextPage == 0 {
			return all, nil
		}
		opts.Page = resp.NextPage
	}
}

func fetchGitHubSourceRulesets(ctx context.Context, req SourceContentRequest) ([]sourceRulesetEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	rulesets, _, err := client.client.Repositories.GetAllRulesets(ctx, req.Owner, req.Repo, true)
	if err != nil {
		return nil, err
	}
	entries := make([]sourceRulesetEntry, 0, len(rulesets))
	for _, ruleset := range rulesets {
		entry := sourceRulesetEntry{
			ID:          ruleset.GetID(),
			Name:        ruleset.Name,
			Source:      ruleset.Source,
			SourceType:  ruleset.GetSourceType(),
			Target:      ruleset.GetTarget(),
			Enforcement: ruleset.Enforcement,
			Rules:       len(ruleset.Rules),
		}
		if ruleset.Conditions != nil && ruleset.Conditions.RefName != nil {
			entry.Includes = append([]string(nil), ruleset.Conditions.RefName.Include...)
			entry.Excludes = append([]string(nil), ruleset.Conditions.RefName.Exclude...)
		}
		if ruleset.Conditions != nil && ruleset.Conditions.RepositoryName != nil {
			entry.RepoIncludes = append([]string(nil), ruleset.Conditions.RepositoryName.Include...)
			entry.RepoExcludes = append([]string(nil), ruleset.Conditions.RepositoryName.Exclude...)
			entry.RepoProtected = sourceBoolSetting(ruleset.Conditions.RepositoryName.Protected)
		}
		if ruleset.Conditions != nil && ruleset.Conditions.RepositoryID != nil {
			entry.RepositoryIDs = append([]int64(nil), ruleset.Conditions.RepositoryID.RepositoryIDs...)
		}
		entry.BypassActors = sourceRulesetBypassActors(ruleset.BypassActors)
		entry.RuleDetails = sourceRulesetRuleDetails(ruleset.Rules)
		entries = append(entries, entry)
	}
	return entries, nil
}

func fetchGitHubSourceRun(ctx context.Context, req SourceContentRequest, runID int64) (sourceRunEntry, []sourceJobEntry, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	run, _, err := client.client.Actions.GetWorkflowRunByID(ctx, req.Owner, req.Repo, runID)
	if err != nil {
		return sourceRunEntry{}, nil, err
	}
	opts := &github.ListWorkflowJobsOptions{Filter: "all", ListOptions: github.ListOptions{PerPage: 100}}
	jobs, _, err := client.client.Actions.ListWorkflowJobs(ctx, req.Owner, req.Repo, runID, opts)
	if err != nil {
		return sourceRunEntry{}, nil, err
	}
	entries := sourceRunEntries([]*github.WorkflowRun{run})
	runEntry := sourceRunEntry{ID: runID}
	if len(entries) > 0 {
		runEntry = entries[0]
	}
	return runEntry, sourceJobEntries(jobs.Jobs), nil
}

func fetchGitHubSourceJobLogs(ctx context.Context, req SourceContentRequest, jobID int64) (sourceLogResponse, error) {
	client := newGitHubClient(strings.TrimSpace(req.Token))
	logURL, _, err := client.client.Actions.GetWorkflowJobLogs(ctx, req.Owner, req.Repo, jobID, 1)
	if err != nil {
		return sourceLogResponse{}, err
	}
	if logURL == nil || logURL.String() == "" {
		return sourceLogResponse{}, sourceRequestError("workflow job logs are unavailable")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, logURL.String(), http.NoBody)
	if err != nil {
		return sourceLogResponse{}, err
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return sourceLogResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return sourceLogResponse{}, fmt.Errorf("download workflow job logs: %s", resp.Status)
	}

	limited := io.LimitReader(resp.Body, sourceViewerMaxLogBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return sourceLogResponse{}, err
	}
	truncated := len(data) > sourceViewerMaxLogBytes
	if truncated {
		data = data[:sourceViewerMaxLogBytes]
	}
	return sourceLogResponse{
		Owner:     req.Owner,
		Repo:      req.Repo,
		JobID:     jobID,
		Content:   string(data),
		Truncated: truncated,
	}, nil
}

func sourceRunEntries(runs []*github.WorkflowRun) []sourceRunEntry {
	entries := make([]sourceRunEntry, 0, len(runs))
	for _, run := range runs {
		entry := sourceRunEntry{
			ID:         run.GetID(),
			Name:       run.GetName(),
			Title:      run.GetDisplayTitle(),
			Branch:     run.GetHeadBranch(),
			Event:      run.GetEvent(),
			Status:     run.GetStatus(),
			Conclusion: run.GetConclusion(),
			RunNumber:  run.GetRunNumber(),
			RunAttempt: run.GetRunAttempt(),
			HTMLURL:    run.GetHTMLURL(),
		}
		if run.Actor != nil {
			entry.Actor = run.Actor.GetLogin()
		}
		if run.CreatedAt != nil {
			entry.CreatedAt = run.CreatedAt.Time
		}
		if run.RunStartedAt != nil {
			entry.StartedAt = run.RunStartedAt.Time
		}
		entries = append(entries, entry)
	}
	return entries
}

func sourceJobEntries(jobs []*github.WorkflowJob) []sourceJobEntry {
	entries := make([]sourceJobEntry, 0, len(jobs))
	for _, job := range jobs {
		entry := sourceJobEntry{
			ID:         job.GetID(),
			Name:       job.GetName(),
			Status:     job.GetStatus(),
			Conclusion: job.GetConclusion(),
			HTMLURL:    job.GetHTMLURL(),
			Labels:     append([]string(nil), job.Labels...),
		}
		if job.StartedAt != nil {
			entry.StartedAt = job.StartedAt.Time
		}
		if job.CompletedAt != nil {
			entry.CompletedAt = job.CompletedAt.Time
		}
		for _, step := range job.Steps {
			entry.Steps = append(entry.Steps, sourceJobStepEntry{
				Name:       step.GetName(),
				Status:     step.GetStatus(),
				Conclusion: step.GetConclusion(),
				Number:     step.GetNumber(),
			})
		}
		entries = append(entries, entry)
	}
	return entries
}

func sourceViewerBranchesPage(req SourceContentRequest, branches []sourceBranchEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(branches))
	for _, branch := range branches {
		badges := []sourceViewerBadgeView{}
		if branch.Protected {
			badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: "protected"})
		}
		rows = append(rows, sourceViewerTableRow{
			Type:   "branch",
			Name:   branch.Name,
			Href:   sourceViewerRepoHref(req.Owner, req.Repo, sourceViewerQueryWithRef("", branch.Name)),
			Size:   sourceShortSHA(branch.SHA),
			Badges: badges,
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No branches found."))
	}
	return sourceViewerRepoTablePage(req, "Branches", "branches", "Branches", rows)
}

func sourceViewerTagsPage(req SourceContentRequest, tags []sourceTagEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(tags))
	for _, tag := range tags {
		rows = append(rows, sourceViewerTableRow{
			Type: "tag",
			Name: tag.Name,
			Href: sourceViewerRepoHref(req.Owner, req.Repo, sourceViewerQueryWithRef("", tag.Name)),
			Size: sourceShortSHA(tag.SHA),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No tags found."))
	}
	return sourceViewerRepoTablePage(req, "Tags", "tags", "Tags", rows)
}

func sourceViewerReleasesPage(req SourceContentRequest, releases []sourceReleaseEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(releases))
	for _, release := range releases {
		badges := []sourceViewerBadgeView{}
		if release.Draft {
			badges = append(badges, sourceViewerBadgeView{Kind: "medium", Label: "draft"})
		}
		if release.Prerelease {
			badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: "pre-release"})
		}
		rows = append(rows, sourceViewerTableRow{
			Type:        "release",
			Name:        release.Name,
			Href:        release.HTMLURL,
			Description: release.TagName,
			Size:        sourceTimeAgo(release.Published),
			Badges:      badges,
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No releases found."))
	}
	return sourceViewerRepoTablePage(req, "Releases", "releases", "Releases", rows)
}

func sourceViewerActionsPage(req SourceContentRequest, runs []sourceRunEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(runs))
	for _, run := range runs {
		rows = append(rows, sourceViewerTableRow{
			Type:   "run",
			Name:   sourceViewerFallback(run.Title, run.Name),
			Href:   sourceViewerActionRunHref(req.Owner, req.Repo, run.ID),
			Meta:   sourceRunMeta(run),
			Badges: sourceRunBadges(run),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No workflow runs found."))
	}
	page := sourceViewerRepoTablePage(req, "Actions", "actions", "Workflow runs", rows)
	page.Table.ActionLinks = sourceViewerActionLinks(req, "runs")
	page.Table.ActionsFilter = sourceViewerActionsFilter(req)
	return page
}

func sourceViewerActionRunnersPage(req SourceContentRequest, runners []sourceRunnerEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(runners))
	for _, runner := range runners {
		rows = append(rows, sourceViewerTableRow{
			Type:   "runner",
			Name:   runner.Name,
			Meta:   sourceRunnerMeta(runner),
			Badges: sourceRunnerBadges(runner),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No repository self-hosted runners found."))
	}
	page := sourceViewerRepoTablePage(req, "Runners", "actions", "Actions runners", rows)
	page.Table.ActionLinks = sourceViewerActionLinks(req, "runners")
	page.Header.GitHubURL = sourceViewerGitHubActionsSubURL(req.Owner, req.Repo, "runners")
	return page
}

func sourceViewerActionCachesPage(req SourceContentRequest, caches []sourceActionCacheEntry, usage sourceCacheUsageEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(caches))
	for _, cache := range caches {
		rows = append(rows, sourceViewerTableRow{
			Type:   "cache",
			Name:   cache.Key,
			Meta:   sourceCacheMeta(cache),
			Size:   sourceByteSize(cache.SizeInBytes),
			Badges: sourceCacheBadges(cache),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No Actions caches found."))
	}
	page := sourceViewerRepoTablePage(req, "Caches", "actions", "Actions caches", rows)
	page.Table.ActionLinks = sourceViewerActionLinks(req, "caches")
	if usage.ActiveCount > 0 || usage.ActiveSizeInBytes > 0 {
		page.Notices = append(page.Notices, sourceViewerNoticeView{
			Kind:    "info",
			Title:   "Cache usage",
			Message: fmt.Sprintf("%d active caches using %s.", usage.ActiveCount, sourceByteSize(usage.ActiveSizeInBytes)),
		})
	}
	page.Header.GitHubURL = sourceViewerGitHubActionsSubURL(req.Owner, req.Repo, "caches")
	return page
}

func sourceViewerIssuesPage(req SourceContentRequest, issues []sourceIssueEntry, state string, pagination sourcePagination) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(issues))
	for _, issue := range issues {
		rows = append(rows, sourceViewerTableRow{
			Type:   "issue",
			Name:   fmt.Sprintf("#%d %s", issue.Number, issue.Title),
			Href:   sourceViewerIssueHref(req.Owner, req.Repo, issue.Number),
			Meta:   sourceIssueMeta(issue),
			Badges: sourceIssueBadges(issue),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow(fmt.Sprintf("No %s issues found.", state)))
	}
	page := sourceViewerRepoTablePage(req, "Issues", "issues", "Issues", rows)
	page.Table.ActionLinks = sourceViewerStateLinks(req, "issues", state)
	page.Table.Pagination = sourceViewerPagination(req, "issues", state, pagination)
	return page
}

func sourceViewerIssuePage(req SourceContentRequest, detail sourceIssueDetail) sourceViewerPage {
	page := sourceViewerDiscussionPage(req, fmt.Sprintf("Issue #%d", detail.Issue.Number), "issues", sourceViewerIssueDiscussion(detail))
	page.Header.GitHubURL = detail.HTMLURL
	if detail.CommentError != "" {
		page.Notices = append(page.Notices, sourceViewerNoticeView{Kind: "warning", Title: "Comments unavailable", Message: "The issue loaded, but comments could not be fetched with the active token.", Detail: detail.CommentError})
	}
	return page
}

func sourceViewerPullRequestsPage(req SourceContentRequest, pulls []sourcePullRequestEntry, state string, pagination sourcePagination) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(pulls))
	for _, pull := range pulls {
		rows = append(rows, sourceViewerTableRow{
			Type:   "pr",
			Name:   fmt.Sprintf("#%d %s", pull.Number, pull.Title),
			Href:   sourceViewerPullRequestHref(req.Owner, req.Repo, pull.Number),
			Meta:   sourcePullRequestMeta(pull),
			Badges: sourcePullRequestBadges(pull),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow(fmt.Sprintf("No %s pull requests found.", state)))
	}
	page := sourceViewerRepoTablePage(req, "Pull requests", "pulls", "Pull requests", rows)
	page.Table.ActionLinks = sourceViewerStateLinks(req, "pulls", state)
	page.Table.Pagination = sourceViewerPagination(req, "pulls", state, pagination)
	return page
}

func sourceViewerPullRequestPage(req SourceContentRequest, detail sourcePullRequestDetail) sourceViewerPage {
	page := sourceViewerDiscussionPage(req, fmt.Sprintf("Pull request #%d", detail.Pull.Number), "pulls", sourceViewerPullRequestDiscussion(detail))
	page.Header.GitHubURL = detail.HTMLURL
	page.Notices = append(page.Notices, sourceViewerPullRequestDetailNotices(detail)...)
	return page
}

func sourceViewerDiscussionPage(req SourceContentRequest, title, active string, discussion sourceViewerDiscussionView) sourceViewerPage {
	return sourceViewerPage{
		Title:      title,
		Header:     sourceViewerRepoHeader(req.Owner, req.Repo, title, sourceViewerGitHubSectionURL(req.Owner, req.Repo, active)),
		Nav:        sourceViewerRepoNav(req.Owner, req.Repo, "", active),
		Notices:    sourceViewerTokenNotice(req),
		Discussion: &discussion,
	}
}

func sourceViewerIssueDiscussion(detail sourceIssueDetail) sourceViewerDiscussionView {
	view := sourceViewerDiscussionView{
		Kind:   "issue",
		Number: detail.Issue.Number,
		Title:  detail.Issue.Title,
		Body:   sourceViewerDiscussionMarkdown(detail.Body),
		Meta:   sourceIssueMeta(detail.Issue),
		Badges: sourceIssueBadges(detail.Issue),
	}
	for _, comment := range detail.Comments {
		view.Timeline = append(view.Timeline, sourceViewerDiscussionItem(comment))
	}
	return view
}

func sourceViewerPullRequestDiscussion(detail sourcePullRequestDetail) sourceViewerDiscussionView {
	view := sourceViewerDiscussionView{
		Kind:   "pull request",
		Number: detail.Pull.Number,
		Title:  detail.Pull.Title,
		Body:   sourceViewerDiscussionMarkdown(detail.Body),
		Meta:   sourcePullRequestMeta(detail.Pull),
		Badges: sourcePullRequestBadges(detail.Pull),
	}
	for _, comment := range detail.IssueComments {
		view.Timeline = append(view.Timeline, sourceViewerDiscussionItem(comment))
	}
	for _, review := range detail.Reviews {
		view.Timeline = append(view.Timeline, sourceViewerDiscussionItem(review))
	}
	for _, comment := range detail.ReviewComments {
		view.Timeline = append(view.Timeline, sourceViewerDiscussionItem(comment))
	}
	sort.SliceStable(view.Timeline, func(i, j int) bool {
		left := view.Timeline[i].CreatedAtTime
		right := view.Timeline[j].CreatedAtTime
		if left.Equal(right) {
			return view.Timeline[i].Type < view.Timeline[j].Type
		}
		if left.IsZero() {
			return false
		}
		if right.IsZero() {
			return true
		}
		return left.Before(right)
	})
	return view
}

func sourceViewerDiscussionItem(entry sourceDiscussionEntry) sourceViewerDiscussionItemView {
	meta := []sourceViewerTableMetaView{}
	sourceViewerAddMeta(&meta, "created", sourceViewerDateTime(entry.CreatedAt))
	sourceViewerAddMeta(&meta, "updated", sourceViewerDateTime(entry.UpdatedAt))
	sourceViewerAddMeta(&meta, "path", entry.Path)
	if entry.Line > 0 {
		sourceViewerAddMeta(&meta, "line", strconv.Itoa(entry.Line))
	}
	sourceViewerAddMeta(&meta, "role", strings.ToLower(entry.Association))
	badges := []sourceViewerBadgeView{}
	if entry.State != "" {
		badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: entry.State})
	}
	return sourceViewerDiscussionItemView{
		Type:          entry.Type,
		Author:        sourceViewerFallback(entry.Author, entry.Name),
		Href:          entry.Href,
		Body:          sourceViewerDiscussionMarkdown(entry.Body),
		Meta:          meta,
		Badges:        badges,
		CreatedAt:     sourceTimeAgo(entry.CreatedAt),
		CreatedAtTime: entry.CreatedAt,
	}
}

func sourceViewerPullRequestDetailNotices(detail sourcePullRequestDetail) []sourceViewerNoticeView {
	notices := []sourceViewerNoticeView{}
	if detail.IssueCommentError != "" {
		notices = append(notices, sourceViewerNoticeView{Kind: "warning", Title: "Comments unavailable", Message: "The pull request loaded, but conversation comments could not be fetched with the active token.", Detail: detail.IssueCommentError})
	}
	if detail.ReviewError != "" {
		notices = append(notices, sourceViewerNoticeView{Kind: "warning", Title: "Reviews unavailable", Message: "The pull request loaded, but reviews could not be fetched with the active token.", Detail: detail.ReviewError})
	}
	if detail.ReviewCommentError != "" {
		notices = append(notices, sourceViewerNoticeView{Kind: "warning", Title: "Review comments unavailable", Message: "The pull request loaded, but inline review comments could not be fetched with the active token.", Detail: detail.ReviewCommentError})
	}
	return notices
}

func sourceViewerStateLinks(req SourceContentRequest, section, activeState string) []sourceViewerNavItemView {
	activeState = sourceViewerNormalizeListState(activeState)
	return []sourceViewerNavItemView{
		{Label: "Open", Href: sourceViewerRepoSectionHref(req.Owner, req.Repo, section, "state=open"), Active: activeState == "open"},
		{Label: "Closed", Href: sourceViewerRepoSectionHref(req.Owner, req.Repo, section, "state=closed"), Active: activeState == "closed"},
	}
}

func sourceViewerPagination(req SourceContentRequest, section, state string, pagination sourcePagination) *sourceViewerPaginationView {
	if pagination.Page <= 0 {
		pagination.Page = 1
	}
	if pagination.Page == 1 && pagination.PrevPage == 0 && pagination.NextPage == 0 {
		return nil
	}
	view := &sourceViewerPaginationView{Page: pagination.Page}
	if pagination.PrevPage > 0 {
		view.PrevHref = sourceViewerListPageHref(req.Owner, req.Repo, section, state, pagination.PrevPage)
	}
	if pagination.NextPage > 0 {
		view.NextHref = sourceViewerListPageHref(req.Owner, req.Repo, section, state, pagination.NextPage)
	}
	return view
}

func sourceViewerListPageHref(owner, repo, section, state string, page int) string {
	query := url.Values{}
	query.Set("state", sourceViewerNormalizeListState(state))
	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}
	return sourceViewerRepoSectionHref(owner, repo, section, query.Encode())
}

func sourceViewerIssueHref(owner, repo string, number int) string {
	return fmt.Sprintf("/viewer/github.com/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(repo), number)
}

func sourceViewerPullRequestHref(owner, repo string, number int) string {
	return fmt.Sprintf("/viewer/github.com/%s/%s/pulls/%d", url.PathEscape(owner), url.PathEscape(repo), number)
}

func sourceViewerListState(r *http.Request) string {
	return sourceViewerNormalizeListState(r.URL.Query().Get("state"))
}

func sourceViewerNormalizeListState(state string) string {
	if strings.EqualFold(strings.TrimSpace(state), "closed") {
		return "closed"
	}
	return "open"
}

func sourceViewerListPage(r *http.Request) int {
	page, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page")))
	if err != nil || page <= 0 {
		return 1
	}
	return page
}

func sourceViewerDiscussionMarkdown(value string) template.HTML {
	if strings.TrimSpace(value) == "" {
		return sourceViewerMarkdownHTML("_No description provided._")
	}
	return sourceViewerMarkdownHTML(value)
}

func sourceViewerAddMeta(meta *[]sourceViewerTableMetaView, label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	*meta = append(*meta, sourceViewerTableMetaView{Label: label, Value: value})
}

func sourceViewerDateTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("Jan 2, 2006 15:04 UTC")
}

func sourceViewerEnvironmentsPage(req SourceContentRequest, environments []sourceEnvironmentEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(environments))
	for _, environment := range environments {
		rows = append(rows, sourceViewerTableRow{
			Type:        "env",
			Name:        environment.Name,
			Description: sourceEnvironmentDescription(environment),
			Meta:        sourceEnvironmentMeta(environment),
			Badges:      sourceEnvironmentBadges(environment),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No environments found."))
	}
	return sourceViewerRepoTablePage(req, "Environments", "environments", "Environments", rows)
}

func sourceViewerRulesetsPage(req SourceContentRequest, rulesets []sourceRulesetEntry) sourceViewerPage {
	rows := make([]sourceViewerTableRow, 0, len(rulesets))
	for _, ruleset := range rulesets {
		rows = append(rows, sourceViewerTableRow{
			Type:        "ruleset",
			Name:        ruleset.Name,
			Description: sourceRulesetDescription(ruleset),
			Meta:        sourceRulesetMeta(ruleset),
			Badges:      sourceRulesetBadges(ruleset),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, sourceViewerEmptyRow("No repository rulesets found."))
	}
	return sourceViewerRepoTablePage(req, "Rulesets", "rulesets", "Repository rulesets", rows)
}

func sourceViewerActionRunPage(req SourceContentRequest, run sourceRunEntry, jobs []sourceJobEntry) sourceViewerPage {
	rows := []sourceViewerTableRow{{
		Type:   "run",
		Name:   sourceViewerFallback(run.Title, run.Name),
		Meta:   sourceRunMeta(run),
		Badges: sourceRunBadges(run),
	}}
	for _, job := range jobs {
		rows = append(rows, sourceViewerTableRow{
			Type:        "job",
			Name:        job.Name,
			Href:        sourceViewerJobLogHref(req.Owner, req.Repo, run.ID, job.ID),
			Description: strings.Join(job.Labels, ", "),
			Badges:      sourceJobBadges(job),
		})
		for _, step := range job.Steps {
			rows = append(rows, sourceViewerTableRow{
				Type:        "step",
				Name:        step.Name,
				Description: fmt.Sprintf("step %d", step.Number),
				Badges:      sourceStepBadges(step),
			})
		}
	}
	page := sourceViewerRepoTablePage(req, fmt.Sprintf("Run %d", run.ID), "actions", "Workflow run", rows)
	page.Header.GitHubURL = run.HTMLURL
	return page
}

func sourceViewerJobLogPage(req SourceContentRequest, logs sourceLogResponse) sourceViewerPage {
	page := sourceViewerPage{
		Title:  fmt.Sprintf("%s/%s job %d logs", req.Owner, req.Repo, logs.JobID),
		Header: sourceViewerRepoHeader(req.Owner, req.Repo, "Job logs", fmt.Sprintf("https://github.com/%s/%s/actions", req.Owner, req.Repo)),
		Nav:    sourceViewerRepoNav(req.Owner, req.Repo, "", "actions"),
		File: &sourceViewerFileView{
			Lines: sourceViewerLines(logs.Content, "job.log", 0, sourceViewerLogInspection(logs.Content, logs.Truncated)),
		},
		Notices: []sourceViewerNoticeView{{
			Kind:    "warning",
			Title:   "Workflow logs may contain sensitive data",
			Message: "Logs are fetched on demand, displayed with a size cap, and are not persisted in the source cache.",
		}},
	}
	if logs.Truncated {
		page.Notices = append(page.Notices, sourceViewerNoticeView{Kind: "warning", Title: "Log truncated", Message: fmt.Sprintf("Only the first %d bytes are shown.", sourceViewerMaxLogBytes)})
	}
	return page
}

func (h *Handler) sourceViewerUnavailablePage(req SourceContentRequest, title, active string, err error) sourceViewerPage {
	message := h.sourceViewerFriendlyGitHubError(req, err)
	return sourceViewerPage{
		Title:  title,
		Header: sourceViewerRepoHeader(req.Owner, req.Repo, title, sourceViewerGitHubSectionURL(req.Owner, req.Repo, active)),
		Nav:    sourceViewerRepoNav(req.Owner, req.Repo, "", active),
		Notices: []sourceViewerNoticeView{{
			Kind:    "warning",
			Title:   title + " unavailable",
			Message: message.Message,
			Action:  message.Action,
			Detail:  message.Detail,
		}},
		Table: &sourceViewerTableView{Rows: []sourceViewerTableRow{sourceViewerEmptyRow("This panel is unavailable with the current token or repository permissions.")}},
	}
}

func sourceViewerRepoTablePage(req SourceContentRequest, title, active, pathText string, rows []sourceViewerTableRow) sourceViewerPage {
	return sourceViewerPage{
		Title:   title,
		Header:  sourceViewerRepoHeader(req.Owner, req.Repo, pathText, sourceViewerGitHubSectionURL(req.Owner, req.Repo, active)),
		Nav:     sourceViewerRepoNav(req.Owner, req.Repo, "", active),
		Notices: sourceViewerTokenNotice(req),
		Table:   &sourceViewerTableView{Rows: rows, Filter: sourceViewerTableFilter(sourceViewerRepoPanelFilterPlaceholder(active))},
	}
}

func sourceViewerRepoPanelFilterPlaceholder(active string) string {
	switch active {
	case "branches":
		return "Find a branch"
	case "tags":
		return "Find a tag"
	case "releases":
		return "Find a release"
	case "actions":
		return "Find a workflow run, runner, or cache entry"
	case "issues":
		return "Find an issue"
	case "pulls":
		return "Find a pull request"
	case "environments":
		return "Find an environment"
	case "rulesets":
		return "Find a ruleset"
	default:
		return "Find an item"
	}
}

func sourceViewerRepoHeader(owner, repo, pathText, githubURL string) sourceViewerHeaderView {
	return sourceViewerHeaderView{
		AriaLabel: "Repository",
		RepoName:  sourceViewerRepoNameViewFor(owner, repo, ""),
		PathText:  pathText,
		GitHubURL: githubURL,
	}
}

func sourceViewerTokenNotice(req SourceContentRequest) []sourceViewerNoticeView {
	if strings.TrimSpace(req.Token) != "" {
		return nil
	}
	return []sourceViewerNoticeView{{
		Kind:    "info",
		Title:   "Using public GitHub access",
		Message: "Private repositories and some Actions data require an active token with the relevant repository or Actions permission.",
	}}
}

type sourceViewerRepositoryAccessHint struct {
	Known        bool
	Private      bool
	DiscoveredBy string
	Permissions  []string
}

func (h *Handler) sourceViewerFriendlyGitHubError(req SourceContentRequest, err error) sourceViewerMessageView {
	return sourceViewerFriendlyGitHubError(req, err, h.sourceViewerRepositoryAccessHint(req))
}

func sourceViewerFriendlyGitHubError(req SourceContentRequest, err error, hint sourceViewerRepositoryAccessHint) sourceViewerMessageView {
	var ghErr *github.ErrorResponse
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		if errors.As(err, &ghErr) && ghErr.Response != nil {
			switch ghErr.Response.StatusCode {
			case http.StatusUnauthorized:
				return sourceViewerTokenAccessMessage(req, hint, "GitHub rejected the active browser token.")
			case http.StatusForbidden:
				return sourceViewerTokenAccessMessage(req, hint, "The active token cannot read this GitHub API.")
			case http.StatusNotFound:
				if hint.Known {
					return sourceViewerTokenAccessMessage(req, hint, "Private repository not visible to the active token.")
				}
				return sourceViewerTokenAccessMessage(req, hint, "GitHub returned 404.")
			}
		}
		return sourceViewerMessageView{Message: err.Error()}
	}
	return sourceViewerMessageView{Message: "The data could not be loaded with the current token."}
}

func sourceViewerTokenAccessMessage(req SourceContentRequest, hint sourceViewerRepositoryAccessHint, lead string) sourceViewerMessageView {
	repo := strings.Trim(strings.TrimSpace(req.Owner)+"/"+strings.TrimSpace(req.Repo), "/")
	action := "Re-pivot or register a fresh token with the required GitHub access."
	if repo != "" {
		action = "Re-pivot or register a fresh token with read access to " + repo + "."
	}
	var details []string
	if source := strings.TrimSpace(req.TokenSource); source != "" {
		details = append(details, "Active token source: "+source+".")
	}
	if sourceViewerTokenLooksEphemeral(req) {
		details = append(details, "For GitHub App tokens, exchange the app credentials again and select the fresh installation token.")
	}
	if hint.DiscoveredBy != "" {
		details = append(details, "Graph metadata says this repo was discovered via "+hint.DiscoveredBy+".")
	}
	if len(hint.Permissions) > 0 {
		details = append(details, "Known graph permissions: "+strings.Join(hint.Permissions, ", ")+".")
	}
	if hint.Private {
		details = append(details, "Known private repo in graph. GitHub returns 404 for private repositories the token cannot see.")
	} else if strings.Contains(lead, "404") {
		details = append(details, "The repository may not exist, or a private repository may be hidden from the active token.")
	}
	return sourceViewerMessageView{
		Message: lead,
		Action:  action,
		Detail:  strings.Join(details, " "),
	}
}

func sourceViewerTokenLooksEphemeral(req SourceContentRequest) bool {
	tokenType := detectTokenTypePrefix(strings.TrimSpace(req.Token))
	source := strings.ToLower(strings.TrimSpace(req.TokenSource))
	return tokenType == "install_app" || strings.Contains(source, "app_token") || strings.Contains(source, "pivot:app")
}

func sourceViewerLogInspection(content string, truncated bool) *sourceViewerInspectionView {
	var risks []sourceViewerRiskView
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "::error") || strings.Contains(lower, " error "):
			risks = append(risks, sourceViewerLogRisk("high", "log-error", "Log line contains an error marker.", i+1))
		case strings.Contains(lower, "::warning") || strings.Contains(lower, " warning "):
			risks = append(risks, sourceViewerLogRisk("medium", "log-warning", "Log line contains a warning marker.", i+1))
		case strings.Contains(line, "***"):
			risks = append(risks, sourceViewerLogRisk("medium", "masked-secret", "Log line contains GitHub secret masking.", i+1))
		}
	}
	if truncated {
		risks = append(risks, sourceViewerLogRisk("medium", "truncated-log", "Log output was truncated before display.", 0))
	}
	return &sourceViewerInspectionView{
		Kind:    "logs",
		Summary: sourceViewerInspectionSummary(&sourceViewerInspectionView{Risks: risks}),
		Risks:   risks,
		Sections: []sourceViewerInspectionSectionView{{
			Title: "Log signals",
			Items: []sourceViewerInspectionItemView{{Label: fmt.Sprintf("%d lines", len(lines))}},
		}},
	}
}

func sourceViewerLogRisk(severity, kind, message string, line int) sourceViewerRiskView {
	label, order := sourceViewerRiskDisplay(kind, 0)
	return sourceViewerRiskView{
		Severity: severity,
		Kind:     kind,
		Label:    label,
		Message:  message,
		Line:     line,
		Href:     sourceLineHref(line),
		Order:    order,
	}
}

func sourceRunMeta(run sourceRunEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 6)
	if run.Branch != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "branch", Value: run.Branch})
	}
	if run.Event != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "event", Value: run.Event})
	}
	if run.Actor != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "actor", Value: run.Actor})
	}
	if run.RunNumber > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "run", Value: fmt.Sprintf("#%d", run.RunNumber)})
	}
	if run.RunAttempt > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "attempt", Value: fmt.Sprint(run.RunAttempt)})
	}
	if timestamp := sourceRunTimestamp(run); timestamp != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "started", Value: timestamp})
	}
	return parts
}

func sourceViewerActionLinks(req SourceContentRequest, active string) []sourceViewerNavItemView {
	links := make([]sourceViewerNavItemView, 0, 3)
	for _, item := range []struct {
		key   string
		label string
		href  string
	}{
		{key: "runs", label: "Runs", href: sourceViewerRepoSectionHref(req.Owner, req.Repo, "actions", "")},
		{key: "runners", label: "Runners", href: sourceViewerGitHubActionsSubViewerHref(req.Owner, req.Repo, "runners")},
		{key: "caches", label: "Caches", href: sourceViewerGitHubActionsSubViewerHref(req.Owner, req.Repo, "caches")},
	} {
		links = append(links, sourceViewerNavItemView{Label: item.label, Href: item.href, Active: item.key == active})
	}
	return links
}

func sourceRunnerMeta(runner sourceRunnerEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 4)
	if runner.ID > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "id", Value: fmt.Sprint(runner.ID)})
	}
	if runner.OS != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "os", Value: runner.OS})
	}
	if len(runner.Labels) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "labels", Value: strings.Join(runner.Labels, ", ")})
	}
	return parts
}

func sourceRunnerBadges(runner sourceRunnerEntry) []sourceViewerBadgeView {
	badges := sourceViewerStateBadges(runner.Status)
	if runner.Busy {
		badges = append(badges, sourceViewerBadgeView{Kind: "medium", Label: "busy"})
	}
	return badges
}

func sourceRunnerLabels(labels []*github.RunnerLabels) []string {
	names := make([]string, 0, len(labels))
	for _, label := range labels {
		if name := strings.TrimSpace(label.GetName()); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func sourceCacheMeta(cache sourceActionCacheEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 5)
	if cache.ID > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "id", Value: fmt.Sprint(cache.ID)})
	}
	if cache.Ref != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "ref", Value: cache.Ref})
	}
	if !cache.CreatedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "created", Value: sourceTimeAgo(cache.CreatedAt)})
	}
	if !cache.LastAccessedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "last used", Value: sourceTimeAgo(cache.LastAccessedAt)})
	}
	if cache.Version != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "version", Value: sourceShortSHA(cache.Version)})
	}
	return parts
}

func sourceCacheBadges(cache sourceActionCacheEntry) []sourceViewerBadgeView {
	if cache.LastAccessedAt.IsZero() {
		return nil
	}
	if time.Since(cache.LastAccessedAt) > 30*24*time.Hour {
		return []sourceViewerBadgeView{{Kind: "medium", Label: "stale"}}
	}
	return []sourceViewerBadgeView{{Kind: "neutral", Label: "recent"}}
}

func sourceIssueMeta(issue sourceIssueEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 5)
	if issue.Author != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "author", Value: issue.Author})
	}
	if issue.Comments > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "comments", Value: fmt.Sprint(issue.Comments)})
	}
	if len(issue.Labels) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "labels", Value: strings.Join(issue.Labels, ", ")})
	}
	if !issue.CreatedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "created", Value: sourceTimeAgo(issue.CreatedAt)})
	}
	if !issue.UpdatedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "updated", Value: sourceTimeAgo(issue.UpdatedAt)})
	}
	return parts
}

func sourceIssueBadges(issue sourceIssueEntry) []sourceViewerBadgeView {
	badges := []sourceViewerBadgeView{{Kind: sourceViewerStateKind(issue.State), Label: sourceViewerFallback(issue.State, "unknown")}}
	if issue.StateReason != "" {
		badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: sourceHumanizeIdentifier(issue.StateReason)})
	}
	return badges
}

func sourceIssueLabels(labels []*github.Label) []string {
	names := make([]string, 0, len(labels))
	for _, label := range labels {
		if name := strings.TrimSpace(label.GetName()); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func sourcePullRequestMeta(pull sourcePullRequestEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 8)
	if pull.Author != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "author", Value: pull.Author})
	}
	if pull.BaseRef != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "base", Value: pull.BaseRef})
	}
	if pull.HeadRef != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "head", Value: pull.HeadRef})
	}
	if pull.Commits > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "commits", Value: fmt.Sprint(pull.Commits)})
	}
	if pull.ChangedFiles > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "files", Value: fmt.Sprint(pull.ChangedFiles)})
	}
	if pull.Additions > 0 || pull.Deletions > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "diff", Value: fmt.Sprintf("+%d / -%d", pull.Additions, pull.Deletions)})
	}
	if pull.Comments > 0 || pull.ReviewComments > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "comments", Value: fmt.Sprintf("%d issue, %d review", pull.Comments, pull.ReviewComments)})
	}
	if !pull.CreatedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "created", Value: sourceTimeAgo(pull.CreatedAt)})
	}
	if !pull.UpdatedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "updated", Value: sourceTimeAgo(pull.UpdatedAt)})
	}
	return parts
}

func sourcePullRequestBadges(pull sourcePullRequestEntry) []sourceViewerBadgeView {
	badges := []sourceViewerBadgeView{{Kind: sourceViewerStateKind(pull.State), Label: sourceViewerFallback(pull.State, "unknown")}}
	if pull.Draft {
		badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: "draft"})
	}
	if pull.Merged {
		badges = append(badges, sourceViewerBadgeView{Kind: "success", Label: "merged"})
	}
	return badges
}

func sourceEnvironmentMeta(environment sourceEnvironmentEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 6)
	if environment.WaitTimer > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "wait", Value: fmt.Sprintf("%d min", environment.WaitTimer)})
	}
	if environment.Reviewers > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "reviewers", Value: fmt.Sprint(environment.Reviewers)})
	}
	if environment.ProtectionRules > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "rules", Value: fmt.Sprint(environment.ProtectionRules)})
	}
	if environment.BranchPolicy != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "branches", Value: environment.BranchPolicy})
	}
	if environment.AdminsBypass != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "admin bypass", Value: environment.AdminsBypass})
	}
	if !environment.UpdatedAt.IsZero() {
		parts = append(parts, sourceViewerTableMetaView{Label: "updated", Value: sourceTimeAgo(environment.UpdatedAt)})
	}
	return parts
}

func sourceEnvironmentBadges(environment sourceEnvironmentEntry) []sourceViewerBadgeView {
	badges := []sourceViewerBadgeView{}
	if environment.Reviewers > 0 || environment.ProtectionRules > 0 {
		badges = append(badges, sourceViewerBadgeView{Kind: "neutral", Label: "protected"})
	}
	return badges
}

func sourceEnvironmentDescription(environment sourceEnvironmentEntry) string {
	details := make([]string, 0, 2)
	if len(environment.ProtectionDetails) > 0 {
		details = append(details, "Protection: "+strings.Join(environment.ProtectionDetails, "; ")+".")
	}
	if len(environment.ReviewerDetails) > 0 {
		details = append(details, "Reviewers: "+strings.Join(environment.ReviewerDetails, ", ")+".")
	}
	return strings.Join(details, " ")
}

func sourceEnvironmentBranchPolicy(environment sourceEnvironmentEntry) string {
	switch {
	case environment.ProtectedBranches && environment.CustomBranchPolicies:
		return "protected branches and custom policies"
	case environment.ProtectedBranches:
		return "protected branches only"
	case environment.CustomBranchPolicies:
		return "custom policies"
	default:
		return "all branches"
	}
}

func sourceEnvironmentReviewerDetails(reviewers []*github.EnvReviewers) []string {
	details := make([]string, 0, len(reviewers))
	for _, reviewer := range reviewers {
		label := sourceHumanizeIdentifier(reviewer.GetType())
		if label == "" {
			label = "reviewer"
		}
		if reviewer.GetID() > 0 {
			label = fmt.Sprintf("%s #%d", label, reviewer.GetID())
		}
		details = append(details, label)
	}
	return details
}

func sourceEnvironmentProtectionDetails(rules []*github.ProtectionRule) []string {
	details := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts := []string{}
		if ruleType := strings.TrimSpace(rule.GetType()); ruleType != "" && !strings.EqualFold(ruleType, "wait_timer") {
			parts = append(parts, sourceHumanizeIdentifier(rule.GetType()))
		}
		if len(rule.Reviewers) > 0 {
			parts = append(parts, fmt.Sprintf("%d required reviewers", len(rule.Reviewers)))
		}
		if rule.GetPreventSelfReview() {
			parts = append(parts, "prevents self-review")
		}
		if len(parts) > 0 {
			details = append(details, strings.Join(parts, ", "))
		}
	}
	return details
}

func sourceRulesetMeta(ruleset sourceRulesetEntry) []sourceViewerTableMetaView {
	parts := make([]sourceViewerTableMetaView, 0, 10)
	if ruleset.SourceType != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "source", Value: ruleset.SourceType})
	}
	if ruleset.Target != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "target", Value: ruleset.Target})
	}
	if ruleset.Rules > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "rules", Value: fmt.Sprint(ruleset.Rules)})
	}
	if len(ruleset.Includes) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "include", Value: strings.Join(ruleset.Includes, ", ")})
	}
	if len(ruleset.Excludes) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "exclude", Value: strings.Join(ruleset.Excludes, ", ")})
	}
	if len(ruleset.RepoIncludes) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "repos", Value: strings.Join(ruleset.RepoIncludes, ", ")})
	}
	if len(ruleset.RepoExcludes) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "repo exclude", Value: strings.Join(ruleset.RepoExcludes, ", ")})
	}
	if ruleset.RepoProtected != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "protected repos", Value: ruleset.RepoProtected})
	}
	if len(ruleset.RepositoryIDs) > 0 {
		parts = append(parts, sourceViewerTableMetaView{Label: "repo ids", Value: sourceInt64List(ruleset.RepositoryIDs)})
	}
	if ruleset.Source != "" {
		parts = append(parts, sourceViewerTableMetaView{Label: "owner", Value: ruleset.Source})
	}
	return parts
}

func sourceRulesetBadges(ruleset sourceRulesetEntry) []sourceViewerBadgeView {
	kind := "neutral"
	switch strings.ToLower(strings.TrimSpace(ruleset.Enforcement)) {
	case "active", "enabled":
		kind = "success"
	case "evaluate":
		kind = "medium"
	case "disabled":
		kind = "low"
	}
	return []sourceViewerBadgeView{{Kind: kind, Label: sourceViewerFallback(ruleset.Enforcement, "unknown")}}
}

func sourceRulesetDescription(ruleset sourceRulesetEntry) string {
	details := make([]string, 0, 2)
	if len(ruleset.RuleDetails) > 0 {
		details = append(details, "Rules: "+strings.Join(ruleset.RuleDetails, "; ")+".")
	}
	if len(ruleset.BypassActors) > 0 {
		details = append(details, "Bypass: "+strings.Join(ruleset.BypassActors, "; ")+".")
	}
	return strings.Join(details, " ")
}

func sourceRulesetBypassActors(actors []*github.BypassActor) []string {
	details := make([]string, 0, len(actors))
	for _, actor := range actors {
		label := sourceHumanizeIdentifier(actor.GetActorType())
		if label == "" {
			label = "actor"
		}
		if actor.GetActorID() > 0 {
			label = fmt.Sprintf("%s #%d", label, actor.GetActorID())
		}
		if actor.GetBypassMode() != "" {
			label += " (" + sourceHumanizeIdentifier(actor.GetBypassMode()) + ")"
		}
		details = append(details, label)
	}
	return details
}

func sourceRulesetRuleDetails(rules []*github.RepositoryRule) []string {
	details := make([]string, 0, len(rules))
	for _, rule := range rules {
		if detail := sourceRulesetRuleDetail(rule); detail != "" {
			details = append(details, detail)
		}
	}
	return details
}

func sourceRulesetRuleDetail(rule *github.RepositoryRule) string {
	if rule == nil || rule.Type == "" {
		return ""
	}
	label := sourceHumanizeIdentifier(rule.Type)
	params := rule.GetParameters()
	if len(params) == 0 {
		return label
	}
	switch rule.Type {
	case "pull_request":
		return sourceRulesetPullRequestRuleDetail(label, params)
	case "required_status_checks":
		return sourceRulesetStatusChecksRuleDetail(label, params)
	case "required_deployments":
		return sourceRulesetDeploymentsRuleDetail(label, params)
	case "workflows":
		return sourceRulesetWorkflowsRuleDetail(label, params)
	case "update":
		return sourceRulesetUpdateRuleDetail(label, params)
	case "commit_message_pattern", "commit_author_email_pattern", "committer_email_pattern", "branch_name_pattern", "tag_name_pattern":
		return sourceRulesetPatternRuleDetail(label, params)
	default:
		return label
	}
}

func sourceRulesetPullRequestRuleDetail(label string, params json.RawMessage) string {
	var parsed github.PullRequestRuleParameters
	if err := json.Unmarshal(params, &parsed); err != nil {
		return label
	}
	parts := []string{label}
	if parsed.RequiredApprovingReviewCount > 0 {
		parts = append(parts, fmt.Sprintf("%d approvals", parsed.RequiredApprovingReviewCount))
	}
	if parsed.RequireCodeOwnerReview {
		parts = append(parts, "code owner review")
	}
	if parsed.RequireLastPushApproval {
		parts = append(parts, "last push approval")
	}
	if parsed.DismissStaleReviewsOnPush {
		parts = append(parts, "dismiss stale reviews")
	}
	if parsed.RequiredReviewThreadResolution {
		parts = append(parts, "conversation resolution")
	}
	return strings.Join(parts, ", ")
}

func sourceRulesetStatusChecksRuleDetail(label string, params json.RawMessage) string {
	var parsed github.RequiredStatusChecksRuleParameters
	if err := json.Unmarshal(params, &parsed); err != nil {
		return label
	}
	parts := []string{label}
	if parsed.StrictRequiredStatusChecksPolicy {
		parts = append(parts, "strict")
	}
	checks := make([]string, 0, len(parsed.RequiredStatusChecks))
	for _, check := range parsed.RequiredStatusChecks {
		if check.Context != "" {
			checks = append(checks, check.Context)
		}
	}
	if len(checks) > 0 {
		parts = append(parts, strings.Join(checks, ", "))
	}
	return strings.Join(parts, ", ")
}

func sourceRulesetDeploymentsRuleDetail(label string, params json.RawMessage) string {
	var parsed github.RequiredDeploymentEnvironmentsRuleParameters
	if err := json.Unmarshal(params, &parsed); err != nil {
		return label
	}
	if len(parsed.RequiredDeploymentEnvironments) == 0 {
		return label
	}
	return label + ", " + strings.Join(parsed.RequiredDeploymentEnvironments, ", ")
}

func sourceRulesetWorkflowsRuleDetail(label string, params json.RawMessage) string {
	var parsed github.RequiredWorkflowsRuleParameters
	if err := json.Unmarshal(params, &parsed); err != nil {
		return label
	}
	paths := make([]string, 0, len(parsed.RequiredWorkflows))
	for _, workflow := range parsed.RequiredWorkflows {
		if workflow.Path != "" {
			paths = append(paths, workflow.Path)
		}
	}
	if len(paths) == 0 {
		return label
	}
	return label + ", " + strings.Join(paths, ", ")
}

func sourceRulesetUpdateRuleDetail(label string, params json.RawMessage) string {
	var parsed github.UpdateAllowsFetchAndMergeRuleParameters
	if err := json.Unmarshal(params, &parsed); err != nil {
		return label
	}
	if parsed.UpdateAllowsFetchAndMerge {
		return label + ", allows fetch and merge"
	}
	return label
}

func sourceRulesetPatternRuleDetail(label string, params json.RawMessage) string {
	var parsed github.RulePatternParameters
	if err := json.Unmarshal(params, &parsed); err != nil {
		return label
	}
	parts := []string{label}
	if parsed.Operator != "" && parsed.Pattern != "" {
		parts = append(parts, sourceHumanizeIdentifier(parsed.Operator)+" "+parsed.Pattern)
	}
	if parsed.Negate != nil && *parsed.Negate {
		parts = append(parts, "negated")
	}
	return strings.Join(parts, ", ")
}

func sourceBoolSetting(value *bool) string {
	if value == nil {
		return ""
	}
	if *value {
		return "allowed"
	}
	return "blocked"
}

func sourceHumanizeIdentifier(value string) string {
	switch value {
	case "RepositoryRole":
		return "repository role"
	case "OrganizationAdmin":
		return "organization admin"
	}
	value = strings.TrimSpace(strings.ReplaceAll(value, "_", " "))
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}

func sourceInt64List(values []int64) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprint(value))
	}
	return strings.Join(parts, ", ")
}

func sourceViewerActionsFilter(req SourceContentRequest) *sourceViewerActionsFilterView {
	statuses := []sourceViewerFilterOptionView{{Label: "Any status"}}
	for _, value := range []string{"success", "failure", "in_progress", "queued", "completed", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale", "requested", "waiting", "pending"} { //nolint:misspell // GitHub API value.
		statuses = append(statuses, sourceViewerFilterOptionView{
			Value:    value,
			Label:    strings.ReplaceAll(value, "_", " "),
			Selected: value == req.ActionStatus,
		})
	}
	return &sourceViewerActionsFilterView{
		Action:      sourceViewerRepoSectionHref(req.Owner, req.Repo, "actions", ""),
		ClearHref:   sourceViewerRepoSectionHref(req.Owner, req.Repo, "actions", ""),
		Actor:       req.ActionActor,
		Branch:      req.ActionBranch,
		Created:     req.ActionCreated,
		Event:       req.ActionEvent,
		Status:      req.ActionStatus,
		StatusItems: statuses,
	}
}

func sourceRunTimestamp(run sourceRunEntry) string {
	timestamp := run.StartedAt
	if timestamp.IsZero() {
		timestamp = run.CreatedAt
	}
	if timestamp.IsZero() {
		return ""
	}
	return timestamp.UTC().Format("Jan 2, 2006 15:04 UTC")
}

func sourceRunState(run sourceRunEntry) string {
	if run.Conclusion != "" {
		return run.Conclusion
	}
	return run.Status
}

func sourceRunBadges(run sourceRunEntry) []sourceViewerBadgeView {
	return sourceViewerStateBadges(sourceRunState(run))
}

func sourceJobState(job sourceJobEntry) string {
	if job.Conclusion != "" {
		return job.Conclusion
	}
	return job.Status
}

func sourceJobBadges(job sourceJobEntry) []sourceViewerBadgeView {
	return sourceViewerStateBadges(sourceJobState(job))
}

func sourceStepState(step sourceJobStepEntry) string {
	if step.Conclusion != "" {
		return step.Conclusion
	}
	return step.Status
}

func sourceStepBadges(step sourceJobStepEntry) []sourceViewerBadgeView {
	return sourceViewerStateBadges(sourceStepState(step))
}

func sourceViewerStateBadges(state string) []sourceViewerBadgeView {
	return []sourceViewerBadgeView{{Kind: sourceViewerStateKind(state), Label: sourceViewerFallback(state, "unknown")}}
}

func sourceViewerStateKind(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "success", "completed", "online":
		return "success"
	case "failure", "timed_out", "cancelled", "action_required", "offline": //nolint:misspell // GitHub API value.
		return "high"
	case "in_progress", "queued", "requested", "waiting", "pending":
		return "medium"
	default:
		return "neutral"
	}
}

func sourceViewerGitHubSectionURL(owner, repo, active string) string {
	base := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	switch active {
	case "branches":
		return base + "/branches/all"
	case "tags":
		return base + "/tags"
	case "releases":
		return base + "/releases"
	case "actions":
		return base + "/actions"
	case "issues":
		return base + "/issues"
	case "pulls":
		return base + "/pulls"
	case "environments":
		return base + "/settings/environments"
	case "rulesets":
		return base + "/settings/rules"
	default:
		return base
	}
}

func sourceViewerGitHubActionsSubURL(owner, repo, section string) string {
	return fmt.Sprintf("https://github.com/%s/%s/actions/%s", owner, repo, strings.Trim(section, "/"))
}

func sourceViewerGitHubActionsSubViewerHref(owner, repo, section string) string {
	return fmt.Sprintf("/viewer/github.com/%s/%s/actions/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(strings.Trim(section, "/")))
}

func sourceShortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func sourceTimeAgo(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format("2006-01-02")
}

func sourceByteSize(size int64) string {
	switch {
	case size >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(size)/(1024*1024*1024))
	case size >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	case size >= 1024:
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	case size > 0:
		return fmt.Sprintf("%d B", size)
	default:
		return ""
	}
}

func sourceViewerActionRunHref(owner, repo string, runID int64) string {
	return fmt.Sprintf("/viewer/github.com/%s/%s/actions/runs/%d", url.PathEscape(owner), url.PathEscape(repo), runID)
}

func sourceViewerJobLogHref(owner, repo string, runID, jobID int64) string {
	return fmt.Sprintf("/viewer/github.com/%s/%s/actions/runs/%d/jobs/%d/logs", url.PathEscape(owner), url.PathEscape(repo), runID, jobID)
}
