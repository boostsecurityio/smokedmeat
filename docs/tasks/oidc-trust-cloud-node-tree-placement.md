# OIDC Trust Cloud Node Tree Placement

## Why This Exists

On large org targets with many GitHub Actions workflows that use OIDC to assume cloud roles, the vuln tree shows a large number of `oidc_trust/...` `[CLOUD]` nodes as dangling leaves near the bottom of the tree.

This is a clear tree-parenting bug and a real usability problem:

- the nodes appear detached from the workflow context that produced them
- the tree gets much longer and noisier than it should
- the operator loses the connection between a workflow job and its OIDC trust path

## Current Behavior

Kitchen analysis already creates cloud assets for detected cloud actions and records them with job relationships.

Current relevant paths:

- cloud assets are created in `internal/kitchen/analyze.go`
- Kitchen adds `job -> cloud asset` relationships for them
- Counter tree rendering is built in `internal/counter/tui/tree.go`

The current tree-building bug is that cloud assets are appended directly under the root instead of being attached via their existing Pantry relationships.

That is why the tree shows many root-level `[CLOUD]` nodes even though the analysis data already knows which job they belong to.

## First Pass Goal

Make `oidc_trust/...` cloud nodes appear under the associated workflow job in the vuln tree.

If a cloud asset has no job parent but does have a workflow parent, attach it there.
Only fall back to a root-level cloud node when there is genuinely no better parent relationship available.

## Non-Goals

This first pass is not:

- a redesign of the tree hierarchy
- a cloud asset grouping feature
- a graph-view feature
- a full OIDC trust summarization pass

The goal is simply to fix the obvious parentage bug in the existing tree.

## Proposed Fix

Update tree construction in Counter so cloud assets follow the same parent-attachment pattern already used for:

- jobs
- secrets
- vulnerabilities
- tokens

Expected attachment order:

1. attach under job when the Pantry relationship exists
2. otherwise attach under workflow when that relationship exists
3. otherwise fall back to root

## Acceptance Cases

- A workflow job with detected AWS OIDC trust shows the `oidc_trust/...` cloud node beneath that job, not at root.
- The same applies for GCP and Azure OIDC trust assets.
- Large org trees no longer accumulate long root-level tails of unrelated `[CLOUD]` nodes when the parent job is known.
- Cloud nodes with no known parent still remain visible via the root fallback path.

## Notes

This is intentionally a small bug-fix slice suitable for pre-freeze work.
It should be implemented with the existing Pantry relationship data rather than new heuristics.
