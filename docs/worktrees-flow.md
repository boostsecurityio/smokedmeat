# Worktrees Flow

Use Git worktrees when you want multiple Codex sessions against the same repo without stashing or branch hopping.

## Default Pattern

Keep the primary checkout on `main`. Put feature worktrees under `../smokedmeat-wt/`. Cut every independent feature branch from the same fresh `origin/main`.

```bash
make worktree-sync-main
make worktree-add NAME=session-a
make worktree-add NAME=session-b
make worktree-add NAME=session-c
make worktree-list
```

Defaults:

- `make worktree-add NAME=foo` creates branch `feat/foo`
- the worktree path is `../smokedmeat-wt/foo`
- the base is `origin/main`

Open one Codex session per worktree. Keep the original checkout on `main` as the clean control workspace.

## When To Override Defaults

Use a custom branch name when the default `feat/<name>` does not fit:

```bash
make worktree-add NAME=auth-cleanup BRANCH=fix/auth-cleanup
```

Use a custom destination when you want a different worktree root:

```bash
make worktree-add NAME=api-cleanup DEST=../alt-worktrees/api-cleanup
```

Use a non-`main` base only for stacked work that truly depends on another open branch:

```bash
make worktree-add NAME=followup BRANCH=feat/followup BASE=feat/base
```

## Review Flow

- Keep one feature per worktree and one PR per branch.
- For unrelated work, branch every PR directly from `origin/main`.
- Open PRs as soon as the branch is coherent, but keep them small enough to review independently.
- Add fixup commits during review. Do not rebase after every comment.
- Rebase or merge `origin/main` only when the branch is next to land, has a real conflict, or CI requires an up-to-date base.
- Use stacked branches only when one change truly depends on another. Otherwise every rewrite of the base branch creates more rebase work.

## Cleanup

After a branch lands:

```bash
make worktree-remove NAME=session-a
make worktree-prune
```

`worktree-remove` removes the worktree directory, then tries `git branch -d`. If the branch is not merged yet, Git keeps the branch and prints a note.
