# Work Tracking: GitHub Issues and GitHub Projects

Public issues for this repository live in GitHub Issues. Maintainer-owned roadmap ideas live as draft items in the private SmokedMeat Roadmap Project.

Use the `gh` CLI for all GitHub operations.

## Destinations

### GitHub Issues

Use GitHub Issues for:

- community bug reports and feature requests
- security, correctness, and usability defects
- work that is ready for public discussion
- implementation-ready tickets
- work that contributors can claim

### SmokedMeat Roadmap

Maintainer-owned roadmap ideas live in:

- Owner: `boostsecurityio`
- Project number: `4`
- Project title: `SmokedMeat Roadmap`
- URL: `https://github.com/orgs/boostsecurityio/projects/4`

Use Project draft items for ideas that should not appear in the repository's public Issues list.

Draft items start with Status `Backlog`. Leave Priority and Size unset until the item has been reviewed.

Convert a draft item to a repository issue when it is ready for public discussion, implementation, or contributor ownership.

## GitHub Issue conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`
- **Read an issue**: `gh issue view <number> --comments`
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments`
- **Comment**: `gh issue comment <number> --body "..."`
- **Apply or remove labels**: `gh issue edit <number> --add-label "..."` or `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repository from `git remote -v`.

## Project conventions

- **List items**: `gh project item-list 4 --owner boostsecurityio`
- **Create a roadmap draft**: `gh project item-create 4 --owner boostsecurityio --title "..." --body "..."`
- **Add an existing issue**: `gh project item-add 4 --owner boostsecurityio --url "<issue-url>"`
- **Inspect fields**: `gh project field-list 4 --owner boostsecurityio`

The Project Status values are:

- `Backlog`
- `Ready`
- `In progress`
- `In review`
- `Done`

The Project Priority values are `P0`, `P1`, and `P2`.

The Project Size values are `XS`, `S`, `M`, `L`, and `XL`.

## Routing skill output

When a skill says "publish to the issue tracker":

- Create a Project draft item when the output is a maintainer-owned roadmap idea, exploratory proposal, or uncommitted future direction.
- Create a GitHub issue when the work is implementation-ready, intended for public discussion, or explicitly requested as an issue.
- Add newly created implementation issues to the SmokedMeat Roadmap Project.

When a skill says "fetch the relevant ticket":

- Use `gh issue view` for a GitHub issue.
- Use `gh project item-list` and the Project APIs for a draft item.

## Pull requests as a triage surface

**PRs as a request surface: no.**

Pull requests are implementation artifacts, not substitutes for issue or roadmap intake.

## Planning documentation

GitHub Issues and the SmokedMeat Roadmap Project are the sources of truth for work status.

Do not create a replacement `docs/ROADMAP.md` or new planning files under `docs/tasks/`.

Durable product behavior belongs in product documentation. Durable architectural decisions belong in `docs/adr/`.
