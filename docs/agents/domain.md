# Domain Docs

How the engineering skills should consume this repository's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repository root, or
- **`CONTEXT-MAP.md`** at the repository root if it exists. It points to one `CONTEXT.md` per context.
- **`docs/adr/`** for decisions affecting the area being changed.

If these files do not exist, proceed silently. Do not flag their absence or suggest creating them upfront. The `/domain-modeling` skill creates them lazily when terminology or decisions are resolved.

## File structure

This repository uses the single-context layout:

```text
/
├── CONTEXT.md
├── docs/adr/
│   └── 0001-separate-kitchen-schema-version-from-application-releases.md
└── internal/
```

## Use the glossary's vocabulary

When output names a domain concept, use the term defined in `CONTEXT.md`. Do not drift to synonyms that the glossary explicitly avoids.

If a needed concept is absent, reconsider whether the term belongs to the project or note the gap for `/domain-modeling`.

## Flag ADR conflicts

If output contradicts an existing ADR, surface the conflict explicitly instead of silently overriding it.
