# Kitchen Persistence Guide

Read this file before changing `internal/kitchen/db/` or any persisted Pantry, stager, session, loot, history, or known-entity shape.

Kitchen schema versions are independent of application release versions. See [ADR-0001](../adr/0001-separate-kitchen-schema-version-from-application-releases.md).

## Compatibility Invariant

Within one schema major:

- newer binaries must open older data with safe defaults
- older binaries must not misinterpret data written by newer binaries
- patch and minor application releases must preserve existing quickstart and development volumes

If either direction is unsafe, advance the schema major and fail fast with guidance to run `make quickstart-purge` or `make dev-quickstart-purge`.

## Version Decisions

Advance the schema minor for additive, backward-compatible disk changes:

- new buckets that do not change existing meaning
- optional persisted fields
- optional Pantry properties or relationships
- metadata or derived state that can be defaulted or rebuilt

Do not change the schema version for:

- Counter-only behavior
- in-memory changes that preserve serialized shape and meaning
- tests, documentation, logging, or internal refactors

Advance the schema major for incompatible changes:

- renamed, removed, or repurposed buckets
- changed key layout or identity rules
- newly required fields
- changed meaning of persisted values
- serialization changes that existing data cannot be read safely
- changes that require a one-off migration or operator purge

## Legacy Data

When a database predates schema metadata but contains the known current buckets, treat it as legacy-current and backfill schema metadata on open.

## Verification

At minimum, run:

```bash
go test ./internal/kitchen/db ./internal/kitchen
```

Include compatibility coverage for legacy-current data, safe minor evolution, and schema-major mismatch behavior whenever the persisted contract changes.
