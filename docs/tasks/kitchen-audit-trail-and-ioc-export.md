# Kitchen Audit Trail And IOC Export

## Why This Exists

Kitchen is the place where enumeration, validation, exploitation, and operator-originated actions should begin and be recorded.

SmokedMeat already has operation history, known-entity persistence, and authenticated HTTP and WebSocket boundaries. What it does not yet have is a comprehensive, append-only audit trail and export format that can answer:

- what action was attempted
- by whom
- when
- from where
- against which repo, org, workflow, or vuln
- with which credential identity
- what connected back
- what secrets were exfiltrated

This task exists to extend current history into a real audit and reporting surface.

## Current Product Facts

Relevant facts today:

- Kitchen already persists operation history in BBolt
- history already includes analysis, exploit attempts, exploit outcomes, agent connections, and secret extraction events
- Kitchen auth middleware already logs structured security events
- Counter already fetches and records history through `/history`

Implication:

- the product already has a partial foundation
- the current history model is too thin for serious audit, reporting, or IOC export

## Product Goal

Add an append-only Kitchen audit trail that can be exported and reviewed.

The audit trail should capture:

- operator action type
- operator identity
- source host information
- timestamps
- target org, repo, workflow, vuln, and delivery path
- credential identity used for the action
- callback and agent linkage
- exfiltrated credential summary

The operator should be able to retrieve this from Counter without shelling into Kitchen manually.

## Non-Goals

This task is not:

- a SIEM replacement
- a promise to store every piece of secret material in plaintext
- a replacement for current history broadcasts

The first slice is trustworthy audit and export, not full analytics.

## Required Audit Fields

### Operator action metadata

- action type
- session ID
- operator name
- timestamp
- target org or repo
- target workflow or vuln when relevant
- delivery method or validation method when relevant

### Origin metadata

- source IP address seen by Kitchen
- resolved reverse DNS when available
- operator host or workstation label when available

### Credential identity

For GitHub tokens and similar credentials, keep:

- token prefix in plaintext
- SHA-256 of the token value
- token type if known
- actor or login if known

This is intended to support correlation with GitHub audit log token attribution, where the token hash is the stable audit key and the prefix remains useful for operator-facing identification.

### Callback and implant outcomes

- stager or callback ID
- callback timestamp
- agent ID
- runner or host context when known

### Exfiltration summary

- secret type
- masked or prefixed identifier
- hash where useful
- repo and workflow context
- extraction timestamp

## Design Principles

### 1. Audit trail is append-only

The audit trail must survive purge operations and should not be rewritten as normal operator state changes.

### 2. Kitchen is the source of truth

Counter can display and export audit data, but the authoritative log must live in Kitchen.

### 3. Store identifiers, not raw secret values

For audit and IOC export, the useful fields are usually:

- prefix
- type
- hash
- context

not the full credential body.

### 4. Separate operator history from formal audit

The current history feed is still useful as operator UX. Audit needs stronger retention guarantees, richer fields, and clearer export semantics.

## Export Formats

Initial export targets should include:

- JSON for complete machine-readable detail
- line-oriented JSON or JSONL for pipeline use
- optional summarized human-readable report later

Useful export groupings:

- by session
- by org
- by repo
- by time range

## Product Flow

### During operation

Kitchen appends audit events for:

- analyze started and completed
- validation started and completed
- exploit attempted, succeeded, or failed
- callback received
- agent connected
- secrets extracted
- purge action performed

### From Counter

The operator should be able to:

- review recent audit entries
- request an export bundle
- download the result from Kitchen

## Implementation Plan

### Phase 1 - Define audit schema

Deliverables:

- event types
- required fields
- token fingerprint rules
- secret masking rules

Done when:

- audit rows are richer than current history rows and the schema is stable enough to build on

### Phase 2 - Persist append-only audit entries

Deliverables:

- Kitchen-side durable audit store
- append-only semantics
- separation from purgeable operational state

Done when:

- exploitation and exfiltration actions leave durable audit records

### Phase 3 - Export and retrieval

Deliverables:

- audit export endpoint
- Counter retrieval flow
- JSON or JSONL export

Done when:

- the operator can extract a coherent audit trail without direct filesystem access to Kitchen

## Open Questions

- Should audit live in a separate BBolt bucket or separate file?
- Should host enrichment such as reverse DNS happen synchronously or lazily?
- Do we want signed export manifests later?

## Done Criteria

This task is in good shape when:

- Kitchen records an append-only audit trail for analysis, validation, exploitation, callback, and exfiltration actions
- token identities can be correlated using prefix plus SHA-256
- purge does not destroy audit trail
- Counter can request and download audit exports
