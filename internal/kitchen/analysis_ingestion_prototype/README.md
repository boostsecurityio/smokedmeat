# Analysis Ingestion Interface Prototype

PROTOTYPE - throw this branch away after the interface decision is captured.

## Question

Which external interface gives Kitchen the deepest Analysis ingestion module:
a minimal completed-result commit, an explicit prepare-and-commit lifecycle, or a
caller-shaped flow that owns remote Analysis through durable Pantry publication?

The prototype runs the same state transitions through all three interface shapes
and exposes everything the caller must know. It uses only in-memory state.

Run it with:

```sh
make prototype-analysis-ingestion
```

Try successful replacement, independent phase failure, confirmed-gone cleanup,
no-op reconciliation, and persistence failure under each design.
