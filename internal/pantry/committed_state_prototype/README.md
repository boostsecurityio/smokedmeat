# Pantry Committed-State Transaction Prototype

PROTOTYPE - throw this branch away after the interface decision is captured.

## Question

Which Pantry-level interface best guarantees old-or-new reader visibility,
writer participation, persistence-first replacement, and ordered publication
without making callers manage transaction mechanics?

The prototype compares a raw candidate callback, an explicit transaction
capability, and a restricted Draft callback. Each interface drives the same
in-memory committed-state model.

Run it with:

```sh
make prototype-pantry-transaction
```

Begin a transaction, mutate the candidate, sample a reader, queue metadata
sync, then commit or fail persistence. Also try cancellation before and after
the durable commit point, an unchanged no-op, and leaking the candidate
capability.
