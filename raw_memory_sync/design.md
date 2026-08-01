# Raw Memory Sync Design

The execution boundary is deliberately narrow:

```text
canonical skill -> canonical agent -> owner-only approval-review JSON
  -> mnemosyne-control sealed PLAN -> deterministic Korean card renderer
  -> exact apply with retained SHA-256
  -> executor receipt/snapshot/history readback
```

The agent never writes memory paths itself.  The executor owns atomic snapshot,
history, and receipt creation.  The approval review is validated, carried in
the v2 PLAN, rendered without agent paraphrase, and written into the planned
snapshot/history detail so the card does not promise content the effects omit.
Immediately before apply, the executor re-derives those two effects from the
sealed review and hash-bound bases; a PLAN with arbitrary or hidden final text
is blocked instead of being written.
Receipt `plan_sha256` is the stable sync ID.

The structured review items are also the later audit boundary: each item is one
standalone plain-text fact. Historical facts and current assertions are split,
and history retains sanitized evidence summaries and readable references. This
adds no receipt or executor field; the existing PLAN still seals the exact
review and receipt SHA remains an internal operation binding.

Read-only semantic verification is owned by the sibling `raw-memory-audit`
package. It never enters this writer pipeline.

The shared installer reads only the canonical `raw_memory_sync/` and
`raw_memory_audit/` packages and writes only their marked projection paths
below an explicit home root. It does not call an external component registry or
installer and never runs an install against a real home in tests.
