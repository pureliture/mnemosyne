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

The installer reads only this package and writes only the marked adapter
projection paths below an explicit home root.  It does not call an external
component registry or installer and never runs an install against a real home
in tests.
