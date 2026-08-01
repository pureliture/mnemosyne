# Raw Memory Audit Design

The shared read-only flow is:

```text
readable memory candidates
  -> user-selected one-sentence unit
  -> internal receipt/effect boundary
  -> bounded source-session evidence
  -> independent synchronization-accuracy judgment
  -> claim-specific current authority
  -> independent current-freshness judgment
  -> plain Korean conversation result
```

The receipt boundary prevents evidence from a different sync operation from
being silently substituted. It does not establish that a stored sentence
semantically matches its source.

The two judgments deliberately use different evidence. Synchronization accuracy
asks what the source session established; current freshness asks what the
appropriate authority says now. An immutable historical fact has no changing
current target and therefore receives `대상 아님`, while a current code,
document, or runtime claim must be checked against its own authority.

No audit artifact is materialized. The canonical skill and agent are the shared
decision engine; adapters only expose that same source to Codex, Claude, and
Hermes. Memory correction stays in the separately approved `raw-memory-sync`
flow.
