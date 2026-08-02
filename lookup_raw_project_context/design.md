# Lookup Raw Project Context Design

The read-only flow is:

```text
current project root + current task context + user question
  -> exact normalized workspace-root lookup
  -> found | not_found | ambiguous | unavailable
  -> bounded raw snapshot and question-relevant history excerpts
  -> agent reads that result before new code inspection
  -> agent inspects current code using raw only as a guide
  -> current-code answer, with any material raw/code mismatch disclosed
```

Project identity is an exact normalized match between the current project root
and `memory/workspaces.yml`. Similar names, comments, sibling repositories, and
recency are not identity proof. Equal matches return readable candidates rather
than selecting one.

The skill derives that root without asking for information already available in
the task: use the active repository or explicit task workspace root first, then
the current Git top-level, and use the current working directory only when no
repository root is available. A nested working directory is never passed as the
project identity when its repository top-level can be observed.

For raw storage, an explicit task-known root wins. Otherwise the user-level
skill checks the current user's standard `~/raw` path and uses it only when its
workspace registry is readable. It does not search other directories by name.

The shared query core reads raw context and reports source paths. It does not
inspect arbitrary project code and does not decide whether a stored statement
is currently true. Receipt linkage, when present, is mechanical provenance
only; it does not replace the raw source and does not prove semantic truth.

The user-level skill owns the cross-source sequence. It runs the raw lookup
before any new code inspection, then inspects only code relevant to the active
question. Current code is the source of truth for current implementation facts.
If raw and code differ, the answer preserves both sources instead of silently
rewriting one into the other. A mismatch that changes the answer receives a
short notice at the top; smaller differences stay with the detailed evidence.

`not_found`, `ambiguous`, and `unavailable` are expected query outcomes. The
skill reports the outcome and continues current-code inspection when the user
question calls for it. Neither the query nor the skill writes raw memory,
project files, caches, or reports.

Default lookup bounds are deterministic: at most eight history records, at most
2,000 characters per history excerpt, at most 12,000 snapshot characters, and
at most 24,000 characters in the JSON result. Truncation is explicit in the
result instead of silently widening the read.

The user-level package is projected from one canonical `SKILL.md` to both
Codex and Hermes. Codex also receives `agents/openai.yaml` for its UI metadata;
Hermes consumes only the canonical skill workflow and receives no divergent
adapter or UI metadata copy.
