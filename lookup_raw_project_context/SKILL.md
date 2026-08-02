---
name: lookup-raw-project-context
description: "Use at the start of a project development or code question to read related raw context before inspecting current code. Read-only lookup; current code remains the source of truth for implementation facts."
---

# Lookup Raw Project Context

Mnemosyne owns this canonical user-level skill. Use raw context as a guide
before new code inspection, then answer current implementation questions from
the current code. This skill itself does not authorize a code or raw-memory
change.

## Boundaries

- Read only. Do not modify raw, the current project, caches, reports, or
  external systems.
- Query raw context before starting new project-code exploration for the active
  question. Existing user-provided code evidence may be retained, but do not
  begin additional inspection first.
- A receipt or stored context can locate provenance; it cannot establish that a
  claim is currently true.
- Do not use this skill for date-range work-list collection. Use
  `collect-raw-sync-history` for that raw-only task.

## Resolve the query inputs

1. Build `project-root` without asking for information already available in the
   task: use the active task or repository workspace root first; otherwise run
   `rtk git rev-parse --show-toplevel` from the current directory; only if that
   is unavailable use the current working directory. Never pass a nested
   directory when a Git top-level is observable.
2. Use the active task context and the user's question together. Keep task
   context concise and factual; do not invent missing goals or identity clues.
3. Use the task-known raw root when available. Otherwise resolve the current
   user's standard `~/raw` location and use it only when
   `memory/workspaces.yml` is readable there. If neither source yields a
   readable raw root, report `unavailable` with that reason and continue to
   relevant code exploration; do not search for or guess a similar directory.

## Look up raw before code

Run the canonical read-only query before any new code exploration:

```bash
rtk mnemosyne-control context lookup-project-context \
  --project-root <project-root> --question <user-question> \
  --task-context <active-task-context> --json --root <raw-root>
```

Pass the question and task context as safely quoted individual arguments; do
not construct a shell command by interpolating their raw text.

Handle every returned outcome explicitly:

- `found`: read the bounded raw snapshot and relevant history excerpts first;
  retain their readable source paths for the response.
- `not_found`: state that no matching raw project context was found, then
  continue code exploration when the question needs it.
- `ambiguous`: show the candidate workspaces or missing identity evidence; do
  not select one, then continue code exploration when needed.
- `unavailable`: state the supplied reason and affected path; do not bypass
  safety checks, then continue code exploration when needed.

## Inspect code and report truth

After the lookup outcome, inspect only current code relevant to the question.
For current implementation facts, current code is the source of truth.

If raw and code differ:

1. Preserve both sources; do not silently rewrite the raw context.
2. When the difference changes the answer, put this short notice at the top:

   ```markdown
   주의: raw 맥락과 현재 코드가 다릅니다. 현재 구현 사실은 코드를 기준으로 설명합니다.
   ```

3. In the detailed evidence, separate `raw 맥락` (with source path) from
   `현재 코드` (with file and relevant location). Smaller differences can stay
   in that detailed evidence without the top notice.

Use this compact response shape:

```markdown
raw 조회: <found | not_found | ambiguous | unavailable>
- raw 출처 또는 사유: <path / candidate / reason>

현재 코드 기준:
- <answer and code evidence>

raw 맥락과의 관계:
- <consistent / difference and its impact>

변경: 없음
```

Never present a raw lookup as current code, runtime, deployment, or external
system verification. This skill only supplies read-only context: when the
active task already authorizes a code change, return control to that approved
workflow after the lookup and code assessment without creating another approval
gate. When no change authority exists, do not mutate code.
