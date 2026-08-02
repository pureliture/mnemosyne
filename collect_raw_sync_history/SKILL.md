---
name: collect-raw-sync-history
description: "Use when working inside the raw repository and the user asks to collect or list work synced to raw for a date range. Read-only; do not use for project-code context or follow-up changes."
---

# Collect Raw Sync History

Mnemosyne owns this canonical skill. Its installed raw-repository copy is a
projection only. Use it only while the active workspace is the raw repository;
do not use it to infer current project implementation facts.

## Boundaries

- Read only. Do not edit raw memory, a project, a cache, or an external
  system.
- A follow-up change using this result is outside this skill. Follow it only
  when the user separately requests that work.
- Do not use the result as a substitute for current code or runtime evidence.
- Treat receipt linkage as mechanical provenance only, never as semantic proof.

## Collect

1. Confirm the active root is the raw repository. Use the raw task workspace
   root when available; otherwise use the current directory only when it is
   clearly that raw repository. If it cannot be established, report that the
   raw-only scope is unavailable and stop without guessing another directory.
2. Obtain an inclusive `from-date` and `to-date` in `YYYY-MM-DD`. If either
   boundary is absent, ask only for the missing date range; do not run a broad
   query or ask for unrelated context.
3. Run the canonical read-only query and inspect its JSON result:

   ```bash
   rtk mnemosyne-control context collect-sync-history \
     --from-date <YYYY-MM-DD> --to-date <YYYY-MM-DD> \
     --json --root <raw-root>
   ```

4. Report each returned work item as a separate chronological list item. Show
   its sync record time, readable source reference, and raw history path when
   returned. Preserve separate records unless the CLI has already removed a
   completely identical reader-facing record.
5. Report unreadable, malformed, or unsafe files separately with their path
   and reason. Do not reconstruct their contents or silently omit the issue.

## Reader-facing result

Use compact Korean output:

```markdown
조회 구간: <from-date> ~ <to-date> (양 끝 포함)

- <sync record time> · <workspace / workstream>
  - 작업: <one work item>
  - 출처: <readable source reference>
  - raw 기록: <history path>

읽지 못한 기록:
- <path> — <reason>

변경: 없음
```

When no record matches, say so plainly and retain `변경: 없음`. Do not claim
that this is a project-context lookup, code verification, or downstream work
completion.
