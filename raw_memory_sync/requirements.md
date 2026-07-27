# Raw Memory Sync Requirements

## Ownership

Mnemosyne owns `raw-memory-sync`.  This directory is its canonical source.
Codex and Claude files are installed projections, not sources of truth, and do
not confer delegation or ownership outside Mnemosyne.

## Required behaviour

1. Resolve the workspace and filter candidates before collection.  Base safety
   skips precede workspace `.raw-memory-ignore`, invocation `--exclude`, and a
   user include request; an include can restore only ignore/exclude matches.
2. Keep collection local and read-only.  Never persist or print raw command
   output, raw file or log bodies, environment dumps, credentials, tokens,
   email values, or secret-like values.  Store transcript summaries by default;
   raw transcripts require explicit approval.
3. Require interactive workstream selection unless batch mode has an explicit
   valid workstream id.  Branches, worktrees, tickets, pages, and PRs are
   references, not split keys.
4. Before any write, create exactly one sealed PLAN with
   `mnemosyne-control memory-sync --plan-out ...`.  Present the Korean approval
   card only, retain the plan SHA-256 internally, and wait for approval of that
   exact plan.
5. After approval, apply the unchanged PLAN only with
   `mnemosyne-control memory-sync --apply-plan ... --expected-plan-sha256 ...`.
   Direct writes, `--apply`, `mnemosyne`, raw external APIs, and Jira,
   Confluence, GitHub, or other external mutations are forbidden.
6. A successful apply must be read back through the executor's snapshot,
   history, and receipt paths.  The sync ID is the approved PLAN SHA-256 kept
   in receipt `plan_sha256`; no executor-core field is added for this package.
7. Generated Codex and Claude projections must be derived from the same
   canonical skill and agent sources, contain the `mnemosyne-control` binding,
   and make no runtime-support claim.

## Approval-card contract

The plan-ready response is plain Korean understandable by a 15-year-old.  It
shows each exact workstream, its separate snapshot and history effects,
sanitized references, and other changes.  It does not expose the PLAN path or
SHA-256 by default.  Its final non-empty line is exactly:

```text
이 내용 그대로 적용할까요?
```
