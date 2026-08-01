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
   Every factual approval-review item is one complete standalone plain-text
   sentence expressing one fact. Historical facts and current assertions are
   separate items. History groups preserve a sanitized plain-language summary
   of the evidence the source session observed and what remained unverified.
3. Require interactive workstream selection unless batch mode has an explicit
   valid workstream id.  Branches, worktrees, tickets, pages, and PRs are
   references, not split keys.
4. Before any write, create one owner-only structured approval review and seal
   it inside exactly one PLAN with
   `mnemosyne-control memory-sync --plan-out ... --approval-review ...`.
   The PLAN output path must be outside `<root>/memory`, in a pre-existing
   owner-only directory with no symlink components; creating a PLAN must not
   itself add an artifact to raw memory.
   Render and present the Korean approval card only from that exact PLAN, retain
   the plan SHA-256 internally, and wait for approval of that exact plan.
5. After approval, apply the unchanged PLAN only with
   `mnemosyne-control memory-sync --apply-plan ... --expected-plan-sha256 ...`.
   Before any raw-memory write, the executor must re-derive the exact
   snapshot/history effects from the sealed review and hash-bound bases, and
   reject any mismatched effect.  PLAN creation must preflight the exact
   canonical APPLY request against the operation-contract transport bound and
   reject any oversized derived PLAN before publishing a PLAN file.
   Direct writes, `--apply`, `mnemosyne`, raw external APIs, and Jira,
   Confluence, GitHub, or other external mutations are forbidden.
6. A successful apply must be read back through the executor's snapshot,
   history, and receipt paths.  The sync ID is the approved PLAN SHA-256 kept
   in receipt `plan_sha256`; no executor-core field is added for this package.
7. Generated Codex and Claude projections must be derived from the same
   canonical skill and agent sources, contain the `mnemosyne-control` binding,
   and make no runtime-support claim.
8. Read-only inspection of an existing memory belongs to `raw-memory-audit`.
   It must not enter this package's review, PLAN, approval, or apply flow.

## Approval-card contract

The plan-ready response is plain Korean understandable by a 15-year-old.  Its
outer Markdown structure is always `한눈에 보기` (at the top),
`최신 상태에 반영할 내용`, `기록으로 남길 내용`,
`이번 기록에 포함하지 않는 내용`, `참고 자료`, and `그 밖의 변경`.
The data under the two content sections is adaptive: compact work can remain
short, while a long or multi-evidence session retains separate natural-language
groups for facts, user decisions, unverified boundaries, investigation scope,
history corrections, and excluded proposals when they apply.  The card and
sealed PLAN use the same structured review data; it does not expose the PLAN
path or SHA-256 by default.  It does show the sealed record timestamp because
that timestamp controls both the history filename and the snapshot update.
Its final non-empty line is exactly:

```text
이 내용 그대로 적용할까요?
```
