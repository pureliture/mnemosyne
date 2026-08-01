---
name: raw-memory-sync
description: "Mnemosyne-owned, approval-gated workspace context sync."
---

# Raw Memory Sync

Mnemosyne owns this capability.  This file is canonical; installed Codex and
Claude files are projections only.  Do not delegate this capability outside
Mnemosyne.

Use it when the user asks to sync, update, register, or refresh raw memory for
the current workspace, including `/raw-memory-sync`.  Accepted hints are
`--workspace <slug>`, repeated `--exclude <glob>`, workspace-root
`.raw-memory-ignore`, `--workstream <id>`, a structured handoff path, and a
sanitized outcome summary.

Use `raw-memory-audit` instead when the user asks only whether an existing
memory is accurate or current. An audit request must not create a review, PLAN,
or memory write.

## Boundaries

- Do not write `~/raw/memory` directly, call raw external APIs, or mutate Jira,
  Confluence, GitHub, or another external system.
- Do not use `mnemosyne` or direct `--apply`.  Always use
  `mnemosyne-control memory-sync --plan-out ... --approval-review ...`, render
  the sealed card with `--render-approval-card ...`, then apply the unchanged
  approved PLAN with `--apply-plan ... --expected-plan-sha256 ...`.
- Keep raw command output, raw private logs and bodies, environment dumps,
  tokens, emails, credentials, and secret-like values out of output and stored
  context.  Store a transcript summary unless the user explicitly approves raw
  transcript storage.
- Store each factual approval-review item as one complete standalone plain-text
  sentence expressing one fact. Split a historical event or decision from any
  claim about what is currently true, even when they are closely related.
- Apply base safety skips, `.raw-memory-ignore`, and `--exclude` before
  candidate discovery.  Report ignored candidates as metadata only, grouped by
  ignore source.  An explicit include can override only ignore/exclude matches,
  never a safety or secret ban.

## Approval flow

Resolve the workspace and require interactive workstream selection unless batch
mode supplies a valid explicit workstream ID.  Before creating a PLAN, prepare
one owner-only (`0600`) JSON approval review.  It is sealed inside the PLAN,
then the executor renders the Korean card from that exact sealed data.  Do not
handwrite a second approval-card summary.

Create the PLAN with both files:

```text
mnemosyne-control memory-sync --plan-out <plan> --approval-review <review.json> ...
```

Keep `<plan>` outside `<root>/memory`.  Keep both `<plan>` and `<review.json>`
in pre-existing owner-only directories with no symlink component (do not use
`/tmp`).  PLAN creation is not allowed to create an unapproved file under raw
memory.

`<review.json>` has exactly this shape.  Every `ref` must match one `--ref`
value exactly and needs a role that explains why a reader should consult it.

```json
{
  "schema": "mnemosyne-workspace-sync-approval-review-v1",
  "overview": "이번 승인으로 무엇을 최신 상태와 기록에 남기는지, 가장 중요한 경계까지 한두 문장으로 설명합니다.",
  "current_state_groups": [
    {"title": "현재 저장소와 CI에서 확인된 사실", "items": ["..."]}
  ],
  "history_groups": [
    {"title": "이번에 대조한 범위", "items": ["..."]}
  ],
  "exclusions": ["원본 명령 출력과 credential"],
  "references": [{"ref": "docs/example.md", "role": "현재 기준을 확인한 자료"}]
}
```

The outer card hierarchy is fixed, but its groups and bullet count are not.
Never compress a long, multi-evidence session into one summary sentence.

Every item in `current_state_groups` and `history_groups` is an auditable memory
sentence:

- Write one fact per item in plain language; do not depend on the group title
  to complete its meaning.
- Put historical events and past decisions in their own sentences. Put current
  assertions in separate sentences so a later audit can judge freshness
  independently.
- In the history groups, summarize which evidence the source session actually
  observed and what remained unverified. Keep this summary readable and
  sanitized; never copy a raw transcript, command output, log, or private body.
- Use readable session and evidence references when available. Hashes remain
  internal operation bindings, not prose that a future reader must understand.
- The overview, title, and summary may summarize the items but must not add a
  factual claim that is absent from the auditable items.

- A simple path or link update may have one compact group in each area.
- Use a detailed evidence ledger when two or more evidence sources are
  involved; facts and unknowns coexist; history needs correction; several user
  decisions matter; an earlier proposal was rejected; or source/CI evidence
  must not be misrepresented as runtime success.
- In detailed cards, split the actual content with natural Korean titles such
  as `현재 저장소와 CI에서 확인된 사실`, `사용자가 정한 운영 방향`,
  `아직 실제 실행으로 확인하지 않은 것`, `이번에 대조한 범위`,
  `기존 기록에서 이어 가거나 바로잡는 내용`, and
  `현재 목표에서 제외하는 제안`.  Do not add a separate evidence-status
  legend or table.
- Keep current facts, user decisions, unverified runtime boundaries, history
  corrections, excluded ideas, and stored exclusions separate.  A current
  source or CI result is never proof that an unrun target runtime succeeded.
- Do not hide raw logs, credentials, endpoints, raw transcript bodies, or a
  full source document inside an item.  They remain excluded even in a detailed
  card.

Render and present only the executor output:

```text
mnemosyne-control memory-sync --render-approval-card <plan>
```

The card always has this reader-facing structure:

```markdown
# 승인 요청 — <workspace>

## 한눈에 보기
> **<이번 승인으로 저장하는 결론과 가장 중요한 경계>**
>
> - **이번 동기화:** <title>
> - **적용 결과:** 최신 상태 1개 갱신 · 기록 1건 추가
> - **저장 제외:** <첫 제외 항목과 나머지 개수>

---

## 최신 상태에 반영할 내용
- **대상 workstream:** `<id>` (<신규|기존>)
### <현재 사실·결정·미확정 사항의 적절한 묶음>
- ...

## 기록으로 남길 내용
### <조사 범위·정정·제외 제안의 적절한 묶음>
- ...

## 이번 기록에 포함하지 않는 내용
- ...

## 참고 자료
- `<ref>` — <role>

## 그 밖의 변경
- 최신 상태(snapshot) 1개를 갱신합니다.
- 기록(history) 1건을 추가합니다.
- 승인 전에는 raw memory를 변경하지 않습니다.

이 내용 그대로 적용할까요?
```

Keep the PLAN SHA-256 internally; do not ask the user to copy it or use it in an
approval card, audit candidate, or normal audit result. After unambiguous
approval, apply only that exact PLAN. Read back the returned snapshot, history,
and receipt paths. After apply, report the receipt's `plan_sha256` only as the
existing sync ID. If a base or PLAN changed, stop and create a new PLAN when
appropriate.
