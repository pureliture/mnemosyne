---
name: raw-memory-audit
description: "Use when the user asks whether one stored raw-memory sentence matches its source session and still matches current authoritative evidence. Read-only and non-persistent."
---

# Raw Memory Audit

Mnemosyne owns this capability. This file is the canonical audit workflow;
installed Codex, Claude, and Hermes files are projections only. All projections
must apply the same evidence and verdict rules.

Use it when the user asks to inspect, verify, or audit an already stored raw
memory. Do not use `raw-memory-sync` merely to inspect a memory.

## Hard boundaries

- This is read-only. Do not create or apply a sync PLAN, edit raw memory, edit a
  workspace source, or mutate an external system.
- Return the audit only in the current conversation. Do not save an audit
  report, sidecar, cache, note, or correction proposal in raw memory or the
  workspace.
- Keep receipt and PLAN hashes internal. A receipt identifies the exact sync
  operation and its evidence boundary; it is not the reader-facing audit unit
  and is not proof that a sentence is true.
- Do not expose or persist raw transcripts, raw command output, private log or
  file bodies, environment dumps, credentials, tokens, emails, endpoints, or
  secret-like values. Cite a sanitized source and summarize only the evidence
  needed for the verdict.
- Never turn a failed audit into an automatic correction. A correction is a
  separate `raw-memory-sync` request with its existing PLAN and approval flow.

## Select one memory sentence

The default audit unit is one complete stored memory sentence, not a receipt,
file, section, workstream, or whole sync.

1. Find the receipt and effect paths internally, then build readable candidates
   from the affected snapshot or history record.
2. Show candidates with plain labels such as date, workspace, workstream, short
   topic, and the sentence itself. Do not ask the user to identify a SHA.
3. If more than one candidate could match the request, explain in plain Korean
   what differs between them and ask the user which sentence to inspect. Stop
   before gathering verdict evidence. Never select the newest or most similar
   candidate by guess.
4. Treat one approval-review item as one sentence only when it is a standalone
   single fact. For a legacy item that mixes facts, combines historical and
   current claims, or has an unclear sentence boundary, report that the
   sentence-level scope cannot be fixed and ask the user to choose or split it.

The receipt fixes which sync operation and stored effects belong to the chosen
sentence. It does not replace the source session. If the sentence itself cannot
be selected unambiguously, ask the user and stop before making either judgment.
If the selected sentence is clear but its receipt, effect path, or sentence
membership cannot be resolved safely, explain what is missing, mark only
`동기화 정확성` as `판단할 근거가 부족함` or `확인할 수 없어 중단`, and continue
the current-freshness judgment whenever its authority can still be inspected.

## Fix the two evidence scopes

Always keep these scopes separate:

- **Source-session scope:** the conversation and bounded source evidence used
  by the sync that stored the sentence. Use it only to decide whether the
  sentence accurately states what that session actually established.
- **Current-authority scope:** the claim-appropriate latest authority observed
  now. Use it only to decide whether a current claim is still true.

Use a readable session or evidence reference stored with the history record
when available. A stored evidence summary helps locate and understand the
source but does not substitute for unavailable primary evidence. Legacy records
with no reliable session or evidence reference receive an insufficient-evidence
judgment; do not reconstruct provenance from similarity, timestamps, or a
nearby file.

## Always make two independent judgments

Run and display both judgments for every selected sentence. One unavailable or
blocked scope never erases the result from the other scope.

### 1. 동기화 정확성

Question: **Did the selected sentence accurately capture what the source
session actually established?**

Use one of these reader-facing judgments:

- `맞음` — the bounded source session and its primary evidence support the
  complete sentence at the stored level of certainty.
- `다름` — the source session contradicts the sentence, uses a narrower scope,
  or left something unverified that the sentence presented as established.
- `판단할 근거가 부족함` — the source session or primary evidence is absent or
  too weak to decide.
- `확인할 수 없어 중단` — permission, safety, corruption, or another explicit
  blocker prevents inspection.

Receipt integrity can show which write is being inspected, but it can never by
itself produce `맞음`.

### 2. 현재 최신성

Question: **Does the selected sentence still match the appropriate current
authority?**

First classify the sentence:

- An immutable historical event or past decision has no changing current
  target. Show `대상 아님` and explain why this fact is historical rather than
  calling it stale.
- A current code claim uses the repository's current reference or default
  branch, not an arbitrary local checkout.
- A current documentation claim uses the latest authoritative document
  version, not an older copy or receipt.
- A runtime or deployment claim uses actual current readback from that runtime.
  Source code, CI, or a deployment declaration is not runtime readback.
- For another claim type, name the authoritative current source before judging.

Use one of these reader-facing judgments:

- `현재도 맞음`
- `현재와 다름 — 낡은 정보`
- `대상 아님`
- `판단할 근거가 부족함`
- `확인할 수 없어 중단`

Do not infer freshness from a recent timestamp, receipt integrity, or the fact
that a sentence is still present in the current snapshot.

## Reader-facing result

Explain enough for the user to understand what was compared. Prefer this plain
Korean structure:

```markdown
검사한 기억: "<선택한 한 문장>"
저장 작업: <날짜 · workspace · workstream · 짧은 주제>

1. 동기화 정확성
- 판정: <맞음 | 다름 | 판단할 근거가 부족함 | 확인할 수 없어 중단>
- 비교한 것: <해당 저장 작업의 원본 세션과 근거>
- 이유: <판정을 이해할 수 있는 설명>

2. 현재 최신성
- 판정: <현재도 맞음 | 현재와 다름 — 낡은 정보 | 대상 아님 |
  판단할 근거가 부족함 | 확인할 수 없어 중단>
- 비교한 것: <현재 권위 자료 또는 대상 아님인 이유>
- 이유: <독립 판정을 이해할 수 있는 설명>

메모 변경: 없음
```

Do not show internal enums or hashes in the normal result. If the memory looks
wrong or stale, state that a separate approved `raw-memory-sync` can prepare a
correction only after the user asks for it.
