# ~/raw Mnemosyne layout & milestones

## Layout (control vs content)

```
~/raw/
  _registry/                 # machine-control SoT (not corpus content)
    placement-map.yml
    pending/                 # status=pending proposals
    decisions/               # approved/rejected history
  inbox/                     # new arrivals default entry
  memory/                    # workspace memory (redaction-heavy)
    workspaces.yml           # do not relocate
    <workspace>/snapshot.md
    <workspace>/history/
  # Skill sources, CLI, tests, git repo live in ~/Projects/mnemosyne/
  # (published sanitized source).
  projects/, artifacts/, reports/, private/, ...
  worktrees/, graphify-out/  # never-touch for placement
```

## Locked product decisions (do not reopen lightly)

1. Always propose → approve for content moves
2. Listable pending queue + decision history required
3. MVP surface = chat + on-disk files (UI later)
4. New/inbox first; selective retroactive only with user scope
5. Registry at `_registry/`; keep `memory/workspaces.yml`
6. Graphify explicit-request-only
7. Human operator primary; agent context secondary

## Milestones

| ID | Scope | Status |
| --- | --- | --- |
| M1 | Registry scaffold + SKILL + bootstrap | done |
| M2 | place propose/approve/reject + list | done |
| M3 | audit read-only | done |
| M4 | memory-sync (history + careful snapshot) | handoff: `HANDOFF-CODEX-M4.md` |
| M5 | context provision for other agents | later |

## Codex handoff pattern

When Hermes tokens are low:

1. Freeze SoT: `requirements.md` (+ closed open questions)
2. Write `HANDOFF-CODEX.md` with locked decisions, paths, work order, non-goals
3. Note git boundary (`~/Projects/mnemosyne` repo vs non-git `~/raw`)
4. Prefer design.md then code; verify with unittest + real smoke after return

## doc-curator adaptation (what we took)

- Registry-first machine control
- Modes: bootstrap / place-sync-like / audit
- Metadata not embedded in content files
- Overwrite safety; no auto-commit

What we did **not** take: full human-view .md/.html pair pipeline.
