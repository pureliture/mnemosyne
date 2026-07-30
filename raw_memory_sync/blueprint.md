# Raw Memory Sync Blueprint

`raw_memory_sync/` is the canonical package.  The package has four layers:

1. `requirements.md` and this blueprint define the approved behaviour and
   ownership boundary.
2. `SKILL.md` is the canonical invocation contract.
3. `agent.md` is the canonical bounded-worker instruction source.
4. `adapters/` supplies thin Codex and Claude envelopes; the installer renders
   them into user-home projections.

The installer is source-owned and has exactly these managed outputs under a
chosen home root:

```text
.codex/skills/raw-memory-sync/SKILL.md
.codex/agents/raw_memory_sync.toml
.codex/config.toml       (only its marked raw_memory_sync registration)
.claude/skills/raw-memory-sync/SKILL.md
.claude/agents/raw-memory-sync.md
```

It can additionally create `.local/bin/mnemosyne-control` only when explicitly
requested, and only when the destination is absent or already points at the
repository launcher.  It refuses to replace another file or link.  `--check`
does not write and is used with a temporary home root in tests.

The package is a source/static contract.  Its build and fixture checks prove
projection parity and executor fixture behaviour; they do not claim an
installed target's runtime support, registration loading, hook execution, or
live raw-memory success.

Before a workspace-sync PLAN is sealed, the agent writes one owner-only
`mnemosyne-workspace-sync-approval-review-v1` JSON input.  The executor seals
that data in a v2 PLAN, renders the fixed Korean outer headings from it, and
retains every supplied group without a display-time bullet budget.  The PLAN
effects persist the current-state and history groups, so the approval card does
not promise detail that the approved write omits.  The PLAN output stays outside
raw memory in an owner-only, no-symlink parent directory.  Creation preflights
the canonical APPLY transport bound, and apply re-derives the exact
snapshot/history effect texts from the sealed review and captured bases before
publishing either file.  The card also displays the sealed record timestamp
that determines those effect timestamps and history filename.
