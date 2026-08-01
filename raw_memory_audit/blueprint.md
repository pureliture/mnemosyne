# Raw Memory Audit Blueprint

`raw_memory_audit/` is the canonical package:

1. `requirements.md`, `design.md`, and this blueprint define the behavior and
   read-only boundary.
2. `SKILL.md` is the shared audit workflow and reader-facing result contract.
3. `agent.md` is the shared bounded-worker instruction source.
4. `adapters/` supplies thin Codex and Claude agent envelopes.

The source-owned installer manages these outputs under a selected home root:

```text
.codex/skills/raw-memory-audit/SKILL.md
.codex/agents/raw_memory_audit.toml
.codex/config.toml       (only its marked raw_memory_audit registration)
.claude/skills/raw-memory-audit/SKILL.md
.claude/agents/raw-memory-audit.md
.hermes/skills/raw-memory-audit/SKILL.md
```

Hermes consumes the same canonical skill projection directly. The adapters add
no evidence, verdict, persistence, or correction behavior.

Package tests prove canonical projection parity, registration safety, and the
presence of the approved audit contract. They do not claim live agent loading,
connector access, source-session availability, or a successful audit against a
real raw-memory installation.
