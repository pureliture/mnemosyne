# Lookup Raw Project Context Blueprint

`lookup_raw_project_context/` is the canonical package:

1. `requirements.md`, `design.md`, and this blueprint define behavior,
   evidence ordering, and the code-as-current-truth boundary.
2. `SKILL.md` owns invocation, code follow-through, and mismatch presentation.
3. `agents/openai.yaml` supplies user-interface metadata only.

The shared implementation lives in
`scripts/mnemosyne_core/raw_memory_query.py`. The public read-only CLI is:

```text
mnemosyne-control context lookup-project-context \
  --project-root <path> --question <text> --task-context <text> \
  --json --root <raw-root>
```

The module is part of `mnemosyne.py`'s verified `RUNTIME_MODULE_CLOSURE` and is
bound by the verified bootstrap before the CLI calls it. This keeps runtime
source hashing and installed-entrypoint manifests complete.

The source-owned installer projects the skill at user level:

```text
<home>/.codex/skills/lookup-raw-project-context/SKILL.md
<home>/.codex/skills/lookup-raw-project-context/agents/openai.yaml
<home>/.hermes/skills/lookup-raw-project-context/SKILL.md
```

The Codex UI metadata is not a Hermes input. Both runtimes consume the same
canonical `SKILL.md`; no Hermes-specific behavior fork is maintained.

No dedicated subagent registration is required. The skill returns control to
the active task after providing context; it does not own or authorize later
code mutation.

Tests prove exact project resolution, all four lookup outcomes, source
reporting, relevance ordering, read-only behavior, and projection parity.
`SKILL.md` defines the raw-before-code sequence and code source-of-truth response
contract; the current tests do not execute that agent-level forward path or
claim deployment or live-runtime truth.
