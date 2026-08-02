# Collect Raw Sync History Blueprint

`collect_raw_sync_history/` is the canonical package:

1. `requirements.md`, `design.md`, and this blueprint define the approved
   behavior and raw-only placement boundary.
2. `SKILL.md` owns invocation and reader-facing presentation.
3. `agents/openai.yaml` supplies user-interface metadata only.

The shared implementation lives in
`scripts/mnemosyne_core/raw_memory_query.py`. The public read-only CLI is:

```text
mnemosyne-control context collect-sync-history \
  --from-date YYYY-MM-DD --to-date YYYY-MM-DD --json --root <raw-root>
```

The module is part of `mnemosyne.py`'s verified `RUNTIME_MODULE_CLOSURE` and is
bound by the verified bootstrap before the CLI calls it. This keeps runtime
source hashing and installed-entrypoint manifests complete.

The source-owned installer projects this skill only under an explicitly chosen
raw root:

```text
<raw-root>/.agents/skills/collect-raw-sync-history/SKILL.md
<raw-root>/.agents/skills/collect-raw-sync-history/agents/openai.yaml
```

It must not create a user-global
`.codex/skills/collect-raw-sync-history`,
`.claude/skills/collect-raw-sync-history`, or
`.hermes/skills/collect-raw-sync-history` projection. Canonical source remains
in this repository; the raw repository receives only the generated projection.

Hermes discovers that same raw projection through `skills.external_dirs`. With
an explicit raw root, the installer manages the resolved
`<raw-root>/.agents/skills` entry in the default Hermes config and in an
already-existing named `mnemosyne` profile. It preserves unrelated YAML and
owns only its bounded marked list fragment. This skill-only projection lane is
separate from the existing agent/adapters, Claude, and managed Codex agent-
registration lane.

Tests prove date filtering, multi-item expansion, exact-only deduplication,
source reporting, read-only behavior, and projection parity. They do not claim
that a particular interactive runtime has reloaded the skill until a separate
installation smoke check observes discovery.
