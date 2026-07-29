# Mnemosyne

Mnemosyne is the Safe Librarian for organizing documents under `~/raw` through
explicit inspection, review, approval, and placement steps.

This repository is the canonical source for the Mnemosyne code, tests, and
Skill. Live memory under `~/raw/memory` and user-installed Skill copies are
runtime projections; they are not stored here.

Mnemosyne also owns `raw-memory-sync` in `raw_memory_sync/`.  Its Codex and
Claude installed files are generated projections, not sources of truth.  Build
or check a chosen (normally temporary) home root without invoking another
component registry:

```bash
python3 scripts/raw_memory_sync_install.py --home-root /tmp/mnemosyne-home
python3 scripts/raw_memory_sync_install.py --home-root /tmp/mnemosyne-home --check
```

When a local `mnemosyne-control` command is needed, add `--install-launcher`.
The installer then writes both `.local/bin/mnemosyne-control` and its
owner-only lock-migration manifest at
`.local/share/mnemosyne/installed-entrypoints.json`; check both with
`--check --install-launcher`.

## Verification

Python 3.10 or newer is required.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts python3 -m unittest discover -s tests -p 'test_*.py'
```
