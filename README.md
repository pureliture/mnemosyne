# Mnemosyne

Mnemosyne is the Safe Librarian for organizing documents under `~/raw` through
explicit inspection, review, approval, and placement steps.

This repository is the canonical source for the Mnemosyne code, tests, and
Skill. Live memory under `~/raw/memory` and user-installed Skill copies are
runtime projections; they are not stored here.

## Verification

Python 3.10 or newer is required.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts python3 -m unittest discover -s tests -p 'test_*.py'
```
