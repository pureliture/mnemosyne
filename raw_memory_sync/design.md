# Raw Memory Sync Design

The execution boundary is deliberately narrow:

```text
canonical skill -> canonical agent -> mnemosyne-control PLAN
  -> Korean approval -> exact apply with retained SHA-256
  -> executor receipt/snapshot/history readback
```

The agent never writes memory paths itself.  The executor owns atomic snapshot,
history, and receipt creation.  Receipt `plan_sha256` is the stable sync ID.

The installer reads only this package and writes only the marked adapter
projection paths below an explicit home root.  It does not call an external
component registry or installer and never runs an install against a real home
in tests.
