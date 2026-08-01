# Raw Memory Audit Requirements

## Ownership

Mnemosyne owns `raw-memory-audit`. This directory is its canonical source.
Codex, Claude, and Hermes files are installed projections and must use the same
audit rules.

## Required behavior

1. The default audit unit is one complete stored memory sentence expressing one
   fact. A receipt identifies its exact sync-operation and effect boundary
   internally; it is not the audit unit and is not reader-facing evidence of
   truth.
2. Candidate selection is readable. When more than one sentence or sync could
   match, the worker explains the differences and asks the user to choose. It
   never guesses from similarity or recency.
3. Every completed audit independently reports synchronization accuracy and
   current freshness. A blocked or insufficient result in one dimension does
   not erase the other dimension.
4. Synchronization accuracy compares the sentence with what the bounded source
   session and its primary evidence actually established. Receipt or effect
   integrity alone cannot support a semantic verdict.
5. Current freshness uses claim-specific current authority: reference/default
   branch for code, latest authoritative version for documents, and actual
   readback for runtime or deployment claims.
6. Immutable historical events and past decisions report current freshness as
   `대상 아님` with a reason. They are not labeled stale merely because time has
   passed.
7. Legacy records with weak provenance, unclear sentence boundaries, or mixed
   historical/current content receive an evidence-limited result rather than
   reconstructed or guessed provenance.
8. The normal result is plain Korean, omits internal hashes and enums, and
   explains what was compared for each judgment.
9. Auditing is read-only and non-persistent. It writes no report, cache,
   sidecar, correction, PLAN, raw-memory file, workspace file, or external
   record.
10. A correction can begin only as a separate user-requested `raw-memory-sync`
    operation under its existing exact-PLAN approval contract.

## Security and evidence boundary

Raw transcripts, command output, private bodies, logs, environments, emails,
credentials, tokens, endpoints, and secret-like values are neither displayed
nor persisted. Sanitized summaries help locate evidence but do not replace
unavailable primary evidence.
