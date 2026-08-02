# Collect Raw Sync History Design

The read-only flow is:

```text
inclusive date range
  -> safely enumerate raw workspace history files
  -> parse sync metadata and readable source references
  -> expand one sync into its individual work items
  -> keep records whose created_at date is in range
  -> remove only completely identical rendered records
  -> return a chronological list plus source paths and read issues
```

The query uses each history record's `created_at` value as the sync record
time. A date-only range is inclusive at both ends and compares the calendar
date written in that timestamp; the query does not silently convert it to a
different timezone.

Work items come from the generated current-state and history bullet sections.
When a legacy sync record has no such sections, its bounded summary paragraph
is one work item. Headings, boundary text, exclusions, and policy boilerplate
are not work items.

A duplicate is removed only when every reader-facing record field is the same:
workspace, workstream, sync record time, item text, readable source references,
and raw history path. Repeated wording from another sync remains a separate
record.

Receipt linkage may be reported as mechanical provenance when present. It is
not required to read a safe history file and never establishes that the stored
content is semantically true.

Malformed, unsafe, or unreadable history files are not guessed through. The
result reports their paths and reasons separately while returning any other
safe records. No raw file, external system, cache, or report is written.

The canonical skill is projected once under the selected raw root at
`.agents/skills/collect-raw-sync-history`. Codex-compatible project discovery
uses that location directly. Hermes reads the same raw-owned projection by
registering `<raw-root>/.agents/skills` as an external skill directory in the
default Hermes config and, when it already exists, the named `mnemosyne`
profile. No user-global Codex, Claude, or Hermes copy of this raw-only skill is
created.
