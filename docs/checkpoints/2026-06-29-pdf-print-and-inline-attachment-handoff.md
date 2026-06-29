# PDF Print And Inline Attachment Handoff

Date: 2026-06-29
Workspace: `/home/jwagner/system-scripts/msg-parser`

## Read First

1. `AGENTS.md`
2. `CONTEXT.md`
3. `docs/checkpoints/2026-06-24-thread-context-and-ui-handoff.md`
4. This checkpoint

## Current Authoritative Baseline

After the current validated rebuild of the attorney bundle:

```text
Messages: 7345
Attachments: 695
Timeline rows: 8040
Integrity status: review_warnings
```

This baseline reflects the rebuild done from the corrected MBOX source, not the older smaller-count baseline from the earlier import pass.

## Current Working Tree Slice

This checkpoint covers the pending source changes in:

```text
M build_attorney_bundle.py
M msg-parser.py
```

Generated bundle artifacts were rebuilt for validation only and are still ignored.

## What Changed

### `msg-parser.py`

Upstream email attachment import was tightened so quoted-history inline CID images are not re-imported as live attachments when they are only referenced inside quoted HTML:

- adds conservative HTML quoted-reply trimming helpers
- extracts `cid:` references from full HTML and active-message HTML
- skips repeated inline image parts whose `Content-ID` appears only in quoted history

Treat this file as the import/source-normalization boundary.

### `build_attorney_bundle.py`

The attorney bundle moved further toward self-contained HTML printing for attachments:

- attachment-derived fields now track `rendered_page_paths`, `render_asset_status`, and `render_asset_warning`
- PDF attachments are rasterized into JPEG page images under `attorney_bundle/attachments/<event path>/pages/`
- old exhibit-PDF-centric print dependency was removed from standard print flows
- print output now embeds PDF attachments as:
  - a metadata cover page
  - one printed page per rasterized PDF page
  - a footer line with exhibit ID, PDF page number, and attachment ID
- messages with PDF attachments get `has-pdf-attachment` so the message bubble framing applies to `.message-core` instead of the whole `.message`
- print layout was refined so:
  - message attachment headings/lists live inside `.message-core`
  - rendered attachment pages stay outside `.message-core` for full-width printing
  - identity grid responds to container width instead of forcing overflow
  - PDF-bearing messages can break after `.message-core`
  - inbound/outbound print inset margins are now `20%`

## Validation Status

These commands passed on the current source state:

```bash
.venv/bin/python -m py_compile build_attorney_bundle.py
.venv/bin/python build_attorney_bundle.py --force
python3 - <<'PY' | node --check -
from pathlib import Path
html = Path('attorney_bundle/index.html').read_text(encoding='utf-8')
start = html.index('<script>') + len('<script>')
end = html.index('</script>', start)
print(html[start:end])
PY
```

Rebuild output:

```text
Bundle written to /home/jwagner/system-scripts/msg-parser/attorney_bundle
Messages: 7345
Attachments: 695
Timeline rows: 8040
Integrity status: review_warnings
```

## Remaining Follow-Ups

Most likely next small slices:

1. Browser print smoke on a few PDF-heavy messages to confirm page breaks and footer alignment in real print preview.
2. Decide whether any remaining non-inline-printable attachment types need a more explicit print treatment than metadata-only sheets.
3. Clean up stale repo-local docs that still mention `build_exhibit_pdfs()` or exhibit-packet-first printing as the active path.

## Suggested Next Prompt

```md
Read `AGENTS.md`, `CONTEXT.md`, `docs/checkpoints/2026-06-24-thread-context-and-ui-handoff.md`, and `docs/checkpoints/2026-06-29-pdf-print-and-inline-attachment-handoff.md`, then continue from the current working tree in `/home/jwagner/system-scripts/msg-parser`.

Current state:
- `msg-parser.py` contains the quoted-inline CID attachment dedupe at import time.
- `build_attorney_bundle.py` now uses rasterized PDF page images for self-contained HTML printing instead of relying on external exhibit references in normal print flows.
- Current validated rebuild baseline is:
  - `Messages: 7345`
  - `Attachments: 695`
  - `Timeline rows: 8040`
  - `Integrity status: review_warnings`

Important context:
- Do not edit generated `attorney_bundle/index.html` directly.
- PDF attachment pages now live under `attorney_bundle/attachments/.../pages/`.
- Messages with PDF attachments use `has-pdf-attachment` so `.message-core` keeps the bubble framing while attachment pages can print full-width.

Task:
- inspect the current diffs narrowly
- continue with the next smallest useful print/UI refinement
- preserve the validated counts/status above unless intentionally rerunning the ingest pipeline again

Validation:
- `.venv/bin/python -m py_compile build_attorney_bundle.py`
- `.venv/bin/python build_attorney_bundle.py --force`
- extracted script piped to `node --check`
```
