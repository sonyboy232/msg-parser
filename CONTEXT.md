# CONTEXT.md

## Purpose

This repo builds an offline attorney review and evidence-preparation bundle from local SMS/MMS, email, and attachment evidence.

Use this file as the first repo-local map after `AGENTS.md`. It should reduce rediscovery, not replace targeted verification.

## Source Map

- `msg-parser.py`
  - Ingests source SMS Backup & Restore XML plus email MBOX into `communications.sqlite`.
  - Saves extracted attachments under `extracted_attachments/`.
  - Defines message IDs, attachment IDs, normalized sender/recipient/body fields, hashes, and attachment metadata.
  - Treat as the ingestion/source-normalization boundary.

- `convert_heic_attachments.py`
  - Converts local HEIC attachments to JPG sidecars where needed.
  - Preserves/copies useful EXIF timestamp data when available.
  - Treat as local attachment-prep tooling, not review UI logic.

- `build_attorney_bundle.py`
  - Reads `communications.sqlite` and `extracted_attachments/`.
  - Copies attachment trees into generated `attorney_bundle/`.
  - Exports deterministic JSON/CSV data under `attorney_bundle/data/`.
  - Generates exhibit PDFs and `attorney_bundle/exhibits/attachment_packet.pdf`.
  - Generates self-contained `attorney_bundle/index.html` through `render_index()`.
  - Validates counts, timeline sort/source labels, attachment references, exhibit paths, hash/size checks, and no GPS/location columns.
  - Treat as the primary file for UI, print, bundle, and exhibit work.

- `ai_triage.py`
  - Builds deterministic candidate sets from `communications.sqlite`.
  - Optionally runs cached AI triage on candidate rows only.
  - Exports additive AI tag/indicator JSON for `build_attorney_bundle.py` to load.
  - Treat as optional/additive. Do not run or expand AI work unless explicitly requested.

- `docs/Attorney Bundle System Spec.md`
  - Product direction for the offline review UI and print model.
  - Current spec priorities: search-first discovery, contextual Timeline, source-aware rendering, detail inspection, attachment manifest, print-ready evidence output.
  - Read targeted sections only when a product decision is unclear.

- `package.json` / `package-lock.json`
  - Local Node support for Playwright browser smoke tests.
  - No formal `npm test` script is currently defined.

## Generated And Private Paths

Do not commit or broadly inspect these unless a targeted task requires it:

- `source_data/` -> raw SMS/MMS archive and source email MBOX.
- `communications.sqlite` -> local source database.
- `extracted_attachments/` -> extracted evidence attachments.
- `attorney_bundle/` -> generated offline bundle, copied attachments, data exports, exhibit PDFs, and AI cache.
- `.venv/`, `node_modules/`, `__pycache__/` -> local runtime/cache dependencies.

If any of these appear in `git status` as unignored files, stop and fix `.gitignore` before staging.

## Data Flow

```text
source_data/
  -> msg-parser.py
  -> communications.sqlite + extracted_attachments/
  -> convert_heic_attachments.py where needed
  -> build_attorney_bundle.py
  -> attorney_bundle/data/*.json|csv
  -> attorney_bundle/exhibits/*.pdf + attachment_packet.pdf
  -> attorney_bundle/index.html
```

Optional AI flow:

```text
communications.sqlite
  -> ai_triage.py --build-candidates
  -> attorney_bundle/ai/candidate_sets.json
  -> ai_triage.py --run-ai / --export when explicitly requested
  -> attorney_bundle/ai/message_tags.json
  -> build_attorney_bundle.py loads tags additively
```

## Current Bundle Expectations

Normal rebuild should currently report:

```text
Messages: 6376
Attachments: 595
Timeline rows: 6971
Integrity status: review_warnings
```

`review_warnings` are expected from known attachment hash/size mismatches around duplicate saved paths. Preserve and expose those warnings; do not hide them.

## UI And Print Boundaries

For UI/print work, start in `build_attorney_bundle.py`:

- `render_index()` -> generated HTML/CSS/JS review app.
- `build_exports()` -> derived display fields, message attachment state, timeline rows.
- `build_exhibit_pdfs()` -> generated exhibit PDFs and packet.
- `validate()` -> integrity checks and warning details.
- `load_ai_triage()` / `apply_ai_triage()` -> optional AI tag integration.

Current UI direction:

- Messages View: compact scan-first list, one row per message.
- Timeline View: global chronological context slices with match highlighting, source-aware SMS/MMS/email rendering, selected state, and bounded expansion.
- Attachments View: manifest/workbench with type, exhibit ID, source event, date, and links.
- Detail Pane: full inspection with body and direct attachments visible; Citation, Evidence Integrity, Metadata, and Thread Context secondary/collapsed.
- Print: court/binder-oriented HTML print plus exhibit PDFs. Keep source paths out of standard print views; full mode may keep traceability.

## Validation Commands

Run after changing Python, generated UI, print, exhibit, or validation logic:

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

Run before/after browser work:

```bash
node -e "require('playwright'); console.log('playwright ok')"
```

Minimum Playwright smoke for UI changes:

- open `attorney_bundle/index.html` via `file://`
- verify counts and integrity status
- switch Messages / Timeline / Attachments
- search by known event ID
- verify Timeline slices and match state
- verify row selection updates detail without moving left-pane scroll
- verify attachment action links and packet PDF link
- check desktop and narrow mobile widths for horizontal overflow

For print changes, smoke Print Current Message, Print Results, Print Summary, Print Filtered Attachments, and the Full Packet link.

## Common Task Start Points

- UI layout or scanability:
  - `rg -n "render_index|renderList|timelineRanges|renderDetail|attachmentLinks|print" build_attorney_bundle.py`

- Timeline behavior:
  - `render_index()` JS functions around `filteredMessages()`, `timelineRanges()`, `timelineRowHtml()`, `renderTimelineList()`, and `bindListInteractions()`.

- Detail pane:
  - `renderDetail()`, `renderAttachmentDetail()`, `threadContextHtml()`, `conversationAttachmentsHtml()`.

- Attachment manifest:
  - `filteredAttachments()`, `filteredAttachmentEntries()`, `attachmentKind()`, `attachmentLinks()`.

- Print:
  - `printStyles()`, `printAttachmentHtml()`, `printMessageHtml()`, `printTimelineTable()`, `printAttachmentManifestTable()`, `printCurrentResults()`, `printCurrentAttachments()`.

- Exhibit generation:
  - `make_cover_pdf()`, `append_pdf_pages()`, `append_image_page()`, `build_exhibit_pdfs()`.

- Integrity warnings:
  - `validate()`, especially copied attachment hash/size checks and exhibit path checks.

- AI triage:
  - `ai_triage.py --dry-run`, `--build-candidates`, `--run-ai`, `--export`.
  - Keep candidate-based scope; do not send the full corpus to AI.

## Token Discipline For This Repo

- Read `AGENTS.md`, then this file, then targeted code excerpts.
- Do not open raw source data or generated attachments as part of general orientation.
- Prefer `rg` anchors and small line ranges over full-file rereads.
- Do not inspect `attorney_bundle/attachments/`, `attorney_bundle/exhibits/`, or `source_data/` unless a failure points there.
- When creating handoffs, include only changed behavior, validation results, known counts/status, and remaining slice.

## Known Tooling Notes

- Playwright is installed locally through Node dependencies.
- `attorney_bundle/` is generated and ignored; rebuild it rather than editing generated files directly.
- `docs/checkpoints` is ignored by default. Use it for local handoff/checkpoint notes unless the user explicitly wants versioned checkpoints.
- The source spec file was moved under `docs/`; if a prompt references the older root-level spec path, check `docs/Attorney Bundle System Spec.md`.

## Current Implementation Baseline (2026-06-23)

Treat the current `build_attorney_bundle.py` working tree as the active implementation baseline, not the older roadmap.

Implemented and expected in `build_attorney_bundle.py`:

- Print actions are grouped under one `Print` menu.
- Timeline View uses global chronological context slices with match highlighting, selected state, source-aware SMS/MMS/email rendering, and bounded expansion.
- Attachments View is a manifest/workbench with type, exhibit/date/source cues and direct action links.
- Detail pane exposes body and direct attachments, with Citation, Evidence Integrity, Metadata, Thread Context, and Bundle Summary as secondary details.
- Standard print views avoid dumping source/saved paths; full mode preserves traceability.
- Timeline print uses print-safe card sections (`timeline-card`) rather than the older wide table model.
- Summary print uses compact `Date | Sender | Snippet | Exhibit` output with an optional attachment appendix.
- `bundle_manifest.json` is embedded into the generated UI payload as `manifest` for Bundle Summary display.

Validation last performed in this sandbox:

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

Rebuild still reported:

```text
Messages: 6376
Attachments: 595
Timeline rows: 6971
Integrity status: review_warnings
```

Generated marker check confirmed:

- `Bundle Summary`
- filter count/update behavior
- `Attachment Appendix`
- summary print titles
- `timeline-card`

Playwright note: Playwright is installed, but this sandbox currently blocks Chromium launch. The next unrestricted/default chat should rerun the browser smoke from `AGENTS.md`.
