# AGENTS.md

## Project Scope

- Project root: `/home/jwagner/system-scripts/msg-parser`.
- Purpose: offline attorney review and evidence preparation for SMS/MMS, email, attachments, deterministic exports, exhibit PDFs, and browser-based review UI.
- Primary source files:
  - `build_attorney_bundle.py` builds the offline review bundle and exhibit outputs.
  - `ai_triage.py` builds deterministic AI candidate sets, optional cached AI labels, and AI tag exports.
  - `convert_heic_attachments.py` handles local attachment conversion support.
  - `msg-parser.py` is the original parsing/import script.
  - `docs/Attorney Bundle System Spec.md` is the current product/spec alignment document.
- The tree also contains raw evidence, generated bundles, local databases, caches, virtualenvs, and Node dependencies; do not assume every local file is commit-worthy source.

## Path Mapping

- Treat these as the same physical project root in different tool contexts:
  - WSL path: `/home/jwagner/system-scripts/msg-parser`
  - Windows UNC path: `\\wsl.localhost\Ubuntu\home\jwagner\system-scripts\msg-parser`
- Prefer `/home/jwagner/system-scripts/msg-parser` for shell commands, repo-local edits, and runtime verification inside Codex.
- Do not infer a missing file or wrong workspace from path-format differences alone; normalize to the shared physical location first.

## Data And Privacy Boundaries

- Never commit raw evidence or generated attorney bundle artifacts.
- Treat these paths as private, local, and ignored unless the user explicitly asks for targeted inspection:
  - `source_data/`
  - `communications.sqlite`
  - `extracted_attachments/`
  - `attorney_bundle/`
  - `attorney_bundle/attachments/`
  - `attorney_bundle/exhibits/`
  - `attorney_bundle/ai/cache.sqlite`
- Avoid opening raw MBOX/XML/ZIP/source evidence, extracted attachments, generated PDFs, or copied attachment trees unless a specific failure requires it.
- Keep deterministic SQLite/export data as the source of truth. Do not overwrite source message text, metadata, event IDs, attachment IDs, hashes, or exhibit IDs as part of UI work.
- Do not add GPS/location features.
- Do not start or expand AI work unless explicitly requested. If AI work is requested, keep it additive, cached, evidence-backed, and scoped to deterministic candidate subsets.

## Search And Token Discipline

- Be actively conscious of token usage during exploration, implementation, and reporting.
- Start with the smallest useful scope: usually `rg` anchors in `build_attorney_bundle.py`, then targeted excerpts around the relevant function.
- For bundle UI work, read only the relevant CSS/JS sections inside `render_index()` before editing.
- Do not reread `docs/Attorney Bundle System Spec.md` in full unless a product decision is unclear; prefer the current task plan or targeted section reads.
- Do not inspect large generated artifacts or evidence trees unless validation points to them.
- Treat the first pass as a scout pass: a few targeted searches and excerpts before expanding.
- If two exploration expansions in a row do not improve the hypothesis, stop widening and restate what is known, unknown, and the narrowest next move.
- Keep user-facing updates concise: changed behavior, validation result, and blockers.

## Git And Commit Boundaries

- Commit source, specs, tests, package manifests, and small durable docs.
- Do not commit:
  - `.venv/`
  - `node_modules/`
  - `source_data/`
  - `communications.sqlite`
  - `extracted_attachments/`
  - `attorney_bundle/`
  - `__pycache__/`
  - generated AI caches/exports unless explicitly promoted to source fixtures.
- Check `.gitignore` before staging. If a raw evidence or generated file appears in `git status`, stop and fix ignore rules before committing.
- Preserve unrelated dirty state. Stage only the files relevant to the user's requested slice.

## Editing And Verification

- Keep edits scoped to the requested slice.
- Prefer focused changes inside `build_attorney_bundle.py`; avoid broad refactors unless needed to complete the spec safely.
- Preserve exhibit PDF generation, exhibit manifest structure, cache reuse behavior, and `review_warnings` visibility.
- Keep the generated HTML offline and `file://` friendly. Do not introduce network dependencies for the review UI.
- Use `apply_patch` for manual source edits.
- After UI/build changes, run:

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

- Expected current bundle counts after a normal rebuild:
  - `Messages: 6376`
  - `Attachments: 595`
  - `Timeline rows: 6971`
  - `Integrity status: review_warnings`
- Preserve `review_warnings`; do not hide or downgrade integrity warnings to make output look cleaner.

## Browser And Print Smoke

- Playwright is available through the local Node setup. Verify with:

```bash
node -e "require('playwright'); console.log('playwright ok')"
```

- For UI changes, smoke `attorney_bundle/index.html` via `file://`.
- Minimum browser smoke:
  - load `index.html`
  - verify counts and integrity text
  - switch Messages / Timeline / Attachments
  - search by a known event ID
  - verify Timeline context slices and match highlighting
  - verify row selection updates detail without moving the left pane
  - verify attachment action links
  - verify packet PDF link
  - verify no horizontal overflow at desktop and narrow mobile widths
- For print changes, smoke:
  - Print Current Message
  - Print Results
  - Print Summary
  - Print Filtered Attachments
  - Print Full Packet link
- Do not generate screenshots, traces, videos, reports, or large artifacts by default. Use them only to diagnose a specific visual failure.

## Current UI Spec Direction

- Discovery should stay search-first, with filters hidden behind progressive disclosure.
- Messages View is for fast scanning: compact list, one row per message, no contextual expansion.
- Timeline View is for contextual understanding: global chronological context slices, source-aware rendering, match state, selected state, and bounded expansion.
- Detail pane is for inspection: timestamp, sender/recipients, full body, direct attachments visible; Citation, Evidence Integrity, Metadata, and Thread Context secondary/collapsed.
- Attachments View is a manifest/workbench: type, exhibit ID, source event, date, and links should be easy to scan.
- Print should be court/binder-oriented. Keep messages as printable HTML text for now; use exhibit PDFs/attachment packet for attachment authority.

## AI Triage Notes

- `ai_triage.py` supports `--dry-run`, `--build-candidates`, `--run-ai`, and `--export`.
- The AI cache is keyed by event/content/model/schema inputs and lives under generated bundle AI output.
- Cost and scope estimates should be based on deterministic candidate exports, not the full message corpus.
- AI labels must never replace original source text or metadata.
- Avoid legal conclusions or accusatory language in generated labels.

## Checkpoints And Handoffs

- Use compact checkpoints when a stable milestone lands, a validation result matters, or a future chat would otherwise need to rediscover state.
- Put checkpoints under `docs/checkpoints/` if the user wants durable repo-local history. Keep them ignored unless the user explicitly wants to version them.
- A good handoff should include:
  - current source files touched
  - generated artifact status
  - validation commands and results
  - known counts/integrity status
  - remaining spec slice
  - any failures or tool friction avoided
- Keep handoffs scan-friendly and avoid dumping long logs.

## Tooling Recovery Rules

- Prefer the normal path first: shell commands, `rg`, targeted excerpts, `apply_patch`, then validation.
- If Playwright is unavailable, verify Node dependencies before adding setup or changing code.
- If a validation command fails, fix the narrow failing area before expanding scope.
- If a command produces too much output, rerun with a narrower grep, line range, or purpose-built static check.
- If generated bundle validation fails after UI edits, check the emitted `<script>` with `node --check` before browser debugging.
