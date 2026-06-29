#!/usr/bin/env python3
"""
Build an offline attorney review bundle from communications.sqlite.

The bundle is intentionally deterministic and local-first:
  - source records are exported to JSON/CSV
  - attachments and the source DB are copied into the bundle
  - index.html embeds the exported records so it can open via file://
  - integrity_report.json records validation warnings instead of hiding them
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


SCRIPT_VERSION = "phase-b-ui-2026-06-22"

MESSAGE_FIELDS = [
    "event_id",
    "source",
    "source_record_id",
    "thread_key",
    "event_dt_utc",
    "direction",
    "sender",
    "recipients_json",
    "subject",
    "body_clean",
    "source_file",
    "content_hash",
]

ATTACHMENT_FIELDS = [
    "attachment_id",
    "event_id",
    "filename",
    "mime_type",
    "exif_dt_raw",
    "exif_dt_utc",
    "saved_path",
    "converted_path",
    "size_bytes",
    "source_file",
    "sha256_hash",
]

TIMELINE_FIELDS = [
    "timeline_dt_utc",
    "source_label",
    "event_id",
    "attachment_id",
    "source",
    "direction",
    "sender",
    "description",
    "metadata_status",
    "source_path",
]

MESSAGE_DERIVED_FIELDS = [
    "body_preview",
    "is_attachment_only",
    "has_exif_attachment",
    "display_sender",
    "display_recipients",
    "display_summary",
    "source_badge",
    "direction_badge",
]

ATTACHMENT_DERIVED_FIELDS = [
    "bundle_saved_path",
    "bundle_converted_path",
    "preferred_view_path",
    "exhibit_id",
    "rendered_page_paths",
    "render_asset_status",
    "render_asset_warning",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build offline attorney review bundle")
    parser.add_argument("--db", default="communications.sqlite", help="SQLite DB path")
    parser.add_argument(
        "--attachments-dir",
        default="extracted_attachments",
        help="Root directory containing extracted attachments",
    )
    parser.add_argument("--output-dir", default="attorney_bundle", help="Bundle output directory")
    parser.add_argument("--force", action="store_true", help="Replace an existing output directory")
    return parser.parse_args()


def row_dicts(conn: sqlite3.Connection, table: str, fields: list[str], order_by: str) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(f"SELECT {', '.join(fields)} FROM {table} ORDER BY {order_by}").fetchall()
    return [{field: normalize_value(row[field]) for field in fields} for row in rows]


def normalize_value(value: Any) -> Any:
    return "" if value is None else value


def decode_recipients(value: str) -> list[str]:
    if not value:
        return []
    try:
        decoded = json.loads(value)
        if isinstance(decoded, list):
            return [str(item) for item in decoded]
    except json.JSONDecodeError:
        pass
    return [value]


def compact_text(value: Any, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def display_person(value: Any, fallback: str = "Unknown") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def badge_value(value: Any, fallback: str = "UNKNOWN") -> str:
    text = str(value or "").strip()
    return text.upper() if text else fallback


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_clean_output(output_dir: Path, force: bool) -> None:
    preserved_exhibits_dir = output_dir.parent / f".{output_dir.name}.exhibits-cache"
    preserved_ai_dir = output_dir.parent / f".{output_dir.name}.ai-cache"
    if preserved_exhibits_dir.exists():
        shutil.rmtree(preserved_exhibits_dir)
    if preserved_ai_dir.exists():
        shutil.rmtree(preserved_ai_dir)
    if output_dir.exists():
        if not force:
            raise SystemExit(f"Output exists: {output_dir}. Re-run with --force to replace it.")
        if (output_dir / "exhibits").exists():
            shutil.move(str(output_dir / "exhibits"), str(preserved_exhibits_dir))
        if (output_dir / "ai").exists():
            shutil.move(str(output_dir / "ai"), str(preserved_ai_dir))
        shutil.rmtree(output_dir)
    (output_dir / "data").mkdir(parents=True)
    (output_dir / "attachments").mkdir(parents=True)
    if preserved_exhibits_dir.exists():
        shutil.move(str(preserved_exhibits_dir), str(output_dir / "exhibits"))
    if preserved_ai_dir.exists():
        shutil.move(str(preserved_ai_dir), str(output_dir / "ai"))


def bundle_attachment_href(path_value: str, prefer_exists: bool = True) -> str:
    if not path_value:
        return ""
    return "attachments/" + Path(path_value).as_posix()


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_ai_triage(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "ai" / "message_tags.json"
    if not path.exists():
        return {"available": False, "tag_options": [], "message_count": 0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"available": False, "tag_options": [], "message_count": 0}

    by_event: dict[str, dict[str, Any]] = {}
    tag_options: set[str] = set()
    for row in data.get("messages", []):
        event_id = str(row.get("event_id") or "")
        if not event_id:
            continue
        tags = [str(tag) for tag in row.get("tags", []) if str(tag or "").strip()]
        results = row.get("results", [])
        if not tags and isinstance(results, list):
            tags = [
                str(result.get("label") or result.get("category") or "")
                for result in results
                if str(result.get("label") or result.get("category") or "").strip()
            ]
        clean_tags = sorted(set(tags))
        if not clean_tags:
            continue
        tag_options.update(clean_tags)
        by_event[event_id] = {"tags": clean_tags, "results": results if isinstance(results, list) else []}

    return {
        "available": bool(by_event),
        "tag_options": sorted(tag_options),
        "message_count": len(by_event),
        "by_event": by_event,
        "source_path": path.as_posix(),
        "metadata": data.get("metadata", {}),
    }


def apply_ai_triage(messages: list[dict[str, Any]], ai_triage: dict[str, Any]) -> None:
    by_event = ai_triage.get("by_event", {})
    if not isinstance(by_event, dict):
        return
    for message in messages:
        row = by_event.get(message["event_id"])
        if not row:
            message["ai_tags"] = []
            message["ai_tag_details"] = []
            continue
        message["ai_tags"] = row.get("tags", [])
        message["ai_tag_details"] = row.get("results", [])


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def timeline_sort_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (row["timeline_dt_utc"] or "", row["event_id"] or "", row["attachment_id"] or "")


def build_exports(
    messages: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for attachment in attachments:
        original_href = bundle_attachment_href(attachment["saved_path"])
        converted_href = bundle_attachment_href(attachment["converted_path"])
        attachment["bundle_saved_path"] = original_href
        attachment["bundle_converted_path"] = converted_href
        attachment["preferred_view_path"] = converted_href or original_href
        attachment_number = str(attachment.get("attachment_id", "")).replace("A-", "", 1)
        attachment["exhibit_id"] = f"EX-{attachment_number}" if attachment_number else ""
        attachment["rendered_page_paths"] = []
        attachment["render_asset_status"] = ""
        attachment["render_asset_warning"] = ""
        by_event[attachment["event_id"]].append(attachment)

    message_exports: list[dict[str, Any]] = []
    for message in messages:
        msg_attachments = by_event.get(message["event_id"], [])
        body = str(message.get("body_clean", "") or "").strip()
        image_attachments = [
            attachment
            for attachment in msg_attachments
            if attachment_kind(attachment) == "image"
            and str(attachment.get("preferred_view_path") or attachment.get("bundle_saved_path") or "").strip()
            and not re.search(
                r"\.heics?$",
                str(
                    attachment.get("preferred_view_path")
                    or attachment.get("bundle_saved_path")
                    or attachment.get("saved_path")
                    or ""
                ).lower(),
            )
        ]
        first_image_attachment = image_attachments[0] if image_attachments else None
        body_preview = compact_text(
            body or (
                f"{len(msg_attachments)} attachment{'s' if len(msg_attachments) != 1 else ''}"
                if msg_attachments
                else "[no message body]"
            ),
            180,
        )
        recipients = decode_recipients(str(message.get("recipients_json", "")))
        display_sender = display_person(message.get("sender"))
        display_recipients = ", ".join(recipients) if recipients else ""
        subject = str(message.get("subject", "") or "").strip()
        summary_source = subject or body or (
            f"{len(msg_attachments)} attachment{'s' if len(msg_attachments) != 1 else ''}"
            if msg_attachments
            else "[no message body]"
        )
        exported = dict(message)
        exported["recipients"] = recipients
        exported["has_attachments"] = bool(msg_attachments)
        exported["attachment_count"] = len(msg_attachments)
        exported["attachments"] = msg_attachments
        exported["ai_tags"] = []
        exported["body_preview"] = body_preview
        exported["is_attachment_only"] = bool(msg_attachments) and len(body) <= 12
        exported["has_exif_attachment"] = any(bool(att.get("exif_dt_utc")) for att in msg_attachments)
        exported["inline_preview_path"] = (
            first_image_attachment.get("preferred_view_path")
            or first_image_attachment.get("bundle_saved_path")
            if first_image_attachment
            else ""
        )
        exported["inline_preview_attachment_id"] = (
            first_image_attachment.get("attachment_id") if first_image_attachment else ""
        )
        exported["additional_inline_image_count"] = max(0, len(image_attachments) - 1)
        exported["display_sender"] = display_sender
        exported["display_recipients"] = display_recipients
        exported["display_summary"] = compact_text(summary_source, 220)
        exported["source_badge"] = badge_value(message.get("source"))
        exported["direction_badge"] = badge_value(message.get("direction"))
        message_exports.append(exported)

    message_by_event = {message["event_id"]: message for message in messages}
    timeline_rows: list[dict[str, Any]] = []

    for message in messages:
        body = str(message.get("body_clean", "") or "").replace("\n", " ").strip()
        description = body[:180] if body else "[no message body]"
        timeline_rows.append(
            {
                "timeline_dt_utc": message["event_dt_utc"],
                "source_label": "message_sent",
                "event_id": message["event_id"],
                "attachment_id": "",
                "source": message["source"],
                "direction": message["direction"],
                "sender": message["sender"],
                "description": description,
                "metadata_status": "message timestamp present",
                "source_path": message["source_file"],
            }
        )

    for attachment in attachments:
        message = message_by_event.get(attachment["event_id"], {})
        exif_dt = attachment.get("exif_dt_utc") or ""
        label = "photo_taken" if exif_dt else "attachment_record"
        timeline_dt = exif_dt or message.get("event_dt_utc", "")
        metadata_status = (
            "EXIF timestamp present"
            if exif_dt
            else "missing EXIF timestamp; using linked message timestamp"
        )
        timeline_rows.append(
            {
                "timeline_dt_utc": timeline_dt,
                "source_label": label,
                "event_id": attachment["event_id"],
                "attachment_id": attachment["attachment_id"],
                "source": message.get("source", ""),
                "direction": message.get("direction", ""),
                "sender": message.get("sender", ""),
                "description": attachment.get("filename") or attachment.get("saved_path") or "[unnamed attachment]",
                "metadata_status": metadata_status,
                "source_path": attachment.get("source_file", ""),
            }
        )

    timeline_rows.sort(key=timeline_sort_key)
    return message_exports, attachments, timeline_rows


def attachment_kind(attachment: dict[str, Any]) -> str:
    mime = str(attachment.get("mime_type") or "").lower()
    name = str(
        attachment.get("filename")
        or attachment.get("saved_path")
        or attachment.get("preferred_view_path")
        or ""
    ).lower()
    if mime.startswith("image/") or re.search(r"\.(jpe?g|png|gif|webp|bmp|tiff?)$", name):
        return "image"
    if mime == "application/pdf" or name.endswith(".pdf"):
        return "pdf"
    if mime.startswith("video/") or re.search(r"\.(mov|mp4|m4v|3gp|avi|wmv)$", name):
        return "video"
    if mime.startswith("audio/") or re.search(r"\.(mp3|m4a|wav|aac|ogg)$", name):
        return "audio"
    if re.search(r"word|excel|powerpoint|officedocument|text/", mime) or re.search(
        r"\.(docx?|xlsx?|pptx?|txt|rtf|csv)$", name
    ):
        return "doc"
    if re.search(r"zip|compressed|tar|gzip", mime) or re.search(r"\.(zip|rar|7z|tar|gz)$", name):
        return "archive"
    return "other"


def bundle_href_to_path(bundle_dir: Path, href: str) -> Path:
    if not href:
        return bundle_dir / "__missing_attachment_path__"
    return bundle_dir / Path(href)


def safe_artifact_name(value: str, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return (text or fallback)[:120]


def court_datetime(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized if "T" in normalized else normalized.replace(" ", "T"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    eastern = parsed.astimezone(ZoneInfo("America/New_York"))
    return eastern.strftime("%m/%d/%Y %I:%M:%S %p %Z").lstrip("0").replace("/0", "/")


def rasterize_pdf_pages(pdf_path: Path, output_dir: Path, stem: str) -> list[Path]:
    ghostscript = shutil.which("gs")
    if not ghostscript:
        raise RuntimeError("Ghostscript (gs) is required to rasterize PDF attachments into printable page images.")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_pattern = output_dir / f"{stem}_%03d.jpg"
    command = [
        ghostscript,
        "-dSAFER",
        "-dBATCH",
        "-dNOPAUSE",
        "-sDEVICE=jpeg",
        "-dJPEGQ=90",
        "-r144",
        f"-sOutputFile={output_pattern}",
        str(pdf_path),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or f"exit status {exc.returncode}"
        raise RuntimeError(f"Ghostscript rasterization failed: {detail}") from exc
    rendered = sorted(output_dir.glob(f"{stem}_*.jpg"))
    if not rendered:
        raise RuntimeError("Ghostscript rasterization finished without producing any JPEG pages.")
    return rendered


def build_attachment_render_assets(
    output_dir: Path,
    attachments: list[dict[str, Any]],
) -> dict[str, Any]:
    exhibits_dir = output_dir / "exhibits"
    if exhibits_dir.exists():
        shutil.rmtree(exhibits_dir)

    warnings: list[dict[str, str]] = []
    pdf_attachment_count = 0
    rendered_pdf_attachment_count = 0
    rendered_pdf_page_count = 0
    inline_printable_attachment_count = 0
    non_inline_printable_attachment_count = 0

    for attachment in sorted(attachments, key=lambda att: (str(att.get("event_id") or ""), str(att.get("attachment_id") or ""))):
        attachment["rendered_page_paths"] = []
        attachment["render_asset_warning"] = ""
        kind = attachment_kind(attachment)
        preferred_href = str(attachment.get("preferred_view_path") or attachment.get("bundle_saved_path") or "")
        preferred_path = bundle_href_to_path(output_dir, preferred_href)

        if kind == "pdf":
            pdf_attachment_count += 1
            source_href = str(attachment.get("bundle_saved_path") or "")
            source_path = bundle_href_to_path(output_dir, source_href)
            if not source_href or not source_path.exists():
                attachment["render_asset_status"] = "metadata_sheet_only"
                attachment["render_asset_warning"] = (
                    "Original PDF file is missing from the bundle, so browser print cannot embed its pages. "
                    "Print this file separately from the original evidence source."
                )
                warnings.append({"attachment_id": str(attachment.get("attachment_id") or ""), "warning": str(attachment["render_asset_warning"])})
                non_inline_printable_attachment_count += 1
                continue
            try:
                saved_parent = Path(str(attachment.get("saved_path") or "")).parent
                rendered_pages_dir = output_dir / "attachments" / saved_parent / "pages"
                rendered_pages_dir.mkdir(parents=True, exist_ok=True)
                page_stem = safe_artifact_name(
                    str(attachment.get("attachment_id") or attachment.get("exhibit_id") or "pdf"),
                    str(attachment.get("exhibit_id") or attachment.get("attachment_id") or "pdf"),
                )
                rendered_pages = rasterize_pdf_pages(source_path, rendered_pages_dir, page_stem)
                attachment["rendered_page_paths"] = [page_path.relative_to(output_dir).as_posix() for page_path in rendered_pages]
                attachment["render_asset_status"] = "pdf_pages_rendered"
                rendered_pdf_attachment_count += 1
                rendered_pdf_page_count += len(rendered_pages)
                inline_printable_attachment_count += 1
            except Exception as exc:
                attachment["render_asset_status"] = "metadata_sheet_only"
                attachment["render_asset_warning"] = (
                    "PDF pages could not be rasterized for browser print. "
                    f"Print this file separately from the original PDF in the bundle. {exc}"
                )
                warnings.append({"attachment_id": str(attachment.get("attachment_id") or ""), "warning": str(attachment["render_asset_warning"])})
                non_inline_printable_attachment_count += 1
            continue

        if kind == "image" and preferred_href and preferred_path.exists() and not preferred_href.lower().endswith((".heic", ".heics")):
            attachment["render_asset_status"] = "image_inline_ready"
            inline_printable_attachment_count += 1
            continue

        attachment["render_asset_status"] = "metadata_sheet_only"
        attachment["render_asset_warning"] = (
            "Browser print cannot embed this attachment type inline. "
            "The original file remains in the offline bundle and may need separate manual printing or review."
        )
        non_inline_printable_attachment_count += 1

    return {
        "pdf_attachment_count": pdf_attachment_count,
        "rendered_pdf_attachment_count": rendered_pdf_attachment_count,
        "rendered_pdf_page_count": rendered_pdf_page_count,
        "inline_printable_attachment_count": inline_printable_attachment_count,
        "non_inline_printable_attachment_count": non_inline_printable_attachment_count,
        "render_asset_warnings": warnings,
        "rendered_pages_location": "attachments/<event_id>/pages/*.jpg",
    }


def validate(
    db_path: Path,
    bundle_dir: Path,
    messages: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
    timeline_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    conn = sqlite3.connect(str(db_path))
    db_message_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    db_attachment_count = conn.execute("SELECT COUNT(*) FROM attachments").fetchone()[0]
    conn.close()

    message_ids = {message["event_id"] for message in messages}
    missing_saved_paths: list[dict[str, str]] = []
    missing_converted_paths: list[dict[str, str]] = []
    missing_rendered_pdf_pages: list[dict[str, str]] = []
    missing_inline_image_paths: list[dict[str, str]] = []
    attachments_missing_render_status: list[dict[str, str]] = []
    attachment_event_mismatches: list[dict[str, str]] = []
    hash_mismatches: list[dict[str, str]] = []
    size_mismatches: list[dict[str, Any]] = []

    for attachment in attachments:
        if attachment["event_id"] not in message_ids:
            attachment_event_mismatches.append(
                {"attachment_id": attachment["attachment_id"], "event_id": attachment["event_id"]}
            )

        saved_path = str(attachment.get("saved_path") or "")
        copied_saved = bundle_dir / "attachments" / saved_path
        if not saved_path or not copied_saved.exists():
            missing_saved_paths.append({"attachment_id": attachment["attachment_id"], "saved_path": saved_path})
        elif attachment.get("sha256_hash"):
            actual_hash = sha256_file(copied_saved)
            if actual_hash != attachment["sha256_hash"]:
                hash_mismatches.append(
                    {
                        "attachment_id": attachment["attachment_id"],
                        "saved_path": saved_path,
                        "expected_sha256": attachment["sha256_hash"],
                        "actual_sha256": actual_hash,
                    }
                )
            actual_size = copied_saved.stat().st_size
            if attachment.get("size_bytes") != "" and int(attachment["size_bytes"]) != actual_size:
                size_mismatches.append(
                    {
                        "attachment_id": attachment["attachment_id"],
                        "saved_path": saved_path,
                        "expected_size_bytes": attachment["size_bytes"],
                        "actual_size_bytes": actual_size,
                    }
                )

        converted_path = str(attachment.get("converted_path") or "")
        if converted_path and not (bundle_dir / "attachments" / converted_path).exists():
            missing_converted_paths.append(
                {"attachment_id": attachment["attachment_id"], "converted_path": converted_path}
            )

        render_status = str(attachment.get("render_asset_status") or "")
        if not render_status:
            attachments_missing_render_status.append(
                {"attachment_id": attachment["attachment_id"], "render_asset_status": render_status}
            )

        kind = attachment_kind(attachment)
        if kind == "pdf" and not attachment.get("rendered_page_paths"):
            missing_rendered_pdf_pages.append(
                {"attachment_id": attachment["attachment_id"], "render_asset_status": render_status}
            )

        preferred_view_path = str(attachment.get("preferred_view_path") or "")
        if (
            kind == "image"
            and preferred_view_path
            and not preferred_view_path.lower().endswith((".heic", ".heics"))
            and not (bundle_dir / preferred_view_path).exists()
        ):
            missing_inline_image_paths.append(
                {"attachment_id": attachment["attachment_id"], "preferred_view_path": preferred_view_path}
            )

    timeline_sorted = timeline_rows == sorted(timeline_rows, key=timeline_sort_key)
    allowed_timeline_labels = {"message_sent", "photo_taken", "attachment_record"}
    unexpected_timeline_labels = sorted(
        {row["source_label"] for row in timeline_rows if row["source_label"] not in allowed_timeline_labels}
    )
    missing_timeline_metadata = [
        {
            "event_id": row["event_id"],
            "attachment_id": row["attachment_id"],
            "source_label": row["source_label"],
        }
        for row in timeline_rows
        if not row["timeline_dt_utc"] or not row["metadata_status"]
    ]

    exported_fields = set(MESSAGE_FIELDS + ATTACHMENT_FIELDS + TIMELINE_FIELDS)
    location_like_fields = sorted(
        field for field in exported_fields if "gps" in field.lower() or "location" in field.lower()
    )

    checks = {
        "message_count_matches": len(messages) == db_message_count,
        "attachment_count_matches": len(attachments) == db_attachment_count,
        "all_saved_paths_exist_in_bundle": not missing_saved_paths,
        "all_converted_paths_exist_in_bundle": not missing_converted_paths,
        "all_pdf_pages_rendered_in_bundle": not missing_rendered_pdf_pages,
        "all_inline_image_paths_exist_in_bundle": not missing_inline_image_paths,
        "all_attachments_have_render_status": not attachments_missing_render_status,
        "all_attachments_map_to_existing_event_id": not attachment_event_mismatches,
        "timeline_rows_sorted": timeline_sorted,
        "timeline_source_labels_valid": not unexpected_timeline_labels,
        "missing_metadata_explicit": not missing_timeline_metadata,
        "no_gps_or_location_columns_exported": not location_like_fields,
        "attachment_hashes_match_copied_files": not hash_mismatches,
        "attachment_sizes_match_copied_files": not size_mismatches,
    }

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_db": str(db_path),
        "bundle_dir": str(bundle_dir),
        "counts": {
            "sqlite_messages": db_message_count,
            "exported_messages": len(messages),
            "sqlite_attachments": db_attachment_count,
            "exported_attachments": len(attachments),
            "timeline_rows": len(timeline_rows),
        },
        "checks": checks,
        "details": {
            "missing_saved_paths": missing_saved_paths,
            "missing_converted_paths": missing_converted_paths,
            "missing_rendered_pdf_pages": missing_rendered_pdf_pages,
            "missing_inline_image_paths": missing_inline_image_paths,
            "attachments_missing_render_status": attachments_missing_render_status,
            "attachment_event_mismatches": attachment_event_mismatches,
            "unexpected_timeline_labels": unexpected_timeline_labels,
            "missing_timeline_metadata": missing_timeline_metadata,
            "location_like_fields": location_like_fields,
            "hash_mismatches": hash_mismatches,
            "size_mismatches": size_mismatches,
        },
        "status": "pass" if all(checks.values()) else "review_warnings",
    }


def build_manifest(
    db_path: Path,
    output_dir: Path,
    messages: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
    timeline_rows: list[dict[str, Any]],
    integrity: dict[str, Any],
    render_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "build_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_db_path": str(db_path),
        "source_db_sha256": sha256_file(db_path),
        "message_count": len(messages),
        "attachment_count": len(attachments),
        "timeline_row_count": len(timeline_rows),
        "generated_bundle_path": str(output_dir),
        "integrity_status": integrity["status"],
        "pdf_attachment_count": render_summary.get("pdf_attachment_count", 0),
        "rendered_pdf_attachment_count": render_summary.get("rendered_pdf_attachment_count", 0),
        "rendered_pdf_page_count": render_summary.get("rendered_pdf_page_count", 0),
        "inline_printable_attachment_count": render_summary.get("inline_printable_attachment_count", 0),
        "non_inline_printable_attachment_count": render_summary.get("non_inline_printable_attachment_count", 0),
        "render_asset_warning_count": len(render_summary.get("render_asset_warnings", [])),
        "rendered_pages_location": render_summary.get("rendered_pages_location", ""),
        "script_name": Path(__file__).name,
        "script_version": SCRIPT_VERSION,
    }


def render_index(
    messages: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
    timeline_rows: list[dict[str, Any]],
    integrity: dict[str, Any],
    render_summary: dict[str, Any],
    ai_triage: dict[str, Any],
    manifest: dict[str, Any],
) -> str:
    payload = json.dumps(
        {
            "messages": messages,
            "attachments": attachments,
            "timeline": timeline_rows,
            "integrity": integrity,
            "renderAssets": render_summary,
            "manifest": manifest,
            "ai": {
                "available": bool(ai_triage.get("available")),
                "tag_options": ai_triage.get("tag_options", []),
                "message_count": ai_triage.get("message_count", 0),
                "metadata": ai_triage.get("metadata", {}),
            },
        },
        ensure_ascii=False,
    ).replace("</", "<\\/")
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Attorney Review Bundle</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f6f1;
      --panel: #ffffff;
      --ink: #1d2528;
      --muted: #667174;
      --line: #d9dfdc;
      --soft-line: #ecefeb;
      --accent: #256268;
      --accent-soft: #e8f1f0;
      --gold: #8a681e;
      --gold-soft: #fbf3d9;
      --warn: #9a4d18;
      --danger-soft: #faebe3;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      height: 100vh;
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
      overflow: hidden;
    }
    header {
      display: grid;
      gap: 12px;
      padding: 16px 20px 14px;
      border-bottom: 1px solid #eef0f2;
      background: #fff;
      box-shadow: 0 4px 14px rgba(24, 35, 39, 0.03);
      z-index: 3;
    }
    h1 { margin: 0; font-size: 24px; line-height: 1.1; letter-spacing: .02em; }
    h2 { margin: 0 0 10px; font-size: 15px; }
    h3 { margin: 14px 0 8px; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0; }
    main {
      display: grid;
      grid-template-columns: minmax(380px, 43%) minmax(460px, 1fr);
      min-height: 0;
      overflow: hidden;
    }
    .header-top, .search-row, .mode-row, .filter-actions, .chips, .meta, .row-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .header-top {
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: start;
      gap: 12px;
    }
    .header-brand {
      grid-column: 2;
      display: grid;
      justify-items: center;
      gap: 4px;
      text-align: center;
    }
    .header-subtitle {
      color: var(--muted);
      font-size: 12px;
      letter-spacing: .1em;
      text-transform: uppercase;
    }
    .header-meta {
      justify-content: center;
      gap: 6px;
      color: #6f7b81;
      font-size: 11px;
      font-weight: 600;
    }
    .header-actions {
      grid-column: 3;
      justify-self: end;
    }
    .mode-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .results-count {
      color: #6f7b81;
      font-size: 12px;
      font-weight: 600;
      white-space: nowrap;
    }
    .search-row {
      margin-top: 10px;
      width: 100%;
      min-width: min(100%, 560px);
      flex-wrap: nowrap;
      justify-content: flex-start;
      align-items: center;
      gap: 10px;
    }
    .search-row input {
      flex: 1 1 auto;
      min-width: 220px;
      max-width: 60vw;
      min-height: 38px;
    }
    .search-actions {
      display: inline-flex;
      justify-content: flex-start;
      align-items: center;
      gap: 8px;
      flex: 0 0 auto;
    }
    .search-actions button {
      width: 110px;
      min-width: 110px;
      min-height: 38px;
      white-space: nowrap;
    }
    #toggleFilters {
      background: var(--accent-soft);
      border-color: #b8cfcb;
      color: var(--accent);
    }
    #clearFilters {
      background: #f4ede2;
      border-color: #d9c5a6;
      color: #7d5521;
    }
    .left, .right { padding: 26px 14px 14px; min-width: 0; overflow: hidden; }
    .left {
      border-right: 1px solid #e1e7e5;
      background: #f7f9fa;
    }
    .right {
      display: flex;
      background: #f8f9fa;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 12px;
      box-shadow: 0 10px 24px rgba(24, 35, 39, 0.06);
    }
    #detailPanel {
      width: 100%;
      min-height: 0;
      overflow: auto;
    }
    .advanced {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
      margin-top: 10px;
    }
    .advanced[hidden] { display: none; }
    label { display: grid; gap: 3px; color: var(--muted); font-size: 12px; }
    input, select, button, textarea {
      width: 100%;
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 5px;
      background: #fff;
      color: var(--ink);
      font: inherit;
      padding: 6px 8px;
    }
    button {
      cursor: pointer;
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
      white-space: nowrap;
    }
    button.secondary {
      background: #fff;
      color: var(--accent);
      border-color: var(--line);
    }
    .button-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: 6px 10px;
      background: #fff;
      color: var(--accent);
      text-decoration: none;
      white-space: nowrap;
    }
    .mode-row { gap: 6px; }
    .mode-label {
      color: #6f7b81;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .03em;
      text-transform: uppercase;
    }
    .mode-row button {
      width: auto;
      min-width: 110px;
      background: #fff;
      color: var(--accent);
      border-color: var(--line);
    }
    .mode-row button[aria-selected="true"] {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }
    .list {
      display: grid;
      align-content: start;
      grid-auto-rows: max-content;
      gap: 7px;
      height: 100%;
      min-height: 0;
      overflow: auto;
      padding-right: 2px;
    }
    .item {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      padding: 9px 10px;
      cursor: pointer;
    }
    .item:hover { border-color: #b9c5c1; }
    .item.active {
      border-color: #17565f;
      background: #f3f9f8;
      box-shadow: inset 0 0 0 2px #17565f, inset 6px 0 0 #17565f;
    }
    .item.match {
      border-color: #d1b15f !important;
      background: #fffdf5 !important;
      box-shadow: inset 3px 0 0 #d1b15f;
    }
    .item.match.active {
      border-color: #17565f;
      background: linear-gradient(0deg, #f3f9f8, #f3f9f8), #fffdf5;
      box-shadow: inset 0 0 0 2px #17565f, inset 6px 0 0 #17565f, inset 0 0 0 4px #f2d985;
    }
    .item-title {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 5px;
    }
    .summary {
      font-size: 12px;
      font-weight: 600;
      color: #6f7b81;
      overflow-wrap: anywhere;
    }
    .timestamp {
      color: #858f94;
      font-size: 11px;
      white-space: nowrap;
    }
    .meta { color: #7e888d; font-size: 11px; }
    .body-preview {
      margin-top: 8px;
      color: #273337;
      font-size: 14px;
      line-height: 1.55;
      overflow-wrap: anywhere;
    }
    .tag-row { margin-top: 8px; }
    .timeline-slice {
      display: grid;
      gap: 18px;
    }
    .slice-separator {
      display: grid;
      grid-template-columns: 1fr;
      align-items: center;
      gap: 6px 10px;
      color: var(--muted);
      font-size: 12px;
      margin: 2px 0;
    }
    .slice-separator-top,
    .slice-separator-bottom {
      justify-self: center;
    }
    .slice-separator-line {
      grid-column: 1 / -1;
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      gap: 10px;
    }
    .slice-separator-line::before,
    .slice-separator-line::after {
      content: "";
      height: 1px;
      background: var(--line);
    }
    .slice-separator-label {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 0;
      text-align: center;
      font-weight: 600;
    }
    .slice-separator button {
      width: auto;
      min-width: 118px;
      min-height: 28px;
      padding: 3px 8px;
      background: #fff;
      color: var(--accent);
      border-color: var(--line);
      font-size: 12px;
    }
    .timeline-row {
      border-radius: 7px;
      cursor: pointer;
      margin-bottom: 6px;
      position: relative;
    }
    .timeline-bubble {
      width: fit-content;
      max-width: 72%;
      padding: 12px 14px 14px 36px;
      border-width: 1px;
      border-radius: 18px;
    }
    .timeline-bubble.direction-outbound {
      justify-self: end;
      margin-left: auto;
      background: #ffffff;
      border-color: #d7dfdc;
      box-shadow: 0 6px 18px rgba(24, 35, 39, 0.04);
    }
    .timeline-bubble.direction-inbound {
      justify-self: start;
      margin-right: auto;
      background: #eef3f8;
      border-color: #d0dbe6;
      box-shadow: 0 6px 18px rgba(52, 77, 102, 0.05);
    }
    .timeline-email {
      width: 100%;
      border-width: 1px;
      border-style: solid;
      border-color: #dcdfe3;
      background: #ffffff;
      box-shadow: 0 8px 22px rgba(24, 35, 39, 0.05);
      display: grid;
      gap: 6px;
      border-radius: 2px;
      padding: 12px 14px 14px 38px;
    }
    .timeline-email.direction-inbound {
      border-color: #dcdfe3;
      background: #eef3f8;
    }
    .timeline-email.direction-outbound {
      border-color: #dcdfe3;
      background: #ffffff;
    }
    .timeline-source-icon {
      position: absolute;
      top: 12px;
      left: 12px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 16px;
      height: 16px;
      color: #b3b8bc;
      font-size: 13px;
      line-height: 1;
      font-weight: 600;
      pointer-events: none;
    }
    .timeline-source-icon.text::before { content: "💬"; }
    .timeline-source-icon.email::before { content: "✉"; }
    .email-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: baseline;
      min-width: 0;
    }
    .email-header {
      display: grid;
      gap: 6px;
      padding-bottom: 10px;
      border-bottom: 1px solid #d7dde3;
      margin-bottom: 2px;
    }
    .email-side {
      display: grid;
      justify-items: end;
      align-items: start;
      gap: 4px;
    }
    .email-sender,
    .email-subject,
    .timeline-email .body-preview {
      display: -webkit-box;
      -webkit-box-orient: vertical;
      overflow: hidden;
      text-overflow: ellipsis;
      word-break: break-word;
    }
    .email-sender {
      -webkit-line-clamp: 1;
      color: #6f7b81;
      font-size: 12px;
      font-weight: 600;
    }
    .email-subject {
      color: #344044;
      font-weight: 650;
      -webkit-line-clamp: 1;
    }
    .email-short-date {
      color: #858f94;
      font-size: 11px;
      white-space: nowrap;
      text-align: right;
    }
    .timeline-email .body-preview {
      color: #2d383d;
      -webkit-line-clamp: 1;
      margin-top: 0;
    }
    .message-ledger {
      width: 100%;
      position: relative;
      padding: 10px 12px 11px 36px;
      display: grid;
      gap: 6px;
      border-width: 1px;
    }
    .message-ledger.direction-inbound {
      background: #eef3f8;
      border-color: #d0dbe6;
    }
    .message-ledger.direction-outbound {
      background: #ffffff;
      border-color: #d7dfdc;
    }
    .message-ledger.medium-email {
      border-radius: 2px;
      border-color: #dcdfe3;
    }
    .message-ledger.medium-text {
      border-radius: 12px;
    }
    .message-ledger .timeline-source-icon {
      top: 9px;
    }
    .message-ledger-meta {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px 12px;
      align-items: start;
      min-width: 0;
    }
    .message-ledger-identity,
    .message-ledger-right {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: baseline;
      min-width: 0;
    }
    .message-ledger-identity {
      color: #6f7b81;
      font-size: 11px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .message-ledger-right {
      justify-content: flex-end;
      color: #858f94;
      font-size: 11px;
      line-height: 1.35;
      white-space: nowrap;
    }
    .message-ledger-id {
      font-weight: 700;
      color: #657279;
      letter-spacing: .01em;
    }
    .message-ledger-email-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: start;
      min-width: 0;
    }
    .message-ledger-subject {
      color: #253136;
      font-size: 15px;
      font-weight: 800;
      line-height: 1.25;
      overflow: hidden;
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 1;
      text-overflow: ellipsis;
      word-break: break-word;
    }
    .message-ledger-snippet {
      color: #273337;
      font-size: 13px;
      line-height: 1.45;
      overflow: hidden;
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 2;
      text-overflow: ellipsis;
      word-break: break-word;
    }
    .message-ledger-tags {
      margin-top: 0;
    }
    .timeline-preview {
      margin-top: 8px;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid rgba(31, 55, 66, .16);
      background: rgba(255,255,255,.72);
    }
    .timeline-preview img {
      display: block;
      width: 100%;
      max-height: 190px;
      object-fit: cover;
      background: #fff;
    }
    .timeline-preview-more {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      padding: 5px 8px;
      background: rgba(22, 53, 64, .06);
      color: #36535a;
      font-size: 12px;
      font-weight: 650;
    }
    .match-label {
      display: inline-flex;
      align-items: center;
      min-height: 20px;
      border-radius: 999px;
      padding: 1px 7px;
      background: var(--gold-soft);
      color: var(--gold);
      border: 1px solid #ead99d;
      font-size: 11px;
      font-weight: 700;
    }
    .badge, .chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      min-height: 22px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 8px;
      background: #fff;
      color: #344044;
      font-size: 12px;
      line-height: 1.2;
    }
    .badge.source { font-weight: 650; }
    .badge.source-sms { background: #e8f4ec; border-color: #bddbc8; color: #27603a; }
    .badge.source-mms { background: #e8f1f8; border-color: #bdd3e6; color: #24577d; }
    .badge.source-email { background: #fff2d8; border-color: #ecd39a; color: #77571a; }
    .badge.direction { font-weight: 650; }
    .badge.direction-inbound { background: #eaf2ff; border-color: #c4d8f4; color: #2e5f95; }
    .badge.direction-outbound { background: #f9eee8; border-color: #e7cdbc; color: #8a4d2b; }
    .badge.attach { background: #eef3fb; border-color: #cad8ec; color: #2f527d; font-weight: 650; }
    .badge.attach-count { background: #eef3fb; border-color: #cad8ec; color: #2f527d; font-weight: 700; min-width: 0; }
    .badge.nearby { background: #f4edfb; border-color: #ddc9ec; color: #68447f; font-weight: 650; }
    .badge.kind-image { background: #eaf7ee; border-color: #bfe0ca; color: #2b6b3d; }
    .badge.kind-pdf { background: #fdeceb; border-color: #efc0bc; color: #943b35; }
    .badge.kind-video { background: #edf0fb; border-color: #cad2ee; color: #46578f; }
    .badge.kind-audio { background: #f3edf9; border-color: #d8c6e9; color: #67458a; }
    .badge.kind-doc { background: #e9f3fb; border-color: #c2d9ec; color: #2c5f83; }
    .badge.kind-archive { background: #f5f0e8; border-color: #dfd1ba; color: #715c3b; }
    .badge.kind-mixed { background: #f4f1ff; border-color: #d5ccf4; color: #5c4a8f; }
    .badge.kind-other { background: #f4f5f3; border-color: #daddd7; color: #687170; }
    .badge.warn { background: var(--gold-soft); border-color: #ead99d; color: var(--gold); }
    .badge.exif { background: #fcebea; border-color: #efc5c0; color: #94433d; font-weight: 650; }
    .badge.ai { background: #f0eef9; border-color: #d7d0ed; color: #5a4a82; }
    .badge.context { background: #f4f5f3; border-color: #daddd7; color: #687170; }
    .tag-icon {
      position: relative;
      display: inline-block;
      width: 14px;
      height: 14px;
      flex: 0 0 14px;
      color: currentColor;
    }
    .icon-source::before {
      content: "";
      position: absolute;
      left: 2px;
      top: 3px;
      width: 10px;
      height: 8px;
      border: 1.5px solid currentColor;
      border-radius: 2px;
    }
    .icon-source::after {
      content: "";
      position: absolute;
      left: 3px;
      top: 5px;
      width: 8px;
      height: 5px;
      border-top: 1.5px solid currentColor;
      transform: skewY(-28deg);
    }
    .icon-inbound::before, .icon-outbound::before {
      content: "";
      position: absolute;
      left: 3px;
      top: 3px;
      width: 7px;
      height: 7px;
      border-left: 2px solid currentColor;
      border-bottom: 2px solid currentColor;
    }
    .icon-inbound::before { transform: rotate(-45deg); }
    .icon-outbound::before { transform: rotate(135deg); }
    .icon-attach::before {
      content: "";
      position: absolute;
      left: 4px;
      top: 1px;
      width: 6px;
      height: 11px;
      border: 1.8px solid currentColor;
      border-radius: 5px;
      transform: rotate(35deg);
    }
    .icon-attach::after {
      content: "";
      position: absolute;
      left: 6px;
      top: 4px;
      width: 3px;
      height: 6px;
      border: 1.3px solid currentColor;
      border-radius: 4px;
      transform: rotate(35deg);
    }
    .icon-nearby::before, .icon-nearby::after {
      content: "";
      position: absolute;
      width: 7px;
      height: 7px;
      border: 1.6px solid currentColor;
      border-radius: 50%;
      top: 3px;
    }
    .icon-nearby::before { left: 1px; }
    .icon-nearby::after { right: 1px; }
    .icon-warn::before {
      content: "";
      position: absolute;
      left: 2px;
      top: 2px;
      width: 10px;
      height: 10px;
      border-left: 2px solid currentColor;
      border-bottom: 2px solid currentColor;
      transform: rotate(45deg);
    }
    .icon-exif::before {
      content: "";
      position: absolute;
      left: 2px;
      top: 2px;
      width: 10px;
      height: 10px;
      border: 1.7px solid currentColor;
      border-radius: 50%;
    }
    .icon-exif::after {
      content: "";
      position: absolute;
      left: 7px;
      top: 4px;
      width: 4px;
      height: 5px;
      border-left: 1.6px solid currentColor;
      border-bottom: 1.6px solid currentColor;
    }
    .icon-ai::before {
      content: "";
      position: absolute;
      left: 4px;
      top: 1px;
      width: 6px;
      height: 12px;
      background: currentColor;
      clip-path: polygon(50% 0, 62% 38%, 100% 50%, 62% 62%, 50% 100%, 38% 62%, 0 50%, 38% 38%);
      opacity: .8;
    }
    .chip button {
      width: auto;
      min-height: 18px;
      border: 0;
      padding: 0 0 0 4px;
      background: transparent;
      color: var(--accent);
    }
    .detail-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }
    .detail-header h2 { margin: 0; }
    .detail-header button {
      width: auto;
      min-width: 130px;
      flex: 0 0 auto;
    }
    .detail-grid { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 6px 10px; }
    .detail-grid.compact { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; }
    .detail-cell {
      border: 1px solid var(--soft-line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #fbfbf8;
      min-width: 0;
    }
    .detail-cell .key {
      display: block;
      margin-bottom: 3px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: .03em;
    }
    .detail-cell .value {
      color: var(--ink);
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .key { color: var(--muted); }
    .value { overflow-wrap: anywhere; }
    .message-body-area {
      max-height: 60vh;
      overflow: auto;
      margin-bottom: 12px;
    }
    .message-heading {
      display: grid;
      gap: 10px;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid #d9dfe3;
    }
    .message-heading-subject {
      color: #253136;
      font-size: 17px;
      font-weight: 800;
      line-height: 1.3;
      overflow-wrap: anywhere;
    }
    .message-heading-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px 12px;
    }
    .message-heading-cell {
      min-width: 0;
    }
    .message-heading-cell .key {
      display: block;
      margin-bottom: 3px;
      color: #7a868c;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    .message-heading-cell .value {
      color: #2a353a;
      font-size: 13px;
      line-height: 1.4;
      overflow-wrap: anywhere;
    }
    .body-box, textarea {
      white-space: pre-wrap;
      background: #fbfbf8;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      max-height: min(62vh, 780px);
      overflow: auto;
    }
    .message-body-area .body-box {
      max-height: none;
      margin: 0;
    }
    .message-gallery {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin: 12px 0 0;
    }
    .message-gallery figure {
      display: grid;
      place-items: center;
      margin: 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: auto;
      background: #fbfbf8;
      padding: 8px;
      align-items: start;
    }
    .message-gallery img {
      display: block;
      width: auto;
      max-width: 100%;
      height: auto;
      max-height: min(52vh, 800px);
      object-fit: contain;
      background: #fff;
    }
    .attachment {
      border-top: 1px solid var(--line);
      padding-top: 10px;
      margin-top: 10px;
    }
    .attachment-meta {
      margin-bottom: 10px;
    }
    .attachment-meta-toggle summary {
      margin-bottom: 8px;
    }
    .attachment-meta-toggle {
      margin-left: 16px;
      padding-left: 12px;
      border-left: 2px solid var(--soft-line);
    }
    .attachment-preview {
      margin: 10px 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfbf8;
      overflow: hidden;
    }
    .attachment-preview img,
    .attachment-preview iframe,
    .attachment-preview video,
    .attachment-preview audio {
      display: block;
      width: 100%;
      max-width: 100%;
      border: 0;
      background: #fff;
    }
    .attachment-preview img {
      max-height: 520px;
      object-fit: contain;
    }
    .attachment-preview iframe {
      height: 520px;
    }
    .attachment-preview video {
      max-height: 520px;
    }
    .attachment-preview audio {
      margin: 10px;
      width: calc(100% - 20px);
    }
    .exhibit-cover {
      border: 2px solid #2b3437;
      border-radius: 6px;
      padding: 14px;
      margin: 10px 0;
      background: #fff;
      text-align: center;
    }
    .exhibit-cover .exhibit-id {
      font-size: 24px;
      font-weight: 750;
      margin-bottom: 8px;
    }
    .exhibit-cover .exhibit-meta {
      display: inline-block;
      max-width: 100%;
      text-align: left;
      color: #344044;
    }
    .preview-note {
      padding: 10px;
      color: var(--muted);
    }
    .inline-message-image {
      margin: 0 0 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      background: #fbfbf8;
    }
    .inline-message-image img {
      display: block;
      width: 100%;
      max-height: 460px;
      object-fit: contain;
      background: #fff;
    }
    details {
      border-top: 1px solid var(--soft-line);
      padding-top: 9px;
      margin-top: 9px;
    }
    summary { cursor: pointer; color: var(--accent); font-weight: 650; }
    .detail-section-empty {
      display: block;
      color: #95a0a5;
      font-size: 12px;
      font-weight: 600;
      padding: 2px 0 8px;
    }
    a { color: var(--accent); overflow-wrap: anywhere; }
    .warning { color: var(--warn); font-weight: 650; }
    .empty { color: var(--muted); padding: 18px 8px; text-align: center; }
    #detailPanel .empty {
      display: grid;
      place-items: center;
      align-content: center;
      gap: 12px;
      min-height: 100%;
      color: #8d989d;
      padding: 28px 18px;
      text-align: center;
    }
    .empty-icon {
      width: 44px;
      height: 44px;
      border: 1px solid #d7dfdc;
      border-radius: 999px;
      background: #f7f9fa;
      position: relative;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.9);
    }
    .empty-icon::before {
      content: "";
      position: absolute;
      width: 14px;
      height: 14px;
      border: 2px solid #8d989d;
      border-radius: 999px;
      top: 10px;
      left: 10px;
    }
    .empty-icon::after {
      content: "";
      position: absolute;
      width: 12px;
      height: 2px;
      background: #8d989d;
      border-radius: 999px;
      transform: rotate(45deg);
      right: 8px;
      bottom: 11px;
    }
    .muted { color: var(--muted); }
    .header-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .header-actions label { display: flex; align-items: center; gap: 6px; }
    .header-actions select { width: auto; min-width: 116px; }
    .header-actions button { width: auto; min-width: 116px; }
    .print-menu {
      position: relative;
      border-top: 0;
      padding-top: 0;
      margin-top: 0;
    }
    .print-menu summary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      border: 1px solid var(--accent);
      border-radius: 5px;
      padding: 6px 12px;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
      font-weight: 650;
      list-style: none;
      white-space: nowrap;
    }
    .print-menu summary::-webkit-details-marker { display: none; }
    .print-menu[open] summary { background: #1e5157; }
    .print-menu-body {
      position: absolute;
      right: 0;
      top: calc(100% + 6px);
      z-index: 5;
      display: grid;
      gap: 6px;
      min-width: 220px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      box-shadow: 0 12px 28px rgba(29, 37, 40, .16);
    }
    .print-menu-body button,
    .print-menu-body a {
      width: 100%;
      justify-content: flex-start;
      text-align: left;
    }
    .thread-context button, .row-actions button { width: auto; min-width: 120px; }
    .thread-context button:disabled {
      opacity: .45;
      cursor: default;
    }
    .thread-context {
      max-height: 60vh;
      overflow: auto;
      padding-right: 4px;
    }
    .thread-context-note {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      margin: 0 0 10px;
      padding: 10px 12px;
      border: 1px solid #ead7d7;
      border-radius: 10px;
      background: #fcf5f5;
      color: #6a5a5a;
      font-size: 12px;
      line-height: 1.45;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.65);
    }
    .thread-context-note-icon {
      flex: 0 0 auto;
      width: 18px;
      height: 18px;
      border-radius: 999px;
      background: #f2dede;
      color: #8a5c5c;
      font-size: 12px;
      font-weight: 700;
      line-height: 18px;
      text-align: center;
    }
    .thread-context-note strong {
      color: #6f4747;
      font-weight: 600;
    }
    .thread-context-nav {
      display: flex;
      justify-content: center;
      margin: 8px 0;
    }
    .thread-context .timeline-slice {
      margin-top: 8px;
    }
    .thread-context .timeline-row {
      cursor: default;
    }
    .thread-context .timeline-row button {
      min-width: 0;
    }
    .row-actions a, .link-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 30px;
      border: 1px solid var(--line);
      border-radius: 5px;
      padding: 4px 8px;
      background: #fff;
      color: var(--accent);
      font-size: 12px;
      text-decoration: none;
      width: auto;
      min-width: 0;
    }
    .compact-actions { margin-top: 8px; }
    .compact-actions a, .compact-actions button { flex: 0 1 auto; }
    .context-tags { justify-content: flex-end; }
    @media (max-width: 980px) {
      body { height: auto; display: block; }
      body { overflow: auto; }
      main { grid-template-columns: 1fr; overflow: visible; }
      .left { border-right: 0; border-bottom: 1px solid var(--line); overflow: visible; }
      .right { max-height: none; overflow: visible; }
      #detailPanel { max-height: 58vh; }
      .list { max-height: 44vh; padding-bottom: 10px; }
      .advanced { grid-template-columns: 1fr; }
      .header-top {
        grid-template-columns: 1fr;
        justify-items: center;
      }
      .header-brand,
      .header-actions {
        grid-column: auto;
      }
      .header-actions { justify-self: center; }
      .search-row { width: 100%; min-width: 0; flex-wrap: wrap; }
      .search-row input { flex: 1 1 100%; max-width: none; }
      .search-actions { width: 100%; justify-content: flex-start; }
      .mode-bar {
        flex-wrap: wrap;
        justify-content: flex-start;
      }
      .results-count {
        width: 100%;
      }
      .mode-bar .header-actions {
        width: 100%;
        justify-self: auto;
      }
      .mode-row button { flex: 1; min-width: 0; }
      .detail-header { align-items: stretch; flex-direction: column; }
      .message-heading-grid { grid-template-columns: 1fr; }
      .detail-grid.compact { grid-template-columns: 1fr; }
      .timeline-bubble { max-width: 100%; }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-top">
      <div class="header-brand">
        <h1>WireTapped</h1>
        <div class="header-subtitle">Communications Intelligence Console</div>
        <div class="meta header-meta">
          <span id="counts"></span>
          <span id="integrityStatus" hidden></span>
        </div>
      </div>
    </div>
    <div class="search-row">
      <input id="search" type="search" placeholder="Search messages, people, filenames, IDs, paths">
      <div class="search-actions">
        <button class="secondary" id="toggleFilters" type="button">Add filter</button>
        <button class="secondary" id="clearFilters" type="button">Clear</button>
      </div>
    </div>
    <div class="chips" id="activeChips"></div>
    <div class="advanced" id="advancedFilters" hidden>
      <label>Source<select id="sourceFilter"></select></label>
      <label>Direction<select id="directionFilter"></select></label>
      <label>Attachment<select id="attachmentFilter">
        <option value="">Any</option>
        <option value="has">Has attachments</option>
        <option value="none">No attachments</option>
        <option value="attachment_only">Attachment only</option>
        <option value="exif">Has EXIF timestamp</option>
      </select></label>
      <label>Start date<input id="startDate" type="date"></label>
      <label>End date<input id="endDate" type="date"></label>
      <label id="aiTagFilterLabel" hidden>AI tag<select id="aiTagFilter"><option value="">Any AI tag</option></select></label>
    </div>
    <div class="mode-bar">
      <div class="mode-row" role="tablist" aria-label="Review mode">
        <span class="mode-label">View:</span>
        <button id="timelineTab" type="button" aria-selected="true">Timeline</button>
        <button id="messagesTab" type="button" aria-selected="false">Messages</button>
      </div>
      <div class="results-count" id="resultsCount"></div>
      <div class="header-actions">
        <details class="print-menu" id="printMenu">
          <summary>Print</summary>
          <div class="print-menu-body">
            <button class="secondary" id="printCurrent" type="button">Print Current Message</button>
            <button class="secondary" id="printResults" type="button">Print Results</button>
            <button class="secondary" id="printSummary" type="button">Print Summary</button>
            <button class="secondary" id="printFullPacket" type="button">Print Full Packet</button>
          </div>
        </details>
      </div>
    </div>
  </header>
  <main>
    <section class="left">
      <div id="resultList" class="list"></div>
    </section>
    <section class="right">
      <div class="panel" id="detailPanel"></div>
    </section>
  </main>
  <script id="bundleData" type="application/json">__BUNDLE_PAYLOAD__</script>
  <script>
    const data = JSON.parse(document.getElementById('bundleData').textContent);
    const messages = data.messages;
    const attachments = data.attachments;
    const timeline = data.timeline;
    const integrity = data.integrity;
    const renderAssets = data.renderAssets || {};
    const manifest = data.manifest || {};
    const ai = data.ai || {};
    const CONVERSATION_ATTACHMENT_WINDOW_HOURS = 24;
    const CONVERSATION_ATTACHMENT_LIMIT = 12;
    const TIMELINE_CONTEXT_SIZE = 3;
    const TIMELINE_EXPAND_SIZE = 5;
    let activeView = 'timeline';
    let activeEventId = '';
    let activeAttachmentId = '';
    const timelineExpansion = new Map();
    const threadContextExpansion = new Map();

    const els = {
      counts: document.getElementById('counts'),
      integrityStatus: document.getElementById('integrityStatus'),
      search: document.getElementById('search'),
      source: document.getElementById('sourceFilter'),
      direction: document.getElementById('directionFilter'),
      attachment: document.getElementById('attachmentFilter'),
      start: document.getElementById('startDate'),
      end: document.getElementById('endDate'),
      aiTag: document.getElementById('aiTagFilter'),
      aiTagLabel: document.getElementById('aiTagFilterLabel'),
      chips: document.getElementById('activeChips'),
      advanced: document.getElementById('advancedFilters'),
      toggleFilters: document.getElementById('toggleFilters'),
      clearFilters: document.getElementById('clearFilters'),
      list: document.getElementById('resultList'),
      detail: document.getElementById('detailPanel'),
      messagesTab: document.getElementById('messagesTab'),
      timelineTab: document.getElementById('timelineTab'),
      resultsCount: document.getElementById('resultsCount'),
      printMenu: document.getElementById('printMenu'),
      printCurrent: document.getElementById('printCurrent'),
      printResults: document.getElementById('printResults'),
      printSummary: document.getElementById('printSummary'),
      printFullPacket: document.getElementById('printFullPacket'),
    };

    function participantKey(value) {
      const text = String(value || '').trim().toLowerCase();
      const digits = text.replace(/\\D/g, '');
      if (digits.length >= 10) return digits.slice(-10);
      return text;
    }
    function normalizeMessageId(value) {
      const text = String(value || '').trim();
      if (!text) return '';
      const match = text.match(/^<(.+)>$/);
      return (match ? match[1] : text).trim().toLowerCase();
    }
    function looksLikeMessageId(value) {
      return Boolean(normalizeMessageId(value)) && /@/.test(String(value || ''));
    }
    function normalizedEmailSubject(value) {
      const text = String(value || '')
        .replace(/^(?:\\s*(?:re|fw|fwd)\\s*:\\s*)+/i, '')
        .replace(/\\s+/g, ' ')
        .trim()
        .toLowerCase();
      return text;
    }
    function conversationKey(message) {
      const people = [message.sender, ...(message.recipients || [])]
        .map(participantKey)
        .filter(Boolean)
        .sort();
      return people.join('|') || message.thread_key || message.event_id;
    }

    const byEvent = new Map(messages.map(message => [message.event_id, message]));
    const byAttachment = new Map(attachments.map(attachment => [attachment.attachment_id, attachment]));
    const chronologicalMessages = messages
      .slice()
      .sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
    const chronologicalIndex = new Map(chronologicalMessages.map((message, index) => [message.event_id, index]));
    const byThread = new Map();
    const byConversation = new Map();
    const emailByMessageId = new Map();
    const emailGraph = new Map();
    const emailFallbackBySubjectConversation = new Map();
    messages.forEach(message => {
      const key = message.thread_key || message.event_id;
      if (!byThread.has(key)) byThread.set(key, []);
      byThread.get(key).push(message);
      const conversation = conversationKey(message);
      if (!byConversation.has(conversation)) byConversation.set(conversation, []);
      byConversation.get(conversation).push(message);
      if (isEmailRecord(message)) {
        const messageId = normalizeMessageId(message.source_record_id);
        if (messageId) emailByMessageId.set(messageId, message);
        emailGraph.set(message.event_id, new Set());
        const normalizedSubject = normalizedEmailSubject(message.subject);
        if (normalizedSubject) {
          const fallbackKey = `${conversation}||${normalizedSubject}`;
          if (!emailFallbackBySubjectConversation.has(fallbackKey)) emailFallbackBySubjectConversation.set(fallbackKey, []);
          emailFallbackBySubjectConversation.get(fallbackKey).push(message);
        }
      }
    });
    messages.forEach(message => {
      if (!isEmailRecord(message)) return;
      const parentMessageId = looksLikeMessageId(message.thread_key) ? normalizeMessageId(message.thread_key) : '';
      if (!parentMessageId) return;
      const parent = emailByMessageId.get(parentMessageId);
      if (!parent || parent.event_id === message.event_id) return;
      emailGraph.get(message.event_id)?.add(parent.event_id);
      emailGraph.get(parent.event_id)?.add(message.event_id);
    });
    els.counts.textContent = `${messages.length} messages | ${attachments.length} attachments | ${timeline.length} timeline rows`;
    els.integrityStatus.textContent = `Integrity: ${integrity.status}`;

    function optionList(values) {
      return '<option value="">Any</option>' + [...new Set(values.filter(Boolean))].sort().map(value => `<option>${escapeHtml(value)}</option>`).join('');
    }
    function isEmailRecord(message) {
      return String(message?.source || '').toLowerCase().includes('email');
    }
    els.source.innerHTML = optionList(messages.map(m => m.source));
    els.direction.innerHTML = optionList(messages.map(m => m.direction));
    const aiTagOptions = ai.available ? (ai.tag_options || []) : [];
    if (aiTagOptions.length) {
      els.aiTag.innerHTML = optionList(aiTagOptions);
      els.aiTagLabel.hidden = false;
    } else {
      els.aiTag.value = '';
      els.aiTagLabel.hidden = true;
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
    }
    function searchText(...values) {
      return values.map(value => String(value || '')).join(' ').toLowerCase();
    }
    function formatBytes(value) {
      const n = Number(value);
      if (!Number.isFinite(n) || n <= 0) return value || '';
      if (n < 1024) return `${n} B`;
      if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
      return `${(n / 1024 / 1024).toFixed(1)} MB`;
    }
    function timezoneCode(value) {
      const text = String(value || '');
      if (text.endsWith('Z') || text.endsWith('+00:00')) return 'UTC';
      const match = text.match(/([+-]\\d{2}:\\d{2})$/);
      return match ? `UTC${match[1]}` : '';
    }
    function formatDateTime(value) {
      const text = String(value || '');
      if (!text) return '';
      const normalized = text.includes('T') ? text : text.replace(' ', 'T');
      const date = new Date(normalized);
      if (Number.isNaN(date.getTime())) return text;
      const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: 'America/New_York',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
        timeZoneName: 'short',
      }).formatToParts(date);
      const byType = Object.fromEntries(parts.map(part => [part.type, part.value]));
      return `${byType.month}/${byType.day}/${byType.year} ${byType.hour}:${byType.minute}:${byType.second} ${byType.dayPeriod} ${byType.timeZoneName}`;
    }
    function formatDateOnly(value) {
      const match = String(value || '').match(/^(\\d{4})-(\\d{2})-(\\d{2})$/);
      return match ? `${match[2]}/${match[3]}/${match[1]}` : String(value || '');
    }
    function formatShortDateTime(value) {
      const text = String(value || '');
      if (!text) return '';
      const normalized = text.includes('T') ? text : text.replace(' ', 'T');
      const date = new Date(normalized);
      if (Number.isNaN(date.getTime())) return text;
      return new Intl.DateTimeFormat('en-US', {
        timeZone: 'America/New_York',
        month: '2-digit',
        day: '2-digit',
        year: '2-digit',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      }).format(date);
    }
    function inDateRange(iso) {
      const day = (iso || '').slice(0, 10);
      if (els.start.value && day < els.start.value) return false;
      if (els.end.value && day > els.end.value) return false;
      return true;
    }
    function messageQueryText(message) {
      return searchText(
        message.event_id, message.source, message.direction, message.sender,
        message.display_recipients, message.subject, message.body_clean,
        message.source_file, message.content_hash, ...(message.ai_tags || []),
        ...(message.ai_tag_details || []).flatMap(result => [
          result.label, result.category, result.confidence, result.supporting_excerpt
        ]),
        ...(message.attachments || []).flatMap(att => [
          att.attachment_id, att.filename, att.mime_type, att.saved_path,
          att.converted_path, att.source_file, att.sha256_hash
        ])
      );
    }
    function messageMatchesControls(message) {
      if (els.source.value && message.source !== els.source.value) return false;
      if (els.direction.value && message.direction !== els.direction.value) return false;
      if (els.attachment.value === 'has' && !message.has_attachments) return false;
      if (els.attachment.value === 'none' && message.has_attachments) return false;
      if (els.attachment.value === 'attachment_only' && !message.is_attachment_only) return false;
      if (els.attachment.value === 'exif' && !message.has_exif_attachment) return false;
      if (els.aiTag.value && !(message.ai_tags || []).includes(els.aiTag.value)) return false;
      return inDateRange(message.event_dt_utc);
    }
    function messageMatches(message, query) {
      if (!messageMatchesControls(message)) return false;
      if (query && !messageQueryText(message).includes(query)) return false;
      return true;
    }
    function activeFilterCount() {
      return [
        els.source.value,
        els.direction.value,
        els.attachment.value,
        els.start.value,
        els.end.value,
        els.aiTag.value,
      ].filter(Boolean).length;
    }
    function updateFilterToggle() {
      const count = activeFilterCount();
      const label = els.advanced.hidden ? 'Add filter' : 'Hide filters';
      els.toggleFilters.textContent = count ? `${label} (${count})` : label;
    }
    function filteredMessages() {
      const query = els.search.value.trim().toLowerCase();
      return messages.filter(message => messageMatches(message, query));
    }
    function filteredAttachments() {
      const query = els.search.value.trim().toLowerCase();
      const matched = filteredMessages();
      const allowed = new Set(matched.map(message => message.event_id));
      return attachments.filter(attachment => {
        const message = byEvent.get(attachment.event_id) || {};
        if (!messageMatchesControls(message)) return false;
        if (!query) return allowed.has(attachment.event_id);
        const directMatch = searchText(
          attachment.attachment_id, attachment.event_id, attachment.filename,
          attachment.mime_type, attachment.saved_path, attachment.converted_path,
          attachment.source_file, attachment.sha256_hash, attachment.exif_dt_utc
        ).includes(query);
        if (directMatch || allowed.has(attachment.event_id)) return true;
        const sourceIndex = chronologicalIndex.get(attachment.event_id);
        if (sourceIndex === undefined) return false;
        const start = Math.max(0, sourceIndex - TIMELINE_CONTEXT_SIZE);
        const end = Math.min(chronologicalMessages.length - 1, sourceIndex + TIMELINE_CONTEXT_SIZE);
        for (let index = start; index <= end; index += 1) {
          if (allowed.has(chronologicalMessages[index].event_id)) return true;
        }
        return false;
      });
    }
    function filteredAttachmentEntries() {
      return filteredAttachments()
        .map(attachment => ({ message: byEvent.get(attachment.event_id) || {}, attachment }))
        .sort((a, b) => String(a.message.event_dt_utc || '').localeCompare(String(b.message.event_dt_utc || '')) || String(a.attachment.attachment_id || '').localeCompare(String(b.attachment.attachment_id || '')));
    }
    function previewableImageAttachments(message) {
      return (message.attachments || []).filter(att => {
        if (attachmentKind(att) !== 'image') return false;
        const href = String(att.preferred_view_path || att.bundle_saved_path || '').toLowerCase();
        return Boolean(href) && !/\\.heics?$/.test(href);
      });
    }
    function messageBodyText(message) {
      return String(message.body_clean || '').trim();
    }
    function displayBodyPreviewText(message) {
      const body = messageBodyText(message);
      if (body) return body;
      const subject = String(message.subject || '').trim();
      if (isEmailMessage(message) && subject) return `[subject only]`;
      return message.body_preview || message.display_summary || '[no message body]';
    }
    function messagePreviewText(message, fallback = '[no message body]') {
      const body = displayBodyPreviewText(message);
      return body || fallback;
    }
    function messageLedgerIdentityText(message) {
      const sender = message.display_sender || message.sender || message.source || 'Message';
      return sender;
    }
    function timelineInlinePreviewHtml(message) {
      const href = message.inline_preview_path;
      if (!href) return '';
      const extra = Number(message.additional_inline_image_count || 0);
      return `
        <div class="timeline-preview">
          <img src="${escapeHtml(href)}" alt="${escapeHtml(message.inline_preview_attachment_id || message.event_id || 'MMS image')}">
          ${extra > 0 ? `<div class="timeline-preview-more">+ ${extra} more</div>` : ''}
        </div>`;
    }
    function nearbyConversationAttachmentEntries(message, includeCurrentMessage) {
      const selectedMs = Date.parse(message.event_dt_utc || '');
      const windowMs = CONVERSATION_ATTACHMENT_WINDOW_HOURS * 60 * 60 * 1000;
      const conversationRows = byConversation.get(conversationKey(message)) || [message];
      return conversationRows
        .flatMap(row => (row.attachments || []).map(att => ({ message: row, attachment: att })))
        .map(row => ({
          ...row,
          deltaMs: Number.isNaN(selectedMs) ? 0 : Math.abs(Date.parse(row.message.event_dt_utc || '') - selectedMs),
        }))
        .filter(row => includeCurrentMessage || row.message.event_id !== message.event_id)
        .filter(row => Number.isNaN(selectedMs) || row.deltaMs <= windowMs)
        .sort((a, b) => a.deltaMs - b.deltaMs || String(a.message.event_dt_utc || '').localeCompare(String(b.message.event_dt_utc || '')));
    }
    function safeClass(value) {
      return String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
    }
    function tagIcon(name) {
      return `<span class="tag-icon icon-${escapeHtml(name)}" aria-hidden="true"></span>`;
    }
    function attachmentKind(att) {
      const mime = String(att.mime_type || '').toLowerCase();
      const name = String(att.filename || att.saved_path || att.preferred_view_path || '').toLowerCase();
      if (mime.startsWith('image/') || /\\.(jpe?g|png|gif|webp|bmp|tiff?)$/.test(name)) return 'image';
      if (mime === 'application/pdf' || name.endsWith('.pdf')) return 'pdf';
      if (mime.startsWith('video/') || /\\.(mov|mp4|m4v|3gp|avi|wmv)$/.test(name)) return 'video';
      if (mime.startsWith('audio/') || /\\.(mp3|m4a|wav|aac|ogg)$/.test(name)) return 'audio';
      if (/word|excel|powerpoint|officedocument|text\\//.test(mime) || /\\.(docx?|xlsx?|pptx?|txt|rtf|csv)$/.test(name)) return 'doc';
      if (/zip|compressed|tar|gzip/.test(mime) || /\\.(zip|rar|7z|tar|gz)$/.test(name)) return 'archive';
      return 'other';
    }
    function attachmentKindSummary(attachments) {
      const kinds = [...new Set((attachments || []).map(attachmentKind).filter(Boolean))];
      if (!kinds.length) return '';
      return kinds.length === 1 ? kinds[0] : 'mixed';
    }
    function kindLabel(kind) {
      const labels = { image: 'IMAGE', pdf: 'PDF', video: 'VIDEO', audio: 'AUDIO', doc: 'DOC', archive: 'ARCHIVE', mixed: 'MIXED', other: 'OTHER' };
      return labels[kind] || String(kind || '').toUpperCase();
    }
    function currentSearchQuery() {
      return els.search.value.trim().toLowerCase();
    }
    function attachmentCountBadge(count) {
      return count ? `<span class="badge attach-count" title="${count} attachment${count === 1 ? '' : 's'}">${tagIcon('attach')}${count}</span>` : '';
    }
    function timelineSourceIconHtml(message) {
      return `<span class="timeline-source-icon ${isEmailMessage(message) ? 'email' : 'text'}" aria-hidden="true"></span>`;
    }
    function messageViewBadges(message) {
      const badges = [];
      if (message.is_attachment_only) badges.push(`<span class="badge warn">${tagIcon('warn')}Attachment only</span>`);
      if (message.has_exif_attachment) badges.push(`<span class="badge exif">${tagIcon('exif')}EXIF time</span>`);
      if (message.ai_tags && message.ai_tags.length) {
        badges.push(...message.ai_tags.map(tag => `<span class="badge ai">${tagIcon('ai')}${escapeHtml(tag)}</span>`));
      }
      return badges.join('');
    }
    function renderBadges(message) {
      const sourceClass = `source-${safeClass(message.source_badge || message.source)}`;
      const directionClass = `direction-${safeClass(message.direction || message.direction_badge)}`;
      const directionIcon = safeClass(message.direction).includes('out') ? 'outbound' : 'inbound';
      const badges = [
        `<span class="badge source ${sourceClass}">${tagIcon('source')}${escapeHtml(message.source_badge || message.source)}</span>`,
        `<span class="badge direction ${directionClass}">${tagIcon(directionIcon)}${escapeHtml(message.direction_badge || message.direction)}</span>`,
      ];
      const directKind = attachmentKindSummary(message.attachments || []);
      if (message.attachment_count) badges.push(`<span class="badge attach kind-${safeClass(directKind)}">${tagIcon('attach')}ATT ${message.attachment_count} ${kindLabel(directKind)}</span>`);
      if (message.is_attachment_only) badges.push(`<span class="badge warn">${tagIcon('warn')}Attachment only</span>`);
      if (message.has_exif_attachment) badges.push(`<span class="badge exif">${tagIcon('exif')}EXIF time</span>`);
      if (message.ai_tags && message.ai_tags.length) {
        badges.push(...message.ai_tags.map(tag => `<span class="badge ai">${tagIcon('ai')}${escapeHtml(tag)}</span>`));
      }
      return badges.join('');
    }
    function renderChips() {
      const chips = [];
      if (els.source.value) chips.push(['source', els.source.value]);
      if (els.direction.value) chips.push(['direction', els.direction.value]);
      if (els.attachment.value) {
        const labels = {
          has: 'Has attachments',
          none: 'No attachments',
          attachment_only: 'Attachment only',
          exif: 'Has EXIF timestamp',
        };
        chips.push(['attachment', labels[els.attachment.value] || els.attachment.value]);
      }
      if (els.start.value || els.end.value) chips.push(['date', `Date: ${els.start.value || 'start'} to ${els.end.value || 'end'}`]);
      if (els.aiTag.value) chips.push(['aiTag', els.aiTag.value]);
      els.chips.innerHTML = chips.map(([key, label]) => `<span class="chip">${escapeHtml(label)} <button type="button" data-chip="${key}" aria-label="Remove ${escapeHtml(label)}">x</button></span>`).join('');
      els.chips.querySelectorAll('[data-chip]').forEach(button => button.addEventListener('click', () => {
        if (button.dataset.chip === 'source') els.source.value = '';
        if (button.dataset.chip === 'direction') els.direction.value = '';
        if (button.dataset.chip === 'attachment') els.attachment.value = '';
        if (button.dataset.chip === 'date') { els.start.value = ''; els.end.value = ''; }
        if (button.dataset.chip === 'aiTag') els.aiTag.value = '';
        render();
      }));
    }
    function isEmailMessage(message) {
      return isEmailRecord(message);
    }
    function directionCss(message) {
      return safeClass(message.direction).includes('out') ? 'direction-outbound' : 'direction-inbound';
    }
    function attachmentIndicatorHtml(message) {
      return '';
    }
    function directMatchIndexes() {
      const query = currentSearchQuery();
      if (!query) return [];
      return messages
        .filter(message => messageMatches(message, query))
        .map(message => chronologicalIndex.get(message.event_id))
        .filter(index => index !== undefined)
        .sort((a, b) => a - b);
    }
    function timelineRanges() {
      const filtered = filteredMessages()
        .map(message => chronologicalIndex.get(message.event_id))
        .filter(index => index !== undefined)
        .sort((a, b) => a - b);
      if (!filtered.length) return { ranges: [], matchIndexes: new Set() };
      const matches = directMatchIndexes();
      const matchIndexes = new Set(matches);
      const sourceIndexes = matches.length ? matches : filtered;
      const ranges = [];
      sourceIndexes.forEach(index => {
        const range = {
          start: Math.max(0, index - TIMELINE_CONTEXT_SIZE),
          end: Math.min(chronologicalMessages.length - 1, index + TIMELINE_CONTEXT_SIZE),
        };
        const previous = ranges[ranges.length - 1];
        if (previous && range.start <= previous.end + 1) {
          previous.end = Math.max(previous.end, range.end);
        } else {
          ranges.push(range);
        }
      });
      return { ranges, matchIndexes };
    }
    function timelineRowHtml(message, isMatch, matchLabel = 'MATCH') {
      const activeClass = message.event_id === activeEventId ? 'active' : '';
      const matchClass = isMatch ? 'match' : '';
      const commonAttrs = `data-event="${escapeHtml(message.event_id)}" data-select-event="${escapeHtml(message.event_id)}"`;
      const bodyPreview = messagePreviewText(message, '[no preview]');
      if (isEmailMessage(message)) {
        return `
          <article class="item timeline-row timeline-email ${directionCss(message)} ${activeClass} ${matchClass}" ${commonAttrs}>
            ${timelineSourceIconHtml(message)}
            <div class="email-header">
              <div class="email-row">
                <span class="email-sender">${escapeHtml(message.display_sender || message.sender || 'Email')}</span>
                <div class="email-side">
                  <span class="email-short-date">${escapeHtml(formatShortDateTime(message.event_dt_utc))}</span>
                </div>
              </div>
              <div class="email-row">
                <div class="email-subject">${escapeHtml(message.subject || '[no subject]')}</div>
                <div class="email-side">${attachmentCountBadge(message.attachment_count || 0)}</div>
              </div>
            </div>
            <div class="body-preview">${escapeHtml(bodyPreview)}</div>
            ${isMatch ? `<div class="meta tag-row"><span class="match-label">${escapeHtml(matchLabel)}</span></div>` : ''}
          </article>`;
      }
      return `
        <article class="item timeline-row timeline-bubble ${directionCss(message)} ${activeClass} ${matchClass}" ${commonAttrs}>
          ${timelineSourceIconHtml(message)}
          <div class="item-title">
            <span class="summary">${escapeHtml(message.display_sender || message.sender || message.source || 'Message')}</span>
            <span class="timestamp">${escapeHtml(formatShortDateTime(message.event_dt_utc))}</span>
          </div>
          ${timelineInlinePreviewHtml(message)}
          ${bodyPreview && !message.is_attachment_only ? `<div class="body-preview">${escapeHtml(bodyPreview)}</div>` : ''}
          ${isMatch ? `<div class="meta tag-row"><span class="match-label">${escapeHtml(matchLabel)}</span></div>` : ''}
        </article>`;
    }
    function renderTimelineList() {
      const { ranges, matchIndexes } = timelineRanges();
      if (!ranges.length) {
        els.list.innerHTML = '<div class="empty">No timeline rows match the current filters.</div>';
        return;
      }
      const parts = [];
      ranges.forEach((range, rangeIndex) => {
        const previousRange = ranges[rangeIndex - 1];
        const next = ranges[rangeIndex + 1];
        const previousGapKey = previousRange ? `gap-${previousRange.end}-${range.start}` : '';
        const gapKey = `gap-${range.end}-${next ? next.start : 'end'}`;
        const prevExpansion = previousGapKey ? (timelineExpansion.get(`${previousGapKey}:backward`) || 0) : 0;
        const nextExpansion = timelineExpansion.get(`${gapKey}:next`) || 0;
        const visibleStart = previousRange
          ? Math.max(previousRange.end + 1, range.start - prevExpansion)
          : range.start;
        const visibleEnd = next ? Math.min(next.start - 1, range.end + nextExpansion) : range.end;
        parts.push('<section class="timeline-slice">');
        for (let index = visibleStart; index <= visibleEnd; index += 1) {
          parts.push(timelineRowHtml(chronologicalMessages[index], matchIndexes.has(index)));
        }
        parts.push('</section>');
        if (next) {
          const nextVisibleStart = Math.max(
            range.end + 1,
            next.start - (timelineExpansion.get(`${gapKey}:backward`) || 0),
          );
          const hiddenBetween = Math.max(0, nextVisibleStart - visibleEnd - 1);
          if (hiddenBetween > 0) {
            parts.push(`
              <div class="slice-separator">
                <div class="slice-separator-top"><button type="button" data-expand-gap-next="${escapeHtml(gapKey)}">Next ${TIMELINE_EXPAND_SIZE}</button></div>
                <div class="slice-separator-line"><span class="slice-separator-label">Skipped ${hiddenBetween} message${hiddenBetween === 1 ? '' : 's'}</span></div>
                <div class="slice-separator-bottom"><button type="button" data-expand-gap-prev="${escapeHtml(gapKey)}">Previous ${TIMELINE_EXPAND_SIZE}</button></div>
              </div>`);
          }
        }
      });
      els.list.innerHTML = parts.join('');
    }
    function visibleTimelineMessages() {
      const { ranges } = timelineRanges();
      const rows = [];
      ranges.forEach((range, rangeIndex) => {
        const previousRange = ranges[rangeIndex - 1];
        const next = ranges[rangeIndex + 1];
        const previousGapKey = previousRange ? `gap-${previousRange.end}-${range.start}` : '';
        const gapKey = `gap-${range.end}-${next ? next.start : 'end'}`;
        const prevExpansion = previousGapKey ? (timelineExpansion.get(`${previousGapKey}:backward`) || 0) : 0;
        const nextExpansion = timelineExpansion.get(`${gapKey}:next`) || 0;
        const visibleStart = previousRange
          ? Math.max(previousRange.end + 1, range.start - prevExpansion)
          : range.start;
        const visibleEnd = next ? Math.min(next.start - 1, range.end + nextExpansion) : range.end;
        for (let index = visibleStart; index <= visibleEnd; index += 1) {
          rows.push(chronologicalMessages[index]);
        }
      });
      return rows;
    }
    function updateActiveItems() {
      els.list.querySelectorAll('.item.active').forEach(item => item.classList.remove('active'));
      if (!activeEventId) return;
      els.list.querySelectorAll(`[data-event="${CSS.escape(activeEventId)}"]`).forEach(item => item.classList.add('active'));
      if (activeAttachmentId) {
        els.list.querySelectorAll(`[data-attachment="${CSS.escape(activeAttachmentId)}"]`).forEach(item => item.classList.add('active'));
      }
    }
    function clearSelection() {
      activeEventId = '';
      activeAttachmentId = '';
    }
    function selectEvent(eventId, attachmentId = '') {
      activeEventId = eventId;
      activeAttachmentId = attachmentId || '';
      renderDetail();
      updateActiveItems();
    }
    function separatorAnchorFromButton(button, direction) {
      const separator = button.closest('.slice-separator');
      if (!separator) return firstVisibleListAnchor();
      const targetSection = direction === 'prev'
        ? separator.nextElementSibling
        : separator.previousElementSibling;
      if (!targetSection) return firstVisibleListAnchor();
      const item = direction === 'prev'
        ? targetSection.querySelector('.item[data-select-event]')
        : [...targetSection.querySelectorAll('.item[data-select-event]')].pop();
      if (!item) return firstVisibleListAnchor();
      const listRect = els.list.getBoundingClientRect();
      return {
        eventId: item.dataset.selectEvent,
        offset: item.getBoundingClientRect().top - listRect.top,
      };
    }
    function bindListInteractions() {
      els.list.querySelectorAll('[data-select-event]').forEach(item => item.addEventListener('click', event => {
        if (event.target.closest('a, button')) return;
        selectEvent(item.dataset.selectEvent, item.dataset.attachment || '');
      }));
      els.list.querySelectorAll('[data-attachment]').forEach(item => item.addEventListener('click', () => {
        activeAttachmentId = item.dataset.attachment;
        selectEvent(item.dataset.event, item.dataset.attachment);
      }));
      els.list.querySelectorAll('[data-expand-gap-prev]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const anchor = separatorAnchorFromButton(button, 'prev');
        const key = `${button.dataset.expandGapPrev}:backward`;
        timelineExpansion.set(key, (timelineExpansion.get(key) || 0) + TIMELINE_EXPAND_SIZE);
        renderList();
        restoreListAnchor(anchor);
      }));
      els.list.querySelectorAll('[data-expand-gap-next]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const anchor = firstVisibleListAnchor();
        const key = `${button.dataset.expandGapNext}:next`;
        timelineExpansion.set(key, (timelineExpansion.get(key) || 0) + TIMELINE_EXPAND_SIZE);
        renderList();
        restoreListAnchor(anchor);
      }));
      els.list.querySelectorAll('a, button').forEach(control => control.addEventListener('click', event => event.stopPropagation()));
    }
    function firstVisibleListAnchor() {
      const listRect = els.list.getBoundingClientRect();
      const item = [...els.list.querySelectorAll('.item[data-select-event]')].find(candidate => {
        const rect = candidate.getBoundingClientRect();
        return rect.bottom > listRect.top + 4;
      });
      return item ? {
        eventId: item.dataset.selectEvent,
        offset: item.getBoundingClientRect().top - listRect.top,
      } : null;
    }
    function restoreListAnchor(anchor) {
      if (!anchor) return;
      const item = els.list.querySelector(`[data-select-event="${CSS.escape(anchor.eventId)}"]`);
      if (!item) return;
      const listRect = els.list.getBoundingClientRect();
      const rect = item.getBoundingClientRect();
      els.list.scrollTop += (rect.top - listRect.top) - anchor.offset;
    }
    function firstVisibleThreadAnchor() {
      const container = els.detail.querySelector('.thread-context');
      if (!container) return null;
      const containerRect = container.getBoundingClientRect();
      const item = [...container.querySelectorAll('.item[data-thread-event]')].find(candidate => {
        const rect = candidate.getBoundingClientRect();
        return rect.bottom > containerRect.top + 4;
      });
      return item ? {
        eventId: item.dataset.threadEvent,
        offset: item.getBoundingClientRect().top - containerRect.top,
      } : null;
    }
    function restoreThreadAnchor(anchor) {
      if (!anchor) return;
      const container = els.detail.querySelector('.thread-context');
      if (!container) return;
      const item = container.querySelector(`[data-thread-event="${CSS.escape(anchor.eventId)}"]`);
      if (!item) return;
      const containerRect = container.getBoundingClientRect();
      const rect = item.getBoundingClientRect();
      container.scrollTop += (rect.top - containerRect.top) - anchor.offset;
    }
    function threadSeparatorAnchorFromButton(button, direction) {
      const container = els.detail.querySelector('.thread-context');
      if (!container) return null;
      const separator = button.closest('.slice-separator');
      if (!separator) return firstVisibleThreadAnchor();
      const targetSection = direction === 'prev'
        ? separator.nextElementSibling
        : separator.previousElementSibling;
      if (!targetSection) return firstVisibleThreadAnchor();
      const item = direction === 'prev'
        ? targetSection.querySelector('.item[data-thread-event]')
        : [...targetSection.querySelectorAll('.item[data-thread-event]')].pop();
      if (!item) return firstVisibleThreadAnchor();
      const containerRect = container.getBoundingClientRect();
      return {
        eventId: item.dataset.threadEvent,
        offset: item.getBoundingClientRect().top - containerRect.top,
      };
    }
    function renderList() {
      renderChips();
      if (activeView === 'messages') {
        const rows = filteredMessages().slice(0, 300);
        els.list.innerHTML = rows.map(message => `
          <article class="item message-ledger medium-${isEmailMessage(message) ? 'email' : 'text'} ${directionCss(message)} ${message.event_id === activeEventId ? 'active' : ''}" data-event="${escapeHtml(message.event_id)}" data-select-event="${escapeHtml(message.event_id)}">
            ${timelineSourceIconHtml(message)}
            <div class="message-ledger-meta">
              <div class="message-ledger-identity">${escapeHtml(messageLedgerIdentityText(message))}</div>
              <div class="message-ledger-right">${!isEmailMessage(message) ? attachmentCountBadge(message.attachment_count || 0) : ''}<span>${escapeHtml(formatShortDateTime(message.event_dt_utc))}</span><span class="message-ledger-id">${escapeHtml(message.event_id)}</span></div>
            </div>
            ${isEmailMessage(message) ? `<div class="message-ledger-email-head"><div class="message-ledger-subject">${escapeHtml(message.subject || '[no subject]')}</div><div>${attachmentCountBadge(message.attachment_count || 0)}</div></div>` : ''}
            <div class="message-ledger-snippet">${escapeHtml(messagePreviewText(message))}</div>
            ${messageViewBadges(message) ? `<div class="meta tag-row message-ledger-tags">${messageViewBadges(message)}</div>` : ''}
          </article>`).join('');
        if (!rows.length) els.list.innerHTML = '<div class="empty">No messages match the current filters.</div>';
      } else {
        renderTimelineList();
      }
      bindListInteractions();
    }
    function detailRow(label, value) {
      return `<div class="key">${escapeHtml(label)}</div><div class="value">${escapeHtml(value || '')}</div>`;
    }
    function aiEvidenceHtml(message) {
      const results = message.ai_tag_details || [];
      if (!results.length) return '';
      return `
        <details>
          <summary>AI Triage Evidence (${results.length})</summary>
          ${results.map(result => `
            <div class="attachment">
              <div class="detail-grid">
                ${detailRow('event_id', result.event_id || message.event_id)}
                ${detailRow('tag', result.label || result.category)}
                ${detailRow('confidence', result.confidence)}
                ${detailRow('supporting excerpt', result.supporting_excerpt)}
                ${detailRow('amount', result.amount)}
                ${detailRow('deadline', result.deadline)}
                ${detailRow('requested action', result.requested_action)}
                ${detailRow('promised action', result.promised_action)}
                ${detailRow('prompt version', result.prompt_version)}
                ${detailRow('model', result.model)}
                ${detailRow('schema', result.category_schema_version)}
              </div>
            </div>`).join('')}
        </details>`;
    }
    function linkRow(label, href, text) {
      if (!href) return detailRow(label, '');
      return `<div class="key">${escapeHtml(label)}</div><div class="value"><a href="${escapeHtml(href)}" target="_blank" rel="noopener">${escapeHtml(text || href)}</a></div>`;
    }
    function detailCard(label, value) {
      return `<div class="detail-cell"><span class="key">${escapeHtml(label)}</span><div class="value">${escapeHtml(value || '')}</div></div>`;
    }
    function bundleSummaryFields() {
      const warningCount = Number(manifest.render_asset_warning_count || 0);
      const sourceDbName = String(manifest.source_db_path || '').split('/').pop();
      return [
        detailCard('bundle built', formatDateTime(manifest.build_timestamp_utc)),
        detailCard('integrity status', manifest.integrity_status || integrity.status),
        detailCard('messages', manifest.message_count || messages.length),
        detailCard('attachments', manifest.attachment_count || attachments.length),
        detailCard('timeline rows', manifest.timeline_row_count || timeline.length),
        detailCard('source database', sourceDbName),
        detailCard('source db SHA-256', manifest.source_db_sha256),
        detailCard('PDF attachments', manifest.pdf_attachment_count),
        detailCard('PDFs rasterized', manifest.rendered_pdf_attachment_count),
        detailCard('rendered PDF pages', manifest.rendered_pdf_page_count),
        detailCard('inline-printable attachments', manifest.inline_printable_attachment_count),
        detailCard('metadata-sheet attachments', manifest.non_inline_printable_attachment_count),
        detailCard('render warnings', warningCount),
        detailCard('rendered pages location', manifest.rendered_pages_location),
      ].join('');
    }
    function recordMetadataHtml(message) {
      return `
        <details>
          <summary>Record Metadata</summary>
          <div class="detail-grid compact">
            ${detailCard('event_id', message.event_id)}
            ${detailCard('timestamp', formatDateTime(message.event_dt_utc))}
            ${detailCard('source', message.source)}
            ${detailCard('direction', message.direction)}
            ${detailCard('sender', message.sender)}
            ${detailCard('recipients', (message.recipients || []).join(', '))}
            ${detailCard('subject', message.subject)}
            ${detailCard('source_record_id', message.source_record_id)}
            ${detailCard('thread_key', message.thread_key)}
            ${detailCard('recipients_json', message.recipients_json)}
            ${detailCard('content_hash', message.content_hash)}
            ${detailCard('source file', message.source_file)}
            ${bundleSummaryFields()}
          </div>
          ${aiEvidenceHtml(message)}
        </details>`;
    }
    function attachmentLinks(att) {
      return `
        <div class="row-actions">
          ${att.preferred_view_path ? `<a href="${escapeHtml(att.preferred_view_path)}" target="_blank" rel="noopener">Open preferred view</a>` : ''}
          ${att.bundle_saved_path ? `<a href="${escapeHtml(att.bundle_saved_path)}" target="_blank" rel="noopener">Open original</a>` : ''}
          ${att.bundle_converted_path ? `<a href="${escapeHtml(att.bundle_converted_path)}" target="_blank" rel="noopener">Open converted JPG</a>` : ''}
          ${(att.rendered_page_paths || []).length ? `<a href="${escapeHtml(att.rendered_page_paths[0])}" target="_blank" rel="noopener">Open first rendered page</a>` : ''}
        </div>`;
    }
    function exhibitCoverHtml(att, sourceMessage) {
      if (attachmentKind(att) !== 'pdf') return '';
      return `
        <div class="exhibit-cover">
          <div class="exhibit-id">${escapeHtml(att.exhibit_id || att.attachment_id || 'PDF Exhibit')}</div>
          <div class="exhibit-meta">
            <div><strong>Attachment ID:</strong> ${escapeHtml(att.attachment_id)}</div>
            <div><strong>Source event_id:</strong> ${escapeHtml(att.event_id)}</div>
            <div><strong>Timestamp:</strong> ${escapeHtml(formatDateTime(sourceMessage?.event_dt_utc || ''))}</div>
            <div><strong>Filename:</strong> ${escapeHtml(att.filename || att.saved_path || '')}</div>
            <div><strong>MIME type:</strong> ${escapeHtml(att.mime_type || '')}</div>
            <div><strong>SHA-256:</strong> ${escapeHtml(att.sha256_hash || '')}</div>
          </div>
        </div>`;
    }
    function attachmentPreviewHtml(att) {
      const kind = attachmentKind(att);
      const href = att.preferred_view_path || att.bundle_saved_path || '';
      if (!href) return '<div class="attachment-preview"><div class="preview-note">No preview path available.</div></div>';
      if (kind === 'pdf') {
        const pages = (att.rendered_page_paths || []).filter(Boolean);
        if (pages.length) {
          return `<div class="attachment-preview"><div class="attachment-media-grid">${pages.map((pageHref, index) => `
            <div>
              <div class="attachment-media-header">${escapeHtml(att.exhibit_id || att.attachment_id || 'Attachment')} | ${escapeHtml(att.filename || att.saved_path || '')} | page ${index + 1}</div>
              <img src="${escapeHtml(pageHref)}" alt="${escapeHtml(att.filename || att.attachment_id || 'PDF page')}">
            </div>`).join('')}</div></div>`;
        }
        return `<div class="attachment-preview"><div class="preview-note">${escapeHtml(att.render_asset_warning || 'PDF pages were not rasterized for inline preview. Print or review the original file separately from the bundle.')}</div></div>`;
      }
      if (kind === 'image' && !String(href).toLowerCase().match(/\\.heics?$/)) {
        return `<div class="attachment-preview"><img src="${escapeHtml(href)}" alt="${escapeHtml(att.filename || att.attachment_id || 'Attachment image')}"></div>`;
      }
      if (kind === 'video') {
        return `<div class="attachment-preview"><video src="${escapeHtml(href)}" controls></video></div>`;
      }
      if (kind === 'audio') {
        return `<div class="attachment-preview"><audio src="${escapeHtml(href)}" controls></audio></div>`;
      }
      return `<div class="attachment-preview"><div class="preview-note">${escapeHtml(att.render_asset_warning || `Inline preview is not available for ${kindLabel(kind)}. Use the attachment links above.`)}</div></div>`;
    }
    function messageBodyHtml(message) {
      const recipients = (message.recipients || []).join(', ');
      const headingHtml = `
        <div class="message-heading">
          ${isEmailMessage(message) && message.subject ? `<div class="message-heading-subject">${escapeHtml(message.subject)}</div>` : ''}
          <div class="message-heading-grid">
            <div class="message-heading-cell">
              <span class="key">From</span>
              <div class="value">${escapeHtml(message.display_sender || message.sender || 'Unknown')}</div>
            </div>
            <div class="message-heading-cell">
              <span class="key">To</span>
              <div class="value">${escapeHtml(recipients || 'Unknown')}</div>
            </div>
            <div class="message-heading-cell">
              <span class="key">Date / Time</span>
              <div class="value">${escapeHtml(formatDateTime(message.event_dt_utc) || 'Unknown')}</div>
            </div>
          </div>
        </div>`;
      const body = messageBodyText(message);
      const galleryHtml = messageBodyGalleryHtml(message);
      if (body && galleryHtml) return `${headingHtml}<div class="body-box">${escapeHtml(body)}</div>${galleryHtml}`;
      if (body) return `${headingHtml}<div class="body-box">${escapeHtml(body)}</div>`;
      if (galleryHtml) return `${headingHtml}${galleryHtml}`;
      if (isEmailMessage(message) && message.subject) {
        return `${headingHtml}<div class="body-box">[subject only]</div>`;
      }
      return `${headingHtml}<div class="body-box">[no body]</div>`;
    }
    function attachmentMetadataHtml(att, message) {
      return `
        <details class="attachment-meta-toggle">
          <summary>Attachment Metadata</summary>
          <div class="detail-grid compact attachment-meta">
            ${detailCard('attachment_id', att.attachment_id)}
            ${detailCard('exhibit_id', att.exhibit_id)}
            ${detailCard('linked event_id', att.event_id)}
            ${detailCard('filename', att.filename || att.saved_path)}
            ${detailCard('MIME type', att.mime_type)}
            ${detailCard('size', formatBytes(att.size_bytes))}
            ${detailCard('EXIF UTC', formatDateTime(att.exif_dt_utc))}
            ${detailCard('render status', att.render_asset_status)}
            ${detailCard('render warning', att.render_asset_warning)}
            ${detailCard('rendered pages', String((att.rendered_page_paths || []).length || 0))}
            ${detailCard('source file path', att.source_file)}
            ${detailCard('saved path', att.saved_path)}
            ${detailCard('converted path', att.converted_path)}
            ${detailCard('preferred view', att.preferred_view_path)}
            ${detailCard('sha256_hash', att.sha256_hash)}
            ${detailCard('EXIF raw', att.exif_dt_raw)}
            ${detailCard('linked message timestamp', formatDateTime(message.event_dt_utc))}
          </div>
        </details>`;
    }
    function messageBodyGalleryHtml(message) {
      const images = previewableImageAttachments(message);
      if (!images.length) return '';
      return `
        <div class="message-gallery">
          ${images.map(att => `
            <figure>
              <img src="${escapeHtml(att.preferred_view_path || att.bundle_saved_path || '')}" alt="${escapeHtml(att.filename || att.attachment_id || 'Message image')}">
            </figure>`).join('')}
        </div>`;
    }
    function activeFilterSummary() {
      const rows = [];
      if (els.search.value.trim()) rows.push(`Search: ${els.search.value.trim()}`);
      if (els.source.value) rows.push(`Source: ${els.source.value}`);
      if (els.direction.value) rows.push(`Direction: ${els.direction.value}`);
      if (els.attachment.value) rows.push(`Attachment filter: ${els.attachment.options[els.attachment.selectedIndex].text}`);
      if (els.start.value || els.end.value) rows.push(`Date: ${els.start.value ? formatDateOnly(els.start.value) : 'start'} to ${els.end.value ? formatDateOnly(els.end.value) : 'end'}`);
      if (els.aiTag.value) rows.push(`AI tag: ${els.aiTag.value}`);
      return rows.length ? rows.join(' | ') : 'No active filters';
    }
    function printStyles() {
      return `
        @page { margin: 0.75in; }
        html, body { max-width: 100%; overflow-x: hidden; }
        body { color: #111; font: 12px/1.42 Georgia, "Times New Roman", serif; max-width: 8.75in; margin: 0 auto; }
        h1 { font: 700 20px/1.2 Arial, sans-serif; margin: 0 0 8px; }
        h2 { font: 700 15px/1.25 Arial, sans-serif; margin: 18px 0 8px; border-bottom: 1px solid #999; padding-bottom: 3px; }
        h3 { font: 700 13px/1.25 Arial, sans-serif; margin: 12px 0 6px; }
        .meta { color: #444; font: 11px/1.35 Arial, sans-serif; margin-bottom: 10px; }
        .message { break-inside: avoid; margin-top: 12px; }

        .message:not(.has-pdf-attachment) { border: 1px solid #bbb; padding: 10px; }
        .message:not(.has-pdf-attachment).direction-outbound { margin-left: 20%; }
        .message:not(.has-pdf-attachment).direction-inbound { margin-right: 20%; }
        .message.has-pdf-attachment { break-inside: auto; page-break-inside: auto; border: 0; padding: 0; }
        .message.has-pdf-attachment .message-core { border: 1px solid #bbb; padding: 10px; }
        .message.has-pdf-attachment.direction-outbound .message-core { margin-left: 20%; }
        .message.has-pdf-attachment.direction-inbound .message-core { margin-right: 20%; }

        .message.direction-inbound .body { background: #ffffff; }
        .grid { display: grid; grid-template-columns: 120px 1fr; gap: 3px 10px; }
        .message-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 6px; }
        .message-head .message-label { font: 700 12px/1.25 Arial, sans-serif; text-transform: uppercase; color: #333; }
        .message-head .message-date { font: 11px/1.25 Arial, sans-serif; color: #444; text-align: right; }
        .message-core { margin-bottom: 0; }
        .message.has-pdf-attachment .message-core { break-inside: avoid; page-break-inside: avoid; }
        .message-identity { display: grid; grid-template-columns: minmax(0, 1.8fr) minmax(0, 1fr); gap: 2px 18px; margin: 10px 0 0; padding: 0; width: 100%; max-width: 100%; font: 11px/1.35 Arial, sans-serif; align-items: start; }
        .message-identity-item { min-width: 0; display: grid; grid-template-columns: 74px minmax(0, 1fr); gap: 8px; align-items: baseline; }
        .message-identity-label { display: block; color: #666; font: 700 10px/1.2 Arial, sans-serif; text-transform: uppercase; letter-spacing: .03em; text-align: left; }
        .message-identity-value { overflow-wrap: anywhere; }
        .message-subject { font: 700 13px/1.3 Arial, sans-serif; margin: 0 0 8px; color: #222; }
        .message-body-meta { margin-top: 8px; font: 11px/1.35 Arial, sans-serif; color: #444; }
        .key { color: #555; font-family: Arial, sans-serif; }
        .body { white-space: pre-wrap; border: 1px solid #ccc; padding: 12px 14px 12px 18px; margin-top: 8px; }
        .citation { font-family: Arial, sans-serif; border-left: 3px solid #555; padding-left: 8px; margin: 8px 0; }
        .attachment { break-inside: avoid-page; page-break-inside: avoid; border: 1px solid #bbb; padding: 8px; margin: 8px 0; overflow: hidden; }
        .message.has-pdf-attachment .attachment-group { break-inside: avoid; page-break-inside: avoid; }

        .exhibit-cover { break-inside: avoid; border: 2px solid #222; padding: 14px; margin: 10px 0; text-align: center; }
        .exhibit-cover .exhibit-id { font: 700 28px/1.2 Arial, sans-serif; margin-bottom: 8px; }
        .exhibit-cover .exhibit-meta { font: 12px/1.35 Arial, sans-serif; text-align: left; display: inline-block; max-width: 100%; }
        .exhibit-image { display: block; width: auto; max-width: 100%; height: auto; max-height: 6.5in; margin: 8px auto; border: 1px solid #999; object-fit: contain; }
        .attachment-list { margin: 6px 0 0 18px; padding: 0; }
        .summary-table { width: 100%; max-width: 100%; border-collapse: collapse; margin-top: 12px; table-layout: fixed; }
        .summary-table th, .summary-table td { border: 1px solid #999; padding: 5px 6px; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }
        .summary-table th { font: 700 11px/1.25 Arial, sans-serif; background: #eee; text-align: left; }
        .summary-table td { font-size: 11px; }
        .summary-body { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
        .exhibit-reference { border-left: 3px solid #777; padding-left: 8px; margin: 10px 0; font: 11px/1.4 Arial, sans-serif; color: #333; }
        .attachment-page { break-before: page; page-break-before: always; break-after: page; page-break-after: always; page-break-inside: avoid; }
        .attachment-page:first-of-type { break-before: auto; page-break-before: auto; }
        .attachment-page:last-of-type { break-after: auto; page-break-after: auto; }
        .attachment-media-header { font: 700 11px/1.35 Arial, sans-serif; margin: 0 0 8px; color: #222; }
        .attachment-media-grid { display: grid; gap: 10px; break-inside: avoid-page; page-break-inside: avoid; }
        .attachment-media-grid img { display: block; width: auto; max-width: 100%; height: auto; max-height: 6.5in; object-fit: contain; border: 1px solid #999; background: #fff; margin-inline: auto; }
        .pdf-cover-page { display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 9in; }
        .pdf-cover-title { font: 700 18px/1.25 Arial, sans-serif; margin: 0 0 16px; text-align: center; }
        .pdf-cover-grid { display: grid; grid-template-columns: max-content max-content; gap: 6px 20px; width: fit-content; max-width: 100%; margin: 0 auto; }
        .pdf-cover-grid .key { text-align: left; font-weight: 700; }
        .pdf-cover-grid div:nth-child(2n) { text-align: left; overflow-wrap: anywhere; }
        .pdf-page-sheet { display: flex; flex-direction: column; min-height: 9in; padding:0; border:none; }
        .pdf-page-media { flex: 1 1 auto; display: flex; align-items: center; justify-content: center; padding-bottom: 8px; }
        .pdf-page-media img { display: block; width: auto; max-width: 100%; height: auto; max-height: calc(10.5in - 100px); object-fit: contain; border: 1px solid #999; background: #fff; margin: 0 auto; }
        .pdf-page-footer { flex: 0 0 auto; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; align-items: center; padding-top: 6px; border-top: 1px solid #777; font: 10px/1.2 Arial, sans-serif; color: #222; }
        .pdf-page-footer div:nth-child(2) { text-align: center; }
        .pdf-page-footer div:nth-child(3) { text-align: right; }
        body.timeline-print { font-size: 10.5px; }
        body.timeline-print h1 { font-size: 18px; }
        body.timeline-print .meta { font-size: 10px; }
        .timeline-card { break-inside: avoid; border: 1px solid #999; padding: 7px 8px; margin: 7px 0; }
        .timeline-card-head { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 6px; font: 700 11px/1.25 Arial, sans-serif; text-transform: uppercase; }
        .timeline-card-id { display: grid; grid-template-columns: 1.2fr .8fr 1fr; gap: 8px; margin-bottom: 6px; font: 11px/1.35 Arial, sans-serif; }
        .timeline-card-id div { border: 1px solid #ccc; padding: 5px 6px; }
        .timeline-card .details { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
        .timeline-card .body-meta { margin-top: 8px; font: 11px/1.35 Arial, sans-serif; color: #444; }
        a { color: #111; text-decoration: underline; overflow-wrap: anywhere; }
        .path { overflow-wrap: anywhere; font-family: Arial, sans-serif; font-size: 11px; }
      `;
    }
    function printDetailRow(label, value) {
      return `<div class="key">${escapeHtml(label)}</div><div>${escapeHtml(value || '')}</div>`;
    }
    function printAiEvidenceHtml(message) {
      const results = message.ai_tag_details || [];
      if (!results.length) return '';
      return `
        <h3>AI Triage Evidence</h3>
        ${results.map(result => `
          <div class="citation">
            ${escapeHtml(result.event_id || message.event_id)} | ${escapeHtml(result.label || result.category || '')} | confidence ${escapeHtml(result.confidence || '')}<br>
            ${escapeHtml(result.supporting_excerpt || '')}
          </div>`).join('')}`;
    }
    function isPrintableImage(att) {
      const mime = String(att.mime_type || '').toLowerCase();
      const path = String(att.preferred_view_path || att.bundle_saved_path || '').toLowerCase();
      return mime.startsWith('image/') && !path.endsWith('.heic') && !path.endsWith('.heics');
    }
    function printableAttachmentMediaHtml(att) {
      const pdfPages = (att.rendered_page_paths || []).filter(Boolean);
      if (pdfPages.length) {
        return `
          <div class="attachment-media-grid">
            ${pdfPages.map((href, index) => `
              <div>
                <div class="attachment-media-header">${escapeHtml(att.exhibit_id || att.attachment_id || 'Attachment')} | ${escapeHtml(att.filename || att.saved_path || '')} | page ${index + 1}</div>
                <img class="exhibit-image" src="${escapeHtml(href)}" alt="${escapeHtml(att.filename || att.attachment_id || 'PDF page')}">
              </div>`).join('')}
          </div>`;
      }
      if (isPrintableImage(att) && att.preferred_view_path) {
        return `
          <div class="attachment-media-grid">
            <div>
              <div class="attachment-media-header">${escapeHtml(att.exhibit_id || att.attachment_id || 'Attachment')} | ${escapeHtml(att.filename || att.saved_path || '')}</div>
              <img class="exhibit-image" src="${escapeHtml(att.preferred_view_path)}" alt="${escapeHtml(att.filename || att.attachment_id || 'Attachment image')}">
            </div>
          </div>`;
      }
      return '';
    }
    function printAttachmentFallbackHtml(att) {
      const note = att.render_asset_warning || 'Browser print cannot embed this attachment inline. Review or print the original bundle file separately.';
      return `
        <div class="exhibit-reference">
          <strong>Attachment requires separate handling.</strong><br>
          ${escapeHtml(note)}
        </div>`;
    }
    function printAttachmentReference(att, sourceMessage) {
      return `<li>${escapeHtml(att.exhibit_id || '')} | ${escapeHtml(att.attachment_id)} | ${escapeHtml(att.filename || att.saved_path || '[unnamed attachment]')} | source event ${escapeHtml(att.event_id)} | ${escapeHtml(formatDateTime(sourceMessage?.event_dt_utc || ''))}</li>`;
    }
    function printAttachmentReferenceList(rows) {
      if (!rows.length) return '';
      return `<ul class="attachment-list">${rows.map(({ message, attachment }) => printAttachmentReference(attachment, message)).join('')}</ul>`;
    }
    function printPdfCoverPageHtml(att, sourceMessage, label, level = 'standard') {
      const fullRows = level === 'full' ? `
            ${printDetailRow('saved path', att.saved_path)}
            ${printDetailRow('converted path', att.converted_path)}
            ${printDetailRow('preferred view', att.preferred_view_path)}
            ${printDetailRow('EXIF raw', att.exif_dt_raw)}
            ${printDetailRow('render status', att.render_asset_status)}
            ${printDetailRow('render warning', att.render_asset_warning)}
      ` : '';
      return `
        <div class="attachment attachment-page pdf-cover-page">
          <div class="pdf-cover-title">${escapeHtml(label || 'Attachment')} ${escapeHtml(att.exhibit_id || att.attachment_id || '')}</div>
          <div class="pdf-cover-grid">
            ${printDetailRow('exhibit_id', att.exhibit_id)}
            ${printDetailRow('attachment_id', att.attachment_id)}
            ${printDetailRow('source event_id', att.event_id)}
            ${printDetailRow('timestamp', formatDateTime(sourceMessage?.event_dt_utc || ''))}
            ${printDetailRow('filename', att.filename || att.saved_path)}
            ${printDetailRow('MIME type', att.mime_type)}
            ${printDetailRow('page count', String((att.rendered_page_paths || []).length || 0))}
            ${level === 'full' ? printDetailRow('size', formatBytes(att.size_bytes)) : ''}
            ${level === 'full' ? printDetailRow('EXIF UTC', formatDateTime(att.exif_dt_utc)) : ''}
            ${level === 'full' ? printDetailRow('sha256_hash', att.sha256_hash) : ''}
            ${fullRows}
          </div>
        </div>`;
    }
    function printAttachmentHtml(att, sourceMessage, label, level = 'standard') {
      if (level === 'summary') {
        return `<ul class="attachment-list">${printAttachmentReference(att, sourceMessage)}</ul>`;
      }
      const pdfPages = (att.rendered_page_paths || []).filter(Boolean);
      if (pdfPages.length) {
        const totalPages = pdfPages.length;
        return `${printPdfCoverPageHtml(att, sourceMessage, label, level)}${pdfPages.map((href, index) => `
          <div class="attachment attachment-page pdf-page-sheet">
            <div class="pdf-page-media">
              <img src="${escapeHtml(href)}" alt="${escapeHtml(att.filename || att.attachment_id || 'PDF page')}">
            </div>
            <div class="pdf-page-footer">
              <div>${escapeHtml(att.exhibit_id || '')}</div>
              <div>${escapeHtml(`Page ${index + 1} of ${totalPages}`)}</div>
              <div>${escapeHtml(att.attachment_id || '')}</div>
            </div>
          </div>`).join('')}`;
      }
      const mediaHtml = printableAttachmentMediaHtml(att);
      const bodyContent = mediaHtml || printAttachmentFallbackHtml(att);
      const fullRows = level === 'full' ? `
            ${printDetailRow('saved path', att.saved_path)}
            ${printDetailRow('converted path', att.converted_path)}
            ${printDetailRow('preferred view', att.preferred_view_path)}
            ${printDetailRow('EXIF raw', att.exif_dt_raw)}
            ${printDetailRow('render status', att.render_asset_status)}
            ${printDetailRow('render warning', att.render_asset_warning)}
      ` : '';
      return `
        <div class="attachment attachment-page">
          <h3>${escapeHtml(label || 'Attachment')} ${escapeHtml(att.exhibit_id || att.attachment_id || '')}</h3>
          ${bodyContent}
          <div class="grid">
            ${printDetailRow('exhibit_id', att.exhibit_id)}
            ${printDetailRow('attachment_id', att.attachment_id)}
            ${printDetailRow('source event_id', att.event_id)}
            ${printDetailRow('timestamp', formatDateTime(sourceMessage?.event_dt_utc || ''))}
            ${printDetailRow('filename', att.filename || att.saved_path)}
            ${printDetailRow('MIME type', att.mime_type)}
            ${level === 'full' ? printDetailRow('size', formatBytes(att.size_bytes)) : ''}
            ${level === 'full' ? printDetailRow('EXIF UTC', formatDateTime(att.exif_dt_utc)) : ''}
            ${level === 'full' ? printDetailRow('sha256_hash', att.sha256_hash) : ''}
            ${fullRows}
          </div>
          ${level === 'full' ? `
            <p class="path">Saved path: ${escapeHtml(att.saved_path || '')}</p>
            ${att.converted_path ? `<p class="path">Converted path: ${escapeHtml(att.converted_path)}</p>` : ''}
            ${att.preferred_view_path ? `<p class="path">Preferred file: <a href="${escapeHtml(att.preferred_view_path)}">${escapeHtml(att.preferred_view_path)}</a></p>` : ''}
            ${att.bundle_saved_path ? `<p class="path">Original file: <a href="${escapeHtml(att.bundle_saved_path)}">${escapeHtml(att.bundle_saved_path)}</a></p>` : ''}
            ${att.bundle_converted_path ? `<p class="path">Converted JPG: <a href="${escapeHtml(att.bundle_converted_path)}">${escapeHtml(att.bundle_converted_path)}</a></p>` : ''}
          ` : ''}
        </div>`;
    }
    function printMessageHtml(message, options = {}) {
      const level = options.level || 'standard';
      const directAttachments = message.attachments || [];
      const directAttachmentRows = directAttachments.map(attachment => ({ message, attachment }));
      const nearbySource = options.includeNearby ? nearbyConversationAttachmentEntries(message, true) : [];
      const nearbyAttachments = level === 'full' ? nearbySource : nearbySource.slice(0, CONVERSATION_ATTACHMENT_LIMIT);
      const subjectLine = isEmailMessage(message) && message.subject
        ? `<div class="message-subject">${escapeHtml(message.subject)}</div>`
        : '';
      const bodyHtml = level === 'summary'
        ? ''
        : `<div class="body">${escapeHtml(message.body_clean || (isEmailMessage(message) && message.subject ? '[subject only]' : '[no body]'))}</div>`;
      const fullRows = level === 'full' ? `
            ${printDetailRow('source_record_id', message.source_record_id)}
            ${printDetailRow('thread_key', message.thread_key)}
            ${printDetailRow('recipients_json', message.recipients_json)}
      ` : '';
      const printDirectionClass = safeClass(message.direction).includes('out') ? 'direction-outbound' : 'direction-inbound';
      const hasPdfAttachmentClass = (
        directAttachments.some(att => attachmentKind(att) === 'pdf')
        || nearbyAttachments.some(row => attachmentKind(row.attachment) === 'pdf')
      ) ? 'has-pdf-attachment' : '';
      const directAttachmentIntro = directAttachments.length
        ? `<div class="attachment-group"><h3>Message Attachments (${directAttachments.length})</h3>${printAttachmentReferenceList(directAttachmentRows)}</div>`
        : '';
      const directAttachmentPages = directAttachments.length
        ? `<div class="attachment-group">${directAttachments.map(att => printAttachmentHtml(att, message, 'Message Attachment', level)).join('')}</div>`
        : '';
      const nearbyAttachmentHeading = `Nearby Conversation Attachments (${nearbyAttachments.length}${nearbySource.length > nearbyAttachments.length ? ` of ${nearbySource.length}` : ''}, +/- ${CONVERSATION_ATTACHMENT_WINDOW_HOURS}h)`;
      const nearbyAttachmentIntro = options.includeNearby && nearbyAttachments.length
        ? `<div class="attachment-group"><h3>${nearbyAttachmentHeading}</h3>${printAttachmentReferenceList(nearbyAttachments)}</div>`
        : '';
      const nearbyAttachmentPages = options.includeNearby && nearbyAttachments.length
        ? `<div class="attachment-group">${nearbyAttachments.map(({ message: sourceMessage, attachment: att }) => printAttachmentHtml(att, sourceMessage, sourceMessage.event_id === message.event_id ? 'Current Message Attachment' : 'Nearby Attachment', level)).join('')}</div>`
        : '';
      return `
        <section class="message ${printDirectionClass} ${hasPdfAttachmentClass}">
          <div class="message-core">
            <div class="message-head">
              <div class="message-label">${escapeHtml(message.direction || 'message')}</div>
              <div class="message-date">${escapeHtml(formatDateTime(message.event_dt_utc))}</div>
            </div>
            ${subjectLine}
            ${bodyHtml}
            <div class="message-identity">
              <div class="message-identity-item"><span class="message-identity-label">Sender</span><div class="message-identity-value">${escapeHtml(message.sender)}</div></div>
              <div class="message-identity-item"><span class="message-identity-label">Source</span><div class="message-identity-value">${escapeHtml(message.source)}</div></div>
              <div class="message-identity-item"><span class="message-identity-label">Recipient</span><div class="message-identity-value">${escapeHtml((message.recipients || []).join(', ') || 'Unknown')}</div></div>
              <div class="message-identity-item"><span class="message-identity-label">ID</span><div class="message-identity-value">${escapeHtml(message.event_id)}</div></div>
            </div>
            ${printAiEvidenceHtml(message)}
            ${directAttachmentIntro}
            ${nearbyAttachmentIntro}
          </div>
          ${directAttachmentPages}
          ${nearbyAttachmentPages}
          ${level === 'full' ? `<div class="grid">${fullRows}</div>` : ''}
        </section>`;
    }
    function printSummaryAttachmentText(message) {
      const direct = (message.attachments || []).map(att => `${att.exhibit_id || ''} ${att.attachment_id} ${kindLabel(attachmentKind(att))} ${att.filename || att.saved_path || ''}`.trim());
      return direct.length ? direct.join('\\n') : '';
    }
    function printSummarySnippet(message) {
      const subject = String(message.subject || '').trim();
      const body = String(message.body_clean || '').replace(/\\s+/g, ' ').trim();
      const base = body || subject || '[no body]';
      return base.length > 220 ? `${base.slice(0, 217)}...` : base;
    }
    function printSummaryExhibitText(message) {
      const exhibitIds = [...new Set((message.attachments || []).map(att => att.exhibit_id || att.attachment_id).filter(Boolean))];
      return exhibitIds.length ? exhibitIds.join('\\n') : 'None';
    }
    function printSummaryTable(messagesForPrint) {
      return `
        <table class="summary-table">
          <thead>
            <tr>
              <th style="width:10%;">Date</th>
              <th style="width:25%;">Sender</th>
              <th>Snippet</th>
              <th style="width:10%;">Exhibit</th>
            </tr>
          </thead>
          <tbody>
            ${messagesForPrint.map(message => `
              <tr>
                <td>${escapeHtml(formatDateOnly(String(message.event_dt_utc || '').slice(0, 10)))}<br>${escapeHtml(formatShortDateTime(message.event_dt_utc).split(', ').slice(1).join(', '))}<br>${escapeHtml(message.event_id)}</td>
                <td class="summary-body">${escapeHtml(message.display_sender || message.sender || '')}</td>
                <td class="summary-body">${escapeHtml(printSummarySnippet(message))}</td>
                <td class="summary-body">${escapeHtml(printSummaryExhibitText(message))}</td>
              </tr>`).join('')}
          </tbody>
        </table>`;
    }
    function printSummaryAppendix(messagesForPrint) {
      const rows = messagesForPrint
        .flatMap(message => (message.attachments || []).map(attachment => ({ message, attachment })));
      if (!rows.length) return '';
      return `<h2>Attachment Appendix</h2>${rows.map(({ message, attachment }) => printAttachmentHtml(attachment, message, 'Attachment Exhibit', 'standard')).join('')}`;
    }
    function printAttachmentSummaryTable(rows) {
      return `
        <table class="summary-table">
          <thead>
            <tr>
              <th style="width:18%;">Date</th>
              <th style="width:18%;">Sender</th>
              <th>Attachment</th>
              <th style="width:20%;">Exhibit</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(({ message, attachment }) => `
              <tr>
                <td>${escapeHtml(formatDateTime(message.event_dt_utc))}<br>${escapeHtml(attachment.event_id || '')}</td>
                <td class="summary-body">${escapeHtml(message.display_sender || message.sender || '')}</td>
                <td class="summary-body">${escapeHtml([
                  attachment.filename || attachment.saved_path || '[unnamed attachment]',
                  attachment.attachment_id,
                  kindLabel(attachmentKind(attachment)),
                ].filter(Boolean).join('\\n'))}</td>
                <td class="summary-body">${escapeHtml(attachment.exhibit_id || attachment.attachment_id || '')}</td>
              </tr>`).join('')}
          </tbody>
        </table>`;
    }
    function timelineResultRows() {
      const allowedEvents = new Set(filteredMessages().map(message => message.event_id));
      const emailEvents = new Set(messages.filter(message => isEmailMessage(message)).map(message => message.event_id));
      return timeline
        .filter(row => allowedEvents.has(row.event_id))
        .filter(row => !(row.attachment_id && emailEvents.has(row.event_id)))
        .slice()
        .sort((a, b) => String(a.timeline_dt_utc || '').localeCompare(String(b.timeline_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')) || String(a.attachment_id || '').localeCompare(String(b.attachment_id || '')));
    }
    function printTimelineTable(rows) {
      return `
        ${rows.map(row => {
          const message = byEvent.get(row.event_id) || {};
          const attachment = row.attachment_id ? byAttachment.get(row.attachment_id) : null;
          const recordId = [row.event_id, row.attachment_id || attachment?.exhibit_id].filter(Boolean).join(' | ');
          const details = [
            row.description || '',
            attachment ? `Attachment: ${attachment.filename || '[unnamed attachment]'}` : '',
          ].filter(Boolean).join('\\n');
          return `
            <section class="timeline-card">
              <div class="timeline-card-head">
                <div>${escapeHtml(row.source_label || 'timeline')}</div>
                <div>${escapeHtml(formatDateTime(row.timeline_dt_utc))}</div>
              </div>
              <div class="timeline-card-id">
                <div><strong>ID:</strong> ${escapeHtml(recordId)}</div>
                <div><strong>Source:</strong> ${escapeHtml([row.source, row.direction].filter(Boolean).join(' / '))}</div>
                <div><strong>Sender:</strong> ${escapeHtml(row.sender || message.display_sender || message.sender || '')}</div>
              </div>
              <div class="details">${escapeHtml(details)}</div>
              <div class="body-meta">${escapeHtml(attachment?.exhibit_id ? `Exhibit: ${attachment.exhibit_id}` : '')}</div>
            </section>`;
        }).join('')}`;
    }
    function printAttachmentManifestTable(rows, level = 'standard') {
      const includeFull = level === 'full';
      return `
        <table class="summary-table">
          <thead>
            <tr>
              <th style="width:15%;">Date / Time</th>
              <th style="width:13%;">Exhibit</th>
              <th>Attachment</th>
              <th style="width:13%;">Type</th>
              <th style="width:12%;">Size</th>
              <th style="width:16%;">Linked Message</th>
              ${includeFull ? '<th style="width:18%;">Print Status</th>' : ''}
            </tr>
          </thead>
          <tbody>
            ${rows.map(({ message, attachment }) => {
              const attachmentText = [
                attachment.filename || attachment.saved_path || '[unnamed attachment]',
                attachment.attachment_id,
                attachment.exif_dt_utc ? `EXIF ${formatDateTime(attachment.exif_dt_utc)}` : '',
              ].filter(Boolean).join('\\n');
              const eventText = [attachment.event_id, message.display_sender || message.sender || ''].filter(Boolean).join('\\n');
              return `
                <tr>
                  <td>${escapeHtml(formatDateTime(message.event_dt_utc))}</td>
                  <td class="summary-body">${escapeHtml([attachment.exhibit_id, attachment.attachment_id].filter(Boolean).join('\\n'))}</td>
                  <td class="summary-body">${escapeHtml(attachmentText)}</td>
                  <td>${escapeHtml(kindLabel(attachmentKind(attachment)))}</td>
                  <td>${escapeHtml(formatBytes(attachment.size_bytes))}</td>
                  <td class="summary-body">${escapeHtml(eventText)}</td>
                  ${includeFull ? `<td class="summary-body">${escapeHtml([
                    attachment.render_asset_status || '',
                    attachment.render_asset_warning || '',
                  ].filter(Boolean).join('\\n'))}</td>` : ''}
                </tr>`;
            }).join('')}
          </tbody>
        </table>`;
    }
    function openPrintDocument(title, bodyHtml, options = {}) {
      const printWindow = window.open('', '_blank');
      if (!printWindow) {
        alert('Please allow pop-ups to print this exhibit view.');
        return;
      }
      const baseHref = location.href.slice(0, location.href.lastIndexOf('/') + 1);
      printWindow.document.open();
      printWindow.document.write(`<!doctype html>
        <html lang="en">
          <head>
            <meta charset="utf-8">
            <base href="${escapeHtml(baseHref)}">
            <title>${escapeHtml(title)}</title>
            <style>${printStyles()}</style>
          </head>
          <body class="${escapeHtml(options.bodyClass || '')}">
            ${bodyHtml}
            <scr${'ipt'}>
              window.addEventListener('load', () => { setTimeout(() => window.print(), 150); });
            </scr${'ipt'}>
          </body>
        </html>`);
      printWindow.document.close();
    }
    function printSelectedDetail() {
      const level = 'standard';
      if (activeView === 'attachments') {
        const attachment = byAttachment.get(activeAttachmentId);
        if (!attachment) return;
        const message = byEvent.get(attachment.event_id) || {};
        openPrintDocument(`Attachment ${attachment.attachment_id}`, `
          <h1>Attorney Review Exhibit - Attachment Detail</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
          ${printAttachmentHtml(attachment, message, 'Selected Attachment', level)}
          <h2>Linked Message</h2>
          ${printMessageHtml(message, { level })}
        `);
        return;
      }
      const message = byEvent.get(activeEventId);
      if (!message) return;
      openPrintDocument(`Message ${message.event_id}`, `
        <h1>Attorney Review Exhibit - Message Detail</h1>
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
        ${printMessageHtml(message, { includeNearby: false, level })}
      `);
    }
    function printCurrentResults() {
      const level = 'standard';
      if (activeView === 'timeline') {
        const rows = visibleTimelineMessages()
          .filter((message, index, all) => all.findIndex(candidate => candidate.event_id === message.event_id) === index)
          .sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
        const appendixRows = rows.flatMap(message => (message.attachments || []).map(attachment => ({ message, attachment })));
        openPrintDocument('Attorney Review Timeline Results', `
          <h1>Attorney Review Exhibit - Chronological Timeline</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
          <p class="meta">${escapeHtml(activeFilterSummary())}</p>
          <p class="meta">${rows.length} messages in the visible timeline slice</p>
          ${rows.length ? rows.map(message => printMessageHtml(message, { level })).join('') : '<p>No timeline rows match the current filters.</p>'}
          ${appendixRows.length ? `<h2>Attachment Appendix</h2>${appendixRows.map(({ message, attachment }) => printAttachmentHtml(attachment, message, 'Attachment Exhibit', level)).join('')}` : ''}
        `);
        return;
      }
      if (activeView === 'attachments') {
        const rows = filteredAttachmentEntries();
        openPrintDocument('Attorney Review Attachment Manifest', `
          <h1>Attorney Review Exhibit - Attachment Manifest</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
          <p class="meta">${escapeHtml(activeFilterSummary())}</p>
          <p class="meta">${rows.length} attachments from ${filteredMessages().length} filtered messages</p>
          ${rows.length ? printAttachmentManifestTable(rows, level) : '<p>No attachments match the current filters.</p>'}
        `);
        return;
      }
      const rows = filteredMessages().slice().sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
      const attachmentCount = rows.reduce((count, message) => count + (message.attachments || []).length, 0);
      const appendixRows = rows.flatMap(message => (message.attachments || []).map(attachment => ({ message, attachment })));
      openPrintDocument('Attorney Review Search Results', `
        <h1>Attorney Review Exhibit - Chronological History</h1>
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
        <p class="meta">${escapeHtml(activeFilterSummary())}</p>
        <p class="meta">${rows.length} messages | ${attachmentCount} direct attachments</p>
        ${rows.map(message => printMessageHtml(message, { level })).join('')}
        ${appendixRows.length ? `<h2>Attachment Appendix</h2>${appendixRows.map(({ message, attachment }) => printAttachmentHtml(attachment, message, 'Attachment Exhibit', level)).join('')}` : ''}
      `);
    }
    function printSummaryResults() {
      if (activeView === 'attachments') {
        const rows = filteredAttachmentEntries();
        openPrintDocument('Attorney Review Attachment Summary', `
          <h1>Attorney Review Exhibit - Attachment Summary</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
          <p class="meta">${escapeHtml(activeFilterSummary())}</p>
          <p class="meta">${rows.length} attachments from ${filteredMessages().length} filtered messages</p>
          ${rows.length ? printAttachmentSummaryTable(rows) : '<p>No attachments match the current filters.</p>'}
        `);
        return;
      }
      const rows = filteredMessages()
        .slice()
        .sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
      const title = activeView === 'timeline'
        ? 'Attorney Review Exhibit - Timeline Summary'
        : 'Attorney Review Exhibit - Search Summary';
      const summaryLabel = activeView === 'timeline' ? 'filtered timeline messages' : 'filtered messages';
      openPrintDocument('Attorney Review Summary', `
        <h1>${escapeHtml(title)}</h1>
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
        <p class="meta">${escapeHtml(activeFilterSummary())}</p>
        <p class="meta">${rows.length} ${escapeHtml(summaryLabel)}</p>
        ${rows.length ? printSummaryTable(rows) : '<p>No messages match the current filters.</p>'}
        ${rows.length ? printSummaryAppendix(rows) : ''}
      `);
    }
    function updatePrintMenuLabels() {
      if (activeView === 'timeline') {
        els.printCurrent.textContent = 'Print Current Message';
        els.printResults.textContent = 'Print Visible Timeline';
        els.printSummary.textContent = 'Print Timeline Summary';
        return;
      }
      if (activeView === 'attachments') {
        els.printCurrent.textContent = 'Print Current Attachment';
        els.printResults.textContent = 'Print Attachment Manifest';
        els.printSummary.textContent = 'Print Attachment Summary';
        return;
      }
      els.printCurrent.textContent = 'Print Current Message';
      els.printResults.textContent = 'Print Search Results';
      els.printSummary.textContent = 'Print Search Summary';
    }
    function filteredMessageAttachments() {
      const seen = new Set();
      return filteredMessages()
        .slice()
        .sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')))
        .flatMap(message => (message.attachments || []).map(att => ({ message, attachment: att })))
        .filter(({ attachment }) => {
          const key = attachment.attachment_id || `${attachment.event_id}:${attachment.saved_path}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .sort((a, b) => String(a.message.event_dt_utc || '').localeCompare(String(b.message.event_dt_utc || '')) || String(a.attachment.attachment_id || '').localeCompare(String(b.attachment.attachment_id || '')));
    }
    function printFullPacket() {
      const level = 'standard';
      const rows = messages
        .slice()
        .sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
      const attachmentRows = rows
        .flatMap(message => (message.attachments || []).map(attachment => ({ message, attachment })))
        .sort((a, b) => String(a.message.event_dt_utc || '').localeCompare(String(b.message.event_dt_utc || '')) || String(a.attachment.attachment_id || '').localeCompare(String(b.attachment.attachment_id || '')));
      openPrintDocument('Attorney Review Full Packet', `
        <h1>Attorney Review Exhibit - Full Packet</h1>
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}</p>
        <p class="meta">All records in the bundle. Current search filters are not applied.</p>
        <p class="meta">${rows.length} messages | ${attachmentRows.length} appendix attachments</p>
        ${rows.length ? rows.map(message => printMessageHtml(message, { level })).join('') : '<p>No messages match the current filters.</p>'}
        ${attachmentRows.length ? `<h2>Attachment Appendix</h2>${attachmentRows.map(({ message, attachment }) => printAttachmentHtml(attachment, message, 'Attachment Exhibit', level)).join('')}` : ''}
      `);
    }
    function sortMessagesChronologically(rows) {
      return rows
        .slice()
        .sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
    }
    function emailThreadRows(message) {
      const graphNeighbors = emailGraph.get(message.event_id) || new Set();
      if (graphNeighbors.size) {
        const visited = new Set([message.event_id]);
        const queue = [message.event_id];
        while (queue.length) {
          const current = queue.shift();
          for (const neighbor of emailGraph.get(current) || []) {
            if (visited.has(neighbor)) continue;
            visited.add(neighbor);
            queue.push(neighbor);
          }
        }
        const graphRows = [...visited]
          .map(eventId => byEvent.get(eventId))
          .filter(Boolean);
        if (graphRows.length > 1) return sortMessagesChronologically(graphRows);
      }

      const exactRows = byThread.get(message.thread_key || message.event_id) || [];
      if (exactRows.length > 1) return sortMessagesChronologically(exactRows);

      const normalizedSubject = normalizedEmailSubject(message.subject);
      if (normalizedSubject) {
        const fallbackKey = `${conversationKey(message)}||${normalizedSubject}`;
        const fallbackRows = emailFallbackBySubjectConversation.get(fallbackKey) || [];
        if (fallbackRows.length > 1) return sortMessagesChronologically(fallbackRows);
      }

      return [message];
    }
    function threadContextSlices(threadRows, currentEventId) {
      const currentIndex = threadRows.findIndex(row => row.event_id === currentEventId);
      if (currentIndex === -1) {
        return { rows: [byEvent.get(currentEventId)].filter(Boolean), currentIndex: -1 };
      }
      const start = Math.max(0, currentIndex - TIMELINE_CONTEXT_SIZE);
      const end = Math.min(threadRows.length - 1, currentIndex + TIMELINE_CONTEXT_SIZE);
      const threadKey = `thread:${currentEventId}`;
      const beforeExpansion = threadContextExpansion.get(`${threadKey}:before`) || 0;
      const afterExpansion = threadContextExpansion.get(`${threadKey}:after`) || 0;
      const visibleStart = Math.max(0, start - beforeExpansion);
      const visibleEnd = Math.min(threadRows.length - 1, end + afterExpansion);
      return {
        currentIndex,
        start,
        end,
        visibleStart,
        visibleEnd,
        rows: threadRows.slice(visibleStart, visibleEnd + 1),
        hiddenBefore: visibleStart,
        hiddenAfter: (threadRows.length - 1) - visibleEnd,
        threadKey,
      };
    }
    function threadContextNote(message) {
      const text = isEmailMessage(message)
        ? 'Shows this email thread only, based on Message-ID, In-Reply-To, or a cautious subject fallback. Nearby messages in the global Timeline may not appear here.'
        : 'Shows this text thread only, based on the imported conversation thread. Nearby messages in the global Timeline may not appear here.';
      return `<div class="thread-context-note"><span class="thread-context-note-icon" aria-hidden="true">i</span><div><strong>Thread-local view.</strong> ${escapeHtml(text)}</div></div>`;
    }
    function threadContextHtml(message, isOpen = false) {
      const threadRows = isEmailMessage(message)
        ? emailThreadRows(message)
        : (byThread.get(message.thread_key || message.event_id) || [message]);
      const context = threadContextSlices(threadRows, message.event_id);
      const rows = context.rows || [message];
      const showThreadNav = threadRows.length > 1;
      return `
        <details ${isOpen ? 'open' : ''}>
          <summary>Thread Context</summary>
          <div class="thread-context">
            ${threadContextNote(message)}
            ${showThreadNav ? `
              <div class="thread-context-nav"><button type="button" data-thread-expand-prev="${escapeHtml(context.threadKey)}" ${context.hiddenBefore ? '' : 'disabled'}>Previous ${TIMELINE_EXPAND_SIZE}</button></div>` : ''}
            <section class="timeline-slice">
              ${rows.map(row => timelineRowHtml(row, row.event_id === message.event_id, 'Current Message').replace('data-select-event=', 'data-thread-event=')).join('')}
            </section>
            ${showThreadNav ? `
              <div class="thread-context-nav"><button type="button" data-thread-expand-next-after="${escapeHtml(context.threadKey)}" ${context.hiddenAfter ? '' : 'disabled'}>Next ${TIMELINE_EXPAND_SIZE}</button></div>` : ''}
          </div>
        </details>`;
    }
    function renderAttachmentDetail(att) {
      const message = byEvent.get(att.event_id) || {};
      els.detail.innerHTML = `
        <div class="detail-header">
        <h2>${escapeHtml(att.attachment_id)} Attachment</h2>
      </div>
      ${attachmentMetadataHtml(att, message)}
        <p><button id="selectSourceMessage" type="button">Select source message</button></p>
        ${attachmentLinks(att)}
        ${exhibitCoverHtml(att, message)}
        ${attachmentPreviewHtml(att)}
        <details>
          <summary>Record Metadata</summary>
          <div class="detail-grid compact">
            ${detailCard('linked message event_id', message.event_id)}
            ${detailCard('linked message timestamp', formatDateTime(message.event_dt_utc))}
            ${detailCard('linked message source', message.source)}
            ${detailCard('linked message direction', message.direction)}
            ${detailCard('linked message sender', message.sender)}
            ${detailCard('linked message recipients', (message.recipients || []).join(', '))}
            ${detailCard('linked message subject', message.subject)}
            ${bundleSummaryFields()}
          </div>
        </details>
      `;
      document.getElementById('selectSourceMessage').addEventListener('click', () => {
        activeEventId = att.event_id;
        activeView = 'timeline';
        render();
      });
    }
    function renderDetail() {
      if (!activeEventId) {
        els.detail.innerHTML = '<div class="empty"><div class="empty-icon" aria-hidden="true"></div><div>Click a message to view details</div></div>';
        return;
      }
      const visibleMessages = filteredMessages();
      const timelineMessages = activeView === 'timeline' ? visibleTimelineMessages() : [];
      const directMatches = activeView === 'timeline'
        ? filteredMessages().filter(message => {
            const query = currentSearchQuery();
            return query ? messageQueryText(message).includes(query) : false;
          })
        : [];
      const message = activeView === 'timeline'
        ? (
          timelineMessages.find(row => row.event_id === activeEventId)
          || directMatches.find(row => row.event_id === activeEventId)
        )
        : visibleMessages.find(row => row.event_id === activeEventId);
      if (!message) {
        clearSelection();
        els.detail.innerHTML = '<div class="empty"><div class="empty-icon" aria-hidden="true"></div><div>Click a message to view details</div></div>';
        return;
      }
      activeEventId = message.event_id;
      const threadContextWasOpen = Boolean(
        els.detail.querySelector('details > summary') &&
        [...els.detail.querySelectorAll('details > summary')].some(summary => summary.textContent.trim() === 'Thread Context' && summary.parentElement?.open)
      );
      const attachments = message.attachments || [];
      const attachmentsHtml = attachments.map(att => `
        <div class="attachment">
          ${attachmentLinks(att)}
          ${attachmentPreviewHtml(att)}
          ${attachmentMetadataHtml(att, message)}
        </div>`).join('');
      const attachmentsSection = attachments.length
        ? `
        <details>
          <summary>Attachments (${attachments.length})</summary>
          ${attachmentsHtml}
        </details>`
        : '<div class="detail-section-empty">No attachments for this message</div>';

      els.detail.innerHTML = `
        <div class="detail-header">
          <h2>${escapeHtml(message.event_id)}</h2>
        </div>
        <div class="message-body-area">${messageBodyHtml(message)}</div>
        ${attachmentsSection}
        ${threadContextHtml(message, threadContextWasOpen)}
        ${recordMetadataHtml(message)}
      `;
      els.detail.querySelectorAll('[data-thread-expand-prev]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const anchor = threadSeparatorAnchorFromButton(button, 'prev');
        const key = `${button.dataset.threadExpandPrev}:before`;
        threadContextExpansion.set(key, (threadContextExpansion.get(key) || 0) + TIMELINE_EXPAND_SIZE);
        renderDetail();
        restoreThreadAnchor(anchor);
      }));
      els.detail.querySelectorAll('[data-thread-expand-next-after]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const anchor = firstVisibleThreadAnchor();
        const key = `${button.dataset.threadExpandNextAfter}:after`;
        threadContextExpansion.set(key, (threadContextExpansion.get(key) || 0) + TIMELINE_EXPAND_SIZE);
        renderDetail();
        restoreThreadAnchor(anchor);
      }));
    }
    function render() {
      const filteredCount = filteredMessages().length;
      els.messagesTab.setAttribute('aria-selected', activeView === 'messages' ? 'true' : 'false');
      els.timelineTab.setAttribute('aria-selected', activeView === 'timeline' ? 'true' : 'false');
      els.resultsCount.textContent = `Results: ${filteredCount} ${filteredCount === 1 ? 'message' : 'messages'}`;
      updatePrintMenuLabels();
      updateFilterToggle();
      renderList();
      renderDetail();
      updateActiveItems();
    }
    els.search.addEventListener('input', () => {
      clearSelection();
      render();
      els.list.scrollTop = 0;
    });
    [els.source, els.direction, els.attachment, els.start, els.end, els.aiTag].forEach(el => el.addEventListener('input', () => {
      clearSelection();
      render();
    }));
    els.toggleFilters.addEventListener('click', () => {
      els.advanced.hidden = !els.advanced.hidden;
      updateFilterToggle();
    });
    els.clearFilters.addEventListener('click', () => {
      els.search.value = '';
      els.source.value = '';
      els.direction.value = '';
      els.attachment.value = '';
      els.start.value = '';
      els.end.value = '';
      els.aiTag.value = '';
      clearSelection();
      render();
      els.list.scrollTop = 0;
    });
    els.timelineTab.addEventListener('click', () => { activeView = 'timeline'; render(); });
    els.messagesTab.addEventListener('click', () => { activeView = 'messages'; render(); });
    els.printCurrent.addEventListener('click', () => { els.printMenu.open = false; printSelectedDetail(); });
    els.printResults.addEventListener('click', () => { els.printMenu.open = false; printCurrentResults(); });
    els.printSummary.addEventListener('click', () => { els.printMenu.open = false; printSummaryResults(); });
    els.printFullPacket.addEventListener('click', () => { els.printMenu.open = false; printFullPacket(); });
    render();
  </script>
</body>
</html>
""".replace("__BUNDLE_PAYLOAD__", payload)


def write_readme(path: Path, integrity: dict[str, Any]) -> None:
    text = f"""Attorney Review Bundle

Open index.html in a browser. No web server or network connection is required.

Primary files:
- index.html: searchable offline review interface.
- data/messages.json: exported message records with linked attachment metadata.
- data/messages.csv: spreadsheet-friendly message export.
- data/attachments.csv: attachment manifest.
- data/timeline.csv: unified message and attachment timeline.
- data/integrity_report.json: deterministic validation checks and warnings.
- data/bundle_manifest.json: build metadata and source database hash.
- data/communications.sqlite: copied source database.
- attachments/: copied original attachment tree plus converted JPG files when present.
- attachments/<event_id>/pages/*.jpg: rasterized JPEG pages for PDF attachments used by self-contained browser print.

Citation format:
E-004123 | 2025-05-01T14:30:00Z | SMS | excerpt...

Caveats:
- The SQLite database and deterministic exports are the source of truth.
- Missing metadata is shown explicitly where known.
- Converted JPG files are preferred for viewing HEIC images, but original saved paths are still exposed.
- Browser print is self-contained for inline-printable attachments. PDF attachments are rasterized into page images, while unsupported attachment types render as metadata sheets with explicit separate-print notes.
- No GPS/location columns or location-derived views are included.
- Optional AI triage output, when present in ai/message_tags.json, is displayed only as a cautious tag layer and does not replace original message text or deterministic metadata.

Integrity status: {integrity["status"]}
See data/integrity_report.json for detailed check results.
"""
    path.write_text(text, encoding="utf-8")


def main() -> None:
    args = parse_args()
    db_path = Path(args.db).resolve()
    attachments_dir = Path(args.attachments_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not db_path.exists():
        raise SystemExit(f"DB not found: {db_path}")
    if not attachments_dir.exists():
        raise SystemExit(f"Attachments directory not found: {attachments_dir}")

    ensure_clean_output(output_dir, args.force)

    conn = sqlite3.connect(str(db_path))
    messages = row_dicts(conn, "messages", MESSAGE_FIELDS, "event_dt_utc, event_id")
    attachments = row_dicts(conn, "attachments", ATTACHMENT_FIELDS, "attachment_id")
    conn.close()

    shutil.copy2(db_path, output_dir / "data" / "communications.sqlite")
    shutil.copytree(attachments_dir, output_dir / "attachments", dirs_exist_ok=True)

    message_exports, attachment_exports, timeline_rows = build_exports(messages, attachments)
    render_summary = build_attachment_render_assets(output_dir, attachment_exports)
    ai_triage = load_ai_triage(output_dir)
    apply_ai_triage(message_exports, ai_triage)
    integrity = validate(db_path, output_dir, message_exports, attachment_exports, timeline_rows)
    integrity["checks"]["attachment_render_assets_generated_without_errors"] = not render_summary.get(
        "render_asset_warnings"
    )
    integrity["details"]["render_asset_warnings"] = render_summary.get("render_asset_warnings", [])
    integrity["render_assets"] = render_summary
    if render_summary.get("render_asset_warnings"):
        integrity["status"] = "review_warnings"
    manifest = build_manifest(
        db_path,
        output_dir,
        message_exports,
        attachment_exports,
        timeline_rows,
        integrity,
        render_summary,
    )

    write_json(output_dir / "data" / "messages.json", message_exports)
    write_csv(
        output_dir / "data" / "messages.csv",
        message_exports,
        MESSAGE_FIELDS + ["has_attachments", "attachment_count"] + MESSAGE_DERIVED_FIELDS,
    )
    write_csv(
        output_dir / "data" / "attachments.csv",
        attachment_exports,
        ATTACHMENT_FIELDS + ATTACHMENT_DERIVED_FIELDS,
    )
    write_csv(output_dir / "data" / "timeline.csv", timeline_rows, TIMELINE_FIELDS)
    write_json(output_dir / "data" / "integrity_report.json", integrity)
    write_json(output_dir / "data" / "bundle_manifest.json", manifest)
    (output_dir / "index.html").write_text(
        render_index(
            message_exports,
            attachment_exports,
            timeline_rows,
            integrity,
            render_summary,
            ai_triage,
            manifest,
        ),
        encoding="utf-8",
    )
    write_readme(output_dir / "README_FOR_ATTORNEY.txt", integrity)

    print(f"Bundle written to {output_dir}")
    print(f"Messages: {len(message_exports)}")
    print(f"Attachments: {len(attachment_exports)}")
    print(f"Timeline rows: {len(timeline_rows)}")
    print(f"Integrity status: {integrity['status']}")


if __name__ == "__main__":
    main()
