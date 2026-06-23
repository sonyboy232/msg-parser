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
import io
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
    "exhibit_pdf_path",
    "exhibit_status",
    "exhibit_warning",
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
        attachment["exhibit_pdf_path"] = ""
        attachment["exhibit_status"] = ""
        attachment["exhibit_warning"] = ""
        by_event[attachment["event_id"]].append(attachment)

    message_exports: list[dict[str, Any]] = []
    for message in messages:
        msg_attachments = by_event.get(message["event_id"], [])
        body = str(message.get("body_clean", "") or "").strip()
        body_preview = compact_text(body or "[no message body]", 180)
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


def require_pdf_libraries() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from PIL import Image
        from pypdf import PdfReader, PdfWriter
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.utils import ImageReader
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise SystemExit(
            "PDF exhibit generation requires pypdf, reportlab, and pillow. "
            "Install them in the active environment, for example: "
            "python -m pip install pypdf reportlab pillow"
        ) from exc
    return PdfReader, PdfWriter, canvas, letter, (Image, ImageReader)


def wrap_reportlab_text(text: str, max_chars: int = 92) -> list[str]:
    words = str(text or "").split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        next_length = length + len(word) + (1 if current else 0)
        if current and next_length > max_chars:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length = next_length
    if current:
        lines.append(" ".join(current))
    return lines or [""]


def make_cover_pdf(
    attachment: dict[str, Any],
    message: dict[str, Any],
    canvas_module: Any,
    pagesize: tuple[float, float],
    warning: str = "",
) -> io.BytesIO:
    buffer = io.BytesIO()
    width, height = pagesize
    pdf = canvas_module.Canvas(buffer, pagesize=pagesize)
    pdf.setTitle(f"{attachment.get('exhibit_id') or attachment.get('attachment_id')} cover")

    y = height - 72
    pdf.setFont("Helvetica-Bold", 28)
    pdf.drawCentredString(width / 2, y, str(attachment.get("exhibit_id") or "Attachment Exhibit"))
    y -= 34
    pdf.setFont("Helvetica-Bold", 15)
    pdf.drawCentredString(width / 2, y, "ATTACHMENT EXHIBIT COVER PAGE")

    y -= 42
    pdf.setFont("Helvetica", 11)
    rows = [
        ("Attachment ID", attachment.get("attachment_id")),
        ("Source event_id", attachment.get("event_id")),
        ("Message timestamp", court_datetime(message.get("event_dt_utc"))),
        ("Sender", message.get("sender")),
        ("Recipients", ", ".join(message.get("recipients") or [])),
        ("Filename", attachment.get("filename") or attachment.get("saved_path")),
        ("MIME type", attachment.get("mime_type")),
        ("Size", attachment.get("size_bytes")),
        ("EXIF timestamp", court_datetime(attachment.get("exif_dt_utc"))),
        ("SHA-256", attachment.get("sha256_hash")),
    ]
    for label, value in rows:
        if y < 96:
            pdf.showPage()
            y = height - 72
            pdf.setFont("Helvetica", 11)
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(72, y, f"{label}:")
        pdf.setFont("Helvetica", 10)
        line_x = 180
        for index, line in enumerate(wrap_reportlab_text(str(value or ""))):
            pdf.drawString(line_x, y - (index * 13), line)
        y -= max(17, 13 * len(wrap_reportlab_text(str(value or ""))) + 4)

    kind = attachment_kind(attachment).upper()
    y -= 10
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(72, y, f"Attachment type: {kind}")
    y -= 20

    if warning:
        pdf.setFillColorRGB(0.5, 0.13, 0.08)
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(72, y, "Generation note:")
        y -= 15
        pdf.setFont("Helvetica", 10)
        for line in wrap_reportlab_text(warning):
            pdf.drawString(72, y, line)
            y -= 13
        pdf.setFillColorRGB(0, 0, 0)

    pdf.setFont("Helvetica", 9)
    pdf.drawString(72, 45, "Generated from the offline attorney review bundle. Original file paths and hashes remain in the manifest.")
    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer


def append_pdf_pages(writer: Any, reader: Any) -> None:
    for page in reader.pages:
        writer.add_page(page)


def append_image_page(
    writer: Any,
    image_path: Path,
    canvas_module: Any,
    pagesize: tuple[float, float],
    image_tools: tuple[Any, Any],
) -> io.BytesIO:
    Image, ImageReader = image_tools
    page = io.BytesIO()
    width, height = pagesize
    margin = 54
    target_dpi = 200
    with Image.open(image_path) as img:
        if getattr(img, "n_frames", 1) > 1:
            img.seek(0)
        if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
            img = img.convert("RGBA")
            background = Image.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1])
            img = background
        elif img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        max_pixels = (
            int((width - margin * 2) / 72 * target_dpi),
            int((height - margin * 2) / 72 * target_dpi),
        )
        img.thumbnail(max_pixels, Image.Resampling.LANCZOS)
        img_width, img_height = img.size
        scale = min((width - margin * 2) / img_width, (height - margin * 2) / img_height)
        draw_width = img_width * scale
        draw_height = img_height * scale
        x = (width - draw_width) / 2
        y = (height - draw_height) / 2
        image_buffer = io.BytesIO()
        img.save(image_buffer, format="JPEG", quality=88, optimize=True)
        image_buffer.seek(0)
        pdf = canvas_module.Canvas(page, pagesize=pagesize)
        pdf.drawImage(ImageReader(image_buffer), x, y, width=draw_width, height=draw_height, preserveAspectRatio=True)
        pdf.showPage()
        pdf.save()
    page.seek(0)
    return page


def rasterize_pdf_pages(pdf_path: Path, output_dir: Path, stem: str) -> list[Path]:
    ghostscript = shutil.which("gs")
    if not ghostscript:
        raise RuntimeError("Ghostscript (gs) is required to rasterize PDF attachments into exhibit pages.")
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


def build_exhibit_pdfs(
    output_dir: Path,
    messages: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
) -> dict[str, Any]:
    PdfReader, PdfWriter, canvas_module, pagesize, image_tools = require_pdf_libraries()
    exhibits_dir = output_dir / "exhibits"
    exhibits_dir.mkdir(parents=True, exist_ok=True)
    rendered_pages_dir = exhibits_dir / "rendered_pages"
    rendered_pages_dir.mkdir(parents=True, exist_ok=True)
    exhibit_manifest_path = exhibits_dir / "exhibit_manifest.json"
    previous_exhibit_manifest: dict[str, dict[str, str]] = {}
    if exhibit_manifest_path.exists():
        try:
            previous_data = json.loads(exhibit_manifest_path.read_text(encoding="utf-8"))
            previous_exhibit_manifest = {
                str(row.get("attachment_id") or ""): row
                for row in previous_data.get("attachments", [])
                if row.get("attachment_id")
            }
        except (json.JSONDecodeError, OSError):
            previous_exhibit_manifest = {}
    message_by_event = {message["event_id"]: message for message in messages}
    warnings: list[dict[str, str]] = []
    packet_writer = PdfWriter()
    generated_count = 0
    reused_count = 0
    manifest_rows: list[dict[str, str]] = []

    sorted_attachments = sorted(
        attachments,
        key=lambda att: (
            str(message_by_event.get(att.get("event_id"), {}).get("event_dt_utc") or ""),
            str(att.get("attachment_id") or ""),
        ),
    )

    for attachment in sorted_attachments:
        message = message_by_event.get(attachment.get("event_id"), {})
        exhibit_id = attachment.get("exhibit_id") or attachment.get("attachment_id") or "EX-UNKNOWN"
        raw_filename = str(attachment.get("filename") or Path(str(attachment.get("saved_path") or "")).name or "")
        filename_stem = Path(raw_filename).stem if raw_filename else "attachment"
        output_name = safe_artifact_name(f"{exhibit_id}_{filename_stem}", str(exhibit_id)) + ".pdf"
        output_path = exhibits_dir / output_name
        relative_path = output_path.relative_to(output_dir).as_posix()
        warning = ""
        writer = PdfWriter()
        kind = attachment_kind(attachment)

        source_href = (
            str(attachment.get("bundle_saved_path") or "")
            if kind == "pdf"
            else str(attachment.get("preferred_view_path") or attachment.get("bundle_saved_path") or "")
        )
        source_path = bundle_href_to_path(output_dir, source_href)

        try:
            previous_row = previous_exhibit_manifest.get(str(attachment.get("attachment_id") or ""), {})
            cached_status = str(previous_row.get("exhibit_status") or "")
            needs_pdf_raster_refresh = kind == "pdf" and "pdf_images" not in cached_status
            can_reuse_output = (
                output_path.exists()
                and not needs_pdf_raster_refresh
                and (not source_path.exists() or output_path.stat().st_mtime >= source_path.stat().st_mtime)
            )
            if can_reuse_output:
                attachment["exhibit_pdf_path"] = relative_path
                attachment["exhibit_status"] = (
                    f"cached_{kind}_exhibit" if cached_status == "cached" else cached_status or f"cached_{kind}_exhibit"
                )
                attachment["exhibit_warning"] = previous_row.get("exhibit_warning") or ""
                if attachment["exhibit_warning"]:
                    warnings.append(
                        {
                            "attachment_id": str(attachment.get("attachment_id") or ""),
                            "warning": str(attachment["exhibit_warning"]),
                        }
                    )
                exhibit_reader = PdfReader(str(output_path))
                append_pdf_pages(packet_writer, exhibit_reader)
                reused_count += 1
                manifest_rows.append(
                    {
                        "attachment_id": str(attachment.get("attachment_id") or ""),
                        "exhibit_id": str(attachment.get("exhibit_id") or ""),
                        "exhibit_pdf_path": relative_path,
                        "exhibit_status": str(attachment.get("exhibit_status") or ""),
                        "exhibit_warning": str(attachment.get("exhibit_warning") or ""),
                    }
                )
                continue

            if not source_path.exists():
                warning = f"Source attachment file was not found in the bundle: {source_href}"

            cover = make_cover_pdf(attachment, message, canvas_module, pagesize, warning)
            append_pdf_pages(writer, PdfReader(cover))
            attachment["exhibit_warning"] = ""

            if source_path.exists() and kind == "pdf":
                try:
                    page_stem = safe_artifact_name(str(attachment.get("attachment_id") or exhibit_id), str(exhibit_id))
                    rendered_pages = rasterize_pdf_pages(source_path, rendered_pages_dir, page_stem)
                    for page_path in rendered_pages:
                        image_page = append_image_page(writer, page_path, canvas_module, pagesize, image_tools)
                        append_pdf_pages(writer, PdfReader(image_page))
                    attachment["exhibit_status"] = "cover_plus_pdf_images"
                except Exception as exc:
                    warning = f"Original PDF could not be rasterized into exhibit pages; cover page generated only. {exc}"
                    attachment["exhibit_status"] = "cover_only_pdf_error"
            elif source_path.exists() and kind == "image":
                try:
                    image_page = append_image_page(writer, source_path, canvas_module, pagesize, image_tools)
                    append_pdf_pages(writer, PdfReader(image_page))
                    attachment["exhibit_status"] = "cover_plus_image"
                except Exception as exc:
                    warning = f"Image could not be embedded; cover page generated only. {exc}"
                    attachment["exhibit_status"] = "cover_only_image_error"
            elif not attachment.get("exhibit_status"):
                attachment["exhibit_status"] = "cover_only"

            if warning and not attachment.get("exhibit_warning"):
                attachment["exhibit_warning"] = warning
                warnings.append({"attachment_id": str(attachment.get("attachment_id") or ""), "warning": warning})

            with output_path.open("wb") as fh:
                writer.write(fh)
            attachment["exhibit_pdf_path"] = relative_path
            generated_count += 1

            exhibit_reader = PdfReader(str(output_path))
            append_pdf_pages(packet_writer, exhibit_reader)
            manifest_rows.append(
                {
                    "attachment_id": str(attachment.get("attachment_id") or ""),
                    "exhibit_id": str(attachment.get("exhibit_id") or ""),
                    "exhibit_pdf_path": relative_path,
                    "exhibit_status": str(attachment.get("exhibit_status") or ""),
                    "exhibit_warning": str(attachment.get("exhibit_warning") or ""),
                }
            )
        except Exception as exc:
            attachment["exhibit_status"] = "generation_failed"
            attachment["exhibit_warning"] = str(exc)
            warnings.append({"attachment_id": str(attachment.get("attachment_id") or ""), "warning": str(exc)})

    packet_path = exhibits_dir / "attachment_packet.pdf"
    with packet_path.open("wb") as fh:
        packet_writer.write(fh)
    write_json(
        exhibit_manifest_path,
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "generated_count": generated_count,
            "reused_count": reused_count,
            "packet_path": packet_path.relative_to(output_dir).as_posix(),
            "attachments": manifest_rows,
        },
    )

    return {
        "generated_exhibit_pdf_count": generated_count,
        "reused_exhibit_pdf_count": reused_count,
        "attachment_packet_pdf_path": packet_path.relative_to(output_dir).as_posix(),
        "exhibit_generation_warnings": warnings,
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
    missing_exhibit_pdf_paths: list[dict[str, str]] = []
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

        exhibit_pdf_path = str(attachment.get("exhibit_pdf_path") or "")
        if not exhibit_pdf_path or not (bundle_dir / exhibit_pdf_path).exists():
            missing_exhibit_pdf_paths.append(
                {"attachment_id": attachment["attachment_id"], "exhibit_pdf_path": exhibit_pdf_path}
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
        "all_exhibit_pdfs_exist_in_bundle": not missing_exhibit_pdf_paths,
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
            "missing_exhibit_pdf_paths": missing_exhibit_pdf_paths,
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
    exhibit_summary: dict[str, Any],
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
        "attachment_packet_pdf_path": exhibit_summary.get("attachment_packet_pdf_path", ""),
        "generated_exhibit_pdf_count": exhibit_summary.get("generated_exhibit_pdf_count", 0),
        "reused_exhibit_pdf_count": exhibit_summary.get("reused_exhibit_pdf_count", 0),
        "exhibit_generation_warning_count": len(exhibit_summary.get("exhibit_generation_warnings", [])),
        "script_name": Path(__file__).name,
        "script_version": SCRIPT_VERSION,
    }


def render_index(
    messages: list[dict[str, Any]],
    attachments: list[dict[str, Any]],
    timeline_rows: list[dict[str, Any]],
    integrity: dict[str, Any],
    exhibit_summary: dict[str, Any],
    ai_triage: dict[str, Any],
    manifest: dict[str, Any],
) -> str:
    payload = json.dumps(
        {
            "messages": messages,
            "attachments": attachments,
            "timeline": timeline_rows,
            "integrity": integrity,
            "exhibits": exhibit_summary,
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
      border-bottom: 1px solid var(--line);
      background: #fff;
      z-index: 3;
    }
    h1 { margin: 0; font-size: 20px; line-height: 1.15; }
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
    .header-top { justify-content: space-between; }
    .search-row { flex-wrap: nowrap; }
    .search-row input { flex: 1 1 70%; min-width: 220px; }
    .search-row button { flex: 0 0 calc(15% - 4px); width: auto; min-width: 92px; padding-inline: 10px; }
    .left, .right { padding: 26px 14px 14px; min-width: 0; overflow: hidden; }
    .left { border-right: 1px solid var(--line); }
    .right { display: flex; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 12px;
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
    .item.active { border-color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
    .item.match {
      border-color: #d1b15f;
      background: #fffdf5;
      box-shadow: inset 3px 0 0 #d1b15f;
    }
    .item.match.active {
      border-color: var(--accent);
      box-shadow: inset 3px 0 0 var(--accent), inset 0 0 0 2px #f2d985;
    }
    .item-title {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 5px;
    }
    .summary {
      font-weight: 650;
      overflow-wrap: anywhere;
    }
    .timestamp {
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }
    .meta { color: var(--muted); font-size: 12px; }
    .body-preview {
      margin-top: 6px;
      color: #344044;
      overflow-wrap: anywhere;
    }
    .tag-row { margin-top: 8px; }
    .timeline-slice {
      display: grid;
      gap: 7px;
    }
    .slice-separator {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      color: var(--muted);
      font-size: 12px;
      margin: 2px 0;
    }
    .slice-separator::before,
    .slice-separator::after {
      content: "";
      height: 1px;
      flex: 1 1 auto;
      background: var(--line);
    }
    .slice-separator button {
      width: auto;
      min-width: 96px;
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
    }
    .timeline-bubble {
      max-width: 88%;
      padding: 9px 10px;
    }
    .timeline-bubble.direction-outbound {
      justify-self: end;
      background: #f8efe9;
    }
    .timeline-bubble.direction-inbound {
      justify-self: start;
      background: #edf5ff;
    }
    .timeline-email {
      width: 100%;
      background: #fff;
    }
    .email-subject {
      color: #344044;
      font-weight: 650;
      overflow-wrap: anywhere;
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
    .detail-grid { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 6px 10px; }
    .key { color: var(--muted); }
    .value { overflow-wrap: anywhere; }
    .body-box, textarea {
      white-space: pre-wrap;
      background: #fbfbf8;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      max-height: 300px;
      overflow: auto;
    }
    .attachment {
      border-top: 1px solid var(--line);
      padding-top: 10px;
      margin-top: 10px;
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
    details {
      border-top: 1px solid var(--soft-line);
      padding-top: 9px;
      margin-top: 9px;
    }
    summary { cursor: pointer; color: var(--accent); font-weight: 650; }
    a { color: var(--accent); overflow-wrap: anywhere; }
    .warning { color: var(--warn); font-weight: 650; }
    .empty { color: var(--muted); padding: 18px 8px; text-align: center; }
    .muted { color: var(--muted); }
    .header-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .header-actions label { display: flex; align-items: center; gap: 6px; }
    .header-actions select { width: auto; min-width: 116px; }
    .header-actions button { width: auto; min-width: 116px; }
    .print-menu {
      position: relative;
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
      .search-row { flex-wrap: wrap; }
      .search-row input, .search-row button { flex: 1 1 auto; }
      .mode-row button { flex: 1; min-width: 0; }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-top">
      <h1>Attorney Review Bundle</h1>
      <div class="meta">
        <span id="counts"></span>
        <span id="integrityStatus"></span>
      </div>
      <div class="header-actions">
        <details class="print-menu" id="printMenu">
          <summary>Print</summary>
          <div class="print-menu-body">
            <label>Print level
              <select id="printLevel">
                <option value="standard" selected>Standard</option>
                <option value="summary">Summary</option>
                <option value="full">Full</option>
              </select>
            </label>
            <button class="secondary" id="printCurrent" type="button">Print Current Message</button>
            <button class="secondary" id="printResults" type="button">Print Results</button>
            <button class="secondary" id="printSummary" type="button">Print Summary</button>
            <button class="secondary" id="printAttachments" type="button">Print Filtered Attachments</button>
            <a class="button-link" id="packetPdfLink" target="_blank" rel="noopener">Print Full Packet</a>
          </div>
        </details>
      </div>
    </div>
    <div class="search-row">
      <input id="search" type="search" placeholder="Search messages, people, filenames, IDs, paths">
      <button class="secondary" id="toggleFilters" type="button">Add filter</button>
      <button class="secondary" id="clearFilters" type="button">Clear</button>
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
    <div class="mode-row" role="tablist" aria-label="Review mode">
      <button id="messagesTab" type="button" aria-selected="true">Messages</button>
      <button id="timelineTab" type="button" aria-selected="false">Timeline</button>
      <button id="attachmentsTab" type="button" aria-selected="false">Attachments</button>
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
    const exhibits = data.exhibits || {};
    const manifest = data.manifest || {};
    const ai = data.ai || {};
    const CONVERSATION_ATTACHMENT_WINDOW_HOURS = 24;
    const CONVERSATION_ATTACHMENT_LIMIT = 12;
    const TIMELINE_CONTEXT_SIZE = 3;
    const TIMELINE_EXPAND_SIZE = 5;
    let activeView = 'messages';
    let activeEventId = messages[0]?.event_id || '';
    let activeAttachmentId = attachments[0]?.attachment_id || '';
    const timelineExpansion = new Map();

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
      attachmentsTab: document.getElementById('attachmentsTab'),
      printMenu: document.getElementById('printMenu'),
      printCurrent: document.getElementById('printCurrent'),
      printResults: document.getElementById('printResults'),
      printSummary: document.getElementById('printSummary'),
      printAttachments: document.getElementById('printAttachments'),
      packetPdfLink: document.getElementById('packetPdfLink'),
      printLevel: document.getElementById('printLevel'),
    };
    if (exhibits.attachment_packet_pdf_path) {
      els.packetPdfLink.href = exhibits.attachment_packet_pdf_path;
    } else {
      els.packetPdfLink.hidden = true;
    }

    function participantKey(value) {
      const text = String(value || '').trim().toLowerCase();
      const digits = text.replace(/\\D/g, '');
      if (digits.length >= 10) return digits.slice(-10);
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
    messages.forEach(message => {
      const key = message.thread_key || message.event_id;
      if (!byThread.has(key)) byThread.set(key, []);
      byThread.get(key).push(message);
      const conversation = conversationKey(message);
      if (!byConversation.has(conversation)) byConversation.set(conversation, []);
      byConversation.get(conversation).push(message);
    });
    els.counts.textContent = `${messages.length} messages | ${attachments.length} attachments | ${timeline.length} timeline rows`;
    els.integrityStatus.textContent = `Integrity: ${integrity.status}`;
    if (integrity.status !== 'pass') els.integrityStatus.className = 'warning';

    function optionList(values) {
      return '<option value="">Any</option>' + [...new Set(values.filter(Boolean))].sort().map(value => `<option>${escapeHtml(value)}</option>`).join('');
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
    function citation(message) {
      const excerpt = String(message.body_clean || '').replace(/\\s+/g, ' ').trim().slice(0, 160);
      return `${message.event_id} | ${formatDateTime(message.event_dt_utc)} | ${message.source} | ${excerpt}`;
    }
    async function copyCitation() {
      const message = byEvent.get(activeEventId);
      if (!message) return;
      const value = citation(message);
      try {
        await navigator.clipboard.writeText(value);
      } catch (err) {
        const field = document.getElementById('citationText');
        if (field) {
          field.focus();
          field.select();
          document.execCommand('copy');
        }
      }
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
    function renderBadges(message) {
      const sourceClass = `source-${safeClass(message.source_badge || message.source)}`;
      const directionClass = `direction-${safeClass(message.direction || message.direction_badge)}`;
      const directionIcon = safeClass(message.direction).includes('out') ? 'outbound' : 'inbound';
      const badges = [
        `<span class="badge source ${sourceClass}">${tagIcon('source')}${escapeHtml(message.source_badge || message.source)}</span>`,
        `<span class="badge direction ${directionClass}">${tagIcon(directionIcon)}${escapeHtml(message.direction_badge || message.direction)}</span>`,
      ];
      const nearbyAttachmentCount = nearbyConversationAttachmentEntries(message, false).length;
      const directKind = attachmentKindSummary(message.attachments || []);
      const nearbyEntries = nearbyConversationAttachmentEntries(message, false);
      const nearbyKind = attachmentKindSummary(nearbyEntries.map(entry => entry.attachment));
      if (message.attachment_count) badges.push(`<span class="badge attach kind-${safeClass(directKind)}">${tagIcon('attach')}ATT ${message.attachment_count} ${kindLabel(directKind)}</span>`);
      if (nearbyAttachmentCount) badges.push(`<span class="badge nearby kind-${safeClass(nearbyKind)}">${tagIcon('nearby')}NEARBY ${nearbyAttachmentCount} ${kindLabel(nearbyKind)}</span>`);
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
      return String(message.source || '').toLowerCase().includes('email');
    }
    function directionCss(message) {
      return safeClass(message.direction).includes('out') ? 'direction-outbound' : 'direction-inbound';
    }
    function attachmentIndicatorHtml(message) {
      const directKind = attachmentKindSummary(message.attachments || []);
      const pieces = [];
      if (message.attachment_count) pieces.push(`<span class="badge attach kind-${safeClass(directKind)}">${tagIcon('attach')}${message.attachment_count} ${kindLabel(directKind)}</span>`);
      if (message.is_attachment_only) pieces.push(`<span class="badge warn">${tagIcon('warn')}Attachment only</span>`);
      if (message.has_exif_attachment) pieces.push(`<span class="badge exif">${tagIcon('exif')}EXIF time</span>`);
      return pieces.join('');
    }
    function timelineRanges() {
      const matches = filteredMessages()
        .map(message => chronologicalIndex.get(message.event_id))
        .filter(index => index !== undefined)
        .sort((a, b) => a - b);
      const matchIndexes = new Set(matches);
      const ranges = [];
      matches.forEach(index => {
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
    function timelineRowHtml(message, isMatch) {
      const activeClass = message.event_id === activeEventId ? 'active' : '';
      const matchClass = isMatch ? 'match' : '';
      const commonAttrs = `data-event="${escapeHtml(message.event_id)}"`;
      if (isEmailMessage(message)) {
        return `
          <article class="item timeline-row timeline-email ${activeClass} ${matchClass}" ${commonAttrs}>
            <div class="item-title">
              <span class="summary">${escapeHtml(message.display_sender || message.sender || 'Email')}</span>
              <span class="timestamp">${escapeHtml(formatDateTime(message.event_dt_utc))}</span>
            </div>
            <div class="email-subject">${escapeHtml(message.subject || '[no subject]')}</div>
            <div class="body-preview">${escapeHtml(message.body_preview || message.display_summary || '[no preview]')}</div>
            <div class="meta tag-row">${isMatch ? '<span class="match-label">MATCH</span>' : ''}${renderBadges(message)}</div>
          </article>`;
      }
      return `
        <article class="item timeline-row timeline-bubble ${directionCss(message)} ${activeClass} ${matchClass}" ${commonAttrs}>
          <div class="item-title">
            <span class="summary">${escapeHtml(message.display_sender || message.sender || message.source || 'Message')}</span>
            <span class="timestamp">${escapeHtml(formatDateTime(message.event_dt_utc))}</span>
          </div>
          <div class="body-preview">${escapeHtml(message.body_preview || message.display_summary || '[no body]')}</div>
          <div class="meta tag-row">${isMatch ? '<span class="match-label">MATCH</span>' : ''}${attachmentIndicatorHtml(message)}</div>
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
        const next = ranges[rangeIndex + 1];
        const gapKey = `gap-${range.end}-${next ? next.start : 'end'}`;
        const expansion = timelineExpansion.get(gapKey) || 0;
        const visibleEnd = next ? Math.min(next.start - 1, range.end + expansion) : range.end;
        parts.push('<section class="timeline-slice">');
        for (let index = range.start; index <= visibleEnd; index += 1) {
          parts.push(timelineRowHtml(chronologicalMessages[index], matchIndexes.has(index)));
        }
        parts.push('</section>');
        if (next && visibleEnd < next.start - 1) {
          const skipped = next.start - visibleEnd - 1;
          parts.push(`<div class="slice-separator"><span>skipped ${skipped} message${skipped === 1 ? '' : 's'}</span><button type="button" data-expand-gap="${escapeHtml(gapKey)}">Show more</button></div>`);
        }
      });
      els.list.innerHTML = parts.join('');
    }
    function updateActiveItems() {
      els.list.querySelectorAll('.item.active').forEach(item => item.classList.remove('active'));
      els.list.querySelectorAll(`[data-event="${CSS.escape(activeEventId)}"]`).forEach(item => item.classList.add('active'));
      if (activeAttachmentId) {
        els.list.querySelectorAll(`[data-attachment="${CSS.escape(activeAttachmentId)}"]`).forEach(item => item.classList.add('active'));
      }
    }
    function selectEvent(eventId, attachmentId = '') {
      activeEventId = eventId;
      if (attachmentId) activeAttachmentId = attachmentId;
      renderDetail();
      updateActiveItems();
    }
    function bindListInteractions() {
      els.list.querySelectorAll('[data-event]').forEach(item => item.addEventListener('click', () => {
        selectEvent(item.dataset.event, item.dataset.attachment || '');
      }));
      els.list.querySelectorAll('[data-attachment]').forEach(item => item.addEventListener('click', () => {
        activeAttachmentId = item.dataset.attachment;
        selectEvent(item.dataset.event, item.dataset.attachment);
      }));
      els.list.querySelectorAll('[data-expand-gap]').forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const key = button.dataset.expandGap;
        timelineExpansion.set(key, (timelineExpansion.get(key) || 0) + TIMELINE_EXPAND_SIZE);
        renderList();
      }));
      els.list.querySelectorAll('a, button').forEach(control => control.addEventListener('click', event => event.stopPropagation()));
    }
    function renderList() {
      renderChips();
      if (activeView === 'messages') {
        const rows = filteredMessages().slice(0, 300);
        els.list.innerHTML = rows.map(message => `
          <article class="item ${message.event_id === activeEventId ? 'active' : ''}" data-event="${escapeHtml(message.event_id)}">
            <div class="item-title"><span class="summary">${escapeHtml(message.display_summary)}</span><span class="timestamp">${escapeHtml(formatDateTime(message.event_dt_utc))}</span></div>
            <div class="meta"><strong>${escapeHtml(message.event_id)}</strong><span>${escapeHtml(message.display_sender)}</span>${message.display_recipients ? `<span>to ${escapeHtml(message.display_recipients)}</span>` : ''}</div>
            <div class="body-preview">${escapeHtml(message.body_preview)}</div>
            <div class="meta tag-row">${renderBadges(message)}</div>
          </article>`).join('');
        if (!rows.length) els.list.innerHTML = '<div class="empty">No messages match the current filters.</div>';
      } else {
        if (activeView === 'attachments') {
          const rows = filteredAttachments().slice(0, 300);
          els.list.innerHTML = rows.map(att => {
            const sourceMessage = byEvent.get(att.event_id) || {};
            return `
            <article class="item ${att.attachment_id === activeAttachmentId ? 'active' : ''}" data-attachment="${escapeHtml(att.attachment_id)}" data-event="${escapeHtml(att.event_id)}">
              <div class="item-title"><span class="summary">${escapeHtml(att.filename || att.saved_path || att.attachment_id)}</span><span class="timestamp">${escapeHtml(att.attachment_id)}</span></div>
              <div class="meta"><strong>${escapeHtml(att.exhibit_id || att.attachment_id)}</strong><span>${escapeHtml(formatDateTime(sourceMessage.event_dt_utc || ''))}</span><span>${escapeHtml(formatBytes(att.size_bytes))}</span></div>
              <div class="body-preview">${escapeHtml(att.filename || att.saved_path || '[unnamed attachment]')}</div>
              <div class="meta tag-row"><span class="badge attach kind-${safeClass(attachmentKind(att))}">${tagIcon('attach')}${kindLabel(attachmentKind(att))}</span>${att.converted_path ? `<span class="badge kind-image">${tagIcon('attach')}Converted JPG</span>` : ''}${att.exif_dt_utc ? `<span class="badge exif">${tagIcon('exif')}EXIF time</span>` : ''}</div>
              <div class="row-actions compact-actions">
                ${att.exhibit_pdf_path ? `<a href="${escapeHtml(att.exhibit_pdf_path)}" target="_blank" rel="noopener">Exhibit PDF</a>` : ''}
                ${att.preferred_view_path ? `<a href="${escapeHtml(att.preferred_view_path)}" target="_blank" rel="noopener">Preferred</a>` : ''}
                ${att.bundle_saved_path ? `<a href="${escapeHtml(att.bundle_saved_path)}" target="_blank" rel="noopener">Original</a>` : ''}
              </div>
            </article>`;
          }).join('');
          if (!rows.length) els.list.innerHTML = '<div class="empty">No attachments match the current filters.</div>';
        } else {
          renderTimelineList();
        }
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
        <details open>
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
    function bundleSummaryHtml() {
      const warningCount = Number(manifest.exhibit_generation_warning_count || 0);
      const sourceDbName = String(manifest.source_db_path || '').split('/').pop();
      return `
        <details>
          <summary>Bundle Summary</summary>
          <div class="detail-grid">
            ${detailRow('bundle built', formatDateTime(manifest.build_timestamp_utc))}
            ${detailRow('integrity status', manifest.integrity_status || integrity.status)}
            ${detailRow('messages', manifest.message_count || messages.length)}
            ${detailRow('attachments', manifest.attachment_count || attachments.length)}
            ${detailRow('timeline rows', manifest.timeline_row_count || timeline.length)}
            ${detailRow('source database', sourceDbName)}
            ${detailRow('source db SHA-256', manifest.source_db_sha256)}
            ${detailRow('generated exhibits', manifest.generated_exhibit_pdf_count)}
            ${detailRow('reused exhibits', manifest.reused_exhibit_pdf_count)}
            ${detailRow('exhibit warnings', warningCount)}
            ${linkRow('full packet PDF', manifest.attachment_packet_pdf_path, manifest.attachment_packet_pdf_path)}
          </div>
        </details>`;
    }
    function attachmentLinks(att) {
      return `
        <div class="row-actions">
          ${att.exhibit_pdf_path ? `<a href="${escapeHtml(att.exhibit_pdf_path)}" target="_blank" rel="noopener">Open exhibit PDF</a>` : ''}
          ${att.preferred_view_path ? `<a href="${escapeHtml(att.preferred_view_path)}" target="_blank" rel="noopener">Open preferred view</a>` : ''}
          ${att.bundle_saved_path ? `<a href="${escapeHtml(att.bundle_saved_path)}" target="_blank" rel="noopener">Open original</a>` : ''}
          ${att.bundle_converted_path ? `<a href="${escapeHtml(att.bundle_converted_path)}" target="_blank" rel="noopener">Open converted JPG</a>` : ''}
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
      if (kind === 'image' && !String(href).toLowerCase().match(/\\.heics?$/)) {
        return `<div class="attachment-preview"><img src="${escapeHtml(href)}" alt="${escapeHtml(att.filename || att.attachment_id || 'Attachment image')}"></div>`;
      }
      if (kind === 'pdf') {
        return `<div class="attachment-preview"><iframe src="${escapeHtml(href)}" title="${escapeHtml(att.filename || att.attachment_id || 'PDF attachment')}"></iframe></div>`;
      }
      if (kind === 'video') {
        return `<div class="attachment-preview"><video src="${escapeHtml(href)}" controls></video></div>`;
      }
      if (kind === 'audio') {
        return `<div class="attachment-preview"><audio src="${escapeHtml(href)}" controls></audio></div>`;
      }
      return `<div class="attachment-preview"><div class="preview-note">Inline preview is not available for ${escapeHtml(kindLabel(kind))}. Use the attachment links above.</div></div>`;
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
        .message { break-inside: avoid; border-top: 1px solid #bbb; padding-top: 10px; margin-top: 12px; }
        .grid { display: grid; grid-template-columns: 120px 1fr; gap: 3px 10px; }
        .key { color: #555; font-family: Arial, sans-serif; }
        .body { white-space: pre-wrap; border: 1px solid #ccc; padding: 8px; margin-top: 8px; }
        .citation { font-family: Arial, sans-serif; border-left: 3px solid #555; padding-left: 8px; margin: 8px 0; }
        .attachment { break-inside: avoid; border: 1px solid #bbb; padding: 8px; margin: 8px 0; }
        .exhibit-cover { break-inside: avoid; border: 2px solid #222; padding: 14px; margin: 10px 0; text-align: center; }
        .exhibit-cover .exhibit-id { font: 700 28px/1.2 Arial, sans-serif; margin-bottom: 8px; }
        .exhibit-cover .exhibit-meta { font: 12px/1.35 Arial, sans-serif; text-align: left; display: inline-block; max-width: 100%; }
        .exhibit-image { display: block; max-width: 100%; max-height: 7in; margin: 8px 0; border: 1px solid #999; object-fit: contain; }
        .attachment-list { margin: 6px 0 0 18px; padding: 0; }
        .summary-table { width: 100%; max-width: 100%; border-collapse: collapse; margin-top: 12px; table-layout: fixed; }
        .summary-table th, .summary-table td { border: 1px solid #999; padding: 5px 6px; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }
        .summary-table th { font: 700 11px/1.25 Arial, sans-serif; background: #eee; text-align: left; }
        .summary-table td { font-size: 11px; }
        .summary-body { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
        .exhibit-reference { border-left: 3px solid #777; padding-left: 8px; margin: 10px 0; font: 11px/1.4 Arial, sans-serif; color: #333; }
        .attachment-page { break-before: page; page-break-before: always; page-break-inside: avoid; }
        .attachment-page:first-of-type { break-before: auto; page-break-before: auto; }
        body.timeline-print { font-size: 10.5px; }
        body.timeline-print h1 { font-size: 18px; }
        body.timeline-print .meta { font-size: 10px; }
        .timeline-card { break-inside: avoid; border: 1px solid #999; padding: 7px 8px; margin: 7px 0; }
        .timeline-card h2 { margin: 0 0 4px; border: 0; padding: 0; font-size: 12px; overflow-wrap: anywhere; }
        .timeline-card .details { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
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
    function printAttachmentReference(att, sourceMessage) {
      return `<li>${escapeHtml(att.exhibit_id || '')} | ${escapeHtml(att.attachment_id)} | ${escapeHtml(att.filename || att.saved_path || '[unnamed attachment]')} | source event ${escapeHtml(att.event_id)} | ${escapeHtml(formatDateTime(sourceMessage?.event_dt_utc || ''))}</li>`;
    }
    function printAttachmentHtml(att, sourceMessage, label, level = 'standard') {
      if (level === 'summary') {
        return `<ul class="attachment-list">${printAttachmentReference(att, sourceMessage)}</ul>`;
      }
      const imageHtml = isPrintableImage(att) && att.preferred_view_path
        ? `<img class="exhibit-image" src="${escapeHtml(att.preferred_view_path)}" alt="${escapeHtml(att.filename || att.attachment_id || 'Attachment image')}">`
        : '';
      const exhibitReference = att.exhibit_id || att.attachment_id || 'attachment exhibit';
      const exhibitReferenceHtml = att.exhibit_pdf_path
        ? `<p class="exhibit-reference">See exhibit ${escapeHtml(exhibitReference)} in the full packet appendix PDF.</p>`
        : `<p class="exhibit-reference">Exhibit rendering is unavailable for this attachment in the appendix packet.</p>`;
      const bodyContent = attachmentKind(att) === 'pdf' && level !== 'full'
        ? exhibitReferenceHtml
        : (imageHtml || exhibitReferenceHtml);
      const fullRows = level === 'full' ? `
            ${printDetailRow('exhibit PDF', att.exhibit_pdf_path)}
            ${printDetailRow('saved path', att.saved_path)}
            ${printDetailRow('converted path', att.converted_path)}
            ${printDetailRow('preferred view', att.preferred_view_path)}
            ${printDetailRow('EXIF raw', att.exif_dt_raw)}
      ` : '';
      return `
        <div class="attachment attachment-page">
          <h3>${escapeHtml(label || 'Attachment')} ${escapeHtml(att.exhibit_id || att.attachment_id || '')}</h3>
          ${exhibitCoverHtml(att, sourceMessage)}
          ${bodyContent}
          <div class="grid">
            ${printDetailRow('exhibit_id', att.exhibit_id)}
            ${printDetailRow('attachment_id', att.attachment_id)}
            ${printDetailRow('source event_id', att.event_id)}
            ${printDetailRow('timestamp', formatDateTime(sourceMessage?.event_dt_utc || ''))}
            ${printDetailRow('filename', att.filename || att.saved_path)}
            ${printDetailRow('MIME type', att.mime_type)}
            ${printDetailRow('size', formatBytes(att.size_bytes))}
            ${printDetailRow('EXIF UTC', formatDateTime(att.exif_dt_utc))}
            ${printDetailRow('sha256_hash', att.sha256_hash)}
            ${fullRows}
          </div>
          ${level === 'full' ? `
            <p class="path">Saved path: ${escapeHtml(att.saved_path || '')}</p>
            ${att.converted_path ? `<p class="path">Converted path: ${escapeHtml(att.converted_path)}</p>` : ''}
            ${att.preferred_view_path ? `<p class="path">Preferred file: <a href="${escapeHtml(att.preferred_view_path)}">${escapeHtml(att.preferred_view_path)}</a></p>` : ''}
            ${att.exhibit_pdf_path ? `<p class="path">Exhibit PDF: <a href="${escapeHtml(att.exhibit_pdf_path)}">${escapeHtml(att.exhibit_pdf_path)}</a></p>` : ''}
            ${att.bundle_saved_path ? `<p class="path">Original file: <a href="${escapeHtml(att.bundle_saved_path)}">${escapeHtml(att.bundle_saved_path)}</a></p>` : ''}
            ${att.bundle_converted_path ? `<p class="path">Converted JPG: <a href="${escapeHtml(att.bundle_converted_path)}">${escapeHtml(att.bundle_converted_path)}</a></p>` : ''}
          ` : ''}
        </div>`;
    }
    function printMessageHtml(message, options = {}) {
      const level = options.level || 'standard';
      const directAttachments = message.attachments || [];
      const nearbySource = options.includeNearby ? nearbyConversationAttachmentEntries(message, true) : [];
      const nearbyAttachments = level === 'full' ? nearbySource : nearbySource.slice(0, CONVERSATION_ATTACHMENT_LIMIT);
      const bodyHtml = level === 'summary'
        ? ''
        : `<div class="body">${escapeHtml(message.body_clean || '[no body]')}</div>`;
      const fullRows = level === 'full' ? `
            ${printDetailRow('source_record_id', message.source_record_id)}
            ${printDetailRow('thread_key', message.thread_key)}
            ${printDetailRow('recipients_json', message.recipients_json)}
      ` : '';
      return `
        <section class="message">
          <h2>${escapeHtml(message.event_id)} | ${escapeHtml(formatDateTime(message.event_dt_utc))}</h2>
          <div class="grid">
            ${printDetailRow('event_id', message.event_id)}
            ${printDetailRow('timestamp', formatDateTime(message.event_dt_utc))}
            ${printDetailRow('source', message.source)}
            ${printDetailRow('direction', message.direction)}
            ${printDetailRow('sender', message.sender)}
            ${printDetailRow('recipients', (message.recipients || []).join(', '))}
            ${printDetailRow('subject', message.subject)}
            ${fullRows}
          </div>
          ${bodyHtml}
          ${printAiEvidenceHtml(message)}
          ${directAttachments.length ? `<h3>Message Attachments (${directAttachments.length})</h3>${directAttachments.map(att => printAttachmentHtml(att, message, 'Message Attachment', level)).join('')}` : ''}
          ${options.includeNearby && nearbyAttachments.length ? `<h3>Nearby Conversation Attachments (${nearbyAttachments.length}${nearbySource.length > nearbyAttachments.length ? ` of ${nearbySource.length}` : ''}, +/- ${CONVERSATION_ATTACHMENT_WINDOW_HOURS}h)</h3>${nearbyAttachments.map(({ message: sourceMessage, attachment: att }) => printAttachmentHtml(att, sourceMessage, sourceMessage.event_id === message.event_id ? 'Current Message Attachment' : 'Nearby Attachment', level)).join('')}` : ''}
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
              <th style="width:18%;">Date</th>
              <th style="width:20%;">Sender</th>
              <th>Snippet</th>
              <th style="width:20%;">Exhibit</th>
            </tr>
          </thead>
          <tbody>
            ${messagesForPrint.map(message => `
              <tr>
                <td>${escapeHtml(formatDateTime(message.event_dt_utc))}<br>${escapeHtml(message.event_id)}</td>
                <td class="summary-body">${escapeHtml(message.display_sender || message.sender || '')}</td>
                <td class="summary-body">${escapeHtml(printSummarySnippet(message))}</td>
                <td class="summary-body">${escapeHtml(printSummaryExhibitText(message))}</td>
              </tr>`).join('')}
          </tbody>
        </table>`;
    }
    function printSummaryAppendix(messagesForPrint) {
      const rows = messagesForPrint
        .filter(message => (message.attachments || []).length)
        .map(message => `
          <tr>
            <td>${escapeHtml(formatDateTime(message.event_dt_utc))}<br>${escapeHtml(message.event_id)}</td>
            <td class="summary-body">${escapeHtml(printSummaryAttachmentText(message))}</td>
          </tr>`)
        .join('');
      if (!rows) return '';
      return `
        <h2>Attachment Appendix</h2>
        <table class="summary-table">
          <thead>
            <tr>
              <th style="width:24%;">Record</th>
              <th>Attachment References</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>`;
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
      return timeline
        .filter(row => allowedEvents.has(row.event_id))
        .slice()
        .sort((a, b) => String(a.timeline_dt_utc || '').localeCompare(String(b.timeline_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')) || String(a.attachment_id || '').localeCompare(String(b.attachment_id || '')));
    }
    function printTimelineTable(rows) {
      return `
        ${rows.map(row => {
          const message = byEvent.get(row.event_id) || {};
          const attachment = row.attachment_id ? byAttachment.get(row.attachment_id) : null;
          const recordText = [row.event_id, row.attachment_id, attachment?.exhibit_id].filter(Boolean).join(' | ');
          const details = [
            row.description || '',
            attachment ? `Attachment: ${attachment.filename || '[unnamed attachment]'}` : '',
            `Source: ${[row.source, row.direction].filter(Boolean).join(' / ')}`,
            `Sender: ${row.sender || message.display_sender || message.sender || ''}`,
            row.metadata_status ? `Metadata: ${row.metadata_status}` : '',
          ].filter(Boolean).join('\\n');
          return `
            <section class="timeline-card">
              <h2>${escapeHtml(formatDateTime(row.timeline_dt_utc))} | ${escapeHtml(row.source_label || 'timeline')}</h2>
              <p class="meta">${escapeHtml(recordText)}</p>
              <div class="details">${escapeHtml(details)}</div>
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
              ${includeFull ? '<th style="width:18%;">Printable File</th>' : ''}
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
                  ${includeFull ? `<td class="summary-body">${attachment.exhibit_pdf_path ? `<a href="${escapeHtml(attachment.exhibit_pdf_path)}">${escapeHtml(attachment.exhibit_pdf_path)}</a>` : ''}</td>` : ''}
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
      const level = els.printLevel.value || 'standard';
      if (activeView === 'attachments') {
        const attachment = byAttachment.get(activeAttachmentId);
        if (!attachment) return;
        const message = byEvent.get(attachment.event_id) || {};
        openPrintDocument(`Attachment ${attachment.attachment_id}`, `
          <h1>Attorney Review Exhibit - Attachment Detail</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: ${escapeHtml(level)}</p>
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
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: ${escapeHtml(level)}</p>
        ${printMessageHtml(message, { includeNearby: true, level })}
      `);
    }
    function printCurrentResults() {
      const level = els.printLevel.value || 'standard';
      if (activeView === 'timeline') {
        const rows = timelineResultRows();
        openPrintDocument('Attorney Review Timeline Results', `
          <h1>Attorney Review Exhibit - Chronological Timeline</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: ${escapeHtml(level)}</p>
          <p class="meta">${escapeHtml(activeFilterSummary())}</p>
          <p class="meta">${rows.length} timeline rows from ${filteredMessages().length} filtered messages</p>
          ${rows.length ? printTimelineTable(rows) : '<p>No timeline rows match the current filters.</p>'}
        `, { bodyClass: 'timeline-print' });
        return;
      }
      if (activeView === 'attachments') {
        const rows = filteredAttachmentEntries();
        openPrintDocument('Attorney Review Attachment Manifest', `
          <h1>Attorney Review Exhibit - Attachment Manifest</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: ${escapeHtml(level)}</p>
          <p class="meta">${escapeHtml(activeFilterSummary())}</p>
          <p class="meta">${rows.length} attachments from ${filteredMessages().length} filtered messages</p>
          ${rows.length ? printAttachmentManifestTable(rows, level) : '<p>No attachments match the current filters.</p>'}
        `);
        return;
      }
      const rows = filteredMessages().slice().sort((a, b) => String(a.event_dt_utc || '').localeCompare(String(b.event_dt_utc || '')) || String(a.event_id || '').localeCompare(String(b.event_id || '')));
      const attachmentCount = rows.reduce((count, message) => count + (message.attachments || []).length, 0);
      openPrintDocument('Attorney Review Search Results', `
        <h1>Attorney Review Exhibit - Chronological History</h1>
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: ${escapeHtml(level)}</p>
        <p class="meta">${escapeHtml(activeFilterSummary())}</p>
        <p class="meta">${rows.length} messages | ${attachmentCount} direct attachments</p>
        ${level === 'summary' ? printSummaryTable(rows) : rows.map(message => printMessageHtml(message, { level })).join('')}
      `);
    }
    function printSummaryResults() {
      if (activeView === 'attachments') {
        const rows = filteredAttachmentEntries();
        openPrintDocument('Attorney Review Attachment Summary', `
          <h1>Attorney Review Exhibit - Attachment Summary</h1>
          <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: summary</p>
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
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: summary</p>
        <p class="meta">${escapeHtml(activeFilterSummary())}</p>
        <p class="meta">${rows.length} ${escapeHtml(summaryLabel)}</p>
        ${rows.length ? printSummaryTable(rows) : '<p>No messages match the current filters.</p>'}
        ${rows.length ? printSummaryAppendix(rows) : ''}
      `);
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
    function printCurrentAttachments() {
      const level = els.printLevel.value || 'standard';
      const rows = activeView === 'attachments' ? filteredAttachmentEntries() : filteredMessageAttachments();
      openPrintDocument('Attorney Review Attachment Packet', `
        <h1>Attorney Review Exhibit - Attachment Packet</h1>
        <p class="meta">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))} | Integrity: ${escapeHtml(integrity.status)} | Detail: ${escapeHtml(level)}</p>
        <p class="meta">${escapeHtml(activeFilterSummary())}</p>
        <p class="meta">${rows.length} attachments from ${filteredMessages().length} filtered messages</p>
        ${rows.length ? rows.map(({ message, attachment }) => printAttachmentHtml(attachment, message, 'Attachment Exhibit', level)).join('') : '<p>No attachments match the current filters.</p>'}
      `);
    }
    function threadContextHtml(message) {
      const threadRows = byThread.get(message.thread_key || message.event_id) || [message];
      const index = threadRows.findIndex(row => row.event_id === message.event_id);
      const start = Math.max(0, index - 3);
      const end = Math.min(threadRows.length, index + 4);
      const rows = threadRows.slice(start, end);
      return `
        <details>
          <summary>Thread Context (${threadRows.length} records)</summary>
          <div class="thread-context">
            ${rows.map(row => `
              <article class="attachment">
                <div class="detail-grid">
                  ${detailRow(row.event_id === message.event_id ? 'current event_id' : 'event_id', row.event_id)}
                  ${detailRow('timestamp', formatDateTime(row.event_dt_utc))}
                  ${detailRow('direction', row.direction)}
                  ${detailRow('sender', row.display_sender || row.sender)}
                  ${detailRow('preview', row.body_preview || row.display_summary)}
                </div>
                ${row.event_id === message.event_id ? '<p class="muted">Current message</p>' : `<p><button type="button" data-select-context="${escapeHtml(row.event_id)}">View Message</button></p>`}
                <div class="meta tag-row context-tags">${renderBadges(row)}</div>
              </article>`).join('')}
          </div>
        </details>`;
    }
    function conversationAttachmentsHtml(message) {
      const nearbyRows = nearbyConversationAttachmentEntries(message, true);
      const rows = nearbyRows.slice(0, CONVERSATION_ATTACHMENT_LIMIT);
      const hiddenCount = Math.max(0, nearbyRows.length - rows.length);
      return `
        <details>
          <summary>Nearby Conversation Attachments (${rows.length}${hiddenCount ? ` of ${nearbyRows.length}` : ''}, +/- ${CONVERSATION_ATTACHMENT_WINDOW_HOURS}h)</summary>
          ${hiddenCount ? `<p class="muted">${hiddenCount} more nearby attachments are hidden here. Use Attachments mode for the full manifest.</p>` : ''}
          ${rows.length ? rows.map(({ message: sourceMessage, attachment: att }) => `
            <div class="attachment">
              <div class="detail-grid">
                ${detailRow('attachment_id', att.attachment_id)}
                ${detailRow('exhibit_id', att.exhibit_id)}
                ${detailRow('source event_id', att.event_id)}
                ${detailRow('timestamp', formatDateTime(sourceMessage.event_dt_utc))}
                ${detailRow('filename', att.filename || att.saved_path)}
                ${detailRow('MIME type', att.mime_type)}
                ${detailRow('size', formatBytes(att.size_bytes))}
                ${detailRow('EXIF UTC', formatDateTime(att.exif_dt_utc))}
              </div>
              <div class="row-actions">
                ${att.exhibit_pdf_path ? `<a href="${escapeHtml(att.exhibit_pdf_path)}" target="_blank" rel="noopener">Open exhibit PDF</a>` : ''}
                ${att.preferred_view_path ? `<a href="${escapeHtml(att.preferred_view_path)}" target="_blank" rel="noopener">Open preferred view</a>` : ''}
                ${att.bundle_saved_path ? `<a href="${escapeHtml(att.bundle_saved_path)}" target="_blank" rel="noopener">Open original</a>` : ''}
                ${att.bundle_converted_path ? `<a href="${escapeHtml(att.bundle_converted_path)}" target="_blank" rel="noopener">Open converted JPG</a>` : ''}
                ${sourceMessage.event_id === message.event_id ? '<span class="badge context">Current message</span>' : `<button type="button" data-select-context="${escapeHtml(sourceMessage.event_id)}">Select source message</button>`}
              </div>
              ${exhibitCoverHtml(att, sourceMessage)}
              ${attachmentPreviewHtml(att)}
            </div>`).join('') : '<p>No attachments found in this conversation.</p>'}
        </details>`;
    }
    function renderAttachmentDetail(att) {
      const message = byEvent.get(att.event_id) || {};
      els.detail.innerHTML = `
        <h2>${escapeHtml(att.attachment_id)} Attachment</h2>
        <p><button id="printDetail" type="button">Print Detail</button></p>
        ${bundleSummaryHtml()}
        <div class="detail-grid">
          ${detailRow('attachment_id', att.attachment_id)}
          ${detailRow('exhibit_id', att.exhibit_id)}
          ${detailRow('linked event_id', att.event_id)}
          ${detailRow('filename', att.filename)}
          ${detailRow('MIME type', att.mime_type)}
          ${detailRow('size', formatBytes(att.size_bytes))}
          ${detailRow('EXIF UTC', formatDateTime(att.exif_dt_utc))}
        </div>
        <p><button id="selectSourceMessage" type="button">Select source message</button></p>
        ${attachmentLinks(att)}
        ${exhibitCoverHtml(att, message)}
        ${attachmentPreviewHtml(att)}
        <details>
          <summary>Metadata</summary>
          <div class="detail-grid">
            ${detailRow('source file path', att.source_file)}
            ${detailRow('exhibit_id', att.exhibit_id)}
            ${linkRow('exhibit PDF', att.exhibit_pdf_path, att.exhibit_pdf_path)}
            ${detailRow('exhibit status', att.exhibit_status)}
            ${detailRow('exhibit warning', att.exhibit_warning)}
            ${detailRow('saved path', att.saved_path)}
            ${detailRow('converted path', att.converted_path)}
            ${detailRow('preferred view', att.preferred_view_path)}
            ${detailRow('size_bytes', att.size_bytes)}
            ${detailRow('sha256_hash', att.sha256_hash)}
            ${detailRow('EXIF raw', att.exif_dt_raw)}
            ${detailRow('linked message event_id', message.event_id)}
            ${detailRow('linked message timestamp', formatDateTime(message.event_dt_utc))}
            ${detailRow('linked message source', message.source)}
            ${detailRow('linked message direction', message.direction)}
            ${detailRow('linked message sender', message.sender)}
            ${detailRow('linked message recipients', (message.recipients || []).join(', '))}
            ${detailRow('linked message subject', message.subject)}
          </div>
        </details>
      `;
      document.getElementById('selectSourceMessage').addEventListener('click', () => {
        activeEventId = att.event_id;
        activeView = 'messages';
        render();
      });
      document.getElementById('printDetail').addEventListener('click', printSelectedDetail);
    }
    function renderDetail() {
      if (activeView === 'attachments') {
        const visibleAttachments = filteredAttachments();
        const attachment = visibleAttachments.find(att => att.attachment_id === activeAttachmentId) || visibleAttachments[0];
        if (!attachment) {
          els.detail.innerHTML = '<h2>No attachments</h2>';
          return;
        }
        activeAttachmentId = attachment.attachment_id;
        activeEventId = attachment.event_id;
        renderAttachmentDetail(attachment);
        return;
      }
      const visibleMessages = filteredMessages();
      const message = activeView === 'timeline'
        ? (byEvent.get(activeEventId) || visibleMessages[0])
        : (visibleMessages.find(row => row.event_id === activeEventId) || visibleMessages[0]);
      if (!message) {
        els.detail.innerHTML = '<h2>No messages</h2>';
        return;
      }
      activeEventId = message.event_id;
      const attachmentsHtml = (message.attachments || []).map(att => `
        <div class="attachment">
          <div class="detail-grid">
            ${detailRow('attachment_id', att.attachment_id)}
            ${detailRow('exhibit_id', att.exhibit_id)}
            ${detailRow('linked event_id', att.event_id)}
            ${detailRow('filename', att.filename)}
            ${detailRow('MIME type', att.mime_type)}
            ${detailRow('size', formatBytes(att.size_bytes))}
            ${detailRow('EXIF UTC', formatDateTime(att.exif_dt_utc))}
          </div>
          ${attachmentLinks(att)}
          ${exhibitCoverHtml(att, message)}
          ${attachmentPreviewHtml(att)}
        </div>`).join('') || '<p>No linked attachments.</p>';

      els.detail.innerHTML = `
        <h2>${escapeHtml(message.event_id)} Detail</h2>
        <p><button id="printDetail" type="button">Print Detail</button></p>
        ${bundleSummaryHtml()}
        <div class="detail-grid">
          ${detailRow('event_id', message.event_id)}
          ${detailRow('timestamp', formatDateTime(message.event_dt_utc))}
          ${detailRow('source', message.source)}
          ${detailRow('direction', message.direction)}
          ${detailRow('sender', message.sender)}
          ${detailRow('recipients', (message.recipients || []).join(', '))}
          ${detailRow('subject', message.subject)}
        </div>
        <h2 style="margin-top:14px;">Body</h2>
        <div class="body-box">${escapeHtml(message.body_clean || '[no body]')}</div>
        ${aiEvidenceHtml(message)}
        <details>
          <summary>Citation</summary>
          <textarea id="citationText" readonly rows="3">${escapeHtml(citation(message))}</textarea>
          <p><button id="copyCitation" type="button">Copy citation</button></p>
        </details>
        <h2>Direct Message Attachments</h2>
        ${attachmentsHtml}
        ${conversationAttachmentsHtml(message)}
        <details>
          <summary>Evidence Integrity</summary>
          <div class="detail-grid">
            ${detailRow('event_id', message.event_id)}
            ${detailRow('content_hash', message.content_hash)}
            ${detailRow('source file', message.source_file)}
          </div>
        </details>
        <details>
          <summary>Metadata</summary>
          <div class="detail-grid">
            ${detailRow('source_record_id', message.source_record_id)}
            ${detailRow('thread_key', message.thread_key)}
            ${detailRow('recipients_json', message.recipients_json)}
          </div>
        </details>
        ${threadContextHtml(message)}
        ${(message.attachments || []).length ? `
        <details>
          <summary>Attachment Metadata</summary>
          ${(message.attachments || []).map(att => `
            <div class="attachment">
              <div class="detail-grid">
                ${detailRow('attachment_id', att.attachment_id)}
                ${detailRow('exhibit_id', att.exhibit_id)}
                ${linkRow('exhibit PDF', att.exhibit_pdf_path, att.exhibit_pdf_path)}
                ${detailRow('exhibit status', att.exhibit_status)}
                ${detailRow('exhibit warning', att.exhibit_warning)}
                ${detailRow('linked event_id', att.event_id)}
                ${detailRow('source file path', att.source_file)}
                ${detailRow('saved path', att.saved_path)}
                ${detailRow('converted path', att.converted_path)}
                ${detailRow('MIME type', att.mime_type)}
                ${detailRow('size_bytes', att.size_bytes)}
                ${detailRow('hash', att.sha256_hash)}
                ${detailRow('EXIF raw', att.exif_dt_raw)}
                ${detailRow('EXIF UTC', formatDateTime(att.exif_dt_utc))}
              </div>
            </div>`).join('')}
        </details>` : ''}
      `;
      document.getElementById('copyCitation').addEventListener('click', copyCitation);
      document.getElementById('printDetail').addEventListener('click', printSelectedDetail);
      els.detail.querySelectorAll('[data-select-context]').forEach(button => button.addEventListener('click', () => {
        activeEventId = button.dataset.selectContext;
        activeView = 'messages';
        render();
      }));
    }
    function render() {
      els.messagesTab.setAttribute('aria-selected', activeView === 'messages' ? 'true' : 'false');
      els.timelineTab.setAttribute('aria-selected', activeView === 'timeline' ? 'true' : 'false');
      els.attachmentsTab.setAttribute('aria-selected', activeView === 'attachments' ? 'true' : 'false');
      updateFilterToggle();
      renderList();
      renderDetail();
    }
    [els.search, els.source, els.direction, els.attachment, els.start, els.end, els.aiTag].forEach(el => el.addEventListener('input', render));
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
      render();
    });
    els.messagesTab.addEventListener('click', () => { activeView = 'messages'; render(); });
    els.timelineTab.addEventListener('click', () => { activeView = 'timeline'; render(); });
    els.attachmentsTab.addEventListener('click', () => { activeView = 'attachments'; render(); });
    els.printCurrent.addEventListener('click', () => { els.printMenu.open = false; printSelectedDetail(); });
    els.printResults.addEventListener('click', () => { els.printMenu.open = false; printCurrentResults(); });
    els.printSummary.addEventListener('click', () => { els.printMenu.open = false; printSummaryResults(); });
    els.printAttachments.addEventListener('click', () => { els.printMenu.open = false; printCurrentAttachments(); });
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
- exhibits/: court-ready derivative PDFs with attachment cover pages.
- exhibits/attachment_packet.pdf: one binder-ready PDF containing all attachment exhibit PDFs.

Citation format:
E-004123 | 2025-05-01T14:30:00Z | SMS | excerpt...

Caveats:
- The SQLite database and deterministic exports are the source of truth.
- Missing metadata is shown explicitly where known.
- Converted JPG files are preferred for viewing HEIC images, but original saved paths are still exposed.
- Attachment exhibit PDFs prepend a metadata cover page. PDFs and images are embedded when local tooling can read them; unsupported formats receive a cover-only exhibit page.
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
    exhibit_summary = build_exhibit_pdfs(output_dir, message_exports, attachment_exports)
    ai_triage = load_ai_triage(output_dir)
    apply_ai_triage(message_exports, ai_triage)
    integrity = validate(db_path, output_dir, message_exports, attachment_exports, timeline_rows)
    integrity["checks"]["exhibit_pdfs_generated_without_errors"] = not exhibit_summary.get(
        "exhibit_generation_warnings"
    )
    integrity["details"]["exhibit_generation_warnings"] = exhibit_summary.get("exhibit_generation_warnings", [])
    integrity["exhibits"] = exhibit_summary
    if exhibit_summary.get("exhibit_generation_warnings"):
        integrity["status"] = "review_warnings"
    manifest = build_manifest(
        db_path,
        output_dir,
        message_exports,
        attachment_exports,
        timeline_rows,
        integrity,
        exhibit_summary,
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
            exhibit_summary,
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
