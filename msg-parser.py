#!/usr/bin/env python3
"""
Ingest communications from:
  1) Google Takeout Gmail MBOX
  2) SMS Backup & Restore XML

Outputs:
  - SQLite DB with normalized messages + attachments
  - Extracted attachment files on disk

Usage example:
  python ingest_communications.py \
    --db communications.sqlite \
    --attachments-dir extracted_attachments \
    --mbox path/to/mail.mbox \
    --smsxml path/to/sms_backup.xml \
    --me-id "joshua.caleb.wagner@gmail.com" \
    --me-id "+1574XXXXXXX" \
    --other-id "krystlemwagner@gmail.com" \
    --other-id "+1574YYYYYYY"

Notes:
  - Run this on a COPY of your source files.
  - For a fully reproducible run, start with an empty DB and empty attachments dir.
  - MMS parsing in SMS Backup & Restore can vary somewhat by version/device.
    This script handles the common structure: text/plain parts as body,
    non-text parts as attachment records.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import mailbox
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
import mimetypes
import traceback

from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Iterable, Optional, Tuple, List

# ------------------------------------------------------------
# Configuration / heuristics
# ------------------------------------------------------------

BATCH_SIZE = 500

RE_QUOTED_REPLY_MARKERS = [
    re.compile(r"(?im)^\s*On .+ wrote:\s*$"),
    re.compile(r"(?im)^\s*On\b(?:.*\n)*?.*?wrote:\s*$"),
    re.compile(r"(?im)^\s*From:\s+.+$"),
    re.compile(r"(?im)^\s*Sent:\s+.+$"),
    re.compile(r"(?im)^\s*To:\s+.+$"),
    re.compile(r"(?im)^\s*Subject:\s+.+$"),
    re.compile(r"(?im)^\s*-{2,}\s*Original Message\s*-{2,}\s*$"),
    re.compile(r"(?im)^\s*Begin forwarded message:\s*$"),
]

RE_HTML_TAGS = re.compile(r"<[^>]+>")
RE_MULTISPACE = re.compile(r"[ \t]+")
RE_MULTIBLANK = re.compile(r"\n{3,}")
RE_CID_REFERENCE = re.compile(r"cid:([^\"' >]+)", re.IGNORECASE)
RE_HTML_QUOTE_MARKERS = [
    re.compile(r'(?is)<div[^>]+class=["\'][^"\']*gmail_quote[^"\']*["\'][^>]*>'),
    re.compile(r'(?is)<div[^>]+class=["\'][^"\']*gmail_attr[^"\']*["\'][^>]*>'),
    re.compile(r"(?is)<blockquote\b"),
    re.compile(r"(?is)-{2,}\s*Original Message\s*-{2,}"),
    re.compile(r"(?is)Begin forwarded message:"),
]

TEXT_MIME_TYPES = {
    "text/plain",
    "text/html",
}

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, file=sys.stderr)

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def to_safe_str(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return str(value)

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def decode_mime_header(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value

def parse_email_addresses(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [addr.strip().lower() for _, addr in getaddresses([value]) if addr]

def normalize_identity(value: Optional[str]) -> str:
    """
    Normalize email/phone-ish identifiers enough for comparison.
    """
    if not value:
        return ""
    v = value.strip().lower()

    # crude phone normalization
    digits = re.sub(r"\D+", "", v)
    if len(digits) >= 10:
        # last 10 digits heuristic for US numbers
        return digits[-10:]

    return v

def decode_bytes_payload(payload: bytes, charset: Optional[str]) -> str:
    if payload is None:
        return ""
    if charset:
        try:
            return payload.decode(charset, errors="replace")
        except Exception:
            pass
    # fallback guesses
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return payload.decode(enc, errors="replace")
        except Exception:
            continue
    return payload.decode("utf-8", errors="replace")

def strip_html_to_text(html_text: str) -> str:
    """
    Minimal HTML -> readable text.
    """
    if not html_text:
        return ""
    text = html_text
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    text = RE_HTML_TAGS.sub("", text)
    text = html.unescape(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = RE_MULTISPACE.sub(" ", text)
    text = RE_MULTIBLANK.sub("\n\n", text)
    return text.strip()

def strip_quoted_reply(text: str) -> str:
    """
    Conservative heuristic:
    keep everything above the first common quoted-reply marker.
    If no marker found, return original text.
    """
    if not text:
        return ""

    text = text.replace("\r\n", "\n").replace("\r", "\n")

    cut_positions = []
    for rx in RE_QUOTED_REPLY_MARKERS:
        m = rx.search(text)
        if m:
            cut_positions.append(m.start())

    if cut_positions:
        cut = min(cut_positions)
        text = text[:cut]

    text = RE_MULTIBLANK.sub("\n\n", text).strip()
    return text

def strip_quoted_reply_html(html_text: str) -> str:
    """
    Conservative HTML variant of strip_quoted_reply().
    Keep only the leading fragment before common quoted-thread wrappers.
    """
    if not html_text:
        return ""

    cut_positions = []
    for rx in RE_HTML_QUOTE_MARKERS:
        m = rx.search(html_text)
        if m:
            cut_positions.append(m.start())

    if cut_positions:
        return html_text[:min(cut_positions)]
    return html_text

def normalize_content_id(value: Optional[str]) -> str:
    if not value:
        return ""
    return value.strip().strip("<>").lower()

def extract_cid_references(html_text: str) -> set[str]:
    if not html_text:
        return set()
    return {match.group(1).strip().strip("<>").lower() for match in RE_CID_REFERENCE.finditer(html_text)}

def get_email_html_body(msg: Message) -> str:
    """
    Collect non-attachment HTML body parts in message order.
    """
    if msg.is_multipart():
        html_parts = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if (part.get_content_disposition() or "").lower() == "attachment":
                continue
            if (part.get_content_type() or "").lower() != "text/html":
                continue
            payload = part.get_payload(decode=True) or b""
            html_parts.append(decode_bytes_payload(payload, part.get_content_charset()))
        return "\n\n".join(part.strip() for part in html_parts if part.strip()).strip()

    payload = msg.get_payload(decode=True) or b""
    if (msg.get_content_type() or "").lower() != "text/html":
        return ""
    return decode_bytes_payload(payload, msg.get_content_charset()).strip()

def referenced_inline_content_ids(msg: Message) -> tuple[set[str], set[str]]:
    html_text = get_email_html_body(msg)
    if not html_text:
        return set(), set()
    all_refs = extract_cid_references(html_text)
    active_refs = extract_cid_references(strip_quoted_reply_html(html_text))
    return all_refs, active_refs

def dt_to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def epoch_ms_to_iso(ms: str) -> str:
    """
    SMS Backup & Restore typically stores epoch ms.
    """
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
        return dt_to_iso(dt)
    except Exception:
        return ""

def safe_filename(name: str, fallback: str) -> str:
    name = (name or "").strip()
    if not name:
        name = fallback
    name = re.sub(r"[^\w.\- ]+", "_", name)
    name = name.strip(" .")
    return name[:180] or fallback

# ------------------------------------------------------------
# SQLite schema + insert helpers
# ------------------------------------------------------------

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS messages (
    event_id            TEXT PRIMARY KEY,
    source              TEXT NOT NULL,           -- EMAIL / SMS / MMS
    source_record_id    TEXT,                    -- message-id, sms id, mms id, etc.
    thread_key          TEXT,
    event_dt_utc        TEXT NOT NULL,
    direction           TEXT,                    -- inbound / outbound / unknown
    sender              TEXT,
    recipients_json     TEXT,                    -- JSON array
    subject             TEXT,
    body_raw            TEXT,
    body_clean          TEXT,
    source_file         TEXT,
    content_hash        TEXT
);

CREATE TABLE IF NOT EXISTS attachments (
    attachment_id       TEXT PRIMARY KEY,
    event_id            TEXT NOT NULL,
    filename            TEXT,
    mime_type           TEXT,
    exif_dt_raw         TEXT,
    exif_dt_utc         TEXT,
    saved_path          TEXT,
    converted_path      TEXT,
    size_bytes          INTEGER,
    source_file         TEXT,
    sha256_hash         TEXT,
    FOREIGN KEY(event_id) REFERENCES messages(event_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_dt ON messages(event_dt_utc);
CREATE INDEX IF NOT EXISTS idx_messages_source ON messages(source);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_key);
CREATE INDEX IF NOT EXISTS idx_attachments_event ON attachments(event_id);
"""

class IdGenerator:
    def __init__(self) -> None:
        self.event_counter = 0
        self.attachment_counter = 0

    def next_event_id(self) -> str:
        self.event_counter += 1
        return f"E-{self.event_counter:06d}"

    def next_attachment_id(self) -> str:
        self.attachment_counter += 1
        return f"A-{self.attachment_counter:06d}"

class Inserter:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.msg_batch = []
        self.att_batch = []

    def add_message(self, row: tuple) -> None:
        self.msg_batch.append(row)
        self._flush_if_needed()

    def add_attachment(self, row: tuple) -> None:
        self.att_batch.append(row)
        self._flush_if_needed()

    def _flush_if_needed(self) -> None:
        if len(self.msg_batch) + len(self.att_batch) >= BATCH_SIZE:
            self.flush()

    def flush(self) -> None:
        if not self.msg_batch and not self.att_batch:
            return

        with self.conn:
            if self.msg_batch:
                self.conn.executemany("""
                    INSERT INTO messages (
                        event_id, source, source_record_id, thread_key, event_dt_utc,
                        direction, sender, recipients_json, subject,
                        body_raw, body_clean, source_file, content_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, self.msg_batch)
                self.msg_batch.clear()

            if self.att_batch:
                self.conn.executemany("""
                    INSERT INTO attachments (
                        attachment_id, event_id, filename, mime_type,
                        saved_path, size_bytes, source_file, sha256_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, self.att_batch)
                self.att_batch.clear()

# ------------------------------------------------------------
# Direction / identity helpers
# ------------------------------------------------------------

def classify_direction(sender: str,
                       recipients: Iterable[str],
                       me_ids: set[str],
                       other_ids: set[str]) -> str:
    s = normalize_identity(sender)
    rs = {normalize_identity(r) for r in recipients if r}

    if s in me_ids:
        return "outbound"
    if s in other_ids:
        return "inbound"

    if rs & me_ids and s and s not in me_ids:
        return "inbound"
    if rs & other_ids and s and s in me_ids:
        return "outbound"

    return "unknown"

# ------------------------------------------------------------
# Email parsing
# ------------------------------------------------------------

def get_email_text_body(msg: Message) -> str:
    """
    Prefer text/plain. Fall back to text/html if needed.
    """
    if msg.is_multipart():
        plain_parts = []
        html_parts = []

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue

            disposition = (part.get_content_disposition() or "").lower()
            if disposition == "attachment":
                continue

            ctype = (part.get_content_type() or "").lower()
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset()

            if ctype == "text/plain":
                plain_parts.append(decode_bytes_payload(payload, charset))
            elif ctype == "text/html":
                html_parts.append(decode_bytes_payload(payload, charset))

        if plain_parts:
            return "\n\n".join(p.strip() for p in plain_parts if p.strip()).strip()
        if html_parts:
            return "\n\n".join(strip_html_to_text(p) for p in html_parts if p.strip()).strip()
        return ""

    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset()
    ctype = (msg.get_content_type() or "").lower()

    if ctype == "text/html":
        return strip_html_to_text(decode_bytes_payload(payload, charset))
    return decode_bytes_payload(payload, charset).strip()

def save_email_attachments(msg: Message,
                           event_id: str,
                           source_file: str,
                           attachments_dir: Path,
                           ids: IdGenerator,
                           inserter: Inserter) -> None:
    referenced_cids, active_cids = referenced_inline_content_ids(msg)

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        disposition = (part.get_content_disposition() or "").lower()
        filename = decode_mime_header(part.get_filename())
        content_id = normalize_content_id(part.get("Content-ID"))

        if disposition != "attachment" and not filename:
            continue

        payload = part.get_payload(decode=True) or b""
        mime_type = (part.get_content_type() or "").lower()

        # Gmail-style reply chains often carry prior inline CID images forward
        # inside quoted HTML. Skip those repeated parts unless the current
        # message body still references them before the quoted history starts.
        if (
            content_id
            and mime_type.startswith("image/")
            and content_id in referenced_cids
            and content_id not in active_cids
        ):
            continue

        attachment_id = ids.next_attachment_id()

        ext = ""
        if filename and "." in filename:
            ext = "." + filename.split(".")[-1]
        filename_safe = safe_filename(filename, f"{attachment_id}{ext}")
        rel_path = Path(event_id) / filename_safe
        full_dir = attachments_dir / event_id
        ensure_dir(full_dir)
        full_path = full_dir / filename_safe
        file_hash = sha256_bytes(payload)

        with open(full_path, "wb") as f:
            f.write(payload)

        inserter.add_attachment((
            attachment_id,
            event_id,
            filename,
            mime_type,
            str(rel_path),
            len(payload),
            source_file,
            file_hash
        ))

def ingest_mbox(mbox_path: Path,
                conn: sqlite3.Connection,
                attachments_dir: Path,
                ids: IdGenerator,
                me_ids: set[str],
                other_ids: set[str]) -> None:
    log(f"Ingesting MBOX: {mbox_path}")
    inserter = Inserter(conn)

    mbox = mailbox.mbox(str(mbox_path))

    for idx, msg in enumerate(mbox, start=1):
        try:
            raw_from = decode_mime_header(msg.get("From", ""))
            sender_addresses = parse_email_addresses(raw_from)
            sender = sender_addresses[0] if sender_addresses else raw_from.strip()

            recipients = []
            recipients += parse_email_addresses(decode_mime_header(msg.get("To", "")))
            recipients += parse_email_addresses(decode_mime_header(msg.get("Cc", "")))

            subject = decode_mime_header(msg.get("Subject", ""))
            message_id = decode_mime_header(msg.get("Message-ID", "")).strip()
            in_reply_to = decode_mime_header(msg.get("In-Reply-To", "")).strip()
            thread_key = in_reply_to or message_id or subject

            dt_raw = msg.get("Date", "")
            try:
                dt = parsedate_to_datetime(dt_raw)
                event_dt_utc = dt_to_iso(dt)
            except Exception:
                event_dt_utc = ""

            body_raw = get_email_text_body(msg)
            body_clean = strip_quoted_reply(body_raw)

            direction = classify_direction(sender, recipients, me_ids, other_ids)
            event_id = ids.next_event_id()
            content_hash = sha256_text(
                "|".join([
                    to_safe_str("EMAIL"),
                    to_safe_str(message_id),
                    to_safe_str(event_dt_utc),
                    to_safe_str(sender),
                    to_safe_str(json.dumps(recipients, ensure_ascii=False)),
                    to_safe_str(subject),
                    to_safe_str(body_clean),
                ])
            )

            inserter.add_message((
                event_id,
                "EMAIL",
                message_id or f"mbox-index:{idx}",
                thread_key,
                event_dt_utc,
                direction,
                sender,
                json.dumps(recipients, ensure_ascii=False),
                subject,
                body_raw,
                body_clean,
                str(mbox_path),
                content_hash,
            ))

            save_email_attachments(msg, event_id, str(mbox_path), attachments_dir, ids, inserter)

            if idx % 100 == 0:
                log(f"  processed {idx} email messages...")

        except Exception as e:
            log(f"  WARNING: failed to process email #{idx}: {e}")

    inserter.flush()

# ------------------------------------------------------------
# SMS/MMS parsing
# ------------------------------------------------------------

def mms_extract_addresses(mms_elem: ET.Element) -> List[Tuple[str, str]]:
    """
    Returns list of (type, address); common SMS Backup & Restore form:
      <addrs>
        <addr address="+123..." type="137" />
      </addrs>

    Observed types in many Android MMS dumps:
      137 = From
      151 = To
    """
    out = []
    addrs = mms_elem.find("addrs")
    if addrs is None:
        return out

    for addr in addrs.findall("addr"):
        a = addr.attrib.get("address", "")
        t = addr.attrib.get("type", "")
        out.append((t, a))
    return out

def resolve_mms_filename(filename_raw, mime_type, attachment_id):
    if filename_raw:
        f = filename_raw.strip()
        if f and f.lower() not in {"null", "none", "undefined"}:
            return f

    ext = mimetypes.guess_extension(mime_type) or ".bin"
    return f"{attachment_id}{ext}"

def mms_extract_parts(mms_elem):
    body_fragments = []
    attachments = []

    parts = mms_elem.find("parts")
    if parts is None:
        return "", attachments

    for part in parts.findall("part"):
        ct = (part.attrib.get("ct") or "").lower()
        text = part.attrib.get("text", "")
        data = part.attrib.get("data", "")
        filename_raw = part.attrib.get("cl", "") or part.attrib.get("name", "")

        # ✅ Normalize garbage values early
        if data and data.strip().lower() in {"null", "none", "undefined"}:
            data = ""

        if ct == "application/smil":
            # ✅ skip MMS layout instructions
            continue

        # ✅ TEXT BODY
        if ct == "text/plain":
            if text:
                body_fragments.append(text)
            elif data:
                try:
                    decoded = base64.b64decode(data, validate=True)
                    body_fragments.append(decoded.decode("utf-8", errors="replace"))
                except Exception:
                    # optional debug
                    print("DEBUG: failed to decode MMS text part")
            continue

        # ✅ ATTACHMENTS
        payload = b""

        if data:
            try:
                payload = base64.b64decode(data, validate=True)
            except Exception:
                # optional debug
                print("DEBUG: invalid base64 for attachment:", ct)

        # ✅ Enforce bytes type
        if not isinstance(payload, bytes):
            payload = b""

        attachments.append({
            "filename_raw": filename_raw,
            "mime_type": ct,
            "payload": payload
        })

    body = "\n\n".join(fragment.strip() for fragment in body_fragments if fragment.strip())

    return body, attachments

def save_mms_attachments(attachments: List[dict],
                         event_id: str,
                         source_file: str,
                         attachments_dir: Path,
                         ids: IdGenerator,
                         inserter: Inserter) -> None:
    for idx, attachment in enumerate(attachments, start=1):
        filename_raw = attachment.get("filename_raw", "")
        mime_type = (attachment.get("mime_type") or "").lower()
        payload = attachment.get("payload", b"")

        # Debug weird payloads BEFORE normalization
        if not isinstance(payload, (bytes, bytearray)):
            print("\n=== DEBUG MMS ATTACHMENT PAYLOAD TYPE ERROR ===")
            print("event_id     :", event_id)
            print("source_file  :", source_file)
            print("index        :", idx)
            print("filename_raw :", repr(filename_raw))
            print("mime_type    :", repr(mime_type))
            print("payload type :", type(payload))
            print("payload repr :", repr(payload))
            print("==============================================\n")

            # Normalize conservatively so we can keep going
            if isinstance(payload, str):
                if payload.strip().lower() in {"", "null", "none", "undefined"}:
                    payload = b""
                else:
                    payload = payload.encode("utf-8", errors="replace")
            else:
                payload = b""

        # Skip empty payloads
        if not payload:
            continue

        attachment_id = ids.next_attachment_id()

        guessed_ext = ""
        if "/" in mime_type:
            subtype = mime_type.split("/", 1)[1]
            if subtype:
                guessed_ext = "." + re.sub(r"[^\w\-]+", "_", subtype)

        filename = resolve_mms_filename(
            filename_raw,
            mime_type,
            attachment_id
        )

        filename_safe = safe_filename(filename, f"{attachment_id}{guessed_ext}")
        rel_path = Path(event_id) / filename_safe
        full_dir = attachments_dir / event_id
        ensure_dir(full_dir)
        full_path = full_dir / filename_safe

        file_hash = sha256_bytes(payload)

        with open(full_path, "wb") as f:
            f.write(payload)

        inserter.add_attachment((
            attachment_id,
            event_id,
            filename,
            mime_type,
            str(rel_path),
            len(payload),
            source_file,
            file_hash
        ))

def ingest_sms_xml(xml_path: Path,
                   conn: sqlite3.Connection,
                   attachments_dir: Path,
                   ids: IdGenerator,
                   me_ids: set[str],
                   other_ids: set[str]) -> None:
    log(f"Ingesting SMS/MMS XML (streaming): {xml_path}")
    inserter = Inserter(conn)

    # Only end events so we can process full <sms> / <mms> elements and clear them.
    context = ET.iterparse(str(xml_path), events=("end",))

    sms_count = 0
    mms_count = 0

    for event, elem in context:
        tag = elem.tag.lower()

        try:
            if tag == "sms":
                sms_id = elem.attrib.get("protocol", "") + ":" + elem.attrib.get("date", "") + ":" + elem.attrib.get("address", "")
                event_dt_utc = epoch_ms_to_iso(elem.attrib.get("date", ""))

                address = elem.attrib.get("address", "")  # other party in many exports
                body_raw = elem.attrib.get("body", "") or ""
                body_clean = body_raw.strip()

                msg_type = elem.attrib.get("type", "")
                # Common Android SMS type:
                # 1=inbox (received), 2=sent
                if msg_type == "1":
                    direction = "inbound"
                    sender = address
                    recipients = [next(iter(me_ids), "me")]
                elif msg_type == "2":
                    direction = "outbound"
                    sender = next(iter(me_ids), "me")
                    recipients = [address]
                else:
                    sender = address
                    recipients = []
                    direction = classify_direction(sender, recipients, me_ids, other_ids)

                event_id = ids.next_event_id()
                content_hash = sha256_text(
                    "|".join([
                        to_safe_str("SMS"),
                        to_safe_str(sms_id),
                        to_safe_str(event_dt_utc),
                        to_safe_str(sender),
                        to_safe_str(json.dumps(recipients, ensure_ascii=False)),
                        to_safe_str(body_clean),
                    ])
                )

                inserter.add_message((
                    event_id,
                    "SMS",
                    sms_id,
                    address,
                    event_dt_utc,
                    direction,
                    sender,
                    json.dumps(recipients, ensure_ascii=False),
                    "",
                    body_raw,
                    body_clean,
                    str(xml_path),
                    content_hash,
                ))

                sms_count += 1
                if sms_count % 1000 == 0:
                    log(f"  processed {sms_count} SMS messages...")

                elem.clear()

            elif tag == "mms":
                mms_id = elem.attrib.get("m_id", "") or elem.attrib.get("date", "")
                event_dt_utc = epoch_ms_to_iso(elem.attrib.get("date", ""))

                addrs = mms_extract_addresses(elem)
                from_addrs = [a for t, a in addrs if t == "137"]
                to_addrs = [a for t, a in addrs if t == "151"]

                sender = from_addrs[0] if from_addrs else ""
                recipients = to_addrs

                body_raw, attachments = mms_extract_parts(elem)
                body_clean = body_raw.strip()

                direction = classify_direction(sender, recipients, me_ids, other_ids)
                if direction == "unknown":
                    # fallback from message box if available
                    msg_box = elem.attrib.get("msg_box", "")
                    if msg_box == "1":
                        direction = "inbound"
                    elif msg_box == "2":
                        direction = "outbound"

                event_id = ids.next_event_id()
                content_hash = sha256_text(
                    "|".join([
                        to_safe_str("MMS"),
                        to_safe_str(mms_id),
                        to_safe_str(event_dt_utc),
                        to_safe_str(sender),
                        to_safe_str(json.dumps(recipients, ensure_ascii=False)),
                        to_safe_str(body_clean),
                    ])
                )

                inserter.add_message((
                    event_id,
                    "MMS",
                    mms_id,
                    sender or (recipients[0] if recipients else ""),
                    event_dt_utc,
                    direction,
                    sender,
                    json.dumps(recipients, ensure_ascii=False),
                    "",
                    body_raw,
                    body_clean,
                    str(xml_path),
                    content_hash,
                ))

                if attachments:
                    save_mms_attachments(attachments, event_id, str(xml_path), attachments_dir, ids, inserter)

                mms_count += 1
                if mms_count % 1000 == 0:
                    log(f"  processed {mms_count} MMS messages...")

                elem.clear()

        except Exception as e:
            line = getattr(elem, "sourceline", "unknown")
            log(f"  WARNING: failed to process <{tag}> element at line {line}: {e}")

            print("\n=== FULL TRACEBACK ===")
            traceback.print_exc()
            print("======================\n")

            elem.clear()

    inserter.flush()
    log(f"Finished XML ingest: {sms_count} SMS, {mms_count} MMS")

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ingest MBOX + SMS Backup & Restore XML into SQLite")
    p.add_argument("--db", required=True, help="SQLite DB path")
    p.add_argument("--attachments-dir", required=True, help="Directory for extracted attachments")
    p.add_argument("--mbox", help="Path to Google Takeout MBOX")
    p.add_argument("--smsxml", help="Path to SMS Backup & Restore XML")
    p.add_argument("--me-id", action="append", default=[], help="Your email/phone identifier (repeatable)")
    p.add_argument("--other-id", action="append", default=[], help="Other party email/phone identifier (repeatable)")
    return p.parse_args()

def main() -> int:
    args = parse_args()

    db_path = Path(args.db)
    attachments_dir = Path(args.attachments_dir)
    ensure_dir(attachments_dir)

    me_ids = {normalize_identity(x) for x in args.me_id if x}
    other_ids = {normalize_identity(x) for x in args.other_id if x}

    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_SQL)

    ids = IdGenerator()

    if args.mbox:
        ingest_mbox(Path(args.mbox), conn, attachments_dir, ids, me_ids, other_ids)

    if args.smsxml:
        ingest_sms_xml(Path(args.smsxml), conn, attachments_dir, ids, me_ids, other_ids)

    conn.close()
    log("Done.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
