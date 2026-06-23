#!/usr/bin/env python3
"""
Optional AI triage layer for the offline attorney review bundle.

This script keeps deterministic exports as the source of truth. It builds small,
rule-selected candidate sets before any AI call, stores a cache keyed by record
identity and prompt/schema metadata, and exports cautious, citation-backed
indicator files for the offline UI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import textwrap
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROMPT_VERSION = "phase-b-triage-v1"
CATEGORY_SCHEMA_VERSION = "phase-b-categories-v1"
DRY_RUN_MODEL = "offline-dry-run"
DEFAULT_NON_RESPONSE_WINDOWS_HOURS = (48, 168)
MAX_EXCERPT_CHARS = 520

FORBIDDEN_OUTPUT_TERMS = [
    "lying",
    "harassment proven",
    "bad faith",
    "definitive contradiction",
]

CATEGORIES: dict[str, dict[str, Any]] = {
    "reimbursement_payment_indicators": {
        "label": "reimbursement/payment",
        "patterns": [
            r"\b(reimburse(?:ment|d)?|refund(?:ed)?|repay|paid\s+back|pay\s+me\s+back)\b",
            r"\b(payment|invoice|receipt|balance|owed|owe[sd]?|expense|expenses)\b",
            r"\b(venmo|cash\s*app|zelle|paypal|deposit|transfer)\b",
            r"\$\s*\d+(?:,\d{3})*(?:\.\d{2})?\b",
        ],
    },
    "request_urgency_indicators": {
        "label": "request urgency",
        "patterns": [
            r"\b(urgent|asap|immediately|right\s+away|today|tonight|tomorrow|deadline)\b",
            r"\b(need\s+you\s+to|please\s+(?:send|call|respond|reply|confirm|let\s+me\s+know))\b",
            r"\b(can\s+you|could\s+you|will\s+you|would\s+you)\b",
            r"\b(call\s+me|respond|reply|answer|confirm)\b",
        ],
    },
    "possible_commitment_indicators": {
        "label": "possible commitment",
        "patterns": [
            r"\b(i\s+will|i'll|i\s+can|i\s+am\s+going\s+to|i'm\s+going\s+to|we\s+will|we'll)\b",
            r"\b(i\s+agree|agreed|promise|committed|commitment)\b",
            r"\b(will\s+(?:send|pay|call|bring|provide|handle|take\s+care|follow\s+up))\b",
            r"\bby\s+(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|tomorrow|today|\d{1,2}/\d{1,2})\b",
        ],
    },
    "legal_adjacent_indicators": {
        "label": "legal/legal-adjacent",
        "patterns": [
            r"\b(attorney|lawyer|counsel|court|legal|lawsuit|sue|mediation|mediator)\b",
            r"\b(agreement|order|filing|hearing|police|report|document|evidence|record)\b",
        ],
    },
    "language_intensity_indicators": {
        "label": "language intensity",
        "patterns": [
            r"\b(furious|angry|ridiculous|unacceptable|insane|crazy|sick\s+of|fed\s+up)\b",
            r"\b(damn|hell|wtf|fuck|fucking|shit|bullshit)\b",
            r"\b(never|always|every\s+single\s+time|you\s+keep|stop\s+ignoring)\b",
            r"!{2,}|\?{2,}|[A-Z]{8,}",
        ],
    },
    "possible_inconsistency_candidates": {
        "label": "possible inconsistency candidate",
        "patterns": [
            r"\b(but\s+you\s+said|you\s+told\s+me|i\s+thought\s+you\s+said|previously\s+you)\b",
            r"\b(that'?s\s+not\s+what|not\s+what\s+you\s+said|you\s+changed|now\s+you'?re\s+saying)\b",
            r"\b(not\s+true|never\s+said|said\s+before|earlier\s+you)\b",
        ],
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build optional attorney-bundle AI triage exports")
    parser.add_argument("--db", default="communications.sqlite", help="SQLite DB path")
    parser.add_argument("--output-dir", default="attorney_bundle", help="Bundle output directory")
    parser.add_argument("--prompt-version", default=PROMPT_VERSION)
    parser.add_argument("--category-schema-version", default=CATEGORY_SCHEMA_VERSION)
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", ""))
    parser.add_argument("--limit", type=int, default=0, help="Maximum candidate rows for dry-run or AI execution")
    parser.add_argument("--dry-run", action="store_true", help="Print deterministic candidate subset without AI calls")
    parser.add_argument("--build-candidates", action="store_true", help="Write deterministic candidate_sets.json")
    parser.add_argument("--run-ai", action="store_true", help="Run AI only for uncached candidate rows")
    parser.add_argument("--export", action="store_true", help="Write JSON exports from candidates and completed cache rows")
    parser.add_argument("--non-response-windows-hours", default="48,168")
    args = parser.parse_args()
    if not any([args.dry_run, args.build_candidates, args.run_ai, args.export]):
        parser.error("Choose at least one action: --dry-run, --build-candidates, --run-ai, or --export")
    return args


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def compact_text(value: Any, limit: int = MAX_EXCERPT_CHARS) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def fallback_content_hash(message: dict[str, Any]) -> str:
    source = "\n".join(
        str(message.get(key) or "")
        for key in ("event_id", "event_dt_utc", "sender", "subject", "body_clean")
    )
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def read_messages(db_path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT event_id, source, source_record_id, thread_key, event_dt_utc,
               direction, sender, recipients_json, subject, body_clean,
               source_file, content_hash
        FROM messages
        ORDER BY event_dt_utc, event_id
        """
    ).fetchall()
    conn.close()
    messages: list[dict[str, Any]] = []
    for row in rows:
        message = {key: ("" if row[key] is None else row[key]) for key in row.keys()}
        if not message.get("content_hash"):
            message["content_hash"] = fallback_content_hash(message)
        messages.append(message)
    return messages


def first_match_excerpt(text: str, patterns: list[re.Pattern[str]]) -> tuple[str, list[str]]:
    matches: list[tuple[int, int, str]] = []
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            matches.append((match.start(), match.end(), pattern.pattern))
    if not matches:
        return "", []
    start, end, _ = min(matches, key=lambda item: item[0])
    window_start = max(0, start - 220)
    window_end = min(len(text), end + 260)
    return compact_text(text[window_start:window_end]), [item[2] for item in matches]


def build_candidates(messages: list[dict[str, Any]]) -> dict[str, Any]:
    compiled = {
        category: [
            re.compile(pattern, 0 if "[A-Z]" in pattern else re.IGNORECASE)
            for pattern in config["patterns"]
        ]
        for category, config in CATEGORIES.items()
    }
    categories: dict[str, list[dict[str, Any]]] = {category: [] for category in CATEGORIES}
    unique_events: set[str] = set()

    for message in messages:
        text = "\n".join(
            part for part in [str(message.get("subject") or ""), str(message.get("body_clean") or "")] if part
        )
        if not text.strip():
            continue
        for category, patterns in compiled.items():
            excerpt, matched_rules = first_match_excerpt(text, patterns)
            if not excerpt:
                continue
            candidate = {
                "event_id": message["event_id"],
                "content_hash": message["content_hash"],
                "event_dt_utc": message["event_dt_utc"],
                "sender": message["sender"],
                "direction": message["direction"],
                "source": message["source"],
                "thread_key": message["thread_key"],
                "category": category,
                "category_label": CATEGORIES[category]["label"],
                "matched_deterministic_rules": matched_rules,
                "supporting_excerpt": excerpt,
            }
            categories[category].append(candidate)
            unique_events.add(message["event_id"])

    return {
        "metadata": {
            "generated_at_utc": now_utc(),
            "category_schema_version": CATEGORY_SCHEMA_VERSION,
            "candidate_category_count": len(categories),
            "unique_event_count": len(unique_events),
            "candidate_count": sum(len(rows) for rows in categories.values()),
            "rules_are_deterministic_prefilters": True,
        },
        "categories": categories,
    }


def ai_dir(output_dir: Path) -> Path:
    path = output_dir / "ai"
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def candidate_sets_path(output_dir: Path) -> Path:
    return ai_dir(output_dir) / "candidate_sets.json"


def cache_path(output_dir: Path) -> Path:
    return ai_dir(output_dir) / "cache.sqlite"


def load_or_build_candidates(db_path: Path, output_dir: Path) -> dict[str, Any]:
    path = candidate_sets_path(output_dir)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    candidates = build_candidates(read_messages(db_path))
    write_json(path, candidates)
    return candidates


def init_cache(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_cache (
            cache_key TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            prompt_version TEXT NOT NULL,
            model TEXT NOT NULL,
            category_schema_version TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT NOT NULL DEFAULT '',
            error TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_cache_event ON ai_cache(event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_cache_status ON ai_cache(status)")
    conn.commit()
    return conn


def cache_key(candidate: dict[str, Any], prompt_version: str, model: str, category_schema_version: str) -> str:
    payload = {
        "event_id": candidate["event_id"],
        "content_hash": candidate["content_hash"],
        "prompt_version": prompt_version,
        "model": model,
        "category_schema_version": category_schema_version,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def iter_candidates(candidate_sets: dict[str, Any], limit: int = 0) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for category in CATEGORIES:
        rows.extend(candidate_sets.get("categories", {}).get(category, []))
    rows.sort(key=lambda row: (str(row.get("event_dt_utc") or ""), str(row.get("event_id") or ""), str(row.get("category") or "")))
    if limit > 0:
        return rows[:limit]
    return rows


def cache_lookup(conn: sqlite3.Connection, key: str) -> dict[str, Any] | None:
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM ai_cache WHERE cache_key = ?", (key,)).fetchone()
    return dict(row) if row else None


def write_cache(
    conn: sqlite3.Connection,
    key: str,
    candidate: dict[str, Any],
    prompt_version: str,
    model: str,
    category_schema_version: str,
    status: str,
    result: dict[str, Any] | None = None,
    error: str = "",
) -> None:
    timestamp = now_utc()
    existing = cache_lookup(conn, key)
    created_at = existing["created_at_utc"] if existing else timestamp
    conn.execute(
        """
        INSERT OR REPLACE INTO ai_cache (
            cache_key, event_id, content_hash, prompt_version, model,
            category_schema_version, category, status, result_json, error,
            created_at_utc, updated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            candidate["event_id"],
            candidate["content_hash"],
            prompt_version,
            model,
            category_schema_version,
            candidate["category"],
            status,
            json.dumps(result or {}, ensure_ascii=False),
            error,
            created_at,
            timestamp,
        ),
    )
    conn.commit()


def triage_prompt(candidate: dict[str, Any]) -> list[dict[str, str]]:
    system = (
        "You are assisting with a cautious evidence triage layer for an attorney review bundle. "
        "Do not make legal conclusions. Use only cautious indicator labels. Return JSON only."
    )
    user_payload = {
        "task": "Assess this deterministic candidate excerpt only. Do not infer from unseen records.",
        "allowed_labels": list(CATEGORIES.keys()),
        "required_evidence": ["event_id", "confidence", "supporting_excerpt"],
        "candidate": candidate,
        "forbidden_terms": FORBIDDEN_OUTPUT_TERMS,
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
    ]


def openai_response_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "event_id": {"type": "string"},
            "category": {"type": "string"},
            "label": {"type": "string"},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "supporting_excerpt": {"type": "string"},
            "amount": {"type": ["string", "null"]},
            "deadline": {"type": ["string", "null"]},
            "requested_action": {"type": ["string", "null"]},
            "promised_action": {"type": ["string", "null"]},
            "notes": {"type": ["string", "null"]},
        },
        "required": [
            "event_id",
            "category",
            "label",
            "confidence",
            "supporting_excerpt",
            "amount",
            "deadline",
            "requested_action",
            "promised_action",
            "notes",
        ],
    }


def call_openai(candidate: dict[str, Any], model: str) -> dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    payload = {
        "model": model,
        "input": triage_prompt(candidate),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "attorney_bundle_triage_result",
                "schema": openai_response_schema(),
                "strict": True,
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API error {exc.code}: {detail}") from exc

    output_text = data.get("output_text")
    if not output_text:
        for item in data.get("output", []):
            for content in item.get("content", []):
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    output_text = content["text"]
                    break
            if output_text:
                break
    if not output_text:
        raise RuntimeError("OpenAI response did not include output_text")
    result = json.loads(output_text)
    result.update(
        {
            "event_id": candidate["event_id"],
            "category": candidate["category"],
            "prompt_version": PROMPT_VERSION,
            "model": model,
            "category_schema_version": CATEGORY_SCHEMA_VERSION,
        }
    )
    validate_result_language(result)
    return result


def generated_text_for_validation(value: Any, parent_key: str = "") -> Any:
    if parent_key in {"supporting_excerpt", "matched_deterministic_rules"}:
        return ""
    if isinstance(value, dict):
        return {key: generated_text_for_validation(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [generated_text_for_validation(item, parent_key) for item in value]
    return value


def validate_result_language(value: Any) -> None:
    text = json.dumps(generated_text_for_validation(value), ensure_ascii=False).lower()
    for term in FORBIDDEN_OUTPUT_TERMS:
        if term.lower() in text:
            raise ValueError(f"Forbidden legal-conclusion wording found in AI output: {term}")


def print_candidate_summary(candidate_sets: dict[str, Any], limit: int) -> None:
    rows = iter_candidates(candidate_sets, limit)
    print("Deterministic candidate subset")
    print(f"  Total candidates: {candidate_sets['metadata']['candidate_count']}")
    print(f"  Unique events: {candidate_sets['metadata']['unique_event_count']}")
    print(f"  Displayed candidates: {len(rows)}")
    for category in CATEGORIES:
        count = len(candidate_sets.get("categories", {}).get(category, []))
        print(f"  {category}: {count}")
    print("")
    for row in rows:
        excerpt = textwrap.shorten(row["supporting_excerpt"], width=180, placeholder="...")
        print(f"- {row['event_id']} | {row['event_dt_utc']} | {row['category']} | {excerpt}")


def run_ai(args: argparse.Namespace, candidate_sets: dict[str, Any]) -> None:
    model = args.model.strip()
    if not model:
        print("--run-ai requested, but no model was supplied. Set OPENAI_MODEL or pass --model.", file=sys.stderr)
        print("No AI calls were made.", file=sys.stderr)
        return
    conn = init_cache(cache_path(Path(args.output_dir)))
    rows = iter_candidates(candidate_sets, args.limit)
    print("Candidate subset before AI")
    print(f"  Selected candidate rows: {len(rows)}")
    print(f"  Unique selected events: {len({row['event_id'] for row in rows})}")
    print(f"  Model: {model}")
    print("")

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is not set. Cache schema is ready, but no AI calls were made.", file=sys.stderr)
        conn.close()
        return

    reused = 0
    completed = 0
    failed = 0
    for candidate in rows:
        key = cache_key(candidate, args.prompt_version, model, args.category_schema_version)
        existing = cache_lookup(conn, key)
        if existing and existing["status"] == "complete":
            reused += 1
            continue
        try:
            result = call_openai(candidate, model)
            result["prompt_version"] = args.prompt_version
            result["category_schema_version"] = args.category_schema_version
            write_cache(conn, key, candidate, args.prompt_version, model, args.category_schema_version, "complete", result)
            completed += 1
        except Exception as exc:  # noqa: BLE001 - preserve per-row failures in cache
            failed += 1
            write_cache(
                conn,
                key,
                candidate,
                args.prompt_version,
                model,
                args.category_schema_version,
                "error",
                {},
                str(exc),
            )
            print(f"AI row failed for {candidate['event_id']} {candidate['category']}: {exc}", file=sys.stderr)
    conn.close()
    print(f"AI cache reused: {reused}")
    print(f"AI rows completed: {completed}")
    print(f"AI rows failed: {failed}")


def completed_ai_results(output_dir: Path) -> list[dict[str, Any]]:
    path = cache_path(output_dir)
    if not path.exists():
        return []
    conn = init_cache(path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT result_json FROM ai_cache WHERE status = 'complete' ORDER BY event_id, category").fetchall()
    conn.close()
    results: list[dict[str, Any]] = []
    for row in rows:
        try:
            result = json.loads(row["result_json"] or "{}")
        except json.JSONDecodeError:
            continue
        if result:
            validate_result_language(result)
            results.append(result)
    return results


def sender_key(value: str) -> str:
    text = str(value or "").strip().lower()
    digits = re.sub(r"\D", "", text)
    if len(digits) >= 10:
        return digits[-10:]
    return text or "unknown"


def event_index(candidate_sets: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in iter_candidates(candidate_sets):
        index.setdefault(row["event_id"], row)
    return index


def counts_summary(candidate_sets: dict[str, Any]) -> dict[str, Any]:
    by_category = {category: len(rows) for category, rows in candidate_sets.get("categories", {}).items()}
    by_sender: Counter[str] = Counter()
    by_month: Counter[str] = Counter()
    for row in iter_candidates(candidate_sets):
        by_sender[row.get("sender") or "Unknown"] += 1
        by_month[str(row.get("event_dt_utc") or "")[:7] or "Unknown"] += 1
    return {
        "by_category": by_category,
        "top_senders": by_sender.most_common(25),
        "by_month": sorted(by_month.items()),
    }


def repeated_request_indicators(candidate_sets: dict[str, Any]) -> list[dict[str, Any]]:
    relevant = []
    for category in ("request_urgency_indicators", "reimbursement_payment_indicators"):
        relevant.extend(candidate_sets.get("categories", {}).get(category, []))
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in relevant:
        groups[(sender_key(row.get("sender", "")), row["category"])].append(row)
    indicators: list[dict[str, Any]] = []
    for (sender, category), rows in groups.items():
        rows.sort(key=lambda row: str(row.get("event_dt_utc") or ""))
        for idx, row in enumerate(rows):
            start = parse_dt(row.get("event_dt_utc", ""))
            if not start:
                continue
            window = [other for other in rows[idx:] if (parse_dt(other.get("event_dt_utc", "")) or start) <= start + timedelta(days=7)]
            if len(window) >= 2:
                indicators.append(
                    {
                        "indicator": "repeated_request_indicators",
                        "category": category,
                        "sender_key": sender,
                        "event_ids": [item["event_id"] for item in window],
                        "count": len(window),
                        "first_event_dt_utc": window[0]["event_dt_utc"],
                        "last_event_dt_utc": window[-1]["event_dt_utc"],
                        "supporting_excerpt": window[0]["supporting_excerpt"],
                    }
                )
                break
    return indicators


def possible_non_response_indicators(candidate_sets: dict[str, Any], windows_hours: tuple[int, ...]) -> list[dict[str, Any]]:
    rows = iter_candidates(candidate_sets)
    request_rows = [
        row
        for row in rows
        if row["category"] in {"request_urgency_indicators", "reimbursement_payment_indicators"}
        and "in" in str(row.get("direction", "")).lower()
    ]
    all_by_thread: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        all_by_thread[row.get("thread_key") or row["event_id"]].append(row)
    indicators: list[dict[str, Any]] = []
    for request in request_rows:
        request_dt = parse_dt(request.get("event_dt_utc", ""))
        if not request_dt:
            continue
        thread_rows = sorted(
            all_by_thread.get(request.get("thread_key") or request["event_id"], []),
            key=lambda row: str(row.get("event_dt_utc") or ""),
        )
        for window_hours in windows_hours:
            deadline = request_dt + timedelta(hours=window_hours)
            later_outbound = [
                row
                for row in thread_rows
                if "out" in str(row.get("direction", "")).lower()
                and request_dt < (parse_dt(row.get("event_dt_utc", "")) or request_dt) <= deadline
            ]
            if not later_outbound:
                indicators.append(
                    {
                        "indicator": "possible_non_response_indicators",
                        "window_hours": window_hours,
                        "request_event_id": request["event_id"],
                        "category": request["category"],
                        "sender": request.get("sender", ""),
                        "event_dt_utc": request.get("event_dt_utc", ""),
                        "supporting_excerpt": request["supporting_excerpt"],
                    }
                )
    return indicators


def commitment_follow_up_candidates(candidate_sets: dict[str, Any]) -> list[dict[str, Any]]:
    commitments = candidate_sets.get("categories", {}).get("possible_commitment_indicators", [])
    requests = (
        candidate_sets.get("categories", {}).get("request_urgency_indicators", [])
        + candidate_sets.get("categories", {}).get("reimbursement_payment_indicators", [])
    )
    results: list[dict[str, Any]] = []
    for commitment in commitments:
        start = parse_dt(commitment.get("event_dt_utc", ""))
        if not start:
            continue
        followups = []
        for request in requests:
            request_dt = parse_dt(request.get("event_dt_utc", ""))
            if request_dt and start < request_dt <= start + timedelta(days=14):
                same_thread = (commitment.get("thread_key") or "") and commitment.get("thread_key") == request.get("thread_key")
                same_sender = sender_key(commitment.get("sender", "")) == sender_key(request.get("sender", ""))
                if same_thread or not same_sender:
                    followups.append(request)
        if followups:
            followups.sort(key=lambda row: str(row.get("event_dt_utc") or ""))
            results.append(
                {
                    "indicator": "commitment_follow_up_candidates",
                    "commitment_event_id": commitment["event_id"],
                    "follow_up_event_ids": [row["event_id"] for row in followups[:5]],
                    "event_dt_utc": commitment["event_dt_utc"],
                    "supporting_excerpt": commitment["supporting_excerpt"],
                }
            )
    return results


def timeline_clusters(candidate_sets: dict[str, Any]) -> list[dict[str, Any]]:
    rows = iter_candidates(candidate_sets)
    by_event: dict[str, dict[str, Any]] = {}
    for row in rows:
        by_event.setdefault(row["event_id"], row)
    ordered = sorted(by_event.values(), key=lambda row: str(row.get("event_dt_utc") or ""))
    clusters: list[dict[str, Any]] = []
    for row in ordered:
        row_dt = parse_dt(row.get("event_dt_utc", ""))
        if not row_dt:
            continue
        nearby = [
            other
            for other in ordered
            if other["event_id"] != row["event_id"]
            and (other_dt := parse_dt(other.get("event_dt_utc", "")))
            and abs((other_dt - row_dt).total_seconds()) <= 24 * 3600
        ]
        if len(nearby) >= 2:
            clusters.append(
                {
                    "center_event_id": row["event_id"],
                    "center_event_dt_utc": row["event_dt_utc"],
                    "nearby_event_ids": [item["event_id"] for item in nearby[:10]],
                    "supporting_excerpt": row["supporting_excerpt"],
                }
            )
        if len(clusters) >= 50:
            break
    return clusters


def export_message_tags(output_dir: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        grouped[result["event_id"]].append(result)
    messages = []
    for event_id, event_results in sorted(grouped.items()):
        tags = sorted({result.get("label") or result.get("category") for result in event_results if result.get("label") or result.get("category")})
        messages.append({"event_id": event_id, "tags": tags, "results": event_results})
    output = {
        "metadata": {
            "generated_at_utc": now_utc(),
            "result_source": "ai_cache_complete_rows",
            "message_count": len(messages),
            "result_count": len(results),
        },
        "messages": messages,
    }
    write_json(ai_dir(output_dir) / "message_tags.json", output)
    return output


def parse_windows(value: str) -> tuple[int, ...]:
    windows = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            windows.append(int(part))
        except ValueError as exc:
            raise SystemExit(f"Invalid --non-response-windows-hours value: {value}") from exc
    return tuple(windows or DEFAULT_NON_RESPONSE_WINDOWS_HOURS)


def export_outputs(args: argparse.Namespace, candidate_sets: dict[str, Any]) -> None:
    output_dir = Path(args.output_dir)
    windows = parse_windows(args.non_response_windows_hours)
    results = completed_ai_results(output_dir)
    message_tags = export_message_tags(output_dir, results)

    summary = counts_summary(candidate_sets)
    requests = {
        "metadata": {"generated_at_utc": now_utc(), "source": "deterministic_candidates"},
        "counts": summary,
        "repeated_request_indicators": repeated_request_indicators(candidate_sets),
        "possible_non_response_indicators": possible_non_response_indicators(candidate_sets, windows),
        "candidate_examples": candidate_sets.get("categories", {}).get("request_urgency_indicators", [])[:50],
        "ai_result_count": len(results),
    }
    commitments = {
        "metadata": {"generated_at_utc": now_utc(), "source": "deterministic_candidates"},
        "possible_commitment_indicators": candidate_sets.get("categories", {}).get("possible_commitment_indicators", []),
        "commitment_follow_up_candidates": commitment_follow_up_candidates(candidate_sets),
    }
    language = {
        "metadata": {"generated_at_utc": now_utc(), "source": "deterministic_candidates"},
        "language_intensity_indicators": candidate_sets.get("categories", {}).get("language_intensity_indicators", []),
    }
    inconsistencies = {
        "metadata": {"generated_at_utc": now_utc(), "source": "deterministic_candidates"},
        "possible_inconsistency_candidates": candidate_sets.get("categories", {}).get("possible_inconsistency_candidates", []),
    }
    insight_summary = {
        "metadata": {"generated_at_utc": now_utc(), "source": "python_sql_deterministic_first"},
        "counts": summary,
        "timeline_clusters": timeline_clusters(candidate_sets),
        "message_tags_exported": message_tags["metadata"],
    }

    for payload in (requests, commitments, language, inconsistencies, insight_summary, message_tags):
        validate_result_language(payload)

    out = ai_dir(output_dir)
    write_json(out / "request_indicators.json", requests)
    write_json(out / "commitments.json", commitments)
    write_json(out / "language_intensity.json", language)
    write_json(out / "possible_inconsistencies.json", inconsistencies)
    write_json(out / "deterministic_insights.json", insight_summary)
    print(f"AI triage exports written to {out}")
    print(f"Completed AI result rows exported: {len(results)}")
    print(f"Message tag records exported: {message_tags['metadata']['message_count']}")


def main() -> None:
    args = parse_args()
    db_path = Path(args.db).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not db_path.exists():
        raise SystemExit(f"DB not found: {db_path}")

    candidate_sets = build_candidates(read_messages(db_path))
    candidate_sets["metadata"]["prompt_version"] = args.prompt_version
    candidate_sets["metadata"]["category_schema_version"] = args.category_schema_version

    if args.dry_run:
        init_cache(cache_path(output_dir)).close()
        print_candidate_summary(candidate_sets, args.limit)
    if args.build_candidates:
        write_json(candidate_sets_path(output_dir), candidate_sets)
        init_cache(cache_path(output_dir)).close()
        print(f"Candidate sets written to {candidate_sets_path(output_dir)}")
    if args.run_ai:
        write_json(candidate_sets_path(output_dir), candidate_sets)
        run_ai(args, candidate_sets)
    if args.export:
        if not candidate_sets_path(output_dir).exists():
            write_json(candidate_sets_path(output_dir), candidate_sets)
        export_outputs(args, candidate_sets)


if __name__ == "__main__":
    main()
