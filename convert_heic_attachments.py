#!/usr/bin/env python3

import sqlite3
from pathlib import Path
import subprocess
import argparse
import shutil


class ConversionError(Exception):
    pass

def log(msg):
    print(msg)

import json
from datetime import datetime, timezone

def extract_exif_datetime(path: Path) -> tuple[str, str]:
    """
    Returns (raw_exif_string, normalized_iso_utc_string)
    """

    try:
        result = subprocess.run(
            [
                "exiftool",
                "-json",
                "-DateTimeOriginal",
                "-CreateDate",
                "-ModifyDate",
                str(path)
            ],
            capture_output=True,
            text=True,
            check=True
        )

        data = json.loads(result.stdout)
        if not data:
            return None, None

        meta = data[0]

        raw = (
            meta.get("DateTimeOriginal") or
            meta.get("CreateDate") or
            meta.get("ModifyDate")
        )

        if not raw:
            return None, None

        # Example format: "2023:08:15 14:32:10"
        try:
            dt = datetime.strptime(raw, "%Y:%m:%d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            iso = dt.isoformat()
        except Exception:
            iso = None

        return raw, iso

    except Exception as e:
        log(f"EXIF parse failed for {path}: {e}")
        return None, None

def copy_exif_from_original(src_path: Path, dst_path: Path) -> bool:
    """
    Copy EXIF/XMP/ICC metadata from the original HEIC to the final JPG,
    but force Orientation=1 so the viewer doesn't rotate it again.
    """
    if not shutil.which("exiftool"):
        log("WARNING: exiftool not found; skipping EXIF copy")
        return False

    try:
        subprocess.run(
            [
                "exiftool",
                "-overwrite_original",
                "-TagsFromFile", str(src_path),
                "-EXIF:all",
                "-XMP:all",
                "-ICC_Profile",
                "-Orientation#=1",
                str(dst_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        log(f"ERROR copying EXIF from {src_path} to {dst_path}: {e}")
        return False

def convert_heic(input_path: Path, output_path: Path) -> bool:
    try:
        if input_path.suffix.lower() == ".heics":
            log(f"Skipping HEICS: {input_path}")
            return False

        if shutil.which("magick"):
            cmd = [
                "magick",
                str(input_path),
                "-auto-orient",
                str(output_path)
            ]
        elif shutil.which("convert"):
            cmd = [
                "convert",
                str(input_path),
                "-auto-orient",
                str(output_path)
            ]
        else:
            raise ConversionError("ImageMagick with HEIC support required")

        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # recopy metadata from original HEIC and force Orientation=1
        copy_exif_from_original(input_path, output_path)

        return True

    except Exception as e:
        log(f"ERROR converting {input_path}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Convert HEIC attachments to JPG")
    parser.add_argument("--db", required=True, help="SQLite DB path")
    parser.add_argument("--attachments-dir", required=True, help="Root attachments directory")

    args = parser.parse_args()

    db_path = Path(args.db)
    attachments_root = Path(args.attachments_dir)

    if not db_path.exists():
        raise FileNotFoundError(f"DB not found: {db_path}")

    if not attachments_root.exists():
        raise FileNotFoundError(f"Attachments dir not found: {attachments_root}")

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    log("Converting HEIC files...")

    cursor.execute("""
        SELECT attachment_id, saved_path
        FROM attachments
        WHERE mime_type LIKE 'image/heic'
          AND (converted_path IS NULL OR converted_path = '')
    """)

    rows = cursor.fetchall()
    log(f"Found {len(rows)} HEIC attachments to process")

    converted_count = 0

    for attachment_id, saved_path in rows:
        input_path = attachments_root / saved_path

        if not input_path.exists():
            log(f"Missing file: {input_path}")
            continue

        output_path = input_path.with_suffix(".jpg")

        # ✅ Idempotency: skip if already exists
        if output_path.exists():
            log(f"Already exists, re-converting: {output_path}")
            output_path.unlink()

#         else:
        success = convert_heic(input_path, output_path)
        if not success:
            continue
        else:
            log(f"Converted : {input_path} -> {output_path}")

        # ✅ Extract EXIF timestamp from original image
        exif_raw, exif_utc = extract_exif_datetime(input_path)

        # ✅ Store paths + EXIF
        rel_converted_path = output_path.relative_to(attachments_root)

        cursor.execute("""
            UPDATE attachments
            SET converted_path = ?, exif_dt_raw = ?, exif_dt_utc = ?
            WHERE attachment_id = ?
        """, (
            str(rel_converted_path),
            exif_raw,
            exif_utc,
            attachment_id
        ))

        converted_count += 1

        if converted_count % 25 == 0:
            log(f"Converted {converted_count} files...")

    conn.commit()
    conn.close()

    log(f"Done. Converted {converted_count} HEIC files.")


if __name__ == "__main__":
    main()