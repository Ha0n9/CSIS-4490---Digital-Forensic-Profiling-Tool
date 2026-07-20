#!/usr/bin/env python3
"""
parse_browser_history.py
Parse browser artifacts from raw dir → browser_history.json

Handles:
  - Chrome / Edge / Brave  → History SQLite  (urls + visits tables)
  - Firefox                → places.sqlite   (moz_places + moz_historyvisits)
  - IE                     → index.dat       (text scan, best-effort)

Usage:
    python3 parse_browser_history.py --raw-dir <dir> --output <file>
"""

import argparse
import json
import re
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Chrome/Edge epoch starts 1601-01-01
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Firefox epoch is Unix time in microseconds
FIREFOX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def chrome_time_to_iso(microseconds: int) -> str:
    try:
        dt = CHROME_EPOCH + timedelta(microseconds=int(microseconds))
        return dt.isoformat()
    except Exception:
        return ""


def firefox_time_to_iso(microseconds: int) -> str:
    try:
        dt = FIREFOX_EPOCH + timedelta(microseconds=int(microseconds))
        return dt.isoformat()
    except Exception:
        return ""


def query_sqlite(db_path: Path, query: str, params: tuple = ()) -> list[tuple]:
    """Copy DB to temp location (avoids WAL/lock issues) and run query."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        shutil.copy2(db_path, tmp_path)
        con = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.execute(query, params)
        rows = cur.fetchall()
        con.close()
        return rows
    except Exception as exc:
        print(f"[!] SQLite error on {db_path.name}: {exc}", file=sys.stderr)
        return []
    finally:
        tmp_path.unlink(missing_ok=True)


def parse_chrome(db_path: Path, browser: str, username: str) -> list[dict]:
    """Parse Chrome/Edge/Brave History SQLite."""
    rows = query_sqlite(
        db_path,
        """
        SELECT u.url, u.title, u.visit_count,
               v.visit_time, v.transition
        FROM urls u
        JOIN visits v ON v.url = u.id
        ORDER BY v.visit_time DESC
        """,
    )
    records = []
    for row in rows:
        records.append(
            {
                "browser": browser,
                "username": username,
                "url": row["url"],
                "title": row["title"] or "",
                "visit_count": row["visit_count"],
                "visited_at": chrome_time_to_iso(row["visit_time"]),
                "transition": row["transition"],
            }
        )
    return records


def parse_firefox(db_path: Path, username: str) -> list[dict]:
    """Parse Firefox places.sqlite."""
    rows = query_sqlite(
        db_path,
        """
        SELECT p.url, p.title, p.visit_count,
               h.visit_date, h.visit_type
        FROM moz_places p
        JOIN moz_historyvisits h ON h.place_id = p.id
        ORDER BY h.visit_date DESC
        """,
    )
    records = []
    for row in rows:
        records.append(
            {
                "browser": "Firefox",
                "username": username,
                "url": row["url"],
                "title": row["title"] or "",
                "visit_count": row["visit_count"],
                "visited_at": firefox_time_to_iso(row["visit_date"]),
                "visit_type": row["visit_type"],
            }
        )
    return records


def parse_ie_index_dat(dat_path: Path, username: str) -> list[dict]:
    """
    Best-effort URL extraction from IE index.dat.
    These are legacy binary files; we scan for URL patterns.
    """
    records = []
    url_pattern = re.compile(
        rb"(?:https?://|ftp://|file://)[^\x00\r\n<>\"]{4,512}"
    )
    try:
        data = dat_path.read_bytes()
        for m in url_pattern.finditer(data):
            url = m.group(0).decode("utf-8", errors="replace").rstrip()
            records.append(
                {
                    "browser": "IE",
                    "username": username,
                    "url": url,
                    "title": "",
                    "visit_count": None,
                    "visited_at": "",
                    "source_file": dat_path.name,
                }
            )
    except Exception as exc:
        print(f"[!] IE index.dat parse error {dat_path}: {exc}", file=sys.stderr)
    return records


def infer_meta_from_filename(filename: str) -> tuple[str, str]:
    """
    Extract (username, browser) from filenames like:
      john_Chrome_Default_History
      alice_Firefox_abc123_places.sqlite
      bob_GPARENT_PARENT_index.dat
    """
    parts = filename.split("_")
    username = parts[0] if parts else "unknown"
    browser = parts[1] if len(parts) > 1 else "unknown"
    return username, browser


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Parse browser artifacts → browser_history.json"
    )
    ap.add_argument("--raw-dir", required=True, help="Root raw browser directory")
    ap.add_argument("--output", required=True, help="Output JSON file path")
    args = ap.parse_args()

    raw_dir = Path(args.raw_dir)
    all_records: list[dict] = []

    # ── Chrome / Edge / Brave ──────────────────────────────────────────────────
    chrome_dir = raw_dir / "chrome"
    if chrome_dir.is_dir():
        for hist_file in chrome_dir.iterdir():
            if not hist_file.is_file():
                continue
            name = hist_file.name
            username, browser = infer_meta_from_filename(name)
            if name.endswith("_History"):
                records = parse_chrome(hist_file, browser, username)
                all_records.extend(records)
                print(f"[*] Chrome/Edge: {len(records)} visits from {name}")

    # ── Firefox ───────────────────────────────────────────────────────────────
    ff_dir = raw_dir / "firefox"
    if ff_dir.is_dir():
        for db_file in ff_dir.glob("*_places.sqlite"):
            username = db_file.name.split("_")[0]
            records = parse_firefox(db_file, username)
            all_records.extend(records)
            print(f"[*] Firefox: {len(records)} visits from {db_file.name}")

    # ── IE ────────────────────────────────────────────────────────────────────
    ie_dir = raw_dir / "ie"
    if ie_dir.is_dir():
        for dat_file in ie_dir.glob("*_index.dat"):
            username = dat_file.name.split("_")[0]
            records = parse_ie_index_dat(dat_file, username)
            all_records.extend(records)
            print(f"[*] IE: {len(records)} URLs from {dat_file.name}")

    result = {
        "artifact": "browser_history",
        "parsed_at": datetime.now(timezone.utc).isoformat() + "Z",
        "count": len(all_records),
        "records": all_records,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    print(f"[✓] {len(all_records)} total browser records → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())