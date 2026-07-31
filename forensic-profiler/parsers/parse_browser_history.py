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
from urllib.parse import unquote, urlparse

# Chrome/Edge epoch starts 1601-01-01
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Firefox epoch is Unix time in microseconds
FIREFOX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# =============================================================================
# Behavior-intent matching — flags search/browsing text that indicates
# anti-forensic/evasive intent (e.g. "how to clear browser history") or
# weapon-acquisition/violence-planning intent (e.g. "ffl transfers", "map of
# gun free zones"), independent of correlation/engine.py's SUSPICIOUS_DOMAINS
# (which flags known-bad *destinations*, not intent expressed in ordinary
# search text on any domain). Deliberately conservative in every category:
# only clearly actionable/planning phrasing, never a bare topic mention —
# e.g. weapon_acquisition/violence_planning patterns require explicit
# purchase or attack-planning language, so ordinary political commentary or
# news coverage about firearms ("gun control debate", "mass shooting
# statistics") does not match.
# =============================================================================
BEHAVIOR_PATTERNS: dict[str, tuple[str, int]] = {
    r"clear\s+(my\s+)?(browser|browsing|internet)\s*history": ("anti_forensic", 3),
    r"delete\s+(my\s+)?(browser|browsing|internet)\s*history": ("anti_forensic", 3),
    r"(permanently|securely)\s+(delete|erase)\s+files?": ("anti_forensic", 3),
    r"wipe\s+(free\s+space|hard\s*drive|disk)": ("anti_forensic", 3),
    r"how\s+to\s+(hide|permanently\s+delete)\s+(files?|folders?|evidence)": ("anti_forensic", 3),
    r"shred(der)?\s+(files?|documents?)": ("anti_forensic", 2),
    r"bypass\s+(firewall|antivirus|admin(istrator)?\s*password)": ("evasion", 3),
    r"disable\s+(antivirus|windows\s*defender|firewall)": ("evasion", 3),
    r"undetectable\s+(keylogger|malware|rat|spyware)": ("evasion", 4),
    r"how\s+to\s+avoid\s+detection": ("evasion", 3),
    r"\b(buy|purchase|order)\s+(an?\s+)?(illegal\s+)?(gun|firearm|rifle|pistol|handgun|shotgun|ammo|ammunition)\b": ("weapon_acquisition", 3),
    r"\b(guns?|firearms?|rifles?|pistols?|ammo|ammunition)\s+for\s+sale\b": ("weapon_acquisition", 2),
    r"\bgun\s*(store|shop)s?\s+near\s+me\b": ("weapon_acquisition", 2),
    r"\bffl\b[\s&,-]*transfers?\b": ("weapon_acquisition", 3),
    r"\b(ghost\s+gun|untraceable\s+(firearm|gun)|no\s+background\s+check\s+(gun|firearm))\b": ("weapon_acquisition", 4),
    r"how\s+to\s+(plan|carry\s+out|commit)\s+(an?\s+)?(mass\s+)?(shooting|attack|massacre)\b": ("violence_planning", 4),
    r"\b(mass\s+shooting|active\s+shooter)\s+(plan|target|location)s?\b": ("violence_planning", 4),
    r"\bmap\s+of\s+gun[-\s]free\s+zones?\b": ("violence_planning", 4),
    r"\bkill\s+(my|the)\s+(coworkers?|classmates?|boss|family)\b": ("violence_planning", 3),
    r"how\s+to\s+(build|make)\s+(an?\s+)?bomb\b": ("violence_planning", 4),
}
_BEHAVIOR_PATTERNS_COMPILED = [
    (re.compile(pattern, re.I), cat, weight)
    for pattern, (cat, weight) in BEHAVIOR_PATTERNS.items()
]


def _path_text(url: str) -> str:
    """
    Decode a URL's path segments into plain, matchable text: percent-decode,
    then replace the common "pretty URL" slug separators -/_/+ with spaces.
    Used as a last-resort fallback when neither the page title nor the
    query string carries any readable text (e.g. a search engine result
    page whose own URL encodes the query as a slug, or a static site page
    like "/how-to-clear-your-browser-history.html").
    """
    try:
        path = unquote(urlparse(url).path or "")
    except Exception:
        return ""
    return re.sub(r"[-_+]", " ", path).lower()


def _query_text(url: str) -> str:
    """Decode a URL's query string into plain, matchable text."""
    try:
        query = unquote(urlparse(url).query or "")
    except Exception:
        return ""
    return re.sub(r"[+]", " ", query).lower()


def _match_behavior(text: str) -> tuple[str, int] | None:
    if not text:
        return None
    for regex, cat, weight in _BEHAVIOR_PATTERNS_COMPILED:
        if regex.search(text):
            return cat, weight
    return None


def _annotate_behavior(record: dict) -> dict:
    """
    Flag a browser-history record with anti-forensic/evasion intent, if
    any, checking page title first, then the URL's query-string text, and
    only falling back to the URL's path-segment text (_path_text()) if
    neither found a match — title/query text is more reliably human-
    readable than a path slug, so it's checked first.
    """
    title = (record.get("title") or "").lower()
    url = record.get("url") or ""

    match = _match_behavior(title)
    matched_on = "title"
    if not match:
        match = _match_behavior(_query_text(url))
        matched_on = "query"
    if not match:
        match = _match_behavior(_path_text(url))
        matched_on = "path"

    if match:
        record["behavior_category"] = match[0]
        record["behavior_weight"] = match[1]
        record["behavior_matched_on"] = matched_on
    else:
        record["behavior_category"] = None
        record["behavior_weight"] = 0
        record["behavior_matched_on"] = ""
    return record


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
    """
    Copy DB (+ any WAL/SHM sidecars sitting next to it) to a temp location
    and run query.

    Chrome/Edge/Brave/Firefox all default to SQLite WAL journal mode, so the
    most recently visited pages can live only in a "<db>-wal" file that
    hasn't been checkpointed into the main database yet. Copying just the
    main file (as this used to do) silently drops that recent activity.
    Copying the "-wal"/"-shm" sidecars alongside the main file under the
    *same* temp base name lets SQLite merge committed WAL frames back in
    when the copy is opened, exactly as it would for the live file.

    Opened read-write (not mode=ro): this is already a disposable temp copy
    — the original evidence file under raw/ is never touched either way —
    and read-write access avoids relying on this SQLite build's read-only
    WAL-recovery support, which isn't guaranteed on every version.
    """
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    sidecar_paths: list[Path] = []
    try:
        shutil.copy2(db_path, tmp_path)
        for ext in ("-wal", "-shm"):
            src = Path(str(db_path) + ext)
            if src.exists():
                dst = Path(str(tmp_path) + ext)
                shutil.copy2(src, dst)
                sidecar_paths.append(dst)

        con = sqlite3.connect(str(tmp_path))
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
        for sidecar in sidecar_paths:
            sidecar.unlink(missing_ok=True)


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
    for r in records:
        _annotate_behavior(r)
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
    for r in records:
        _annotate_behavior(r)
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
    for r in records:
        _annotate_behavior(r)
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