#!/usr/bin/env python3
"""
parse_deleted_files.py
Parse Recycle Bin artifacts → deleted_files.json

Supports:
  - Windows XP: RECYCLER/INFO2 binary format
  - Windows Vista+: $Recycle.Bin / $I + $R file pairs

No EZ Tools required.
"""

import argparse
import json
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(ft: int) -> str:
    if ft == 0:
        return ""
    try:
        return (WINDOWS_EPOCH + timedelta(microseconds=ft // 10)).isoformat()
    except Exception:
        return ""


# =============================================================================
# Windows XP INFO2 parser
# =============================================================================

def parse_info2(info2_path: Path) -> list[dict]:
    """
    Parse RECYCLER/INFO2 (Windows 9x/XP/2003).
    File layout:
      Header: 20 bytes
      Records: 280 bytes each (ANSI path) or variable if Unicode suffix present
    Record layout (280 bytes):
      0x00  deleted_flag   DWORD  (0x00 = free, non-zero = deleted)
      0x04  drive_number   DWORD
      0x08  deletion_time  FILETIME (8 bytes)
      0x10  file_size      DWORD
      0x14  original_path  ANSI 260 bytes (null-terminated)
    Optional Unicode suffix (appended after the ANSI path in later XP builds):
      The record block may be 280+520 bytes if Unicode path is present.
    """
    records = []
    RECORD_SIZE = 280

    try:
        data = info2_path.read_bytes()
    except Exception as e:
        print(f"[!] Cannot read INFO2 {info2_path}: {e}", file=sys.stderr)
        return records

    if len(data) < 20:
        return records

    # Header: version at 0x00, record_size at 0x0C, record_count at 0x10
    version     = struct.unpack_from("<I", data, 0x00)[0]
    rec_size    = struct.unpack_from("<I", data, 0x0C)[0] if len(data) >= 16 else RECORD_SIZE

    # Use detected record size if reasonable
    if rec_size not in (280, 800):
        rec_size = RECORD_SIZE

    offset = 20  # skip header
    while offset + rec_size <= len(data):
        chunk = data[offset: offset + rec_size]

        deleted_flag = struct.unpack_from("<I", chunk, 0x00)[0]
        if deleted_flag == 0:
            offset += rec_size
            continue

        drive_num    = struct.unpack_from("<I", chunk, 0x04)[0]
        deletion_ft  = struct.unpack_from("<Q", chunk, 0x08)[0]
        file_size    = struct.unpack_from("<I", chunk, 0x10)[0]

        # ANSI path
        raw_path = chunk[0x14:0x14 + 260]
        ansi_path = raw_path.split(b"\x00")[0].decode("latin-1", errors="replace")

        # Unicode path (if 800-byte record)
        uni_path = ""
        if rec_size >= 800 and len(chunk) >= 800:
            uni_raw = chunk[280:280 + 520]
            uni_path = uni_raw.decode("utf-16-le", errors="replace").split("\x00")[0]

        original_path = uni_path if uni_path else ansi_path

        records.append({
            "source":        "INFO2",
            "original_path": original_path,
            "file_size":     str(file_size),
            "deleted_at":    filetime_to_iso(deletion_ft),
            "drive_number":  drive_num,
            "sid":           "",
            "source_file":   str(info2_path),
        })

        offset += rec_size

    return records


# =============================================================================
# Windows Vista+ $Recycle.Bin $I file parser
# =============================================================================

def parse_i_file(i_path: Path, sid: str) -> dict | None:
    """
    Parse a $I?????? file from $Recycle.Bin.
    Format:
      0x00  header    QWORD  (1 or 2)
      0x08  file_size QWORD
      0x10  deleted_at FILETIME (8 bytes)
      0x18  original_path UTF-16LE null-terminated (version 1)
              OR
            path_length DWORD + UTF-16LE (version 2)
    """
    try:
        data = i_path.read_bytes()
    except Exception as e:
        print(f"[!] Cannot read {i_path}: {e}", file=sys.stderr)
        return None

    if len(data) < 28:
        return None

    header    = struct.unpack_from("<Q", data, 0x00)[0]
    file_size = struct.unpack_from("<Q", data, 0x08)[0]
    del_ft    = struct.unpack_from("<Q", data, 0x10)[0]

    original_path = ""
    if header == 1:
        # Version 1: path starts at 0x18
        raw = data[0x18:]
        original_path = raw.rstrip(b"\x00").decode("utf-16-le", errors="replace").split("\x00")[0]
    elif header == 2:
        # Version 2: path length DWORD at 0x18, then path
        if len(data) >= 0x1C:
            path_len = struct.unpack_from("<I", data, 0x18)[0]
            raw = data[0x1C: 0x1C + path_len * 2]
            original_path = raw.decode("utf-16-le", errors="replace")
    else:
        # Unknown version — try both offsets
        raw = data[0x18:]
        original_path = raw.rstrip(b"\x00").decode("utf-16-le", errors="replace").split("\x00")[0]

    return {
        "source":        "$I_file",
        "original_path": original_path,
        "file_size":     str(file_size),
        "deleted_at":    filetime_to_iso(del_ft),
        "sid":           sid,
        "i_file":        i_path.name,
        "r_file":        "$R" + i_path.name[2:],  # corresponding $R file
        "source_file":   str(i_path),
    }


def scan_recycle_bin_modern(rb_dir: Path) -> list[dict]:
    """Scan $Recycle.Bin directory for $I files."""
    records = []
    # Structure: $Recycle.Bin/<SID>/$Ixxxxxx
    for sid_dir in rb_dir.iterdir():
        if not sid_dir.is_dir():
            continue
        sid = sid_dir.name
        for f in sid_dir.iterdir():
            if f.is_file() and f.name.upper().startswith("$I"):
                rec = parse_i_file(f, sid)
                if rec:
                    records.append(rec)
    return records


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Parse Recycle Bin artifacts → deleted_files.json"
    )
    ap.add_argument("--raw-dir",  required=True, help="raw/ directory from extraction")
    ap.add_argument("--output",   required=True, help="Output JSON file")
    ap.add_argument("--win-ver",  default="unknown", choices=["xp","modern","unknown"])
    ap.add_argument("--json-dir", default="",    help="(unused, legacy compat)")
    args = ap.parse_args()

    rb_dir = Path(args.raw_dir) / "recycle_bin"
    records: list[dict] = []

    if not rb_dir.is_dir():
        print(f"[!] Recycle bin dir not found: {rb_dir}", file=sys.stderr)
    else:
        # INFO2 (XP)
        for info2 in list(rb_dir.rglob("INFO2")) + list(rb_dir.rglob("info2")):
            print(f"[*] Parsing INFO2: {info2}")
            r = parse_info2(info2)
            records.extend(r)
            print(f"    → {len(r)} entries")

        # $I files (modern)
        i_files = list(rb_dir.rglob("$I*")) + list(rb_dir.rglob("[Ii]nfo_*"))
        if i_files:
            print(f"[*] Found {len(i_files)} $I files")
            for sid_dir in rb_dir.iterdir():
                if not sid_dir.is_dir():
                    continue
                for f in sid_dir.iterdir():
                    name = f.name
                    if f.is_file() and (name.startswith("$I") or name.startswith("$i")):
                        rec = parse_i_file(f, sid_dir.name)
                        if rec:
                            records.append(rec)
            print(f"[✓] {sum(1 for r in records if r['source']=='$I_file')} $I entries")

    result = {
        "artifact":        "deleted_files",
        "windows_version": args.win_ver,
        "parsed_at":       datetime.now(timezone.utc).isoformat() + "Z",
        "count":           len(records),
        "records":         records,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"[✓] {len(records)} deleted file records → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())