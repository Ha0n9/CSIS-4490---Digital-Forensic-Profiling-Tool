#!/usr/bin/env python3
"""
parse_application_activity.py
Parse Windows Prefetch (.pf) files directly → application_activity.json

Supports format versions:
  17 = Windows XP / 2003
  23 = Windows Vista / 7
  26 = Windows 8 / 8.1
  30 = Windows 10 (uncompressed — MAM-compressed files noted but skipped)

No EZ Tools required.
"""

import argparse
import json
import os
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SCCA_MAGIC = b"SCCA"
MAM_MAGIC  = b"MAM\x04"  # Windows 10 compressed


def filetime_to_iso(ft: int) -> str:
    if ft == 0:
        return ""
    try:
        return (WINDOWS_EPOCH + timedelta(microseconds=ft // 10)).isoformat()
    except Exception:
        return ""


def read_utf16(data: bytes, offset: int, max_bytes: int) -> str:
    chunk = data[offset:offset + max_bytes]
    try:
        s = chunk.decode("utf-16-le", errors="replace")
        return s.split("\x00")[0]
    except Exception:
        return ""


def parse_pf_v17(data: bytes, filename: str) -> dict | None:
    """Windows XP prefetch format (version 17)."""
    if len(data) < 0x98:
        return None

    exe_name = read_utf16(data, 0x10, 60)
    pf_hash  = struct.unpack_from("<I", data, 0x4C)[0]

    # Section offsets
    sec_a_off = struct.unpack_from("<I", data, 0x54)[0]  # file metrics
    sec_a_cnt = struct.unpack_from("<I", data, 0x58)[0]
    sec_c_off = struct.unpack_from("<I", data, 0x64)[0]  # filename strings
    sec_c_len = struct.unpack_from("<I", data, 0x68)[0]

    last_run_ft = struct.unpack_from("<Q", data, 0x78)[0]
    run_count   = struct.unpack_from("<I", data, 0x90)[0]

    # Parse referenced filenames (section C = UTF-16LE string pool)
    filenames = []
    if sec_c_off and sec_c_len and sec_c_off + sec_c_len <= len(data):
        pool = data[sec_c_off:sec_c_off + sec_c_len]
        raw = pool.decode("utf-16-le", errors="replace")
        filenames = [f for f in raw.split("\x00") if f.strip()]

    return {
        "executable":    exe_name,
        "pf_hash":       f"{pf_hash:08X}",
        "format_version": 17,
        "run_count":     run_count,
        "last_run":      filetime_to_iso(last_run_ft),
        "previous_runs": [],
        "files_loaded":  filenames,
        "source_file":   filename,
    }


def parse_pf_v23_v26(data: bytes, version: int, filename: str) -> dict | None:
    """Windows Vista/7 (v23) and Win8/8.1 (v26) prefetch format."""
    if len(data) < 0xF0:
        return None

    exe_name = read_utf16(data, 0x10, 60)
    pf_hash  = struct.unpack_from("<I", data, 0x4C)[0]

    sec_c_off = struct.unpack_from("<I", data, 0x64)[0]
    sec_c_len = struct.unpack_from("<I", data, 0x68)[0]

    last_run_ft = struct.unpack_from("<Q", data, 0x80)[0]
    run_count   = struct.unpack_from("<I", data, 0x98)[0]

    filenames = []
    if sec_c_off and sec_c_len and sec_c_off + sec_c_len <= len(data):
        pool = data[sec_c_off:sec_c_off + sec_c_len]
        raw = pool.decode("utf-16-le", errors="replace")
        filenames = [f for f in raw.split("\x00") if f.strip()]

    return {
        "executable":    exe_name,
        "pf_hash":       f"{pf_hash:08X}",
        "format_version": version,
        "run_count":     run_count,
        "last_run":      filetime_to_iso(last_run_ft),
        "previous_runs": [],
        "files_loaded":  filenames,
        "source_file":   filename,
    }


def parse_pf_v30(data: bytes, filename: str) -> dict | None:
    """Windows 10 uncompressed prefetch (version 30)."""
    if len(data) < 0x130:
        return None

    exe_name = read_utf16(data, 0x10, 60)
    pf_hash  = struct.unpack_from("<I", data, 0x4C)[0]

    sec_c_off = struct.unpack_from("<I", data, 0x64)[0]
    sec_c_len = struct.unpack_from("<I", data, 0x68)[0]

    # v30 has 8 run timestamps at 0x80
    run_times = []
    for i in range(8):
        ft = struct.unpack_from("<Q", data, 0x80 + i * 8)[0]
        ts = filetime_to_iso(ft)
        if ts:
            run_times.append(ts)

    last_run = run_times[0] if run_times else ""
    prev_runs = run_times[1:] if len(run_times) > 1 else []

    run_count = struct.unpack_from("<I", data, 0xD0)[0] if len(data) > 0xD4 else 0

    filenames = []
    if sec_c_off and sec_c_len and sec_c_off + sec_c_len <= len(data):
        pool = data[sec_c_off:sec_c_off + sec_c_len]
        raw = pool.decode("utf-16-le", errors="replace")
        filenames = [f for f in raw.split("\x00") if f.strip()]

    return {
        "executable":    exe_name,
        "pf_hash":       f"{pf_hash:08X}",
        "format_version": 30,
        "run_count":     run_count,
        "last_run":      last_run,
        "previous_runs": prev_runs,
        "files_loaded":  filenames,
        "source_file":   filename,
    }


def parse_prefetch_file(pf_path: Path) -> dict | None:
    try:
        data = pf_path.read_bytes()
    except Exception as e:
        print(f"[!] Cannot read {pf_path}: {e}", file=sys.stderr)
        return None

    if len(data) < 8:
        return None

    # MAM compressed (Windows 10) — skip, would need decompression
    if data[:4] == MAM_MAGIC:
        try:
            import ctypes
            # Try xpress huffman decompression via RtlDecompressBufferEx
            # Not available on Linux — note and skip
            pass
        except Exception:
            pass
        print(f"[!] {pf_path.name}: MAM-compressed (Win10), skipping", file=sys.stderr)
        return {
            "executable":     pf_path.name,
            "format_version": "MAM-compressed",
            "note":           "Windows 10 compressed prefetch — use PECmd on Windows to parse",
            "source_file":    pf_path.name,
        }

    if data[4:8] != SCCA_MAGIC:
        print(f"[!] {pf_path.name}: not a valid prefetch file", file=sys.stderr)
        return None

    version = struct.unpack_from("<I", data, 0)[0]
    fname   = pf_path.name

    if version == 17:
        return parse_pf_v17(data, fname)
    elif version == 23:
        return parse_pf_v23_v26(data, 23, fname)
    elif version == 26:
        return parse_pf_v23_v26(data, 26, fname)
    elif version == 30:
        return parse_pf_v30(data, fname)
    else:
        print(f"[!] {fname}: unknown version {version}", file=sys.stderr)
        return {"executable": fname, "format_version": version, "source_file": fname}


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse .pf prefetch files → application_activity.json")
    ap.add_argument("--raw-dir",  required=True, help="raw/ directory from extraction")
    ap.add_argument("--output",   required=True, help="Output JSON file")
    ap.add_argument("--json-dir", default="", help="(unused, legacy compat)")
    args = ap.parse_args()

    prefetch_dir = Path(args.raw_dir) / "prefetch"
    if not prefetch_dir.is_dir():
        print(f"[!] Prefetch dir not found: {prefetch_dir}", file=sys.stderr)
        records = []
    else:
        pf_files = sorted(prefetch_dir.glob("*.pf"))
        print(f"[*] Found {len(pf_files)} .pf files")
        records = []
        for pf in pf_files:
            rec = parse_prefetch_file(pf)
            if rec:
                records.append(rec)
        print(f"[✓] Parsed {len(records)} prefetch entries")

    # Sort by last_run descending so most recent appears first
    records.sort(key=lambda r: r.get("last_run", "") or "", reverse=True)

    result = {
        "artifact":  "application_activity",
        "parsed_at": datetime.now(timezone.utc).isoformat() + "Z",
        "count":     len(records),
        "records":   records,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"[✓] Written → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())