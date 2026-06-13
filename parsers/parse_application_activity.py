#!/usr/bin/env python3
"""
parse_application_activity.py
Artifact : Application Activity — Prefetch files (.pf)
Source   : raw/prefetch/*.pf
Output   : application_activity.json

Supports Windows XP (v17), Vista/7 (v23), Win8 (v26), Win10 (v30/v31)
Pure Python, no EZ Tools required.

Usage:
    python3 parse_application_activity.py --raw-dir <raw/> --output <file.json>
"""

import argparse
import json
import struct
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

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# =============================================================================
# Prefetch header layout
#
# All versions start with:
#   0x00  DWORD  version
#   0x04  DWORD  signature  (0x41434353 = "SCCA")
#   0x08  DWORD  unknown
#   0x0C  DWORD  file_size
#   0x10  WCHAR[29]  exe_name (58 bytes, null-padded)
#   0x4A  DWORD  prefetch_hash
#
# Last run timestamps and run count differ by version:
#   v17 (XP):         one timestamp at 0x78, run_count at 0x90
#   v23 (Vista/7):    one timestamp at 0x80, run_count at 0x98
#   v26 (Win8):       eight timestamps at 0x80, run_count at 0xD0
#   v30/v31 (Win10):  eight timestamps at 0x80, run_count at 0xD0
#                     (may be MAM-compressed — handled below)
# =============================================================================

PF_SIGNATURE = 0x41434353  # "SCCA"
MAM_SIGNATURE = 0x044D414D  # compressed Win10 prefetch

def _decompress_mam(data: bytes) -> bytes | None:
    """Attempt to decompress MAM-compressed Win10 prefetch using ctypes xpress."""
    # Try using the xpress_huff decompressor via Python's ctypes on Windows.
    # On Linux/Kali we fall back to the raw data (header fields still readable).
    try:
        import ctypes
        # Uncompressed size is stored at bytes 4-8 of the MAM block
        uncompressed_size = struct.unpack_from("<I", data, 4)[0]
        compressed_data = data[8:]
        buf = ctypes.create_string_buffer(uncompressed_size)
        ntdll = ctypes.WinDLL("ntdll")
        workspace_size = ctypes.c_ulong(0)
        ntdll.RtlGetCompressionWorkSpaceSize(0x104, ctypes.byref(workspace_size), ctypes.c_ulong(0))
        workspace = ctypes.create_string_buffer(workspace_size.value)
        final_size = ctypes.c_ulong(0)
        ntdll.RtlDecompressBufferEx(
            0x104, buf, uncompressed_size,
            compressed_data, len(compressed_data),
            ctypes.byref(final_size), workspace
        )
        return bytes(buf[:final_size.value])
    except Exception:
        return None

def parse_pf_file(pf_path: Path) -> dict | None:
    try:
        data = pf_path.read_bytes()
    except Exception as e:
        print(f"  [!] Cannot read {pf_path.name}: {e}")
        return None

    if len(data) < 84:
        return None

    # Check for MAM compression (Win10 compressed prefetch)
    if struct.unpack_from("<I", data, 0)[0] == MAM_SIGNATURE:
        decompressed = _decompress_mam(data)
        if decompressed and len(decompressed) > 84:
            data = decompressed
        else:
            # On Linux: parse what we can from the MAM header
            # Exe name is still readable from the filename
            exe_name = pf_path.stem.rsplit("-", 1)[0] if "-" in pf_path.stem else pf_path.stem
            return {
                "exe_name":        exe_name,
                "pf_hash":         pf_path.stem.rsplit("-", 1)[-1] if "-" in pf_path.stem else "",
                "file_size":       len(data),
                "version":         "v30/v31 (MAM compressed — limited parse on Linux)",
                "run_count":       None,
                "last_run":        "",
                "all_run_times":   [],
                "source_file":     pf_path.name,
            }

    # Check signature
    sig = struct.unpack_from("<I", data, 4)[0]
    if sig != PF_SIGNATURE:
        return None

    version   = struct.unpack_from("<I", data, 0)[0]
    file_size = struct.unpack_from("<I", data, 0x0C)[0]

    # Exe name: UTF-16LE, 29 chars at 0x10
    try:
        exe_raw  = data[0x10:0x10 + 58]
        exe_name = exe_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        exe_name = pf_path.stem

    pf_hash  = struct.unpack_from("<I", data, 0x4C)[0]

    last_run = ""
    all_runs: list[str] = []
    run_count = None

    if version == 17:  # XP
        if len(data) >= 0x94:
            ft = struct.unpack_from("<Q", data, 0x78)[0]
            last_run = filetime_to_iso(ft)
            all_runs = [last_run] if last_run else []
            run_count = struct.unpack_from("<I", data, 0x90)[0]

    elif version == 23:  # Vista/7
        if len(data) >= 0x9C:
            ft = struct.unpack_from("<Q", data, 0x80)[0]
            last_run = filetime_to_iso(ft)
            all_runs = [last_run] if last_run else []
            run_count = struct.unpack_from("<I", data, 0x98)[0]

    elif version in (26, 30, 31):  # Win8 / Win10
        if len(data) >= 0xD4:
            run_count = struct.unpack_from("<I", data, 0xD0)[0]
            for i in range(8):
                offset = 0x80 + i * 8
                if offset + 8 > len(data):
                    break
                ft = struct.unpack_from("<Q", data, offset)[0]
                if ft:
                    all_runs.append(filetime_to_iso(ft))
            all_runs = [r for r in all_runs if r]
            last_run = all_runs[0] if all_runs else ""

    return {
        "exe_name":      exe_name,
        "pf_hash":       f"{pf_hash:08X}",
        "file_size":     file_size,
        "version":       {17: "v17 (XP)", 23: "v23 (Vista/7)", 26: "v26 (Win8)",
                          30: "v30 (Win10)", 31: "v31 (Win10)"}.get(version, f"v{version}"),
        "run_count":     run_count,
        "last_run":      last_run,
        "all_run_times": all_runs,
        "source_file":   pf_path.name,
    }

def main() -> int:
    ap = argparse.ArgumentParser(description="Parse Prefetch files → application_activity.json")
    ap.add_argument("--raw-dir", required=True, help="raw/ directory from extraction")
    ap.add_argument("--output",  required=True, help="Output JSON file")
    # Accept --mount for compat but ignore it (we always read from raw/)
    ap.add_argument("--mount",   default="", help="(unused, compat)")
    args = ap.parse_args()

    pf_dir = Path(args.raw_dir) / "prefetch"
    records: list[dict] = []

    if not pf_dir.is_dir():
        print(f"  [!] Prefetch directory not found: {pf_dir}")
    else:
        pf_files = list(pf_dir.glob("*.pf")) + list(pf_dir.glob("*.PF"))
        print(f"  [*] Found {len(pf_files)} .pf files")
        for pf in sorted(pf_files):
            rec = parse_pf_file(pf)
            if rec:
                records.append(rec)
        print(f"  [✓] Parsed {len(records)} prefetch entries")

    result = {
        "artifact":  "application_activity",
        "parsed_at": now_iso() + "Z",
        "count":     len(records),
        "records":   sorted(records, key=lambda r: r.get("last_run") or "", reverse=True),
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"  [✓] Written → {args.output}")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
