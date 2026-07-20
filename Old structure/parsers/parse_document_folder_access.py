#!/usr/bin/env python3
"""
parse_document_folder_access.py
Parse LNK files and Jump Lists → document_folder_access.json

LNK: uses pylnk3 (python-pylnk3)
Jump Lists: OLE/CFB compound files — parsed with struct (no extra deps)

No EZ Tools required.
"""

import argparse
import json
import os
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import pylnk3
    HAS_PYLNK = True
except ImportError:
    HAS_PYLNK = False
    print("[!] pylnk3 not installed — LNK metadata will be limited", file=sys.stderr)

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(ft: int) -> str:
    if ft == 0:
        return ""
    try:
        return (WINDOWS_EPOCH + timedelta(microseconds=ft // 10)).isoformat()
    except Exception:
        return ""


# =============================================================================
# LNK parser
# =============================================================================

def parse_lnk_pylnk(lnk_path: Path, username: str) -> dict:
    """Parse using pylnk3 library."""
    rec = {
        "type":          "lnk",
        "username":      username,
        "source_file":   lnk_path.name,
        "target_path":   "",
        "arguments":     "",
        "working_dir":   "",
        "drive_type":    "",
        "volume_label":  "",
        "target_created":  "",
        "target_modified": "",
        "target_accessed": "",
        "file_size":     "",
        "network_share": "",
        "description":   "",
    }
    try:
        lnk = pylnk3.for_file(str(lnk_path))

        # Target path
        if hasattr(lnk, "local_path") and lnk.local_path:
            rec["target_path"] = lnk.local_path
        elif hasattr(lnk, "network_path") and lnk.network_path:
            rec["target_path"] = lnk.network_path
            rec["network_share"] = lnk.network_path

        if hasattr(lnk, "arguments") and lnk.arguments:
            rec["arguments"] = lnk.arguments
        if hasattr(lnk, "working_dir") and lnk.working_dir:
            rec["working_dir"] = lnk.working_dir
        if hasattr(lnk, "description") and lnk.description:
            rec["description"] = lnk.description

        # File times
        if hasattr(lnk, "file_time") and lnk.file_time:
            ft = lnk.file_time
            rec["target_modified"] = ft.isoformat() if hasattr(ft, "isoformat") else str(ft)
        if hasattr(lnk, "create_time") and lnk.create_time:
            ct = lnk.create_time
            rec["target_created"] = ct.isoformat() if hasattr(ct, "isoformat") else str(ct)
        if hasattr(lnk, "access_time") and lnk.access_time:
            at = lnk.access_time
            rec["target_accessed"] = at.isoformat() if hasattr(at, "isoformat") else str(at)

        if hasattr(lnk, "file_size") and lnk.file_size:
            rec["file_size"] = str(lnk.file_size)

        # Drive info from link_info
        if hasattr(lnk, "link_info") and lnk.link_info:
            li = lnk.link_info
            if hasattr(li, "drive_type"):
                rec["drive_type"] = str(li.drive_type)
            if hasattr(li, "volume_label") and li.volume_label:
                rec["volume_label"] = li.volume_label

    except Exception as e:
        rec["parse_error"] = str(e)

    return rec


def parse_lnk_raw(lnk_path: Path, username: str) -> dict:
    """Minimal fallback LNK parser using raw struct (no pylnk3)."""
    rec = {
        "type":        "lnk",
        "username":    username,
        "source_file": lnk_path.name,
        "target_path": "",
    }
    try:
        data = lnk_path.read_bytes()
        if len(data) < 76 or data[0:4] != b"\x4C\x00\x00\x00":
            return rec

        link_flags  = struct.unpack_from("<I", data, 0x14)[0]
        file_attribs = struct.unpack_from("<I", data, 0x18)[0]

        # File times (FILETIME at 0x1C, 0x24, 0x2C)
        ct = struct.unpack_from("<Q", data, 0x1C)[0]
        at = struct.unpack_from("<Q", data, 0x24)[0]
        mt = struct.unpack_from("<Q", data, 0x2C)[0]

        rec["target_created"]  = filetime_to_iso(ct)
        rec["target_accessed"] = filetime_to_iso(at)
        rec["target_modified"] = filetime_to_iso(mt)
        rec["file_size"]       = str(struct.unpack_from("<I", data, 0x34)[0])

        # If HasLinkTargetIDList flag set, skip ID list
        offset = 76
        if link_flags & 0x01:
            if len(data) > offset + 2:
                idlist_size = struct.unpack_from("<H", data, offset)[0]
                offset += 2 + idlist_size

        # LinkInfo structure
        if link_flags & 0x02 and len(data) > offset + 28:
            li_size    = struct.unpack_from("<I", data, offset)[0]
            li_flags   = struct.unpack_from("<I", data, offset + 8)[0]
            local_off  = struct.unpack_from("<I", data, offset + 16)[0]
            net_off    = struct.unpack_from("<I", data, offset + 20)[0]
            tail_off   = struct.unpack_from("<I", data, offset + 24)[0]

            if li_flags & 0x01 and local_off:  # VolumeID + LocalBasePath
                path_start = offset + local_off
                path_end = data.find(b"\x00", path_start)
                if path_end > path_start:
                    rec["target_path"] = data[path_start:path_end].decode("latin-1", errors="replace")

        # String data (after LinkInfo)
        # HasName = 0x04, HasRelativePath = 0x08, HasWorkingDir = 0x10, HasArguments = 0x20
        str_offset = offset + (struct.unpack_from("<I", data, offset)[0] if link_flags & 0x02 else 0)
        is_unicode = bool(link_flags & 0x80)  # IsUnicode flag

        def read_count_string(off: int) -> tuple[str, int]:
            if off + 2 > len(data):
                return "", off
            count = struct.unpack_from("<H", data, off)[0]
            off += 2
            if is_unicode:
                s = data[off:off + count * 2].decode("utf-16-le", errors="replace")
                return s, off + count * 2
            else:
                s = data[off:off + count].decode("latin-1", errors="replace")
                return s, off + count

        so = str_offset
        if link_flags & 0x04:   # NAME_STRING
            _, so = read_count_string(so)
        if link_flags & 0x08:   # RELATIVE_PATH
            _, so = read_count_string(so)
        if link_flags & 0x10:   # WORKING_DIR
            wd, so = read_count_string(so)
            rec["working_dir"] = wd
        if link_flags & 0x20:   # COMMAND_LINE_ARGUMENTS
            args, so = read_count_string(so)
            rec["arguments"] = args

    except Exception as e:
        rec["parse_error"] = str(e)

    return rec


def parse_lnk(lnk_path: Path, username: str) -> dict:
    if HAS_PYLNK:
        return parse_lnk_pylnk(lnk_path, username)
    return parse_lnk_raw(lnk_path, username)


# =============================================================================
# Jump List parser — reads AppID + embedded LNK blocks from .automaticDestinations
# (OLE CFB compound file; we extract AppID from filename and count entries)
# =============================================================================

def parse_jump_list(jl_path: Path, username: str) -> dict:
    """
    Parse jump list file.
    AutomaticDestinations: OLE CFB compound file containing LNK streams.
    CustomDestinations: series of LNK files concatenated.
    """
    rec = {
        "type":           "jump_list",
        "username":       username,
        "source_file":    jl_path.name,
        "app_id":         jl_path.stem,
        "app_description": "",
        "entry_count":    0,
        "entries":        [],
    }

    data = b""
    try:
        data = jl_path.read_bytes()
    except Exception as e:
        rec["parse_error"] = str(e)
        return rec

    # CustomDestinations: starts with LNK magic (4C 00 00 00)
    if data[:4] == b"\x4C\x00\x00\x00":
        # Series of LNK blobs separated by some padding
        offset = 0
        entries = []
        while offset < len(data) - 76:
            if data[offset:offset+4] == b"\x4C\x00\x00\x00":
                # Extract modified time from this LNK block
                mt = struct.unpack_from("<Q", data, offset + 0x2C)[0] if offset + 0x34 <= len(data) else 0
                entries.append({
                    "offset": offset,
                    "modified": filetime_to_iso(mt),
                })
                # Advance past this LNK (use stored size if available)
                rec_size = struct.unpack_from("<I", data, offset + 0x34)[0] if offset + 0x38 <= len(data) else 0
                offset += max(76, rec_size if rec_size < 0x10000 else 76)
            else:
                offset += 4
        rec["entry_count"] = len(entries)
        rec["entries"] = entries[:20]  # cap at 20
        return rec

    # AutomaticDestinations: OLE CFB
    # CFB header magic: D0 CF 11 E0 A1 B1 1A E1
    if data[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        # Count LNK streams by scanning for LNK magic inside the compound file
        lnk_count = data.count(b"\x4C\x00\x00\x00\x01\x14\x02\x00")
        rec["entry_count"] = lnk_count
        rec["note"] = "AutomaticDestinations OLE CFB — use LECmd/JLECmd for full parse"

    return rec


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Parse LNK + Jump Lists → document_folder_access.json"
    )
    ap.add_argument("--raw-dir",  required=True, help="raw/ directory from extraction")
    ap.add_argument("--output",   required=True, help="Output JSON file")
    ap.add_argument("--json-dir", default="",    help="(unused, legacy compat)")
    args = ap.parse_args()

    raw = Path(args.raw_dir)
    lnk_dir = raw / "lnk_files"
    jl_dir  = raw / "jump_lists"

    all_records: list[dict] = []

    # LNK files
    if lnk_dir.is_dir():
        for user_dir in sorted(lnk_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            uname = user_dir.name
            for lnk_file in sorted(user_dir.glob("*.lnk")) + sorted(user_dir.glob("*.LNK")):
                rec = parse_lnk(lnk_file, uname)
                all_records.append(rec)
        print(f"[✓] {sum(1 for r in all_records if r['type']=='lnk')} LNK files parsed")

    # Jump lists
    jl_records: list[dict] = []
    if jl_dir.is_dir():
        for user_dir in sorted(jl_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            uname = user_dir.name
            for jl_file in sorted(user_dir.iterdir()):
                if jl_file.is_file():
                    jl_records.append(parse_jump_list(jl_file, uname))
        all_records.extend(jl_records)
        print(f"[✓] {len(jl_records)} jump list files parsed")

    result = {
        "artifact":  "document_folder_access",
        "parsed_at": datetime.now(timezone.utc).isoformat() + "Z",
        "count":     len(all_records),
        "records":   all_records,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"[✓] Written → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())