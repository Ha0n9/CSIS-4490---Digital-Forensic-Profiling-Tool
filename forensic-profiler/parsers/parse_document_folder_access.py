#!/usr/bin/env python3
"""
parse_document_folder_access.py
Parse LNK files and Jump Lists → document_folder_access.json

Uses pure struct-based LNK parser (no pylnk3 dependency).
pylnk3 has known issues with Win10 LNK files ("This is not a valid drive" error)
so we parse raw binary directly for reliability across XP/Win10/Win11.

Jump Lists: OLE/CFB + CustomDestinations, struct-only.
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

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Drive type map per MS-SHLLINK spec
DRIVE_TYPE_MAP = {
    0: "Unknown",
    1: "No root dir",
    2: "Removable",
    3: "Fixed",
    4: "Remote",
    5: "CDROM",
    6: "RAMDisk",
}

# =============================================================================
# LNK raw struct parser — covers XP + Vista + Win7 + Win10 + Win11
#
# MS-SHLLINK binary layout:
#   0x00  DWORD  HeaderSize (always 0x4C)
#   0x04  GUID   LinkCLSID
#   0x14  DWORD  LinkFlags
#   0x18  DWORD  FileAttributes
#   0x1C  QWORD  CreationTime   (FILETIME)
#   0x24  QWORD  AccessTime     (FILETIME)
#   0x2C  QWORD  WriteTime      (FILETIME)
#   0x34  DWORD  FileSize
#   0x38  DWORD  IconIndex
#   0x3C  DWORD  ShowCommand
#   0x40  WORD   HotKey
#   0x42  WORD   Reserved1
#   0x44  DWORD  Reserved2
#   0x48  DWORD  Reserved3
#   --- After header (0x4C) ---
#   [IDList]     if HasTargetIDList flag
#   [LinkInfo]   if HasLinkInfo flag
#   [StringData] variable count strings
#
# LinkInfo layout (offsets relative to LinkInfo start):
#   +0x00  DWORD  LinkInfoSize
#   +0x04  DWORD  LinkInfoHeaderSize  (0x1C for basic, 0x24 for extended)
#   +0x08  DWORD  LinkInfoFlags
#   +0x0C  DWORD  VolumeIDOffset      (relative to LinkInfo start)
#   +0x10  DWORD  LocalBasePathOffset (relative to LinkInfo start)
#   +0x14  DWORD  CommonNetworkRelativeLinkOffset
#   +0x18  DWORD  CommonPathSuffixOffset
#   (extended only, header >= 0x24:)
#   +0x1C  DWORD  LocalBasePathOffsetUnicode
#   +0x20  DWORD  CommonPathSuffixOffsetUnicode
#
# VolumeID layout (offsets relative to VolumeID start):
#   +0x00  DWORD  VolumeIDSize
#   +0x04  DWORD  DriveType
#   +0x08  DWORD  DriveSerialNumber
#   +0x0C  DWORD  VolumeLabelOffset   (relative to VolumeID start)
#   (if VolumeLabelOffset == 0x14, extended header with unicode label follows)
#   +0x10  DWORD  VolumeLabelOffsetUnicode (only if offset==0x14)
# =============================================================================

# LinkFlags bitmask
LF_HAS_TARGETIDLIST       = 0x00000001
LF_HAS_LINKINFO           = 0x00000002
LF_HAS_NAME               = 0x00000004
LF_HAS_RELATIVEPATH       = 0x00000008
LF_HAS_WORKINGDIR         = 0x00000010
LF_HAS_ARGUMENTS          = 0x00000020
LF_HAS_ICONLOCATION       = 0x00000040
LF_IS_UNICODE             = 0x00000080

# LinkInfoFlags bitmask
LIF_VOLUME_ID_AND_LOCAL   = 0x00000001
LIF_COMMON_NETWORK        = 0x00000002


def _read_sz(data: bytes, offset: int) -> str:
    """Read null-terminated ANSI string."""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("latin-1", errors="replace")


def _read_wsz(data: bytes, offset: int) -> str:
    """Read null-terminated UTF-16LE string."""
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    return data[offset:end].decode("utf-16-le", errors="replace")


def _read_counted(data: bytes, offset: int, unicode: bool) -> tuple[str, int]:
    """Read CountedString (2-byte count + chars). Returns (string, new_offset)."""
    if offset + 2 > len(data):
        return "", offset
    count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if unicode:
        s = data[offset:offset + count * 2].decode("utf-16-le", errors="replace")
        return s, offset + count * 2
    else:
        s = data[offset:offset + count].decode("latin-1", errors="replace")
        return s, offset + count


def parse_lnk_raw(lnk_path: Path, username: str) -> dict:
    rec: dict = {
        "type":            "lnk",
        "username":        username,
        "source_file":     lnk_path.name,
        "target_path":     "",
        "arguments":       "",
        "working_dir":     "",
        "drive_type":      "",
        "drive_serial":    "",
        "volume_label":    "",
        "target_created":  "",
        "target_modified": "",
        "target_accessed": "",
        "file_size":       "",
        "network_share":   "",
        "description":     "",
    }

    try:
        data = lnk_path.read_bytes()
    except Exception as e:
        rec["parse_error"] = f"read error: {e}"
        return rec

    # Validate LNK magic (header size = 0x4C)
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        rec["parse_error"] = "not a valid LNK file (bad header size)"
        return rec

    try:
        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        is_unicode  = bool(link_flags & LF_IS_UNICODE)

        # Target file timestamps + size (from Shell Link Header)
        ct = struct.unpack_from("<Q", data, 0x1C)[0]
        at = struct.unpack_from("<Q", data, 0x24)[0]
        mt = struct.unpack_from("<Q", data, 0x2C)[0]
        rec["target_created"]  = filetime_to_iso(ct)
        rec["target_accessed"] = filetime_to_iso(at)
        rec["target_modified"] = filetime_to_iso(mt)
        rec["file_size"]       = str(struct.unpack_from("<I", data, 0x34)[0])

        cursor = 0x4C  # start right after fixed header

        # ── IDList (skip it) ────────────────────────────────────────────────
        if link_flags & LF_HAS_TARGETIDLIST:
            if cursor + 2 > len(data):
                return rec
            idlist_size = struct.unpack_from("<H", data, cursor)[0]
            cursor += 2 + idlist_size

        # ── LinkInfo ────────────────────────────────────────────────────────
        if link_flags & LF_HAS_LINKINFO:
            if cursor + 0x1C > len(data):
                return rec

            li_base        = cursor
            li_size        = struct.unpack_from("<I", data, li_base + 0x00)[0]
            li_header_size = struct.unpack_from("<I", data, li_base + 0x04)[0]
            li_flags       = struct.unpack_from("<I", data, li_base + 0x08)[0]
            vol_id_off     = struct.unpack_from("<I", data, li_base + 0x0C)[0]
            local_path_off = struct.unpack_from("<I", data, li_base + 0x10)[0]
            net_link_off   = struct.unpack_from("<I", data, li_base + 0x14)[0]

            # Extended unicode offsets (header >= 0x24)
            local_path_off_uni = 0
            if li_header_size >= 0x24 and li_base + 0x20 <= len(data):
                local_path_off_uni = struct.unpack_from("<I", data, li_base + 0x1C)[0]

            # VolumeID block (only when VolumeIDAndLocalBasePath flag set)
            if li_flags & LIF_VOLUME_ID_AND_LOCAL and vol_id_off:
                vol_base = li_base + vol_id_off
                if vol_base + 0x10 <= len(data):
                    drive_type_val  = struct.unpack_from("<I", data, vol_base + 0x04)[0]
                    drive_serial    = struct.unpack_from("<I", data, vol_base + 0x08)[0]
                    label_off_ansi  = struct.unpack_from("<I", data, vol_base + 0x0C)[0]

                    rec["drive_type"]   = DRIVE_TYPE_MAP.get(drive_type_val, f"Unknown({drive_type_val})")
                    rec["drive_serial"] = f"{drive_serial:08X}"

                    # label_off_ansi == 0x14 → extended header has unicode label offset
                    if label_off_ansi == 0x14 and vol_base + 0x14 <= len(data):
                        label_off_uni = struct.unpack_from("<I", data, vol_base + 0x10)[0]
                        rec["volume_label"] = _read_wsz(data, vol_base + label_off_uni)
                    elif label_off_ansi:
                        rec["volume_label"] = _read_sz(data, vol_base + label_off_ansi)

            # Local path (prefer unicode if available)
            if li_flags & LIF_VOLUME_ID_AND_LOCAL:
                if local_path_off_uni and is_unicode:
                    rec["target_path"] = _read_wsz(data, li_base + local_path_off_uni)
                elif local_path_off:
                    rec["target_path"] = _read_sz(data, li_base + local_path_off)

            # Network share path
            if li_flags & LIF_COMMON_NETWORK and net_link_off:
                net_base = li_base + net_link_off
                if net_base + 0x14 <= len(data):
                    net_name_off = struct.unpack_from("<I", data, net_base + 0x08)[0]
                    if net_name_off:
                        rec["network_share"] = _read_sz(data, net_base + net_name_off)
                        if not rec["target_path"]:
                            rec["target_path"] = rec["network_share"]

            cursor = li_base + li_size if li_size > 0 else cursor + 0x1C

        # ── StringData ──────────────────────────────────────────────────────
        # Order: NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGS, ICON_LOCATION
        string_flags = [
            (LF_HAS_NAME,         "description"),
            (LF_HAS_RELATIVEPATH, None),
            (LF_HAS_WORKINGDIR,   "working_dir"),
            (LF_HAS_ARGUMENTS,    "arguments"),
            (LF_HAS_ICONLOCATION, None),
        ]
        for flag, field in string_flags:
            if link_flags & flag:
                s, cursor = _read_counted(data, cursor, is_unicode)
                if field:
                    rec[field] = s

    except Exception as e:
        rec["parse_error"] = f"struct parse error: {e}"

    return rec


# =============================================================================
# Jump List parser
# =============================================================================

def parse_jump_list(jl_path: Path, username: str) -> dict:
    rec: dict = {
        "type":        "jump_list",
        "username":    username,
        "source_file": jl_path.name,
        "app_id":      jl_path.stem,
        "entry_count": 0,
        "entries":     [],
    }
    try:
        data = jl_path.read_bytes()
    except Exception as e:
        rec["parse_error"] = str(e)
        return rec

    # CustomDestinations: starts with LNK magic
    if data[:4] == b"\x4C\x00\x00\x00":
        offset = 0
        entries = []
        while offset < len(data) - 76:
            if data[offset:offset + 4] == b"\x4C\x00\x00\x00":
                mt = struct.unpack_from("<Q", data, offset + 0x2C)[0] if offset + 0x34 <= len(data) else 0
                entries.append({"offset": offset, "modified": filetime_to_iso(mt)})
                rs = struct.unpack_from("<I", data, offset + 0x34)[0] if offset + 0x38 <= len(data) else 0
                offset += max(76, rs if 0 < rs < 0x10000 else 76)
            else:
                offset += 4
        rec["entry_count"] = len(entries)
        rec["entries"] = entries[:20]
        return rec

    # AutomaticDestinations: OLE CFB
    if data[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        lnk_count = data.count(b"\x4C\x00\x00\x00\x01\x14\x02\x00")
        rec["entry_count"] = lnk_count
        rec["note"] = "AutomaticDestinations OLE CFB"

    return rec


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="Parse LNK + Jump Lists → document_folder_access.json")
    ap.add_argument("--raw-dir",  required=True)
    ap.add_argument("--output",   required=True)
    ap.add_argument("--json-dir", default="")
    args = ap.parse_args()

    raw = Path(args.raw_dir)
    all_records: list[dict] = []
    error_count = 0

    # LNK files
    lnk_dir = raw / "lnk_files"
    lnk_count = 0
    if lnk_dir.is_dir():
        for user_dir in sorted(lnk_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            uname = user_dir.name
            for lnk_file in sorted(
                list(user_dir.glob("*.lnk")) + list(user_dir.glob("*.LNK"))
            ):
                rec = parse_lnk_raw(lnk_file, uname)
                if "parse_error" in rec:
                    error_count += 1
                all_records.append(rec)
                lnk_count += 1
        print(f"[✓] {lnk_count} LNK files parsed ({error_count} errors)")

    # Jump lists
    jl_dir = raw / "jump_lists"
    jl_count = 0
    if jl_dir.is_dir():
        for user_dir in sorted(jl_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            uname = user_dir.name
            for jl_file in sorted(user_dir.iterdir()):
                if jl_file.is_file():
                    all_records.append(parse_jump_list(jl_file, uname))
                    jl_count += 1
        print(f"[✓] {jl_count} jump list files parsed")

    result = {
        "artifact":  "document_folder_access",
        "parsed_at": now_iso() + "Z",
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
