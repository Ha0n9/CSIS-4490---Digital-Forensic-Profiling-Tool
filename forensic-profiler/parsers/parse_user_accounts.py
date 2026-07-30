#!/usr/bin/env python3
"""
parse_user_accounts.py
Parse SAM + NTUSER.DAT hives directly using python-registry → user_accounts.json

No EZ Tools required.
"""

import argparse
import codecs
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from Registry import Registry
except ImportError:
    print("[!] Missing: pip install python-registry --break-system-packages", file=sys.stderr)
    sys.exit(1)

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(ft: int) -> str:
    try:
        return (WINDOWS_EPOCH + timedelta(microseconds=ft // 10)).isoformat()
    except Exception:
        return ""


def open_hive(path: Path):
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        print(f"[!] Cannot open {path}: {e}", file=sys.stderr)
        return None


def parse_sam(sam_path: Path) -> list[dict]:
    """Extract user accounts from SAM hive."""
    users = []
    reg = open_hive(sam_path)
    if not reg:
        return users

    try:
        sam_users = reg.open("SAM\\Domains\\Account\\Users")
    except Exception as e:
        print(f"[!] SAM\\Domains\\Account\\Users not found: {e}", file=sys.stderr)
        return users

    # Iterate RID subkeys (hex RID names like '000001F4')
    for subkey in sam_users.subkeys():
        name = subkey.name()
        if name == "Names":
            continue
        try:
            rid = int(name, 16)
        except ValueError:
            continue

        user = {"rid": rid, "rid_hex": name, "source": "SAM"}

        # V value contains username and various account data (binary blob)
        try:
            v_val = subkey.value("V").raw_data()
            # Username offset/length at 0x0C/0x10 (relative to 0xCC base)
            import struct
            uname_off = struct.unpack_from("<I", v_val, 0x0C)[0] + 0xCC
            uname_len = struct.unpack_from("<I", v_val, 0x10)[0]
            if uname_len > 0 and uname_off + uname_len <= len(v_val):
                user["username"] = v_val[uname_off:uname_off + uname_len].decode("utf-16-le", errors="replace")

            # Full name
            fn_off = struct.unpack_from("<I", v_val, 0x18)[0] + 0xCC
            fn_len = struct.unpack_from("<I", v_val, 0x1C)[0]
            if fn_len > 0 and fn_off + fn_len <= len(v_val):
                user["full_name"] = v_val[fn_off:fn_off + fn_len].decode("utf-16-le", errors="replace")

            # Comment / description
            cm_off = struct.unpack_from("<I", v_val, 0x24)[0] + 0xCC
            cm_len = struct.unpack_from("<I", v_val, 0x28)[0]
            if cm_len > 0 and cm_off + cm_len <= len(v_val):
                user["description"] = v_val[cm_off:cm_off + cm_len].decode("utf-16-le", errors="replace")

            # NOTE: account control flags (disabled/locked/pwd-never-expires)
            # are NOT stored here. V is a variable-length string/SID blob —
            # it has no fixed flags field. Those flags live in the F value
            # (see below); see also account_disabled/account_locked/
            # password_never_expires there.

        except Exception as e:
            user["v_parse_error"] = str(e)

        # F value: last login, password last set, etc.
        try:
            f_val = subkey.value("F").raw_data()
            import struct
            # Last login time at 0x08 (FILETIME)
            ll_ft = struct.unpack_from("<Q", f_val, 0x08)[0]
            user["last_login"] = filetime_to_iso(ll_ft) if ll_ft else ""

            # Password last set at 0x18
            ps_ft = struct.unpack_from("<Q", f_val, 0x18)[0]
            user["password_last_set"] = filetime_to_iso(ps_ft) if ps_ft else ""

            # Account expiry at 0x20
            ex_ft = struct.unpack_from("<Q", f_val, 0x20)[0]
            user["account_expires"] = filetime_to_iso(ex_ft) if ex_ft not in (0, 0x7FFFFFFFFFFFFFFF) else "Never"

            # Account Control Block (ACB) flags — WORD at 0x38 in the F
            # value (not the V value — see the comment left in the V-value
            # block above). Bit layout per the documented SAM F-value
            # structure (RegRipper samparse.pl / Passcape SAM notes — the
            # same reference family the other F-value offsets above follow):
            #   0x0001  Account Disabled
            #   0x0002  Home directory required
            #   0x0004  Password not required
            #   0x0008  Temporary duplicate account
            #   0x0010  Normal user account
            #   0x0020  MNS logon user account
            #   0x0200  Password does not expire
            #   0x0400  Account auto locked
            acb_flags = struct.unpack_from("<H", f_val, 0x38)[0] if len(f_val) > 0x3A else 0
            user["account_disabled"] = bool(acb_flags & 0x0001)
            user["password_never_expires"] = bool(acb_flags & 0x0200)
            user["account_locked"] = bool(acb_flags & 0x0400)

            # Failed login count at 0x40 (2 bytes)
            user["failed_logins"] = struct.unpack_from("<H", f_val, 0x40)[0] if len(f_val) > 0x42 else 0

            # Login count at 0x42
            user["login_count"] = struct.unpack_from("<H", f_val, 0x42)[0] if len(f_val) > 0x44 else 0

        except Exception as e:
            user["f_parse_error"] = str(e)

        # Last write time of the subkey = last account modification
        try:
            lw = subkey.timestamp()
            user["last_modified"] = lw.isoformat() if lw else ""
        except Exception:
            pass

        users.append(user)

    # Also grab usernames from Names subkey (simpler, just names + RIDs)
    try:
        names_key = sam_users.open("Names")
        name_map = {sk.name(): sk for sk in names_key.subkeys()}
        # Merge usernames into user records by matching RID
        for user in users:
            rid_hex = f"{user['rid']:08X}"
            for uname, sk in name_map.items():
                try:
                    # The default value type encodes the RID
                    rid_from_name = sk.value("(default)").value_type()
                    if rid_from_name == user["rid"] and "username" not in user:
                        user["username"] = uname
                except Exception:
                    pass
    except Exception:
        pass

    return users


def parse_ntuser_run_keys(ntuser_path: Path, username: str) -> list[dict]:
    """Extract Run/RunOnce autostart entries from NTUSER.DAT."""
    entries = []
    reg = open_hive(ntuser_path)
    if not reg:
        return entries

    run_paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    ]
    for rp in run_paths:
        try:
            key = reg.open(rp)
            for val in key.values():
                entries.append({
                    "username": username,
                    "key": rp,
                    "name": val.name(),
                    "data": str(val.value()),
                    "last_modified": key.timestamp().isoformat() if key.timestamp() else "",
                })
        except Exception:
            pass

    return entries


# =============================================================================
# UserAssist — per-user program execution history
#
# UserAssist tracks GUI-launched programs (Explorer double-clicks, Start
# Menu, taskbar) under each user's own NTUSER.DAT. Unlike Prefetch (system-
# wide, weak per-user attribution — see correlation/engine.py's score_app()),
# a UserAssist entry can only exist inside the specific user's own hive, so
# it is unambiguous per-user evidence by construction.
#
# Value names under each GUID's \Count subkey are ROT13-encoded (a long-
# standing, non-cryptographic Windows convention — not a security measure),
# uniformly — including the housekeeping/counter entries, not just program
# launches. Two confirmed naming conventions exist across Windows versions
# (confirmed against real captured hives during validation, one XP-era
# image and one Windows 10 image):
#   XP/Vista: decoded name is prefixed "UEME_RUNPATH:" (executables) or
#             "UEME_RUNPIDL:"/"UEME_RUNCPL:" (shell namespace items).
#   Win7+:    no "UEME_RUN*" prefix at all — the decoded name IS the raw
#             path / AppUserModelID / .lnk target directly (e.g.
#             "Microsoft.Getstarted_8wekyb3d8bbwe!App", "C:\Users\Public\
#             Desktop\Google Chrome.lnk").
# Across every version, "UEME_CTL*" entries (e.g. "UEME_CTLSESSION", a
# session counter; "UEME_CTLCUACount:ctor", a UAC-prompt counter) are
# session/UI bookkeeping, never a program launch, and must be excluded —
# checked on the *decoded* name, since they are ROT13-encoded exactly like
# every other value name in this key, not stored literally.
# =============================================================================

# GUIDs differ entirely between XP and Vista+ (confirmed against a real XP
# hive during validation, which has no CEBFF5CD-.../F4E57C4B-... subkeys at
# all — only the pair below). Both pairs are checked unconditionally; a
# hive only ever populates the pair matching its own OS version, and the
# other pair's reg.open() simply fails and is skipped (see below).
#   XP:      5E6AB780-... : EXE launch history
#            75048700-... : Explorer/shell namespace item history
#   Vista+:  CEBFF5CD-... : EXE launch history
#            F4E57C4B-... : Explorer/shell namespace item history
USERASSIST_GUIDS = [
    "5E6AB780-7743-11CF-A12B-00AA004AE837",
    "75048700-EF1F-11D0-9888-006097DEACF9",
    "CEBFF5CD-ACE2-4F4F-9178-9926F41749EA",
    "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F",
]

_UEME_RUN_PREFIX_RE = re.compile(r"^UEME_RUN(?:PATH|PIDL|CPL):", re.I)


def _rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def _userassist_program_name(decoded_name: str) -> str | None:
    """
    Given an already-ROT13-decoded UserAssist value name, return the
    program/path it represents, or None if the name is UI/session
    bookkeeping rather than an actual program-launch record.

    Any "UEME_"-prefixed name is either a real XP/Vista-era program record
    ("UEME_RUNPATH:<path>"/"UEME_RUNPIDL:<pidl>", with an actual identifier
    after the colon) or an aggregate UI/session counter that is NOT tied to
    a specific program — confirmed present in real captured hives:
    "UEME_CTLSESSION", "UEME_CTLCUACount:ctor", "UEME_UITOOLBAR",
    "UEME_UITOOLBAR:0x1,120", "UEME_UISCUT", and even a bare
    "UEME_RUNPATH"/"UEME_RUNPIDL" with nothing after it at all. Only a
    genuine "UEME_RUNPATH:"/"UEME_RUNPIDL:"/"UEME_RUNCPL:" prefix (colon
    required) counts as a program record; anything else "UEME_"-shaped is
    bookkeeping and returns None.

    A name with no "UEME_" prefix at all is the Win7+ convention: no
    wrapper — the decoded name IS the path/AppUserModelID/.lnk target
    directly (e.g. "Microsoft.Getstarted_8wekyb3d8bbwe!App",
    "C:\\Users\\Public\\Desktop\\Google Chrome.lnk").
    """
    if decoded_name.upper().startswith("UEME_"):
        m = _UEME_RUN_PREFIX_RE.match(decoded_name)
        if not m:
            return None
        program = decoded_name[m.end():].strip()
    else:
        program = decoded_name.strip()
    return program or None


def _parse_userassist_count_value(raw: bytes) -> dict | None:
    """
    Decode a UserAssist \\Count value's binary payload into run_count and
    last_run. Layout differs by Windows version, keyed off the value's
    total length (there is no in-band version field):
      16-67 bytes (XP):     run_count DWORD @ 0x04, last_run FILETIME @ 0x08
      68+ bytes   (Vista+): run_count DWORD @ 0x04, last_run FILETIME @ 0x3C
    Any other (shorter) length is skipped rather than guessed at.
    """
    n = len(raw)
    try:
        if 16 <= n < 68:
            run_count = struct.unpack_from("<I", raw, 0x04)[0]
            ft = struct.unpack_from("<Q", raw, 0x08)[0]
            layout = "xp"
        elif n >= 68:
            run_count = struct.unpack_from("<I", raw, 0x04)[0]
            ft = struct.unpack_from("<Q", raw, 0x3C)[0]
            layout = "vista+"
        else:
            return None
    except Exception:
        return None
    return {
        "run_count": run_count,
        "last_run": filetime_to_iso(ft) if ft else "",
        "layout": layout,
    }


def parse_ntuser_userassist(ntuser_path: Path, username: str) -> list[dict]:
    """Extract UserAssist program-execution history from NTUSER.DAT."""
    entries: list[dict] = []
    reg = open_hive(ntuser_path)
    if not reg:
        return entries

    for guid in USERASSIST_GUIDS:
        key_path = (
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
            f"UserAssist\\{{{guid}}}\\Count"
        )
        try:
            key = reg.open(key_path)
        except Exception:
            continue

        for val in key.values():
            raw_name = val.name()
            try:
                decoded_name = _rot13(raw_name)
            except Exception:
                continue

            program = _userassist_program_name(decoded_name)
            if not program:
                continue
            try:
                raw_val = val.raw_data()
            except Exception:
                continue
            parsed = _parse_userassist_count_value(raw_val)
            if parsed is None:
                continue
            entries.append({
                "username": username,
                "program": program,
                "run_count": parsed["run_count"],
                "last_run": parsed["last_run"],
                "guid": guid,
                "layout": parsed["layout"],
            })

    return entries


def parse_ntuser_typed_paths(ntuser_path: Path, username: str) -> list[dict]:
    """Extract TypedPaths (address bar history) from NTUSER.DAT."""
    entries = []
    reg = open_hive(ntuser_path)
    if not reg:
        return entries
    try:
        key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
        for val in key.values():
            entries.append({
                "username": username,
                "type": "TypedPath",
                "value": str(val.value()),
            })
    except Exception:
        pass
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse SAM + NTUSER.DAT → user_accounts.json")
    ap.add_argument("--raw-dir",  required=True, help="raw/ directory from extraction")
    ap.add_argument("--output",   required=True, help="Output JSON file")
    # Legacy compat args (ignored — kept so bash script doesn't break)
    ap.add_argument("--json-dir", default="", help="(unused, legacy compat)")
    args = ap.parse_args()

    raw = Path(args.raw_dir)
    hives_dir = raw / "hives"

    users: list[dict] = []
    autorun: list[dict] = []
    typed_paths: list[dict] = []
    userassist: list[dict] = []

    # SAM
    sam_path = hives_dir / "system" / "SAM"
    if sam_path.exists():
        print(f"[*] Parsing SAM: {sam_path}")
        users = parse_sam(sam_path)
        print(f"[✓] {len(users)} user accounts from SAM")
    else:
        print(f"[!] SAM not found at {sam_path}", file=sys.stderr)

    # NTUSER.DAT per user
    users_dir = hives_dir / "users"
    if users_dir.is_dir():
        for user_dir in sorted(users_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            uname = user_dir.name
            ntuser = user_dir / "NTUSER.DAT"
            if ntuser.exists():
                print(f"[*] Parsing NTUSER.DAT: {uname}")
                autorun.extend(parse_ntuser_run_keys(ntuser, uname))
                typed_paths.extend(parse_ntuser_typed_paths(ntuser, uname))
                ua = parse_ntuser_userassist(ntuser, uname)
                userassist.extend(ua)
                print(f"    UserAssist: {len(ua)} entries")

    result = {
        "artifact": "user_accounts",
        "parsed_at": datetime.now(timezone.utc).isoformat() + "Z",
        "users": {"count": len(users), "records": users},
        "autorun_entries": {"count": len(autorun), "records": autorun},
        "typed_paths": {"count": len(typed_paths), "records": typed_paths},
        "userassist": {"count": len(userassist), "records": userassist},
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"[✓] Written → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())