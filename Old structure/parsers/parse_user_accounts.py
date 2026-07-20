#!/usr/bin/env python3
"""
parse_user_accounts.py
Parse SAM + NTUSER.DAT hives directly using python-registry → user_accounts.json

No EZ Tools required.
"""

import argparse
import json
import os
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

            # Account flags (at fixed offset 0x90 in V value on XP)
            acc_flags = struct.unpack_from("<H", v_val, 0x90)[0] if len(v_val) > 0x92 else 0
            user["account_disabled"] = bool(acc_flags & 0x01)
            user["password_never_expires"] = bool(acc_flags & 0x08)
            user["account_locked"] = bool(acc_flags & 0x10)

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

    result = {
        "artifact": "user_accounts",
        "parsed_at": datetime.now(timezone.utc).isoformat() + "Z",
        "users": {"count": len(users), "records": users},
        "autorun_entries": {"count": len(autorun), "records": autorun},
        "typed_paths": {"count": len(typed_paths), "records": typed_paths},
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    print(f"[✓] Written → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())