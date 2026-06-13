#!/usr/bin/env python3
"""
parse_event_logs.py
Artifact : Event Logs + Network Activity
Sources  : .evtx (Windows Vista+) via python-evtx
           .evt  (Windows XP)     via basic binary parsing (no deprecated libs)

Usage:
    python3 parse_event_logs.py --raw-dir <raw/event_logs> --output <event.json> --network <network.json>
    python3 parse_event_logs.py --mount <mount_point>      --output <event.json> --network <network.json>
"""

import argparse
import json
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# Event ID categories
# NOTE: includes both modern (Vista+) and legacy XP IDs
# =============================================================================

NETWORK_EVENT_IDS = {
    # ── Modern Windows (Vista/7/10/11) ────────────────────────────────────────
    3,                              # Sysmon: network connection
    22,                             # Sysmon: DNS query
    4001, 4002, 4004,               # WLAN connect/disconnect
    10000, 10001, 1002,             # Network profile / firewall
    5156, 5157, 5158,               # WFP allow/block connection
    4778, 4779,                     # RDP session connect/disconnect
    5140, 5142, 5144, 5145,         # Network share access
    8001, 8002, 8003,               # WLAN-AutoConfig operational
    11000, 11001, 11002,            # WLAN association
    20225, 20226,                   # VPN / RAS
    2003, 2004, 2005,               # Windows Firewall rule changes
    30800, 30803, 30804,            # SMB client connectivity
    3008, 3020,                     # DNS Client
    50066, 50067, 50068, 50073, 50074,  # DHCP
    # ── Windows XP legacy (.evt) ──────────────────────────────────────────────
    528,    # Successful logon (XP) — type 3 = network logon
    529,    # Logon failure: unknown username or bad password
    530,    # Logon failure: account logon time restriction
    531,    # Logon failure: account currently disabled
    532,    # Logon failure: user account has expired
    533,    # Logon failure: user not allowed to log on to this computer
    534,    # Logon failure: user has not been granted the requested logon type
    535,    # Logon failure: the specified account's password has expired
    536,    # Logon failure: the NetLogon component is not active
    537,    # Logon failure: unexpected error
    539,    # Logon failure: account locked out
    540,    # Successful network logon (XP key network event)
    541,    # IPsec main mode SA established
    542,    # IPsec main mode SA ended
    543,    # IPsec main mode SA ended (initiator)
    544,    # IPsec main mode authentication failed
    545,    # IPsec peer authentication failed
    546,    # IKE security association establishment failed
    547,    # IKE negotiation failed
    576,    # Special privileges assigned to new logon (admin escalation)
    682,    # Session reconnected to window station
    683,    # Session disconnected from window station
    861,    # Windows Firewall: allowed a new program to accept incoming connections
}

LOGON_EVENT_IDS = {
    # Modern
    4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769,
    # XP legacy
    528, 529, 538,   # logon success, failure, logoff
    540,             # network logon (XP)
    576,             # special privileges
    680,             # account used for logon by SAM
}

PROCESS_EVENT_IDS = {
    4688, 4689,   # modern: process create/exit
    592,  593,    # XP: process create/exit
}

SERVICE_EVENT_IDS = {
    7045, 4697, 7036,   # modern: service installed/changed/state-change
    7000, 7001, 7002,   # XP: service failed, stopped, start-pending
}

# =============================================================================
# Helpers
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_ts(ts: str | None) -> str | None:
    if not ts:
        return None
    ts = ts.strip().rstrip("Z")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return ts


def filetime_to_iso(filetime: int) -> str | None:
    try:
        unix_ts = (filetime - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
    except Exception:
        return None

# =============================================================================
# EVTX parser (python-evtx)
# =============================================================================

def _parse_evtx_xml(xml_str: str, file_name: str) -> dict | None:
    try:
        root = ET.fromstring(xml_str)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        system = root.find("e:System", ns) or root.find("System")
        if system is None:
            return None

        def get_text(tag: str) -> str | None:
            n = system.find(f"e:{tag}", ns) or system.find(tag)
            return n.text if n is not None else None

        def get_attr(tag: str, attr: str) -> str | None:
            n = system.find(f"e:{tag}", ns) or system.find(tag)
            return n.attrib.get(attr) if n is not None else None

        event_id_raw = get_text("EventID")
        event_id = int(event_id_raw) if event_id_raw and event_id_raw.isdigit() else None

        event_data_el = root.find("e:EventData", ns) or root.find("EventData")
        event_data: dict = {}
        if event_data_el is not None:
            for data in event_data_el:
                name = data.attrib.get("Name", f"Data_{len(event_data)}")
                event_data[name] = data.text or ""

        return {
            "source_format": "evtx",
            "file":          file_name,
            "event_id":      event_id,
            "provider":      get_attr("Provider", "Name"),
            "timestamp":     normalize_ts(get_attr("TimeCreated", "SystemTime")),
            "computer":      get_text("Computer"),
            "level":         get_text("Level"),
            "channel":       get_text("Channel"),
            "record_id":     get_text("EventRecordID"),
            "event_data":    event_data,
        }
    except Exception:
        return None


def parse_evtx_file(file_path: Path) -> list[dict]:
    events = []
    try:
        from Evtx.Evtx import Evtx
        with Evtx(str(file_path)) as log:
            for record in log.records():
                try:
                    e = _parse_evtx_xml(record.xml(), file_path.name)
                    if e:
                        events.append(e)
                except Exception:
                    continue
    except ImportError:
        print("  [!] python-evtx not installed: sudo pip install python-evtx --break-system-packages")
    except Exception as err:
        print(f"  [!] EVTX error {file_path.name}: {err}")
    return events

# =============================================================================
# EVT parser — Windows XP binary format, pure struct (no deprecated libs)
#
# Record layout:
#   0x00  DWORD  Length
#   0x04  DWORD  Magic = "LfLe"
#   0x08  DWORD  RecordNumber
#   0x0C  DWORD  TimeGenerated  (Unix timestamp)
#   0x10  DWORD  TimeWritten    (Unix timestamp)
#   0x14  DWORD  EventID (low 16 bits)
#   0x18  WORD   EventType
#   0x1A  WORD   NumStrings
#   0x24  DWORD  StringOffset
#   0x38  ...    SourceName (null-terminated UTF-16LE)
#          ...    ComputerName
#          ...    Strings
# =============================================================================

EVT_HEADER_MAGIC = b"LfLe"
EVT_RECORD_FIXED = 56

EVT_LEVEL_MAP = {
    1: "Error",
    2: "Warning",
    4: "Information",
    8: "Success Audit",
    16: "Failure Audit",
}


def _read_utf16_string(data: bytes, offset: int) -> tuple[str, int]:
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    try:
        s = data[offset:end].decode("utf-16-le", errors="replace")
    except Exception:
        s = ""
    return s, end + 2


def _parse_evt_record(data: bytes, file_name: str) -> dict | None:
    if len(data) < EVT_RECORD_FIXED:
        return None
    try:
        magic        = data[0x04:0x08]
        if magic != EVT_HEADER_MAGIC:
            return None

        record_num   = struct.unpack_from("<I", data, 0x08)[0]
        time_gen     = struct.unpack_from("<I", data, 0x0C)[0]
        event_id_raw = struct.unpack_from("<I", data, 0x14)[0]
        event_type   = struct.unpack_from("<H", data, 0x18)[0]
        num_strings  = struct.unpack_from("<H", data, 0x1A)[0]
        str_offset   = struct.unpack_from("<I", data, 0x24)[0]

        event_id = event_id_raw & 0xFFFF

        try:
            timestamp = datetime.fromtimestamp(time_gen, tz=timezone.utc).isoformat()
        except Exception:
            timestamp = None

        source_name, pos = _read_utf16_string(data, 0x38)
        computer_name, _ = _read_utf16_string(data, pos)

        strings: list[str] = []
        if str_offset < len(data) and num_strings > 0:
            str_pos = str_offset
            for _ in range(num_strings):
                if str_pos >= len(data):
                    break
                s, str_pos = _read_utf16_string(data, str_pos)
                strings.append(s)

        return {
            "source_format": "evt",
            "file":          file_name,
            "event_id":      event_id,
            "provider":      source_name,
            "timestamp":     timestamp,
            "computer":      computer_name,
            "level":         EVT_LEVEL_MAP.get(event_type, str(event_type)),
            "channel":       file_name.replace(".Evt", "").replace(".evt", ""),
            "record_id":     record_num,
            "event_data":    {f"String{i}": s for i, s in enumerate(strings)},
        }
    except Exception:
        return None


def parse_evt_file(file_path: Path) -> list[dict]:
    events = []
    try:
        data = file_path.read_bytes()
    except Exception as err:
        print(f"  [!] Cannot read {file_path.name}: {err}")
        return events

    if len(data) < 8:
        return events

    pos = 48  # skip EVT file header
    while pos < len(data) - 4:
        idx = data.find(EVT_HEADER_MAGIC, pos)
        if idx == -1:
            break

        rec_start = idx - 4
        if rec_start < 0:
            pos = idx + 4
            continue

        try:
            rec_len = struct.unpack_from("<I", data, rec_start)[0]
        except Exception:
            pos = idx + 4
            continue

        if rec_len < EVT_RECORD_FIXED or rec_len > 524288:
            pos = idx + 4
            continue

        rec_end = rec_start + rec_len
        if rec_end > len(data):
            pos = idx + 4
            continue

        event = _parse_evt_record(data[rec_start:rec_end], file_path.name)
        if event:
            events.append(event)

        pos = rec_end

    return events

# =============================================================================
# Directory scanner
# =============================================================================

def parse_event_logs_dir(log_dir: Path) -> list[dict]:
    all_events: list[dict] = []

    if not log_dir.exists():
        print(f"  [!] Event logs dir not found: {log_dir}")
        return all_events

    evtx_files = list(log_dir.rglob("*.evtx"))
    evt_files  = list(log_dir.rglob("*.evt")) + list(log_dir.rglob("*.Evt"))

    print(f"  [*] Found {len(evtx_files)} .evtx, {len(evt_files)} .evt files")

    for f in evtx_files:
        events = parse_evtx_file(f)
        print(f"    evtx {f.name}: {len(events)} records")
        all_events.extend(events)

    for f in evt_files:
        events = parse_evt_file(f)
        print(f"    evt  {f.name}: {len(events)} records")
        all_events.extend(events)

    return all_events

# =============================================================================
# Categorize
# =============================================================================

def categorize(events: list[dict]) -> dict[str, list[dict]]:
    network: list[dict] = []
    logon:   list[dict] = []
    process: list[dict] = []
    service: list[dict] = []

    for e in events:
        eid = e.get("event_id")
        if eid in NETWORK_EVENT_IDS:  network.append(e)
        if eid in LOGON_EVENT_IDS:    logon.append(e)
        if eid in PROCESS_EVENT_IDS:  process.append(e)
        if eid in SERVICE_EVENT_IDS:  service.append(e)

    return {"network": network, "logon": logon, "process": process, "service": service}

# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Event Logs (.evtx + .evt) → JSON")
    parser.add_argument("--mount",   help="Mount point (searches winevt/Logs or system32/config)")
    parser.add_argument("--raw-dir", help="Directory containing pre-copied .evtx/.evt files (preferred)")
    parser.add_argument("--output",  required=True, help="Output JSON for all event logs")
    parser.add_argument("--network", required=True, help="Output JSON for network events")
    args = parser.parse_args()

    if args.raw_dir:
        log_dir = Path(args.raw_dir)
    elif args.mount:
        mount = Path(args.mount)
        candidates = [
            mount / "Windows/System32/winevt/Logs",
            mount / "WINDOWS/System32/winevt/Logs",
            mount / "WINDOWS/system32/config",
        ]
        log_dir = next((p for p in candidates if p.exists()), None)
        if not log_dir:
            found = list(mount.rglob("*.evtx"))[:1] or list(mount.rglob("*.evt"))[:1]
            log_dir = found[0].parent if found else Path("/nonexistent")
    else:
        parser.error("Provide --raw-dir or --mount")

    print(f"  [*] Parsing event logs from: {log_dir}")
    all_events = parse_event_logs_dir(log_dir)
    cats = categorize(all_events)
    srt = lambda lst: sorted(lst, key=lambda x: x.get("timestamp") or "", reverse=True)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "artifact_type": "event_logs",
                "parsed_at":     now_iso(),
                "source":        str(log_dir),
            },
            "summary": {
                "total_events":   len(all_events),
                "network_events": len(cats["network"]),
                "logon_events":   len(cats["logon"]),
                "process_events": len(cats["process"]),
                "service_events": len(cats["service"]),
            },
            "logon_events":   srt(cats["logon"]),
            "process_events": srt(cats["process"]),
            "service_events": srt(cats["service"]),
            "all_events":     srt(all_events),
        }, f, indent=2, ensure_ascii=False)
    print(f"  [✓] {len(all_events)} total events → {out_path}")

    net_path = Path(args.network)
    net_path.parent.mkdir(parents=True, exist_ok=True)
    with open(net_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "artifact_type": "network_activity",
                "parsed_at":     now_iso(),
                "source":        str(log_dir),
            },
            "summary": {"total_network_events": len(cats["network"])},
            "network_events": srt(cats["network"]),
        }, f, indent=2, ensure_ascii=False)
    print(f"  [✓] {len(cats['network'])} network events → {net_path}")


if __name__ == "__main__":
    main()