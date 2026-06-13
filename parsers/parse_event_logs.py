#!/usr/bin/env python3
"""
parse_event_logs.py
Artifact : Event Logs + Network Activity
Sources  : .evtx (Windows Vista+) — primary: evtx (fast parser), fallback: python-evtx
           .evt  (Windows XP)     — raw struct parsing

Install:
    pip install evtx --break-system-packages          # primary (handles Win10/11)
    pip install python-evtx --break-system-packages   # fallback

Usage:
    python3 parse_event_logs.py --raw-dir <raw/event_logs> --output <out.json> --network <net.json>
"""

import argparse
import json
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# Event ID categories — Modern (Vista+) AND XP legacy
# =============================================================================

NETWORK_EVENT_IDS = {
    # Modern
    3, 22,
    4001, 4002, 4004,
    5156, 5157, 5158,
    4778, 4779,
    5140, 5142, 5144, 5145,
    8001, 8002, 8003,
    11000, 11001, 11002,
    10000, 10001, 1002,
    20225, 20226,
    2003, 2004, 2005,
    30800, 30803, 30804,
    3008, 3020,
    50066, 50067, 50068, 50073, 50074,
    # XP legacy
    528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 539,
    540, 541, 542, 543, 544, 545, 546, 547,
    576, 682, 683, 861,
}

LOGON_EVENT_IDS   = {4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769,
                     528, 529, 538, 540, 576, 680}
PROCESS_EVENT_IDS = {4688, 4689, 592, 593}
SERVICE_EVENT_IDS = {7045, 4697, 7036, 7000, 7001, 7002}

# =============================================================================
# Helpers
# =============================================================================

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_ts(ts: str | None) -> str | None:
    if not ts:
        return None
    ts = ts.strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return ts

# =============================================================================
# XML parser — shared by both evtx libraries
# Tries with namespace, then strips namespace and retries
# =============================================================================

def _parse_xml(xml_str: str, file_name: str) -> dict | None:
    """Parse EVTX record XML string into normalized dict."""

    def extract(root: ET.Element, use_ns: bool) -> dict:
        p = f"{{{NS}}}" if use_ns else ""

        system = root.find(f"{p}System")
        event_data_el = root.find(f"{p}EventData")

        result: dict = {
            "event_id": None, "provider": None, "timestamp": None,
            "computer": None, "level": None, "channel": None, "record_id": None,
        }

        if system is not None:
            def txt(tag):
                n = system.find(f"{p}{tag}")
                return n.text if n is not None else None
            def atr(tag, a):
                n = system.find(f"{p}{tag}")
                return n.attrib.get(a) if n is not None else None

            raw_id = txt("EventID")
            result["event_id"]  = int(raw_id) if raw_id and raw_id.strip().isdigit() else None
            result["provider"]  = atr("Provider", "Name")
            result["timestamp"] = normalize_ts(atr("TimeCreated", "SystemTime"))
            result["computer"]  = txt("Computer")
            result["level"]     = txt("Level")
            result["channel"]   = txt("Channel")
            result["record_id"] = txt("EventRecordID")

        event_data: dict = {}
        if event_data_el is not None:
            for i, child in enumerate(event_data_el):
                name = child.attrib.get("Name") or child.tag.split("}")[-1] or f"Data_{i}"
                event_data[name] = child.text or ""
        result["event_data"] = event_data
        return result

    # Strategy 1: parse with namespace
    try:
        root = ET.fromstring(xml_str)
        fields = extract(root, use_ns=True)
        # If System block parsed ok, return
        if fields["event_id"] is not None or fields["timestamp"] is not None:
            fields.update({"source_format": "evtx", "file": file_name})
            return fields
    except ET.ParseError:
        pass

    # Strategy 2: strip namespace and retry
    try:
        clean = xml_str.replace(f' xmlns="{NS}"', "").replace(f"xmlns='{NS}'", "")
        root2 = ET.fromstring(clean)
        fields = extract(root2, use_ns=False)
        fields.update({"source_format": "evtx", "file": file_name})
        return fields
    except ET.ParseError:
        return None

# =============================================================================
# EVTX — primary parser: evtx (fast, handles Win10/11 correctly)
# =============================================================================

def _parse_evtx_fast(file_path: Path) -> list[dict]:
    """Parse using the 'evtx' package (pip install evtx)."""
    events = []
    try:
        from evtx import PyEvtxParser
        parser = PyEvtxParser(str(file_path))
        for record in parser.records():
            try:
                xml_str = record.get("data", "")
                if not xml_str:
                    continue
                e = _parse_xml(xml_str, file_path.name)
                if e:
                    events.append(e)
            except Exception:
                continue
    except ImportError:
        raise  # caller will fallback to python-evtx
    except Exception as err:
        print(f"  [!] evtx fast parser error {file_path.name}: {err}")
    return events

# =============================================================================
# EVTX — fallback parser: python-evtx
# =============================================================================

def _parse_evtx_legacy(file_path: Path) -> list[dict]:
    """Fallback using python-evtx library."""
    events = []
    try:
        from Evtx.Evtx import Evtx
        with Evtx(str(file_path)) as log:
            for record in log.records():
                try:
                    e = _parse_xml(record.xml(), file_path.name)
                    if e:
                        events.append(e)
                except Exception:
                    continue
    except ImportError:
        print("  [!] No EVTX parser available.")
        print("  [!] Install: pip install evtx --break-system-packages")
        print("  [!]      or: pip install python-evtx --break-system-packages")
    except Exception as err:
        print(f"  [!] python-evtx error {file_path.name}: {err}")
    return events

# Detect available parser once at import time
_HAS_FAST_EVTX = False
try:
    import evtx  # noqa: F401
    _HAS_FAST_EVTX = True
except ImportError:
    pass

_HAS_LEGACY_EVTX = False
try:
    import Evtx  # noqa: F401
    _HAS_LEGACY_EVTX = True
except ImportError:
    pass

def parse_evtx_file(file_path: Path) -> list[dict]:
    if _HAS_FAST_EVTX:
        try:
            events = _parse_evtx_fast(file_path)
            null_count = sum(1 for e in events if e.get("event_id") is None)
            if null_count:
                print(f"    evtx {file_path.name}: {len(events)} records "
                      f"({null_count} null event_id — XML namespace issue)")
            else:
                print(f"    evtx {file_path.name}: {len(events)} records")
            return events
        except ImportError:
            pass  # fall through to legacy

    if _HAS_LEGACY_EVTX:
        events = _parse_evtx_legacy(file_path)
        print(f"    evtx {file_path.name}: {len(events)} records (via python-evtx fallback)")
        return events

    print(f"  [!] Skipping {file_path.name} — no EVTX parser installed")
    return []

# =============================================================================
# EVT parser — Windows XP binary, pure struct
# =============================================================================

EVT_HEADER_MAGIC = b"LfLe"
EVT_RECORD_FIXED = 56
EVT_LEVEL_MAP = {1:"Error", 2:"Warning", 4:"Information",
                 8:"Success Audit", 16:"Failure Audit"}

def _read_utf16(data: bytes, offset: int) -> tuple[str, int]:
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
    if len(data) < EVT_RECORD_FIXED or data[0x04:0x08] != EVT_HEADER_MAGIC:
        return None
    try:
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

        source_name, pos = _read_utf16(data, 0x38)
        computer_name, _ = _read_utf16(data, pos)

        strings: list[str] = []
        if str_offset < len(data) and num_strings > 0:
            sp = str_offset
            for _ in range(num_strings):
                if sp >= len(data):
                    break
                s, sp = _read_utf16(data, sp)
                strings.append(s)

        return {
            "source_format": "evt",
            "file":       file_name,
            "event_id":   event_id,
            "provider":   source_name,
            "timestamp":  timestamp,
            "computer":   computer_name,
            "level":      EVT_LEVEL_MAP.get(event_type, str(event_type)),
            "channel":    file_name.replace(".Evt","").replace(".evt",""),
            "record_id":  record_num,
            "event_data": {f"String{i}": s for i, s in enumerate(strings)},
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
    pos = 48
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

    parser_info = []
    if _HAS_FAST_EVTX:   parser_info.append("evtx (fast)")
    if _HAS_LEGACY_EVTX: parser_info.append("python-evtx (fallback)")
    if not parser_info:   parser_info.append("NONE — install evtx package!")
    print(f"  [*] EVTX parser: {', '.join(parser_info)}")
    print(f"  [*] Found {len(evtx_files)} .evtx, {len(evt_files)} .evt files")

    for f in evtx_files:
        all_events.extend(parse_evtx_file(f))

    for f in evt_files:
        events = parse_evt_file(f)
        print(f"    evt  {f.name}: {len(events)} records")
        all_events.extend(events)

    return all_events

# =============================================================================
# Categorize
# =============================================================================

def categorize(events: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"network":[], "logon":[], "process":[], "service":[]}
    for e in events:
        eid = e.get("event_id")
        if eid in NETWORK_EVENT_IDS:  out["network"].append(e)
        if eid in LOGON_EVENT_IDS:    out["logon"].append(e)
        if eid in PROCESS_EVENT_IDS:  out["process"].append(e)
        if eid in SERVICE_EVENT_IDS:  out["service"].append(e)
    return out

# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Event Logs (.evtx + .evt) → JSON")
    parser.add_argument("--mount",   help="Mount point (auto-searches winevt/Logs or system32/config)")
    parser.add_argument("--raw-dir", help="Directory with pre-copied .evtx/.evt files (preferred)")
    parser.add_argument("--output",  required=True)
    parser.add_argument("--network", required=True)
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
            "metadata": {"artifact_type": "event_logs", "parsed_at": now_iso(),
                         "source": str(log_dir)},
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
            "metadata": {"artifact_type": "network_activity", "parsed_at": now_iso(),
                         "source": str(log_dir)},
            "summary": {"total_network_events": len(cats["network"])},
            "network_events": srt(cats["network"]),
        }, f, indent=2, ensure_ascii=False)
    print(f"  [✓] {len(cats['network'])} network events → {net_path}")

if __name__ == "__main__":
    main()
