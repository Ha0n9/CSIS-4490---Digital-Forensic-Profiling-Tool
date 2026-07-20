#!/usr/bin/env python3
"""
correlate_artifacts.py  -  Final Version
Forensic artifact correlation -> per-user suspicion scoring

Scoring model:
  Artifact Score  = (weight x frequency) per category, hybrid 70% raw + 30% normalized
  Timeline Bonus  = additive bonuses for cross-artifact behavioral patterns
  Final Score     = Artifact Score + Timeline Bonus

Key design decisions:
  - System accounts are tagged (account_type=system) but KEPT in intermediate
    scoring data so they contribute to timeline correlation. Excluded from ranking only.
  - Network traffic is classified into three buckets:
      external          -> full score
      internal_suspicious (lateral movement ports/processes) -> 70% score
      internal_benign   (DNS/DHCP/NTP/broadcast) -> ignored
  - Two-pass aggregation: first pass computes raw scores and max for normalization,
    second pass applies hybrid formula.

Usage:
    python3 correlate_artifacts.py --json-dir output/json --output output/scores.json
    python3 correlate_artifacts.py --json-dir output/json --output output/scores.json \
        --ground-truth ground_truth.json
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# =============================================================================
# WEIGHTS  (original justified values - do not change without test data)
# =============================================================================

WEIGHTS = {
    "deleted_files":    4,
    "event_anomalies":  4,
    "app_activity":     3,
    "network_activity": 3,
    "document_access":  2,
    "browser_history":  1,
    "user_accounts":    1,
}

TIMELINE_BONUS = {
    "file_access_then_deletion":  5,
    "app_exec_then_network":      4,
    "activity_then_log_gap":      6,
    "rapid_actions":              3,
    "multi_source_consistency":   5,
}

# Hybrid ratio
RAW_WEIGHT  = 0.70
NORM_WEIGHT = 0.30

# =============================================================================
# SYSTEM ACCOUNT DEFINITIONS
# These accounts are tagged but NOT removed from intermediate data.
# They are excluded only from the final ranking table.
# =============================================================================

SYSTEM_ACCOUNT_NAMES: set[str] = {
    "localsystem", "system", "local service", "network service",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service",
    "wdagutilityaccount",
}

_DWM_RE         = re.compile(r"^dwm-\d+$",          re.IGNORECASE)
_DEFAULTUSER_RE = re.compile(r"^defaultuser\d+$",    re.IGNORECASE)
_MACHINE_RE     = re.compile(r".+\$$")               # ends with $


def account_type(username: str) -> str:
    """Return 'system', 'builtin', or 'user'."""
    if not username:
        return "system"
    u = username.lower().strip()
    if u in SYSTEM_ACCOUNT_NAMES:           return "system"
    if _DWM_RE.match(u):                    return "system"
    if _DEFAULTUSER_RE.match(u):            return "system"
    if _MACHINE_RE.match(u):                return "system"
    if "nt authority" in u:                 return "system"
    if "window manager" in u:               return "system"
    if u in ("administrator", "guest", "defaultaccount"):
        return "builtin"
    return "user"


def is_rankable(username: str) -> bool:
    """Only 'user' and 'builtin' accounts appear in the final ranking."""
    return account_type(username) in ("user", "builtin")

# =============================================================================
# NETWORK TRAFFIC CLASSIFICATION
# external          -> full score
# internal_suspicious -> lateral movement signals -> 70% score
# internal_benign   -> ignored (DNS/DHCP/NTP/broadcast)
# =============================================================================

_INTERNAL_IP = [
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^127\.\d+\.\d+\.\d+$"),
    re.compile(r"^169\.254\.\d+\.\d+$"),
    re.compile(r"^::1$"),
]

# Ports associated with lateral movement
_LATERAL_PORTS: set[int] = {
    22,    # SSH
    135,   # RPC
    139,   # NetBIOS
    445,   # SMB
    3389,  # RDP
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    47001, # WinRM alt
}

# Process names associated with lateral movement
_LATERAL_PROCESSES = {
    "psexec", "psexesvc", "wmic", "wmiprvse", "winrm",
    "powershell", "cmd", "mstsc", "svchost",
}

# Benign internal traffic (always ignored)
_BENIGN_PORTS: set[int] = {53, 67, 68, 123, 137, 138, 5353, 1900}


def classify_network(dest_ip: str, dest_port: str | int, process: str) -> str:
    """Return 'external', 'internal_suspicious', or 'internal_benign'."""
    ip = (dest_ip or "").strip()
    is_internal = any(p.match(ip) for p in _INTERNAL_IP) or ip in ("127.0.0.1", "localhost")

    try:
        port = int(dest_port)
    except (TypeError, ValueError):
        port = 0

    proc = (process or "").lower()

    if not is_internal:
        return "external"

    # Internal - check if benign
    if port in _BENIGN_PORTS:
        return "internal_benign"

    # Internal - check for lateral movement signals
    if port in _LATERAL_PORTS:
        return "internal_suspicious"
    if any(lp in proc for lp in _LATERAL_PROCESSES):
        return "internal_suspicious"

    return "internal_benign"


# Network score multipliers per traffic class
_NET_MULTIPLIER = {
    "external":            1.0,
    "internal_suspicious": 0.7,
    "internal_benign":     0.0,
}

# =============================================================================
# SUSPICIOUS DEFINITIONS
# =============================================================================

SUSPICIOUS_EXES: dict[str, tuple[str, float]] = {
    # Recon
    "nmap":       ("recon", 1.5), "wireshark":  ("recon", 1.5),
    "tshark":     ("recon", 1.5), "netstat":    ("recon", 1.0),
    "whoami":     ("recon", 1.0), "ipconfig":   ("recon", 1.0),
    "arp":        ("recon", 1.0), "nslookup":   ("recon", 1.0),
    "tracert":    ("recon", 1.0), "masscan":    ("recon", 2.0),
    "zenmap":     ("recon", 1.5),
    # Remote access / lateral movement
    "psexec":     ("remote_access", 2.0), "putty":       ("remote_access", 1.5),
    "winscp":     ("remote_access", 2.0), "mstsc":       ("remote_access", 1.5),
    "vnc":        ("remote_access", 1.5), "teamviewer":  ("remote_access", 1.5),
    "anydesk":    ("remote_access", 1.5), "plink":       ("remote_access", 2.0),
    "ncat":       ("remote_access", 2.0), "netcat":      ("remote_access", 2.0),
    # Exfiltration
    "ftp":        ("exfiltration", 1.5), "rclone":   ("exfiltration", 2.5),
    "robocopy":   ("exfiltration", 1.0), "curl":     ("exfiltration", 1.5),
    "wget":       ("exfiltration", 1.5),
    # Execution / bypass
    "powershell": ("execution", 1.5), "wscript":   ("execution", 2.0),
    "mshta":      ("execution", 2.0), "rundll32":  ("execution", 2.0),
    "regsvr32":   ("execution", 2.0), "cscript":   ("execution", 1.5),
    "certutil":   ("execution", 2.0), "bitsadmin": ("execution", 2.0),
    "msiexec":    ("execution", 1.5),
    # Deletion / wiping
    "sdelete":    ("deletion", 2.5), "eraser":    ("deletion", 2.5),
    "cipher":     ("deletion", 2.0), "ccleaner":  ("deletion", 2.0),
    "diskpart":   ("deletion", 2.0), "shred":     ("deletion", 2.5),
    # Compression (flag only; low weight alone)
    "7z":         ("compression", 1.0), "winrar":  ("compression", 1.0),
    "zip":        ("compression", 0.5),
    # Credential tools
    "mimikatz":   ("credential", 3.0), "pwdump":   ("credential", 3.0),
    "hashcat":    ("credential", 2.5), "hydra":    ("credential", 2.5),
    "aircrack":   ("credential", 2.5),
}

SUSPICIOUS_DOMAINS: dict[str, tuple[str, int]] = {
    # Weapons / violence
    "gunbroker":    ("weapons", 3), "armslist":    ("weapons", 3),
    "gunsamerica":  ("weapons", 3), "bladehq":     ("weapons", 2),
    "ar15":         ("weapons", 3), "ammoland":    ("weapons", 2),
    "massshooting": ("violence", 4), "massacre":   ("violence", 4),
    "explosive":    ("violence", 4), "manifesto":  ("violence", 3),
    "bomb making":  ("violence", 5), "how to kill":("violence", 5),
    # Dark / anonymous
    "tor2web":      ("anonymization", 3), ".onion": ("anonymization", 4),
    "i2p":          ("anonymization", 3), "darkweb":("anonymization", 3),
    # File sharing / exfil
    "mega.nz":      ("exfil_site", 3), "wetransfer": ("exfil_site", 2),
    "anonfiles":    ("exfil_site", 3), "gofile":     ("exfil_site", 2),
    "zippyshare":   ("exfil_site", 2), "4shared":    ("exfil_site", 2),
    "mediafire":    ("exfil_site", 1), "sendspace":  ("exfil_site", 2),
    # Paste sites
    "pastebin":     ("paste_site", 2), "hastebin":   ("paste_site", 2),
    "ghostbin":     ("paste_site", 2), "privatebin": ("paste_site", 2),
    # VPN / proxy
    "nordvpn":      ("vpn", 2), "expressvpn": ("vpn", 2),
    "protonvpn":    ("vpn", 2), "hide.me":    ("vpn", 2),
    "mullvad":      ("vpn", 2), "hidemyass":  ("vpn", 2),
    # Hacking resources
    "exploit-db":   ("hacking", 4), "metasploit": ("hacking", 3),
    "hackforums":   ("hacking", 3), "nulled":     ("hacking", 3),
    "shodan":       ("hacking", 2),
}

SENSITIVE_EXTENSIONS: set[str] = {
    ".docx", ".doc", ".xlsx", ".xls", ".pdf", ".pptx", ".ppt",
    ".pst", ".ost", ".msg",
    ".kdbx", ".kdb",
    ".pfx", ".p12", ".cer", ".key",
    ".sql", ".db", ".sqlite",
    ".bak", ".backup", ".csv",
}

ANOMALY_EVENT_IDS: dict[int, tuple[str, int]] = {
    # Logon failures
    4625: ("logon_failure", 2),        529: ("logon_failure", 2),
    # Account lockout
    4740: ("account_lockout", 3),      539: ("account_lockout", 3),
    # Audit log cleared
    1102: ("log_cleared", 5),          517: ("log_cleared", 5),
    # Service installation (persistence)
    7045: ("service_install", 3),     4697: ("service_install", 3),
    # Privilege escalation
    4672: ("privilege_escalation", 3), 576: ("privilege_escalation", 3),
    # Process creation
    4688: ("process_creation", 1),     592: ("process_creation", 1),
    # Firewall changes
    2003: ("firewall_change", 3),     2004: ("firewall_change", 3),
}

# =============================================================================
# HELPERS
# =============================================================================

def load_json(path: Path) -> dict | list | None:
    if not path.exists():
        print(f"  [!] Not found: {path.name}")
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [!] Failed to load {path.name}: {e}")
        return None


def parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def norm_name(name: str) -> str:
    return name.strip().lower() if name else ""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _username_from_path(path: str) -> str | None:
    if not path:
        return None
    m = re.search(
        r"(?:Users|Documents and Settings)[/\\]([^/\\]+)",
        path, re.IGNORECASE,
    )
    if m:
        name = m.group(1)
        skip = {"all users", "default user", "default", "public",
                "localservice", "networkservice", "systemprofile"}
        if name.lower() not in skip:
            return name
    return None


def resolve_username(path: str = "", sid: str | None = None,
                     sid_map: dict | None = None) -> str:
    uname = _username_from_path(path)
    if uname:
        return norm_name(uname)
    if sid and sid_map:
        uname = sid_map.get(sid)
        if uname:
            return norm_name(uname)
    return ""   # unresolvable - caller decides what to do

# =============================================================================
# BUILD USER REGISTRY
# =============================================================================

def build_sid_map(ua_data: dict | None) -> dict[str, str]:
    sid_map: dict[str, str] = {}
    if not ua_data:
        return sid_map
    for rec in ua_data.get("users", {}).get("records", []):
        rid   = rec.get("rid")
        uname = rec.get("username", "")
        if rid and uname:
            sid_map[str(rid)] = norm_name(uname)
    return sid_map


def build_user_list(ua_data: dict | None) -> dict[str, dict]:
    """Returns ALL accounts (including system) tagged with account_type."""
    users: dict[str, dict] = {}
    if not ua_data:
        return users
    for rec in ua_data.get("users", {}).get("records", []):
        uname = rec.get("username", "")
        if not uname:
            continue
        key = norm_name(uname)
        if not key:
            continue
        users[key] = {
            "username":         uname,
            "account_type":     account_type(uname),
            "rid":              rec.get("rid"),
            "last_login":       rec.get("last_login", ""),
            "login_count":      rec.get("login_count", 0),
            "failed_logins":    rec.get("failed_logins", 0),
            "account_disabled": rec.get("account_disabled", False),
            "description":      rec.get("description", ""),
        }
    return users

# =============================================================================
# SCORING FUNCTIONS
# Each returns {username_key: {count, evidence, ...}}
# System accounts are included with their account_type tag.
# =============================================================================

def score_deleted_files(data: dict | None, sid_map: dict | None = None) -> dict:
    scores: dict = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        user = resolve_username(rec.get("original_path", ""),
                                rec.get("sid"), sid_map)
        if not user:
            continue
        scores[user]["count"] += 1
        scores[user]["evidence"].append({
            "path":       rec.get("original_path", ""),
            "deleted_at": rec.get("deleted_at", ""),
            "file_size":  rec.get("file_size", ""),
            "source":     rec.get("source", ""),
        })
    return dict(scores)


def score_application_activity(data: dict | None) -> dict:
    """Prefetch is system-wide - stored under '__apps__' key for distribution."""
    scores: dict = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        exe       = rec.get("exe_name", "").lower()
        run_count = rec.get("run_count") or 1
        last_run  = rec.get("last_run", "")
        for kw, (cat, mult) in SUSPICIOUS_EXES.items():
            if kw in exe:
                scores["__apps__"]["count"]          += run_count
                scores["__apps__"]["weighted_count"] += run_count * mult
                scores["__apps__"]["evidence"].append({
                    "exe": exe, "category": cat,
                    "multiplier": mult, "run_count": run_count, "last_run": last_run,
                })
                break
    return dict(scores)


def score_event_logs(data: dict | None) -> dict:
    scores: dict = defaultdict(lambda: {
        "count": 0, "weighted_count": 0.0,
        "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    for evt in data.get("all_events", []):
        eid   = evt.get("event_id")
        ts    = evt.get("timestamp", "")
        edata = evt.get("event_data", {})
        if eid not in ANOMALY_EVENT_IDS:
            continue
        label, evt_weight = ANOMALY_EVENT_IDS[eid]
        uname = (edata.get("SubjectUserName") or edata.get("TargetUserName") or
                 edata.get("AccountName")     or edata.get("String0") or "")
        if not uname:
            continue
        key = norm_name(uname)
        scores[key]["count"]          += 1
        scores[key]["weighted_count"] += evt_weight
        scores[key]["account_type"]    = account_type(uname)
        scores[key]["evidence"].append({
            "event_id":  eid,   "label":    label,
            "weight":    evt_weight, "timestamp": ts,
            "computer":  evt.get("computer", ""),
        })
    return dict(scores)


def score_network_activity(data: dict | None) -> dict:
    """
    Three-bucket classification:
      external           -> weight multiplier 1.0
      internal_suspicious-> lateral movement signals -> multiplier 0.7
      internal_benign    -> ignored
    """
    scores: dict = defaultdict(lambda: {
        "count": 0.0,   # weighted count (after multiplier)
        "raw_count": 0, "external": 0, "internal_suspicious": 0,
        "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    for evt in data.get("network_events", []):
        edata    = evt.get("event_data", {})
        dest_ip  = edata.get("DestAddress")  or edata.get("IpAddress", "")
        dest_port= edata.get("DestPort")     or edata.get("IpPort", "")
        process  = (edata.get("Application") or edata.get("ProcessName", "")).lower()

        traffic_class = classify_network(dest_ip, dest_port, process)
        multiplier    = _NET_MULTIPLIER[traffic_class]
        if multiplier == 0.0:
            continue    # benign - skip entirely

        uname = (edata.get("SubjectUserName") or edata.get("TargetUserName") or
                 edata.get("AccountName") or "")
        if not uname:
            continue
        key = norm_name(uname)

        scores[key]["raw_count"]  += 1
        scores[key]["count"]      += multiplier   # weighted count
        scores[key]["account_type"] = account_type(uname)
        if traffic_class == "external":
            scores[key]["external"] += 1
        else:
            scores[key]["internal_suspicious"] += 1

        scores[key]["evidence"].append({
            "event_id":     evt.get("event_id"),
            "timestamp":    evt.get("timestamp", ""),
            "dest_ip":      dest_ip,
            "dest_port":    dest_port,
            "process":      process,
            "traffic_class":traffic_class,
            "multiplier":   multiplier,
        })
    return dict(scores)


def score_document_access(data: dict | None) -> dict:
    scores: dict = defaultdict(lambda: {
        "count": 0, "sensitive_count": 0,
        "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        if rec.get("type") != "lnk":
            continue
        uname  = rec.get("username", "")
        target = rec.get("target_path", "")
        ts     = rec.get("target_accessed", "") or rec.get("target_modified", "")
        key    = norm_name(uname)
        if not key:
            continue
        scores[key]["count"]        += 1
        scores[key]["account_type"]  = account_type(uname)
        ext = Path(target).suffix.lower() if target else ""
        if ext in SENSITIVE_EXTENSIONS:
            scores[key]["sensitive_count"] += 1
            scores[key]["evidence"].append({
                "target": target, "accessed_at": ts, "extension": ext,
            })
    return dict(scores)


def score_browser_history(data: dict | None) -> dict:
    scores: dict = defaultdict(lambda: {
        "count": 0, "flagged_count": 0, "flagged_weight": 0.0,
        "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        uname = rec.get("username", "")
        url   = (rec.get("url") or "").lower()
        title = rec.get("title", "")
        key   = norm_name(uname)
        if not key:
            continue
        scores[key]["count"]       += 1
        scores[key]["account_type"] = account_type(uname)
        for kw, (cat, dw) in SUSPICIOUS_DOMAINS.items():
            if kw in url or kw in title.lower():
                scores[key]["flagged_count"]  += 1
                scores[key]["flagged_weight"] += dw
                scores[key]["evidence"].append({
                    "url": rec.get("url", ""), "title": title,
                    "category": cat, "weight": dw,
                    "visited": rec.get("visited_at", ""),
                    "browser": rec.get("browser", ""),
                })
                break
    return dict(scores)


def score_user_accounts(data: dict | None) -> dict:
    scores: dict = defaultdict(lambda: {
        "count": 0, "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    for rec in data.get("users", {}).get("records", []):
        uname  = rec.get("username", "")
        key    = norm_name(uname)
        if not key:
            continue
        scores[key]["account_type"] = account_type(uname)
        failed = rec.get("failed_logins", 0) or 0
        if failed >= 5:
            scores[key]["count"] += 1
            scores[key]["evidence"].append({
                "flag": "high_failed_logins",
                "failed_logins": failed,
                "last_login":    rec.get("last_login", ""),
            })
        if rec.get("account_disabled"):
            scores[key]["count"] += 1
            scores[key]["evidence"].append({"flag": "account_disabled_but_active"})
    return dict(scores)

# =============================================================================
# TIMELINE BUILDER
# System accounts ARE included in timelines so their events can contribute
# to lateral movement pattern detection for real user accounts.
# =============================================================================

def _build_timeline(user: str, doc_s: dict, del_s: dict,
                    app_s: dict, net_s: dict, evt_s: dict) -> list[dict]:
    events: list[dict] = []

    for ev in doc_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("accessed_at"))
        if ts:
            events.append({"ts": ts, "type": "document_access",
                           "detail": ev.get("target", "")})

    for ev in del_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("deleted_at"))
        if ts:
            events.append({"ts": ts, "type": "deleted_file",
                           "detail": ev.get("path", "")})

    for ev in net_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("timestamp"))
        if ts:
            events.append({"ts": ts, "type": "network_activity",
                           "detail": ev.get("dest_ip", ""),
                           "traffic_class": ev.get("traffic_class", "external")})

    for ev in evt_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("timestamp"))
        if ts:
            events.append({"ts": ts, "type": "event_anomaly",
                           "detail": ev.get("label", "")})

    # App execution is system-wide - include for every user
    for ev in app_s.get("__apps__", {}).get("evidence", []):
        ts = parse_ts(ev.get("last_run"))
        if ts:
            events.append({"ts": ts, "type": "application_exec",
                           "detail": ev.get("exe", "")})

    return sorted(events, key=lambda x: x["ts"])

# =============================================================================
# TIMELINE CORRELATION
# =============================================================================

def calculate_timeline_bonuses(
    user: str, doc_s: dict, del_s: dict,
    app_s: dict, net_s: dict, evt_s: dict,
) -> tuple[int, list[dict]]:

    timeline = _build_timeline(user, doc_s, del_s, app_s, net_s, evt_s)
    if not timeline:
        return 0, []

    bonus    = 0
    patterns: list[dict] = []
    used:     set[Any]   = set()

    # ── Pattern 1: File access -> deletion within 5 min ───────────────────────
    for acc in (e for e in timeline if e["type"] == "document_access"):
        for dlt in (e for e in timeline if e["type"] == "deleted_file"):
            pair = (id(acc), id(dlt))
            if pair in used: continue
            delta = (dlt["ts"] - acc["ts"]).total_seconds()
            if 0 <= delta <= 300:
                used.add(pair)
                bonus += TIMELINE_BONUS["file_access_then_deletion"]
                patterns.append({
                    "pattern":   "file_access_then_deletion",
                    "bonus":     TIMELINE_BONUS["file_access_then_deletion"],
                    "detail":    f"Accessed '{acc['detail']}' then deleted "
                                 f"'{dlt['detail']}' ({int(delta)}s later)",
                    "timestamp": acc["ts"].isoformat(),
                })

    # ── Pattern 2: App execution -> network activity within 10 min ────────────
    for app in (e for e in timeline if e["type"] == "application_exec"):
        for net in (e for e in timeline if e["type"] == "network_activity"):
            pair = (id(app), id(net))
            if pair in used: continue
            delta = (net["ts"] - app["ts"]).total_seconds()
            if 0 <= delta <= 600:
                used.add(pair)
                bonus += TIMELINE_BONUS["app_exec_then_network"]
                patterns.append({
                    "pattern":   "app_exec_then_network",
                    "bonus":     TIMELINE_BONUS["app_exec_then_network"],
                    "detail":    f"Ran '{app['detail']}' then network to "
                                 f"'{net['detail']}' ({int(delta)}s later)",
                    "timestamp": app["ts"].isoformat(),
                })

    # ── Pattern 3: Activity burst -> log gap ≥ 1 hour ─────────────────────────
    for i in range(len(timeline) - 1):
        gap = (timeline[i+1]["ts"] - timeline[i]["ts"]).total_seconds()
        if gap >= 3600:
            key = f"gap_{timeline[i]['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                bonus += TIMELINE_BONUS["activity_then_log_gap"]
                patterns.append({
                    "pattern":   "activity_then_log_gap",
                    "bonus":     TIMELINE_BONUS["activity_then_log_gap"],
                    "detail":    f"{gap/3600:.1f}h silence after "
                                 f"{timeline[i]['ts'].isoformat()}",
                    "timestamp": timeline[i]["ts"].isoformat(),
                })
                break

    # ── Pattern 4: Rapid actions - ≥ 5 events within 60 s ────────────────────
    for i, evt in enumerate(timeline):
        window = [e for e in timeline
                  if 0 <= (e["ts"] - evt["ts"]).total_seconds() <= 60]
        if len(window) >= 5:
            key = f"rapid_{evt['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                bonus += TIMELINE_BONUS["rapid_actions"]
                patterns.append({
                    "pattern":   "rapid_actions",
                    "bonus":     TIMELINE_BONUS["rapid_actions"],
                    "detail":    f"{len(window)} events in 60s starting "
                                 f"{evt['ts'].isoformat()}",
                    "timestamp": evt["ts"].isoformat(),
                })
            break

    # ── Pattern 5: Multi-source consistency - ≥ 3 types in 5 min ─────────────
    for i, evt in enumerate(timeline):
        window = [e for e in timeline
                  if 0 <= (e["ts"] - evt["ts"]).total_seconds() <= 300]
        types  = {e["type"] for e in window}
        if len(types) >= 3:
            key = f"multi_{evt['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                bonus += TIMELINE_BONUS["multi_source_consistency"]
                patterns.append({
                    "pattern":   "multi_source_consistency",
                    "bonus":     TIMELINE_BONUS["multi_source_consistency"],
                    "detail":    f"{len(types)} artifact types in 5min: "
                                 f"{', '.join(sorted(types))}",
                    "timestamp": evt["ts"].isoformat(),
                })
            break

    return bonus, patterns

# =============================================================================
# AGGREGATE  -  two-pass hybrid scoring
# Pass 1: compute raw scores + find max for normalization
# Pass 2: apply hybrid formula, compute timelines, build output
# =============================================================================

def aggregate_scores(
    users: dict, del_s: dict, app_s: dict, evt_s: dict,
    net_s: dict, doc_s: dict, brw_s: dict, usr_s: dict,
) -> list[dict]:

    # Collect all keys that appear in any scoring dict
    all_keys: set[str] = set(users.keys())
    for d in (del_s, evt_s, net_s, doc_s, brw_s, usr_s):
        all_keys.update(d.keys())
    # Remove unresolvable / empty
    all_keys = {k for k in all_keys if k and k not in ("", "-")}

    if not all_keys:
        print("  [!] No accounts found in any artifact - check JSON files.")
        return []

    num_users = len({k for k in all_keys if is_rankable(k)}) or 1

    # ── Pass 1: raw scores ────────────────────────────────────────────────────
    raw: dict[str, float] = {}
    for user in all_keys:
        del_c   = del_s.get(user, {}).get("count", 0)
        evt_wc  = evt_s.get(user, {}).get("weighted_count", 0.0)
        net_c   = net_s.get(user, {}).get("count", 0.0)   # already weighted by multiplier
        doc_sc  = doc_s.get(user, {}).get("sensitive_count", 0)
        brw_fw  = brw_s.get(user, {}).get("flagged_weight", 0.0)
        usr_c   = usr_s.get(user, {}).get("count", 0)
        app_wc  = app_s.get("__apps__", {}).get("weighted_count", 0.0)
        has_act = del_c > 0 or evt_wc > 0 or net_c > 0 or doc_sc > 0 or brw_fw > 0
        app_share = (app_wc / num_users) if has_act else 0

        raw[user] = (
            del_c   * WEIGHTS["deleted_files"]
            + (evt_wc / 4) * WEIGHTS["event_anomalies"]
            + app_share    * WEIGHTS["app_activity"]
            + net_c        * WEIGHTS["network_activity"]
            + doc_sc       * WEIGHTS["document_access"]
            + brw_fw       * WEIGHTS["browser_history"]
            + min(usr_c * WEIGHTS["user_accounts"], 5)
        )

    max_raw = max(raw.values(), default=1.0) or 1.0

    # ── Pass 2: normalized + hybrid ──────────────────────────────────────────
    results: list[dict] = []

    for user in sorted(all_keys):
        uinfo        = users.get(user, {"username": user, "account_type": account_type(user)})
        display_name = uinfo.get("username", user)
        acct_type    = uinfo.get("account_type", account_type(user))

        del_c   = del_s.get(user, {}).get("count", 0)
        evt_c   = evt_s.get(user, {}).get("count", 0)
        evt_wc  = evt_s.get(user, {}).get("weighted_count", 0.0)
        net_c   = net_s.get(user, {}).get("count", 0.0)
        net_raw = net_s.get(user, {}).get("raw_count", 0)
        net_ext = net_s.get(user, {}).get("external", 0)
        net_int = net_s.get(user, {}).get("internal_suspicious", 0)
        doc_t   = doc_s.get(user, {}).get("count", 0)
        doc_sc  = doc_s.get(user, {}).get("sensitive_count", 0)
        brw_t   = brw_s.get(user, {}).get("count", 0)
        brw_fc  = brw_s.get(user, {}).get("flagged_count", 0)
        brw_fw  = brw_s.get(user, {}).get("flagged_weight", 0.0)
        usr_c   = usr_s.get(user, {}).get("count", 0)
        app_wc  = app_s.get("__apps__", {}).get("weighted_count", 0.0)
        has_act = del_c > 0 or evt_c > 0 or net_c > 0 or doc_sc > 0 or brw_fc > 0
        app_share = (app_wc / num_users) if has_act else 0

        raw_score = raw[user]

        # Normalized (per-event proportion)
        total_ev = max(del_c + evt_c + net_c + doc_sc + brw_fc + usr_c, 1)
        def norm(v: float) -> float: return v / total_ev

        norm_score = (
            WEIGHTS["deleted_files"]    * norm(del_c)
            + WEIGHTS["event_anomalies"]  * norm(evt_wc)
            + WEIGHTS["app_activity"]     * norm(app_share)
            + WEIGHTS["network_activity"] * norm(net_c)
            + WEIGHTS["document_access"]  * norm(doc_sc)
            + WEIGHTS["browser_history"]  * norm(brw_fw)
            + WEIGHTS["user_accounts"]    * norm(usr_c)
        )

        # Hybrid: 70% raw (scaled 0-100) + 30% norm (scaled 0-100)
        raw_scaled  = (raw_score / max_raw) * 100
        norm_scaled = norm_score * 100
        artifact_score = RAW_WEIGHT * raw_scaled + NORM_WEIGHT * norm_scaled

        # Timeline bonus
        tl_bonus, tl_patterns = calculate_timeline_bonuses(
            user, doc_s, del_s, app_s, net_s, evt_s,
        )

        final_score = artifact_score + tl_bonus

        results.append({
            "username":     display_name,
            "username_key": user,
            "account_type": acct_type,
            "rankable":     is_rankable(user),
            "account_info": {
                "rid":              uinfo.get("rid"),
                "last_login":       uinfo.get("last_login", ""),
                "login_count":      uinfo.get("login_count", 0),
                "failed_logins":    uinfo.get("failed_logins", 0),
                "account_disabled": uinfo.get("account_disabled", False),
            },
            "artifact_scores": {
                "deleted_files":    {"raw_count": del_c,
                                     "score": round(del_c * WEIGHTS["deleted_files"], 2)},
                "event_anomalies":  {"raw_count": evt_c,
                                     "score": round((evt_wc/4) * WEIGHTS["event_anomalies"], 2)},
                "app_activity":     {"raw_count": app_s.get("__apps__",{}).get("count",0),
                                     "score": round(app_share * WEIGHTS["app_activity"], 2)},
                "network_activity": {"raw_count": net_raw,
                                     "external": net_ext,
                                     "internal_suspicious": net_int,
                                     "weighted_count": round(net_c, 2),
                                     "score": round(net_c * WEIGHTS["network_activity"], 2)},
                "document_access":  {"raw_count": doc_t, "sensitive_count": doc_sc,
                                     "score": round(doc_sc * WEIGHTS["document_access"], 2)},
                "browser_history":  {"raw_count": brw_t, "flagged_count": brw_fc,
                                     "score": round(brw_fw * WEIGHTS["browser_history"], 2)},
                "user_accounts":    {"raw_count": usr_c,
                                     "score": round(min(usr_c * WEIGHTS["user_accounts"], 5), 2)},
            },
            "raw_score":         round(raw_score, 2),
            "normalized_score":  round(norm_score, 4),
            "artifact_score":    round(artifact_score, 2),
            "timeline_bonus":    tl_bonus,
            "timeline_patterns": tl_patterns,
            "final_score":       round(final_score, 2),
            "evidence": {
                "deleted_files":    del_s.get(user, {}).get("evidence", [])[:20],
                "event_anomalies":  evt_s.get(user, {}).get("evidence", [])[:20],
                "network_activity": net_s.get(user, {}).get("evidence", [])[:20],
                "document_access":  doc_s.get(user, {}).get("evidence", [])[:20],
                "browser_history":  brw_s.get(user, {}).get("evidence", [])[:20],
                "app_activity":     app_s.get("__apps__", {}).get("evidence", [])[:20],
                "user_accounts":    usr_s.get(user, {}).get("evidence", []),
            },
        })

    # Sort: rankable accounts first by score, then system accounts (unranked)
    rankable  = sorted([r for r in results if r["rankable"]],
                       key=lambda x: x["final_score"], reverse=True)
    sys_accts = [r for r in results if not r["rankable"]]

    for i, r in enumerate(rankable, 1):
        r["rank"] = i
    for r in sys_accts:
        r["rank"] = None   # explicitly not ranked

    return rankable + sys_accts

# =============================================================================
# EVALUATION
# =============================================================================

def evaluate_results(results: list[dict], ground_truth: dict) -> dict:
    """
    ground_truth: {"username_or_key": true/false, ...}
    Predicted suspicious = final_score > 0 AND rankable.
    """
    TP = FP = FN = TN = 0
    details = []
    for r in results:
        if not r["rankable"]:
            continue
        user      = r["username_key"]
        predicted = r["final_score"] > 0
        actual    = ground_truth.get(user, ground_truth.get(r["username"], False))
        if predicted and actual:       TP += 1; label = "TP"
        elif predicted and not actual: FP += 1; label = "FP"
        elif not predicted and actual: FN += 1; label = "FN"
        else:                          TN += 1; label = "TN"
        details.append({"user": r["username"], "predicted": predicted,
                        "actual": actual, "result": label,
                        "final_score": r["final_score"]})

    prec = TP / (TP + FP) if (TP + FP) else 0
    rec  = TP / (TP + FN) if (TP + FN) else 0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    return {"TP": TP, "FP": FP, "FN": FN, "TN": TN,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "details": details}

# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Correlate forensic artifacts -> per-user suspicion scores (Final)"
    )
    ap.add_argument("--json-dir",     required=True)
    ap.add_argument("--output",       required=True)
    ap.add_argument("--ground-truth", default="",
                    help="Optional JSON ground-truth file for evaluation")
    args = ap.parse_args()

    json_dir = Path(args.json_dir)
    out_path = Path(args.output)

    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║       Forensic Artifact Correlator - Final          ║")
    print("  ║       Hybrid 70/30 · 3-Bucket Network · Full TL    ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(f"\n  JSON dir : {json_dir}\n  Output   : {out_path}\n")

    # Load
    print("[*] Loading artifacts...")
    ua_data  = load_json(json_dir / "user_accounts.json")
    app_data = load_json(json_dir / "application_activity.json")
    evt_data = load_json(json_dir / "event_logs.json")
    net_data = load_json(json_dir / "network_activity.json")
    doc_data = load_json(json_dir / "document_folder_access.json")
    brw_data = load_json(json_dir / "browser_history.json")
    del_data = load_json(json_dir / "deleted_files.json")

    # Build user registry
    print("[*] Building user registry...")
    users   = build_user_list(ua_data)
    sid_map = build_sid_map(ua_data)
    rankable_count = sum(1 for u in users.values() if u["account_type"] in ("user","builtin"))
    print(f"    Total accounts : {len(users)}  |  Rankable : {rankable_count}")

    # Score
    print("[*] Scoring artifact categories...")
    del_s = score_deleted_files(del_data, sid_map)
    app_s = score_application_activity(app_data)
    evt_s = score_event_logs(evt_data)
    net_s = score_network_activity(net_data)
    doc_s = score_document_access(doc_data)
    brw_s = score_browser_history(brw_data)
    usr_s = score_user_accounts(ua_data)

    print(f"    Deleted files      : {sum(v['count'] for v in del_s.values())} records")
    print(f"    Event anomalies    : {sum(v['count'] for v in evt_s.values())} records")
    print(f"    Suspicious apps    : {sum(v.get('count',0) for v in app_s.values())} executions")
    net_ext = sum(v.get('external',0) for v in net_s.values())
    net_int = sum(v.get('internal_suspicious',0) for v in net_s.values())
    print(f"    Network (external) : {net_ext}  |  internal suspicious : {net_int}")
    print(f"    Sensitive docs     : {sum(v.get('sensitive_count',0) for v in doc_s.values())}")
    print(f"    Flagged URLs       : {sum(v.get('flagged_count',0) for v in brw_s.values())}")

    # Aggregate
    print("[*] Aggregating - two-pass hybrid (70% raw + 30% normalized)...")
    results = aggregate_scores(users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s)

    # Summary - only rankable accounts
    ranked = [r for r in results if r["rankable"]]
    print()
    print("  ┌──────────────────────────────────────────────────────────────────┐")
    print("  │  SUSPICION SCORE RANKING                                        │")
    print("  ├──────┬──────────────────────┬──────────┬──────────┬────────────┤")
    print("  │ Rank │ Username             │ Artifact │ Timeline │ Final      │")
    print("  ├──────┼──────────────────────┼──────────┼──────────┼────────────┤")
    for r in ranked:
        print(f"  │ {r['rank']:<4} │ {r['username']:<20} │ "
              f"{r['artifact_score']:<8.2f} │ {r['timeline_bonus']:<8} │ "
              f"{r['final_score']:<10.2f} │")
    print("  └──────┴──────────────────────┴──────────┴──────────┴────────────┘")
    print()
    print("  Note: system accounts retained in data for timeline correlation")
    print("        but excluded from ranking (rank = null in output JSON).")
    print()

    # Evaluation
    evaluation = None
    if args.ground_truth:
        gt_path = Path(args.ground_truth)
        if gt_path.exists():
            with open(gt_path, encoding="utf-8") as f:
                gt = json.load(f)
            evaluation = evaluate_results(results, gt)
            print("[*] Evaluation:")
            print(f"    Precision={evaluation['precision']}  "
                  f"Recall={evaluation['recall']}  F1={evaluation['f1']}")
            print(f"    TP={evaluation['TP']} FP={evaluation['FP']} "
                  f"FN={evaluation['FN']} TN={evaluation['TN']}")
            print()

    # Write output
    output = {
        "metadata": {
            "version":                "final",
            "generated_at":           now_iso(),
            "json_source":            str(json_dir),
            "total_accounts":         len(results),
            "rankable_accounts":      len(ranked),
            "scoring_method":         f"hybrid_{int(RAW_WEIGHT*100)}_{int(NORM_WEIGHT*100)}",
            "network_classification": "3-bucket (external/internal_suspicious/internal_benign)",
            "system_accounts":        "tagged, retained in data, excluded from ranking",
            "weights_used":           WEIGHTS,
            "timeline_bonuses_used":  TIMELINE_BONUS,
        },
        "users":      results,
        "evaluation": evaluation,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)

    print(f"[✓] scores.json written -> {out_path}")
    print()


if __name__ == "__main__":
    main()