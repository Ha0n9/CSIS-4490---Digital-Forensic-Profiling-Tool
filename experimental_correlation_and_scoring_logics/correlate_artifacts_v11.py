#!/usr/bin/env python3
"""
correlate_artifacts_v10.1.py  -  Review & Hardened Version
Forensic artifact correlation -> per-user suspicion scoring

Changes from v10:
  [FIX-10D] _has_real_evidence(): browser_history now only counts as real
            evidence if there are flagged URLs (flagged_count > 0 or
            flagged_weight > 0). Raw browser history without flagged URLs
            should not elevate a user to HIGH/MEDIUM.
            
Inherited from v10:
  [FIX-10A] Risk label assignment: added _has_real_evidence()
  [FIX-10B] Users with only shared app pool → LOW
  [FIX-10C] Percentile uses real_evidence users only

Usage:
    python3 correlate_artifacts_v10.1.py --json-dir output/json --output output/scores.json
"""

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# =============================================================================
# WEIGHTS
# =============================================================================

WEIGHTS = {
    "deleted_files":    4,
    "event_anomalies":  4,
    "app_activity":     3,
    "network_activity": 3,
    "document_access":  2,
    "browser_history":  0.5,
    "user_accounts":    1,
}

MAX_NORM_SCORE: float = float(sum(WEIGHTS.values()))  # 17.5

TIMELINE_BONUS = {
    "file_access_then_deletion":  5,
    "app_exec_then_network":      4,
    "activity_then_log_gap":      6,
    "rapid_actions":              3,
    "multi_source_consistency":   5,
}

TIMELINE_BONUS_CAP = {
    "file_access_then_deletion":  15,
    "app_exec_then_network":      12,
    "activity_then_log_gap":       6,
    "rapid_actions":               9,
    "multi_source_consistency":   10,
}

RAW_WEIGHT  = 0.70
NORM_WEIGHT = 0.30

# =============================================================================
# SYSTEM ACCOUNT DEFINITIONS
# =============================================================================

SYSTEM_ACCOUNT_NAMES: set[str] = {
    "localsystem", "system", "local service", "network service",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service",
    "wdagutilityaccount",
}

_DWM_RE         = re.compile(r"^dwm-\d+$",          re.IGNORECASE)
_DEFAULTUSER_RE = re.compile(r"^defaultuser\d+$",    re.IGNORECASE)
_MACHINE_RE     = re.compile(r".+\$$")


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
    return account_type(username) in ("user", "builtin")

# =============================================================================
# NETWORK TRAFFIC CLASSIFICATION
# =============================================================================

_INTERNAL_IP = [
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^127\.\d+\.\d+\.\d+$"),
    re.compile(r"^169\.254\.\d+\.\d+$"),
    re.compile(r"^::1$"),
]

_LATERAL_PORTS: set[int] = {22, 135, 139, 445, 3389, 5985, 5986, 47001}
_LATERAL_PROCESSES = {
    "psexec", "psexesvc", "wmic", "wmiprvse", "winrm",
    "powershell", "cmd", "mstsc", "svchost",
}
_BENIGN_PORTS: set[int] = {53, 67, 68, 123, 137, 138, 5353, 1900}

CLOUD_STORAGE_DOMAINS = {
    "onedrive.live.com", "sharepoint.com", "outlook.com", "office.com",
    "google.com", "drive.google.com", "dropbox.com", "box.com",
    "amazonaws.com", "s3.amazonaws.com", "live.com", "storage.live.com",
}


def classify_network(dest_ip: str, dest_port: str | int, process: str, url: str = "") -> str:
    ip = (dest_ip or "").strip()
    is_internal = any(p.match(ip) for p in _INTERNAL_IP) or ip in ("127.0.0.1", "localhost")
    try:
        port = int(dest_port)
    except (TypeError, ValueError):
        port = 0
    proc = (process or "").lower()
    
    if url:
        url_lower = url.lower()
        for domain in CLOUD_STORAGE_DOMAINS:
            if domain in url_lower:
                return "internal_benign" if is_internal else "external_benign"
    
    if not is_internal:
        return "external"
    if port in _BENIGN_PORTS:
        return "internal_benign"
    if port in _LATERAL_PORTS or any(lp in proc for lp in _LATERAL_PROCESSES):
        return "internal_suspicious"
    return "internal_benign"


_NET_MULTIPLIER = {
    "external":            1.0,
    "external_benign":     0.3,
    "internal_suspicious": 0.7,
    "internal_benign":     0.0,
}

# =============================================================================
# SUSPICIOUS DEFINITIONS
# =============================================================================

SUSPICIOUS_EXES: dict[str, tuple[str, float]] = {
    "nmap":       ("recon", 1.5), "wireshark":  ("recon", 1.5),
    "tshark":     ("recon", 1.5), "netstat":    ("recon", 1.0),
    "whoami":     ("recon", 1.0), "ipconfig":   ("recon", 1.0),
    "arp":        ("recon", 1.0), "nslookup":   ("recon", 1.0),
    "tracert":    ("recon", 1.0), "masscan":    ("recon", 2.0),
    "zenmap":     ("recon", 1.5),
    "psexec":     ("remote_access", 2.0), "putty":       ("remote_access", 1.5),
    "winscp":     ("remote_access", 2.0), "mstsc":       ("remote_access", 1.5),
    "vnc":        ("remote_access", 1.5), "teamviewer":  ("remote_access", 1.5),
    "anydesk":    ("remote_access", 1.5), "plink":       ("remote_access", 2.0),
    "ncat":       ("remote_access", 2.0), "netcat":      ("remote_access", 2.0),
    "ftp":        ("exfiltration", 1.5), "rclone":   ("exfiltration", 2.5),
    "robocopy":   ("exfiltration", 1.0), "curl":     ("exfiltration", 1.5),
    "wget":       ("exfiltration", 1.5),
    "powershell": ("execution", 1.5), "wscript":   ("execution", 2.0),
    "mshta":      ("execution", 2.0), "rundll32":  ("execution", 2.0),
    "regsvr32":   ("execution", 2.0), "cscript":   ("execution", 1.5),
    "certutil":   ("execution", 2.0), "bitsadmin": ("execution", 2.0),
    "msiexec":    ("execution", 1.5),
    "sdelete":    ("deletion", 2.5), "eraser":    ("deletion", 2.5),
    "cipher":     ("deletion", 2.0), "ccleaner":  ("deletion", 2.0),
    "diskpart":   ("deletion", 2.0), "shred":     ("deletion", 2.5),
    "7z":         ("compression", 1.0), "winrar":  ("compression", 1.0),
    "zip":        ("compression", 0.5),
    "mimikatz":   ("credential", 3.0), "pwdump":   ("credential", 3.0),
    "hashcat":    ("credential", 2.5), "hydra":    ("credential", 2.5),
    "aircrack":   ("credential", 2.5),
}

SUSPICIOUS_DOMAINS: dict[str, tuple[str, int]] = {
    "gunbroker":    ("weapons", 3), "armslist":    ("weapons", 3),
    "gunsamerica":  ("weapons", 3), "bladehq":     ("weapons", 2),
    "ar15":         ("weapons", 3), "ammoland":    ("weapons", 2),
    "massshooting": ("violence", 4), "massacre":   ("violence", 4),
    "explosive":    ("violence", 4), "manifesto":  ("violence", 3),
    "tor2web":      ("anonymization", 3), ".onion": ("anonymization", 4),
    "i2p":          ("anonymization", 3), "darkweb":("anonymization", 3),
    "mega.nz":      ("exfil_site", 3), "wetransfer": ("exfil_site", 2),
    "anonfiles":    ("exfil_site", 3), "gofile":     ("exfil_site", 2),
    "zippyshare":   ("exfil_site", 2), "4shared":    ("exfil_site", 2),
    "mediafire":    ("exfil_site", 1), "sendspace":  ("exfil_site", 2),
    "pastebin":     ("paste_site", 2), "hastebin":   ("paste_site", 2),
    "ghostbin":     ("paste_site", 2), "privatebin": ("paste_site", 2),
    "nordvpn":      ("vpn", 2), "expressvpn": ("vpn", 2),
    "protonvpn":    ("vpn", 2), "hide.me":    ("vpn", 2),
    "mullvad":      ("vpn", 2), "hidemyass":  ("vpn", 2),
    "exploit-db":   ("hacking", 4), "metasploit": ("hacking", 3),
    "hackforums":   ("hacking", 3), "nulled":     ("hacking", 3),
    "shodan":       ("hacking", 2),
    "theblaze":     ("propaganda", 2), "breitbart": ("propaganda", 2),
    "infowars":     ("propaganda", 2), "dailywire": ("propaganda", 2),
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
    4625: ("logon_failure", 2),        529: ("logon_failure", 2),
    4740: ("account_lockout", 3),      539: ("account_lockout", 3),
    1102: ("log_cleared", 5),          517: ("log_cleared", 5),
    7045: ("service_install", 3),     4697: ("service_install", 3),
    4672: ("privilege_escalation", 3), 576: ("privilege_escalation", 3),
    4688: ("process_creation", 1),     592: ("process_creation", 1),
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
    return ""


def log_scale(value: float, max_val: float) -> float:
    if max_val <= 0:
        return 0.0
    return (math.log1p(value) / math.log1p(max_val)) * 100.0

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
# =============================================================================

def score_deleted_files(data: dict | None, sid_map: dict | None = None) -> dict:
    scores: dict = defaultdict(lambda: {"count": 0, "evidence": []})
    unresolved = 0
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        user = resolve_username(rec.get("original_path", ""),
                                rec.get("sid"), sid_map)
        if not user:
            user = "__unknown__"
            unresolved += 1
        scores[user]["count"] += 1
        scores[user]["evidence"].append({
            "path":       rec.get("original_path", ""),
            "deleted_at": rec.get("deleted_at", ""),
            "file_size":  rec.get("file_size", ""),
            "source":     rec.get("source", ""),
        })
    if unresolved:
        print(f"  [!] deleted_files: {unresolved} records with unresolvable user attribution")
    return dict(scores)


def score_application_activity(data: dict | None, sid_map: dict | None = None) -> dict:
    scores: dict = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return dict(scores)
    shared_count = 0
    attributed_count = 0
    for rec in data.get("records", []):
        exe       = rec.get("exe_name", "").lower()
        exe_path  = rec.get("exe_path", "") or rec.get("path", "") or ""
        run_count = rec.get("run_count") or 1
        last_run  = rec.get("last_run", "")
        for kw, (cat, mult) in SUSPICIOUS_EXES.items():
            if kw in exe:
                user = resolve_username(exe_path, rec.get("sid"), sid_map)
                if not user:
                    user = "__apps__"
                    shared_count += 1
                else:
                    attributed_count += 1
                scores[user]["count"]          += run_count
                scores[user]["weighted_count"] += run_count * mult
                scores[user]["evidence"].append({
                    "exe":        exe,
                    "category":   cat,
                    "multiplier": mult,
                    "run_count":  run_count,
                    "last_run":   last_run,
                    "attributed": user != "__apps__",
                })
                break
    if shared_count or attributed_count:
        print(f"  [i] app_activity: {attributed_count} attributed to users, "
              f"{shared_count} in shared pool")
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
    scores: dict = defaultdict(lambda: {
        "count": 0.0, "raw_count": 0, "external": 0, "internal_suspicious": 0,
        "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    for evt in data.get("network_events", []):
        edata    = evt.get("event_data", {})
        dest_ip  = edata.get("DestAddress")  or edata.get("IpAddress", "")
        dest_port= edata.get("DestPort")     or edata.get("IpPort", "")
        process  = (edata.get("Application") or edata.get("ProcessName", "")).lower()
        url      = edata.get("Url", "") or edata.get("Uri", "") or ""
        
        traffic_class = classify_network(dest_ip, dest_port, process, url)
        multiplier    = _NET_MULTIPLIER.get(traffic_class, 0.0)
        if multiplier == 0.0:
            continue
        uname = (edata.get("SubjectUserName") or edata.get("TargetUserName") or
                 edata.get("AccountName") or "")
        if not uname:
            continue
        key = norm_name(uname)
        scores[key]["raw_count"]  += 1
        scores[key]["count"]      += multiplier
        scores[key]["account_type"] = account_type(uname)
        if "external" in traffic_class:
            scores[key]["external"] += 1
        elif traffic_class == "internal_suspicious":
            scores[key]["internal_suspicious"] += 1
        scores[key]["evidence"].append({
            "event_id":      evt.get("event_id"),
            "timestamp":     evt.get("timestamp", ""),
            "dest_ip":       dest_ip,
            "dest_port":     dest_port,
            "process":       process,
            "url":           url[:200] if url else "",
            "traffic_class": traffic_class,
            "multiplier":    multiplier,
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
                "flag":         "high_failed_logins",
                "failed_logins": failed,
                "last_login":    rec.get("last_login", ""),
            })
        if rec.get("account_disabled"):
            scores[key]["count"] += 1
            scores[key]["evidence"].append({"flag": "account_disabled_but_active"})
    return dict(scores)


def score_network_from_browser(data: dict | None) -> dict:
    scores: dict = defaultdict(lambda: {
        "count": 0.0, "raw_count": 0, "external": 0, "internal_suspicious": 0,
        "account_type": "user", "evidence": [],
    })
    if not data:
        return dict(scores)
    
    for rec in data.get("records", []):
        uname = rec.get("username", "")
        url = (rec.get("url") or "").lower()
        title = rec.get("title", "").lower()
        visited = rec.get("visited_at", "")
        key = norm_name(uname)
        if not key:
            continue
        
        matched = False
        for kw, (cat, weight) in SUSPICIOUS_DOMAINS.items():
            if kw in url or kw in title:
                net_weight = weight * 0.3
                scores[key]["count"] += net_weight
                scores[key]["raw_count"] += 1
                scores[key]["external"] += 1
                scores[key]["account_type"] = account_type(uname)
                scores[key]["evidence"].append({
                    "url": rec.get("url", ""),
                    "category": cat,
                    "weight": weight,
                    "visited_at": visited,
                    "browser": rec.get("browser", ""),
                })
                matched = True
                break
        
        if not matched:
            for domain in ["onedrive.live.com", "drive.google.com", "dropbox.com", 
                          "box.com", "amazonaws.com", "s3.amazonaws.com"]:
                if domain in url:
                    scores[key]["count"] += 0.1
                    scores[key]["raw_count"] += 1
                    scores[key]["external"] += 1
                    break
    
    return dict(scores)


# =============================================================================
# TIMELINE BUILDER
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

    for ev in app_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("last_run"))
        if ts:
            events.append({"ts": ts, "type": "application_exec",
                           "detail": ev.get("exe", "")})

    return sorted(events, key=lambda x: x["ts"])


def _has_any_evidence(user: str, doc_s: dict, del_s: dict,
                      app_s: dict, net_s: dict, evt_s: dict) -> bool:
    return (
        doc_s.get(user, {}).get("count", 0) > 0 or
        del_s.get(user, {}).get("count", 0) > 0 or
        app_s.get(user, {}).get("count", 0) > 0 or
        net_s.get(user, {}).get("raw_count", 0) > 0 or
        evt_s.get(user, {}).get("count", 0) > 0
    )

# =============================================================================
# TIMELINE CORRELATION
# =============================================================================

def calculate_timeline_bonuses(
    user: str, doc_s: dict, del_s: dict,
    app_s: dict, net_s: dict, evt_s: dict,
    artifact_score: float = 0.0,
) -> tuple[int, list[dict]]:
    if not _has_any_evidence(user, doc_s, del_s, app_s, net_s, evt_s):
        return 0, []

    timeline = _build_timeline(user, doc_s, del_s, app_s, net_s, evt_s)
    if not timeline:
        return 0, []

    bonus    = 0
    patterns: list[dict] = []
    used:     set[Any]   = set()

    bonus_by_type: dict[str, int] = defaultdict(int)

    def add_bonus(pattern_key: str, detail: str, timestamp: str) -> bool:
        cap = TIMELINE_BONUS_CAP[pattern_key]
        current = bonus_by_type[pattern_key]
        if current >= cap:
            return False
        b = TIMELINE_BONUS[pattern_key]
        bonus_by_type[pattern_key] += b
        patterns.append({
            "pattern":   pattern_key,
            "bonus":     b,
            "detail":    detail,
            "timestamp": timestamp,
        })
        return True

    # Pattern 1: File access -> deletion within 5 min
    for acc in (e for e in timeline if e["type"] == "document_access"):
        for dlt in (e for e in timeline if e["type"] == "deleted_file"):
            pair = (id(acc), id(dlt))
            if pair in used:
                continue
            delta = (dlt["ts"] - acc["ts"]).total_seconds()
            if 0 <= delta <= 300:
                used.add(pair)
                if add_bonus(
                    "file_access_then_deletion",
                    f"Accessed '{acc['detail']}' then deleted '{dlt['detail']}' ({int(delta)}s later)",
                    acc["ts"].isoformat(),
                ):
                    bonus += TIMELINE_BONUS["file_access_then_deletion"]

    # Pattern 2: App execution -> network activity within 10 min
    for app in (e for e in timeline if e["type"] == "application_exec"):
        for net in (e for e in timeline if e["type"] == "network_activity"):
            pair = (id(app), id(net))
            if pair in used:
                continue
            delta = (net["ts"] - app["ts"]).total_seconds()
            if 0 <= delta <= 600:
                used.add(pair)
                if add_bonus(
                    "app_exec_then_network",
                    f"Ran '{app['detail']}' then network to '{net['detail']}' ({int(delta)}s later)",
                    app["ts"].isoformat(),
                ):
                    bonus += TIMELINE_BONUS["app_exec_then_network"]

    # Pattern 3: Activity burst THEN log gap >= 1 hour
    BURST_WINDOW_SEC = 3600
    MIN_PRE_GAP_EVENTS = 3

    for i in range(len(timeline) - 1):
        gap = (timeline[i+1]["ts"] - timeline[i]["ts"]).total_seconds()
        if gap >= 3600:
            gap_start = timeline[i]["ts"]
            pre_gap_events = [
                e for e in timeline[:i+1]
                if (gap_start - e["ts"]).total_seconds() <= BURST_WINDOW_SEC
            ]
            if len(pre_gap_events) >= MIN_PRE_GAP_EVENTS:
                key = f"gap_{timeline[i]['ts'].isoformat()}"
                if key not in used:
                    used.add(key)
                    if add_bonus(
                        "activity_then_log_gap",
                        f"{gap/3600:.1f}h silence after burst of {len(pre_gap_events)} events "
                        f"(last: {timeline[i]['ts'].isoformat()})",
                        timeline[i]["ts"].isoformat(),
                    ):
                        bonus += TIMELINE_BONUS["activity_then_log_gap"]
                    break

    # Pattern 4: Rapid actions - >= 5 events within 60 s
    for i, evt in enumerate(timeline):
        window = [e for e in timeline
                  if 0 <= (e["ts"] - evt["ts"]).total_seconds() <= 60]
        if len(window) >= 5:
            key = f"rapid_{evt['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                if add_bonus(
                    "rapid_actions",
                    f"{len(window)} events in 60s starting {evt['ts'].isoformat()}",
                    evt["ts"].isoformat(),
                ):
                    bonus += TIMELINE_BONUS["rapid_actions"]

    # Pattern 5: Multi-source consistency - >= 3 types in 5 min
    for i, evt in enumerate(timeline):
        window = [e for e in timeline
                  if 0 <= (e["ts"] - evt["ts"]).total_seconds() <= 300]
        types = {e["type"] for e in window}
        if len(types) >= 3:
            key = f"multi_{evt['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                if add_bonus(
                    "multi_source_consistency",
                    f"{len(types)} artifact types in 5min: {', '.join(sorted(types))}",
                    evt["ts"].isoformat(),
                ):
                    bonus += TIMELINE_BONUS["multi_source_consistency"]

    return bonus, patterns

# =============================================================================
# EVIDENCE DIVERSITY SCORE
# =============================================================================

def compute_diversity_score(
    del_c: int, evt_c: int, app_wc: float, net_c: float,
    doc_sc: int, brw_fc: int, usr_c: int,
) -> dict:
    categories = {
        "deleted_files":    del_c > 0,
        "event_anomalies":  evt_c > 0,
        "app_activity":     app_wc > 0,
        "network_activity": net_c > 0,
        "document_access":  doc_sc > 0,
        "browser_history":  brw_fc > 0,
        "user_accounts":    usr_c > 0,
    }
    hit = [k for k, v in categories.items() if v]
    count = len(hit)
    score = round(count / 7.0, 4)
    return {
        "category_count":   count,
        "diversity_score":  score,
        "categories_hit":   hit,
    }

# =============================================================================
# [FIX-10D] REAL EVIDENCE DETECTION (fixed browser_history check)
# =============================================================================

def _has_real_evidence(user_data: dict) -> bool:
    """
    Check if user has REAL evidence (not just shared app pool).
    Users with ONLY shared pool app_activity should NOT be elevated to HIGH.
    
    [FIX-10D] Browser history: only count if there are flagged URLs.
    Raw browser history without flagged URLs should not count as real evidence.
    """
    scores = user_data.get("artifact_scores", {})
    
    # Real evidence categories
    if scores.get("deleted_files", {}).get("raw_count", 0) > 0:
        return True
    if scores.get("event_anomalies", {}).get("raw_count", 0) > 0:
        return True
    if scores.get("document_access", {}).get("raw_count", 0) > 0:
        return True
    
    # [FIX-10D] Browser history: only count flagged URLs as real evidence
    brw = scores.get("browser_history", {})
    if brw.get("flagged_count", 0) > 0 or brw.get("flagged_weight", 0) > 0:
        return True
    
    if scores.get("user_accounts", {}).get("raw_count", 0) > 0:
        return True
    if scores.get("network_activity", {}).get("raw_count", 0) > 0:
        return True
    
    # App activity: only count if attributed (not just shared pool)
    app = scores.get("app_activity", {})
    if app.get("attributed_count", 0) > 0:
        return True
    
    return False

# =============================================================================
# AGGREGATE - two-pass hybrid scoring with log1p
# =============================================================================

def aggregate_scores(
    users: dict, del_s: dict, app_s: dict, evt_s: dict,
    net_s: dict, doc_s: dict, brw_s: dict, usr_s: dict,
    net_brw_s: dict,
) -> list[dict]:

    all_keys: set[str] = set(users.keys())
    for d in (del_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s):
        all_keys.update(d.keys())
    all_keys.update(k for k in app_s.keys() if k != "__apps__")
    all_keys = {k for k in all_keys if k and k not in ("", "-", "__unknown__")}

    if not all_keys:
        print("  [!] No accounts found in any artifact - check JSON files.")
        return []

    num_users = len({k for k in all_keys if is_rankable(k)}) or 1

    # Pass 1: raw scores
    raw: dict[str, float] = {}
    for user in all_keys:
        del_c   = del_s.get(user, {}).get("count", 0)
        evt_wc  = evt_s.get(user, {}).get("weighted_count", 0.0)
        net_c   = net_s.get(user, {}).get("count", 0.0)
        net_brw = net_brw_s.get(user, {}).get("count", 0.0)
        doc_sc  = doc_s.get(user, {}).get("sensitive_count", 0)
        brw_fw  = brw_s.get(user, {}).get("flagged_weight", 0.0)
        usr_c   = usr_s.get(user, {}).get("count", 0)

        app_user_wc = app_s.get(user, {}).get("weighted_count", 0.0)
        app_shared  = app_s.get("__apps__", {}).get("weighted_count", 0.0)
        app_share   = app_user_wc + (app_shared / num_users)

        raw[user] = (
            del_c   * WEIGHTS["deleted_files"]
            + evt_wc * WEIGHTS["event_anomalies"]
            + app_share    * WEIGHTS["app_activity"]
            + (net_c + net_brw) * WEIGHTS["network_activity"]
            + doc_sc       * WEIGHTS["document_access"]
            + brw_fw       * WEIGHTS["browser_history"]
            + min(usr_c * WEIGHTS["user_accounts"], 5)
        )

    max_raw = max(raw.values(), default=1.0) or 1.0

    # Pass 2: normalized + hybrid
    results: list[dict] = []

    for user in sorted(all_keys):
        uinfo        = users.get(user, {"username": user, "account_type": account_type(user)})
        display_name = uinfo.get("username", user)
        acct_type    = uinfo.get("account_type", account_type(user))

        del_c   = del_s.get(user, {}).get("count", 0)
        evt_c   = evt_s.get(user, {}).get("count", 0)
        evt_wc  = evt_s.get(user, {}).get("weighted_count", 0.0)
        net_c   = net_s.get(user, {}).get("count", 0.0)
        net_brw = net_brw_s.get(user, {}).get("count", 0.0)
        net_raw = net_s.get(user, {}).get("raw_count", 0) + net_brw_s.get(user, {}).get("raw_count", 0)
        net_ext = net_s.get(user, {}).get("external", 0) + net_brw_s.get(user, {}).get("external", 0)
        net_int = net_s.get(user, {}).get("internal_suspicious", 0)
        doc_t   = doc_s.get(user, {}).get("count", 0)
        doc_sc  = doc_s.get(user, {}).get("sensitive_count", 0)
        brw_t   = brw_s.get(user, {}).get("count", 0)
        brw_fc  = brw_s.get(user, {}).get("flagged_count", 0)
        brw_fw  = brw_s.get(user, {}).get("flagged_weight", 0.0)
        usr_c   = usr_s.get(user, {}).get("count", 0)
        app_user_wc = app_s.get(user, {}).get("weighted_count", 0.0)
        app_shared  = app_s.get("__apps__", {}).get("weighted_count", 0.0)
        app_share   = app_user_wc + (app_shared / num_users)

        net_total = net_c + net_brw

        raw_score = raw[user]

        total_ev = max(del_c + evt_c + net_total + doc_sc + brw_fc + usr_c + app_share, 1)
        def norm(v: float) -> float: return v / total_ev

        norm_score = (
            WEIGHTS["deleted_files"]    * norm(del_c)
            + WEIGHTS["event_anomalies"]  * norm(evt_wc)
            + WEIGHTS["app_activity"]     * norm(app_share)
            + WEIGHTS["network_activity"] * norm(net_total)
            + WEIGHTS["document_access"]  * norm(doc_sc)
            + WEIGHTS["browser_history"]  * norm(brw_fw)
            + WEIGHTS["user_accounts"]    * norm(usr_c)
        )

        raw_scaled  = log_scale(raw_score, max_raw)
        norm_scaled = (norm_score / MAX_NORM_SCORE) * 100.0
        artifact_score = RAW_WEIGHT * raw_scaled + NORM_WEIGHT * norm_scaled

        tl_bonus, tl_patterns = calculate_timeline_bonuses(
            user, doc_s, del_s, app_s, net_s, evt_s,
            artifact_score=artifact_score,
        )

        final_score = artifact_score + tl_bonus

        diversity = compute_diversity_score(
            del_c, evt_c, app_share, net_total, doc_sc, brw_fc, usr_c
        )

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
                                     "weighted_count": round(evt_wc, 2),
                                     "score": round(evt_wc * WEIGHTS["event_anomalies"], 2)},
                "app_activity":     {
                    "attributed_count": app_s.get(user, {}).get("count", 0),
                    "shared_pool_count": app_s.get("__apps__", {}).get("count", 0),
                    "effective_weighted": round(app_share, 2),
                    "score": round(app_share * WEIGHTS["app_activity"], 2),
                },
                "network_activity": {"raw_count": net_raw,
                                     "external": net_ext,
                                     "internal_suspicious": net_int,
                                     "weighted_count": round(net_total, 2),
                                     "score": round(net_total * WEIGHTS["network_activity"], 2)},
                "document_access":  {"raw_count": doc_t, "sensitive_count": doc_sc,
                                     "score": round(doc_sc * WEIGHTS["document_access"], 2)},
                "browser_history":  {"raw_count": brw_t, "flagged_count": brw_fc,
                                     "flagged_weight": round(brw_fw, 2),
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
            "diversity":         diversity,
            "risk_label":        None,
            "evidence": {
                "deleted_files":    del_s.get(user, {}).get("evidence", [])[:20],
                "event_anomalies":  evt_s.get(user, {}).get("evidence", [])[:20],
                "network_activity": net_s.get(user, {}).get("evidence", [])[:20] + 
                                    net_brw_s.get(user, {}).get("evidence", [])[:10],
                "document_access":  doc_s.get(user, {}).get("evidence", [])[:20],
                "browser_history":  brw_s.get(user, {}).get("evidence", [])[:20],
                "app_activity":     (
                    app_s.get(user, {}).get("evidence", [])[:10]
                    + app_s.get("__apps__", {}).get("evidence", [])[:10]
                ),
                "user_accounts":    usr_s.get(user, {}).get("evidence", []),
            },
        })

    # Sort: rankable by score, system accounts unranked
    rankable  = sorted([r for r in results if r["rankable"]],
                       key=lambda x: x["final_score"], reverse=True)
    sys_accts = [r for r in results if not r["rankable"]]

    for i, r in enumerate(rankable, 1):
        r["rank"] = i
    for r in sys_accts:
        r["rank"] = None

    # Assign risk labels using REAL EVIDENCE gate
    _assign_risk_labels(rankable)

    return rankable + sys_accts


# =============================================================================
# RISK CLASSIFICATION - REAL EVIDENCE GATE
# =============================================================================

def _assign_risk_labels(ranked_users: list[dict]) -> None:
    """
    Assigns HIGH / MEDIUM / LOW labels with REAL EVIDENCE gate.

    [FIX-10D] Browser history without flagged URLs does NOT count as real evidence.
    Users with ONLY shared app pool or unflagged browser history are LOW.
    Only users with REAL evidence can be elevated to HIGH/MEDIUM.
    """
    if not ranked_users:
        return

    # First pass: users with no real evidence or artifact_score == 0 are LOW
    for r in ranked_users:
        if r["artifact_score"] <= 0 or not _has_real_evidence(r):
            r["risk_label"] = "LOW"

    # Second pass: only users with real evidence AND artifact_score > 0
    real_evidence_users = [
        r for r in ranked_users 
        if r["artifact_score"] > 0 and _has_real_evidence(r)
    ]

    if not real_evidence_users:
        return

    n = len(real_evidence_users)

    if n == 1:
        real_evidence_users[0]["risk_label"] = "HIGH"
        return

    if n == 2:
        sorted_users = sorted(real_evidence_users, 
                              key=lambda x: x["final_score"], reverse=True)
        sorted_users[0]["risk_label"] = "HIGH"
        sorted_users[1]["risk_label"] = "MEDIUM"
        return

    # n >= 3: use score-value percentile thresholds on real evidence users only
    scores_sorted = sorted(r["final_score"] for r in real_evidence_users)
    p80 = scores_sorted[math.floor((n - 1) * 0.80)]
    p50 = scores_sorted[math.floor((n - 1) * 0.50)]

    for r in real_evidence_users:
        s = r["final_score"]
        if s >= p80:
            r["risk_label"] = "HIGH"
        elif s >= p50:
            r["risk_label"] = "MEDIUM"
        else:
            r["risk_label"] = "LOW"

# =============================================================================
# EVALUATION
# =============================================================================

def evaluate_results(results: list[dict], ground_truth: dict,
                     threshold_method: str = "sigma") -> dict:
    rankable = [r for r in results if r["rankable"]]
    scores = [r["final_score"] for r in rankable]

    if threshold_method == "positive":
        threshold = 0.0
    elif threshold_method == "percentile" and scores:
        scores_sorted = sorted(scores)
        cutoff_idx = int(len(scores_sorted) * 0.80)
        threshold = scores_sorted[cutoff_idx] if cutoff_idx < len(scores_sorted) else 0.0
    elif scores and len(scores) >= 2:
        mean = statistics.mean(scores)
        std  = statistics.stdev(scores)
        threshold = mean + std
    else:
        threshold = 0.0

    TP = FP = FN = TN = 0
    details = []
    for r in rankable:
        user      = r["username_key"]
        predicted = r["final_score"] >= threshold
        actual    = ground_truth.get(user, ground_truth.get(r["username"], False))
        if predicted and actual:       TP += 1; label = "TP"
        elif predicted and not actual: FP += 1; label = "FP"
        elif not predicted and actual: FN += 1; label = "FN"
        else:                          TN += 1; label = "TN"
        details.append({
            "user":         r["username"],
            "predicted":    predicted,
            "actual":       actual,
            "result":       label,
            "final_score":  r["final_score"],
            "risk_label":   r.get("risk_label"),
            "diversity":    r.get("diversity", {}).get("diversity_score"),
        })

    prec = TP / (TP + FP) if (TP + FP) else 0
    rec  = TP / (TP + FN) if (TP + FN) else 0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    return {
        "threshold":        round(threshold, 4),
        "threshold_method": threshold_method,
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "precision": round(prec, 4),
        "recall":    round(rec, 4),
        "f1":        round(f1, 4),
        "details":   details,
    }

# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Correlate forensic artifacts -> per-user suspicion scores (v10.1)"
    )
    ap.add_argument("--json-dir",     required=True)
    ap.add_argument("--output",       required=True)
    ap.add_argument("--ground-truth", default="",
                    help="Optional JSON ground-truth file for evaluation")
    ap.add_argument("--threshold-method", default="sigma",
                    choices=["positive", "sigma", "percentile"],
                    help="Evaluation threshold method (default: sigma)")
    args = ap.parse_args()

    json_dir = Path(args.json_dir)
    out_path = Path(args.output)

    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║       Forensic Artifact Correlator - v10.1          ║")
    print("  ║    zero-guard · evidence-gated risk classification  ║")
    print("  ║    + real-evidence gate (browser flagged only)      ║")
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
    app_s = score_application_activity(app_data, sid_map)
    evt_s = score_event_logs(evt_data)
    net_s = score_network_activity(net_data)
    doc_s = score_document_access(doc_data)
    brw_s = score_browser_history(brw_data)
    usr_s = score_user_accounts(ua_data)

    net_brw_s = score_network_from_browser(brw_data)

    print(f"    Deleted files      : {sum(v['count'] for v in del_s.values())} records")
    print(f"    Event anomalies    : {sum(v['count'] for v in evt_s.values())} records")
    print(f"    Suspicious apps    : {sum(v.get('count',0) for v in app_s.values())} executions")
    net_ext = sum(v.get('external',0) for v in net_s.values())
    net_int = sum(v.get('internal_suspicious',0) for v in net_s.values())
    net_brw_count = sum(v.get('raw_count',0) for v in net_brw_s.values())
    print(f"    Network (external) : {net_ext}  |  internal suspicious : {net_int}")
    print(f"    Network from browser : {net_brw_count} flagged URL visits")
    print(f"    Sensitive docs     : {sum(v.get('sensitive_count',0) for v in doc_s.values())}")
    print(f"    Flagged URLs       : {sum(v.get('flagged_count',0) for v in brw_s.values())}")

    # Aggregate
    print("[*] Aggregating - log1p hybrid scoring + evidence diversity...")
    results = aggregate_scores(users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s)

    # Summary
    ranked = [r for r in results if r["rankable"]]
    print()
    print("  ┌──────────────────────────────────────────────────────────────────────────────┐")
    print("  │  SUSPICION SCORE RANKING                                                    │")
    print("  ├──────┬──────────────────────┬──────────┬──────────┬────────────┬──────┬─────┤")
    print("  │ Rank │ Username             │ Artifact │ Timeline │ Final      │ Risk │ Div │")
    print("  ├──────┼──────────────────────┼──────────┼──────────┼────────────┼──────┼─────┤")
    for r in ranked:
        div = r.get("diversity", {}).get("category_count", 0)
        risk = r.get("risk_label", "---")
        print(f"  │ {r['rank']:<4} │ {r['username']:<20} │ "
              f"{r['artifact_score']:<8.2f} │ {r['timeline_bonus']:<8} │ "
              f"{r['final_score']:<10.2f} │ {risk:<4} │ {div}/7 │")
    print("  └──────┴──────────────────────┴──────────┴──────────┴────────────┴──────┴─────┘")
    print()

    # Evaluation
    evaluation = None
    if args.ground_truth:
        gt_path = Path(args.ground_truth)
        if gt_path.exists():
            with open(gt_path, encoding="utf-8") as f:
                gt = json.load(f)
            evaluation = evaluate_results(results, gt, args.threshold_method)
            print(f"[*] Evaluation (threshold={evaluation['threshold']:.2f}, "
                  f"method={evaluation['threshold_method']}):")
            print(f"    Precision={evaluation['precision']}  "
                  f"Recall={evaluation['recall']}  F1={evaluation['f1']}")
            print(f"    TP={evaluation['TP']} FP={evaluation['FP']} "
                  f"FN={evaluation['FN']} TN={evaluation['TN']}")
            print()

    # Write output
    output = {
        "metadata": {
            "version":                "v10.1",
            "generated_at":           now_iso(),
            "json_source":            str(json_dir),
            "total_accounts":         len(results),
            "rankable_accounts":      len(ranked),
            "scoring_method":         f"log1p_hybrid_{int(RAW_WEIGHT*100)}_{int(NORM_WEIGHT*100)}_normfix_zerogard",
            "network_classification": "enhanced: internal/external + cloud storage detection",
            "system_accounts":        "tagged, retained in data, excluded from ranking",
            "app_attribution":        "per-user path-based + shared pool ALL users",
            "browser_network":        "extracted from flagged URLs (weighted 0.3x)",
            "real_evidence_gate":     "users with ONLY shared app pool or unflagged browser → LOW",
            "max_norm_score":         MAX_NORM_SCORE,
            "timeline_bonus_caps":    TIMELINE_BONUS_CAP,
            "log_gap_min_pre_events": 3,
            "weights_used":           WEIGHTS,
            "timeline_bonuses_used":  TIMELINE_BONUS,
            "changes_from_v10": [
                "FIX-10D: _has_real_evidence(): browser_history now only counts as real",
                "         evidence if there are flagged URLs (flagged_count > 0 or",
                "         flagged_weight > 0). Raw browser history without flagged",
                "         URLs should not elevate a user to HIGH/MEDIUM.",
            ],
            "changes_from_v9": [
                "FIX-10A: Risk label assignment: added _has_real_evidence()",
                "FIX-10B: Users with only shared app pool → LOW",
                "FIX-10C: Percentile uses real_evidence users only",
            ],
            "changes_from_v8": [
                "FIX-8A: Network activity: added score_network_from_browser()",
                "FIX-8B: App activity shared pool: now distributed to ALL users",
                "FIX-8C: Timeline bonus gating: uses _has_any_evidence()",
                "FIX-8D: Browser history weight: reduced from 1.0 to 0.5",
                "FIX-8E: Network classification: added cloud storage detection",
            ],
            "changes_from_v7": [
                "FIX-H: Risk labels score-gated: score==0 → LOW unconditionally",
            ],
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