#!/usr/bin/env python3
"""
correlate_artifacts_v3.py
Final analysis stage with hybrid scoring, system account filtering,
and improved user attribution.

Features:
- Hybrid scoring: 60% raw + 40% normalized
- System account filtering (DWM, defaultuser, localsystem, etc.)
- Improved user attribution via path + SID mapping
- Suspicious executable, domain, and event ID detection
- Timeline correlation with pattern detection
- Optional evaluation (precision, recall, F1) if ground truth provided

Usage:
    python3 correlate_artifacts_v3.py --json-dir output/json --output output/scores.json
    python3 correlate_artifacts_v3.py --json-dir output/json --output output/scores.json \\
        --ground-truth ground_truth.json
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

# =============================================================================
# WEIGHTS - Balanced for V3
# =============================================================================

WEIGHTS = {
    "deleted_files":    5,    # Increased - highly suspicious behavior
    "event_anomalies":  4,    # Keep
    "app_activity":     3,    # Keep
    "network_activity": 2,    # Decreased - too many false positives
    "document_access":  3,    # Increased - sensitive document access
    "browser_history":  2,    # Slightly increased
    "user_accounts":    1,    # Keep
}

TIMELINE_BONUS = {
    "file_access_then_deletion":  5,
    "app_exec_then_network":      4,
    "activity_then_log_gap":      6,
    "rapid_actions":              3,
    "multi_source_consistency":   5,
}

# =============================================================================
# SYSTEM ACCOUNTS - NEVER RANK THESE
# =============================================================================

SYSTEM_ACCOUNTS: Set[str] = {
    "localsystem", "system", "local service", "network service",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service",
}

# Pattern for DWM accounts: dwm-1, dwm-2, etc.
DWM_PATTERN = re.compile(r'^dwm-\d+$', re.IGNORECASE)
# Pattern for DefaultUser accounts: defaultuser0, defaultuser1, etc.
DEFAULTUSER_PATTERN = re.compile(r'^defaultuser\d+$', re.IGNORECASE)

# =============================================================================
# SUSPICIOUS DEFINITIONS
# =============================================================================

SUSPICIOUS_EXES = {
    # Recon
    "nmap":       ("recon", 1.5), "wireshark": ("recon", 1.5),
    "tshark":     ("recon", 1.5), "netstat":   ("recon", 1.0),
    "whoami":     ("recon", 1.0), "ipconfig":  ("recon", 1.0),
    "arp":        ("recon", 1.0), "nslookup":  ("recon", 1.0),
    "tracert":    ("recon", 1.0), "masscan":   ("recon", 2.0),
    "zenmap":     ("recon", 1.5),
    # Remote access
    "psexec":     ("remote_access", 2.0), "putty":      ("remote_access", 1.5),
    "winscp":     ("remote_access", 2.0), "mstsc":      ("remote_access", 1.5),
    "vnc":        ("remote_access", 1.5), "teamviewer": ("remote_access", 1.5),
    "anydesk":    ("remote_access", 1.5), "plink":      ("remote_access", 2.0),
    "ncat":       ("remote_access", 2.0), "netcat":     ("remote_access", 2.0),
    # Exfiltration
    "ftp":        ("exfiltration", 1.5), "rclone":  ("exfiltration", 2.5),
    "robocopy":   ("exfiltration", 1.0), "curl":    ("exfiltration", 1.5),
    "wget":       ("exfiltration", 1.5),
    # Execution / bypass
    "powershell": ("execution", 1.5), "wscript":  ("execution", 2.0),
    "mshta":      ("execution", 2.0), "rundll32": ("execution", 2.0),
    "regsvr32":   ("execution", 2.0), "cscript":  ("execution", 1.5),
    "certutil":   ("execution", 2.0), "bitsadmin":("execution", 2.0),
    "msiexec":    ("execution", 1.5),
    # Deletion / wiping
    "sdelete":    ("deletion", 2.5), "eraser":   ("deletion", 2.5),
    "cipher":     ("deletion", 2.0), "ccleaner": ("deletion", 2.0),
    "diskpart":   ("deletion", 2.0), "shred":    ("deletion", 2.5),
    # Compression
    "7z":         ("compression", 1.0), "winrar": ("compression", 1.0),
    "zip":        ("compression", 0.5),
    # Credential tools
    "mimikatz":   ("credential", 3.0), "pwdump":  ("credential", 3.0),
    "hashcat":    ("credential", 2.5), "hydra":   ("credential", 2.5),
    "aircrack":   ("credential", 2.5),
}

SUSPICIOUS_DOMAINS = {
    # Weapons / violence
    "gunbroker":    ("weapons", 3), "armslist":   ("weapons", 3),
    "gunsamerica":  ("weapons", 3), "bladehq":    ("weapons", 2),
    "ar15":         ("weapons", 3), "ammoland":   ("weapons", 2),
    "massshooting": ("violence", 4),"massacre":   ("violence", 4),
    "explosive":    ("violence", 4),"manifesto":  ("violence", 3),
    "bomb making":  ("violence", 5),"how to kill":("violence", 5),
    # Anonymization / dark web
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

SENSITIVE_EXTENSIONS = {
    ".docx", ".doc", ".xlsx", ".xls", ".pdf", ".pptx", ".ppt",
    ".pst", ".ost", ".msg",
    ".kdbx", ".kdb",
    ".pfx", ".p12", ".cer", ".key",
    ".sql", ".db", ".sqlite",
    ".bak", ".backup", ".csv",
}

ANOMALY_EVENT_IDS = {
    4625: ("logon_failure", 2),       529: ("logon_failure", 2),
    4740: ("account_lockout", 3),     539: ("account_lockout", 3),
    1102: ("log_cleared", 5),         517: ("log_cleared", 5),
    7045: ("service_install", 3),     4697: ("service_install", 3),
    4672: ("privilege_escalation", 3),576: ("privilege_escalation", 3),
    4688: ("process_creation", 1),    592: ("process_creation", 1),
    2003: ("firewall_change", 3),     2004: ("firewall_change", 3),
}

# Internal IP ranges (for filtering network traffic)
INTERNAL_IP_PATTERNS = [
    re.compile(r'^10\.\d+\.\d+\.\d+$'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$'),
    re.compile(r'^192\.168\.\d+\.\d+$'),
    re.compile(r'^127\.\d+\.\d+\.\d+$'),
    re.compile(r'^169\.254\.\d+\.\d+$'),
]

# =============================================================================
# HELPERS
# =============================================================================

def load_json(path: Path) -> Optional[Dict | List]:
    """Load JSON file safely."""
    if not path.exists():
        print(f"  [!] Not found: {path.name}")
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [!] Failed to load {path.name}: {e}")
        return None


def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    """Parse timestamp string to datetime object."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def normalize_username(name: str) -> str:
    """Normalize username to lowercase for comparison."""
    return name.strip().lower() if name else "unknown"


def is_system_account(username: str) -> bool:
    """Check if username is a system account that should never be ranked."""
    if not username:
        return True
    
    username_lower = username.lower()
    
    # Check explicit system accounts
    if username_lower in SYSTEM_ACCOUNTS:
        return True
    
    # Check DWM pattern (dwm-1, dwm-2, etc.)
    if DWM_PATTERN.match(username_lower):
        return True
    
    # Check DefaultUser pattern (defaultuser0, defaultuser1, etc.)
    if DEFAULTUSER_PATTERN.match(username_lower):
        return True
    
    # Check for machine accounts (end with $)
    if username_lower.endswith('$'):
        return True
    
    # Check for special system patterns
    if any(x in username_lower for x in ['nt authority', 'window manager']):
        return True
    
    return False


def is_internal_ip(ip: str) -> bool:
    """Check if IP address is in internal range."""
    if not ip:
        return False
    
    ip = ip.strip()
    for pattern in INTERNAL_IP_PATTERNS:
        if pattern.match(ip):
            return True
    
    # Check for localhost
    if ip in ('127.0.0.1', '::1', 'localhost'):
        return True
    
    return False


def now_iso() -> str:
    """Get current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _username_from_path(path: str) -> Optional[str]:
    """Extract username from Windows file path."""
    if not path:
        return None
    m = re.search(
        r"(?:Users|Documents and Settings)[/\\]([^/\\]+)",
        path, re.IGNORECASE
    )
    if m:
        name = m.group(1)
        skip = {"All Users", "Default User", "Default", "Public",
                "LocalService", "NetworkService", "systemprofile"}
        if name.lower() not in {s.lower() for s in skip}:
            return name
    return None


def resolve_username(path: str = "", sid: Optional[str] = None,
                     sid_map: Optional[Dict] = None) -> str:
    """
    Resolve username from path, SID, or fallback to 'unresolved'.
    IMPORTANT: Never returns 'system' - system accounts are filtered out.
    """
    # Try path first (most reliable)
    uname = _username_from_path(path)
    if uname:
        return normalize_username(uname)
    
    # Try SID mapping
    if sid and sid_map:
        uname = sid_map.get(sid)
        if uname:
            return normalize_username(uname)
    
    # Fallback: return 'unresolved' instead of 'system'
    return "unresolved"


def build_sid_map(ua_data: Optional[Dict]) -> Dict[str, str]:
    """Build {SID_string: username} from user_accounts.json."""
    sid_map: Dict[str, str] = {}
    if not ua_data:
        return sid_map
    for rec in ua_data.get("users", {}).get("records", []):
        rid = rec.get("rid")
        uname = rec.get("username", "")
        if rid and uname:
            sid_map[str(rid)] = normalize_username(uname)
    return sid_map


def build_user_list(ua_data: Optional[Dict]) -> Dict[str, Dict]:
    """Build user list from user_accounts.json."""
    users: Dict[str, Dict] = {}
    if not ua_data:
        return users
    for rec in ua_data.get("users", {}).get("records", []):
        uname = rec.get("username", "")
        if not uname:
            continue
        key = normalize_username(uname)
        
        # Skip system accounts
        if is_system_account(key):
            continue
            
        users[key] = {
            "username":         uname,
            "rid":              rec.get("rid"),
            "last_login":       rec.get("last_login", ""),
            "login_count":      rec.get("login_count", 0),
            "failed_logins":    rec.get("failed_logins", 0),
            "account_disabled": rec.get("account_disabled", False),
            "description":      rec.get("description", ""),
        }
    return users

# =============================================================================
# SCORING FUNCTIONS - V3 Improvements
# =============================================================================

def score_deleted_files(data: Optional[Dict], sid_map: Optional[Dict] = None) -> Dict:
    """Weight 5 - Count deleted files per user with improved attribution."""
    scores = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    
    for rec in data.get("records", []):
        user = resolve_username(
            rec.get("original_path", ""),
            rec.get("sid"),
            sid_map
        )
        
        # Skip system accounts
        if is_system_account(user):
            continue
            
        scores[user]["count"] += 1
        scores[user]["evidence"].append({
            "path":       rec.get("original_path", ""),
            "deleted_at": rec.get("deleted_at", ""),
            "file_size":  rec.get("file_size", ""),
            "source":     rec.get("source", ""),
        })
    
    return dict(scores)


def score_application_activity(data: Optional[Dict]) -> Dict:
    """Weight 3 - Flag suspicious executables in prefetch."""
    scores = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return dict(scores)
    
    for rec in data.get("records", []):
        exe = rec.get("exe_name", "").lower()
        run_count = rec.get("run_count") or 1
        last_run = rec.get("last_run", "")
        
        for keyword, (category, multiplier) in SUSPICIOUS_EXES.items():
            if keyword in exe:
                # Only track for correlation, not for user scoring
                # Will be distributed in aggregation
                scores["__system_apps__"]["count"] += run_count
                scores["__system_apps__"]["weighted_count"] += run_count * multiplier
                scores["__system_apps__"]["evidence"].append({
                    "exe":        exe,
                    "category":   category,
                    "multiplier": multiplier,
                    "run_count":  run_count,
                    "last_run":   last_run,
                })
                break
    
    return dict(scores)


def score_event_logs(data: Optional[Dict]) -> Dict:
    """Weight 4 - Count anomalous events per user with system filtering."""
    scores = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return dict(scores)
    
    for evt in data.get("all_events", []):
        eid = evt.get("event_id")
        ts = evt.get("timestamp", "")
        edata = evt.get("event_data", {})
        
        if eid not in ANOMALY_EVENT_IDS:
            continue
        
        label, evt_weight = ANOMALY_EVENT_IDS[eid]
        
        # Extract username from event data
        uname = (
            edata.get("SubjectUserName") or
            edata.get("TargetUserName") or
            edata.get("AccountName") or
            edata.get("String0") or
            ""
        )
        
        # Skip system accounts
        if is_system_account(uname):
            continue
        
        key = normalize_username(uname)
        scores[key]["count"] += 1
        scores[key]["weighted_count"] += evt_weight
        scores[key]["evidence"].append({
            "event_id":  eid,
            "label":     label,
            "weight":    evt_weight,
            "timestamp": ts,
            "computer":  evt.get("computer", ""),
        })
    
    return dict(scores)


def score_network_activity(data: Optional[Dict]) -> Dict:
    """
    Weight 2 - Count network events per user.
    V3: Only count outbound traffic and suspicious processes.
    """
    scores = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    
    for evt in data.get("network_events", []):
        edata = evt.get("event_data", {})
        
        # Check if outbound traffic (dest IP)
        dest_ip = edata.get("DestAddress") or edata.get("IpAddress", "")
        if is_internal_ip(dest_ip):
            continue  # Skip internal traffic
        
        # Check if process is suspicious
        process = (edata.get("Application") or edata.get("ProcessName", "")).lower()
        if process and not any(exe in process for exe in SUSPICIOUS_EXES.keys()):
            # Still count but with lower weight
            # This is handled in aggregation with event weights
            pass
        
        uname = (
            edata.get("SubjectUserName") or
            edata.get("TargetUserName") or
            edata.get("AccountName") or
            ""
        )
        
        # Skip system accounts
        if is_system_account(uname):
            continue
        
        key = normalize_username(uname)
        scores[key]["count"] += 1
        scores[key]["evidence"].append({
            "event_id":  evt.get("event_id"),
            "timestamp": evt.get("timestamp", ""),
            "dest_ip":   dest_ip,
            "dest_port": edata.get("DestPort") or edata.get("IpPort", ""),
            "process":   process,
            "is_suspicious_process": bool(process and any(exe in process for exe in SUSPICIOUS_EXES.keys())),
        })
    
    return dict(scores)


def score_document_access(data: Optional[Dict]) -> Dict:
    """Weight 3 - Count LNK files pointing to sensitive documents per user."""
    scores = defaultdict(lambda: {"count": 0, "sensitive_count": 0, "evidence": []})
    if not data:
        return dict(scores)
    
    for rec in data.get("records", []):
        if rec.get("type") != "lnk":
            continue
        
        uname = rec.get("username", "")
        if is_system_account(uname):
            continue
        
        target = rec.get("target_path", "")
        ts = rec.get("target_accessed", "") or rec.get("target_modified", "")
        
        key = normalize_username(uname)
        scores[key]["count"] += 1
        
        ext = Path(target).suffix.lower() if target else ""
        if ext in SENSITIVE_EXTENSIONS:
            scores[key]["sensitive_count"] += 1
            scores[key]["evidence"].append({
                "target":      target,
                "accessed_at": ts,
                "extension":   ext,
            })
    
    return dict(scores)


def score_browser_history(data: Optional[Dict]) -> Dict:
    """Weight 2 - Flag suspicious URLs per user."""
    scores = defaultdict(lambda: {"count": 0, "flagged_count": 0, "evidence": []})
    if not data:
        return dict(scores)
    
    for rec in data.get("records", []):
        uname = rec.get("username", "")
        if is_system_account(uname):
            continue
        
        url = (rec.get("url") or "").lower()
        title = rec.get("title", "")
        
        key = normalize_username(uname)
        scores[key]["count"] += 1
        
        for keyword, (category, domain_weight) in SUSPICIOUS_DOMAINS.items():
            if keyword in url or keyword in title.lower():
                scores[key]["flagged_count"] += 1
                scores[key]["evidence"].append({
                    "url":      rec.get("url", ""),
                    "title":    title,
                    "category": category,
                    "weight":   domain_weight,
                    "visited":  rec.get("visited_at", ""),
                    "browser":  rec.get("browser", ""),
                })
                break
    
    return dict(scores)


def score_user_accounts(data: Optional[Dict]) -> Dict:
    """Weight 1 - Flag suspicious account attributes."""
    scores = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    
    for rec in data.get("users", {}).get("records", []):
        uname = rec.get("username", "")
        if is_system_account(uname):
            continue
        
        key = normalize_username(uname)
        failed = rec.get("failed_logins", 0) or 0
        
        if failed >= 5:
            scores[key]["count"] += 1
            scores[key]["evidence"].append({
                "flag":          "high_failed_logins",
                "failed_logins": failed,
                "last_login":    rec.get("last_login", ""),
            })
        
        if rec.get("account_disabled"):
            scores[key]["count"] += 1
            scores[key]["evidence"].append({
                "flag": "account_disabled_but_active",
            })
    
    return dict(scores)

# =============================================================================
# TIMELINE BUILDER
# =============================================================================

def _build_user_timeline(user: str, doc_s: Dict, del_s: Dict, 
                         app_s: Dict, net_s: Dict, evt_s: Dict) -> List[Dict]:
    """Build a flat sorted event list for one user across all artifact types."""
    events: List[Dict] = []
    
    # Document access
    for ev in doc_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("accessed_at"))
        if ts:
            events.append({"ts": ts, "type": "document_access",
                           "detail": ev.get("target", "")})
    
    # Deleted files
    for ev in del_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("deleted_at"))
        if ts:
            events.append({"ts": ts, "type": "deleted_file",
                           "detail": ev.get("path", "")})
    
    # Network activity
    for ev in net_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("timestamp"))
        if ts:
            events.append({"ts": ts, "type": "network_activity",
                           "detail": ev.get("dest_ip", "")})
    
    # Event log anomalies
    for ev in evt_s.get(user, {}).get("evidence", []):
        ts = parse_ts(ev.get("timestamp"))
        if ts:
            events.append({"ts": ts, "type": "event_anomaly",
                           "detail": ev.get("label", "")})
    
    # App execution (system-level, include for all users)
    for ev in app_s.get("__system_apps__", {}).get("evidence", []):
        ts = parse_ts(ev.get("last_run"))
        if ts:
            events.append({"ts": ts, "type": "application_exec",
                           "detail": ev.get("exe", "")})
    
    return sorted(events, key=lambda x: x["ts"])

# =============================================================================
# TIMELINE CORRELATION - V3 Improvements
# =============================================================================

def calculate_timeline_bonuses(user: str, doc_s: Dict, del_s: Dict, 
                                app_s: Dict, net_s: Dict, evt_s: Dict,
                                evt_data: Optional[Dict]) -> Tuple[int, List[Dict]]:
    """Calculate timeline bonuses for a user."""
    timeline = _build_user_timeline(user, doc_s, del_s, app_s, net_s, evt_s)
    if not timeline:
        return 0, []
    
    bonus = 0
    patterns: List[Dict] = []
    used: Set[Any] = set()
    
    # Pattern 1: File access → deletion within 5 min
    access_evts = [e for e in timeline if e["type"] == "document_access"]
    delete_evts = [e for e in timeline if e["type"] == "deleted_file"]
    for acc in access_evts:
        for dlt in delete_evts:
            pair = (id(acc), id(dlt))
            if pair in used:
                continue
            delta = (dlt["ts"] - acc["ts"]).total_seconds()
            if 0 <= delta <= 300:
                used.add(pair)
                bonus += TIMELINE_BONUS["file_access_then_deletion"]
                patterns.append({
                    "pattern": "file_access_then_deletion",
                    "bonus":   TIMELINE_BONUS["file_access_then_deletion"],
                    "detail":  f"Accessed '{acc['detail']}' then deleted "
                               f"'{dlt['detail']}' ({int(delta)}s later)",
                    "timestamp": acc["ts"].isoformat(),
                })
    
    # Pattern 2: App execution → network activity within 10 min
    app_evts = [e for e in timeline if e["type"] == "application_exec"]
    net_evts = [e for e in timeline if e["type"] == "network_activity"]
    for app in app_evts:
        for net in net_evts:
            pair = (id(app), id(net))
            if pair in used:
                continue
            delta = (net["ts"] - app["ts"]).total_seconds()
            if 0 <= delta <= 600:
                used.add(pair)
                bonus += TIMELINE_BONUS["app_exec_then_network"]
                patterns.append({
                    "pattern": "app_exec_then_network",
                    "bonus":   TIMELINE_BONUS["app_exec_then_network"],
                    "detail":  f"Ran '{app['detail']}' then network to "
                               f"'{net['detail']}' ({int(delta)}s later)",
                    "timestamp": app["ts"].isoformat(),
                })
    
    # Pattern 3: Activity burst → log gap ≥1 hour
    for i in range(len(timeline) - 1):
        gap = (timeline[i+1]["ts"] - timeline[i]["ts"]).total_seconds()
        if gap >= 3600:
            key = f"gap_{timeline[i]['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                bonus += TIMELINE_BONUS["activity_then_log_gap"]
                patterns.append({
                    "pattern": "activity_then_log_gap",
                    "bonus":   TIMELINE_BONUS["activity_then_log_gap"],
                    "detail":  f"{int(gap/3600):.1f}h silence after "
                               f"{timeline[i]['ts'].isoformat()}",
                    "timestamp": timeline[i]["ts"].isoformat(),
                })
                break  # count once per user
    
    # Pattern 4: Rapid actions — ≥5 events within 60 sec
    for i in range(len(timeline)):
        window = [e for e in timeline
                  if 0 <= (e["ts"] - timeline[i]["ts"]).total_seconds() <= 60]
        if len(window) >= 5:
            key = f"rapid_{timeline[i]['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                bonus += TIMELINE_BONUS["rapid_actions"]
                patterns.append({
                    "pattern": "rapid_actions",
                    "bonus":   TIMELINE_BONUS["rapid_actions"],
                    "detail":  f"{len(window)} events in 60s starting "
                               f"{timeline[i]['ts'].isoformat()}",
                    "timestamp": timeline[i]["ts"].isoformat(),
                })
            break
    
    # Pattern 5: Multi-source consistency — ≥3 artifact types in 5 min
    for i in range(len(timeline)):
        window = [e for e in timeline
                  if 0 <= (e["ts"] - timeline[i]["ts"]).total_seconds() <= 300]
        types_in_window = {e["type"] for e in window}
        if len(types_in_window) >= 3:
            key = f"multi_{timeline[i]['ts'].isoformat()}"
            if key not in used:
                used.add(key)
                bonus += TIMELINE_BONUS["multi_source_consistency"]
                patterns.append({
                    "pattern": "multi_source_consistency",
                    "bonus":   TIMELINE_BONUS["multi_source_consistency"],
                    "detail":  f"{len(types_in_window)} artifact types in 5min: "
                               f"{', '.join(sorted(types_in_window))}",
                    "timestamp": timeline[i]["ts"].isoformat(),
                })
            break
    
    return bonus, patterns

# =============================================================================
# HYBRID SCORING - V3 Core Feature
# =============================================================================

def aggregate_scores(users: Dict, del_s: Dict, app_s: Dict, evt_s: Dict,
                      net_s: Dict, doc_s: Dict, brw_s: Dict, usr_s: Dict,
                      evt_data: Optional[Dict]) -> List[Dict]:
    """
    Aggregate scores using hybrid approach:
    - 60% raw scores (maintains scale, reflects activity volume)
    - 40% normalized scores (fair comparison between users)
    """
    # Collect all valid user keys (excluding system accounts)
    all_keys: Set[str] = set(users.keys())
    for d in (del_s, evt_s, net_s, doc_s, brw_s, usr_s):
        all_keys.update(d.keys())
    
    # Remove system accounts and unresolved
    all_keys = {k for k in all_keys if not is_system_account(k) and k != "unresolved"}
    
    if not all_keys:
        print("  [!] No valid user accounts found!")
        return []
    
    results = []
    
    # First pass: calculate raw scores for normalization
    raw_scores: Dict[str, float] = {}
    max_raw_score = 0.0
    
    for user in sorted(all_keys):
        uinfo = users.get(user, {"username": user})
        display_name = uinfo.get("username", user)
        
        # Raw counts
        del_count = del_s.get(user, {}).get("count", 0)
        evt_count = evt_s.get(user, {}).get("count", 0)
        evt_wcount = evt_s.get(user, {}).get("weighted_count", 0.0)
        net_count = net_s.get(user, {}).get("count", 0)
        doc_sens = doc_s.get(user, {}).get("sensitive_count", 0)
        brw_flagged = brw_s.get(user, {}).get("flagged_count", 0)
        usr_count = usr_s.get(user, {}).get("count", 0)
        
        # App activity (system-wide, distributed)
        app_wcount = app_s.get("__system_apps__", {}).get("weighted_count", 0.0)
        has_activity = (del_count > 0 or evt_count > 0 or net_count > 0)
        app_share = app_wcount / max(len(all_keys), 1) if has_activity else 0
        
        # Raw scoring (similar to V1)
        raw_score = (
            del_count * WEIGHTS["deleted_files"] +
            (evt_wcount / 4) * WEIGHTS["event_anomalies"] +
            app_share * WEIGHTS["app_activity"] +
            net_count * WEIGHTS["network_activity"] +
            doc_sens * WEIGHTS["document_access"] +
            brw_flagged * WEIGHTS["browser_history"] +
            min(usr_count * WEIGHTS["user_accounts"], 5)
        )
        
        raw_scores[user] = raw_score
        if raw_score > max_raw_score:
            max_raw_score = raw_score
    
    # Second pass: calculate final hybrid scores
    for user in sorted(all_keys):
        uinfo = users.get(user, {"username": user})
        display_name = uinfo.get("username", user)
        
        # Raw counts
        del_count = del_s.get(user, {}).get("count", 0)
        evt_count = evt_s.get(user, {}).get("count", 0)
        evt_wcount = evt_s.get(user, {}).get("weighted_count", 0.0)
        net_count = net_s.get(user, {}).get("count", 0)
        doc_total = doc_s.get(user, {}).get("count", 0)
        doc_sens = doc_s.get(user, {}).get("sensitive_count", 0)
        brw_total = brw_s.get(user, {}).get("count", 0)
        brw_flagged = brw_s.get(user, {}).get("flagged_count", 0)
        usr_count = usr_s.get(user, {}).get("count", 0)
        
        # App activity
        app_wcount = app_s.get("__system_apps__", {}).get("weighted_count", 0.0)
        has_activity = (del_count > 0 or evt_count > 0 or net_count > 0)
        app_share = app_wcount / max(len(all_keys), 1) if has_activity else 0
        
        # Total events for normalization
        total_events = (del_count + evt_count + net_count + 
                        doc_sens + brw_flagged + usr_count)
        total_events = max(total_events, 1)  # Avoid division by zero
        
        def norm(c: float) -> float:
            return c / total_events
        
        # Normalized scores (similar to V2)
        norm_score = (
            WEIGHTS["deleted_files"] * norm(del_count) +
            WEIGHTS["event_anomalies"] * norm(evt_wcount) +
            WEIGHTS["app_activity"] * norm(app_share) +
            WEIGHTS["network_activity"] * norm(net_count) +
            WEIGHTS["document_access"] * norm(doc_sens) +
            WEIGHTS["browser_history"] * norm(brw_flagged) +
            WEIGHTS["user_accounts"] * norm(usr_count)
        )
        
        # Raw score (from first pass)
        raw_score = raw_scores.get(user, 0)
        
        # Normalize raw score to 0-100 scale
        raw_score_normalized = (raw_score / max_raw_score * 100) if max_raw_score > 0 else 0
        
        # Normalize norm score to 0-100 scale
        norm_score_scaled = norm_score * 100
        
        # HYBRID: 60% raw (activity volume) + 40% normalized (fair comparison)
        artifact_score = (0.6 * raw_score_normalized) + (0.4 * norm_score_scaled)
        
        # Timeline bonus (additive, not scaled)
        timeline_bonus, timeline_patterns = calculate_timeline_bonuses(
            user, doc_s, del_s, app_s, net_s, evt_s, evt_data
        )
        
        # Final score: hybrid artifact score + timeline bonus
        final_score = artifact_score + timeline_bonus
        
        results.append({
            "username": display_name,
            "username_key": user,
            "account_info": {
                "rid": uinfo.get("rid"),
                "last_login": uinfo.get("last_login", ""),
                "login_count": uinfo.get("login_count", 0),
                "failed_logins": uinfo.get("failed_logins", 0),
                "account_disabled": uinfo.get("account_disabled", False),
            },
            "artifact_scores": {
                "deleted_files": {
                    "raw_count": del_count,
                    "score": round(WEIGHTS["deleted_files"] * norm(del_count), 4)
                },
                "event_anomalies": {
                    "raw_count": evt_count,
                    "score": round(WEIGHTS["event_anomalies"] * norm(evt_wcount), 4)
                },
                "app_activity": {
                    "raw_count": app_s.get("__system_apps__", {}).get("count", 0),
                    "score": round(WEIGHTS["app_activity"] * norm(app_share), 4)
                },
                "network_activity": {
                    "raw_count": net_count,
                    "score": round(WEIGHTS["network_activity"] * norm(net_count), 4)
                },
                "document_access": {
                    "raw_count": doc_total,
                    "sensitive_count": doc_sens,
                    "score": round(WEIGHTS["document_access"] * norm(doc_sens), 4)
                },
                "browser_history": {
                    "raw_count": brw_total,
                    "flagged_count": brw_flagged,
                    "score": round(WEIGHTS["browser_history"] * norm(brw_flagged), 4)
                },
                "user_accounts": {
                    "raw_count": usr_count,
                    "score": round(WEIGHTS["user_accounts"] * norm(usr_count), 4)
                },
            },
            "raw_score": round(raw_score, 2),
            "normalized_score": round(norm_score, 4),
            "artifact_score": round(artifact_score, 2),
            "timeline_bonus": timeline_bonus,
            "timeline_patterns": timeline_patterns,
            "final_score": round(final_score, 2),
            "evidence": {
                "deleted_files": del_s.get(user, {}).get("evidence", [])[:20],
                "event_anomalies": evt_s.get(user, {}).get("evidence", [])[:20],
                "network_activity": net_s.get(user, {}).get("evidence", [])[:20],
                "document_access": doc_s.get(user, {}).get("evidence", [])[:20],
                "browser_history": brw_s.get(user, {}).get("evidence", [])[:20],
                "app_activity": app_s.get("__system_apps__", {}).get("evidence", [])[:20],
                "user_accounts": usr_s.get(user, {}).get("evidence", []),
            },
        })
    
    # Sort by final score descending
    results.sort(key=lambda x: x["final_score"], reverse=True)
    for i, r in enumerate(results, 1):
        r["rank"] = i
    
    return results

# =============================================================================
# EVALUATION
# =============================================================================

def evaluate_results(results: List[Dict], ground_truth: Dict) -> Dict:
    """
    Evaluate scoring accuracy against ground truth.
    ground_truth format: {"username": true/false, ...}
    A user is predicted suspicious if final_score > 0.
    """
    TP = FP = FN = TN = 0
    details = []
    
    for r in results:
        user = r["username_key"]
        predicted = r["final_score"] > 0
        actual = ground_truth.get(user, ground_truth.get(r["username"], False))
        
        if predicted and actual:
            TP += 1
            label = "TP"
        elif predicted and not actual:
            FP += 1
            label = "FP"
        elif not predicted and actual:
            FN += 1
            label = "FN"
        else:
            TN += 1
            label = "TN"
        
        details.append({
            "user": r["username"],
            "predicted": predicted,
            "actual": actual,
            "result": label,
            "final_score": r["final_score"]
        })
    
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0
    
    return {
        "TP": TP,
        "FP": FP,
        "FN": FN,
        "TN": TN,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "details": details,
    }

# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate forensic artifacts → per-user suspicion scores (V3 - Hybrid)"
    )
    parser.add_argument("--json-dir", required=True,
                        help="Directory containing JSON output from extract_artifacts.sh")
    parser.add_argument("--output", required=True,
                        help="Output path for scores.json")
    parser.add_argument("--ground-truth", default="",
                        help="Optional JSON file with ground truth labels for evaluation")
    args = parser.parse_args()
    
    json_dir = Path(args.json_dir)
    out_path = Path(args.output)
    
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║       Forensic Artifact Correlator V3               ║")
    print("  ║       Hybrid Scoring + System Filtering             ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  JSON dir : {json_dir}")
    print(f"  Output   : {out_path}")
    print()
    
    # Load all JSON files
    print("[*] Loading artifacts...")
    ua_data = load_json(json_dir / "user_accounts.json")
    app_data = load_json(json_dir / "application_activity.json")
    evt_data = load_json(json_dir / "event_logs.json")
    net_data = load_json(json_dir / "network_activity.json")
    doc_data = load_json(json_dir / "document_folder_access.json")
    brw_data = load_json(json_dir / "browser_history.json")
    del_data = load_json(json_dir / "deleted_files.json")
    
    # Build user list and SID map
    print("[*] Building user list from SAM (filtering system accounts)...")
    users = build_user_list(ua_data)
    sid_map = build_sid_map(ua_data)
    print(f"    Found {len(users)} user(s): {', '.join(users.keys()) or 'none'}")
    
    # Score each category with V3 improvements
    print("[*] Scoring artifact categories (V3)...")
    del_s = score_deleted_files(del_data, sid_map)
    app_s = score_application_activity(app_data)
    evt_s = score_event_logs(evt_data)
    net_s = score_network_activity(net_data)
    doc_s = score_document_access(doc_data)
    brw_s = score_browser_history(brw_data)
    usr_s = score_user_accounts(ua_data)
    
    print(f"    Deleted files    : {sum(v['count'] for v in del_s.values())} records")
    print(f"    Event anomalies  : {sum(v['count'] for v in evt_s.values())} records")
    print(f"    Suspicious apps  : {sum(v['count'] for v in app_s.values())} executions")
    print(f"    Network events   : {sum(v['count'] for v in net_s.values())} records")
    print(f"    Sensitive docs   : {sum(v.get('sensitive_count', 0) for v in doc_s.values())} files")
    print(f"    Flagged URLs     : {sum(v.get('flagged_count', 0) for v in brw_s.values())} URLs")
    
    # Aggregate with hybrid scoring
    print("[*] Aggregating scores with hybrid (60% raw + 40% normalized)...")
    results = aggregate_scores(
        users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, evt_data
    )
    
    # Print summary table
    print()
    print("  ┌──────────────────────────────────────────────────────────────────┐")
    print("  │  SUSPICION SCORE SUMMARY (V3 - Hybrid)                         │")
    print("  ├──────┬──────────────────────┬──────────┬──────────┬────────────┤")
    print("  │ Rank │ Username             │ Artifact │ Timeline │ Final      │")
    print("  ├──────┼──────────────────────┼──────────┼──────────┼────────────┤")
    for r in results:
        print(f"  │ {r['rank']:<4} │ {r['username']:<20} │ "
              f"{r['artifact_score']:<8.2f} │ {r['timeline_bonus']:<8} │ "
              f"{r['final_score']:<10.2f} │")
    print("  └──────┴──────────────────────┴──────────┴──────────┴────────────┘")
    print()
    
    # Optional evaluation
    evaluation = None
    if args.ground_truth:
        gt_path = Path(args.ground_truth)
        if gt_path.exists():
            with open(gt_path, encoding="utf-8") as f:
                ground_truth = json.load(f)
            evaluation = evaluate_results(results, ground_truth)
            print("[*] Evaluation against ground truth:")
            print(f"    Precision : {evaluation['precision']}")
            print(f"    Recall    : {evaluation['recall']}")
            print(f"    F1 Score  : {evaluation['f1']}")
            print(f"    TP={evaluation['TP']} FP={evaluation['FP']} "
                  f"FN={evaluation['FN']} TN={evaluation['TN']}")
            print()
    
    # Write output
    output = {
        "metadata": {
            "version": "3.0",
            "generated_at": now_iso(),
            "json_source": str(json_dir),
            "total_users": len(results),
            "weights_used": WEIGHTS,
            "timeline_bonuses_used": TIMELINE_BONUS,
            "scoring_method": "hybrid_60_40",
            "system_accounts_filtered": True,
        },
        "users": results,
        "evaluation": evaluation,
    }
    
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"[✓] scores.json written → {out_path}")
    print()


if __name__ == "__main__":
    main()
