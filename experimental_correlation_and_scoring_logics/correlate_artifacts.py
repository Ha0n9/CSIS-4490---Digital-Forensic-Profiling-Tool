#!/usr/bin/env python3
"""
correlate_artifacts.py
Correlate all extracted forensic artifacts → per-user suspicion scores

Usage:
    python3 correlate_artifacts.py --json-dir output/json --output output/scores.json

Input (from extract_artifacts.sh):
    user_accounts.json
    application_activity.json
    event_logs.json
    browser_history.json
    document_folder_access.json
    deleted_files.json

Output:
    scores.json — per-user artifact scores, timeline bonuses, final suspicion scores
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

# =============================================================================
# Constants — Weights
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
    "file_access_then_deletion":    5,
    "app_exec_then_network":        4,
    "activity_then_log_gap":        6,
    "rapid_actions":                3,
    "multi_source_consistency":     5,
}

# =============================================================================
# Suspicious Executable Definitions
# Format: { exe_name_fragment: (category, weight_multiplier) }
# =============================================================================

SUSPICIOUS_EXES = {
    # Recon tools
    "nmap":        ("recon", 1.5),
    "wireshark":   ("recon", 1.5),
    "tshark":      ("recon", 1.5),
    "netstat":     ("recon", 1.0),
    "whoami":      ("recon", 1.0),
    "ipconfig":    ("recon", 1.0),
    "arp":         ("recon", 1.0),
    "nslookup":    ("recon", 1.0),
    "tracert":     ("recon", 1.0),
    "ping":        ("recon", 0.5),
    "masscan":     ("recon", 2.0),
    "zenmap":      ("recon", 1.5),
    "angry ip":    ("recon", 1.5),
    # Remote access / lateral movement
    "psexec":      ("remote_access", 2.0),
    "putty":       ("remote_access", 1.5),
    "winscp":      ("remote_access", 2.0),
    "mstsc":       ("remote_access", 1.5),
    "vnc":         ("remote_access", 1.5),
    "teamviewer":  ("remote_access", 1.5),
    "anydesk":     ("remote_access", 1.5),
    "plink":       ("remote_access", 2.0),
    "nc":          ("remote_access", 2.0),
    "ncat":        ("remote_access", 2.0),
    "netcat":      ("remote_access", 2.0),
    # Exfiltration
    "ftp":         ("exfiltration", 1.5),
    "rclone":      ("exfiltration", 2.5),
    "robocopy":    ("exfiltration", 1.0),
    "xcopy":       ("exfiltration", 1.0),
    "curl":        ("exfiltration", 1.5),
    "wget":        ("exfiltration", 1.5),
    # Execution / bypass
    "powershell":  ("execution", 1.5),
    "wscript":     ("execution", 2.0),
    "mshta":       ("execution", 2.0),
    "rundll32":    ("execution", 2.0),
    "regsvr32":    ("execution", 2.0),
    "cscript":     ("execution", 1.5),
    "certutil":    ("execution", 2.0),
    "bitsadmin":   ("execution", 2.0),
    "msiexec":     ("execution", 1.5),
    # Deletion / wiping
    "sdelete":     ("deletion", 2.5),
    "eraser":      ("deletion", 2.5),
    "cipher":      ("deletion", 2.0),
    "ccleaner":    ("deletion", 2.0),
    "diskpart":    ("deletion", 2.0),
    "format":      ("deletion", 2.0),
    "shred":       ("deletion", 2.5),
    # Compression (flag only — low weight alone, high if combined)
    "7z":          ("compression", 1.0),
    "7zip":        ("compression", 1.0),
    "winrar":      ("compression", 1.0),
    "pkzip":       ("compression", 1.0),
    "zip":         ("compression", 0.5),
    # Password / credential tools
    "mimikatz":    ("credential", 3.0),
    "pwdump":      ("credential", 3.0),
    "fgdump":      ("credential", 3.0),
    "wce":         ("credential", 3.0),
    "hashcat":     ("credential", 2.5),
    "john":        ("credential", 2.0),
    "hydra":       ("credential", 2.5),
    "aircrack":    ("credential", 2.5),
}

# Sensitive document extensions for document access scoring
SENSITIVE_EXTENSIONS = {
    ".docx", ".doc", ".xlsx", ".xls", ".pdf", ".pptx", ".ppt",
    ".pst", ".ost", ".msg",           # email archives
    ".kdbx", ".kdb",                  # keepass databases
    ".pfx", ".p12", ".cer", ".key",   # certificates / private keys
    ".sql", ".db", ".sqlite",         # databases
    ".bak", ".backup",                # backups
    ".csv",                           # data exports
}

# Suspicious browser domains / keywords
SUSPICIOUS_DOMAINS = {
    # Violence / weapons
    "gunbroker":       ("weapons", 3),
    "armslist":        ("weapons", 3),
    "gunsamerica":     ("weapons", 3),
    "gun.deals":       ("weapons", 3),
    "bladehq":         ("weapons", 2),
    "knifecenter":     ("weapons", 2),
    "trueswords":      ("weapons", 2),
    "defensivecarry":  ("weapons", 2),
    "thefiringline":   ("weapons", 2),
    "ar15":            ("weapons", 3),
    "ammoland":        ("weapons", 2),
    "massshooting":    ("violence", 4),
    "massacre":        ("violence", 4),
    "howto kill":      ("violence", 5),
    "bomb making":     ("violence", 5),
    "explosive":       ("violence", 4),
    "manifesto":       ("violence", 3),
    # Dark / anonymous
    "tor2web":         ("anonymization", 3),
    ".onion":          ("anonymization", 4),
    "i2p":             ("anonymization", 3),
    "tails":           ("anonymization", 2),
    "darkweb":         ("anonymization", 3),
    # File sharing / exfiltration
    "mega.nz":         ("exfil_site", 3),
    "mega.co.nz":      ("exfil_site", 3),
    "wetransfer":      ("exfil_site", 2),
    "anonfiles":       ("exfil_site", 3),
    "gofile":          ("exfil_site", 2),
    "zippyshare":      ("exfil_site", 2),
    "sendspace":       ("exfil_site", 2),
    "mediafire":       ("exfil_site", 1),
    "4shared":         ("exfil_site", 2),
    "rapidshare":      ("exfil_site", 2),
    "dropbox":         ("exfil_site", 1),
    # Paste sites
    "pastebin":        ("paste_site", 2),
    "hastebin":        ("paste_site", 2),
    "ghostbin":        ("paste_site", 2),
    "rentry":          ("paste_site", 2),
    "privatebin":      ("paste_site", 2),
    # VPN / proxy / anonymization
    "nordvpn":         ("vpn", 2),
    "expressvpn":      ("vpn", 2),
    "protonvpn":       ("vpn", 2),
    "hide.me":         ("vpn", 2),
    "mullvad":         ("vpn", 2),
    "ipvanish":        ("vpn", 2),
    "hidemyass":       ("vpn", 2),
    "proxify":         ("vpn", 2),
    "anonymouse":      ("vpn", 2),
    # Hacking / exploit resources
    "exploit-db":      ("hacking", 4),
    "exploitdb":       ("hacking", 4),
    "metasploit":      ("hacking", 3),
    "hackforums":      ("hacking", 3),
    "nulled":          ("hacking", 3),
    "crackingking":    ("hacking", 3),
    "leakforums":      ("hacking", 3),
    "kali.org":        ("hacking", 1),  # low — could be legitimate
    "shodan":          ("hacking", 2),
}

# Event IDs that indicate anomalies
ANOMALY_EVENT_IDS = {
    # Logon failures
    4625: ("logon_failure", 2),
    529:  ("logon_failure", 2),   # XP
    # Account locked
    4740: ("account_lockout", 3),
    539:  ("account_lockout", 3), # XP
    # Audit log cleared
    1102: ("log_cleared", 5),
    517:  ("log_cleared", 5),     # XP
    # Log service stopped
    4608: ("log_service", 2),
    # New service installed (persistence)
    7045: ("service_install", 3),
    4697: ("service_install", 3),
    # Privilege escalation
    4672: ("privilege_escalation", 3),
    576:  ("privilege_escalation", 3), # XP
    # Process created with suspicious flags
    4688: ("process_creation", 1),
    592:  ("process_creation", 1), # XP
    # Firewall disabled
    2003: ("firewall_change", 3),
    2004: ("firewall_change", 3),
}

# Time window constants (seconds)
WINDOW_FILE_TO_DELETE  = 300   # 5 minutes
WINDOW_APP_TO_NETWORK  = 600   # 10 minutes
WINDOW_RAPID_ACTIONS   = 60    # 1 minute, threshold 5 events
WINDOW_MULTI_SOURCE    = 300   # 5 minutes, 3+ artifact types

# =============================================================================
# Helpers
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
    ts = ts.strip().rstrip("Z")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def normalize_username(name: str) -> str:
    return name.strip().lower() if name else "unknown"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# =============================================================================
# Step 1 — Build user list from user_accounts.json
# =============================================================================

def build_user_list(data: dict | None) -> dict[str, dict]:
    """Returns {username_lower: {username, rid, last_login, login_count, failed_logins, ...}}"""
    users: dict[str, dict] = {}
    if not data:
        return users

    for rec in data.get("users", {}).get("records", []):
        uname = rec.get("username", "")
        if not uname:
            continue
        key = normalize_username(uname)
        users[key] = {
            "username":      uname,
            "rid":           rec.get("rid"),
            "last_login":    rec.get("last_login", ""),
            "login_count":   rec.get("login_count", 0),
            "failed_logins": rec.get("failed_logins", 0),
            "account_disabled": rec.get("account_disabled", False),
            "description":   rec.get("description", ""),
        }
    return users


# =============================================================================
# Step 2 — Score each artifact category per user
# =============================================================================

def score_deleted_files(data: dict | None) -> dict[str, dict]:
    """Weight 4 — count deleted files per user (from SID/path attribution)."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return scores

    for rec in data.get("records", []):
        path = rec.get("original_path", "")
        sid  = rec.get("sid", "")
        ts   = rec.get("deleted_at", "")

        # Try to extract username from path
        uname = _username_from_path(path) or sid or "unknown"
        key = normalize_username(uname)

        scores[key]["count"] += 1
        scores[key]["evidence"].append({
            "path":       path,
            "deleted_at": ts,
            "file_size":  rec.get("file_size", ""),
            "source":     rec.get("source", ""),
        })

    return dict(scores)


def score_application_activity(data: dict | None) -> dict[str, dict]:
    """Weight 3 — flag suspicious executables in prefetch."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return scores

    for rec in data.get("records", []):
        exe = rec.get("exe_name", "").lower()
        run_count = rec.get("run_count") or 1
        last_run  = rec.get("last_run", "")

        for keyword, (category, multiplier) in SUSPICIOUS_EXES.items():
            if keyword in exe:
                # Use "unknown" as user since prefetch isn't user-specific
                # but note the exe for correlation
                key = "system"
                scores[key]["count"] += run_count
                scores[key]["weighted_count"] += run_count * multiplier
                scores[key]["evidence"].append({
                    "exe":        exe,
                    "category":   category,
                    "multiplier": multiplier,
                    "run_count":  run_count,
                    "last_run":   last_run,
                })
                break

    return dict(scores)


def score_event_logs(data: dict | None) -> dict[str, dict]:
    """Weight 4 — count anomalous events per user."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return scores

    all_events = data.get("all_events", [])

    for evt in all_events:
        eid   = evt.get("event_id")
        ts    = evt.get("timestamp", "")
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
            "unknown"
        )
        # Skip machine accounts and system
        if uname.endswith("$") or uname.lower() in ("system", "local service",
                                                      "network service", "-", "unknown"):
            uname = "system"

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


def score_network_activity(data: dict | None) -> dict[str, dict]:
    """Weight 3 — count network events per user."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return scores

    for evt in data.get("network_events", []):
        eid   = evt.get("event_id")
        ts    = evt.get("timestamp", "")
        edata = evt.get("event_data", {})

        uname = (
            edata.get("SubjectUserName") or
            edata.get("TargetUserName") or
            edata.get("AccountName") or
            "unknown"
        )
        if uname.endswith("$") or uname.lower() in ("system", "-", "unknown"):
            uname = "system"

        key = normalize_username(uname)
        scores[key]["count"] += 1
        scores[key]["evidence"].append({
            "event_id":   eid,
            "timestamp":  ts,
            "dest_ip":    edata.get("DestAddress") or edata.get("IpAddress", ""),
            "dest_port":  edata.get("DestPort") or edata.get("IpPort", ""),
            "process":    edata.get("Application") or edata.get("ProcessName", ""),
        })

    return dict(scores)


def score_document_access(data: dict | None) -> dict[str, dict]:
    """Weight 2 — count LNK files pointing to sensitive documents per user."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "sensitive_count": 0, "evidence": []})
    if not data:
        return scores

    for rec in data.get("records", []):
        if rec.get("type") != "lnk":
            continue

        uname  = rec.get("username", "unknown")
        target = rec.get("target_path", "")
        ts     = rec.get("target_accessed", "") or rec.get("target_modified", "")

        key = normalize_username(uname)
        scores[key]["count"] += 1

        # Check if target is a sensitive file type
        ext = Path(target).suffix.lower() if target else ""
        is_sensitive = ext in SENSITIVE_EXTENSIONS

        if is_sensitive:
            scores[key]["sensitive_count"] += 1
            scores[key]["evidence"].append({
                "target":      target,
                "accessed_at": ts,
                "extension":   ext,
            })

    return dict(scores)


def score_browser_history(data: dict | None) -> dict[str, dict]:
    """Weight 1 — flag suspicious URLs per user."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "flagged_count": 0, "evidence": []})
    if not data:
        return scores

    for rec in data.get("records", []):
        uname = rec.get("username", "unknown")
        url   = (rec.get("url") or "").lower()
        ts    = rec.get("visited_at", "")
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
                    "visited":  ts,
                    "browser":  rec.get("browser", ""),
                })
                break

    return dict(scores)


def score_user_accounts(data: dict | None) -> dict[str, dict]:
    """Weight 0-1 — flag suspicious account attributes."""
    scores: dict[str, dict] = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return scores

    for rec in data.get("users", {}).get("records", []):
        uname = rec.get("username", "unknown")
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
# Step 3 — Timeline correlation (bonus layer)
# =============================================================================

def _build_user_timeline(
    username_key: str,
    doc_scores:  dict,
    del_scores:  dict,
    app_scores:  dict,
    net_scores:  dict,
    evt_scores:  dict,
) -> list[dict]:
    """Build a flat sorted event list for one user across all artifact types."""
    events: list[dict] = []

    # Document access events
    for ev in doc_scores.get(username_key, {}).get("evidence", []):
        ts = parse_ts(ev.get("accessed_at"))
        if ts:
            events.append({"ts": ts, "type": "document_access", "detail": ev.get("target", "")})

    # Deleted file events
    for ev in del_scores.get(username_key, {}).get("evidence", []):
        ts = parse_ts(ev.get("deleted_at"))
        if ts:
            events.append({"ts": ts, "type": "file_deletion", "detail": ev.get("path", "")})

    # Network events
    for ev in net_scores.get(username_key, {}).get("evidence", []):
        ts = parse_ts(ev.get("timestamp"))
        if ts:
            events.append({"ts": ts, "type": "network_activity", "detail": ev.get("dest_ip", "")})

    # Anomalous event log events
    for ev in evt_scores.get(username_key, {}).get("evidence", []):
        ts = parse_ts(ev.get("timestamp"))
        if ts:
            events.append({"ts": ts, "type": "event_anomaly", "detail": ev.get("label", "")})

    # App activity (system-level, include for all users)
    for ev in app_scores.get("system", {}).get("evidence", []):
        ts = parse_ts(ev.get("last_run"))
        if ts:
            events.append({"ts": ts, "type": "app_execution", "detail": ev.get("exe", "")})

    return sorted(events, key=lambda x: x["ts"])


def calculate_timeline_bonuses(
    username_key: str,
    doc_scores:  dict,
    del_scores:  dict,
    app_scores:  dict,
    net_scores:  dict,
    evt_scores:  dict,
    all_events_data: dict | None,
) -> tuple[int, list[dict]]:
    """
    Calculate timeline bonuses for a user.
    Returns (total_bonus, list of matched patterns with details).
    """
    timeline = _build_user_timeline(username_key, doc_scores, del_scores,
                                     app_scores, net_scores, evt_scores)
    if not timeline:
        return 0, []

    bonuses_earned: list[dict] = []
    total_bonus = 0
    used_pairs: set[tuple] = set()  # avoid double-counting same event pair

    # ── Pattern 1: File access → deletion within 5 min ──────────────────────
    access_evts = [e for e in timeline if e["type"] == "document_access"]
    delete_evts = [e for e in timeline if e["type"] == "file_deletion"]

    for acc in access_evts:
        for dlt in delete_evts:
            pair = (id(acc), id(dlt))
            if pair in used_pairs:
                continue
            delta = (dlt["ts"] - acc["ts"]).total_seconds()
            if 0 <= delta <= WINDOW_FILE_TO_DELETE:
                used_pairs.add(pair)
                bonus = TIMELINE_BONUS["file_access_then_deletion"]
                total_bonus += bonus
                bonuses_earned.append({
                    "pattern":    "file_access_then_deletion",
                    "bonus":      bonus,
                    "detail":     f"Accessed '{acc['detail']}' then deleted '{dlt['detail']}' "
                                  f"({int(delta)}s later)",
                    "timestamp":  acc["ts"].isoformat(),
                })

    # ── Pattern 2: App execution → network activity within 10 min ───────────
    app_evts = [e for e in timeline if e["type"] == "app_execution"]
    net_evts  = [e for e in timeline if e["type"] == "network_activity"]

    for app in app_evts:
        for net in net_evts:
            pair = (id(app), id(net))
            if pair in used_pairs:
                continue
            delta = (net["ts"] - app["ts"]).total_seconds()
            if 0 <= delta <= WINDOW_APP_TO_NETWORK:
                used_pairs.add(pair)
                bonus = TIMELINE_BONUS["app_exec_then_network"]
                total_bonus += bonus
                bonuses_earned.append({
                    "pattern":   "app_exec_then_network",
                    "bonus":     bonus,
                    "detail":    f"Ran '{app['detail']}' then network to '{net['detail']}' "
                                 f"({int(delta)}s later)",
                    "timestamp": app["ts"].isoformat(),
                })

    # ── Pattern 3: Activity burst → log gap (check if logs go silent) ───────
    # Detect: cluster of activity followed by no events for >1 hour
    if len(timeline) >= 3:
        for i in range(len(timeline) - 2):
            window_end = timeline[i]["ts"] + timedelta(minutes=10)
            cluster = [e for e in timeline[i:] if e["ts"] <= window_end]
            if len(cluster) >= 3:
                # Check for silence after the cluster
                cluster_end = max(e["ts"] for e in cluster)
                subsequent = [e for e in timeline if e["ts"] > cluster_end]
                if subsequent:
                    silence = (subsequent[0]["ts"] - cluster_end).total_seconds()
                    if silence >= 3600:  # 1 hour gap
                        key = f"gap_{cluster_end.isoformat()}"
                        if key not in used_pairs:
                            used_pairs.add(key)
                            bonus = TIMELINE_BONUS["activity_then_log_gap"]
                            total_bonus += bonus
                            bonuses_earned.append({
                                "pattern":   "activity_then_log_gap",
                                "bonus":     bonus,
                                "detail":    f"Burst of {len(cluster)} events ending "
                                             f"{cluster_end.isoformat()}, then "
                                             f"{int(silence/3600):.1f}h silence",
                                "timestamp": cluster_end.isoformat(),
                            })

    # ── Pattern 4: Rapid actions (>5 events within 60 seconds) ──────────────
    for i in range(len(timeline)):
        window_end = timeline[i]["ts"] + timedelta(seconds=WINDOW_RAPID_ACTIONS)
        burst = [e for e in timeline[i:] if e["ts"] <= window_end]
        if len(burst) >= 5:
            key = f"rapid_{timeline[i]['ts'].isoformat()}"
            if key not in used_pairs:
                used_pairs.add(key)
                bonus = TIMELINE_BONUS["rapid_actions"]
                total_bonus += bonus
                bonuses_earned.append({
                    "pattern":   "rapid_actions",
                    "bonus":     bonus,
                    "detail":    f"{len(burst)} events in 60s starting "
                                 f"{timeline[i]['ts'].isoformat()}",
                    "timestamp": timeline[i]["ts"].isoformat(),
                })

    # ── Pattern 5: Multi-source consistency (3+ artifact types in 5 min) ────
    for i in range(len(timeline)):
        window_end = timeline[i]["ts"] + timedelta(seconds=WINDOW_MULTI_SOURCE)
        cluster = [e for e in timeline[i:] if e["ts"] <= window_end]
        types_in_window = {e["type"] for e in cluster}
        if len(types_in_window) >= 3:
            key = f"multi_{timeline[i]['ts'].isoformat()}"
            if key not in used_pairs:
                used_pairs.add(key)
                bonus = TIMELINE_BONUS["multi_source_consistency"]
                total_bonus += bonus
                bonuses_earned.append({
                    "pattern":   "multi_source_consistency",
                    "bonus":     bonus,
                    "detail":    f"{len(types_in_window)} artifact types in 5min window: "
                                 f"{', '.join(sorted(types_in_window))}",
                    "timestamp": timeline[i]["ts"].isoformat(),
                })

    return total_bonus, bonuses_earned


# =============================================================================
# Step 4 — Aggregate per-user final score
# =============================================================================

def aggregate_scores(
    users:       dict[str, dict],
    del_scores:  dict,
    app_scores:  dict,
    evt_scores:  dict,
    net_scores:  dict,
    doc_scores:  dict,
    brw_scores:  dict,
    usr_scores:  dict,
    evt_data:    dict | None,
) -> list[dict]:
    """
    For each user, compute:
        artifact_score = sum(weight × frequency) per category
        timeline_bonus = sum of matched pattern bonuses
        final_score    = artifact_score + timeline_bonus
    """

    # Collect all known usernames across all score dicts
    all_keys: set[str] = set(users.keys())
    for d in (del_scores, evt_scores, net_scores, doc_scores, brw_scores, usr_scores):
        all_keys.update(d.keys())
    all_keys.discard("system")
    all_keys.discard("unknown")

    results: list[dict] = []

    for key in sorted(all_keys):
        uinfo = users.get(key, {"username": key})
        display_name = uinfo.get("username", key)

        # ── Artifact score breakdown ────────────────────────────────────────

        # Deleted files: weight 4
        del_data  = del_scores.get(key, {})
        del_count = del_data.get("count", 0)
        del_score = del_count * WEIGHTS["deleted_files"]

        # Event anomalies: weight 4 (use weighted_count which accounts for severity)
        evt_data_u  = evt_scores.get(key, {})
        evt_count   = evt_data_u.get("count", 0)
        evt_w_count = evt_data_u.get("weighted_count", 0.0)
        evt_score   = evt_w_count * WEIGHTS["event_anomalies"] / 4  # normalize

        # App activity: weight 3 (use weighted_count from multipliers)
        app_data    = app_scores.get("system", {})
        app_count   = app_data.get("count", 0)
        app_w_count = app_data.get("weighted_count", 0.0)
        # App is system-wide — divide equally among all users as baseline,
        # but only count if user has correlated network/doc activity
        has_activity = (del_count > 0 or evt_count > 0 or
                        net_scores.get(key, {}).get("count", 0) > 0)
        app_score = (app_w_count * WEIGHTS["app_activity"] / max(len(all_keys), 1)
                     if has_activity else 0)

        # Network activity: weight 3
        net_data  = net_scores.get(key, {})
        net_count = net_data.get("count", 0)
        net_score = net_count * WEIGHTS["network_activity"]

        # Document access: weight 2 (only sensitive files score)
        doc_data  = doc_scores.get(key, {})
        doc_sens  = doc_data.get("sensitive_count", 0)
        doc_total = doc_data.get("count", 0)
        doc_score = doc_sens * WEIGHTS["document_access"]

        # Browser history: weight 1 (only flagged URLs score)
        brw_data    = brw_scores.get(key, {})
        brw_flagged = brw_data.get("flagged_count", 0)
        brw_total   = brw_data.get("count", 0)
        # Use domain-specific weights for flagged URLs
        brw_score = sum(
            ev.get("weight", 1) * WEIGHTS["browser_history"]
            for ev in brw_data.get("evidence", [])
        )

        # User account: weight 0-1
        usr_data  = usr_scores.get(key, {})
        usr_count = usr_data.get("count", 0)
        usr_score = min(usr_count * WEIGHTS["user_accounts"], 5)  # cap at 5

        artifact_score = (del_score + evt_score + app_score +
                          net_score + doc_score + brw_score + usr_score)

        # ── Timeline bonus ──────────────────────────────────────────────────
        timeline_bonus, timeline_patterns = calculate_timeline_bonuses(
            key, doc_scores, del_scores, app_scores, net_scores, evt_scores, evt_data
        )

        final_score = artifact_score + timeline_bonus

        results.append({
            "username":     display_name,
            "username_key": key,
            "account_info": {
                "rid":              uinfo.get("rid"),
                "last_login":       uinfo.get("last_login", ""),
                "login_count":      uinfo.get("login_count", 0),
                "failed_logins":    uinfo.get("failed_logins", 0),
                "account_disabled": uinfo.get("account_disabled", False),
            },
            "artifact_scores": {
                "deleted_files":    {"raw_count": del_count,  "score": round(del_score, 2)},
                "event_anomalies":  {"raw_count": evt_count,  "score": round(evt_score, 2)},
                "app_activity":     {"raw_count": app_count,  "score": round(app_score, 2)},
                "network_activity": {"raw_count": net_count,  "score": round(net_score, 2)},
                "document_access":  {"raw_count": doc_total,  "sensitive_count": doc_sens,
                                     "score": round(doc_score, 2)},
                "browser_history":  {"raw_count": brw_total,  "flagged_count": brw_flagged,
                                     "score": round(brw_score, 2)},
                "user_accounts":    {"raw_count": usr_count,  "score": round(usr_score, 2)},
            },
            "artifact_score":  round(artifact_score, 2),
            "timeline_bonus":  timeline_bonus,
            "timeline_patterns": timeline_patterns,
            "final_score":     round(final_score, 2),
            "evidence": {
                "deleted_files":    del_data.get("evidence", [])[:20],
                "event_anomalies":  evt_data_u.get("evidence", [])[:20],
                "network_activity": net_data.get("evidence", [])[:20],
                "document_access":  doc_data.get("evidence", [])[:20],
                "browser_history":  brw_data.get("evidence", [])[:20],
                "app_activity":     app_data.get("evidence", [])[:20],
                "user_accounts":    usr_data.get("evidence", []),
            },
        })

    # Sort by final score descending
    results.sort(key=lambda x: x["final_score"], reverse=True)

    # Add rank
    for i, r in enumerate(results, 1):
        r["rank"] = i

    return results


# =============================================================================
# Utility: extract username from Windows file path
# =============================================================================

def _username_from_path(path: str) -> str | None:
    if not path:
        return None
    # Match: C:\Users\<username>\ or C:\Documents and Settings\<username>\
    m = re.search(
        r"(?:Users|Documents and Settings)[/\\]([^/\\]+)",
        path, re.IGNORECASE
    )
    if m:
        name = m.group(1)
        skip = {"All Users", "Default User", "Default", "Public",
                "LocalService", "NetworkService", "systemprofile"}
        if name not in skip:
            return name
    return None


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate forensic artifacts → per-user suspicion scores"
    )
    parser.add_argument("--json-dir", required=True,
                        help="Directory containing JSON output from extract_artifacts.sh")
    parser.add_argument("--output",   required=True,
                        help="Output path for scores.json")
    args = parser.parse_args()

    json_dir = Path(args.json_dir)
    out_path = Path(args.output)

    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║       Forensic Artifact Correlator                  ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  JSON dir : {json_dir}")
    print(f"  Output   : {out_path}")
    print()

    # ── Load all JSON files ──────────────────────────────────────────────────
    print("[*] Loading artifacts...")
    ua_data  = load_json(json_dir / "user_accounts.json")
    app_data = load_json(json_dir / "application_activity.json")
    evt_data = load_json(json_dir / "event_logs.json")
    net_data = load_json(json_dir / "network_activity.json")
    doc_data = load_json(json_dir / "document_folder_access.json")
    brw_data = load_json(json_dir / "browser_history.json")
    del_data = load_json(json_dir / "deleted_files.json")

    # ── Build user list ──────────────────────────────────────────────────────
    print("[*] Building user list from SAM...")
    users = build_user_list(ua_data)
    print(f"    Found {len(users)} user account(s): {', '.join(users.keys()) or 'none'}")

    # ── Score each artifact category ─────────────────────────────────────────
    print("[*] Scoring artifact categories...")
    del_scores = score_deleted_files(del_data)
    app_scores = score_application_activity(app_data)
    evt_scores = score_event_logs(evt_data)
    net_scores = score_network_activity(net_data)
    doc_scores = score_document_access(doc_data)
    brw_scores = score_browser_history(brw_data)
    usr_scores = score_user_accounts(ua_data)

    print(f"    Deleted files    : {sum(v['count'] for v in del_scores.values())} records across "
          f"{len(del_scores)} user(s)")
    print(f"    Event anomalies  : {sum(v['count'] for v in evt_scores.values())} records across "
          f"{len(evt_scores)} user(s)")
    print(f"    Suspicious apps  : {sum(v['count'] for v in app_scores.values())} executions")
    print(f"    Network events   : {sum(v['count'] for v in net_scores.values())} records across "
          f"{len(net_scores)} user(s)")
    print(f"    Document access  : {sum(v.get('sensitive_count',0) for v in doc_scores.values())} "
          f"sensitive files across {len(doc_scores)} user(s)")
    print(f"    Flagged URLs     : {sum(v.get('flagged_count',0) for v in brw_scores.values())} "
          f"across {len(brw_scores)} user(s)")

    # ── Aggregate + timeline ─────────────────────────────────────────────────
    print("[*] Aggregating scores and running timeline correlation...")
    results = aggregate_scores(
        users, del_scores, app_scores, evt_scores,
        net_scores, doc_scores, brw_scores, usr_scores, evt_data
    )

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  SUSPICION SCORE SUMMARY                           │")
    print("  ├──────┬──────────────────────┬──────────┬───────────┤")
    print("  │ Rank │ Username             │ Artifact │ Final     │")
    print("  ├──────┼──────────────────────┼──────────┼───────────┤")
    for r in results:
        print(f"  │ {r['rank']:<4} │ {r['username']:<20} │ "
              f"{r['artifact_score']:<8.1f} │ {r['final_score']:<9.1f} │")
    print("  └──────┴──────────────────────┴──────────┴───────────┘")
    print()

    # ── Write output ─────────────────────────────────────────────────────────
    output = {
        "metadata": {
            "generated_at":  now_iso(),
            "json_source":   str(json_dir),
            "total_users":   len(results),
            "weights_used":  WEIGHTS,
            "timeline_bonuses_used": TIMELINE_BONUS,
        },
        "users": results,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)

    print(f"[✓] scores.json written → {out_path}")
    print()


if __name__ == "__main__":
    main()
