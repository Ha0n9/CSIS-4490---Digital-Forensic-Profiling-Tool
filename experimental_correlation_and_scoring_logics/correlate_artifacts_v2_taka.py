#!/usr/bin/env python3
"""
correlate_artifacts.py
Final analysis stage of the forensic pipeline.

Features:
- Artifact-based scoring (normalized per-user)
- Suspicious executable, domain, and event ID detection
- Timeline correlation with pattern detection
- User attribution via path + SID mapping
- Suspicion scoring and ranking
- Optional evaluation (precision, recall, F1) if ground truth provided

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

# =============================================================================
# WEIGHTS
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


def normalize_username(name: str) -> str:
    return name.strip().lower() if name else "unknown"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# =============================================================================
# USER ATTRIBUTION
# =============================================================================

def _username_from_path(path: str) -> str | None:
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


def resolve_username(path: str, sid: str | None = None,
                     sid_map: dict | None = None) -> str:
    uname = _username_from_path(path)
    if not uname and sid and sid_map:
        uname = sid_map.get(sid)
    return normalize_username(uname or "unknown")


def build_sid_map(ua_data: dict | None) -> dict[str, str]:
    """Build {SID_string: username} from user_accounts.json for recycle bin attribution."""
    sid_map: dict[str, str] = {}
    if not ua_data:
        return sid_map
    for rec in ua_data.get("users", {}).get("records", []):
        rid = rec.get("rid")
        uname = rec.get("username", "")
        if rid and uname:
            # Windows SID pattern ends with the RID; store the RID as fallback key too
            sid_map[str(rid)] = normalize_username(uname)
    return sid_map


def build_user_list(ua_data: dict | None) -> dict[str, dict]:
    users: dict[str, dict] = {}
    if not ua_data:
        return users
    for rec in ua_data.get("users", {}).get("records", []):
        uname = rec.get("username", "")
        if not uname:
            continue
        key = normalize_username(uname)
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
# SCORING FUNCTIONS
# =============================================================================

def score_deleted_files(data, sid_map=None):
    scores = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        user = resolve_username(rec.get("original_path", ""),
                                rec.get("sid"), sid_map)
        scores[user]["count"] += 1
        scores[user]["evidence"].append({
            "path":       rec.get("original_path", ""),
            "deleted_at": rec.get("deleted_at", ""),
            "file_size":  rec.get("file_size", ""),
            "source":     rec.get("source", ""),
        })
    return dict(scores)


def score_application_activity(data):
    scores = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        exe = rec.get("exe_name", "").lower()
        run_count = rec.get("run_count") or 1
        last_run  = rec.get("last_run", "")
        for keyword, (category, multiplier) in SUSPICIOUS_EXES.items():
            if keyword in exe:
                scores["system"]["count"] += run_count
                scores["system"]["weighted_count"] += run_count * multiplier
                scores["system"]["evidence"].append({
                    "exe":        exe,
                    "category":   category,
                    "multiplier": multiplier,
                    "run_count":  run_count,
                    "last_run":   last_run,
                })
                break
    return dict(scores)


def score_event_logs(data):
    scores = defaultdict(lambda: {"count": 0, "weighted_count": 0.0, "evidence": []})
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
                 edata.get("AccountName") or edata.get("String0") or "unknown")
        if uname.endswith("$") or uname.lower() in ("system","local service",
                                                      "network service","-","unknown"):
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


def score_network_activity(data):
    scores = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    for evt in data.get("network_events", []):
        edata = evt.get("event_data", {})
        uname = (edata.get("SubjectUserName") or edata.get("TargetUserName") or
                 edata.get("AccountName") or "unknown")
        if uname.endswith("$") or uname.lower() in ("system", "-", "unknown"):
            uname = "system"
        key = normalize_username(uname)
        scores[key]["count"] += 1
        scores[key]["evidence"].append({
            "event_id":  evt.get("event_id"),
            "timestamp": evt.get("timestamp", ""),
            "dest_ip":   edata.get("DestAddress") or edata.get("IpAddress", ""),
            "dest_port": edata.get("DestPort") or edata.get("IpPort", ""),
            "process":   edata.get("Application") or edata.get("ProcessName", ""),
        })
    return dict(scores)


def score_document_access(data):
    scores = defaultdict(lambda: {"count": 0, "sensitive_count": 0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        if rec.get("type") != "lnk":
            continue
        uname  = rec.get("username", "unknown")
        target = rec.get("target_path", "")
        ts     = rec.get("target_accessed", "") or rec.get("target_modified", "")
        key    = normalize_username(uname)
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


def score_browser_history(data):
    scores = defaultdict(lambda: {"count": 0, "flagged_count": 0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("records", []):
        uname = rec.get("username", "unknown")
        url   = (rec.get("url") or "").lower()
        title = rec.get("title", "")
        key   = normalize_username(uname)
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


def score_user_accounts(data):
    scores = defaultdict(lambda: {"count": 0, "evidence": []})
    if not data:
        return dict(scores)
    for rec in data.get("users", {}).get("records", []):
        uname  = rec.get("username", "unknown")
        key    = normalize_username(uname)
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
            scores[key]["evidence"].append({"flag": "account_disabled_but_active"})
    return dict(scores)

# =============================================================================
# TIMELINE BUILDER
# =============================================================================

def _build_user_timeline(user, doc_s, del_s, app_s, net_s, evt_s):
    events = []

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
    for ev in app_s.get("system", {}).get("evidence", []):
        ts = parse_ts(ev.get("last_run"))
        if ts:
            events.append({"ts": ts, "type": "application_exec",
                           "detail": ev.get("exe", "")})

    return sorted(events, key=lambda x: x["ts"])

# =============================================================================
# TIMELINE CORRELATION
# =============================================================================

def calculate_timeline_bonuses(user, doc_s, del_s, app_s, net_s, evt_s, evt_data):
    timeline = _build_user_timeline(user, doc_s, del_s, app_s, net_s, evt_s)
    if not timeline:
        return 0, []

    bonus = 0
    patterns = []
    used: set = set()

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
    net_evts  = [e for e in timeline if e["type"] == "network_activity"]
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
# AGGREGATE SCORING (NORMALIZED — from v2)
# =============================================================================

def aggregate_scores(users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, evt_data):
    all_keys: set[str] = set(users.keys())
    for d in (del_s, evt_s, net_s, doc_s, brw_s, usr_s):
        all_keys.update(d.keys())
    all_keys.discard("system")
    all_keys.discard("unknown")

    results = []

    for user in sorted(all_keys):
        uinfo        = users.get(user, {"username": user})
        display_name = uinfo.get("username", user)

        # Raw counts
        del_count  = del_s.get(user, {}).get("count", 0)
        evt_count  = evt_s.get(user, {}).get("count", 0)
        net_count  = net_s.get(user, {}).get("count", 0)
        doc_sens   = doc_s.get(user, {}).get("sensitive_count", 0)
        doc_total  = doc_s.get(user, {}).get("count", 0)
        brw_flagged = brw_s.get(user, {}).get("flagged_count", 0)
        brw_total  = brw_s.get(user, {}).get("count", 0)
        usr_count  = usr_s.get(user, {}).get("count", 0)
        app_count  = app_s.get("system", {}).get("count", 0)
        app_wcount = app_s.get("system", {}).get("weighted_count", 0.0)

        # Total events for normalization (v2 approach)
        total_events = (del_count + evt_count + net_count + doc_sens +
                        brw_flagged + usr_count + (app_count if del_count > 0
                        or evt_count > 0 or net_count > 0 else 0))

        def norm(c):
            return c / total_events if total_events > 0 else 0

        # Normalized scores × weight
        del_score  = WEIGHTS["deleted_files"]    * norm(del_count)
        evt_score  = WEIGHTS["event_anomalies"]  * norm(evt_s.get(user, {}).get("weighted_count", 0))
        net_score  = WEIGHTS["network_activity"] * norm(net_count)
        doc_score  = WEIGHTS["document_access"]  * norm(doc_sens)
        brw_score  = WEIGHTS["browser_history"]  * norm(
            sum(ev.get("weight", 1) for ev in brw_s.get(user, {}).get("evidence", []))
        )
        usr_score  = WEIGHTS["user_accounts"]    * norm(usr_count)

        # App: system-wide, only applied if user has other correlated activity
        has_activity = (del_count > 0 or evt_count > 0 or net_count > 0)
        app_score = (WEIGHTS["app_activity"] * norm(app_wcount / max(len(all_keys), 1))
                     if has_activity else 0)

        artifact_score = (del_score + evt_score + app_score + net_score +
                          doc_score + brw_score + usr_score)

        # Timeline bonus
        timeline_bonus, timeline_patterns = calculate_timeline_bonuses(
            user, doc_s, del_s, app_s, net_s, evt_s, evt_data
        )

        final_score = artifact_score + timeline_bonus

        results.append({
            "username":     display_name,
            "username_key": user,
            "account_info": {
                "rid":              uinfo.get("rid"),
                "last_login":       uinfo.get("last_login", ""),
                "login_count":      uinfo.get("login_count", 0),
                "failed_logins":    uinfo.get("failed_logins", 0),
                "account_disabled": uinfo.get("account_disabled", False),
            },
            "artifact_scores": {
                "deleted_files":    {"raw_count": del_count,  "score": round(del_score, 4)},
                "event_anomalies":  {"raw_count": evt_count,  "score": round(evt_score, 4)},
                "app_activity":     {"raw_count": app_count,  "score": round(app_score, 4)},
                "network_activity": {"raw_count": net_count,  "score": round(net_score, 4)},
                "document_access":  {"raw_count": doc_total,  "sensitive_count": doc_sens,
                                     "score": round(doc_score, 4)},
                "browser_history":  {"raw_count": brw_total,  "flagged_count": brw_flagged,
                                     "score": round(brw_score, 4)},
                "user_accounts":    {"raw_count": usr_count,  "score": round(usr_score, 4)},
            },
            "artifact_score":    round(artifact_score, 4),
            "timeline_bonus":    timeline_bonus,
            "timeline_patterns": timeline_patterns,
            "final_score":       round(final_score, 4),
            "evidence": {
                "deleted_files":    del_s.get(user, {}).get("evidence", [])[:20],
                "event_anomalies":  evt_s.get(user, {}).get("evidence", [])[:20],
                "network_activity": net_s.get(user, {}).get("evidence", [])[:20],
                "document_access":  doc_s.get(user, {}).get("evidence", [])[:20],
                "browser_history":  brw_s.get(user, {}).get("evidence", [])[:20],
                "app_activity":     app_s.get("system", {}).get("evidence", [])[:20],
                "user_accounts":    usr_s.get(user, {}).get("evidence", []),
            },
        })

    results.sort(key=lambda x: x["final_score"], reverse=True)
    for i, r in enumerate(results, 1):
        r["rank"] = i

    return results

# =============================================================================
# EVALUATION (from v2)
# =============================================================================

def evaluate_results(results: list[dict], ground_truth: dict) -> dict:
    """
    Evaluate scoring accuracy against ground truth.
    ground_truth format: {"username": true/false, ...}
    A user is predicted suspicious if final_score > 0.
    """
    TP = FP = FN = TN = 0
    details = []

    for r in results:
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

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall    = TP / (TP + FN) if (TP + FN) else 0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "details":   details,
    }

# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate forensic artifacts → per-user suspicion scores"
    )
    parser.add_argument("--json-dir",      required=True,
                        help="Directory containing JSON output from extract_artifacts.sh")
    parser.add_argument("--output",        required=True,
                        help="Output path for scores.json")
    parser.add_argument("--ground-truth",  default="",
                        help="Optional JSON file with ground truth labels for evaluation")
    args = parser.parse_args()

    json_dir = Path(args.json_dir)
    out_path = Path(args.output)

    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║       Forensic Artifact Correlator                   ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    print(f"  JSON dir : {json_dir}")
    print(f"  Output   : {out_path}")
    print()

    # Load all JSON files
    print("[*] Loading artifacts...")
    ua_data  = load_json(json_dir / "user_accounts.json")
    app_data = load_json(json_dir / "application_activity.json")
    evt_data = load_json(json_dir / "event_logs.json")
    net_data = load_json(json_dir / "network_activity.json")
    doc_data = load_json(json_dir / "document_folder_access.json")
    brw_data = load_json(json_dir / "browser_history.json")
    del_data = load_json(json_dir / "deleted_files.json")

    # Build user list and SID map
    print("[*] Building user list from SAM...")
    users   = build_user_list(ua_data)
    sid_map = build_sid_map(ua_data)
    print(f"    Found {len(users)} user(s): {', '.join(users.keys()) or 'none'}")

    # Score each category
    print("[*] Scoring artifact categories...")
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
    print(f"    Sensitive docs   : {sum(v.get('sensitive_count',0) for v in doc_s.values())} files")
    print(f"    Flagged URLs     : {sum(v.get('flagged_count',0) for v in brw_s.values())} URLs")

    # Aggregate + timeline
    print("[*] Aggregating scores and running timeline correlation...")
    results = aggregate_scores(
        users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, evt_data
    )

    # Print summary table
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  SUSPICION SCORE SUMMARY                               │")
    print("  ├──────┬──────────────────────┬──────────┬───────────────┤")
    print("  │ Rank │ Username             │ Artifact │ Final Score   │")
    print("  ├──────┼──────────────────────┼──────────┼───────────────┤")
    for r in results:
        print(f"  │ {r['rank']:<4} │ {r['username']:<20} │ "
              f"{r['artifact_score']:<8.4f} │ {r['final_score']:<13.4f} │")
    print("  └──────┴──────────────────────┴──────────┴───────────────┘")
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
            "generated_at":          now_iso(),
            "json_source":           str(json_dir),
            "total_users":           len(results),
            "weights_used":          WEIGHTS,
            "timeline_bonuses_used": TIMELINE_BONUS,
        },
        "users":      results,
        "evaluation": evaluation,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)

    print(f"[✓] scores.json written → {out_path}")
    print()


if __name__ == "__main__":
    main()