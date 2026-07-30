#!/usr/bin/env python3
"""
Correlation Engine - Main correlation logic
Based on full_forensic_profiler_v1.py engine
"""

import json
import math
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict
from urllib.parse import urlparse

# ── Constants (v11) ───────────────────────────────────────────────────────────
WEIGHTS = {
    "deleted_files":    4,
    "event_anomalies":  4,
    "app_activity":     3,
    "network_activity": 3,
    "document_access":  2,
    "browser_history":  0.5,
    "user_accounts":    1,
}

# Per-category ceiling on a single category's contribution to a user's raw
# weighted score (metric * WEIGHTS[cat]), in the same "points" unit as the
# weight itself. This bounds how much any one high-volume artifact source
# (e.g. thousands of browser-history rows, or a large unattributed app pool)
# can dominate the total, independent of what any other user in the same
# image scored. FIXED_SCORE_CEILING is their sum: a constant, not derived
# from the current run's data, which is what makes artifact_score comparable
# across different forensic images (see calculate_aggregate()).
CATEGORY_CAP = {
    "deleted_files":    40.0,
    "event_anomalies":  60.0,
    "app_activity":     30.0,
    "network_activity": 45.0,
    "document_access":  30.0,
    "browser_history":  20.0,
    "user_accounts":     5.0,
}
FIXED_SCORE_CEILING: float = float(sum(CATEGORY_CAP.values()))  # 230.0

# Absolute risk-classification thresholds (see assign_risk_labels()). These
# replace percentile-of-this-run labeling, which could mark a user HIGH
# purely for ranking in the top 20% of a quiet image with no real suspects.
RISK_THRESHOLDS = {
    "high_score":     18.0,   # final_score at/above this + enough diversity => HIGH
    "medium_score":    6.0,   # final_score at/above this (or 2+ categories) => MEDIUM
    "high_diversity":  2,     # independent evidence categories required for HIGH
}
# Categories treated as strong, independently-attributable evidence for risk
# purposes. browser_history/user_accounts are corroborating signals only —
# a user should not reach HIGH on browser flags or failed-login counts alone.
STRONG_EVIDENCE_CATEGORIES = {
    "deleted_files", "event_anomalies", "document_access",
    "app_activity", "network_activity",
}

TIMELINE_BONUS = {
    "file_access_then_deletion":     5,
    "app_exec_then_network":         4,
    "activity_then_log_gap":         6,
    "rapid_actions":                 3,
    "multi_source_consistency":      5,
    # Only path by which a privileged logon (event 4672/576) can
    # contribute anything at all — see PRIVILEGED_LOGON_EVENT_IDS above.
    "privileged_logon_then_activity":4,
}
TIMELINE_BONUS_CAP = {
    "file_access_then_deletion":     15,
    "app_exec_then_network":         12,
    "activity_then_log_gap":          6,
    "rapid_actions":                  9,
    "multi_source_consistency":      10,
    "privileged_logon_then_activity":12,
}

SYSTEM_ACCOUNTS = {
    "localsystem","system","local service","network service",
    "nt authority\\system","nt authority\\local service",
    "nt authority\\network service","wdagutilityaccount",
}
_DWM_RE = re.compile(r"^dwm-\d+$", re.I)
_DEF_RE = re.compile(r"^defaultuser\d+$", re.I)
_MCH_RE = re.compile(r".+\$$")

# Exact, extension-qualified executable basenames — matched via a direct
# dict lookup against the cleaned basename (see _exe_basename()), never a
# substring scan. A substring scan on "kw in exe" would match unrelated
# binaries that merely contain a keyword (e.g. "powershell_backup.exe" would
# wrongly match "powershell", and "mpcmdrun.exe" contains "cmd"-like
# fragments); known suspicious *variants* of a tool (e.g. PowerShell ISE,
# 64-bit builds) are listed as their own explicit entries instead.
SUSPICIOUS_EXES: dict[str, tuple[str, float]] = {
    "nmap.exe": ("recon", 1.5), "wireshark.exe": ("recon", 1.5),
    "netstat.exe": ("recon", 1.0), "whoami.exe": ("recon", 1.0),
    "ipconfig.exe": ("recon", 1.0), "arp.exe": ("recon", 1.0),
    "psexec.exe": ("remote_access", 2.0), "psexec64.exe": ("remote_access", 2.0),
    "putty.exe": ("remote_access", 1.5),
    "mstsc.exe": ("remote_access", 1.5), "teamviewer.exe": ("remote_access", 1.5),
    "powershell.exe": ("execution", 1.5), "powershell_ise.exe": ("execution", 1.5),
    "pwsh.exe": ("execution", 1.5),
    "wscript.exe": ("execution", 2.0),
    "mshta.exe": ("execution", 2.0), "rundll32.exe": ("execution", 2.0),
    "regsvr32.exe": ("execution", 2.0), "cscript.exe": ("execution", 1.5),
    "certutil.exe": ("execution", 2.0), "bitsadmin.exe": ("execution", 2.0),
    "sdelete.exe": ("deletion", 2.5), "sdelete64.exe": ("deletion", 2.5),
    "cipher.exe": ("deletion", 2.0),
    "ccleaner.exe": ("deletion", 2.0), "ccleaner64.exe": ("deletion", 2.0),
    "diskpart.exe": ("deletion", 2.0),
    "mimikatz.exe": ("credential", 3.0), "mimikatz64.exe": ("credential", 3.0),
    "pwdump.exe": ("credential", 3.0),
    "hashcat.exe": ("credential", 2.5), "hydra.exe": ("credential", 2.5),
}

# Known suspicious domains/TLDs. Matched via _domain_matches(), which
# requires the browser/network hostname to *equal* the entry or be a
# subdomain of it (host == domain or host.endswith("." + domain)) — never a
# bare substring scan, which would match unrelated hosts that merely contain
# the keyword (e.g. "mypastebinclone.com" against "pastebin.com", or an
# ad-tracking token that coincidentally contains "i2p").
SUSPICIOUS_DOMAINS: dict[str, tuple[str, int]] = {
    "tor2web.org": ("anonymization", 3), "onion": ("anonymization", 4),
    "i2p": ("anonymization", 3), "darkweb": ("anonymization", 3),
    "mega.nz": ("exfil_site", 3), "wetransfer.com": ("exfil_site", 2),
    "anonfiles.com": ("exfil_site", 3), "pastebin.com": ("paste_site", 2),
    "exploit-db.com": ("hacking", 4), "metasploit.com": ("hacking", 3),
    "shodan.io": ("hacking", 2),
}

SENSITIVE_EXTS = {".docx",".doc",".xlsx",".xls",".pdf",".pptx",".ppt",
                  ".pst",".ost",".msg",".kdbx",".pfx",".p12",".cer",
                  ".key",".sql",".db",".sqlite",".bak",".backup",".csv",
                  # Archive formats: a strong data-staging/exfiltration
                  # signal on their own (compressing files is rarely
                  # incidental) — confirmed missing by a real case
                  # (Adam/GroundTruth_Adam) where a "Client_Backup.zip"
                  # staged from exactly the sensitive files below was
                  # invisible to scoring.
                  ".zip",".rar",".7z",".gz",".tar",
                  # .txt: genuinely common for real sensitive content (the
                  # same case's actual insider-threat evidence — client
                  # lists, analysis drafts — was plain text) and this
                  # extension's absence was the single biggest scoring gap
                  # found. Included despite being a more generic extension
                  # than the others here (a stray readme.txt/changelog.txt
                  # will also count) — accepted as a deliberate false-
                  # positive/false-negative tradeoff in favor of not
                  # missing real evidence, consistent with document_access
                  # only ever contributing a modest, capped category score
                  # (WEIGHTS["document_access"]=2, CATEGORY_CAP=30) rather
                  # than being able to single-handedly drive a HIGH rating.
                  ".txt"}

# .txt is too generic an extension to treat as unconditionally sensitive
# the way the formats above are — confirmed by a real false positive found
# during validation: Windows' own default placeholder filename ("New Text
# Document.txt") tripped it immediately. Every other extension in
# SENSITIVE_EXTS already implies structured business/personal content by
# construction (a .docx or .kdbx doesn't get created by accident); .txt
# does not, so it additionally requires a sensitivity-suggestive keyword in
# the filename itself.
SENSITIVE_TXT_KEYWORDS = (
    "client", "customer", "confidential", "password", "credential", "secret",
    "private", "financial", "finance", "report", "backup", "draft",
    "contract", "salary", "ssn", "account", "invoice", "budget",
    "database", "internal", "project", "aws", "key",
)


def _is_sensitive_target(target: str, ext: str) -> bool:
    """
    True if `target` (a full file path) should count as a sensitive
    document. Structured formats (.docx/.pdf/.kdbx/... and archives —
    .zip/.rar/.7z/.gz/.tar) are sensitive by extension alone: the format
    itself implies deliberate, structured content or a deliberate staging/
    bundling action, not something created by accident. ".txt" is the one
    exception — far too generic an extension to treat as unconditionally
    sensitive (confirmed by a real false positive: Windows' own default
    placeholder filename, "New Text Document.txt") — so it additionally
    requires a sensitivity-suggestive keyword, checked against BOTH the
    filename and the full containing directory path. Directory context
    matters because a file's folder often carries more signal than its own
    name (e.g. a generically-named file sitting inside a folder called
    "Client_Project" or "Confidential" is still elevated risk) — this is
    the same read a human analyst would make, still expressed as a plain
    deterministic keyword-membership test, not a similarity score.
    """
    if ext not in SENSITIVE_EXTS:
        return False
    if ext != ".txt":
        return True
    if not target:
        return False
    p = Path(target)
    text = f"{p.stem} {p.parent}".lower()
    return any(kw in text for kw in SENSITIVE_TXT_KEYWORDS)

ANOMALY_EVENT_IDS: dict[int, tuple[str, int]] = {
    4625:("logon_failure",2), 529:("logon_failure",2),
    4740:("account_lockout",3), 539:("account_lockout",3),
    1102:("log_cleared",5), 517:("log_cleared",5),
    7045:("service_install",3), 4697:("service_install",3),
    4688:("process_creation",1), 592:("process_creation",1),
}

# Event 4672/576 ("Special privileges assigned to new logon") is
# deliberately NOT in ANOMALY_EVENT_IDS above — it carries zero standalone
# weight in event_anomalies scoring. It fires on every admin-equivalent
# logon (any local admin, or any UAC-elevated session) with zero attack
# involved, and standard DFIR guidance treats it as informative only in
# temporal correlation with independently-suspicious activity, never
# alone. A real captured case (Adam/GroundTruth_Adam) demonstrated the
# failure mode concretely: an uninvolved bystander account racked up
# enough 4672 events alone to outscore the actual ground-truth-confirmed
# suspect, while the case's own curated "events that matter" list
# contained zero 4672 events.
#
# Instead, these events are tracked separately (score_privileged_logons())
# and can only ever contribute via the "privileged_logon_then_activity"
# timeline-correlation pattern (see calculate_timeline_bonuses()) — i.e.
# only when a privileged session falls within PRIVILEGED_LOGON_WINDOW_S of
# other independently-scored real evidence for the same user. This mirrors
# the same "only meaningful in correlation" architecture the five existing
# timeline patterns already use for other single-artifact-type evidence.
PRIVILEGED_LOGON_EVENT_IDS: dict[int, str] = {4672: "privileged_logon", 576: "privileged_logon"}
PRIVILEGED_LOGON_WINDOW_S = 1800  # 30 min: an elevated session/token's practical scope

# ── Threat / Anomaly classification (report-only) ──────────────────────────
# Severity used to populate the HTML report's "Threats Detected" and
# "Anomalies" sections from evidence the scoring above has already gathered.
# Purely a labeling/aggregation layer over existing per-user evidence — it
# does not feed back into artifact_score/final_score/risk_label at all.
_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# "Threats" are indicator-based findings: a specific known-malicious tool,
# destination, or anti-forensics/persistence technique was observed. Keyed
# off the same category vocabulary SUSPICIOUS_EXES/SUSPICIOUS_DOMAINS/
# ANOMALY_EVENT_IDS already assign to each piece of evidence.
THREAT_EXE_SEVERITY = {
    "credential": "HIGH", "remote_access": "MEDIUM", "execution": "MEDIUM",
    "deletion": "MEDIUM", "recon": "LOW",
}
THREAT_DOMAIN_SEVERITY = {
    "anonymization": "HIGH", "exfil_site": "HIGH", "hacking": "HIGH",
    "paste_site": "MEDIUM",
    # Behavior-text categories (see parsers/parse_browser_history.py's
    # BEHAVIOR_PATTERNS) reuse this same severity map via build_threats().
    "anti_forensic": "HIGH", "evasion": "HIGH",
}
THREAT_EVENT_SEVERITY = {
    "log_cleared": "HIGH", "account_lockout": "MEDIUM", "service_install": "MEDIUM",
}

# "Anomalies" are behavioral/timing irregularities: the cross-artifact
# temporal patterns calculate_timeline_bonuses() already detects, plus
# account-flag evidence from score_accounts(). Distinct from threats above —
# an anomaly says "this timing is unusual", not "this is a known-bad tool".
ANOMALY_PATTERN_SEVERITY = {
    "file_access_then_deletion": "HIGH",
    "app_exec_then_network": "HIGH",
    "multi_source_consistency": "HIGH",
    "activity_then_log_gap": "MEDIUM",
    "rapid_actions": "MEDIUM",
}
ANOMALY_PATTERN_LABEL = {
    "file_access_then_deletion": "File Access Followed by Deletion",
    "app_exec_then_network": "Application Execution Followed by Network Activity",
    "multi_source_consistency": "Multi-Source Activity Correlation",
    "activity_then_log_gap": "Activity Burst Followed by Logging Gap",
    "rapid_actions": "Rapid Sequential Actions",
}

_INTERNAL_IP = [
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^127\.\d+\.\d+\.\d+$"),
    re.compile(r"^169\.254\.\d+\.\d+$"),
]

# Network destination tiers: internal LAN traffic alone is weak evidence,
# an unrecognized external destination is baseline, and a destination that
# matches a known-suspicious domain/IP indicator is weighted heavily.
NETWORK_TIER_WEIGHTS = {
    "internal":   0.3,
    "external":   1.0,
    "suspicious": 3.0,
}

WINDOWS_EPOCH = datetime(1601,1,1,tzinfo=timezone.utc)

# ── SID resolution ──────────────────────────────────────────────────────────
# Matches a standard domain/local-account SID and captures its trailing RID
# (e.g. "S-1-5-21-484763869-796845957-839522115-1004" -> 1004), which is
# cross-referenced against user_accounts.json's "rid" field. Built as a
# `search`, not `match`, so it also finds a SID embedded inside a longer
# string (e.g. a Recycle Bin per-SID subfolder path) when an artifact's own
# "sid" field is present but was left blank by its parser.
_SID_RID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-(\d+)", re.I)

# ── Timestamp parsing ────────────────────────────────────────────────────────
# Formats actually observed across this pipeline's artifact JSON, beyond the
# ISO-with-offset case datetime.fromisoformat() already handles: naive
# (no timezone) timestamps, space-separated date/time, date-only, and the
# US-locale format some EZ Tools CSV-derived exports use.
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)
# Timestamps before this year are treated as unparseable/sentinel, not real
# evidence. This reliably filters the FAT/LNK "zero date" (1980-01-01,
# observed in this pipeline's own document_folder_access.json output for
# unset target_accessed/created/modified fields), the Unix epoch
# (1970-01-01), and the Windows FILETIME epoch (1601-01-01) — all of which
# some tools emit to mean "not set" rather than a real event time. Letting
# these into timeline correlation would fabricate false "multiple users
# active at the same instant" pattern matches across unrelated evidence.
_MIN_PLAUSIBLE_YEAR = 1990


class CorrelationEngine:
    """Main correlation engine for forensic artifacts"""
    
    def __init__(
        self,
        json_dir: str,
        output_dir: str,
        config: Optional[Dict] = None
    ):
        self.json_dir = Path(json_dir)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Data containers
        self.users = []
        self.events = []
        self.network = []
        self.browser = []
        self.files = []
        self.deleted = []
        self.apps = []
    
    def load_json(self, filename: str) -> Optional[Dict]:
        filepath = self.json_dir / filename
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load {filename}: {e}")
        return None
    
    def load_all_artifacts(self):
        """Load all JSON artifacts from extraction"""
        artifact_map = {
            'user_accounts.json': 'users',
            'event_logs.json': 'events',
            'network_activity.json': 'network',
            'browser_history.json': 'browser',
            'document_folder_access.json': 'files',
            'deleted_files.json': 'deleted',
            'application_activity.json': 'apps'
        }
        
        for filename, attr in artifact_map.items():
            data = self.load_json(filename)
            if data:
                if isinstance(data, list):
                    setattr(self, attr, data)
                elif isinstance(data, dict):
                    found = False
                    
                    # Special: user_accounts.json
                    if attr == 'users' and 'users' in data:
                        if isinstance(data['users'], dict) and 'records' in data['users']:
                            setattr(self, attr, data['users']['records'])
                            found = True
                            print(f"  Loaded {len(data['users']['records'])} users")
                        elif isinstance(data['users'], list):
                            setattr(self, attr, data['users'])
                            found = True
                    
                    # Special: event_logs.json
                    if not found and attr == 'events' and 'all_events' in data:
                        if isinstance(data['all_events'], list):
                            setattr(self, attr, data['all_events'])
                            found = True
                            print(f"  Loaded {len(data['all_events'])} events")
                    
                    # Special: network_activity.json
                    if not found and attr == 'network' and 'network_events' in data:
                        if isinstance(data['network_events'], list):
                            setattr(self, attr, data['network_events'])
                            found = True
                            print(f"  Loaded {len(data['network_events'])} network events")
                    
                    # Try common keys
                    if not found:
                        for key in ['records', 'data', 'results', 'artifacts', 
                                   'events', 'users', 'files']:
                            if key in data and isinstance(data[key], list):
                                setattr(self, attr, data[key])
                                found = True
                                break
                    
                    if not found:
                        setattr(self, attr, [data])
    
    def _norm(self, n: str) -> str:
        return n.strip().lower() if n else ""

    def _host_of(self, url: str) -> str:
        """
        Hostname only (lowercased), not the full URL. SUSPICIOUS_DOMAINS keywords
        must be matched against the host — matching the full URL (including query
        strings) produces false positives from coincidental substrings inside
        tracking tokens (e.g. "...6I2pR8..." wrongly matching the "i2p" keyword).
        Strips userinfo ("user:pass@host") and a port suffix so
        "pastebin.com:443" still matches "pastebin.com" cleanly.
        """
        if not url:
            return ""
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            host = ""
        host = host or url.lower()
        host = host.rsplit("@", 1)[-1]
        host = host.split(":", 1)[0]
        return host

    def _domain_matches(self, host: str, domain: str) -> bool:
        """
        True if `host` IS `domain`/TLD or a subdomain of it — not merely a
        hostname that happens to contain it as a substring. This is what
        makes "pastebin.com" match "paste.pastebin.com" but not
        "mypastebinclone.com", and makes "i2p"/"onion" only match a real
        pseudo-TLD suffix (".i2p"/".onion") rather than any substring
        occurring anywhere in the host (the root cause of a real false
        positive found in EXP-03, where an ad-tracking query token
        coincidentally contained "i2p").
        """
        host = (host or "").rstrip(".")
        domain = (domain or "").lstrip(".")
        if not host or not domain:
            return False
        return host == domain or host.endswith("." + domain)

    def _exe_basename(self, exe_field: str) -> str:
        """
        Clean a Prefetch exe_name/exe_path field down to a bare, lowercased
        "name.exe" basename suitable for an exact SUSPICIOUS_EXES lookup.
        Prefetch exe_name fields are sometimes followed by a NUL byte and
        trailing binary junk (padding from the .pf file's fixed-width
        field) — that only ever comes after the real filename, so cutting
        at the first NUL is enough to isolate it.
        """
        name = (exe_field or "").split("\x00")[0].strip()
        if not name:
            return ""
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
        return name.lower()

    def _classify_dest(self, dest: str) -> str:
        """Classify a network destination (IP or hostname) as internal/external/suspicious."""
        if not dest:
            return "external"
        d = dest.strip().lower()
        if any(rx.match(d) for rx in _INTERNAL_IP):
            return "internal"
        for kw in SUSPICIOUS_DOMAINS:
            if self._domain_matches(d, kw):
                return "suspicious"
        return "external"

    def _acct_type(self, u: str) -> str:
        if not u: return "system"
        ul = u.lower().strip()
        if ul in SYSTEM_ACCOUNTS: return "system"
        if _DWM_RE.match(ul) or _DEF_RE.match(ul) or _MCH_RE.match(ul): return "system"
        if "nt authority" in ul or "window manager" in ul: return "system"
        if ul in ("administrator","guest","defaultaccount"): return "builtin"
        return "user"
    
    def _rankable(self, u: str) -> bool:
        return self._acct_type(u) in ("user","builtin")
    
    def _log_scale(self, v: float, mx: float) -> float:
        if mx <= 0: return 0.0
        return (math.log1p(v) / math.log1p(mx)) * 100.0
    
    def _user_from_path(self, path: str) -> str:
        if not path: return ""
        m = re.search(r"(?:Users|Documents and Settings)[/\\]([^/\\]+)", path, re.I)
        if m:
            n = m.group(1)
            if n.lower() not in {"all users","default user","default","public",
                                 "localservice","networkservice","systemprofile"}:
                return n
        return ""
    
    def _build_sid_map(self) -> None:
        """
        rid (int) -> normalized username, built from user_accounts.json.
        user_accounts.json only carries the account's RID (e.g. 1004), not
        a full SID, so resolution works by matching the trailing RID of any
        SID string against this map rather than an exact SID string match.
        """
        self._rid_to_user: Dict[int, str] = {}
        for rec in self.users:
            rid = rec.get("rid")
            uname = rec.get("username", "")
            if rid is None or not uname:
                continue
            try:
                self._rid_to_user[int(rid)] = self._norm(uname)
            except (TypeError, ValueError):
                continue

    def _user_from_sid(self, sid) -> str:
        """
        Resolve a username from a full SID, or any string that has one
        embedded in it (e.g. a Recycle Bin per-SID subfolder path), via its
        trailing RID against the map built by _build_sid_map(). Returns ""
        if no SID is found or its RID isn't a known local account.
        """
        if not sid:
            return ""
        rid_map = getattr(self, "_rid_to_user", None)
        if not rid_map:
            return ""
        m = _SID_RID_RE.search(str(sid))
        if not m:
            return ""
        return rid_map.get(int(m.group(1)), "")

    def _resolve_user(self, path="", sid=None) -> str:
        """
        Resolve an artifact record to a username. Path-based attribution
        (a "Users\\<name>" / "Documents and Settings\\<name>" segment) is
        tried first since it is the most direct signal. When that fails —
        or the artifact's own path doesn't identify a user at all — fall
        back to SID-based attribution using `sid`, which may be the
        record's own SID field, or any other available string that has a
        SID embedded in it (callers pass e.g. a Recycle Bin source_file
        path here when the parsed "sid" field itself is blank). This
        recovers evidence that would otherwise silently become
        "__unknown__"/"__apps__" purely because a path couldn't be parsed.
        """
        u = self._user_from_path(path)
        if u:
            return self._norm(u)
        u = self._user_from_sid(sid)
        if u:
            return u
        u = self._user_from_sid(path)
        if u:
            return u
        return ""

    def _parse_ts(self, ts) -> Optional[datetime]:
        """
        Parse a forensic timestamp from any format actually observed across
        this pipeline's artifact JSON into a timezone-aware UTC datetime.
        Handles ISO timestamps with/without microseconds, a bare "Z" (or
        this codebase's own malformed "+00:00Z" double-offset metadata
        timestamps), naive timestamps with no timezone at all (assumed
        UTC, since every upstream parser in this pipeline already targets
        UTC where it can), space-separated and date-only forms, and a raw
        numeric epoch as a last resort. Returns None for anything missing,
        unparseable, or implausibly old (see _MIN_PLAUSIBLE_YEAR) rather
        than raising — timeline correlation must skip bad evidence, not
        crash on it, and a caller must never see a naive datetime mixed
        with an aware one.
        """
        if ts is None:
            return None

        dt: Optional[datetime] = None
        if isinstance(ts, (int, float)):
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        else:
            s = str(ts).strip()
            if not s:
                return None
            # Normalize a bare "Z" suffix, or this codebase's own malformed
            # "+00:00Z" double-offset (see run()), to a single explicit UTC
            # offset before parsing.
            s = re.sub(r"(\+00:00)?Z$", "+00:00", s)
            try:
                dt = datetime.fromisoformat(s)
            except ValueError:
                for fmt in _TS_FORMATS:
                    try:
                        dt = datetime.strptime(s, fmt)
                        break
                    except ValueError:
                        continue
            if dt is None:
                return None

        dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        if dt.year < _MIN_PLAUSIBLE_YEAR:
            return None
        return dt
    
    # ── Scoring functions ──────────────────────────────────────────────────────
    def score_deleted(self, data):
        s = defaultdict(lambda: {"count":0,"evidence":[]})
        for r in (data or {}).get("records", []):
            # deleted_files.json carries a dedicated "sid" field, but the
            # parser sometimes leaves it blank even though the SID is
            # visible in the Recycle Bin's own per-SID subfolder path
            # (source_file, e.g. ".../recycle_bin/S-1-5-21-.../INFO2") — try
            # both so a blank "sid" field doesn't lose otherwise-recoverable
            # attribution.
            u = self._resolve_user(
                r.get("original_path",""),
                r.get("sid") or r.get("source_file",""),
            ) or "__unknown__"
            s[u]["count"] += 1
            s[u]["evidence"].append({"path":r.get("original_path",""),
                                     "deleted_at":r.get("deleted_at","")})
        return dict(s)

    def _userassist_basename(self, program: str) -> str:
        """Normalize a UserAssist "program" string down to a bare, lowercased
        filename comparable to Prefetch's _exe_basename() output (e.g.
        "C:\\WINDOWS\\system32\\wupdmgr.exe" -> "wupdmgr.exe")."""
        name = (program or "").replace("/", "\\").rsplit("\\", 1)[-1]
        return name.strip().lower()

    def _build_userassist_index(self, records) -> Dict[str, set]:
        """
        basename -> set of usernames whose own UserAssist history
        references it. Built once per run() from user_accounts.json's
        "userassist" records (see parsers/parse_user_accounts.py's
        parse_ntuser_userassist()) and used only as an attribution
        fallback in score_app() — never as its own scored evidence
        category.
        """
        idx: Dict[str, set] = defaultdict(set)
        for r in records or []:
            uname = self._norm(r.get("username", ""))
            key = self._userassist_basename(r.get("program", ""))
            if uname and key:
                idx[key].add(uname)
        return dict(idx)

    def score_app(self, data, userassist_index: Optional[Dict[str, set]] = None):
        """
        Score suspicious Prefetch executions. Matching is an exact lookup
        of the cleaned basename against SUSPICIOUS_EXES (see
        _exe_basename()) — not a substring scan — so an unrelated binary
        that merely contains a keyword (e.g. "powershell_backup.exe")
        cannot be mistaken for the real tool.

        Attribution is tried in two steps:
          1. Prefetch's own exe_path/section_c_paths (path-based — see
             _resolve_user()). This is the primary, most direct signal.
          2. If that fails, UserAssist correlation: a UserAssist entry can
             only exist inside the specific user's own NTUSER.DAT, so it is
             unambiguous per-user evidence by construction — but only when
             EXACTLY ONE user's UserAssist history references this exe's
             basename. A tie (2+ candidate users) is deliberately left
             unattributed rather than guessed at, since attributing to an
             arbitrary one of several candidates would fabricate evidence.
        Anything neither step resolves is pooled under "__apps__" and is
        deliberately NOT split across every account by the caller (see
        calculate_aggregate()) — it is case-wide evidence, not
        per-account evidence. Every evidence item records which method
        (if any) attributed it, via "attribution_method".
        """
        s = defaultdict(lambda: {"count":0,"weighted_count":0.0,"evidence":[]})
        userassist_index = userassist_index or {}
        attributed = shared = ua_attributed = 0
        for r in (data or {}).get("records", []):
            exe = self._exe_basename(r.get("exe_name",""))
            hit = SUSPICIOUS_EXES.get(exe)
            if not hit:
                continue
            cat, mult = hit
            path = r.get("exe_path","") or ""
            cnt = r.get("run_count") or 1
            lrun = r.get("last_run","")
            paths = r.get("section_c_paths", [])
            user = ""
            for cp in [path] + (paths if isinstance(paths, list) else []):
                user = self._resolve_user(cp)
                if user: break

            if user:
                attribution_method = "prefetch_path"
                attributed += 1
            else:
                candidates = userassist_index.get(exe, set())
                if len(candidates) == 1:
                    user = next(iter(candidates))
                    attribution_method = "userassist_correlation"
                    ua_attributed += 1
                else:
                    user = "__apps__"
                    attribution_method = "unattributed"
                    shared += 1

            s[user]["count"] += cnt
            s[user]["weighted_count"] += cnt * mult
            s[user]["evidence"].append({"exe":exe,"category":cat,
                "multiplier":mult,"run_count":cnt,"last_run":lrun,
                "attribution_method":attribution_method})
        return dict(s)
    
    def score_events(self, data):
        s = defaultdict(lambda: {"count":0,"weighted_count":0.0,"account_type":"user","evidence":[]})
        for e in (data or {}).get("all_events", []):
            eid = e.get("event_id")
            if eid not in ANOMALY_EVENT_IDS: continue
            label, w = ANOMALY_EVENT_IDS[eid]
            ed = e.get("event_data",{})
            u = (ed.get("SubjectUserName") or ed.get("TargetUserName") or
                 ed.get("AccountName") or ed.get("String0") or "")
            if not u: continue
            k = self._norm(u)
            s[k]["count"] += 1
            s[k]["weighted_count"] += w
            s[k]["evidence"].append({"event_id":eid,"label":label,"weight":w,
                                     "timestamp":e.get("timestamp","")})
        return dict(s)
    
    def score_privileged_logons(self, data):
        """
        Track privileged-logon events (4672/576) per user WITHOUT scoring
        them — no weighted_count, no category contribution. Purely a
        timestamped evidence source for calculate_timeline_bonuses()'s
        "privileged_logon_then_activity" correlation check; see
        PRIVILEGED_LOGON_EVENT_IDS for why these carry no standalone
        weight.
        """
        s = defaultdict(lambda: {"count":0,"evidence":[]})
        for e in (data or {}).get("all_events", []):
            eid = e.get("event_id")
            if eid not in PRIVILEGED_LOGON_EVENT_IDS: continue
            ed = e.get("event_data",{})
            u = (ed.get("SubjectUserName") or ed.get("TargetUserName") or
                 ed.get("AccountName") or ed.get("String0") or "")
            if not u: continue
            k = self._norm(u)
            s[k]["count"] += 1
            s[k]["evidence"].append({"event_id":eid,"label":PRIVILEGED_LOGON_EVENT_IDS[eid],
                                     "timestamp":e.get("timestamp","")})
        return dict(s)

    def score_network(self, data):
        """
        Score network events, differentiating destinations into
        internal/external/suspicious tiers (NETWORK_TIER_WEIGHTS) rather
        than counting every event equally — a purely internal LAN
        connection is much weaker evidence than a connection to a known
        exfiltration/anonymization destination.
        """
        s = defaultdict(lambda: {"count":0.0,"raw_count":0,
                                  "internal":0,"external":0,"suspicious":0,
                                  "evidence":[]})
        for e in (data or {}).get("network_events", []):
            ed = e.get("event_data",{})
            dip = ed.get("DestAddress") or ed.get("IpAddress","")
            if not dip: continue
            u = (ed.get("SubjectUserName") or ed.get("TargetUserName") or
                 ed.get("AccountName") or "")
            if not u: continue
            k = self._norm(u)
            tier = self._classify_dest(dip)
            s[k]["raw_count"] += 1
            s[k]["count"] += NETWORK_TIER_WEIGHTS[tier]
            s[k][tier] += 1
            s[k]["evidence"].append({"event_id":e.get("event_id"),
                                     "timestamp":e.get("timestamp",""),
                                     "dest_ip":dip,"tier":tier})
        return dict(s)

    def score_network_from_browser(self, data):
        s = defaultdict(lambda: {"count":0.0,"raw_count":0,"evidence":[]})
        for r in (data or {}).get("records", []):
            u = r.get("username","")
            k = self._norm(u)
            if not k: continue
            host = self._host_of(r.get("url",""))
            for kw,(cat,w) in SUSPICIOUS_DOMAINS.items():
                if self._domain_matches(host, kw):
                    s[k]["count"] += w * 0.3
                    s[k]["raw_count"] += 1
                    s[k]["evidence"].append({"url":r.get("url",""),"category":cat,
                        "weight":w,"visited_at":r.get("visited_at","")})
                    break
        return dict(s)
    
    def score_documents(self, data):
        s = defaultdict(lambda: {"count":0,"sensitive_count":0,"evidence":[]})
        for r in (data or {}).get("records", []):
            if r.get("type") != "lnk": continue
            u = r.get("username","")
            k = self._norm(u)
            if not k: continue
            s[k]["count"] += 1
            target = r.get("target_path","")
            ext = Path(target).suffix.lower() if target else ""
            if _is_sensitive_target(target, ext):
                s[k]["sensitive_count"] += 1
                s[k]["evidence"].append({"target":target,"extension":ext,
                    "accessed_at":r.get("target_accessed","")})
        return dict(s)
    
    def score_browser(self, data):
        """
        Flag browser-history evidence from two independent signals:
          1. Known-bad *destination* (SUSPICIOUS_DOMAINS, matched against
             the URL's host — unchanged from before).
          2. Anti-forensic/evasive *intent* expressed in the page title,
             URL query string, or URL path text, regardless of which
             domain it's on (see parsers/parse_browser_history.py's
             BEHAVIOR_PATTERNS / _annotate_behavior() — the parser computes
             "behavior_category"/"behavior_weight" once per record; this
             just consumes it). A record can be flagged by both signals
             independently — they represent different kinds of evidence.
        """
        s = defaultdict(lambda: {"count":0,"flagged_count":0,"flagged_weight":0.0,"evidence":[]})
        for r in (data or {}).get("records", []):
            u = r.get("username","")
            k = self._norm(u)
            if not k: continue
            host = self._host_of(r.get("url",""))
            s[k]["count"] += 1
            for kw,(cat,dw) in SUSPICIOUS_DOMAINS.items():
                if self._domain_matches(host, kw):
                    s[k]["flagged_count"] += 1
                    s[k]["flagged_weight"] += dw
                    s[k]["evidence"].append({"url":r.get("url",""),"category":cat,
                        "weight":dw,"visited":r.get("visited_at",""),"signal":"domain"})
                    break

            behavior_cat = r.get("behavior_category")
            if behavior_cat:
                bw = r.get("behavior_weight", 0) or 0
                s[k]["flagged_count"] += 1
                s[k]["flagged_weight"] += bw
                s[k]["evidence"].append({"url":r.get("url",""),"category":behavior_cat,
                    "weight":bw,"visited":r.get("visited_at",""),"signal":"behavior_text",
                    "matched_on":r.get("behavior_matched_on","")})
        return dict(s)
    
    def score_accounts(self, data):
        s = defaultdict(lambda: {"count":0,"evidence":[]})
        for r in (data or {}).get("users",{}).get("records", []):
            u = r.get("username","")
            k = self._norm(u)
            if not k: continue
            if (r.get("failed_logins") or 0) >= 5:
                s[k]["count"] += 1
                s[k]["evidence"].append({"flag":"high_failed_logins",
                                         "failed_logins":r.get("failed_logins")})
        return dict(s)
    
    def _build_timeline(self, user, doc_s, del_s, app_s, net_s, evt_s, priv_s=None) -> List[Dict]:
        """
        Merge every timestamped evidence item for `user` across the
        "real evidence" sources into one chronological list. This is the
        per-user activity sequence that calculate_timeline_bonuses() walks
        to detect cross-artifact temporal patterns (P1-P6) — separate from
        reporting.html_report's _build_timeline(), which does the same kind
        of merge but for display in the HTML report, not for scoring.

        priv_s (privileged-logon evidence, from score_privileged_logons())
        is included here purely as timeline context for P6
        ("privileged_logon_then_activity") — unlike the other five sources,
        it never independently contributes to event_anomalies scoring; see
        PRIVILEGED_LOGON_EVENT_IDS.
        """
        events: List[Dict] = []
        for ev in doc_s.get(user, {}).get("evidence", []):
            ts = self._parse_ts(ev.get("accessed_at"))
            if ts:
                events.append({"ts": ts, "type": "document_access", "detail": ev.get("target", "")})
        for ev in del_s.get(user, {}).get("evidence", []):
            ts = self._parse_ts(ev.get("deleted_at"))
            if ts:
                events.append({"ts": ts, "type": "deleted_file", "detail": ev.get("path", "")})
        for ev in net_s.get(user, {}).get("evidence", []):
            ts = self._parse_ts(ev.get("timestamp"))
            if ts:
                events.append({"ts": ts, "type": "network_activity", "detail": ev.get("dest_ip", "")})
        for ev in evt_s.get(user, {}).get("evidence", []):
            ts = self._parse_ts(ev.get("timestamp"))
            if ts:
                events.append({"ts": ts, "type": "event_anomaly", "detail": ev.get("label", "")})
        for ev in app_s.get(user, {}).get("evidence", []):
            ts = self._parse_ts(ev.get("last_run"))
            if ts:
                events.append({"ts": ts, "type": "application_exec", "detail": ev.get("exe", "")})
        for ev in (priv_s or {}).get(user, {}).get("evidence", []):
            ts = self._parse_ts(ev.get("timestamp"))
            if ts:
                events.append({"ts": ts, "type": "privileged_logon", "detail": ev.get("label", "")})
        return sorted(events, key=lambda x: x["ts"])

    def calculate_timeline_bonuses(self, user, doc_s, del_s, app_s, net_s, evt_s, priv_s=None):
        """
        Detect cross-artifact temporal patterns in `user`'s timeline and
        return (bonus, patterns), ported from correlate_artifacts_v11.py's
        calculate_timeline_bonuses(). Each pattern is capped independently
        (TIMELINE_BONUS_CAP) so one repeated pattern can't dominate the score.
        """
        timeline = self._build_timeline(user, doc_s, del_s, app_s, net_s, evt_s, priv_s)
        if not timeline:
            return 0, []

        bonus = 0
        patterns: List[Dict] = []
        used: set = set()
        bonus_by_type = defaultdict(int)

        def add_bonus(pattern_key, detail, timestamp) -> bool:
            cap = TIMELINE_BONUS_CAP[pattern_key]
            if bonus_by_type[pattern_key] >= cap:
                return False
            b = TIMELINE_BONUS[pattern_key]
            bonus_by_type[pattern_key] += b
            patterns.append({"pattern": pattern_key, "bonus": b, "detail": detail, "timestamp": timestamp})
            return True

        # P1: File access -> deletion within 5 min. Pairs are tracked by
        # timeline index, not object identity (id()) — index is stable and
        # portable, whereas relying on id() ties correctness to CPython's
        # object-identity semantics for no real benefit.
        accesses = [(i, e) for i, e in enumerate(timeline) if e["type"] == "document_access"]
        deletions = [(i, e) for i, e in enumerate(timeline) if e["type"] == "deleted_file"]
        for ai, acc in accesses:
            for di, dlt in deletions:
                pair = (ai, di)
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

        # P2: App execution -> network activity within 10 min
        app_execs = [(i, e) for i, e in enumerate(timeline) if e["type"] == "application_exec"]
        net_events = [(i, e) for i, e in enumerate(timeline) if e["type"] == "network_activity"]
        for pi, app in app_execs:
            for ni, net in net_events:
                pair = (pi, ni)
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

        # P3: Activity burst then log gap >= 1 hour
        for i in range(len(timeline) - 1):
            gap = (timeline[i + 1]["ts"] - timeline[i]["ts"]).total_seconds()
            if gap >= 3600:
                gap_start = timeline[i]["ts"]
                pre_gap_events = [
                    e for e in timeline[:i + 1]
                    if (gap_start - e["ts"]).total_seconds() <= 3600
                ]
                if len(pre_gap_events) >= 3:
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

        # P4: Rapid actions - >= 5 events within 60 s
        for evt in timeline:
            window = [e for e in timeline if 0 <= (e["ts"] - evt["ts"]).total_seconds() <= 60]
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

        # P5: Multi-source consistency - >= 3 artifact types in 5 min
        for evt in timeline:
            window = [e for e in timeline if 0 <= (e["ts"] - evt["ts"]).total_seconds() <= 300]
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

        # P6: Privileged logon (4672/576) correlated with other real
        # evidence within PRIVILEGED_LOGON_WINDOW_S, in either order — an
        # elevated session used to act, or elevated right after acting to
        # cover tracks, are both meaningful. This is the ONLY way a
        # privileged-logon event can contribute anything at all; see
        # PRIVILEGED_LOGON_EVENT_IDS for why it carries no standalone
        # weight in event_anomalies.
        priv_events = [(i, e) for i, e in enumerate(timeline) if e["type"] == "privileged_logon"]
        other_events = [(i, e) for i, e in enumerate(timeline) if e["type"] != "privileged_logon"]
        for pi, priv in priv_events:
            for oi, other in other_events:
                pair = ("priv", pi, oi)
                if pair in used:
                    continue
                delta = abs((other["ts"] - priv["ts"]).total_seconds())
                if delta <= PRIVILEGED_LOGON_WINDOW_S:
                    used.add(pair)
                    order = "before" if other["ts"] >= priv["ts"] else "after"
                    if add_bonus(
                        "privileged_logon_then_activity",
                        f"Privileged logon {order} '{other['type']}: {other['detail']}' "
                        f"({int(delta)}s apart)",
                        priv["ts"].isoformat(),
                    ):
                        bonus += TIMELINE_BONUS["privileged_logon_then_activity"]

        return bonus, patterns

    def _category_scores(self, del_c, evt_wc, app_own, net_total, doc_sc, brw_fw, usr_c) -> Dict[str, float]:
        """
        Each category's contribution to a user's score, in one consistent
        unit — metric * WEIGHTS[category] — independently capped at
        CATEGORY_CAP so no single high-volume category can dominate the
        total. This replaces the old raw/normalized blend, which divided a
        mix of raw counts and pre-weighted floats by a denominator that
        summed those same incompatible units together.
        """
        return {
            "deleted_files":    min(del_c * WEIGHTS["deleted_files"], CATEGORY_CAP["deleted_files"]),
            "event_anomalies":  min(evt_wc * WEIGHTS["event_anomalies"], CATEGORY_CAP["event_anomalies"]),
            "app_activity":     min(app_own * WEIGHTS["app_activity"], CATEGORY_CAP["app_activity"]),
            "network_activity": min(net_total * WEIGHTS["network_activity"], CATEGORY_CAP["network_activity"]),
            "document_access":  min(doc_sc * WEIGHTS["document_access"], CATEGORY_CAP["document_access"]),
            "browser_history":  min(brw_fw * WEIGHTS["browser_history"], CATEGORY_CAP["browser_history"]),
            "user_accounts":    min(usr_c * WEIGHTS["user_accounts"], CATEGORY_CAP["user_accounts"]),
        }

    def calculate_aggregate(self, users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s, priv_s=None):
        all_keys = set(users.keys())
        for d in (del_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s):
            all_keys.update(d.keys())
        all_keys.update(k for k in app_s if k != "__apps__")
        all_keys = {k for k in all_keys if k and k not in ("","-","__unknown__")}

        if not all_keys:
            return []

        # Unattributed ("shared pool") suspicious-application activity is
        # retained as case-wide context (surfaced below and in run()'s
        # summary) but is deliberately NOT split across every account.
        # Distributing it evenly previously gave every innocent account a
        # non-evidentiary score floor just for existing in the same image,
        # which is what produced the narrow HIGH/LOW score gap flagged in
        # RA4/EXP-02/EXP-03 — an account's score must come only from
        # activity actually attributable to it.
        app_shared_wc = app_s.get("__apps__",{}).get("weighted_count",0.0)

        def app_own(u):
            return app_s.get(u,{}).get("weighted_count",0.0)

        # Results — each user's artifact_score depends only on their own
        # evidence and the fixed constants above, never on what any other
        # account in this image scored. That is what makes the same
        # evidence produce the same score on every run, and makes scores
        # comparable across different forensic images (requirement: no
        # image-relative normalization).
        results = []
        for u in sorted(all_keys):
            ui = users.get(u, {"username": u})
            del_c = del_s.get(u,{}).get("count",0)
            evt_c = evt_s.get(u,{}).get("count",0)
            evt_wc = evt_s.get(u,{}).get("weighted_count",0.0)
            net_c = net_s.get(u,{}).get("count",0.0)
            net_bw = net_brw_s.get(u,{}).get("count",0.0)
            net_raw = net_s.get(u,{}).get("raw_count",0) + net_brw_s.get(u,{}).get("raw_count",0)
            doc_t = doc_s.get(u,{}).get("count",0)
            doc_sc = doc_s.get(u,{}).get("sensitive_count",0)
            brw_t = brw_s.get(u,{}).get("count",0)
            brw_fc = brw_s.get(u,{}).get("flagged_count",0)
            brw_fw = brw_s.get(u,{}).get("flagged_weight",0.0)
            usr_c = usr_s.get(u,{}).get("count",0)
            app_own_val = app_own(u)
            net_total = net_c + net_bw

            cat_scores = self._category_scores(
                del_c, evt_wc, app_own_val, net_total, doc_sc, brw_fw, usr_c
            )
            total_weighted = sum(cat_scores.values())
            artifact_score = min(
                100.0,
                (math.log1p(total_weighted) / math.log1p(FIXED_SCORE_CEILING)) * 100.0,
            )

            tl_bonus, tl_patterns = self.calculate_timeline_bonuses(
                u, doc_s, del_s, app_s, net_s, evt_s, priv_s
            )
            final_score = artifact_score + tl_bonus

            # Diversity — attributed app activity only; the shared pool
            # does not count toward any individual account's diversity.
            cats = {"deleted": del_c > 0, "events": evt_c > 0,
                    "app": app_own_val > 0, "network": net_total > 0,
                    "docs": doc_sc > 0, "browser": brw_fc > 0,
                    "accounts": usr_c > 0}
            div_count = sum(1 for v in cats.values() if v)

            results.append({
                "username": u,
                "display_name": ui.get("username", u),
                "account_type": self._acct_type(u),
                "rankable": self._rankable(u),
                "artifact_score": round(artifact_score, 2),
                "timeline_bonus": tl_bonus,
                "timeline_patterns": tl_patterns,
                "final_score": round(final_score, 2),
                "risk_label": None,
                "risk_rationale": "",
                "diversity": {"category_count": div_count},
                "artifact_breakdown": {
                    "deleted_files": {"count": del_c, "score": round(cat_scores["deleted_files"], 2)},
                    "event_anomalies": {"count": evt_c, "score": round(cat_scores["event_anomalies"], 2)},
                    "app_activity": {
                        "effective": round(app_own_val, 2),
                        "attributed_count": app_s.get(u,{}).get("count",0),
                        "score": round(cat_scores["app_activity"], 2),
                        "shared_pool_weighted": round(app_shared_wc, 2),
                    },
                    "network_activity": {"weighted": round(net_total, 2), "raw_count": net_raw, "score": round(cat_scores["network_activity"], 2)},
                    "document_access": {"count": doc_t, "sensitive": doc_sc, "score": round(cat_scores["document_access"], 2)},
                    "browser_history": {"count": brw_t, "flagged": brw_fc, "score": round(cat_scores["browser_history"], 2)},
                    "user_accounts": {"count": usr_c, "score": round(cat_scores["user_accounts"], 2)},
                },
                "evidence": {
                    "deleted_files": del_s.get(u,{}).get("evidence", [])[:20],
                    "event_anomalies": evt_s.get(u,{}).get("evidence", [])[:20],
                    "network_activity": net_s.get(u,{}).get("evidence", [])[:20],
                    "browser_history": brw_s.get(u,{}).get("evidence", [])[:20],
                    "app_activity": app_s.get(u,{}).get("evidence", [])[:20],
                    "user_accounts": usr_s.get(u,{}).get("evidence", [])[:20],
                    "document_access": doc_s.get(u,{}).get("evidence", [])[:20],
                }
            })

        return results
    
    def _security_log_coverage(self, events: List[Dict]) -> Dict[str, Any]:
        """
        Distinguish "zero event_anomalies because nothing happened" from
        "zero event_anomalies because there is no visibility into the
        Security log at all" — Windows XP ships with Security-channel
        auditing disabled by default, so an unmodified XP image very
        commonly has no usable Security-log evidence regardless of what
        the user actually did. Report-only: purely a coverage/confidence
        annotation surfaced in summary/the HTML report, and does not feed
        into scoring — event_anomalies' score is unaffected either way.
        """
        sec_events = [
            e for e in events
            if str(e.get("channel", "")).strip().lower() in ("security", "secevent")
        ]
        observed = len(sec_events)
        if observed > 0:
            return {
                "security_events_observed": observed,
                "status": "OBSERVED",
                "note": f"{observed} Security-channel event(s) observed.",
            }
        return {
            "security_events_observed": 0,
            "status": "NO_VISIBILITY",
            "note": (
                "No Security-channel events were found in this image's event "
                "logs. This commonly means Security auditing was never "
                "enabled (the Windows XP default) or the Security log "
                "wasn't captured, rather than a clean audit trail — a LOW "
                "event_anomalies score here should not be read as proof "
                "nothing happened."
            ),
        }

    def _has_real_evidence(self, r: Dict) -> bool:
        """
        Check if user has REAL evidence (not just a slice of the shared,
        unattributed app-activity pool). Users whose only "activity" is an
        equal-split crumb of that shared pool must not be elevated to
        HIGH/MEDIUM just because every account technically has a score > 0.
        """
        b = r["artifact_breakdown"]
        if b["deleted_files"]["count"] > 0: return True
        if b["event_anomalies"]["count"] > 0: return True
        if b["document_access"]["sensitive"] > 0: return True
        if b["browser_history"]["flagged"] > 0: return True
        if b["user_accounts"]["count"] > 0: return True
        if b["network_activity"]["raw_count"] > 0: return True
        if b["app_activity"]["attributed_count"] > 0: return True
        return False

    def _strong_category_count(self, r: Dict) -> int:
        """Number of STRONG_EVIDENCE_CATEGORIES with a non-zero score contribution."""
        b = r["artifact_breakdown"]
        return sum(1 for c in STRONG_EVIDENCE_CATEGORIES if b[c]["score"] > 0)

    def assign_risk_labels(self, ranked):
        """
        Absolute-threshold risk classification (RISK_THRESHOLDS), not
        percentile-of-this-run. Percentile ranking guarantees someone is
        always "top 20%" even in an image with no real suspects, which can
        mislabel an ordinary user HIGH purely for out-ranking equally
        innocent peers. Every label here is instead justified against a
        fixed score/diversity bar and recorded in risk_rationale, so the
        classification is explainable independent of who else is in the
        same image.
        """
        if not ranked: return
        for r in ranked:
            if not self._has_real_evidence(r):
                r["risk_label"] = "LOW"
                r["risk_rationale"] = (
                    "No user-attributable evidence beyond shared/system activity."
                )
                continue

            score = r["final_score"]
            diversity = r["diversity"]["category_count"]
            strong = self._strong_category_count(r)

            if (score >= RISK_THRESHOLDS["high_score"]
                    and diversity >= RISK_THRESHOLDS["high_diversity"]
                    and strong >= 1):
                r["risk_label"] = "HIGH"
                r["risk_rationale"] = (
                    f"Score {score:.2f} (>= {RISK_THRESHOLDS['high_score']}) across "
                    f"{diversity} independent evidence categories, including "
                    f"{strong} strong (user-attributed) source(s)."
                )
            elif score >= RISK_THRESHOLDS["medium_score"] or diversity >= 2:
                r["risk_label"] = "MEDIUM"
                r["risk_rationale"] = (
                    f"Score {score:.2f} / {diversity} categories — suspicious but "
                    f"incomplete evidence relative to the HIGH threshold "
                    f"({RISK_THRESHOLDS['high_score']})."
                )
            else:
                r["risk_label"] = "LOW"
                r["risk_rationale"] = (
                    f"Score {score:.2f} from a single, isolated indicator — "
                    "insufficient for elevation above LOW."
                )
    
    def build_threats(self, results: List[Dict]) -> List[Dict]:
        """
        Indicator-based threats, aggregated per (user, threat type) from
        evidence already attached to each rankable user's result — known-
        suspicious executable execution, contact with a known-suspicious
        network/browser destination, and anti-forensics/persistence event
        types (log clearing, service install, account lockout). Read-only
        over `results`; does not touch scoring.
        """
        buckets: Dict[tuple, Dict[str, Any]] = {}

        def add(user: str, ttype: str, severity: str, detail: str, ts: str = "") -> None:
            key = (user, ttype)
            b = buckets.setdefault(key, {"count": 0, "severity": severity, "sample": detail, "times": []})
            b["count"] += 1
            if ts:
                b["times"].append(ts)
            if _SEV_RANK[severity] > _SEV_RANK[b["severity"]]:
                b["severity"] = severity

        for r in results:
            if not r.get("rankable"):
                continue
            user = r.get("display_name") or r.get("username", "")
            evidence = r.get("evidence", {})

            for e in evidence.get("app_activity", []):
                sev = THREAT_EXE_SEVERITY.get(e.get("category"))
                if sev:
                    add(user, f"Suspicious Tool Execution: {e.get('category','').replace('_',' ').title()}",
                        sev, str(e.get("exe", "?")), str(e.get("last_run", "")))

            for e in evidence.get("network_activity", []):
                if e.get("tier") == "suspicious":
                    add(user, "Suspicious Network Destination", "HIGH",
                        str(e.get("dest_ip", "?")), str(e.get("timestamp", "")))

            for e in evidence.get("browser_history", []):
                cat = e.get("category")
                label = f"Suspicious Domain Visit: {cat.replace('_',' ').title()}" if cat else "Suspicious Domain Visit"
                add(user, label, THREAT_DOMAIN_SEVERITY.get(cat, "MEDIUM"),
                    str(e.get("url", "?")), str(e.get("visited", "")))

            for e in evidence.get("event_anomalies", []):
                sev = THREAT_EVENT_SEVERITY.get(e.get("label"))
                if sev:
                    add(user, str(e.get("label", "")).replace("_", " ").title(), sev,
                        f"Event ID {e.get('event_id')}", str(e.get("timestamp", "")))

        threats = []
        for (user, ttype), b in buckets.items():
            times = sorted(t for t in b["times"] if t)
            when = f"{times[0]} to {times[-1]}" if len(times) > 1 else (times[0] if times else "")
            desc = f"{user}: {b['count']} occurrence(s), e.g. {b['sample']}"
            if when:
                desc += f" ({when})"
            threats.append({
                "type": ttype, "severity": b["severity"], "description": desc, "count": b["count"],
            })

        threats.sort(key=lambda t: (-_SEV_RANK[t["severity"]], -t["count"]))
        return threats

    def build_anomalies(self, results: List[Dict]) -> List[Dict]:
        """
        Behavioral/timing anomalies, aggregated per (user, pattern type)
        from timeline_patterns calculate_timeline_bonuses() already computed
        for each rankable user, plus account-flag evidence from
        score_accounts(). Read-only over `results`; does not touch scoring.
        """
        anomalies = []
        for r in results:
            if not r.get("rankable"):
                continue
            user = r.get("display_name") or r.get("username", "")

            pattern_counts: Dict[str, Dict[str, Any]] = {}
            for p in r.get("timeline_patterns", []) or []:
                key = p.get("pattern")
                pc = pattern_counts.setdefault(key, {"count": 0, "detail": p.get("detail", ""), "time": p.get("timestamp", "")})
                pc["count"] += 1

            for key, pc in pattern_counts.items():
                anomalies.append({
                    "type": ANOMALY_PATTERN_LABEL.get(key, str(key).replace("_", " ").title()),
                    "severity": ANOMALY_PATTERN_SEVERITY.get(key, "LOW"),
                    "description": f"{user}: {pc['detail']}",
                    "count": pc["count"],
                    "time": pc["time"] or "N/A",
                })

            for e in r.get("evidence", {}).get("user_accounts", []):
                if e.get("flag") == "high_failed_logins":
                    anomalies.append({
                        "type": "Excessive Failed Logins",
                        "severity": "MEDIUM",
                        "description": f"{user}: {e.get('failed_logins')} failed login attempts recorded, "
                                        "exceeding the normal threshold.",
                        "count": e.get("failed_logins", 0),
                        "time": "N/A",
                    })

        anomalies.sort(key=lambda a: (-_SEV_RANK.get(a["severity"], 0), -a["count"]))
        return anomalies

    def run(self) -> Dict[str, Any]:
        """Run the complete correlation engine"""
        print("[*] Loading artifacts...")
        self.load_all_artifacts()
        
        print("[*] Building user map...")
        # Build user map
        users = {}
        for rec in self.users:
            u = rec.get("username", "")
            k = self._norm(u)
            if k:
                users[k] = {"username": u, "account_type": self._acct_type(u)}

        # rid -> username, for SID-based attribution fallback in _resolve_user()
        self._build_sid_map()

        print("[*] Scoring artifacts...")
        user_accounts_data = self.load_json("user_accounts.json") or {}
        userassist_records = user_accounts_data.get("userassist", {}).get("records", [])
        userassist_index = self._build_userassist_index(userassist_records)

        event_logs_data = self.load_json("event_logs.json")
        del_s = self.score_deleted(self.load_json("deleted_files.json"))
        app_s = self.score_app(self.load_json("application_activity.json"), userassist_index=userassist_index)
        evt_s = self.score_events(event_logs_data)
        priv_s = self.score_privileged_logons(event_logs_data)
        net_s = self.score_network(self.load_json("network_activity.json"))
        doc_s = self.score_documents(self.load_json("document_folder_access.json"))
        brw_s = self.score_browser(self.load_json("browser_history.json"))
        usr_s = self.score_accounts(self.load_json("user_accounts.json"))
        net_brw_s = self.score_network_from_browser(self.load_json("browser_history.json"))

        print("[*] Aggregating scores...")
        results = self.calculate_aggregate(users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s, priv_s)
        
        # Rank and assign risk labels
        ranked = sorted([r for r in results if r["rankable"]], key=lambda x: x["final_score"], reverse=True)
        for i, r in enumerate(ranked, 1):
            r["rank"] = i
        self.assign_risk_labels(ranked)
        
        # Combine ranked and system accounts
        sys_accts = [r for r in results if not r["rankable"]]
        for r in sys_accts:
            r["rank"] = None
        all_results = ranked + sys_accts

        print("[*] Building threats and anomalies...")
        threats = self.build_threats(all_results)
        anomalies = self.build_anomalies(all_results)

        # Generate summary
        now_iso = datetime.now(timezone.utc).isoformat()  # already "...+00:00"; do not also append "Z"
        summary = {
            'total_users': len(self.users),
            'total_events': len(self.events),
            'total_network': len(self.network),
            'total_browser': len(self.browser),
            'total_files': len(self.files),
            'total_deleted': len(self.deleted),
            'total_apps': len(self.apps),
            # Unattributed suspicious-application activity, retained as
            # case-wide context. Deliberately not divided across accounts —
            # see calculate_aggregate() — so this is visible here instead.
            'unattributed_app_activity_weighted': round(app_s.get("__apps__", {}).get("weighted_count", 0.0), 2),
            'security_log_coverage': self._security_log_coverage(self.events),
            'parsed_at': now_iso,
        }

        # Individual shared-pool records (case-wide context only — never
        # attributed to any one account, never fed into scoring). Exposed
        # here purely so the report can show what ran on the system even
        # when it can't be tied to a specific user; see calculate_aggregate().
        shared_pool_app_activity = app_s.get("__apps__", {}).get("evidence", [])

        output = {
            'artifact': 'correlated_results',
            'parsed_at': now_iso,
            'shared_pool_app_activity': shared_pool_app_activity,
            'summary': summary,
            'user_correlations': all_results,
            'anomalies': anomalies,
            'threats': threats,
            'total_anomalies': len(anomalies),
            'total_threats': len(threats),
            'high_risk_users': [u for u in all_results if u.get('risk_label') == 'HIGH']
        }
        
        output_file = self.output_dir / 'correlation_results.json'
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[✓] Correlation complete → {output_file}")
        print(f"[✓] {len(ranked)} users analyzed")
        print(f"[✓] {len(threats)} threats, {len(anomalies)} anomalies identified")

        return output