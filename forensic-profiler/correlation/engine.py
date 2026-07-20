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

from .rules import CorrelationRules
from .weights import ScoreWeights


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
MAX_NORM_SCORE: float = float(sum(WEIGHTS.values()))   # 17.5
RAW_WEIGHT  = 0.70
NORM_WEIGHT = 0.30

TIMELINE_BONUS = {
    "file_access_then_deletion":  5,
    "app_exec_then_network":      4,
    "activity_then_log_gap":      6,
    "rapid_actions":              3,
    "multi_source_consistency":   5,
}
TIMELINE_BONUS_CAP = {
    "file_access_then_deletion": 15,
    "app_exec_then_network":     12,
    "activity_then_log_gap":      6,
    "rapid_actions":              9,
    "multi_source_consistency":  10,
}

SYSTEM_ACCOUNTS = {
    "localsystem","system","local service","network service",
    "nt authority\\system","nt authority\\local service",
    "nt authority\\network service","wdagutilityaccount",
}
_DWM_RE = re.compile(r"^dwm-\d+$", re.I)
_DEF_RE = re.compile(r"^defaultuser\d+$", re.I)
_MCH_RE = re.compile(r".+\$$")

SUSPICIOUS_EXES: dict[str, tuple[str, float]] = {
    "nmap": ("recon", 1.5), "wireshark": ("recon", 1.5),
    "netstat": ("recon", 1.0), "whoami": ("recon", 1.0),
    "ipconfig": ("recon", 1.0), "arp": ("recon", 1.0),
    "psexec": ("remote_access", 2.0), "putty": ("remote_access", 1.5),
    "mstsc": ("remote_access", 1.5), "teamviewer": ("remote_access", 1.5),
    "powershell": ("execution", 1.5), "wscript": ("execution", 2.0),
    "mshta": ("execution", 2.0), "rundll32": ("execution", 2.0),
    "regsvr32": ("execution", 2.0), "cscript": ("execution", 1.5),
    "certutil": ("execution", 2.0), "bitsadmin": ("execution", 2.0),
    "sdelete": ("deletion", 2.5), "cipher": ("deletion", 2.0),
    "ccleaner": ("deletion", 2.0), "diskpart": ("deletion", 2.0),
    "mimikatz": ("credential", 3.0), "pwdump": ("credential", 3.0),
    "hashcat": ("credential", 2.5), "hydra": ("credential", 2.5),
}

SUSPICIOUS_DOMAINS: dict[str, tuple[str, int]] = {
    "tor2web": ("anonymization", 3), ".onion": ("anonymization", 4),
    "i2p": ("anonymization", 3), "darkweb": ("anonymization", 3),
    "mega.nz": ("exfil_site", 3), "wetransfer": ("exfil_site", 2),
    "anonfiles": ("exfil_site", 3), "pastebin": ("paste_site", 2),
    "exploit-db": ("hacking", 4), "metasploit": ("hacking", 3),
    "shodan": ("hacking", 2),
}

SENSITIVE_EXTS = {".docx",".doc",".xlsx",".xls",".pdf",".pptx",".ppt",
                  ".pst",".ost",".msg",".kdbx",".pfx",".p12",".cer",
                  ".key",".sql",".db",".sqlite",".bak",".backup",".csv"}

ANOMALY_EVENT_IDS: dict[int, tuple[str, int]] = {
    4625:("logon_failure",2), 529:("logon_failure",2),
    4740:("account_lockout",3), 539:("account_lockout",3),
    1102:("log_cleared",5), 517:("log_cleared",5),
    7045:("service_install",3), 4697:("service_install",3),
    4672:("privilege_escalation",3), 576:("privilege_escalation",3),
    4688:("process_creation",1), 592:("process_creation",1),
}

_INTERNAL_IP = [
    re.compile(r"^10\.\d+\.\d+\.\d+$"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$"),
    re.compile(r"^192\.168\.\d+\.\d+$"),
    re.compile(r"^127\.\d+\.\d+\.\d+$"),
    re.compile(r"^169\.254\.\d+\.\d+$"),
]

WINDOWS_EPOCH = datetime(1601,1,1,tzinfo=timezone.utc)


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
        """
        if not url:
            return ""
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            host = ""
        return host or url.lower()
    
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
    
    def _resolve_user(self, path="", sid=None) -> str:
        u = self._user_from_path(path)
        if u: return self._norm(u)
        return ""
    
    def _parse_ts(self, ts) -> datetime | None:
        if not ts: return None
        try: return datetime.fromisoformat(str(ts).replace("Z","+00:00"))
        except Exception: return None
    
    # ── Scoring functions ──────────────────────────────────────────────────────
    def score_deleted(self, data):
        s = defaultdict(lambda: {"count":0,"evidence":[]})
        for r in (data or {}).get("records", []):
            u = self._resolve_user(r.get("original_path",""), r.get("sid")) or "__unknown__"
            s[u]["count"] += 1
            s[u]["evidence"].append({"path":r.get("original_path",""),
                                     "deleted_at":r.get("deleted_at","")})
        return dict(s)
    
    def score_app(self, data):
        s = defaultdict(lambda: {"count":0,"weighted_count":0.0,"evidence":[]})
        attributed = shared = 0
        for r in (data or {}).get("records", []):
            exe = (r.get("exe_name","") or "").split("\x00")[0].strip().lower()
            path = r.get("exe_path","") or ""
            cnt = r.get("run_count") or 1
            lrun = r.get("last_run","")
            paths = r.get("section_c_paths", [])
            for kw,(cat,mult) in SUSPICIOUS_EXES.items():
                if kw in exe:
                    user = ""
                    for cp in [path] + (paths if isinstance(paths, list) else []):
                        user = self._resolve_user(cp, r.get("sid"))
                        if user: break
                    if not user:
                        user = "__apps__"; shared += 1
                    else:
                        attributed += 1
                    s[user]["count"] += cnt
                    s[user]["weighted_count"] += cnt * mult
                    s[user]["evidence"].append({"exe":exe,"category":cat,
                        "multiplier":mult,"run_count":cnt,"last_run":lrun})
                    break
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
    
    def score_network(self, data):
        s = defaultdict(lambda: {"count":0.0,"raw_count":0,"external":0,"evidence":[]})
        for e in (data or {}).get("network_events", []):
            ed = e.get("event_data",{})
            dip = ed.get("DestAddress") or ed.get("IpAddress","")
            if not dip: continue
            u = (ed.get("SubjectUserName") or ed.get("TargetUserName") or
                 ed.get("AccountName") or "")
            if not u: continue
            k = self._norm(u)
            s[k]["raw_count"] += 1
            s[k]["count"] += 1.0
            s[k]["evidence"].append({"event_id":e.get("event_id"),
                                     "timestamp":e.get("timestamp",""),
                                     "dest_ip":dip})
        return dict(s)
    
    def score_network_from_browser(self, data):
        s = defaultdict(lambda: {"count":0.0,"raw_count":0,"evidence":[]})
        for r in (data or {}).get("records", []):
            u = r.get("username","")
            k = self._norm(u)
            if not k: continue
            host = self._host_of(r.get("url",""))
            for kw,(cat,w) in SUSPICIOUS_DOMAINS.items():
                if kw in host:
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
            if ext in SENSITIVE_EXTS:
                s[k]["sensitive_count"] += 1
                s[k]["evidence"].append({"target":target,"extension":ext,
                    "accessed_at":r.get("target_accessed","")})
        return dict(s)
    
    def score_browser(self, data):
        s = defaultdict(lambda: {"count":0,"flagged_count":0,"flagged_weight":0.0,"evidence":[]})
        for r in (data or {}).get("records", []):
            u = r.get("username","")
            k = self._norm(u)
            if not k: continue
            host = self._host_of(r.get("url",""))
            s[k]["count"] += 1
            for kw,(cat,dw) in SUSPICIOUS_DOMAINS.items():
                if kw in host:
                    s[k]["flagged_count"] += 1
                    s[k]["flagged_weight"] += dw
                    s[k]["evidence"].append({"url":r.get("url",""),"category":cat,
                        "weight":dw,"visited":r.get("visited_at","")})
                    break
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
    
    def calculate_aggregate(self, users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s):
        all_keys = set(users.keys())
        for d in (del_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s):
            all_keys.update(d.keys())
        all_keys.update(k for k in app_s if k != "__apps__")
        all_keys = {k for k in all_keys if k and k not in ("","-","__unknown__")}
        
        if not all_keys:
            return []
        
        num_users = len({k for k in all_keys if self._rankable(k)}) or 1
        app_shared_wc = app_s.get("__apps__",{}).get("weighted_count",0.0)
        
        def app_share(u):
            uw = app_s.get(u,{}).get("weighted_count",0.0)
            return uw + (app_shared_wc / num_users)
        
        # Raw scores
        raw = {}
        for u in all_keys:
            del_c = del_s.get(u,{}).get("count",0)
            evt_wc = evt_s.get(u,{}).get("weighted_count",0.0)
            net_c = net_s.get(u,{}).get("count",0.0)
            net_bw = net_brw_s.get(u,{}).get("count",0.0)
            doc_sc = doc_s.get(u,{}).get("sensitive_count",0)
            brw_fw = brw_s.get(u,{}).get("flagged_weight",0.0)
            usr_c = usr_s.get(u,{}).get("count",0)
            app_share_val = app_share(u)
            raw[u] = (del_c * WEIGHTS["deleted_files"] +
                      evt_wc * WEIGHTS["event_anomalies"] +
                      app_share_val * WEIGHTS["app_activity"] +
                      (net_c + net_bw) * WEIGHTS["network_activity"] +
                      doc_sc * WEIGHTS["document_access"] +
                      brw_fw * WEIGHTS["browser_history"] +
                      min(usr_c * WEIGHTS["user_accounts"], 5))
        
        max_raw = max(raw.values(), default=1.0) or 1.0
        
        # Results
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
            app_share_val = app_share(u)
            net_total = net_c + net_bw
            
            raw_score = raw[u]
            total_ev = max(del_c + evt_c + net_total + doc_sc + brw_fc + usr_c + app_share_val, 1)
            
            def norm(v): return v / total_ev
            
            norm_score = (WEIGHTS["deleted_files"] * norm(del_c) +
                          WEIGHTS["event_anomalies"] * norm(evt_wc) +
                          WEIGHTS["app_activity"] * norm(app_share_val) +
                          WEIGHTS["network_activity"] * norm(net_total) +
                          WEIGHTS["document_access"] * norm(doc_sc) +
                          WEIGHTS["browser_history"] * norm(brw_fw) +
                          WEIGHTS["user_accounts"] * norm(usr_c))
            
            raw_scaled = self._log_scale(raw_score, max_raw)
            norm_scaled = (norm_score / MAX_NORM_SCORE) * 100.0
            artifact_score = RAW_WEIGHT * raw_scaled + NORM_WEIGHT * norm_scaled
            
            # Diversity
            cats = {"deleted": del_c > 0, "events": evt_c > 0,
                    "app": app_share_val > 0, "network": net_total > 0,
                    "docs": doc_sc > 0, "browser": brw_fc > 0,
                    "accounts": usr_c > 0}
            div_count = sum(1 for v in cats.values() if v)
            
            results.append({
                "username": u,
                "display_name": ui.get("username", u),
                "account_type": self._acct_type(u),
                "rankable": self._rankable(u),
                "artifact_score": round(artifact_score, 2),
                "timeline_bonus": 0,
                "timeline_patterns": [],
                "final_score": round(artifact_score, 2),
                "risk_label": None,
                "diversity": {"category_count": div_count},
                "artifact_breakdown": {
                    "deleted_files": {"count": del_c, "score": round(del_c * WEIGHTS["deleted_files"], 2)},
                    "event_anomalies": {"count": evt_c, "score": round(evt_wc * WEIGHTS["event_anomalies"], 2)},
                    "app_activity": {"effective": round(app_share_val, 2), "attributed_count": app_s.get(u,{}).get("count",0), "score": round(app_share_val * WEIGHTS["app_activity"], 2)},
                    "network_activity": {"weighted": round(net_total, 2), "raw_count": net_raw, "score": round(net_total * WEIGHTS["network_activity"], 2)},
                    "document_access": {"count": doc_t, "sensitive": doc_sc, "score": round(doc_sc * WEIGHTS["document_access"], 2)},
                    "browser_history": {"count": brw_t, "flagged": brw_fc, "score": round(brw_fw * WEIGHTS["browser_history"], 2)},
                    "user_accounts": {"count": usr_c, "score": round(min(usr_c * WEIGHTS["user_accounts"], 5), 2)},
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

    def assign_risk_labels(self, ranked):
        if not ranked: return
        for r in ranked:
            r["risk_label"] = "LOW"
        real = [r for r in ranked if r["artifact_score"] > 0 and self._has_real_evidence(r)]
        if not real: return
        n = len(real)
        if n == 1:
            real[0]["risk_label"] = "HIGH"
        elif n == 2:
            srt = sorted(real, key=lambda x: x["final_score"], reverse=True)
            srt[0]["risk_label"] = "HIGH"
            srt[1]["risk_label"] = "MEDIUM"
        else:
            scores_sorted = sorted(r["final_score"] for r in real)
            p80 = scores_sorted[math.floor((n - 1) * 0.80)]
            p50 = scores_sorted[math.floor((n - 1) * 0.50)]
            for r in real:
                s = r["final_score"]
                r["risk_label"] = "HIGH" if s >= p80 else ("MEDIUM" if s >= p50 else "LOW")
    
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
        
        print("[*] Scoring artifacts...")
        del_s = self.score_deleted(self.load_json("deleted_files.json"))
        app_s = self.score_app(self.load_json("application_activity.json"))
        evt_s = self.score_events(self.load_json("event_logs.json"))
        net_s = self.score_network(self.load_json("network_activity.json"))
        doc_s = self.score_documents(self.load_json("document_folder_access.json"))
        brw_s = self.score_browser(self.load_json("browser_history.json"))
        usr_s = self.score_accounts(self.load_json("user_accounts.json"))
        net_brw_s = self.score_network_from_browser(self.load_json("browser_history.json"))
        
        print("[*] Aggregating scores...")
        results = self.calculate_aggregate(users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, net_brw_s)
        
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
        
        # Generate summary
        summary = {
            'total_users': len(self.users),
            'total_events': len(self.events),
            'total_network': len(self.network),
            'total_browser': len(self.browser),
            'total_files': len(self.files),
            'total_deleted': len(self.deleted),
            'total_apps': len(self.apps),
            'parsed_at': datetime.now(timezone.utc).isoformat() + 'Z'
        }
        
        output = {
            'artifact': 'correlated_results',
            'parsed_at': datetime.now(timezone.utc).isoformat() + 'Z',
            'summary': summary,
            'user_correlations': all_results,
            'anomalies': [],
            'threats': [],
            'total_anomalies': 0,
            'total_threats': 0,
            'high_risk_users': [u for u in all_results if u.get('risk_label') == 'HIGH']
        }
        
        output_file = self.output_dir / 'correlation_results.json'
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[✓] Correlation complete → {output_file}")
        print(f"[✓] {len(ranked)} users analyzed")
        
        return output