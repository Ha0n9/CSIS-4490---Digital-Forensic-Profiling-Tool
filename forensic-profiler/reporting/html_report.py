#!/usr/bin/env python3
"""
HTML Report Generator - Create forensic analysis reports
Based on full_forensic_profiler_v1.py HTML template
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List


# Maps each evidence category to: the field holding its timestamp, a display
# icon/label, and a formatter for a one-line human-readable description.
TIMELINE_SPECS = {
    "deleted_files": {
        "ts": "deleted_at", "icon": "🗑️", "label": "File Deleted",
        "fmt": lambda e: f"Deleted file: {e.get('path') or '(unknown path)'}",
    },
    "event_anomalies": {
        "ts": "timestamp", "icon": "⚠️", "label": "Event Log",
        "fmt": lambda e: f"{str(e.get('label','')).replace('_',' ').title()} "
                          f"(Event ID {e.get('event_id','?')})",
    },
    "network_activity": {
        "ts": "timestamp", "icon": "🌐", "label": "Network",
        "fmt": lambda e: f"Network connection to {e.get('dest_ip') or '(unknown host)'}",
    },
    "browser_history": {
        "ts": "visited", "icon": "🔎", "label": "Browser",
        "fmt": lambda e: f"Visited flagged site ({e.get('category','')}): {e.get('url','')}",
    },
    "app_activity": {
        "ts": "last_run", "icon": "⚙️", "label": "Application Run",
        "fmt": lambda e: f"Ran {e.get('exe','?')} ({e.get('category','')}) "
                          f"× {e.get('run_count','?')} times",
    },
    "document_access": {
        "ts": "accessed_at", "icon": "📄", "label": "Document Access",
        "fmt": lambda e: f"Accessed sensitive file: {e.get('target','?')}",
    },
}


class HTMLReporter:
    """Generate HTML forensic reports from correlation results"""

    def __init__(
        self,
        json_dir: str,
        correlated_dir: str,
        output_dir: str,
        config: Optional[Dict] = None
    ):
        self.json_dir = Path(json_dir)
        self.correlated_dir = Path(correlated_dir)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.title = self.config.get('title', 'Forensic Analysis Report')
    
    def load_correlation_results(self) -> Optional[Dict]:
        """Load correlation results from disk"""
        filepath = self.correlated_dir / 'correlation_results.json'
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load correlation results: {e}")
        return None
    
    def _esc(self, s) -> str:
        """HTML-escape a value."""
        import html as _html
        return _html.escape(str(s)) if s is not None else ""

    def _fmt_ts(self, ts: str) -> str:
        """Pretty-print an ISO timestamp; falls back to the raw string."""
        if not ts:
            return "Unknown time"
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)

    def _build_timeline(self, user: Dict) -> List[Dict]:
        """
        Merge every timestamped evidence item across all categories into a
        single chronological list — this is "what did this user do" in the
        order it happened, which is what actually explains a risk label.
        """
        evidence = user.get("evidence", {})
        events: List[Dict] = []
        for category, spec in TIMELINE_SPECS.items():
            for item in evidence.get(category, []):
                ts = item.get(spec["ts"], "")
                if not ts:
                    continue
                try:
                    desc = spec["fmt"](item)
                except Exception:
                    desc = str(item)
                events.append({
                    "ts": ts,
                    "icon": spec["icon"],
                    "label": spec["label"],
                    "desc": desc,
                })
        events.sort(key=lambda e: e["ts"])
        return events

    def _render_timeline_html(self, events: List[Dict]) -> str:
        if not events:
            return '<p class="muted">No timestamped evidence available for this user.</p>'
        rows = ""
        for e in events:
            rows += f'''
            <li class="tl-item">
                <span class="tl-icon">{e["icon"]}</span>
                <span class="tl-time">{self._esc(self._fmt_ts(e["ts"]))}</span>
                <span class="tl-cat">{self._esc(e["label"])}</span>
                <span class="tl-desc">{self._esc(e["desc"])}</span>
            </li>
            '''
        return f'<ul class="timeline">{rows}</ul>'

    def _render_breakdown_html(self, user: Dict) -> str:
        b = user.get("artifact_breakdown", {})
        rows = [
            ("Deleted Files", b.get("deleted_files", {}).get("count", 0), b.get("deleted_files", {}).get("score", 0)),
            ("Event Anomalies", b.get("event_anomalies", {}).get("count", 0), b.get("event_anomalies", {}).get("score", 0)),
            ("Application Activity (attributed)", b.get("app_activity", {}).get("attributed_count", 0), b.get("app_activity", {}).get("score", 0)),
            ("Network Activity", b.get("network_activity", {}).get("raw_count", 0), b.get("network_activity", {}).get("score", 0)),
            ("Sensitive Document Access", b.get("document_access", {}).get("sensitive", 0), b.get("document_access", {}).get("score", 0)),
            ("Flagged Browser History", b.get("browser_history", {}).get("flagged", 0), b.get("browser_history", {}).get("score", 0)),
            ("Account Flags", b.get("user_accounts", {}).get("count", 0), b.get("user_accounts", {}).get("score", 0)),
        ]
        body = "".join(
            f'<tr><td>{self._esc(label)}</td><td class="r">{count}</td><td class="r">{score}</td></tr>'
            for label, count, score in rows
        )
        tl_bonus = user.get("timeline_bonus", 0)
        if tl_bonus:
            body += f'<tr><td>Timeline Pattern Bonus</td><td class="r">—</td><td class="r">+{tl_bonus}</td></tr>'
        return f'''
        <table class="tbl breakdown">
            <thead><tr><th>Category</th><th class="r">Count</th><th class="r">Score Contribution</th></tr></thead>
            <tbody>{body}</tbody>
        </table>
        '''

    def _render_user_detail(self, user: Dict) -> str:
        username = self._esc(user.get("display_name") or user.get("username", "Unknown"))
        risk_level = user.get("risk_label") or "NONE"
        risk_class = risk_level.lower()
        score = user.get("final_score", 0)
        events = self._build_timeline(user)
        open_attr = " open" if risk_level in ("HIGH", "MEDIUM") else ""

        return f'''
        <details class="user-detail"{open_attr}>
            <summary>
                <strong>{username}</strong>
                <span class="badge badge-{risk_class}">{self._esc(risk_level)}</span>
                <span class="risk-score risk-{risk_class}">{score}</span>
                <span class="muted">{len(events)} timestamped event(s)</span>
            </summary>
            <div class="user-detail-body">
                <h4>Score Breakdown</h4>
                {self._render_breakdown_html(user)}
                <h4>Activity Timeline</h4>
                {self._render_timeline_html(events)}
            </div>
        </details>
        '''

    def generate(self) -> Path:
        """Generate the final report"""
        print("[*] Loading correlation results...")
        correlation_results = self.load_correlation_results()
        
        if not correlation_results:
            print("[!] No correlation results found. Generating empty report.")
            correlation_results = {
                'summary': {},
                'user_correlations': [],
                'anomalies': [],
                'threats': [],
                'total_anomalies': 0,
                'total_threats': 0,
                'high_risk_users': []
            }
        
        html = self.generate_html(correlation_results)
        
        output_file = self.output_dir / 'forensic_report.html'
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"[✓] Report generated → {output_file}")
        return output_file
    
    def generate_html(self, data: Dict) -> str:
        """Generate complete HTML report"""
        
        summary = data.get('summary', {})
        users = data.get('user_correlations', [])
        anomalies = data.get('anomalies', [])
        threats = data.get('threats', [])
        total_anomalies = data.get('total_anomalies', 0)
        total_threats = data.get('total_threats', 0)
        high_risk_users = data.get('high_risk_users', [])
        
        gen_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # ── Summary stats ──────────────────────────────────────────────────────
        stats = [
            ('Users', summary.get('total_users', 0)),
            ('Events', summary.get('total_events', 0)),
            ('Network', summary.get('total_network', 0)),
            ('Browser History', summary.get('total_browser', 0)),
            ('Files', summary.get('total_files', 0)),
            ('Anomalies', total_anomalies),
            ('Threats', total_threats),
            ('High Risk Users', len(high_risk_users))
        ]
        
        stats_html = ""
        for label, value in stats:
            stats_html += f'''
            <div class="stat-card">
                <div class="stat-value">{value}</div>
                <div class="stat-label">{label}</div>
            </div>
            '''
        
        # ── Threats ────────────────────────────────────────────────────────────
        threats_html = ""
        if threats:
            for threat in threats:
                severity = threat.get('severity', 'LOW').lower()
                threats_html += f'''
                <div class="anomaly severity-{severity}">
                    <div class="anomaly-header">
                        <strong>{self._esc(threat.get('type', 'Unknown'))}</strong>
                        <span class="badge badge-{severity}">{self._esc(threat.get('severity', 'LOW'))}</span>
                    </div>
                    <p>{self._esc(threat.get('description', ''))}</p>
                    <div class="anomaly-meta">
                        <small>Count: {threat.get('count', 0)}</small>
                    </div>
                </div>
                '''
        else:
            threats_html = '<p><em>No threats detected</em></p>'
        
        # ── Anomalies ──────────────────────────────────────────────────────────
        anomalies_html = ""
        if anomalies:
            for anomaly in anomalies:
                severity = anomaly.get('severity', 'LOW').lower()
                anomalies_html += f'''
                <div class="anomaly severity-{severity}">
                    <div class="anomaly-header">
                        <strong>{self._esc(anomaly.get('type', 'Unknown'))}</strong>
                        <span class="badge badge-{severity}">{self._esc(anomaly.get('severity', 'LOW'))}</span>
                    </div>
                    <p>{self._esc(anomaly.get('description', ''))}</p>
                    <div class="anomaly-meta">
                        <small>Count: {anomaly.get('count', 0)}</small>
                        <small>Time: {self._esc(anomaly.get('time', 'N/A'))}</small>
                    </div>
                </div>
                '''
        else:
            anomalies_html = '<p><em>No anomalies detected</em></p>'
        
        # ── Users table ───────────────────────────────────────────────────────
        users_html = ""
        if users:
            users_html = '''
            <table class="tbl">
                <thead>
                    <tr>
                        <th>User</th>
                        <th class="r">Events</th>
                        <th class="r">Network</th>
                        <th class="r">Files</th>
                        <th class="r">Browser</th>
                        <th class="r">Risk Score</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
            '''
            
            for user in users[:50]:
                username = user.get('display_name') or user.get('username', 'Unknown')
                risk_level = user.get('risk_label') or 'NONE'
                risk_class = risk_level.lower()
                breakdown = user.get('artifact_breakdown', {})
                event_count = breakdown.get('event_anomalies', {}).get('count', 0)
                network_count = breakdown.get('network_activity', {}).get('raw_count', 0)
                file_count = breakdown.get('document_access', {}).get('count', 0)
                browser_count = breakdown.get('browser_history', {}).get('count', 0)
                risk_score = user.get('final_score', 0)

                users_html += f'''
                <tr>
                    <td><strong>{self._esc(username)}</strong></td>
                    <td class="r">{event_count}</td>
                    <td class="r">{network_count}</td>
                    <td class="r">{file_count}</td>
                    <td class="r">{browser_count}</td>
                    <td class="r"><span class="risk-score risk-{risk_class}">{risk_score}</span></td>
                    <td><span class="badge badge-{risk_class}">{self._esc(risk_level)}</span></td>
                </tr>
                '''
            
            users_html += '</tbody></table>'
            
            if len(users) > 50:
                users_html += f'<p class="muted">Showing 50 of {len(users)} users</p>'
        else:
            users_html = '<p><em>No user data available</em></p>'

        # ── Per-user timelines ────────────────────────────────────────────────
        rankable_users = [u for u in users if u.get("rankable")]
        rankable_users.sort(key=lambda u: (
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(u.get("risk_label"), 3),
            u.get("rank") or 999,
        ))
        if rankable_users:
            timelines_html = "".join(self._render_user_detail(u) for u in rankable_users)
        else:
            timelines_html = "<p><em>No rankable user data available</em></p>"

        # ── Full HTML document ────────────────────────────────────────────────
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{self.title}</title>
<style>
  :root {{
    --navy:#1a2744; --blue:#2563eb; --teal:#0f766e; --red:#dc2626;
    --amber:#b45309; --green:#166534; --gray:#374151; --border:#d1d5db;
    --bg:#f6f7f9; --card:#ffffff;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ margin:0; font-family:'Segoe UI',Arial,sans-serif; background:var(--bg);
         color:#111827; font-size:14px; line-height:1.5; }}
  header {{ background:var(--navy); color:#fff; padding:24px 32px; }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  header .sub {{ color:#9db2d9; font-size:13px; }}
  main {{ max-width:1100px; margin:0 auto; padding:24px 32px 64px; }}
  section {{ background:var(--card); border:1px solid var(--border); border-radius:8px;
             padding:20px 24px; margin-bottom:24px; }}
  h2 {{ margin:0 0 12px; font-size:17px; color:var(--navy);
        border-bottom:2px solid var(--blue); padding-bottom:6px; }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin: 16px 0;
  }}
  .stat-card {{
    background:#f8f9fa; padding:12px; border-radius:8px;
    text-align:center; border-left:4px solid var(--blue);
  }}
  .stat-value {{ font-size:24px; font-weight:bold; color:var(--navy); }}
  .stat-label {{ color:#6b7280; font-size:12px; margin-top:4px; }}
  
  .tbl {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .tbl th {{ background:var(--navy); color:#fff; padding:7px 10px; text-align:left;
             font-weight:600; font-size:12px; }}
  .tbl td {{ padding:7px 10px; border-bottom:1px solid #e5e7eb; }}
  .tbl tbody tr:nth-child(even) {{ background:#fafbfc; }}
  .tbl tbody tr:hover {{ background:#f0f7ff; }}
  .r {{ text-align:right; }}
  .muted {{ color:#6b7280; font-size:12px; }}
  
  .badge {{ display:inline-block; padding:2px 10px; border-radius:12px;
            font-size:11px; font-weight:700; letter-spacing:.5px; }}
  .badge-high {{ background:#fee2e2; color:var(--red); border:1px solid var(--red); }}
  .badge-medium {{ background:#fef3c7; color:var(--amber); border:1px solid var(--amber); }}
  .badge-low {{ background:#f0fdf4; color:var(--green); border:1px solid #86efac; }}
  .badge-none {{ background:#f3f4f6; color:#6b7280; border:1px solid #d1d5db; }}
  
  .risk-score {{ font-weight:bold; padding:2px 10px; border-radius:4px; }}
  .risk-high {{ background:#fee2e2; color:var(--red); }}
  .risk-medium {{ background:#fef3c7; color:var(--amber); }}
  .risk-low {{ background:#f0fdf4; color:var(--green); }}
  .risk-none {{ background:#f3f4f6; color:#6b7280; }}
  
  .anomaly, .threat {{ padding:14px 16px; margin:10px 0; border-radius:6px;
                        border-left:4px solid #d1d5db; background:#fafbfc; }}
  .severity-high {{ border-left-color:var(--red); background:#fef2f2; }}
  .severity-medium {{ border-left-color:var(--amber); background:#fef9e7; }}
  .severity-low {{ border-left-color:var(--green); background:#f0faf4; }}
  
  .anomaly-header, .threat-header {{
    display:flex; justify-content:space-between; align-items:center;
    margin-bottom:6px;
  }}
  .anomaly-meta {{ margin-top:8px; color:#6b7280; font-size:12px; }}
  .anomaly-meta small {{ margin-right:16px; }}
  
  .section-desc {{ color:#6b7280; margin-bottom:12px; font-size:13px; }}

  .user-detail {{ border:1px solid var(--border); border-radius:6px; margin-bottom:10px;
                   background:#fafbfc; overflow:hidden; }}
  .user-detail summary {{ cursor:pointer; list-style:none; padding:10px 14px;
                           display:flex; align-items:center; gap:10px; }}
  .user-detail summary::-webkit-details-marker {{ display:none; }}
  .user-detail summary::before {{ content:"▸"; color:#6b7280; }}
  .user-detail[open] summary::before {{ content:"▾"; }}
  .user-detail-body {{ padding:4px 16px 16px; border-top:1px solid var(--border); }}
  .user-detail-body h4 {{ margin:14px 0 6px; font-size:13px; color:var(--navy); }}
  .breakdown {{ margin-bottom:6px; }}

  .timeline {{ list-style:none; margin:0; padding:0; border-left:2px solid var(--border);
               margin-left:6px; }}
  .tl-item {{ position:relative; padding:6px 0 6px 18px; font-size:13px;
              display:flex; flex-wrap:wrap; gap:8px; align-items:baseline; }}
  .tl-item::before {{ content:""; position:absolute; left:-6px; top:12px;
                       width:9px; height:9px; border-radius:50%; background:var(--blue); }}
  .tl-icon {{ font-size:13px; }}
  .tl-time {{ font-family:monospace; color:#374151; font-size:12px; white-space:nowrap; }}
  .tl-cat {{ font-weight:600; color:var(--navy); font-size:12px; }}
  .tl-desc {{ color:#111827; flex:1 1 260px; }}

  .footer {{ margin-top:40px; padding-top:20px; border-top:2px solid #e5e7eb;
             text-align:center; color:#9ca3af; font-size:12px; }}
  
  @media print {{
    body {{ background:white; padding:0; }}
    section {{ box-shadow:none; border:1px solid #ddd; }}
    .stat-card {{ border-left-color:#333; }}
  }}
</style>
</head>
<body>
<header>
  <h1>🔍 {self.title}</h1>
  <div class="sub">Generated: {gen_at}</div>
</header>
<main>
  <section>
    <h2>Executive Summary</h2>
    <div class="summary-grid">{stats_html}</div>
  </section>

  <section>
    <h2>Threats Detected</h2>
    <p class="section-desc">Potential security threats identified in the analysis.</p>
    {threats_html}
  </section>

  <section>
    <h2>Anomalies</h2>
    <p class="section-desc">Unusual patterns and anomalies detected.</p>
    {anomalies_html}
  </section>

  <section>
    <h2>User Activity Analysis</h2>
    <p class="section-desc">Risk scores and activity summary for each user.</p>
    {users_html}
  </section>

  <section>
    <h2>Investigation Timelines</h2>
    <p class="section-desc">
      Score breakdown and chronological activity timeline per user — this is the
      evidence trail behind each risk label. HIGH/MEDIUM users are expanded by default.
    </p>
    {timelines_html}
  </section>

  <div class="footer">
    {self.title} | Generated with Forensic Profiler v1.0 | {gen_at}
  </div>
</main>
</body>
</html>'''
        
        return html