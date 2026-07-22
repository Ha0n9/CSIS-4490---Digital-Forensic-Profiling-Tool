#!/usr/bin/env python3
"""
Investigation Narrative Generator

Turns a single already-correlated/scored user record (one entry of
correlation_results.json's "user_correlations") into an investigator-oriented
narrative: a phased evidence chain, a plain-language summary, a confidence
rating and analyst notes.

Rules:
  - Consumes correlation output only — never re-reads raw artifact JSON and
    never re-runs any scoring in correlation/engine.py.
  - Fully offline/deterministic: no network calls, no LLMs, no randomness,
    no wall-clock reads. The same input always produces the same output.
  - Every phase, count and time range is read straight out of the evidence
    already attached to the user record. Nothing about intent is invented —
    language stays hedged ("indicates", "may indicate", "is consistent
    with", "requires further investigation").
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# How far apart two timestamps in the same evidence category can be before
# they're treated as separate activity bursts, when reporting whether a
# phase happened as one cluster or several.
_CLUSTER_GAP = timedelta(minutes=60)

# Per-category (ts_field, phase_key) — mirrors the "evidence" dict shape
# produced by CorrelationEngine.calculate_aggregate(). Kept local rather than
# imported from reporting.html_report's TIMELINE_SPECS: correlation/ must not
# depend on reporting/ (dependency runs the other way).
_TS_FIELD = {
    "deleted_files": "deleted_at",
    "event_anomalies": "timestamp",
    "network_activity": "timestamp",
    "browser_history": "visited",
    "app_activity": "last_run",
    "document_access": "accessed_at",
}

# timeline_patterns keys (from CorrelationEngine.calculate_timeline_bonuses)
# that corroborate a behavior across two independent evidence categories,
# as opposed to a single-category timing cluster. Used to grade confidence.
_CROSS_CATEGORY_PATTERNS = {
    "file_access_then_deletion",
    "app_exec_then_network",
    "multi_source_consistency",
}

_PATTERN_SENTENCES = {
    "file_access_then_deletion": (
        "Sensitive file access was followed by deletion within a short "
        "window ({detail}), which is consistent with deliberate cleanup "
        "and requires further investigation."
    ),
    "app_exec_then_network": (
        "Application execution was followed by network activity "
        "({detail}), suggesting the executed tool may have been used to "
        "establish an outbound connection."
    ),
    "activity_then_log_gap": (
        "A burst of activity was followed by a gap in logged events "
        "({detail}), which may indicate log clearing, system downtime, or "
        "an attempt to obscure subsequent actions and warrants further "
        "review."
    ),
    "rapid_actions": (
        "A burst of rapid, closely-timed actions was detected "
        "({detail}), a pattern more consistent with scripted or automated "
        "activity than routine manual use."
    ),
    "multi_source_consistency": (
        "Multiple independent artifact types were active within the same "
        "short window ({detail}), corroborating that this activity is "
        "attributable to a single session rather than coincidental "
        "overlap."
    ),
}

_MAX_SUPPORTING_EVENTS = 10


def _parse_ts(ts: Any) -> Optional[datetime]:
    """Best-effort parse of a correlation-output timestamp string, or None."""
    if not ts:
        return None
    s = str(ts).strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _dated(evidence: List[Dict], ts_field: str) -> List[Tuple[datetime, Dict]]:
    """(timestamp, item) pairs for evidence with a parseable timestamp, sorted."""
    out = []
    for item in evidence:
        ts = _parse_ts(item.get(ts_field))
        if ts:
            out.append((ts, item))
    out.sort(key=lambda p: p[0])
    return out


def _clusters(times: List[datetime], gap: timedelta = _CLUSTER_GAP) -> int:
    """Number of activity bursts in a sorted timestamp list, split on `gap`."""
    if not times:
        return 0
    count = 1
    for prev, cur in zip(times, times[1:]):
        if cur - prev > gap:
            count += 1
    return count


def _time_range_str(times: List[datetime]) -> str:
    if not times:
        return "unknown"
    lo, hi = times[0], times[-1]
    if lo.date() == hi.date():
        if lo == hi:
            return lo.strftime("%Y-%m-%d %H:%M")
        return f"{lo.strftime('%Y-%m-%d %H:%M')} to {hi.strftime('%H:%M')}"
    return f"{lo.strftime('%Y-%m-%d')} to {hi.strftime('%Y-%m-%d')}"


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _phase_confidence(count: int, cluster_count: int, cross_category_hit: bool) -> str:
    if cross_category_hit and count >= 2:
        return "HIGH"
    if count >= 3 or (count >= 2 and cluster_count == 1):
        return "MEDIUM"
    return "LOW"


def _build_phase(
    phase: str,
    dated_items: List[Tuple[datetime, Dict]],
    description: str,
    assessment: str,
    cross_category_hit: bool = False,
) -> Optional[Dict[str, Any]]:
    if not dated_items:
        return None
    times = [t for t, _ in dated_items]
    events = [e for _, e in dated_items][:_MAX_SUPPORTING_EVENTS]
    cluster_count = _clusters(times)
    return {
        "phase": phase,
        "time_range": _time_range_str(times),
        "description": description,
        "assessment": assessment,
        "confidence": _phase_confidence(len(dated_items), cluster_count, cross_category_hit),
        "supporting_events": events,
    }


def _phase_initial_suspicious(evidence: Dict, patterns: set) -> Optional[Dict]:
    items = [
        e for e in evidence.get("event_anomalies", [])
        if e.get("label") != "privilege_escalation"
    ]
    dated = _dated(items, _TS_FIELD["event_anomalies"])
    if not dated:
        return None
    labels = sorted({e.get("label", "unknown").replace("_", " ") for _, e in dated})
    description = (
        f"{_plural(len(dated), 'anomalous account event')} were observed "
        f"({', '.join(labels)}), preceding the account's more targeted activity."
    )
    assessment = (
        "This activity is consistent with the opening stage of the observed "
        "evidence chain and indicates the account's behavior warrants closer "
        "review from this point forward."
    )
    return _build_phase("Initial Suspicious Activity", dated, description, assessment)


def _phase_privileged(evidence: Dict, patterns: set) -> Optional[Dict]:
    items = [e for e in evidence.get("event_anomalies", []) if e.get("label") == "privilege_escalation"]
    dated = _dated(items, _TS_FIELD["event_anomalies"])
    if not dated:
        return None
    ids = sorted({str(e.get("event_id", "?")) for _, e in dated})
    description = (
        f"{_plural(len(dated), 'Event ID ' + '/'.join(ids) + ' privilege escalation event')} "
        f"were observed."
    )
    assessment = "Repeated privileged logon events indicate elevated account usage."
    cluster_count = _clusters([t for t, _ in dated])
    if cluster_count > 1:
        assessment += (
            f" Activity occurred across {cluster_count} distinct time clusters, "
            "consistent with recurring privileged sessions rather than a single "
            "isolated event."
        )
    return _build_phase("Privileged Activity", dated, description, assessment)


def _phase_sensitive_docs(evidence: Dict, patterns: set) -> Optional[Dict]:
    items = evidence.get("document_access", [])
    dated = _dated(items, _TS_FIELD["document_access"])
    if not dated:
        return None
    description = f"{_plural(len(dated), 'sensitive document')} were accessed."
    assessment = "The accessed files require further review."
    cross_hit = "file_access_then_deletion" in patterns
    return _build_phase(
        "Sensitive Data Interaction", dated, description, assessment, cross_category_hit=cross_hit
    )


def _phase_cleanup(evidence: Dict, patterns: set, pattern_details: List[str]) -> Optional[Dict]:
    items = evidence.get("deleted_files", [])
    dated = _dated(items, _TS_FIELD["deleted_files"])
    if not dated:
        return None
    description = f"{_plural(len(dated), 'deleted file')} were recovered."
    cross_hit = "file_access_then_deletion" in patterns
    if cross_hit:
        assessment = (
            "Deletion activity occurring shortly after sensitive file access "
            "is consistent with deliberate cleanup behavior and requires "
            "further investigation."
        )
        if pattern_details:
            assessment += f" Specifically: {pattern_details[0]}"
    else:
        assessment = (
            "Deletion activity following sensitive file access may indicate "
            "cleanup behavior; no direct access-then-deletion timing pattern "
            "was independently confirmed, so this requires further "
            "investigation to establish sequence."
        )
    return _build_phase("Cleanup Activity", dated, description, assessment, cross_category_hit=cross_hit)


def _phase_network_browser(evidence: Dict, patterns: set) -> Optional[Dict]:
    net_items = evidence.get("network_activity", [])
    brw_items = evidence.get("browser_history", [])
    dated = _dated(net_items, _TS_FIELD["network_activity"]) + _dated(brw_items, _TS_FIELD["browser_history"])
    dated.sort(key=lambda p: p[0])
    if not dated:
        return None
    suspicious_tiers = {e.get("tier") for e in net_items if e.get("tier") == "suspicious"}
    flagged_categories = sorted({e.get("category", "flagged") for e in brw_items})
    parts = []
    if net_items:
        parts.append(f"{_plural(len(net_items), 'network connection')}")
    if brw_items:
        cat_str = f" ({', '.join(flagged_categories)})" if flagged_categories else ""
        parts.append(f"{_plural(len(brw_items), 'flagged browser visit')}{cat_str}")
    description = " and ".join(parts) + " were recorded."
    cross_hit = "app_exec_then_network" in patterns
    if suspicious_tiers:
        assessment = (
            "Connections to known suspicious destinations indicate potential "
            "exfiltration or anonymization activity and require further "
            "investigation."
        )
    elif brw_items:
        assessment = (
            "Visits to flagged domains are consistent with reconnaissance, "
            "anonymization, or data-exfiltration research and require "
            "further investigation."
        )
    else:
        assessment = (
            "Network activity is present alongside other evidence and should "
            "be reviewed for context; no destination in this set was flagged "
            "as independently suspicious."
        )
    return _build_phase("Network & Browser Activity", dated, description, assessment, cross_category_hit=cross_hit)


def _phase_account_changes(evidence: Dict, patterns: set) -> Optional[Dict]:
    items = evidence.get("user_accounts", [])
    if not items:
        return None
    flags = sorted({str(e.get("flag", "unknown")).replace("_", " ") for e in items})
    description = f"{_plural(len(items), 'account anomaly flag')} were recorded ({', '.join(flags)})."
    assessment = (
        "Elevated failed-login activity or other account flags may indicate "
        "credential issues or attempted unauthorized access and warrant "
        "review."
    )
    return {
        "phase": "Account Changes",
        "time_range": "n/a",
        "description": description,
        "assessment": assessment,
        "confidence": "MEDIUM" if len(items) > 1 else "LOW",
        "supporting_events": items[:_MAX_SUPPORTING_EVENTS],
    }


def _summary_sentence(phase_names: List[str]) -> str:
    themes = {
        "Initial Suspicious Activity": "irregular account activity",
        "Privileged Activity": "privileged activity",
        "Sensitive Data Interaction": "sensitive document access",
        "Cleanup Activity": "file deletion/cleanup activity",
        "Network & Browser Activity": "network and browser activity involving flagged destinations",
        "Account Changes": "account anomaly flags",
    }
    parts = [themes[p] for p in phase_names if p in themes]
    if not parts:
        return "No correlated evidence chain was identified for this account from the available artifacts."
    if len(parts) == 1:
        return f"The account shows evidence of {parts[0]}."
    if len(parts) == 2:
        return f"The account shows evidence of {parts[0]} combined with {parts[1]}."
    return "The account shows a pattern of " + ", ".join(parts[:-1]) + f", and {parts[-1]}."


def _confidence(user: Dict, evidence_chain: List[Dict], cross_category_hit: bool) -> str:
    if not evidence_chain:
        return "LOW"
    diversity = (user.get("diversity") or {}).get("category_count", 0)
    if diversity >= 3 or (diversity >= 2 and cross_category_hit):
        return "HIGH"
    if diversity >= 2 or cross_category_hit:
        return "MEDIUM"
    return "LOW"


def _analyst_notes(user: Dict, evidence_chain: List[Dict]) -> List[str]:
    notes: List[str] = []
    risk_label = user.get("risk_label") or "LOW"
    final_score = user.get("final_score", 0)
    rationale = user.get("risk_rationale", "")
    notes.append(
        f"Overall risk classification: {risk_label} (score {final_score})"
        + (f" — {rationale}" if rationale else ".")
    )
    for pattern in user.get("timeline_patterns", []) or []:
        key = pattern.get("pattern")
        template = _PATTERN_SENTENCES.get(key)
        if template:
            notes.append(template.format(detail=pattern.get("detail", "")))
    if not evidence_chain:
        notes.append(
            "No correlated evidence chain could be constructed from the "
            "available artifacts for this account."
        )
    return notes


def build_narrative(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build an investigator-oriented narrative from one already-scored
    correlation record (an entry of correlation_results.json's
    "user_correlations"). Pure function of its input — same record always
    produces the same narrative.
    """
    evidence = user.get("evidence", {}) or {}
    patterns = {p.get("pattern") for p in (user.get("timeline_patterns") or [])}
    pattern_details = [
        p.get("detail", "") for p in (user.get("timeline_patterns") or [])
        if p.get("pattern") == "file_access_then_deletion"
    ]

    phase_builders = [
        _phase_initial_suspicious(evidence, patterns),
        _phase_privileged(evidence, patterns),
        _phase_sensitive_docs(evidence, patterns),
        _phase_cleanup(evidence, patterns, pattern_details),
        _phase_network_browser(evidence, patterns),
        _phase_account_changes(evidence, patterns),
    ]
    evidence_chain = [p for p in phase_builders if p]

    cross_category_hit = bool(patterns & _CROSS_CATEGORY_PATTERNS)

    return {
        "user": user.get("display_name") or user.get("username", "unknown"),
        "risk_level": user.get("risk_label") or "LOW",
        "summary": _summary_sentence([p["phase"] for p in evidence_chain]),
        "evidence_chain": evidence_chain,
        "confidence": _confidence(user, evidence_chain, cross_category_hit),
        "analyst_notes": _analyst_notes(user, evidence_chain),
    }
