#!/usr/bin/env python3
"""
correlate_artifacts.py

Full forensic correlation + scoring engine.

Features:
- User attribution (path + SID fallback)
- Artifact scoring (hybrid: normalized + raw boost)
- Timeline correlation (pattern detection)
- Suspicion scoring + ranking
- Evaluation (precision / recall / F1)

Usage:
python3 correlate_artifacts.py --json-dir output/json --output output/scores.json
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime

# =============================================================================
# CONSTANTS
# =============================================================================

WEIGHTS = {
    "deleted_files": 4,
    "event_anomalies": 4,
    "app_activity": 3,
    "network_activity": 3,
    "document_access": 2,
    "browser_history": 1,
    "user_accounts": 1,
}

# =============================================================================
# HELPERS
# =============================================================================

def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except:
        print(f"[!] Failed to load {path}")
        return None


def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except:
        return None


def normalize_username(name):
    return name.strip().lower() if name else "unknown"

# =============================================================================
# USER ATTRIBUTION
# =============================================================================

def _username_from_path(path):
    if not path:
        return None

    m = re.search(r"(?:Users|Documents and Settings)[/\\]([^/\\]+)", path, re.IGNORECASE)

    if m:
        name = m.group(1)

        skip = {
            "all users", "default user", "default", "public",
            "localservice", "networkservice", "systemprofile"
        }

        if name.lower() not in skip:
            return name

    return None


def resolve_username(path, sid=None, sid_map=None):
    uname = _username_from_path(path)

    if not uname and sid and sid_map:
        uname = sid_map.get(sid)

    if not uname:
        uname = "unknown"

    return normalize_username(uname)

# =============================================================================
# SCORING FUNCTIONS
# =============================================================================

def score_deleted_files(data):
    scores = defaultdict(lambda: {"count": 0, "evidence": []})

    if not data:
        return scores

    for rec in data.get("records", []):
        user = resolve_username(rec.get("original_path"), rec.get("sid"))
        scores[user]["count"] += 1
        scores[user]["evidence"].append(rec)

    return scores


def simple_count(data, key_field="username"):
    scores = defaultdict(lambda: {"count": 0, "evidence": []})

    if not data:
        return scores

    for rec in data.get("records", []):
        user = normalize_username(rec.get(key_field, "unknown"))
        scores[user]["count"] += 1
        scores[user]["evidence"].append(rec)

    return scores

# =============================================================================
# TIMELINE BUILDER
# =============================================================================

def _build_user_timeline(user, doc, deleted, app, net, evt):
    events = []

    def add(src, field, etype):
        for r in src.get(user, {}).get("evidence", []):
            ts = parse_ts(r.get(field))
            if ts:
                events.append({"ts": ts, "type": etype})

    add(doc, "timestamp", "document_access")
    add(deleted, "deleted_at", "deleted_file")
    add(app, "last_run", "application_exec")
    add(net, "timestamp", "network_activity")
    add(evt, "timestamp", "event_log")

    events.sort(key=lambda x: x["ts"])
    return events

# =============================================================================
# TIMELINE CORRELATION
# =============================================================================

def calculate_timeline_bonuses(user, doc, deleted, app, net, evt, evt_data):

    timeline = _build_user_timeline(user, doc, deleted, app, net, evt)

    if not timeline:
        return 0, []

    bonus = 0
    patterns = []

    # file access → deletion
    for i in range(len(timeline) - 1):
        a, b = timeline[i], timeline[i+1]
        if a["type"] == "document_access" and b["type"] == "deleted_file":
            if 0 <= (b["ts"] - a["ts"]).total_seconds() <= 300:
                bonus += 5
                patterns.append({"pattern": "file_access_then_delete"})

    # app → network
    for i in range(len(timeline) - 1):
        a, b = timeline[i], timeline[i+1]
        if a["type"] == "application_exec" and b["type"] == "network_activity":
            if 0 <= (b["ts"] - a["ts"]).total_seconds() <= 600:
                bonus += 4
                patterns.append({"pattern": "app_then_network"})

    # rapid actions
    for i in range(len(timeline)):
        window = [e for e in timeline if 0 <= (e["ts"] - timeline[i]["ts"]).total_seconds() <= 60]
        if len(window) >= 5:
            bonus += 3
            patterns.append({"pattern": "rapid_actions"})
            break

    # multi source
    for i in range(len(timeline)):
        window = [e for e in timeline if 0 <= (e["ts"] - timeline[i]["ts"]).total_seconds() <= 300]
        if len(set(e["type"] for e in window)) >= 3:
            bonus += 5
            patterns.append({"pattern": "multi_source"})
            break

    # log gap
    for i in range(len(timeline) - 1):
        gap = (timeline[i+1]["ts"] - timeline[i]["ts"]).total_seconds()
        if gap > 3600:
            bonus += 6
            patterns.append({"pattern": "log_gap"})
            break

    return bonus, patterns

# =============================================================================
# HYBRID SCORING (CORE FIX)
# =============================================================================

def score_component(count, total, weight):
    if total == 0:
        return 0

    normalized = count / total
    raw_boost = min(count / 5, 1) * 0.3  # prevent domination

    return weight * (normalized + raw_boost)

# =============================================================================
# AGGREGATE SCORES
# =============================================================================

def aggregate_scores(users, del_s, app_s, evt_s, net_s, doc_s, brw_s, usr_s, evt_data):

    results = []

    for user in users:

        total_events = (
            del_s.get(user, {}).get("count", 0) +
            app_s.get(user, {}).get("count", 0) +
            evt_s.get(user, {}).get("count", 0) +
            net_s.get(user, {}).get("count", 0) +
            doc_s.get(user, {}).get("count", 0) +
            brw_s.get(user, {}).get("count", 0) +
            usr_s.get(user, {}).get("count", 0)
        )

        del_score = score_component(del_s.get(user, {}).get("count", 0), total_events, WEIGHTS["deleted_files"])
        evt_score = score_component(evt_s.get(user, {}).get("count", 0), total_events, WEIGHTS["event_anomalies"])
        app_score = score_component(app_s.get(user, {}).get("count", 0), total_events, WEIGHTS["app_activity"])
        net_score = score_component(net_s.get(user, {}).get("count", 0), total_events, WEIGHTS["network_activity"])
        doc_score = score_component(doc_s.get(user, {}).get("sensitive_count", 0), total_events, WEIGHTS["document_access"])
        brw_score = score_component(brw_s.get(user, {}).get("flagged_count", 0), total_events, WEIGHTS["browser_history"])
        usr_score = score_component(usr_s.get(user, {}).get("count", 0), total_events, WEIGHTS["user_accounts"])

        artifact_score = del_score + evt_score + app_score + net_score + doc_score + brw_score + usr_score

        bonus, patterns = calculate_timeline_bonuses(
            user, doc_s, del_s, app_s, net_s, evt_s, evt_data
        )

        final_score = artifact_score + bonus

        results.append({
            "user": user,
            "artifact_score": round(artifact_score, 3),
            "timeline_bonus": bonus,
            "final_score": round(final_score, 3),
            "patterns": patterns
        })

    results.sort(key=lambda x: x["final_score"], reverse=True)
    return results

# =============================================================================
# EVALUATION
# =============================================================================

def evaluate_results(results, ground_truth):

    TP = FP = FN = TN = 0

    for r in results:
        user = r["user"]
        predicted = r["final_score"] > 0
        actual = ground_truth.get(user, False)

        if predicted and actual:
            TP += 1
        elif predicted:
            FP += 1
        elif actual:
            FN += 1
        else:
            TN += 1

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return {"precision": precision, "recall": recall, "f1": f1}

# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    print("[*] Loading artifacts...")

    base = args.json_dir

    user_data = load_json(f"{base}/user_accounts.json")
    del_data  = load_json(f"{base}/deleted_files.json")
    evt_data  = load_json(f"{base}/event_logs.json")
    app_data  = load_json(f"{base}/application_activity.json")
    net_data  = load_json(f"{base}/network_activity.json")
    doc_data  = load_json(f"{base}/document_folder_access.json")
    brw_data  = load_json(f"{base}/browser_history.json")

    users = set()

    if user_data:
        for r in user_data.get("records", []):
            users.add(normalize_username(r.get("username")))

    print(f"[*] Found {len(users)} users")

    print("[*] Scoring artifacts...")

    del_scores = score_deleted_files(del_data)
    evt_scores = simple_count(evt_data)
    app_scores = simple_count(app_data)
    net_scores = simple_count(net_data)
    doc_scores = simple_count(doc_data)
    brw_scores = simple_count(brw_data)
    usr_scores = simple_count(user_data)

    print("[*] Correlating and scoring...")

    results = aggregate_scores(
        users,
        del_scores,
        app_scores,
        evt_scores,
        net_scores,
        doc_scores,
        brw_scores,
        usr_scores,
        evt_data
    )

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[✓] Output written → {args.output}")


if __name__ == "__main__":
    main()