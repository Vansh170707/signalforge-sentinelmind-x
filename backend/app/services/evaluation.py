"""Ground-truth evaluation (blueprint section 28). Every number is computed; nothing is hard-coded."""

from __future__ import annotations

from collections import Counter, defaultdict
from math import comb
from typing import Any

PRIORITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def correlation_metrics(pred: dict[str, str], truth: dict[str, str]) -> dict[str, Any]:
    """pred/truth: alert_id -> incident id. Evaluated on alerts present in both."""
    ids = [a for a in pred if a in truth]
    if not ids:
        return {}
    cont: Counter[tuple[str, str]] = Counter((pred[a], truth[a]) for a in ids)
    pred_sizes: Counter[str] = Counter(pred[a] for a in ids)
    true_sizes: Counter[str] = Counter(truth[a] for a in ids)
    tp = sum(comb(n, 2) for n in cont.values())
    pp = sum(comb(n, 2) for n in pred_sizes.values())
    tpairs = sum(comb(n, 2) for n in true_sizes.values())
    precision = tp / pp if pp else 1.0
    recall = tp / tpairs if tpairs else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    by_pred: dict[str, Counter[str]] = defaultdict(Counter)
    by_true: dict[str, Counter[str]] = defaultdict(Counter)
    for (p, t), n in cont.items():
        by_pred[p][t] += n
        by_true[t][p] += n
    purity = sum(max(c.values()) for c in by_pred.values()) / len(ids)
    multi_pred = [p for p, s in pred_sizes.items() if s > 1]
    over_merged = [p for p in multi_pred if len(by_pred[p]) > 1]
    multi_true = [t for t, s in true_sizes.items() if s > 1]
    split = [t for t in multi_true if len(by_true[t]) > 1]
    return {
        "alerts_evaluated": len(ids),
        "generated_incidents": len(pred_sizes),
        "ground_truth_incidents": len(true_sizes),
        "pairwise_precision": round(precision, 4),
        "pairwise_recall": round(recall, 4),
        "pairwise_f1": round(f1, 4),
        "incident_purity": round(purity, 4),
        "over_merge_rate": round(len(over_merged) / len(multi_pred), 4) if multi_pred else 0.0,
        "split_rate": round(len(split) / len(multi_true), 4) if multi_true else 0.0,
        "singleton_rate": round(sum(1 for s in pred_sizes.values() if s == 1) / len(pred_sizes), 4),
        "compression_ratio": round(len(ids) / len(pred_sizes), 2),
    }


def dominant_truth(pred: dict[str, str], truth: dict[str, str]) -> dict[str, tuple[str, float]]:
    """generated incident -> (dominant ground-truth incident, share of alerts)."""
    groups: dict[str, Counter[str]] = defaultdict(Counter)
    for a, p in pred.items():
        if a in truth:
            groups[p][truth[a]] += 1
    out = {}
    for p, c in groups.items():
        t, n = c.most_common(1)[0]
        out[p] = (t, n / sum(c.values()))
    return out


def priority_metrics(ranked_incidents: list[dict[str, Any]], pred: dict[str, str], truth: dict[str, str],
                     gt_incidents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """ranked_incidents: generated incidents sorted by risk desc, each with incident_id + severity.

    A ground-truth incident is 'found at rank r' at the best rank of a generated incident whose dominant
    ground truth is that incident.
    """
    dom = dominant_truth(pred, truth)
    best_rank: dict[str, int] = {}
    for r, inc in enumerate(ranked_incidents, start=1):
        t = dom.get(inc["incident_id"], (None, 0))[0]
        if t and t not in best_rank:
            best_rank[t] = r
    critical = [t for t, v in gt_incidents.items() if v.get("priority") == "critical"]
    high_crit = [t for t, v in gt_incidents.items() if v.get("priority") in ("high", "critical")]
    top3 = sum(1 for t in critical if best_rank.get(t, 10**9) <= 3)
    top5 = sum(1 for t in high_crit if best_rank.get(t, 10**9) <= 5)
    benign_ids = {p for p, (t, _) in dom.items() if not gt_incidents.get(t, {}).get("malicious")}
    benign_ranked = [inc for inc in ranked_incidents if inc["incident_id"] in benign_ids]
    false_high = [inc for inc in benign_ranked if inc["severity"] in ("high", "critical")]
    planted = []
    for t, v in gt_incidents.items():
        if v.get("malicious") or v.get("scenario") == "benign_maintenance_critical_server":
            planted.append({
                "ground_truth_incident_id": t,
                "scenario": v.get("scenario"),
                "expected_priority": v.get("priority"),
                "malicious": v.get("malicious"),
                "rank": best_rank.get(t),
            })
    planted.sort(key=lambda x: x["rank"] or 10**9)
    return {
        "top3_critical_recall": round(top3 / len(critical), 4) if critical else None,
        "top5_high_critical_recall": round(top5 / min(5, len(high_crit)), 4) if high_crit else None,
        "false_high_rate": round(len(false_high) / len(benign_ranked), 4) if benign_ranked else 0.0,
        "false_high_count": len(false_high),
        "benign_incidents": len(benign_ranked),
        "planted_incident_ranks": planted,
    }


def detection_metrics(scores: dict[str, float], truth: dict[str, str], gt_incidents: dict[str, dict[str, Any]],
                      threshold: float) -> dict[str, Any]:
    """Alert-level detection quality of a 0..1 score against malicious labels."""
    tp = fp = fn = tn = 0
    for a, s in scores.items():
        t = truth.get(a)
        if t is None:
            continue
        mal = bool(gt_incidents.get(t, {}).get("malicious"))
        flagged = s >= threshold
        if flagged and mal:
            tp += 1
        elif flagged and not mal:
            fp += 1
        elif not flagged and mal:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"threshold": threshold, "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
