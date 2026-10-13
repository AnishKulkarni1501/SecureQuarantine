"""Ablation evaluation helpers for family-split benchmark JSONL datasets.

Each record must carry a split assigned outside this script (train/test) and a
family key. Scores here are research baselines, not production probabilities.
"""
from collections import defaultdict


def predict(record: dict, experiment: str) -> tuple[float, str]:
    static = min(0.75, 0.25 * int(record.get("static_hits", 0)))
    runtime = min(0.55, 0.25 * len(set(record.get("runtime_event_types", [])))) if experiment in {"B", "D"} else 0.0
    ai = min(0.2, 0.05 * int(record.get("supported_ai_capabilities", 0))) if experiment in {"C", "D"} else 0.0
    score = min(1.0, static + runtime + ai)
    required = {"A": ("static_complete",), "B": ("static_complete", "dynamic_complete"), "C": ("static_complete", "ai_complete"), "D": ("static_complete", "dynamic_complete", "ai_complete")}[experiment]
    if not all(record.get(stage, False) for stage in required):
        return score, "analyze_further"
    return score, "quarantine" if score >= 0.8 else "human_review" if score >= 0.15 else "release"


def evaluate(records: list[dict], experiment: str) -> dict:
    tp = fp = fn = tn = reviews = 0
    scores = []
    for row in records:
        score, action = predict(row, experiment)
        actual = row["label"] == "malicious"
        reviews += int(action in {"human_review", "analyze_further"})
        if action in {"human_review", "analyze_further"}:
            continue
        predicted = action == "quarantine"
        tp += int(predicted and actual)
        fp += int(predicted and not actual)
        fn += int(not predicted and actual)
        tn += int(not predicted and not actual)
        scores.append(score)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"experiment": experiment, "n": len(records), "auto_decided": tp + fp + fn + tn, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "false_positive_rate": fp / (fp + tn) if fp + tn else None, "false_negative_rate": fn / (fn + tp) if fn + tp else None, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision and recall and precision + recall else 0.0, "review_or_incomplete_count": reviews, "mean_latency_ms": sum(float(row.get("latency_ms", 0)) for row in records) / len(records) if records else None}


def run_ablation(records: list[dict]) -> dict:
    if any(r.get("split") != "test" for r in records):
        raise ValueError("Only records explicitly marked split='test' belong in reported test metrics")
    families = defaultdict(set)
    for row in records:
        if not row.get("family") or row.get("label") not in {"benign", "malicious"}:
            raise ValueError("Each record requires family and benign/malicious label fields")
        families[row["family"]].add(row["label"])
    return {"test_families": len(families), "test_records": len(records), "metrics": [evaluate(records, name) for name in "ABCD"], "caveat": "Heuristic ablation scaffold. The caller must create family-disjoint train/test splits and calibrate on a separate validation set."}
