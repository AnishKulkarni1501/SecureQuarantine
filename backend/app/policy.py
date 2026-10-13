"""Transparent conservative baseline. Scores are heuristics, not probabilities."""
from collections.abc import Iterable


def correlate(findings: Iterable, functions: Iterable, events: Iterable) -> dict:
    static = {(item.get("kind") if isinstance(item, dict) else item.kind) for item in findings}
    inferred = {cap.lower() for fn in functions for cap in ((fn.get("capabilities") if isinstance(fn, dict) else fn.capabilities) or [])}
    observed = {(event.get("event_type") if isinstance(event, dict) else event.event_type).lower() for event in events}
    links: list[dict] = []
    rules = {
        "network": ("network_api", "network"),
        "persistence": ("persistence_hint", "registry"),
        "process_injection": ("process_injection_hint", "process"),
    }
    for capability, (static_kind, event_kind) in rules.items():
        has_static = static_kind in static
        has_ai = any(capability in item for item in inferred)
        has_observed = event_kind in observed
        if has_static or has_ai or has_observed:
            links.append({"capability": capability, "static_support": has_static, "inferred_support": has_ai, "runtime_observed": has_observed, "relationship": "corroborated" if has_observed and (has_ai or has_static) else "runtime_only" if has_observed else "inferred_or_static_only"})
    return {"links": links, "contradictions": [], "untested_hypotheses": [link["capability"] for link in links if not link["runtime_observed"]], "observed_events": len(list(events))}


def assess_risk(findings: Iterable, functions: Iterable, events: Iterable, completeness: str, stage_status: dict) -> dict:
    findings = list(findings)
    functions = list(functions)
    events = list(events)
    # Evidence-weighted heuristic on a 0..1 scale, deliberately not presented
    # as a calibrated probability. AI self-reported confidence is excluded.
    static_weight = min(0.75, sum(0.25 for f in findings if (f.get("source") if isinstance(f, dict) else f.source) in {"static_strings", "static_imports"}))
    observed_weight = min(0.55, 0.25 * len({e.event_type for e in events}))
    supported_ai_weight = min(0.20, 0.05 * sum(bool(f.get("capabilities") if isinstance(f, dict) else f.capabilities) for f in functions))
    score = round(min(1.0, static_weight + observed_weight + supported_ai_weight), 2)
    missing = any(state in {"failed", "not_configured", "incomplete"} for stage, state in stage_status.items() if stage != "static")
    if missing or completeness != "complete":
        action = "human_review" if score >= 0.5 else "analyze_further"
    else:
        action = "quarantine" if score >= 0.8 else "human_review" if score >= 0.5 else "release" if score < 0.15 else "analyze_further"
    return {"score": score, "score_type": "heuristic_not_probability", "recommendation": action, "completeness": completeness, "missing_stages": [name for name, state in stage_status.items() if state in {"failed", "not_configured", "incomplete"}], "basis": {"static_indicator_contribution": static_weight, "runtime_event_contribution": observed_weight, "AI_capability_contribution": supported_ai_weight}}
