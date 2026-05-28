#!/usr/bin/env python3
"""
ttp_profiler.py - Module 0x0F Capstone: Threat Profiling
========================================================
Ingests one or more AIH-C IOC JSON files, maps observations to MITRE ATT&CK
Enterprise Reconnaissance/Resource Development techniques, computes confidence,
and emits JSON or Markdown actor profiles.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone


TECHNIQUE_RULES = {
    "domain": {"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development"},
    "ip": {"id": "T1583.004", "name": "Acquire Infrastructure: Server", "tactic": "Resource Development"},
    "url": {"id": "T1583.006", "name": "Acquire Infrastructure: Web Services", "tactic": "Resource Development"},
    "jarm": {"id": "T1588.004", "name": "Obtain Capabilities: Digital Certificates", "tactic": "Resource Development"},
    "cve": {"id": "T1588.006", "name": "Obtain Capabilities: Vulnerabilities", "tactic": "Resource Development"},
    "wallet": {"id": "T1657", "name": "Financial Theft", "tactic": "Impact"},
}

CONTEXT_RULES = [
    ("public_listing", True, {"id": "T1583.006", "name": "Acquire Infrastructure: Web Services", "tactic": "Resource Development"}),
    ("service", "API Gateway", {"id": "T1583.006", "name": "Acquire Infrastructure: Web Services", "tactic": "Resource Development"}),
    ("role", "c2", {"id": "T1584.004", "name": "Compromise Infrastructure: Server", "tactic": "Resource Development"}),
    ("classification", "scanner", {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}),
]


@dataclass
class Profile:
    actor_id: str
    generated_at: str
    indicator_count: int
    source_modules: list[str]
    techniques: list[dict]
    confidence: str
    evidence_summary: dict
    next_hunts: list[str]


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_inputs(patterns: list[str]) -> tuple[list[dict], list[str]]:
    if not patterns and not sys.stdin.isatty():
        stdin_data = sys.stdin.read().strip()
        if stdin_data:
            data = json.loads(stdin_data)
            return data.get("indicators", []), [data.get("metadata", {}).get("source_module", "stdin")]

    indicators: list[dict] = []
    modules: list[str] = []
    if not patterns:
        return (
            [
                {"type": "domain", "value": "mock-c2.example.com", "context": {"role": "c2"}},
                {"type": "ip", "value": "203.0.113.15", "context": {"classification": "scanner"}},
                {"type": "wallet", "value": "bc1q_actor", "context": {"confidence": "medium"}},
            ],
            ["mock"],
        )

    files: list[str] = []
    for pattern in patterns:
        matches = glob.glob(pattern)
        files.extend(matches or [pattern])

    for path in files:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        modules.append(data.get("metadata", {}).get("source_module", "unknown"))
        indicators.extend(data.get("indicators", []))
    return indicators, sorted(set(modules))


def context_lookup(context: dict, key: str):
    if key in context:
        return context[key]
    for value in context.values():
        if isinstance(value, dict) and key in value:
            return value[key]
    return None


def map_techniques(indicators: list[dict]) -> list[dict]:
    mapped: dict[str, dict] = {}
    evidence: defaultdict[str, list[str]] = defaultdict(list)
    for item in indicators:
        base = TECHNIQUE_RULES.get(item.get("type"))
        if base:
            mapped[base["id"]] = dict(base)
            evidence[base["id"]].append(item.get("value", "unknown"))

        context = item.get("context", {}) or {}
        for key, expected, technique in CONTEXT_RULES:
            value = context_lookup(context, key)
            matched = value == expected or (isinstance(value, str) and isinstance(expected, str) and expected in value)
            if matched:
                mapped[technique["id"]] = dict(technique)
                evidence[technique["id"]].append(item.get("value", "unknown"))

    techniques = []
    for technique_id, technique in mapped.items():
        technique["evidence_count"] = len(set(evidence[technique_id]))
        technique["sample_evidence"] = sorted(set(evidence[technique_id]))[:5]
        techniques.append(technique)
    return sorted(techniques, key=lambda item: (-item["evidence_count"], item["id"]))


def compute_confidence(indicators: list[dict], techniques: list[dict], modules: list[str]) -> str:
    if len(modules) >= 3 and len(techniques) >= 3 and len(indicators) >= 5:
        return "high"
    if len(techniques) >= 2 or len(indicators) >= 3:
        return "medium"
    return "low"


def build_profile(indicators: list[dict], modules: list[str], actor_id: str) -> Profile:
    techniques = map_techniques(indicators)
    type_counts = Counter(item.get("type", "unknown") for item in indicators)
    role_counts = Counter((item.get("context") or {}).get("role", "unknown") for item in indicators)
    next_hunts = [
        "Pivot domains through CT logs and passive DNS",
        "Convert high-confidence techniques into Sigma/EDR hunts",
        "Review weak pivots before making attribution claims",
    ]
    return Profile(
        actor_id=actor_id,
        generated_at=now_utc(),
        indicator_count=len(indicators),
        source_modules=modules,
        techniques=techniques,
        confidence=compute_confidence(indicators, techniques, modules),
        evidence_summary={"indicator_types": dict(type_counts), "roles": dict(role_counts)},
        next_hunts=next_hunts,
    )


def markdown(profile: Profile) -> str:
    lines = [
        f"# Actor Profile: {profile.actor_id}",
        "",
        f"- Generated: {profile.generated_at}",
        f"- Confidence: {profile.confidence}",
        f"- Indicators: {profile.indicator_count}",
        f"- Source modules: {', '.join(profile.source_modules)}",
        "",
        "## Technique Mapping",
        "",
        "| Technique | Tactic | Evidence |",
        "|---|---|---:|",
    ]
    for technique in profile.techniques:
        lines.append(f"| {technique['id']} {technique['name']} | {technique['tactic']} | {technique['evidence_count']} |")
    lines.extend(["", "## Next Hunts", ""])
    lines.extend(f"- {hunt}" for hunt in profile.next_hunts)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="AIH-C actor TTP profiler")
    parser.add_argument("-i", "--input", action="append", help="AIH-C IOC JSON file or glob. Repeatable.")
    parser.add_argument("--actor-id", default="UNKNOWN_ACTOR")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    indicators, modules = load_inputs(args.input or [])
    profile = build_profile(indicators, modules, args.actor_id)
    if args.format == "markdown":
        print(markdown(profile))
        return
    print(json.dumps(profile.__dict__, indent=2))


if __name__ == "__main__":
    main()
