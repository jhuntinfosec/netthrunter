#!/usr/bin/env python3
"""
detection_pack_builder.py - Module 0x10 Capstone
Generates Sigma-like rules and OCSF-style example events from AIH-C findings.
"""

from __future__ import annotations

import argparse
import glob
import json
from datetime import datetime, timezone


DEFAULT_FINDINGS = {
    "metadata": {"source_module": "demo", "generated_at": "2026-05-28T00:00:00Z"},
    "indicators": [
        {"type": "domain", "value": "malicious-update.s3.amazonaws.com", "context": {"role": "stager", "service": "S3 object storage"}},
        {"type": "ip", "value": "203.0.113.15", "context": {"classification": "scanner", "paths": ["/.env", "/config.json"]}},
        {"type": "url", "value": "https://api-id.execute-api.us-east-1.amazonaws.com/login", "context": {"role": "redirector"}},
    ],
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_findings(patterns: list[str]) -> list[dict]:
    if not patterns:
        return DEFAULT_FINDINGS["indicators"]
    indicators: list[dict] = []
    for pattern in patterns:
        for path in glob.glob(pattern) or [pattern]:
            with open(path, encoding="utf-8") as handle:
                indicators.extend(json.load(handle).get("indicators", []))
    return indicators


def sigma_rule(indicator: dict, index: int) -> dict:
    value = indicator.get("value", "")
    kind = indicator.get("type", "unknown")
    context = indicator.get("context", {}) or {}
    title = f"AIH-C Infrastructure Lead {kind.upper()} {index}"
    field = {
        "ip": "destination.ip",
        "domain": "dns.question.name",
        "url": "url.full",
        "wallet": "threat.indicator.name",
        "cve": "vulnerability.id",
    }.get(kind, "threat.indicator.name")
    tags = ["attack.resource_development"]
    if context.get("classification") == "scanner":
        tags = ["attack.reconnaissance", "attack.t1595"]
    elif context.get("role") in {"stager", "redirector"}:
        tags.append("attack.t1583.006")
    return {
        "title": title,
        "id": f"aih-c-{index:04d}",
        "status": "experimental",
        "description": f"Detects telemetry referencing {value} from AIH-C infrastructure hunting.",
        "logsource": {"category": "network"},
        "detection": {"selection": {field: value}, "condition": "selection"},
        "falsepositives": ["Shared cloud/CDN infrastructure", "Security research traffic", "Internal testing"],
        "level": "medium",
        "tags": tags,
    }


def render_yaml(obj: dict, indent: int = 0) -> str:
    lines: list[str] = []
    pad = " " * indent
    for key, value in obj.items():
        if isinstance(value, dict):
            lines.append(f"{pad}{key}:")
            lines.append(render_yaml(value, indent + 2))
        elif isinstance(value, list):
            lines.append(f"{pad}{key}:")
            for item in value:
                lines.append(f"{pad}  - {item}")
        else:
            text = str(value).replace("'", "''")
            lines.append(f"{pad}{key}: '{text}'")
    return "\n".join(lines)


def ocsf_event(indicator: dict) -> dict:
    return {
        "activity_name": "Threat Intelligence Indicator Match",
        "category_name": "Findings",
        "class_name": "Detection Finding",
        "time": now_utc(),
        "severity": "Medium",
        "metadata": {"product": {"name": "AIH-C Detection Pack Builder"}},
        "observable": {"type": indicator.get("type"), "value": indicator.get("value")},
        "enrichment": indicator.get("context", {}),
    }


def build_pack(indicators: list[dict]) -> dict:
    rules = [sigma_rule(item, idx + 1) for idx, item in enumerate(indicators)]
    return {
        "metadata": {"source_module": "0x10_detection_pack", "generated_at": now_utc()},
        "sigma_rules": rules,
        "ocsf_examples": [ocsf_event(item) for item in indicators],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build detection packs from AIH-C findings")
    parser.add_argument("-i", "--input", action="append", help="AIH-C JSON file or glob. Repeatable.")
    parser.add_argument("--format", choices=["json", "sigma"], default="json")
    args = parser.parse_args()

    pack = build_pack(load_findings(args.input or []))
    if args.format == "sigma":
        for rule in pack["sigma_rules"]:
            print("---")
            print(render_yaml(rule))
        return
    print(json.dumps(pack, indent=2))


if __name__ == "__main__":
    main()
