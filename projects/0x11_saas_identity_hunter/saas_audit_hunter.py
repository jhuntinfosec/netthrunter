#!/usr/bin/env python3
"""
saas_audit_hunter.py - Module 0x11 Capstone
Scores SaaS/OAuth audit events and extracts infrastructure pivots.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


MOCK_EVENTS = [
    {
        "timestamp": "2026-05-21T13:12:00Z",
        "actor": "admin@example.org",
        "action": "ConsentToApplication",
        "app_name": "Secure Document Viewer",
        "publisher": "Unverified",
        "scopes": ["offline_access", "Mail.ReadWrite", "Files.Read.All"],
        "redirect_uri": "https://login-secure-docs.example.net/oauth/callback",
        "source_ip": "185.220.101.77",
        "user_agent": "Mozilla/5.0",
    },
    {
        "timestamp": "2026-05-21T13:20:00Z",
        "actor": "user@example.org",
        "action": "MailboxRuleCreated",
        "app_name": "Exchange Online",
        "publisher": "Microsoft",
        "scopes": [],
        "redirect_uri": "",
        "source_ip": "203.0.113.50",
        "user_agent": "Outlook",
    },
]

HIGH_RISK_SCOPES = {"offline_access", "Mail.ReadWrite", "Files.Read.All", "Directory.ReadWrite.All"}
DOMAIN_RE = re.compile(r"https?://([^/]+)")


@dataclass
class SaaSFinding:
    app_name: str
    action: str
    risk_score: int
    confidence: str
    infrastructure_pivots: list[str]
    evidence: list[str]
    event: dict


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_events(path: str | None) -> list[dict]:
    if not path:
        return MOCK_EVENTS
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, list) else data.get("events", [])


def domain_from_url(url: str) -> str | None:
    match = DOMAIN_RE.match(url or "")
    return match.group(1).lower() if match else None


def score_event(event: dict) -> SaaSFinding:
    evidence: list[str] = []
    risk = 10
    scopes = set(event.get("scopes", []))
    risky_scopes = sorted(scopes & HIGH_RISK_SCOPES)
    if risky_scopes:
        risk += 15 * len(risky_scopes)
        evidence.append(f"High-risk OAuth scopes: {', '.join(risky_scopes)}")
    if event.get("publisher", "").lower() == "unverified":
        risk += 20
        evidence.append("Publisher is unverified")
    if event.get("action") == "ConsentToApplication":
        risk += 15
        evidence.append("OAuth application consent event")
    if event.get("source_ip", "").startswith("185.220."):
        risk += 15
        evidence.append("Source IP resembles proxy/Tor training range")

    pivots = []
    redirect_domain = domain_from_url(event.get("redirect_uri", ""))
    if redirect_domain:
        pivots.append(redirect_domain)
        evidence.append("Redirect URI domain extracted")
    confidence = "high" if risk >= 75 else "medium" if risk >= 45 else "low"
    return SaaSFinding(event.get("app_name", "unknown"), event.get("action", "unknown"), min(100, risk), confidence, pivots, evidence, event)


def output_table(findings: list[SaaSFinding]) -> None:
    print(f"{'APP':28} {'ACTION':24} {'RISK':>4} CONF PIVOTS")
    print("-" * 100)
    for item in findings:
        print(f"{item.app_name[:28]:28} {item.action[:24]:24} {item.risk_score:>4} {item.confidence:5} {', '.join(item.infrastructure_pivots)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SaaS/OAuth audit hunter")
    parser.add_argument("-f", "--file", help="JSON audit events")
    parser.add_argument("--format", choices=["json", "table"], default="json")
    args = parser.parse_args()

    findings = sorted([score_event(event) for event in load_events(args.file)], key=lambda item: item.risk_score, reverse=True)
    if args.format == "table":
        output_table(findings)
        return

    indicators = []
    for finding in findings:
        for pivot in finding.infrastructure_pivots:
            indicators.append({"type": "domain", "value": pivot, "context": asdict(finding)})
        indicators.append({"type": "ip", "value": finding.event.get("source_ip", "unknown"), "context": asdict(finding)})

    print(json.dumps({"metadata": {"source_module": "0x11_saas_audit_hunter", "generated_at": now_utc()}, "indicators": indicators}, indent=2))


if __name__ == "__main__":
    main()
