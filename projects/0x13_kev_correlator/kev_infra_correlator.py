#!/usr/bin/env python3
"""
kev_infra_correlator.py - Module 0x13 Capstone
Correlates mock CISA KEV entries with exposed-service fingerprints.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


MOCK_KEV = [
    {"cve": "CVE-2025-24813", "vendor": "Apache", "product": "Tomcat", "date_added": "2025-03-12", "known_ransomware": False},
    {"cve": "CVE-2024-3400", "vendor": "Palo Alto Networks", "product": "PAN-OS", "date_added": "2024-04-12", "known_ransomware": False},
    {"cve": "CVE-2023-34362", "vendor": "Progress", "product": "MOVEit Transfer", "date_added": "2023-06-02", "known_ransomware": True},
]

MOCK_ASSETS = [
    {"asset": "198.51.100.25", "product": "Apache Tomcat", "evidence": ["Server: Apache-Coyote/1.1", "title: Apache Tomcat"], "public": True},
    {"asset": "vpn.example.org", "product": "PAN-OS", "evidence": ["GlobalProtect portal"], "public": True},
    {"asset": "files.example.net", "product": "MOVEit Transfer", "evidence": ["title: MOVEit Transfer"], "public": False},
]


@dataclass
class KEVFinding:
    asset: str
    cve: str
    vendor: str
    product: str
    risk_score: int
    confidence: str
    evidence: list[str]
    recommended_action: str


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: str | None, fallback: list[dict], key: str) -> list[dict]:
    if not path:
        return fallback
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, list) else data.get(key, [])


def correlate(kev_entries: list[dict], assets: list[dict]) -> list[KEVFinding]:
    findings: list[KEVFinding] = []
    for asset in assets:
        asset_product = asset.get("product", "").lower()
        for kev in kev_entries:
            if kev["product"].lower() not in asset_product and asset_product not in kev["product"].lower():
                continue
            risk = 45
            evidence = list(asset.get("evidence", []))
            evidence.append(f"Product matched KEV entry {kev['cve']}")
            if asset.get("public"):
                risk += 25
                evidence.append("Asset is public-facing")
            if kev.get("known_ransomware"):
                risk += 20
                evidence.append("KEV entry is associated with ransomware use")
            confidence = "high" if risk >= 80 else "medium" if risk >= 55 else "low"
            findings.append(
                KEVFinding(
                    asset=asset["asset"],
                    cve=kev["cve"],
                    vendor=kev["vendor"],
                    product=kev["product"],
                    risk_score=min(100, risk),
                    confidence=confidence,
                    evidence=evidence,
                    recommended_action="Prioritize remediation and hunt for related exploitation telemetry",
                )
            )
    return sorted(findings, key=lambda item: item.risk_score, reverse=True)


def output_table(findings: list[KEVFinding]) -> None:
    print(f"{'ASSET':24} {'CVE':16} {'PRODUCT':18} {'RISK':>4} CONF")
    print("-" * 86)
    for item in findings:
        print(f"{item.asset[:24]:24} {item.cve:16} {item.product[:18]:18} {item.risk_score:>4} {item.confidence}")


def main() -> None:
    parser = argparse.ArgumentParser(description="KEV infrastructure correlator")
    parser.add_argument("--kev", help="JSON KEV data")
    parser.add_argument("--assets", help="JSON exposed asset fingerprints")
    parser.add_argument("--format", choices=["json", "table"], default="json")
    args = parser.parse_args()

    findings = correlate(load_json(args.kev, MOCK_KEV, "kev"), load_json(args.assets, MOCK_ASSETS, "assets"))
    if args.format == "table":
        output_table(findings)
        return
    indicators = []
    for item in findings:
        kind = "ip" if item.asset.replace(".", "").isdigit() else "domain"
        indicators.append({"type": kind, "value": item.asset, "context": asdict(item)})
        indicators.append({"type": "cve", "value": item.cve, "context": asdict(item)})
    print(json.dumps({"metadata": {"source_module": "0x13_kev_infra_correlator", "generated_at": now_utc()}, "indicators": indicators}, indent=2))


if __name__ == "__main__":
    main()
