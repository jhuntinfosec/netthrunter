#!/usr/bin/env python3
"""
k8s_exposure_mapper.py - Module 0x12 Capstone
Scores mock Kubernetes/registry metadata and exports AIH-C indicators.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


MOCK_RESOURCES = [
    {
        "kind": "APIServer",
        "name": "prod-api",
        "endpoint": "https://k8s-prod.example.net:6443",
        "public": True,
        "anonymous_access": False,
        "tags": ["internet-facing"],
    },
    {
        "kind": "Pod",
        "name": "metrics-helper",
        "image": "registry.example.net/system/metrics-helper:latest",
        "privileged": True,
        "hostPath": True,
        "service_account": "cluster-admin-helper",
    },
    {
        "kind": "Image",
        "name": "docker.io/public/miner-helper:latest",
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "created": "2026-05-22T01:10:00Z",
        "entrypoint": "xmrig --donate-level 1",
    },
]


@dataclass
class K8sFinding:
    kind: str
    name: str
    risk_score: int
    confidence: str
    pivots: list[dict]
    evidence: list[str]
    resource: dict


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_resources(path: str | None) -> list[dict]:
    if not path:
        return MOCK_RESOURCES
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, list) else data.get("resources", [])


def score_resource(resource: dict) -> K8sFinding:
    risk = 10
    evidence: list[str] = []
    pivots: list[dict] = []
    if resource.get("public"):
        risk += 25
        evidence.append("Public Kubernetes endpoint")
    if resource.get("anonymous_access"):
        risk += 30
        evidence.append("Anonymous access enabled")
    if resource.get("privileged"):
        risk += 25
        evidence.append("Privileged workload")
    if resource.get("hostPath"):
        risk += 20
        evidence.append("hostPath mount present")
    if "miner" in resource.get("name", "").lower() or "xmrig" in resource.get("entrypoint", "").lower():
        risk += 30
        evidence.append("Crypto-mining image or entrypoint signal")
    if resource.get("endpoint"):
        pivots.append({"type": "url", "value": resource["endpoint"]})
    if resource.get("image"):
        pivots.append({"type": "container_image", "value": resource["image"]})
    if resource.get("digest"):
        pivots.append({"type": "hash", "value": resource["digest"]})
    confidence = "high" if risk >= 75 else "medium" if risk >= 45 else "low"
    return K8sFinding(resource.get("kind", "Unknown"), resource.get("name", "unknown"), min(100, risk), confidence, pivots, evidence, resource)


def output_table(findings: list[K8sFinding]) -> None:
    print(f"{'KIND':12} {'NAME':24} {'RISK':>4} CONF EVIDENCE")
    print("-" * 92)
    for item in findings:
        print(f"{item.kind:12} {item.name[:24]:24} {item.risk_score:>4} {item.confidence:5} {', '.join(item.evidence)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes exposure mapper")
    parser.add_argument("-f", "--file", help="JSON resources")
    parser.add_argument("--format", choices=["json", "table"], default="json")
    args = parser.parse_args()

    findings = sorted([score_resource(item) for item in load_resources(args.file)], key=lambda item: item.risk_score, reverse=True)
    if args.format == "table":
        output_table(findings)
        return

    indicators = []
    for finding in findings:
        for pivot in finding.pivots:
            indicators.append({"type": pivot["type"], "value": pivot["value"], "context": asdict(finding)})
    print(json.dumps({"metadata": {"source_module": "0x12_k8s_exposure_mapper", "generated_at": now_utc()}, "indicators": indicators}, indent=2))


if __name__ == "__main__":
    main()
