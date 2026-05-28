#!/usr/bin/env python3
"""
cloud_mapper.py - Module 0x0B Capstone: Cloud Infrastructure Hunting
====================================================================
Maps IPs and hostnames to likely cloud providers/services, simulates safe
object-store exposure checks, scores risk, and emits the AIH-C IOC schema.

The implementation is mock-first: it runs offline and demonstrates the
analysis workflow without brute-forcing or downloading cloud-hosted content.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


MOCK_RANGES = {
    "AWS": [
        ("CloudFront/Global Accelerator", ipaddress.ip_network("13.248.0.0/14")),
        ("EC2 us-east-1", ipaddress.ip_network("3.80.0.0/12")),
        ("Lambda/API Gateway", ipaddress.ip_network("54.239.0.0/16")),
    ],
    "GCP": [
        ("Google Cloud", ipaddress.ip_network("34.0.0.0/15")),
        ("Cloud Run", ipaddress.ip_network("35.184.0.0/13")),
    ],
    "Azure": [
        ("Azure Front Door/App Service", ipaddress.ip_network("20.33.0.0/16")),
        ("Azure Compute", ipaddress.ip_network("40.64.0.0/10")),
    ],
    "Cloudflare": [
        ("CDN/Workers", ipaddress.ip_network("104.16.0.0/12")),
    ],
}

SERVICE_PATTERNS = [
    (re.compile(r"\.s3[.-].*amazonaws\.com$|\.s3\.amazonaws\.com$"), "AWS", "S3 object storage"),
    (re.compile(r"\.s3-website[-.].*amazonaws\.com$"), "AWS", "S3 static website"),
    (re.compile(r"\.cloudfront\.net$"), "AWS", "CloudFront edge"),
    (re.compile(r"\.execute-api\.[^.]+\.amazonaws\.com$"), "AWS", "API Gateway"),
    (re.compile(r"\.lambda-url\.[^.]+\.on\.aws$"), "AWS", "Lambda function URL"),
    (re.compile(r"\.blob\.core\.windows\.net$"), "Azure", "Azure Blob Storage"),
    (re.compile(r"\.azurewebsites\.net$"), "Azure", "Azure App Service"),
    (re.compile(r"\.trafficmanager\.net$"), "Azure", "Azure Traffic Manager"),
    (re.compile(r"\.run\.app$"), "GCP", "Cloud Run"),
    (re.compile(r"\.cloudfunctions\.net$"), "GCP", "Cloud Functions"),
    (re.compile(r"\.firebaseapp\.com$"), "GCP", "Firebase Hosting"),
    (re.compile(r"\.workers\.dev$"), "Cloudflare", "Cloudflare Workers"),
]

SUSPICIOUS_OBJECT_TERMS = {
    "config",
    "payload",
    "stager",
    "beacon",
    "implant",
    "panel",
    "wallet",
    "backup",
    "dump",
}

MOCK_BUCKETS = {
    "malicious-update.s3.amazonaws.com": {
        "public_listing": True,
        "objects": [
            {"name": "config.json", "size": 2048, "last_modified": "2026-05-20T11:32:00Z"},
            {"name": "payload.bin", "size": 447488, "last_modified": "2026-05-20T11:36:00Z"},
            {"name": "operator_notes.txt", "size": 612, "last_modified": "2026-05-20T11:40:00Z"},
        ],
    },
    "cdn-stage.blob.core.windows.net": {
        "public_listing": True,
        "objects": [
            {"name": "stage1.ps1", "size": 9302, "last_modified": "2026-05-18T04:10:00Z"},
            {"name": "backup.zip", "size": 123004, "last_modified": "2026-05-18T04:11:00Z"},
        ],
    },
}


@dataclass
class CloudFinding:
    target: str
    provider: str
    service: str
    confidence: str
    risk_score: int
    evidence: list[str]
    storage: dict


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.target:
        targets.extend(args.target)
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            targets.extend(line.strip() for line in handle if line.strip() and not line.startswith("#"))
    return targets or ["13.248.118.1", "malicious-update.s3.amazonaws.com", "api-id.execute-api.us-east-1.amazonaws.com"]


def identify_by_ip(target: str) -> tuple[str, str, list[str]]:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return "Unknown", "Unknown", []

    for provider, ranges in MOCK_RANGES.items():
        for service, network in ranges:
            if ip in network:
                return provider, service, [f"{ip} is inside {network}"]
    return "Unknown/On-Prem", "Unknown", ["No mock provider range matched"]


def identify_by_hostname(target: str) -> tuple[str, str, list[str]]:
    host = target.lower().strip(".")
    evidence: list[str] = []
    for pattern, provider, service in SERVICE_PATTERNS:
        if pattern.search(host):
            evidence.append(f"Hostname matches {service} pattern")
            return provider, service, evidence
    return "Unknown", "Unknown", ["No managed-service hostname pattern matched"]


def check_storage(target: str) -> dict:
    host = target.lower().strip(".")
    data = MOCK_BUCKETS.get(host, {"public_listing": False, "objects": []})
    suspicious = []
    for obj in data["objects"]:
        name = obj["name"].lower()
        if any(term in name for term in SUSPICIOUS_OBJECT_TERMS):
            suspicious.append(obj["name"])
    return {
        "public_listing": data["public_listing"],
        "object_count": len(data["objects"]),
        "suspicious_objects": suspicious,
        "objects_metadata_only": data["objects"],
    }


def score(provider: str, service: str, storage: dict, evidence: list[str]) -> tuple[int, str]:
    risk = 10
    if provider not in {"Unknown", "Unknown/On-Prem"}:
        risk += 15
    if service in {"S3 object storage", "S3 static website", "Azure Blob Storage"}:
        risk += 15
    if "API Gateway" in service or "Lambda" in service or "Cloud Run" in service:
        risk += 15
    if storage["public_listing"]:
        risk += 25
    risk += min(20, 5 * len(storage["suspicious_objects"]))
    if len(evidence) >= 2:
        risk += 5
    risk = min(100, risk)
    confidence = "high" if risk >= 70 else "medium" if risk >= 40 else "low"
    return risk, confidence


def analyze_target(target: str) -> CloudFinding:
    ip_provider, ip_service, ip_evidence = identify_by_ip(target)
    host_provider, host_service, host_evidence = identify_by_hostname(target)

    provider = host_provider if host_provider != "Unknown" else ip_provider
    service = host_service if host_service != "Unknown" else ip_service
    evidence = ip_evidence + host_evidence
    storage = check_storage(target)
    if storage["public_listing"]:
        evidence.append("Mock object-store listing is public")
    if storage["suspicious_objects"]:
        evidence.append("Suspicious object names present in listing metadata")

    risk, confidence = score(provider, service, storage, evidence)
    return CloudFinding(target, provider, service, confidence, risk, evidence, storage)


def to_ioc(finding: CloudFinding) -> dict:
    indicator_type = "ip"
    try:
        ipaddress.ip_address(finding.target)
    except ValueError:
        indicator_type = "domain"
    return {
        "type": indicator_type,
        "value": finding.target,
        "context": asdict(finding),
    }


def output_table(findings: Iterable[CloudFinding]) -> None:
    rows = list(findings)
    print(f"{'TARGET':38} {'PROVIDER':12} {'SERVICE':24} {'RISK':>4} CONF")
    print("-" * 92)
    for item in rows:
        print(f"{item.target[:38]:38} {item.provider[:12]:12} {item.service[:24]:24} {item.risk_score:>4} {item.confidence}")


def output_csv(findings: Iterable[CloudFinding]) -> None:
    rows = list(findings)
    writer = csv.DictWriter(
        __import__("sys").stdout,
        fieldnames=["target", "provider", "service", "risk_score", "confidence", "public_listing"],
    )
    writer.writeheader()
    for item in rows:
        writer.writerow(
            {
                "target": item.target,
                "provider": item.provider,
                "service": item.service,
                "risk_score": item.risk_score,
                "confidence": item.confidence,
                "public_listing": item.storage["public_listing"],
            }
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud infrastructure mapper")
    parser.add_argument("-t", "--target", action="append", help="Target IP or hostname. Repeatable.")
    parser.add_argument("-f", "--file", help="File containing targets, one per line")
    parser.add_argument("--format", choices=["json", "table", "csv"], default="json")
    args = parser.parse_args()

    findings = [analyze_target(target) for target in read_targets(args)]
    if args.format == "table":
        output_table(findings)
        return
    if args.format == "csv":
        output_csv(findings)
        return

    print(
        json.dumps(
            {
                "metadata": {"source_module": "0x0B_cloud_mapper", "generated_at": now_utc()},
                "indicators": [to_ioc(finding) for finding in findings],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
