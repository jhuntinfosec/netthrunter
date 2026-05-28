#!/usr/bin/env python3
"""
decoy_listener.py - Module 0x0E Capstone: Active Defense & Deception
=====================================================================
Runs a safe HTTP decoy or a demo simulation, profiles scanner behavior,
enriches source IPs with mock provider data, and exports AIH-C indicators.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


IOC_LOG: list[dict] = []

MOCK_ENRICHMENT = {
    ipaddress.ip_network("198.51.100.0/24"): {"asn": "AS64501", "provider": "TrainingNet", "type": "research"},
    ipaddress.ip_network("203.0.113.0/24"): {"asn": "AS64502", "provider": "ExampleCloud", "type": "cloud"},
    ipaddress.ip_network("185.220.0.0/16"): {"asn": "AS60729", "provider": "Tor/Proxy-like", "type": "proxy"},
}

PATH_WEIGHTS = {
    "/.env": 25,
    "/config.json": 20,
    "/backup.zip": 20,
    "/admin": 15,
    "/wp-login.php": 10,
    "/payload.bin": 25,
}


@dataclass
class ScannerProfile:
    source_ip: str
    request_count: int
    paths: list[str]
    user_agents: list[str]
    enrichment: dict
    risk_score: int
    classification: str


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def enrich_ip(ip_str: str) -> dict:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"asn": "Unknown", "provider": "Unknown", "type": "unknown"}
    for network, data in MOCK_ENRICHMENT.items():
        if ip in network:
            return data
    return {"asn": "Unknown", "provider": "Unknown", "type": "unknown"}


def log_event(source_ip: str, path: str, user_agent: str) -> None:
    IOC_LOG.append(
        {
            "source_ip": source_ip,
            "path": path,
            "user_agent": user_agent or "-",
            "timestamp": now_utc(),
        }
    )


class DecoyHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        return

    def do_GET(self) -> None:
        log_event(self.client_address[0], self.path, self.headers.get("User-Agent", "-"))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Index of /</h1><ul>"
            b"<li><a href='config.json'>config.json</a></li>"
            b"<li><a href='backup.zip'>backup.zip</a></li>"
            b"<li><a href='payload.bin'>payload.bin</a></li>"
            b"</ul></body></html>"
        )


def demo_events() -> None:
    samples = [
        ("198.51.100.2", "/", "masscan/1.3.2"),
        ("203.0.113.15", "/config.json", "python-requests/2.31"),
        ("203.0.113.15", "/.env", "python-requests/2.31"),
        ("185.220.101.77", "/admin", "Mozilla/5.0"),
        ("185.220.101.77", "/payload.bin", "curl/8.1.2"),
    ]
    for ip, path, ua in samples:
        log_event(ip, path, ua)


def profile_events(events: list[dict]) -> list[ScannerProfile]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        grouped[event["source_ip"]].append(event)

    profiles: list[ScannerProfile] = []
    for source_ip, records in grouped.items():
        paths = [record["path"] for record in records]
        user_agents = sorted({record["user_agent"] for record in records})
        enrichment = enrich_ip(source_ip)
        risk = 10 * len(records) + sum(PATH_WEIGHTS.get(path, 0) for path in paths)
        if enrichment["type"] in {"proxy", "cloud"}:
            risk += 15
        risk = min(100, risk)
        classification = "scanner" if risk >= 50 else "crawler" if risk >= 25 else "background"
        profiles.append(
            ScannerProfile(
                source_ip=source_ip,
                request_count=len(records),
                paths=sorted(Counter(paths), key=Counter(paths).get, reverse=True),
                user_agents=user_agents,
                enrichment=enrichment,
                risk_score=risk,
                classification=classification,
            )
        )
    return sorted(profiles, key=lambda item: item.risk_score, reverse=True)


def output_table(profiles: list[ScannerProfile]) -> None:
    print(f"{'IP':16} {'REQ':>3} {'RISK':>4} {'CLASS':10} PROVIDER")
    print("-" * 72)
    for item in profiles:
        print(
            f"{item.source_ip:16} {item.request_count:>3} {item.risk_score:>4} "
            f"{item.classification:10} {item.enrichment['provider']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe decoy listener")
    parser.add_argument("-p", "--port", type=int, default=8080)
    parser.add_argument("--demo", action="store_true", help="Run simulated decoy events instead of binding a port")
    parser.add_argument("--format", choices=["json", "table"], default="json")
    args = parser.parse_args()

    if args.demo:
        demo_events()
    else:
        print(f"[*] Starting decoy listener on port {args.port}. Press Ctrl+C to stop and dump IOCs.")
        server = HTTPServer(("", args.port), DecoyHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()

    profiles = profile_events(IOC_LOG)
    if args.format == "table":
        output_table(profiles)
        return

    print(
        json.dumps(
            {
                "metadata": {"source_module": "0x0E_decoy_listener", "generated_at": now_utc()},
                "indicators": [
                    {"type": "ip", "value": item.source_ip, "context": asdict(item)}
                    for item in profiles
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
