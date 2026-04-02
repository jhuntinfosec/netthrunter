#!/usr/bin/env python3
"""
lambda_scanner.py — Module 0x09 Capstone: Distributed Scanner Deployment
=========================================================================
Demonstrates distributed scanning architecture using AWS Lambda for
authorized threat hunting. Includes SAM template generation, multi-region
simulation, cost estimation, and result aggregation.

This script is educational: it simulates the distributed scanning workflow
locally. For real deployment, use the generated SAM template.

Usage:
  python lambda_scanner.py                              # Demo mode
  python lambda_scanner.py --simulate -t 1.2.3.4        # Simulate scan
  python lambda_scanner.py --gen-sam                     # Generate SAM template
  python lambda_scanner.py --estimate --targets 1000    # Cost estimation
  python lambda_scanner.py --format json                # JSON output

Environment Variables:
  AWS_REGION          — Default region (default: us-east-1)

@decision DEC-OPSEC-001
@title Local simulation over live deployment
@status accepted
@rationale Educational tool must demonstrate concepts without requiring
  AWS accounts, API keys, or real infrastructure. The simulation shows
  exactly what distributed scanning looks like — different source IPs,
  regional distribution, result aggregation — using mock data.

@decision DEC-OPSEC-002
@title SAM template as generated artifact, not embedded deployment
@status accepted
@rationale Generating a template.yaml file that students can review,
  modify, and deploy themselves is more educational than auto-deploying.
  It teaches the infrastructure-as-code pattern and allows customization.
"""

import argparse
import hashlib
import json
import os
import random
import ssl
import socket
import sys
import textwrap
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# AWS Region IP Pool Simulation
# ---------------------------------------------------------------------------
# Real AWS Lambda functions receive IPs from the region's NAT pool.
# These mock pools demonstrate the concept of IP diversity per region.

REGION_IP_POOLS = {
    "us-east-1": ["3.80.{}.{}",  "54.210.{}.{}",  "18.206.{}.{}"],
    "us-west-2": ["34.210.{}.{}", "52.24.{}.{}",   "44.226.{}.{}"],
    "eu-west-1": ["54.78.{}.{}",  "34.245.{}.{}",  "52.49.{}.{}"],
    "eu-central-1": ["3.120.{}.{}", "18.196.{}.{}", "52.57.{}.{}"],
    "ap-southeast-1": ["13.228.{}.{}", "54.179.{}.{}", "18.136.{}.{}"],
    "ap-northeast-1": ["13.112.{}.{}", "54.168.{}.{}", "18.179.{}.{}"],
}

# Realistic browser User-Agent strings for scan configuration
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

# ---------------------------------------------------------------------------
# Mock scan results for demonstration
# ---------------------------------------------------------------------------

MOCK_TARGETS = [
    {
        "target": "198.51.100.22:443",
        "note": "Suspected Cobalt Strike team server",
        "mock_result": {
            "status": "SUCCESS",
            "server_header": "Unknown",
            "http_status_code": 404,
            "cert_issuer_cn": "Major Cobalt Strike",
            "cert_serial": "146473198",
            "tls_version": "TLSv1.2",
        },
    },
    {
        "target": "203.0.113.45:443",
        "note": "Suspected Sliver C2",
        "mock_result": {
            "status": "SUCCESS",
            "server_header": "nginx",
            "http_status_code": 200,
            "cert_issuer_cn": "operators llc",
            "cert_serial": "8A3F2C1D",
            "tls_version": "TLSv1.3",
        },
    },
    {
        "target": "192.0.2.88:8443",
        "note": "Suspected open directory stager",
        "mock_result": {
            "status": "SUCCESS",
            "server_header": "SimpleHTTP/0.6 Python/3.11.4",
            "http_status_code": 200,
            "cert_issuer_cn": None,
            "cert_serial": None,
            "tls_version": "TLSv1.3",
        },
    },
    {
        "target": "198.51.100.99:443",
        "note": "Suspected Havoc C2",
        "mock_result": {
            "status": "HTTP_ERROR",
            "server_header": "nginx/1.18.0",
            "http_status_code": 403,
            "cert_issuer_cn": "Let's Encrypt",
            "cert_serial": "04B2A1...",
            "tls_version": "TLSv1.3",
        },
    },
    {
        "target": "203.0.113.200:50050",
        "note": "Suspected CS team server (management port)",
        "mock_result": {
            "status": "CONNECTION_FAILED",
            "error": "Connection refused",
        },
    },
]


def simulate_lambda_ip(region: str) -> str:
    """Generate a simulated Lambda source IP for a given region."""
    templates = REGION_IP_POOLS.get(region, REGION_IP_POOLS["us-east-1"])
    template = random.choice(templates)
    return template.format(random.randint(1, 254), random.randint(1, 254))


def lambda_handler(event: dict, context: dict) -> dict:
    """
    AWS Lambda entry point for distributed scanning.

    When deployed to Lambda, each invocation gets a fresh IP from the
    region's NAT pool. The researcher's IP is never exposed to the target.

    This function probes a single target's TLS configuration and extracts
    server metadata useful for C2 identification (see Module 0x04).
    """
    target = event.get("target", "example.com")
    port = event.get("port", 443)
    ua = event.get("user_agent", random.choice(USER_AGENTS))

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"https://{target}:{port}"
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, timeout=5.0, context=ctx) as response:
            server_header = response.getheader("Server", "Unknown")
            cert = response.getpeercert()

            issuer_cn = None
            cert_serial = None
            if cert:
                if "issuer" in cert:
                    issuer_dict = {}
                    for rdn in cert["issuer"]:
                        for attr_type, attr_value in rdn:
                            issuer_dict[attr_type] = attr_value
                    issuer_cn = issuer_dict.get("commonName")
                cert_serial = cert.get("serialNumber")

            return {
                "statusCode": 200,
                "target": f"{target}:{port}",
                "status": "SUCCESS",
                "server_header": server_header,
                "http_status_code": response.code,
                "cert_issuer_cn": issuer_cn,
                "cert_serial": cert_serial,
                "tls_version": getattr(
                    response, "version", None
                ),
            }

    except urllib.error.HTTPError as e:
        return {
            "statusCode": 200,
            "target": f"{target}:{port}",
            "status": "HTTP_ERROR",
            "http_status_code": e.code,
            "server_header": e.headers.get("Server", "Unknown"),
            "error_msg": str(e),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "target": f"{target}:{port}",
            "status": "CONNECTION_FAILED",
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Multi-region simulation
# ---------------------------------------------------------------------------


def simulate_distributed_scan(
    targets: list[str], regions: list[str], mock: bool = True
) -> list[dict]:
    """
    Simulate a multi-region distributed scan.

    In a real deployment, this would invoke Lambda functions across regions
    via boto3. Here we simulate the workflow to demonstrate the concept.
    """
    results = []
    mock_idx = 0

    for i, target_str in enumerate(targets):
        # Parse target:port
        if ":" in target_str and target_str.count(":") == 1:
            host, port_str = target_str.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host, port = target_str, 443
        else:
            host, port = target_str, 443

        # Round-robin across regions
        region = regions[i % len(regions)]
        source_ip = simulate_lambda_ip(region)
        ua = random.choice(USER_AGENTS)

        timestamp = datetime.now(timezone.utc).isoformat()

        if mock:
            # Use mock results for demonstration
            mock_target = MOCK_TARGETS[mock_idx % len(MOCK_TARGETS)]
            mock_idx += 1
            scan_result = dict(mock_target["mock_result"])
            scan_result["target"] = f"{host}:{port}"
        else:
            # Live scan via lambda_handler
            event = {"target": host, "port": port, "user_agent": ua}
            scan_result = lambda_handler(event, {})

        result = {
            "target": f"{host}:{port}",
            "region": region,
            "source_ip": source_ip,
            "user_agent": ua[:50] + "...",
            "timestamp": timestamp,
            **scan_result,
        }
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# SAM template generation
# ---------------------------------------------------------------------------

SAM_TEMPLATE = textwrap.dedent("""\
    AWSTemplateFormatVersion: '2010-09-09'
    Transform: AWS::Serverless-2016-10-31
    Description: >
      Distributed scanner for authorized threat hunting (Module 0x09).
      Deploy to multiple regions for IP diversity.

    Globals:
      Function:
        Timeout: 10
        MemorySize: 128
        Runtime: python3.12

    Resources:
      ScannerFunction:
        Type: AWS::Serverless::Function
        Properties:
          Handler: lambda_scanner.lambda_handler
          Description: Probe a single target and return TLS/HTTP metadata
          Events:
            ScanApi:
              Type: Api
              Properties:
                Path: /scan
                Method: post

      ResultsBucket:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: !Sub "${AWS::StackName}-results"
          LifecycleConfiguration:
            Rules:
              - Id: AutoDeleteResults
                Status: Enabled
                ExpirationInDays: 30

    Outputs:
      ScannerApi:
        Description: API Gateway endpoint for the scanner
        Value: !Sub "https://${ServerlessRestApi}.execute-api.${AWS::Region}.amazonaws.com/Prod/scan"
      ResultsBucket:
        Description: S3 bucket for scan result aggregation
        Value: !Ref ResultsBucket
""")


def generate_sam_template(output_path: str = "template.yaml") -> str:
    """Generate an AWS SAM template for Lambda deployment."""
    with open(output_path, "w") as f:
        f.write(SAM_TEMPLATE)
    return output_path


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def estimate_cost(
    num_targets: int,
    num_regions: int = 3,
    memory_mb: int = 128,
    duration_ms: int = 500,
) -> dict:
    """
    Estimate AWS Lambda cost for a scanning campaign.

    Pricing (as of 2024):
    - $0.20 per 1M requests
    - $0.0000166667 per GB-second
    - Free tier: 1M requests + 400K GB-seconds/month
    """
    total_invocations = num_targets * num_regions
    request_cost = total_invocations * 0.0000002  # $0.20 per 1M

    gb_seconds = (memory_mb / 1024) * (duration_ms / 1000)
    compute_cost = total_invocations * gb_seconds * 0.0000166667

    total = request_cost + compute_cost

    free_tier_invocations = 1_000_000
    free_tier_gb_seconds = 400_000
    total_gb_seconds = total_invocations * gb_seconds

    within_free_tier = (
        total_invocations <= free_tier_invocations
        and total_gb_seconds <= free_tier_gb_seconds
    )

    return {
        "total_invocations": total_invocations,
        "targets": num_targets,
        "regions": num_regions,
        "memory_mb": memory_mb,
        "duration_ms": duration_ms,
        "request_cost_usd": round(request_cost, 4),
        "compute_cost_usd": round(compute_cost, 4),
        "total_cost_usd": round(total, 4),
        "total_gb_seconds": round(total_gb_seconds, 2),
        "within_free_tier": within_free_tier,
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def format_text(results: list[dict]) -> str:
    """Format results as human-readable text."""
    lines = []
    for r in results:
        status = r.get("status", "UNKNOWN")
        target = r.get("target", "?")
        region = r.get("region", "?")
        source = r.get("source_ip", "?")
        server = r.get("server_header", "?")

        status_icon = {"SUCCESS": "+", "HTTP_ERROR": "!", "CONNECTION_FAILED": "-"}.get(
            status, "?"
        )
        lines.append(f"  [{status_icon}] {target}")
        lines.append(f"      Region: {region} | Source IP: {source}")
        if status == "CONNECTION_FAILED":
            lines.append(f"      Error: {r.get('error', 'unknown')}")
        else:
            lines.append(
                f"      Server: {server} | HTTP {r.get('http_status_code', '?')}"
            )
            if r.get("cert_issuer_cn"):
                lines.append(f"      Cert Issuer: {r['cert_issuer_cn']}")
            if r.get("cert_serial"):
                lines.append(f"      Cert Serial: {r['cert_serial']}")

    return "\n".join(lines)


def format_csv(results: list[dict]) -> str:
    """Format results as CSV."""
    headers = [
        "target",
        "region",
        "source_ip",
        "status",
        "http_status_code",
        "server_header",
        "cert_issuer_cn",
        "cert_serial",
        "tls_version",
    ]
    lines = [",".join(headers)]
    for r in results:
        row = [str(r.get(h, "")) for h in headers]
        lines.append(",".join(row))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Module 0x09: Distributed Scanner for Authorized Threat Hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s                                    Demo mode (mock targets)
              %(prog)s --simulate -t 1.2.3.4,5.6.7.8     Simulate distributed scan
              %(prog)s --gen-sam                           Generate SAM template
              %(prog)s --estimate --targets 1000           Cost estimation
        """),
    )
    parser.add_argument(
        "-t", "--target", help="Target(s), comma-separated (host:port)"
    )
    parser.add_argument("-f", "--file", help="File with targets, one per line")
    parser.add_argument(
        "--regions",
        default="us-east-1,eu-west-1,ap-southeast-1",
        help="Comma-separated AWS regions (default: us-east-1,eu-west-1,ap-southeast-1)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run distributed scan simulation",
    )
    parser.add_argument(
        "--gen-sam",
        action="store_true",
        help="Generate AWS SAM template.yaml",
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="Estimate Lambda cost for campaign",
    )
    parser.add_argument(
        "--targets",
        type=int,
        default=100,
        help="Number of targets for cost estimation (default: 100)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=True,
        help="Use mock data (default: True)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use live scanning (requires network access)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    regions = [r.strip() for r in args.regions.split(",")]
    use_mock = not args.live

    # --- SAM template generation ---
    if args.gen_sam:
        path = generate_sam_template()
        print(f"[+] SAM template written to: {path}")
        print("[*] Deploy with: sam build && sam deploy --guided")
        print("[*] Review the template before deploying to understand the resources.")
        return

    # --- Cost estimation ---
    if args.estimate:
        est = estimate_cost(
            num_targets=args.targets,
            num_regions=len(regions),
        )
        print("[*] Lambda Cost Estimation")
        print(f"    Targets:          {est['targets']}")
        print(f"    Regions:          {est['regions']}")
        print(f"    Total invocations:{est['total_invocations']}")
        print(f"    Memory:           {est['memory_mb']} MB")
        print(f"    Duration:         {est['duration_ms']} ms")
        print(f"    GB-seconds:       {est['total_gb_seconds']}")
        print(f"    Request cost:     ${est['request_cost_usd']}")
        print(f"    Compute cost:     ${est['compute_cost_usd']}")
        print(f"    Total cost:       ${est['total_cost_usd']}")
        print(
            f"    Free tier:        {'YES' if est['within_free_tier'] else 'NO — exceeds free tier'}"
        )
        return

    # --- Collect targets ---
    targets = []
    if args.target:
        targets = [t.strip() for t in args.target.split(",")]
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.simulate:
        # Default demo targets for simulation
        targets = [mt["target"] for mt in MOCK_TARGETS]

    # --- Simulate or demo ---
    if args.simulate or (not args.gen_sam and not args.estimate):
        if not targets:
            targets = [mt["target"] for mt in MOCK_TARGETS]
            use_mock = True

        if args.format == "text" or not args.simulate:
            print("[*] Distributed Scanner — Module 0x09")
            print(f"[*] Timestamp: {datetime.now(timezone.utc).isoformat()}")
            print(f"[*] Regions: {', '.join(regions)}")
            print(f"[*] Targets: {len(targets)}")
            print(f"[*] Mode: {'MOCK (simulated)' if use_mock else 'LIVE'}")
            if use_mock:
                print(
                    "[!] Running in mock mode — no network requests made"
                )
                print(
                    "[!] Use --live flag for real scanning (requires authorization)"
                )
            print()

        results = simulate_distributed_scan(targets, regions, mock=use_mock)

        if args.format == "json":
            print(json.dumps(results, indent=2))
        elif args.format == "csv":
            print(format_csv(results))
        else:
            print("--- Scan Results ---")
            print(format_text(results))
            print()
            print(f"[*] {len(results)} targets scanned across {len(regions)} regions")
            success = sum(1 for r in results if r.get("status") == "SUCCESS")
            errors = sum(1 for r in results if r.get("status") == "HTTP_ERROR")
            failed = sum(1 for r in results if r.get("status") == "CONNECTION_FAILED")
            print(f"    Connected: {success} | HTTP errors: {errors} | Failed: {failed}")
            print()

            unique_ips = set(r.get("source_ip", "") for r in results)
            print(f"[*] Source IP diversity: {len(unique_ips)} unique IPs used")
            for ip in sorted(unique_ips):
                region = next(
                    (r["region"] for r in results if r.get("source_ip") == ip), "?"
                )
                print(f"    {ip} ({region})")

            print()
            print("[*] Next steps:")
            print("    1. Generate SAM template: python lambda_scanner.py --gen-sam")
            print("    2. Review and customize template.yaml")
            print("    3. Deploy: sam build && sam deploy --guided")
            print("    4. Invoke: aws lambda invoke --function-name ScannerFunction ...")


if __name__ == "__main__":
    main()
