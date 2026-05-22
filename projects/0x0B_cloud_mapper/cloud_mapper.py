#!/usr/bin/env python3
"""
cloud_mapper.py — Cloud Infrastructure Reconnaissance
Module 0x0B Capstone Project | AIH-C Curriculum

Maps IPs to cloud providers and simulates S3 bucket hunting.
"""

import argparse
import json
import ipaddress
from datetime import datetime, timezone

# Mock Cloud Ranges
MOCK_RANGES = {
    "AWS": [ipaddress.IPv4Network("13.248.0.0/14")],
    "GCP": [ipaddress.IPv4Network("34.0.0.0/15")],
    "Azure": [ipaddress.IPv4Network("20.33.0.0/16")]
}

def identify_provider(ip_str: str) -> str:
    """Identify cloud provider for an IP."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for provider, nets in MOCK_RANGES.items():
            for net in nets:
                if ip in net:
                    return provider
    except ValueError:
        pass
    return "Unknown/On-Prem"

def check_bucket(domain: str) -> dict:
    """Mock check for open S3 buckets."""
    # Simulate finding an open bucket for a specific demo domain
    if "malicious" in domain:
        return {"status": "open", "files": ["config.json", "payload.bin"]}
    return {"status": "closed", "files": []}

def main():
    parser = argparse.ArgumentParser(description="Cloud Infrastructure Mapper")
    parser.add_argument("-t", "--target", required=True, help="Target IP or Domain")
    args = parser.parse_args()

    results = {
        "target": args.target,
        "provider": identify_provider(args.target),
        "bucket": check_bucket(args.target)
    }

    # Output using IOC schema format
    ioc_output = {
        "metadata": {
            "source_module": "0x0B_cloud_mapper",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "indicators": [
            {
                "type": "ip" if args.target.replace(".","").isdigit() else "domain",
                "value": args.target,
                "context": results
            }
        ]
    }
    
    print(json.dumps(ioc_output, indent=2))

if __name__ == "__main__":
    main()
