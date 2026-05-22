#!/usr/bin/env python3
"""
ttp_profiler.py — Threat Profiling and MITRE Mapping
Module 0x0F Capstone Project | AIH-C Curriculum

Ingests IOC schemas and outputs a behavioral TTP profile.
"""

import argparse
import json
from datetime import datetime

def map_ttps(indicators: list) -> dict:
    """Mock mapping of indicators to MITRE TTPs."""
    profile = {
        "actor_id": "UNKNOWN_ACTOR",
        "tactics": [],
        "techniques": [],
        "summary": "Generated behavioral profile."
    }
    
    types = [i.get("type") for i in indicators]
    
    if "domain" in types:
        profile["techniques"].append({"id": "T1583.001", "name": "Acquire Infrastructure: Domains"})
    
    if "jarm" in types:
        profile["techniques"].append({"id": "T1588.004", "name": "Obtain Capabilities: Digital Certificates"})
        
    if "hash" in types:
        profile["techniques"].append({"id": "T1584.004", "name": "Compromise Infrastructure: Server"})

    # Deduplicate
    profile["techniques"] = [dict(t) for t in {tuple(d.items()) for d in profile["techniques"]}]
    return profile

def main():
    parser = argparse.ArgumentParser(description="Threat Profiler (TTP Mapper)")
    parser.add_argument("-i", "--input", help="Path to input IOC schema JSON file")
    args = parser.parse_args()

    indicators = []
    if args.input:
        try:
            with open(args.input) as f:
                data = json.load(f)
                indicators = data.get("indicators", [])
        except Exception as e:
            print(f"[!] Error reading {args.input}: {e}")
            return
    else:
        # Mock data
        indicators = [
            {"type": "domain", "value": "mock.com"},
            {"type": "jarm", "value": "mock_hash"}
        ]

    profile = map_ttps(indicators)
    
    print("="*50)
    print(" ACTOR BEHAVIORAL PROFILE")
    print("="*50)
    print(json.dumps(profile, indent=2))

if __name__ == "__main__":
    main()
