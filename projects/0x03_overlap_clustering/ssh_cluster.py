#!/usr/bin/env python3
# Module 0x03 Capstone Project: Overlap & Clustering Engine
# Fully Working Reference Solution

import requests
import os
import json
from collections import Counter

# Set your API keys as an environmental variable `export SHODAN_API_KEY="xxx"`
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

def search_ssh_hash(ssh_hash: str) -> list:
    """
    Query the Shodan API for all global servers sharing this exact SSH Host Key.
    """
    if not SHODAN_API_KEY:
        print("[!] No SHODAN_API_KEY set. Using internal offline mock dataset...")
        # Offline mock representation of Shodan 'matches' response
        # To test the clustering logic without burning API credits
        return [
            {"ip_str": "1.2.3.4", "asn": "AS20473", "isp": "Choopa, LLC"},
            {"ip_str": "1.2.3.5", "asn": "AS20473", "isp": "Choopa, LLC"},
            {"ip_str": "4.5.6.7", "asn": "AS398324", "isp": "HostHatch"},
            {"ip_str": "99.88.77.66", "asn": "AS20473", "isp": "Choopa, LLC"},
            {"ip_str": "11.22.33.44", "asn": "AS16276", "isp": "OVH SAS"},
        ]

    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=port:22+hash:{ssh_hash}"
    try:
        response = requests.get(url, timeout=10.0)
        response.raise_for_status()
        return response.json().get("matches", [])
    except Exception as e:
        print(f"[x] Error querying Shodan: {e}")
        return []

def analyze_clusters(nodes: list):
    """
    Takes the raw search nodes and calculates ASN/Hosting affinity.
    If 90% of a threat actor's infrastructure is on one ASN, they have a preference.
    """
    if not nodes:
        print("No nodes found to analyze.")
        return
        
    total_nodes = len(nodes)
    asn_counter = Counter()
    isp_mapping = {}
    
    for node in nodes:
        asn = node.get("asn", "Unknown ASN")
        isp = node.get("isp", "Unknown ISP")
        
        asn_counter[asn] += 1
        isp_mapping[asn] = isp  # Store the readable name
        
    print(f"\n[*] Total Overlapping Nodes Found: {total_nodes}")
    print("\n--- Autonomous System (ASN) Infrastructure Clustering ---")
    
    # Sort and display the clusters
    for asn, count in asn_counter.most_common():
        percentage = (count / total_nodes) * 100
        readable_isp = isp_mapping.get(asn, "Unknown")
        print(f"[+] {asn:<10} | {readable_isp:<15} | Nodes: {count:<4} | Affinity: {percentage:.1f}%")
        
        # Threat logic: High affinity implies targeted procurement!
        if percentage > 50:
            print(f"    [!] HIGH CONFIDENCE CLUSTER DETECTED. The adversary heavily biases {readable_isp}.")

if __name__ == "__main__":
    print("--- Module 0x03: Infrastructure Clustering Engine ---")
    
    # We are searching for an arbitrary theoretical SSH hash.
    target_ssh_hash = "f1:2a:b3:4c:5d:6e:-123456789" 
    print(f"[*] Targeting structural SSH overlap: {target_ssh_hash}")
    
    nodes = search_ssh_hash(target_ssh_hash)
    analyze_clusters(nodes)
