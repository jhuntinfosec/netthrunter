#!/usr/bin/env python3
# Module 0x08 Capstone Project: Exit Node Proxy Validator
# Fully Working Reference Solution

import requests
import json
import time

def check_ip_intelligence(ip: str) -> dict:
    """
    Submits a raw IP to IP-API to gather ASN, Hosting, and ISP tags.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,mobile,proxy,hosting"
    try:
        response = requests.get(url, timeout=5.0)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error querying {ip}: {e}")
        return None

def analyze_exit_nodes(ip_list: list):
    """
    Applies logic checks to determine if an IP is Residential or Datacenter-hosted.
    """
    results = []
    
    for ip in ip_list:
        data = check_ip_intelligence(ip)
        if data and data.get('status') == 'success':
            asn = data.get('as', 'Unknown')
            isp = data.get('isp', 'Unknown')
            
            # The API often tags data centers natively via the 'hosting' boolean
            is_datacenter = data.get('hosting', False)
            is_mobile = data.get('mobile', False)
            
            # Determine origin classification
            if is_datacenter:
                classification = "[DATACENTER / PROXY EXIT]"
                confidence = "High"
            elif is_mobile:
                classification = "[RESIDENTIAL MOBILE IP]"
                confidence = "High"
            else:
                classification = "[RESIDENTIAL ISP]"
                # Could be a botnet proxy on a resident machine
                confidence = "Medium: Might be a residential botnet proxy."
                
            results.append({
                "ip": ip,
                "asn": asn.split(" ")[0],
                "isp": isp,
                "classification": classification,
                "note": confidence
            })
            
        time.sleep(1.2) # Throttle to respect public API limits
        
    print(f"\n[*] Analyzed {len(results)} IP addresses.")
    print("-" * 60)
    for r in results:
        print(f"[{r['ip']}] {r['classification']}")
        print(f"    ISP: {r['isp']} | ASN: {r['asn']}")
        print(f"    Confidence: {r['note']}\n")

if __name__ == "__main__":
    print("[*] Starting Residential Proxy Validator...")
    
    mock_traffic_log = [
        "104.16.0.0",       # Cloudflare (Datacenter)
        "172.217.164.110",  # Google (Datacenter)
        "76.102.103.104",   # Comcast (Simulated Residential)
        "45.32.228.0"       # Choopa/Vultr (Datacenter / Cheap VPS)
    ]
    
    analyze_exit_nodes(mock_traffic_log)
