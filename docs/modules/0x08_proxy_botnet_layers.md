# Module 0x08: Proxy & Botnet Layers

## Overview

When malware executes, it rarely uses the target's direct internet connection—and threat actors rarely connect directly to their C2. Botnets act as massive proxy exits. Identifying residential proxy exit nodes and multi-tier backconnect architecture is paramount to hunting the true actor origin.

## Key Concepts
* **Residential Proxies versus Datacenter Proxies**: Differentiating traffic routing via ASNs and IP reputation.
* **Socks5 Backconnects**: The infrastructure logic used by proxies like 911.re, VIP72, or modern variants.
* **Multi-tier Infrastructure**: Tracing traffic from the Target -> Residential IP -> Cloud VPS -> Actor C2.

---
## 🛠️ Module Project: ASN & Proxy Validation Checker
*Reference: Art of Cyber Warfare*

Given a massive PCAP or list of internal connections, how do you quickly determine if an outgoing connection is going to a legitimate ISP (residential) or a known bulletproof proxy hosting provider?

### The Objective
1. Load a list of IPs.
2. Query the IP against an ASN mapping database (like `ip-api.com` or local MaxMind GeoLite2).
3. Flag connections that terminate in Datacenters (e.g., AWS, DigitalOcean, Hetzner, or obscure foreign ASNs) vs Residential ISPs (Comcast, AT&T).

### Boilerplate Setup
```python
# proxy_validator.py
import requests
import json
import time

def check_ip_asn(ip):
    # For large scale, NEVER use an API directly without a local DB. 
    # This is purely demonstration.
    response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as")
    if response.status_code == 200:
        return response.json()
    return None

def analyze_traffic(ip_list):
    results = []
    suspicious_asns = ["AS20473", "AS212238"]  # Choopa, Datacamp, etc.
    
    for ip in ip_list:
        data = check_ip_asn(ip)
        if data and data['status'] == 'success':
            asn_string = data.get('as', '')
            isp = data.get('isp', '')
            
            # Simple flagging logic
            is_suspicious = bool([x for x in suspicious_asns if x in asn_string])
            results.append({
                "ip": ip,
                "isp": isp,
                "asn": asn_string,
                "datacenter_flag": is_suspicious # Improve this logic!
            })
        time.sleep(1.5) # Throttle public API usage
    return results

if __name__ == "__main__":
    ips = ["8.8.8.8", "104.16.0.0"] # Add your target list
    print(json.dumps(analyze_traffic(ips), indent=2))
```

**Takeaway:** A triage script that rapidly classifies outbound traffic to single out anomalous Datacenter proxy routing from standard Residential traffic.
