# Module 0x02: Infrastructure Mapping

## Overview

Tracking IPs and domains requires looking into the past. In this module, we focus on Passive DNS (pDNS) pivoting, Certificate Transparency (CT) log monitoring, and WHOIS history to track actor staging infrastructure.

## Key Concepts
* **Certificate Transparency (CT)**: Monitoring new TLS certs as they are issued in real-time.
* **pDNS**: Correlating domains to historical IP resolutions.
* **WHOIS patterns**: Tracking registrar and proxy behaviors.

---
## 🛠️ Module Project: CT Log Async Parser
*Reference: Hacking APIs*

Adversaries need TLS certificates to make their phishing or C2 sites look legitimate. We can catch them at the moment of registration.

### The Objective
1. Query the `crt.sh` JSON API asynchronously.
2. Search for newly issued certificates matching a specific phishing or DGA keyword (e.g., `microsoft-update`, `login-` or random entropy).
3. Resolve the returned domains to IPs.

### Boilerplate Setup
```python
# ct_hunter.py
import asyncio
import httpx
import json

async def fetch_ct_logs(keyword):
    url = f"https://crt.sh/?q={keyword}&output=json"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            if response.status_code == 200:
                return response.json()
        except:
            return []

async def main():
    keyword = "admin-auth"
    print(f"[*] Hunting CT logs for: {keyword}")
    results = await fetch_ct_logs(keyword)
    
    for entry in results[:10]:
        domain = entry.get('name_value')
        print(f"[+] Found Certificate for: {domain}")
        # Next step: Implement DNS resolution for each domain here

if __name__ == "__main__":
    asyncio.run(main())
```

**Takeaway:** A real-time threat intelligence feed alerting you the moment an adversary sets up a new domain containing your monitored keywords!
