# Module 0x09: Hunter OPSEC

## Overview

Anti-scanning detection is a reality. Sophisticated actors monitor their own access logs for JARM/JA3 probes. If they see a specific scanner IP or fingerprint repeatedly, they will rotate their infra, block your range, or feed you false telemetry.

## Key Concepts
* **Identifying Researcher Traps**: Decoy C2 servers (honeypots) that actors monitor.
* **Distributed Hunting**: Using Serverless (AWS Lambda, Google Cloud Functions) to distribute your outbound requests and avoid IP bans.
* **Scanner Obfuscation**: Camouflaging your scanning tool's Python Requests/httpx HTTP headers and TLS signatures.

---
## 🛠️ Module Project: Distributed Scanner Deployment
*Reference: From Day Zero to Zero Day*

Instead of running a scanner script from your local machine, deploy it statelessly so it receives a new IP address every run from a pool of cloud provider endpoints.

### The Objective
1. Write a minimal Python script that fetches the `Server` header from an IP and calculates its JA3 fingerprint (using `jarm` or `ja3`).
2. Wrap this script inside an AWS Lambda, Azure Function, or Google Cloud Run container.
3. Trigger the function 10 times to demonstrate that the originating IP is entirely different on each run.

### Boilerplate Setup
```python
# lambda_scanner.py (For AWS Lambda)
import urllib.request
import json
import ssl

def lambda_handler(event, context):
    target = event.get('target', 'example.com')
    port = event.get('port', 443)
    
    # Establish a barebones TLS connection and pull the certificate details
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = f"https://{target}:{port}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Safari/537.36'})
        
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            server_header = response.getheader('Server')
            cert = response.getpeercert()
            
            return {
                'statusCode': 200,
                'target': target,
                'server_header': server_header,
                'cert_issuer': dict(x[0] for x in cert['issuer']) if cert else None
            }
            
    except Exception as e:
        return {
            'statusCode': 500,
            'error': str(e)
        }
```

**Takeaway:** A completely obfuscated scanning profile that blends your threat intelligence gathering in with generic cloud traffic, rendering adversary IP blocking useless.
