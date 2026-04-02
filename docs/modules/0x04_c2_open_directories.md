# Module 0x04: C2 & Open Directories

## Overview

Identifying the exact Command and Control (C2) software allows us to understand the adversary's capabilities. This module discusses framework-specific fingerprints and how to hunt for misconfigured, public open directories exposing malicious payloads.

## Key Concepts
* **Advanced Dorking**: Searching exposed file systems via Google, Shodan, or custom web scanners.
* **Framework Fingerprints**: Cobalt Strike (checksums, stagers, Malleable profiles), Sliver, Havoc, Mythic.
* **Stager Profiling**: Differentiating between default stagers and bespoke web servers.

---
## 🛠️ Module Project: Custom Web Scanner for Stagers
*Reference: Black Hat Go & Black Hat Python*

Your goal is to parse arbitrary web servers for signs of default Cobalt Strike URI stagers or exposed directories containing `.bin` payloads.

### The Objective
1. Read a list of potential malicious endpoints.
2. Send HTTP requests and analyze the `Server` or `X-Powered-By` headers.
3. Attempt to fetch a common default Cobalt Strike URL path (e.g. `1234.bin` or calculate a URI checksum).
4. Alert if an open directory is encountered (regex for "Index of /").

### Boilerplate Setup (Python implementation)
```python
# c2_dorker.py
import httpx
import re

async def check_directory_listing(url):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=5.0)
            if "Index of /" in resp.text:
                print(f"[!] Open Directory Found: {url}")
                # Extra: Extract the .bin or .ps1 files listed using bs4 or regex
                payloads = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
                return payloads
    except:
        pass
    return None

# Your Turn: Write the main execution loop to read URLs from a file and async them!
```

**Takeaway:** An automated recon tool capable of indexing and downloading stagers left open by lazy adversaries!
