# Module 0x03: Overlap & Clustering

## Overview

We move from flat lists to relationship graphs. If three IPs share an SSH key fingerprint and are hosted on the same "bulletproof" ASN, they are treated as a single cluster. This module covers identifying structural overlaps across seemingly disparate assets.

## Key Concepts
* **ASN Affinity**: Many threat actors prefer specific hosting providers that ignore DMCA/Abuse complaints.
* **Shared SSH Keys**: Adversaries often use automate infrastructure pipelines (Ansible/Terraform) spreading identical SSH Host Keys across multiple C2s.
* **Registrar Trends**: Correlating WHOIS patterns and the usage of specific Privacy Protect providers.

---
## 🛠️ Module Project: Tracking SSH Key Overlaps
*Reference: The Threat Hunter's Query Playbook*

We are going to hunt for adversaries creating identical infrastructure across different networks.

### The Objective
1. Query Shodan or Censys for an SSH Host Key (RSA or Ed25519 hash).
2. Retrieve the results.
3. Group the identified IP addresses by their Autonomous System Number (ASN) or ISP.

### Boilerplate Setup
```python
# ssh_clustering.py
import requests
import os

# Set your API keys as environmental variables
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

def search_ssh_hash(ssh_hash):
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=port:22+hash:{ssh_hash}"
    try:
        response = requests.get(url).json()
        return response.get("matches", [])
    except Exception as e:
        print(f"Error querying Shodan: {e}")
        return []

if __name__ == "__main__":
    target_ssh_hash = "f1:2a:..." # Replace with a known bad hash
    nodes = search_ssh_hash(target_ssh_hash)
    
    asn_groups = {}
    for node in nodes:
        ip = node.get("ip_str")
        asn = node.get("asn")
        # Step 2: Build the grouping dictionary here and output the results
```

**Takeaway:** A clustering logic script that transforms a single indicator into an actor's entire infrastructure map across multiple hosting providers!
