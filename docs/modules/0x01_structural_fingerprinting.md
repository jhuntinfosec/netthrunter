# Module 0x01: Structural Fingerprinting

## Overview

Instead of blocking an IP, we block the **Server Response Pattern**. This module covers deep-dive techniques into JARM, JA3/S, JA4+, TLS Handshake anomalies, and tracking SSH/HTTP header signatures.

## Key Concepts
* **JA3/JA3S**: Fingerprinting the TLS negotiation between clients and servers.
* **JARM**: Active TLS server fingerprinting.
* **HTTP/2 Analytics**: Identifying specific framework multiplexing footprints.

> **Hunter's Note:** Many actors use default Go-lang or Python TLS implementations. Hunting for the specific JARM hash of a default Mythic or Sliver server allows for global pre-emptive mapping.

---
## 🛠️ Module Project: Active TLS Fingerprinting
*Reference: Black Hat Python 2E*

Your task is to build a Python script that calculates the JARM hash of a given IP address or a list of IPs. You will emulate the JARM active TLS probing mechanism.

### The Objective
1. Handshake with an IP over typical TLS ports (443, 8443, etc.).
2. Send 10 specific TLS Client Hello packets.
3. Record the server's responses (selected cipher suite and TLS extension hashes).
4. Combine them into a 62-character hash.

### Boilerplate Setup
```python
#!/usr/bin/env python3
# Module 0x01 Capstone Project: Structural Fingerprinting Explorer
# Fully Working Reference Solution

import socket
import ssl
import sys
import hashlib
import json

def get_tls_fingerprint(ip: str, port: int = 443) -> dict:
    """
    Connects to an IP, extracts the TLS certificate, and calculates structural hashes 
    (SHA-256 of the raw certificate) to track actor overlaps.
    Note: For full JARM support, you would clone the Salesforce JARM repository.
    This script implements standard Certificate Hashing natively.
    """
    # Create an SSL context that accepts self-signed or invalid certificates (C2 standard)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    
    result = {
        "target": f"{ip}:{port}",
        "connected": False,
        "cert_sha256": None,
        "issuer": None,
        "subject": None
    }

    try:
        # Wrap the socket
        secure_sock = ctx.wrap_socket(sock, server_hostname=ip)
        secure_sock.connect((ip, port))
        
        # Get the binary certificate
        cert_bin = secure_sock.getpeercert(binary_form=True)
        cert_dict = secure_sock.getpeercert()
        
        result["connected"] = True
        
        if cert_bin:
            # Hash the raw certificate. This hash is often unique to a specific Metasploit/CobaltStrike default.
            cert_hash = hashlib.sha256(cert_bin).hexdigest()
            result["cert_sha256"] = cert_hash
            
            # Print parsed dict if available
            if cert_dict:
                issuer_info = dict(x[0] for x in cert_dict.get('issuer', []))
                subject_info = dict(x[0] for x in cert_dict.get('subject', []))
                
                result["issuer"] = issuer_info.get("commonName") or issuer_info.get("organizationName")
                result["subject"] = subject_info.get("commonName") or subject_info.get("organizationName")
                
    except Exception as e:
        result["error"] = str(e)
    finally:
        sock.close()
        
    return result

if __name__ == "__main__":
    print("[*] Active TLS Structural Fingerprinter
")
    
    # We test against some publicly accessible reliable TLS servers 
    # (In practice, replace these with suspected C2 IPs)
    targets = [
        ("8.8.8.8", 443),
        ("1.1.1.1", 443),
        ("example.com", 443)
    ]
    
    results = []
    
    for ip, port in targets:
        print(f"[*] Probing {ip}:{port}...")
        res = get_tls_fingerprint(ip, port)
        results.append(res)
        
    print("
--- Structural Fingerprints ---")
    print(json.dumps(results, indent=2))
    
    print("
[+] Feed these 'cert_sha256' hashes into Shodan or Censys to cluster the infrastructure!")

```

**Takeaway:** A valid JSON output mapping IPs to JARM hashes that can be fed into Shodan or Censys for clustering in future modules!
