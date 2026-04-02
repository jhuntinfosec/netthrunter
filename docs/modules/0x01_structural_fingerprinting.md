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
# jarm_scanner.py
import socket
import ssl
import sys

def send_hello(ip, port, hello_bytes):
    # Setup socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((ip, port))
        s.send(hello_bytes)
        data = s.recv(1484)
        return data
    except Exception as e:
        return None
    finally:
        s.close()

if __name__ == "__main__":
    target = sys.argv[1]
    print(f"[*] Scanning {target} for TLS Fingerprint...")
    # Add your JARM logic here natively or by importing the jarm core
```

**Takeaway:** A valid JSON output mapping IPs to JARM hashes that can be fed into Shodan or Censys for clustering in future modules!
