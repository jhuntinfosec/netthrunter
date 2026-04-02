# Module 0x06: Edge Layer Obfuscation

## Overview

Modern adversaries hide behind Cloudflare, Fastly, or custom CDNs to obfuscate their true location and utilize verified TLS certificates. By analyzing Domain Fronting, Cloudflare Tunnels (Argo), and Web Application Firewall (WAF) evasions, we can bypass the edge and identify the backend.

## Key Concepts
* **Domain Fronting & Borrowing**: Exploiting CDN logic using `Host` vs `SNI` header mismatches.
* **Cloudflare Tunnels (Argo)**: Creating zero-trust inbound tunnels without internet-exposed ports or public DNS.
* **WAF Evasion Fingerprinting**: Identifying unique response headers when directly querying origin IPs behind a WAF.

---
## 🛠️ Module Project: HTTP Header Mismatch Tester
*Reference: Adversarial Tradecraft in Cybersecurity & Hacking APIs*

Your job is to write a tester that deliberately connects to a CDN Edge IP but requests a different inner `Host` header to simulate a domain front, or tests for origin IP exposure.

### The Objective
1. Initiate a TLS connection specifically pointing the SNI to an allowed high-reputation domain (e.g., `cdn.discordapp.com`).
2. Overwrite the HTTP `Host` header with the target malicious C2 domain.
3. Compare the response (e.g., 403 Forbidden vs 200 OK or a staged payload).

### Boilerplate Setup
```python
# cdn_edge_tester.py
import socket
import ssl

def check_domain_front(edge_ip, sni_target, host_header):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Wrap the socket with the legitimate SNI
        secure_sock = context.wrap_socket(sock, server_hostname=sni_target)
        secure_sock.connect((edge_ip, 443))
        
        # Send an HTTP request with the malicious Host!
        request = f"GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
        secure_sock.sendall(request.encode())
        
        response = secure_sock.recv(4096)
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e)
    finally:
        sock.close()

if __name__ == "__main__":
    edge_node = "104.18.2.1" # Example Cloudflare
    sni = "discord.com"
    target = "c2.malicious-actor.xyz"
    
    print(check_domain_front(edge_node, sni, target))
    # Parse the response to see if Cloudflare blocked it or routed it!
```

**Takeaway:** A script to rapidly test edge-layer misconfigurations and detect adversaries hiding behind legitimate CDN trust planes.
