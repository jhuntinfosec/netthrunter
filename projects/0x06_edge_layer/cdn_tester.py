#!/usr/bin/env python3
# Module 0x06 Capstone Project: Edge-Layer Mismatch Tester
# Fully Working Reference Solution

import socket
import ssl
import sys

def test_domain_front(edge_ip: str, allowed_sni: str, malicious_host: str, port: int = 443):
    """
    Connects to a CDN Edge Node using an 'allowed' SNI to establish the TLS tunnel,
    then requests a potentially blocked or hidden 'malicious_host' at the HTTP layer.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print(f"[*] Edge Routing via: {edge_ip}:{port}")
    print(f"[*] Tunnel SNI     : {allowed_sni}")
    print(f"[*] HTTP Host Header: {malicious_host}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)

    try:
        # Wrap socket specifically defining the allowed SNI
        secure_sock = context.wrap_socket(sock, server_hostname=allowed_sni)
        secure_sock.connect((edge_ip, port))
        
        # Forge the HTTP request inside the TLS tunnel
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {malicious_host}\r\n"
            f"User-Agent: AIH-C-Scanner/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        
        secure_sock.sendall(request.encode())
        
        # Pull response
        response = b""
        while True:
            data = secure_sock.recv(4096)
            if not data:
                break
            response += data
            if len(response) > 8192:  # Cut it off so we don't grab infinite streams
                break
                
        decoded = response.decode('utf-8', errors='ignore')
        
        # Parse output
        status_line = decoded.splitlines()[0] if decoded else "No response"
        print(f"\n[+] STATUS CODE   : {status_line}")
        
        if "403" in status_line or "Forbidden" in status_line:
            print("[✓] C2 or WAF actively blocking the mismatch.")
        elif "200 OK" in status_line:
            print("[!] DOMAIN FRONT SUCCESSFUL! C2 payload served.")
        else:
            print("[-] Inconclusive matching response. See headers:")
            print("\n".join(decoded.splitlines()[:10]))  # First 10 lines
            
    except Exception as e:
        print(f"[x] Connection failed: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    # Test values (these are standard harmless CDNs for lab purposes)
    # WARNING: To truly test a C2, you need the adversary's actual CDN IP and their registered domain
    CF_EDGE = "104.18.2.1"
    HARMLESS_SNI = "discord.com"
    MALICIOUS_C2_HOST = "a.malicious.example.com"
    
    test_domain_front(CF_EDGE, HARMLESS_SNI, MALICIOUS_C2_HOST)
