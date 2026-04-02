#!/usr/bin/env python3
"""
Module 0x06 Capstone Project: CDN & Edge Layer Analysis Toolkit
AIH-C (Advanced Infrastructure & Adversary Hunting Curriculum)

Analyzes CDN presence, WAF provider, Cloudflare Tunnel indicators, and
origin IP hypothesis testing via TLS certificate comparison.

Usage (offline demo — no network required):
    python cdn_tester.py

Usage (live analysis — authorized targets only):
    python cdn_tester.py -t cloudflare.com
    python cdn_tester.py -t a.com,b.com --format json
    python cdn_tester.py -f targets.txt --check-origin 198.51.100.10
    python cdn_tester.py --sni-test 104.18.2.1 discord.com test.example.com

See Module 0x09 for OPSEC guidance before live analysis.

@decision DEC-0x06-001
@title Mock-first architecture for offline demonstration
@status accepted
@rationale Running this tool against live infrastructure requires authorized
  targets. Mock mode provides full pedagogical value without requiring live
  targets, making the tool runnable in any training environment. All live
  functions degrade gracefully on network errors.

Cross-references:
  - Module 0x01: TLS fingerprinting (JARM/JA3) — cert serial comparison in
    origin verification re-uses the structural fingerprinting concept.
  - Module 0x02: Infrastructure mapping — origin discovery feeds directly
    into subdomain/ASN pivot workflows documented there.
"""

import argparse
import csv
import json
import socket
import ssl
import sys
import hashlib
from io import StringIO
from typing import Optional

# ── Optional dependency handling ───────────────────────────────────────────────
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


# ═══════════════════════════════════════════════════════════════════════════════
# CDN Signature Database
# ═══════════════════════════════════════════════════════════════════════════════

CDN_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server_values": ["cloudflare"],
        "cookies": ["__cf_bm", "__cflb", "__cfwaitingroom"],
        "error_codes": ["1020", "1010", "1015", "1000", "1001"],
        "ip_ranges_hint": ["104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22"],
    },
    "CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "server_values": [],
        "via_pattern": "cloudfront.net",
        "x_cache_values": ["Hit from cloudfront", "Miss from cloudfront"],
    },
    "Akamai": {
        "headers": ["x-akamai-session-info", "x-check-cacheable", "x-serial",
                    "x-akamai-transformed"],
        "server_values": ["akamaighost", "akamai"],
        "x_cache_pattern": "TCP_",
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "x-served-by", "x-cache-hits"],
        "server_values": [],
        "via_pattern": "varnish",
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server_values": ["sucuri/cloudproxy", "sucuri"],
    },
    "Imperva/Incapsula": {
        "headers": ["x-iinfo"],
        "cookies": ["incap_ses_", "visid_incap_", "_incap_ref_"],
    },
    "BunnyCDN": {
        "headers": ["bunnycdn-cache-status", "cdn-requestid"],
        "server_values": ["bunnycdn"],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Response Database (offline demonstration)
# ═══════════════════════════════════════════════════════════════════════════════

MOCK_RESPONSES = {
    "cloudflare-demo.example.com": {
        "status": "HTTP/1.1 200 OK",
        "headers": {
            "server": "cloudflare",
            "cf-ray": "7f2a8b3c4d5e6f78-IAD",
            "cf-cache-status": "DYNAMIC",
            "cf-request-id": "0a1b2c3d4e5f",
            "content-type": "text/html; charset=UTF-8",
        },
        "body": "<html><body>Mock Cloudflare-proxied response</body></html>",
        "cdn": "Cloudflare",
        "cname": None,
        "origin_ip": "198.51.100.10",
    },
    "cloudfront-demo.example.com": {
        "status": "HTTP/1.1 200 OK",
        "headers": {
            "x-amz-cf-id": "ABC123xyz_DEFGH",
            "x-amz-cf-pop": "IAD89-C1",
            "x-cache": "Miss from cloudfront",
            "via": "1.1 abc123.cloudfront.net (CloudFront)",
            "content-type": "text/html",
        },
        "body": "<html><body>Mock CloudFront response</body></html>",
        "cdn": "CloudFront",
        "cname": None,
        "origin_ip": "198.51.100.20",
    },
    "akamai-demo.example.com": {
        "status": "HTTP/1.1 200 OK",
        "headers": {
            "x-akamai-session-info": "name=AMSA_CONTENT_TYPE_PROFILE; value=12345",
            "x-serial": "12345",
            "x-check-cacheable": "YES",
            "x-cache": "TCP_MISS from a23-77-89-12.deploy.akamaitechnologies.com",
            "server": "AkamaiGHost",
        },
        "body": "<html><body>Mock Akamai response</body></html>",
        "cdn": "Akamai",
        "cname": None,
        "origin_ip": "198.51.100.30",
    },
    "argo-tunnel-demo.example.com": {
        "status": "HTTP/1.1 200 OK",
        "headers": {
            "server": "cloudflare",
            "cf-ray": "8a3b4c5d6e7f8901-DFW",
            "cf-cache-status": "DYNAMIC",
        },
        "body": "<html><body>Mock Cloudflare Tunnel (Argo) response</body></html>",
        "cdn": "Cloudflare",
        "cname": "a1b2c3d4e5f6789012345678.cfargotunnel.com",
        "origin_ip": None,  # Tunnel: no exposed origin IP
    },
    "direct-origin.example.com": {
        "status": "HTTP/1.1 200 OK",
        "headers": {
            "server": "nginx/1.24.0",
            "content-type": "text/html",
            "x-powered-by": "PHP/8.1",
        },
        "body": "<html><body>Direct origin — no CDN detected</body></html>",
        "cdn": None,
        "cname": None,
        "origin_ip": "203.0.113.45",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# CDN Detection
# ═══════════════════════════════════════════════════════════════════════════════

def detect_cdn_from_headers(headers: dict) -> tuple:
    """
    Classify CDN provider from HTTP response headers.

    Returns (cdn_name, matched_signals) where cdn_name is None if no CDN
    detected. matched_signals lists the specific header/cookie names that
    triggered the match — useful for report output.

    @decision DEC-0x06-002
    @title Multi-signal scoring over single-header matching
    @status accepted
    @rationale Single-header matching produces false positives (e.g., 'server:
      cloudflare' can be spoofed). Scoring multiple independent signals reduces
      false positive rate. The CDN with the highest signal count wins.
    """
    normalized = {k.lower(): v.lower() for k, v in headers.items()}
    scores = {}

    for cdn_name, sig in CDN_SIGNATURES.items():
        matched = []

        # Check named headers
        for h in sig.get("headers", []):
            if h.lower() in normalized:
                matched.append(h)

        # Check server header values
        server_val = normalized.get("server", "")
        for sv in sig.get("server_values", []):
            if sv in server_val:
                matched.append(f"server:{sv}")

        # Check Via header pattern
        via_pattern = sig.get("via_pattern", "")
        if via_pattern and via_pattern in normalized.get("via", ""):
            matched.append(f"via:{via_pattern}")

        # Check x-cache patterns
        x_cache_pattern = sig.get("x_cache_pattern", "")
        if x_cache_pattern and x_cache_pattern in normalized.get("x-cache", ""):
            matched.append(f"x-cache:{x_cache_pattern}")

        # Check x-cache specific values (CloudFront)
        for xcv in sig.get("x_cache_values", []):
            if xcv.lower() in normalized.get("x-cache", ""):
                matched.append(f"x-cache:{xcv}")

        # Check cookies (set-cookie header)
        cookie_header = normalized.get("set-cookie", "")
        for ck in sig.get("cookies", []):
            if ck in cookie_header:
                matched.append(f"cookie:{ck}")

        if matched:
            scores[cdn_name] = matched

    if not scores:
        return None, []

    best = max(scores, key=lambda k: len(scores[k]))
    return best, scores[best]


def classify_waf(status_code: int, headers: dict, body: str) -> Optional[str]:
    """
    Attempt WAF provider classification from response status, headers, and body.

    @decision DEC-0x06-003
    @title Body-pattern matching as WAF fallback
    @status accepted
    @rationale Header-only WAF detection misses cases where operators strip
      identifying headers. Body patterns (error page text, reference ID formats)
      provide a secondary signal.
    """
    normalized_headers = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()

    if "cf-ray" in normalized_headers:
        for code in ["1020", "1010", "1015"]:
            if code in body:
                return f"Cloudflare WAF (block code {code})"
        return "Cloudflare WAF"

    if "x-amz-cf-id" in normalized_headers:
        if "request blocked" in body_lower or "error" in body_lower:
            return "AWS WAF / CloudFront"
        return "AWS CloudFront (WAF status unclear)"

    if "x-akamai-session-info" in normalized_headers:
        return "Akamai WAF"
    if "reference #" in body_lower and "akamai" in body_lower:
        return "Akamai WAF (body pattern)"

    if "x-sucuri-id" in normalized_headers or "sucuri/cloudproxy" in normalized_headers.get("server", ""):
        return "Sucuri WAF"

    if "x-iinfo" in normalized_headers or "incap_ses_" in normalized_headers.get("set-cookie", ""):
        return "Imperva/Incapsula WAF"

    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Cloudflare Tunnel Detection
# ═══════════════════════════════════════════════════════════════════════════════

def check_cloudflare_tunnel(domain: str, mock_cname: Optional[str] = None) -> dict:
    """
    Check for Cloudflare Tunnel (Argo) indicators via DNS.

    Looks for:
    - CNAME resolution to *.cfargotunnel.com
    - TXT records at _cf-tunnel.{domain}

    The cfargotunnel.com CNAME target encodes a UUID that uniquely identifies
    the tunnel. When detected, the origin IP is not discoverable — the tunnel
    is outbound-only from the operator's host to Cloudflare edge.
    """
    result = {
        "tunnel_detected": False,
        "cname": None,
        "tunnel_id": None,
        "method": None,
    }

    # Mock path (for offline demo)
    if mock_cname is not None:
        if "cfargotunnel.com" in mock_cname:
            tunnel_id = mock_cname.split(".cfargotunnel.com")[0]
            result.update({
                "tunnel_detected": True,
                "cname": mock_cname,
                "tunnel_id": tunnel_id,
                "method": "CNAME (mock)",
            })
        return result

    # Live DNS path
    if not HAS_DNSPYTHON:
        result["method"] = "skipped (dnspython not installed; pip install dnspython)"
        return result

    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname_target = str(rdata.target).rstrip(".")
            if "cfargotunnel.com" in cname_target:
                tunnel_id = cname_target.replace(".cfargotunnel.com", "")
                result.update({
                    "tunnel_detected": True,
                    "cname": cname_target,
                    "tunnel_id": tunnel_id,
                    "method": "CNAME",
                })
                return result
    except Exception:
        pass

    # TXT record check at _cf-tunnel.domain
    try:
        txt_domain = f"_cf-tunnel.{domain}"
        answers = dns.resolver.resolve(txt_domain, "TXT")
        for rdata in answers:
            result.update({
                "tunnel_detected": True,
                "cname": None,
                "tunnel_id": str(rdata),
                "method": "TXT",
            })
            return result
    except Exception:
        pass

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# TLS Certificate Comparison (Origin Verification)
# ═══════════════════════════════════════════════════════════════════════════════

def get_cert_fingerprint(host: str, port: int = 443,
                         sni: Optional[str] = None) -> Optional[str]:
    """
    Retrieve SHA-256 fingerprint of TLS certificate from host:port.

    Cross-references Module 0x01 (Structural Fingerprinting): certificate
    serial numbers and fingerprints are the same structural artifacts used in
    JA3S/JARM analysis. A matching fingerprint across CDN and direct-origin
    connections confirms the origin with high confidence.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    server_hostname = sni if sni else host

    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    return hashlib.sha256(cert_der).hexdigest()
    except Exception:
        return None

    return None


def verify_origin_ip(domain: str, candidate_ip: str, port: int = 443) -> dict:
    """
    Compare TLS certificate on candidate_ip to certificate served by domain.

    A matching fingerprint means the candidate IP presents the same certificate
    as the CDN-fronted domain — strong evidence this is the true origin.

    @decision DEC-0x06-004
    @title Certificate fingerprint comparison over CN/SAN matching
    @status accepted
    @rationale CN/SAN matching is susceptible to wildcard certificates that
      cover many unrelated domains on the same CDN. SHA-256 fingerprint
      comparison of the DER-encoded certificate is exact — matches only when
      the same certificate object is presented, eliminating wildcard false
      positives.
    """
    result = {
        "domain": domain,
        "candidate_ip": candidate_ip,
        "cdn_fingerprint": None,
        "origin_fingerprint": None,
        "match": False,
        "error": None,
    }

    cdn_fp = get_cert_fingerprint(domain, port, sni=domain)
    result["cdn_fingerprint"] = cdn_fp

    origin_fp = get_cert_fingerprint(candidate_ip, port, sni=domain)
    result["origin_fingerprint"] = origin_fp

    if cdn_fp and origin_fp:
        result["match"] = (cdn_fp == origin_fp)
    elif not cdn_fp:
        result["error"] = "Could not retrieve CDN certificate"
    elif not origin_fp:
        result["error"] = f"Could not connect to candidate origin {candidate_ip}:{port}"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# SNI Mismatch Test (original module functionality, preserved)
# ═══════════════════════════════════════════════════════════════════════════════

def test_sni_mismatch(edge_ip: str, sni: str, host_header: str,
                      port: int = 443) -> dict:
    """
    Connect to edge_ip with TLS SNI=sni, send HTTP request with Host=host_header.

    Tests whether the CDN routes based on the inner Host header independently
    of the outer SNI — the domain fronting detection primitive. If the CDN
    returns HTTP 421 (Misdirected Request), SNI/Host consistency is enforced.
    If it returns 200, routing separation is possible.

    Used for: detecting CDN routing policy, confirming fronting mitigations,
    or understanding how a specific CDN node handles mismatch cases.
    """
    result = {
        "edge_ip": edge_ip,
        "sni": sni,
        "host_header": host_header,
        "status_line": None,
        "response_headers": {},
        "verdict": None,
        "error": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((edge_ip, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"User-Agent: AIH-C-Scanner/1.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                ssock.sendall(request.encode())

                response = b""
                while True:
                    data = ssock.recv(4096)
                    if not data:
                        break
                    response += data
                    if len(response) > 16384:
                        break

        decoded = response.decode("utf-8", errors="ignore")
        lines = decoded.splitlines()
        result["status_line"] = lines[0] if lines else "No response"

        # Parse response headers
        headers = {}
        for line in lines[1:]:
            if not line.strip():
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        result["response_headers"] = headers

        # Interpret result
        status = result["status_line"]
        if "421" in status:
            result["verdict"] = "BLOCKED: Misdirected Request (CDN enforces SNI/Host consistency)"
        elif "403" in status or "Forbidden" in status:
            result["verdict"] = "BLOCKED: WAF or firewall rule active"
        elif "200" in status:
            cdn, signals = detect_cdn_from_headers(headers)
            if cdn:
                result["verdict"] = f"ROUTED: Response from CDN ({cdn}) — check Host routing"
            else:
                result["verdict"] = "ROUTED: 200 OK — possible front success or passthrough"
        else:
            result["verdict"] = f"INCONCLUSIVE: {status}"

    except Exception as e:
        result["error"] = str(e)
        result["verdict"] = f"ERROR: {e}"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Live HTTP Probe
# ═══════════════════════════════════════════════════════════════════════════════

def probe_domain(domain: str, port: int = 443) -> dict:
    """
    Perform a live HTTPS probe of domain and return headers and body excerpt.

    Uses stdlib urllib to avoid external dependencies. HTTP/2 support requires
    httpx (optional; not enforced here to keep zero-dependency baseline).

    Note: urllib follows redirects by default. Set redirect policy if needed
    for precise status code capture.
    """
    result = {
        "domain": domain,
        "status_code": None,
        "headers": {},
        "body_excerpt": "",
        "error": None,
    }

    if not HAS_URLLIB:
        result["error"] = "urllib not available"
        return result

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"https://{domain}:{port}/" if port != 443 else f"https://{domain}/"
        req = urllib.request.Request(url, headers={"User-Agent": "AIH-C-Scanner/1.0"})

        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            result["status_code"] = resp.status
            result["headers"] = dict(resp.headers)
            raw_body = resp.read(4096).decode("utf-8", errors="ignore")
            result["body_excerpt"] = raw_body[:500]

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["headers"] = dict(e.headers) if e.headers else {}
        try:
            result["body_excerpt"] = e.read(2048).decode("utf-8", errors="ignore")
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Mode (offline demonstration)
# ═══════════════════════════════════════════════════════════════════════════════

def run_mock_demo():
    """
    Demonstrate full analysis workflow using simulated CDN responses.

    Exercises all detection functions without making any live network
    connections. Safe to run in any environment.

    @decision DEC-0x06-005
    @title Mock mode as default entry point
    @status accepted
    @rationale Requiring live targets for a curriculum demo creates friction and
      ethical concerns. Mock mode provides identical code paths with simulated
      data, demonstrating all detection logic without network access. Students
      see real output format before attempting live analysis on authorized
      targets.
    """
    print("=" * 72)
    print("  AIH-C Module 0x06 — CDN & Edge Layer Analysis (MOCK DEMO)")
    print("  Simulated responses — no live network connections")
    print("=" * 72)

    for domain, mock_data in MOCK_RESPONSES.items():
        print(f"\n{'─' * 72}")
        print(f"  Target: {domain}")
        print(f"{'─' * 72}")

        headers = mock_data["headers"]
        body = mock_data["body"]
        status = mock_data["status"]
        status_code = int(status.split()[1])

        print(f"  [HTTP] {status}")
        print(f"  [HDR]  Response headers:")
        for k, v in headers.items():
            print(f"           {k}: {v}")

        # CDN Detection
        cdn_name, signals = detect_cdn_from_headers(headers)
        if cdn_name:
            print(f"\n  [CDN]  Provider  : {cdn_name}")
            print(f"  [CDN]  Signals   : {', '.join(signals)}")
        else:
            print(f"\n  [CDN]  No CDN detected — likely direct-to-origin")

        # WAF Fingerprinting
        waf = classify_waf(status_code, headers, body)
        if waf:
            print(f"  [WAF]  Provider  : {waf}")
        else:
            print(f"  [WAF]  No WAF fingerprint detected")

        # Cloudflare Tunnel Detection
        tunnel_result = check_cloudflare_tunnel(domain, mock_cname=mock_data.get("cname"))
        if tunnel_result["tunnel_detected"]:
            print(f"  [TUN]  CLOUDFLARE TUNNEL DETECTED")
            print(f"  [TUN]  CNAME     : {tunnel_result['cname']}")
            print(f"  [TUN]  Tunnel ID : {tunnel_result['tunnel_id']}")
            print(f"  [TUN]  Origin IP : NOT EXPOSED (Argo outbound-only tunnel)")
        else:
            origin_ip = mock_data.get("origin_ip")
            if origin_ip:
                print(f"  [TUN]  No Cloudflare Tunnel — candidate origin: {origin_ip}")
            else:
                print(f"  [TUN]  No Cloudflare Tunnel")

        # Summary verdict
        print(f"\n  [>>>]  VERDICT:", end=" ")
        if tunnel_result["tunnel_detected"]:
            print("Cloudflare Tunnel active. Origin not discoverable via DNS/cert.")
        elif cdn_name and mock_data.get("origin_ip"):
            print(
                f"{cdn_name} proxy confirmed. Pursue origin via DNS history, "
                f"email headers, cert match."
            )
        elif not cdn_name:
            print("Direct-to-origin. Enumerate ports, services, and cert SANs directly.")

    print(f"\n{'═' * 72}")
    print("  Mock demo complete.")
    print("  Use -t <domain> for live analysis (authorized targets only).")
    print(f"{'═' * 72}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Analysis Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_target(domain: str, check_origin_ip: Optional[str] = None,
                   deep: bool = False, port: int = 443) -> dict:
    """
    Run full analysis pipeline against a live domain.

    Steps:
    1. HTTP probe — retrieve headers and body
    2. CDN detection — classify provider from headers
    3. WAF fingerprinting — classify WAF from headers/body
    4. Cloudflare Tunnel detection — DNS CNAME/TXT check
    5. Origin verification — if check_origin_ip provided, compare certs
    """
    result = {
        "domain": domain,
        "cdn": None,
        "cdn_signals": [],
        "waf": None,
        "tunnel": None,
        "origin_verified": None,
        "probe": None,
        "error": None,
    }

    print(f"[*] Analyzing: {domain}")

    # Step 1: HTTP probe
    probe = probe_domain(domain, port=port)
    result["probe"] = probe

    if probe["error"] and not probe["headers"]:
        result["error"] = f"Probe failed: {probe['error']}"
        return result

    headers = probe["headers"]
    body = probe["body_excerpt"]
    status_code = probe["status_code"] or 0

    # Step 2: CDN detection
    cdn_name, signals = detect_cdn_from_headers(headers)
    result["cdn"] = cdn_name
    result["cdn_signals"] = signals

    # Step 3: WAF fingerprinting
    waf = classify_waf(status_code, headers, body)
    result["waf"] = waf

    # Step 4: Cloudflare Tunnel detection
    tunnel = check_cloudflare_tunnel(domain)
    result["tunnel"] = tunnel

    # Step 5: Origin certificate comparison (if requested)
    if check_origin_ip:
        print(f"[*] Verifying origin IP: {check_origin_ip}")
        origin_result = verify_origin_ip(domain, check_origin_ip, port=port)
        result["origin_verified"] = origin_result

    return result


def print_analysis_result(result: dict):
    """Human-readable report for a single analysis result."""
    domain = result["domain"]
    print(f"\n{'═' * 60}")
    print(f"  {domain}")
    print(f"{'═' * 60}")

    probe = result.get("probe") or {}
    if probe.get("status_code"):
        print(f"  Status     : {probe['status_code']}")

    if result.get("error"):
        print(f"  ERROR      : {result['error']}")
        return

    # CDN
    cdn = result.get("cdn")
    if cdn:
        print(f"  CDN        : {cdn}")
        print(f"  Signals    : {', '.join(result.get('cdn_signals', []))}")
    else:
        print(f"  CDN        : None detected (possible direct-to-origin)")

    # WAF
    waf = result.get("waf")
    print(f"  WAF        : {waf or 'None detected'}")

    # Tunnel
    tunnel = result.get("tunnel") or {}
    if tunnel.get("tunnel_detected"):
        print(f"  CF Tunnel  : DETECTED (ID: {tunnel.get('tunnel_id')})")
        print(f"  CNAME      : {tunnel.get('cname')}")
    else:
        print(f"  CF Tunnel  : Not detected")

    # Origin verification
    origin = result.get("origin_verified")
    if origin:
        match_str = "MATCH (origin confirmed)" if origin.get("match") else "NO MATCH"
        print(f"  Origin Cert: {match_str}")
        if origin.get("error"):
            print(f"  Cert Error : {origin['error']}")
        cdn_fp = origin.get("cdn_fingerprint") or ""
        origin_fp = origin.get("origin_fingerprint") or ""
        print(f"  CDN FP     : {cdn_fp[:16]}..." if cdn_fp else "  CDN FP     : N/A")
        print(f"  Origin FP  : {origin_fp[:16]}..." if origin_fp else "  Origin FP  : N/A")


# ═══════════════════════════════════════════════════════════════════════════════
# Output Formatters
# ═══════════════════════════════════════════════════════════════════════════════

def format_results(results: list, fmt: str) -> str:
    """Serialize results list to text, json, or csv."""
    if fmt == "json":
        return json.dumps(results, indent=2, default=str)

    if fmt == "csv":
        out = StringIO()
        fields = ["domain", "cdn", "waf", "tunnel_detected", "origin_match", "error"]
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            tunnel = r.get("tunnel") or {}
            origin = r.get("origin_verified") or {}
            writer.writerow({
                "domain": r.get("domain", ""),
                "cdn": r.get("cdn", ""),
                "waf": r.get("waf", ""),
                "tunnel_detected": tunnel.get("tunnel_detected", False),
                "origin_match": origin.get("match", ""),
                "error": r.get("error", ""),
            })
        return out.getvalue()

    # text: handled inline by print_analysis_result
    return ""


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cdn_tester.py",
        description="Module 0x06: CDN & Edge Layer Analysis Toolkit (AIH-C)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cdn_tester.py                          # Mock demo (offline, default)
  python cdn_tester.py -t cloudflare.com        # Live analysis of single domain
  python cdn_tester.py -t a.com,b.com           # Multiple targets
  python cdn_tester.py -f targets.txt           # Targets from file
  python cdn_tester.py -t cdn.example.com --check-origin 198.51.100.10
  python cdn_tester.py -t example.com --format json
  python cdn_tester.py --sni-test 104.18.2.1 discord.com test.example.com

AUTHORIZED USE ONLY. See Module 0x09 for OPSEC guidance.
        """,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-t", "--target",
        metavar="DOMAIN[,DOMAIN]",
        help="Comma-separated list of target domains",
    )
    target_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="File with one domain per line",
    )
    target_group.add_argument(
        "--sni-test",
        nargs=3,
        metavar=("EDGE_IP", "SNI", "HOST_HEADER"),
        help="SNI mismatch test: edge_ip sni host_header",
    )
    target_group.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="Run offline mock demonstration (default when no target given)",
    )

    parser.add_argument(
        "--check-origin",
        metavar="IP",
        help="Candidate origin IP to verify via cert fingerprint comparison",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep analysis (extended probes)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Target port (default: 443)",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Default: mock demo if no target specified
    if not args.target and not args.file and not args.sni_test and not args.mock:
        run_mock_demo()
        return

    if args.mock:
        run_mock_demo()
        return

    # SNI mismatch test (standalone mode)
    if args.sni_test:
        edge_ip, sni, host_header = args.sni_test
        print(f"[*] SNI Mismatch Test")
        print(f"    Edge IP     : {edge_ip}")
        print(f"    SNI         : {sni}")
        print(f"    Host Header : {host_header}")
        result = test_sni_mismatch(edge_ip, sni, host_header, port=args.port)
        print(f"\n[+] Status     : {result['status_line']}")
        print(f"[+] Verdict    : {result['verdict']}")
        if result["response_headers"]:
            cdn, signals = detect_cdn_from_headers(result["response_headers"])
            if cdn:
                print(f"[+] CDN        : {cdn} ({', '.join(signals)})")
        if result.get("error"):
            print(f"[!] Error      : {result['error']}")
        return

    # Collect targets
    targets = []
    if args.target:
        targets = [t.strip() for t in args.target.split(",") if t.strip()]
    elif args.file:
        try:
            with open(args.file) as fh:
                targets = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        print("[!] No targets specified.", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # Analyze all targets
    all_results = []
    for domain in targets:
        result = analyze_target(
            domain,
            check_origin_ip=args.check_origin,
            deep=args.deep,
            port=args.port,
        )
        all_results.append(result)

        if args.format == "text":
            print_analysis_result(result)

    # Non-text output
    if args.format in ("json", "csv"):
        print(format_results(all_results, args.format))


if __name__ == "__main__":
    main()
