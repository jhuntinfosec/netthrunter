# Module 0x06: Edge Layer Obfuscation

## Overview

Modern adversaries hide behind Cloudflare, Fastly, or custom CDNs to obfuscate their true location and utilize verified TLS certificates. By analyzing Domain Fronting, Cloudflare Tunnels (Argo), and Web Application Firewall (WAF) evasions, we can bypass the edge and identify the backend.

## Key Concepts
* **Domain Fronting & Borrowing**: Exploiting CDN logic using `Host` vs `SNI` header mismatches.
* **Cloudflare Tunnels (Argo)**: Creating zero-trust inbound tunnels without internet-exposed ports or public DNS.
* **WAF Evasion Fingerprinting**: Identifying unique response headers when directly querying origin IPs behind a WAF.

---

## Domain Fronting: Deep Explanation

Domain fronting is one of the most sophisticated CDN abuse techniques documented in adversary tradecraft. Understanding it mechanically is prerequisite to detecting it.

### How CDN Edge Nodes Route Requests

A CDN operates as a distributed reverse proxy. When a client connects to a CDN edge node, two separate layers of routing occur:

**Layer 1: TLS Routing (SNI)**

During the TLS handshake, before any HTTP data is transmitted, the client sends a `ClientHello` message containing the Server Name Indication (SNI) extension. This plaintext field tells the edge node which certificate to present. CDN edge nodes terminate TLS using the certificate matching the SNI value.

```
Client → [TLS ClientHello: SNI=allowed.cdn-customer.com] → CDN Edge
CDN Edge → [TLS Certificate for allowed.cdn-customer.com] → Client
```

**Layer 2: HTTP Routing (Host Header)**

After the TLS tunnel is established, the client sends an HTTP request inside the encrypted channel. The `Host` header in this request is what the CDN uses to determine which backend origin to forward the request to. Critically, this value is encrypted inside TLS — the CDN reads it after decryption.

```
[Inside TLS Tunnel]
GET / HTTP/1.1
Host: c2.adversary-domain.com    ← CDN routes based on THIS
```

### The Domain Fronting Exploit

Domain fronting exploits the gap between these two routing decisions. The adversary:

1. Resolves a high-reputation CDN customer domain (e.g., `allowed.cdn-customer.com`) to get a CDN edge IP
2. Opens a TLS connection to that IP with `SNI=allowed.cdn-customer.com` (passes SNI inspection)
3. Sends an HTTP request with `Host: c2.adversary-domain.com` inside the tunnel
4. The CDN, having decrypted the request, forwards it to the origin registered for `c2.adversary-domain.com`

Network monitoring sees: encrypted traffic to `allowed.cdn-customer.com`. The actual destination is the adversary's C2. Both domains must be customers of the same CDN.

### Which CDNs Blocked It and When

| CDN | Status | Date | Notes |
|-----|--------|------|-------|
| AWS CloudFront | Blocked | April 2018 | Terminated Signal/Telegram accounts using fronting |
| Google GFE | Blocked | April 2018 | Concurrent enforcement with AWS |
| Cloudflare | Partially blocked | Ongoing | Requires domains on same account; worker-based routing complicates this |
| Azure CDN | Limited exposure | Varies | Some legacy routing configurations remained |
| Fastly | Case-by-case | Varies | Shared infrastructure creates edge cases |
| Akamai | Largely mitigated | Varies | Enterprise controls introduced |

The coordinated blocking in April 2018 was directly triggered by documented abuse. Signal was using fronting via `google.com` to bypass censorship in Egypt and Oman. Simultaneously, APT29 (Cozy Bear) was observed using the `meek-azure` transport from the Tor Project to route C2 traffic through `ajax.aspnetcdn.com` (a Microsoft Azure CDN endpoint) — a high-reputation domain that would pass most corporate DLP and proxy inspection rules.

### APT29 and meek-azure: A Documented Case

The meek pluggable transport was designed for Tor to defeat deep packet inspection. `meek-azure` specifically:

- Resolved `ajax.aspnetcdn.com` (Microsoft's CDN for ASP.NET libraries)
- Established TLS with SNI matching that domain
- Forwarded Tor traffic in the HTTP body with the legitimate `Host` header
- The Azure CDN passed the request to a Tor bridge registered under `ajax.aspnetcdn.com`

APT29 adopted this transport for C2 communication, making their traffic indistinguishable from standard CDN traffic at the network layer. This is documented in threat intelligence reports from 2017-2018.

---

## Domain Borrowing

Domain borrowing is a related but distinct technique that emerged as fronting controls were deployed.

### How It Differs from Domain Fronting

| Technique | SNI | Host Header | Requirement |
|-----------|-----|-------------|-------------|
| Domain Fronting | High-reputation domain | Adversary's domain | Both on same CDN |
| Domain Borrowing | Adversary's domain | Same or close | Shared IP pool overlap |

In domain borrowing, the adversary registers their own domain and onboards it to a CDN. They then craft traffic patterns that leverage the CDN's shared IP pool — the same IP ranges serve thousands of customers. Because the adversary's domain is legitimately registered on the CDN, SNI validation passes. The value to the adversary is reputational: traffic to their domain routes through CDN infrastructure with clean IP reputation.

The CDN's shared IP pool is the enabler. A Cloudflare edge IP serves both `legitimate-bank.com` and `adversary-c2.com`. Network blocklists cannot block the IP without collateral damage. Certificate transparency logs (see Module 0x02) may reveal newly registered CDN-fronted domains before they're used.

---

## Cloudflare Tunnel (Argo) Detection

Cloudflare Tunnels (`cloudflared`) represent a different class of infrastructure obfuscation that has become common in adversary toolkits due to its zero-cost, zero-configuration nature.

### How Cloudflare Tunnels Work

Traditional server hosting requires an inbound port exposed to the internet. Cloudflare Tunnels invert this:

```
[C2 Server] → outbound QUIC/443 → [Cloudflare Edge] ← inbound HTTPS ← [Victim/Implant]
```

The `cloudflared` daemon on the adversary's machine maintains a persistent outbound connection to Cloudflare's edge. Cloudflare edge nodes proxy inbound requests from victims/implants to the `cloudflared` daemon. The origin server never binds a public port. No firewall rules need modification. The origin IP is never exposed.

Abuse of free-tier tunnels is documented: adversaries have registered free Cloudflare accounts, created tunnels for C2 endpoints, and discarded accounts when burned — the operational cost is zero.

### Detection Indicators

**DNS CNAME Resolution**

Cloudflare Tunnel domains resolve to `*.cfargotunnel.com`:

```bash
dig CNAME target.adversary.com
# target.adversary.com → abc123def456.cfargotunnel.com
```

The CNAME target contains a UUID-format identifier unique to the tunnel. Once the tunnel is deleted, the CNAME target becomes invalid. Hunting for `cfargotunnel.com` CNAME records in passive DNS is a reliable detection signal.

**TXT Record Presence**

Tunnel verification records appear as TXT records:

```bash
dig TXT _cf-tunnel.target.adversary.com
```

**HTTP Response Headers**

Every response through a Cloudflare Tunnel carries Cloudflare edge headers:

| Header | Value Pattern | Significance |
|--------|--------------|--------------|
| `cf-ray` | `{16hex}-{airport-code}` | Cloudflare Ray ID — always present |
| `cf-cache-status` | `DYNAMIC`, `HIT`, `MISS` | Cache status |
| `server` | `cloudflare` | Server identification |
| `cf-request-id` | Hex string | Per-request tracking |

The `cf-ray` header format encodes the serving PoP (point of presence) as an IATA airport code suffix (e.g., `7f2a8b3c4d5e6f78-IAD` for Ashburn, VA). This can be used to infer approximate geographic routing.

**Behavioral Indicators**

- Port 443 is the only exposed port (no port 80 redirect, no SSH, no alternate ports)
- TLS certificate is issued to `cloudflare.com`, not the origin domain, when the tunnel uses Cloudflare's edge certificate
- HTTP/2 is enforced (Cloudflare edge always negotiates HTTP/2 with clients)
- Response latency patterns differ from direct-hosted infrastructure

---

## WAF Fingerprinting

Web Application Firewalls leave identifiable signatures in HTTP responses. Distinguishing WAF providers is valuable for infrastructure hunting: it narrows the suspect's hosting choices and reveals operational patterns.

### Cloudflare WAF

**Positive Indicators:**

| Signal | Pattern |
|--------|---------|
| `cf-ray` header | Always present: `{16hex}-{airport-code}` |
| `cf-cache-status` | `DYNAMIC`, `HIT`, `MISS`, `BYPASS` |
| `server` header | `cloudflare` |
| Block page HTTP status | `403` with error code `1020` (Access Denied by Firewall Rule) |
| Block page content | Contains `Cloudflare` branding and Ray ID |
| Cookie | `__cf_bm` (bot management), `__cflb` (load balancing) |

**Error Code Reference:**

- `1000` — DNS points to prohibited IP (CNAME loop)
- `1001` — DNS resolution failure
- `1006`/`1007`/`1008` — IP blocked
- `1010` — Browser check required
- `1015` — Rate limited
- `1020` — Firewall rule block (most common for WAF blocks)

### Akamai WAF

**Positive Indicators:**

| Signal | Pattern |
|--------|---------|
| `x-akamai-session-info` | Session metadata header |
| `x-check-cacheable` | Cache advisory |
| `x-serial` | Akamai serial number |
| `x-cache` | `TCP_HIT`, `TCP_MISS` from Akamai ghost nodes |
| Error page | Contains `Reference #` followed by a numeric ID |
| `x-akamai-transformed` | Transformation tracking |

Akamai block pages typically include a reference ID in the format `Reference #18.{hex}.{timestamp}.{hex}` which can be used to fingerprint the specific Akamai configuration.

### AWS WAF / CloudFront

**Positive Indicators:**

| Signal | Pattern |
|--------|---------|
| `x-amz-cf-id` | CloudFront request ID (always present) |
| `x-amz-cf-pop` | Serving edge PoP identifier (e.g., `IAD89-C1`) |
| `x-cache` | `Hit from cloudfront` or `Miss from cloudfront` |
| `via` | `1.1 {hash}.cloudfront.net (CloudFront)` |
| Block page | HTTP 403 with `ERROR: The request could not be satisfied` |
| Block page | References `CloudFront` and includes `Request ID` |

AWS WAF block responses return HTTP 403 with a minimal HTML page. The `x-amz-cf-id` header uniquely identifies the request in CloudFront logs — useful for correlating with leaked access logs during incident response.

### Sucuri WAF

**Positive Indicators:**

| Signal | Pattern |
|--------|---------|
| `x-sucuri-id` | Sucuri request identifier |
| `x-sucuri-cache` | `HIT` or `MISS` |
| Block page | Sucuri-branded firewall block page with incident ID |
| `server` | `Sucuri/Cloudproxy` |

Sucuri is common for WordPress sites. Adversaries using compromised WordPress infrastructure may transit Sucuri WAF unintentionally, revealing the WAF through response headers.

### Imperva / Incapsula WAF

**Positive Indicators:**

| Signal | Pattern |
|--------|---------|
| `incap_ses_*` cookies | Session tracking cookies |
| `visid_incap_*` cookies | Visitor identification |
| `x-iinfo` | Imperva internal routing info |
| Block page | Imperva-branded "Access Denied" with incident ID |
| `_incap_ref_*` cookie | Referral tracking |

Imperva is common in enterprise and financial sector deployments. The `incap_ses_*` cookie contains session data that can be correlated across requests.

---

## CDN Origin Discovery

When a CDN is confirmed, the next objective is identifying the true origin IP. This is the core pivot that connects CDN infrastructure to a physical host or cloud instance.

### Technique 1: DNS History (Pre-CDN Records)

Before an operator moved a domain behind a CDN, the domain's A record pointed directly to the origin. DNS history services retain these records.

**Tools:** SecurityTrails, PassiveTotal, VirusTotal graph, Shodan DNS history

```
SecurityTrails query: api.securitytrails.com/v1/history/{domain}/dns/a
```

Look for A records predating the CDN migration date. If the same IP appears in historical records and still hosts content, the origin has not changed. Validate by connecting directly and checking TLS certificate fingerprints (see Technique 5).

### Technique 2: Email Header Analysis

When domains send outbound email (newsletters, account notifications, password resets), the `Received:` headers in email metadata reveal the sending server's IP — often the unproxied origin.

```
Received: from mail.adversary.com ([203.0.113.45])
```

Email infrastructure is frequently not behind the CDN. If `mail.adversary.com` or the SPF record `ip4:` ranges overlap with the suspected C2 IP space, this is a strong indicator.

**Collection method:** Subscribe to any outbound email from the target domain. Parse `Received:` headers working from bottom to top — the bottom-most entry represents the true sending infrastructure.

### Technique 3: Direct IP Scanning and Certificate Matching

CDN operators use shared edge IPs. The origin is often a cloud instance or dedicated server that still serves HTTPS on port 443 — just not via the CDN's routing. The TLS certificate presented on the origin will match the certificate served through the CDN (both are issued for the same domain).

**Workflow:**
1. Obtain the CDN-served TLS certificate fingerprint (SHA-256)
2. Identify likely origin ASNs (cloud providers: AWS, Hetzner, OVH, DigitalOcean, Vultr)
3. Scan for IPs presenting identical certificate fingerprints
4. Direct connection to matching IP confirms origin

```bash
# Get CDN certificate fingerprint
echo | openssl s_client -connect cdn-domain.com:443 2>/dev/null | \
  openssl x509 -fingerprint -sha256 -noout

# Censys search for same fingerprint on non-CDN IPs
# Search: parsed.names: "target.domain.com" AND NOT ip: 104.16.0.0/12
```

This technique is documented in CloudFlair's methodology and is the most reliable origin discovery approach.

### Technique 4: Subdomain Exposure

CDN operators configure the apex domain and primary subdomains behind the CDN, but may leave ancillary subdomains unproxied:

- `staging.adversary.com` — development environments
- `vpn.adversary.com` — VPN endpoints
- `admin.adversary.com` — administrative interfaces
- `ftp.adversary.com` — legacy file transfer

Passive DNS enumeration (see Module 0x02: Infrastructure Mapping) reveals these subdomains. Any A record pointing outside the CDN IP ranges is a candidate origin.

### Technique 5: IPv6 Exposure

CDNs vary in their IPv6 support. Many operators configure IPv6 on their origin servers without routing that traffic through the CDN. DNS AAAA record queries for CDN-fronted domains may return:

- The CDN's IPv6 range (proxied — no useful information)
- The origin's IPv6 address (unproxied — direct pivot)

```bash
dig AAAA target-domain.com
```

IPv6 addresses often coexist with IPv4 on cloud instances. If an AAAA record resolves outside Cloudflare's `2606:4700::/32` or `2400:cb00::/32` ranges, it is likely the origin.

### Technique 6: SSL Certificate Matching via Censys

Censys indexes TLS certificates presented by hosts across the internet. Searching Censys for a certificate matching the CDN-served certificate reveals all IPs presenting that certificate — including origin servers not behind the CDN.

```
# Censys search syntax
parsed.names: "target.adversary.com"
```

Filter results to exclude known CDN IP ranges. Remaining results are candidate origins. Cross-validate by checking whether the certificate was issued before or after CDN migration.

This technique cross-references Module 0x01 (TLS fingerprinting) — certificate serial numbers and SANs (Subject Alternative Names) act as structural fingerprints that persist across CDN and origin.

---

## HTTP/2 and HTTP/3 Analysis

Protocol negotiation behavior provides CDN fingerprinting signals independent of response headers.

### ALPN Negotiation

Application-Layer Protocol Negotiation (ALPN) occurs during the TLS handshake. The client proposes supported protocols; the server selects one. CDN edge nodes consistently negotiate HTTP/2 (`h2`). Direct-to-origin connections to C2 frameworks often negotiate HTTP/1.1 or expose ALPN mismatches.

**Fingerprinting value:** A host advertising HTTP/2 support in ALPN but exhibiting HTTP/1.1 frame behavior may indicate a CDN bypass or misconfigured origin. This cross-references Module 0x01's TLS fingerprinting methodology — ALPN values are part of the JA3S fingerprint.

### HTTP/2 Settings Frames

HTTP/2 connections begin with a SETTINGS frame that configures the session. CDN edge nodes (Cloudflare, CloudFront, Fastly) have characteristic SETTINGS frame parameters:

- Initial window size
- Maximum concurrent streams
- Header table size
- Max frame size

These parameters differ between CDN providers and direct connections. Tools like `h2fingerprint` can extract these values for comparison.

### QUIC and HTTP/3

Cloudflare and Google CDN support HTTP/3 (QUIC). The `alt-svc` response header advertises QUIC availability:

```
alt-svc: h3=":443"; ma=86400
```

QUIC fingerprinting is an emerging technique (analogous to JA3 for TLS). The QUIC Initial packet contains version negotiation, connection ID lengths, and transport parameter ordering that differs between client implementations (Chromium, Firefox, curl, Go's `quic-go`). CDN edge nodes present a QUIC fingerprint distinct from direct-origin traffic.

---

## Tool Reference

| Tool | Purpose | URL |
|------|---------|-----|
| **CloudFlair** | Automated origin IP discovery behind Cloudflare | `github.com/christophetd/CloudFlair` |
| **CrimeFlare** | Historical Cloudflare-origin IP database | Public dataset |
| **Censys** | Certificate and banner search for origin discovery | `search.censys.io` |
| **SecurityTrails** | DNS history, subdomain enumeration | `securitytrails.com` |
| **Shodan** | `http.headers_hash`, CDN identification via banners | `shodan.io` |
| **wafw00f** | WAF fingerprinting via crafted HTTP requests | `github.com/EnableSecurity/wafw00f` |
| **MassDNS** | High-speed DNS resolution for subdomain enumeration | `github.com/blechschmidt/massdns` |
| **httpx** | HTTP probe with header extraction, HTTP/2 support | `github.com/projectdiscovery/httpx` |
| **dnsx** | DNS record resolution and enumeration | `github.com/projectdiscovery/dnsx` |

---

## Case Study: Uncovering a C2 Behind Cloudflare

The following walkthrough illustrates the complete origin discovery workflow against a hypothetical threat actor infrastructure.

### Phase 1: Initial CDN Detection

A suspicious domain `updates.cdn-distribution[.]com` appears in endpoint telemetry. Initial DNS resolution:

```
updates.cdn-distribution[.]com → 104.21.45.67  (Cloudflare IP range 104.16.0.0/12)
```

Response headers confirm Cloudflare:
```
server: cloudflare
cf-ray: 7f2a8b3c4d5e6f78-IAD
cf-cache-status: DYNAMIC
```

**Finding:** The domain is Cloudflare-proxied. The true origin is unknown.

### Phase 2: WAF Fingerprinting

HTTP probes to the domain return:
- Port 443: Cloudflare edge (confirmed by `cf-ray`)
- Port 80: 301 redirect to HTTPS
- Non-standard ports (8443, 8080): No response (origin ports not exposed)

A crafted request with invalid HTTP method triggers a Cloudflare 403 with error code `1020` — a firewall rule is active. The operator has configured Cloudflare WAF rules.

### Phase 3: DNS History Pivot

SecurityTrails query for `updates.cdn-distribution[.]com` DNS A record history:

```
2024-01-15: A → 185.220.101.45  (before Cloudflare migration)
2024-03-01: A → 104.21.45.67   (post-CDN migration)
```

The pre-CDN IP `185.220.101.45` is in Hetzner's ASN (AS24940). This is a candidate origin.

### Phase 4: Email Header Analysis

The domain's MX record points to `mail.cdn-distribution[.]com`. A legitimate-looking password reset email was captured during investigation. The `Received:` headers:

```
Received: from mail.cdn-distribution.com (185.220.101.45)
```

The mail server IP matches the historical A record. High confidence in origin.

### Phase 5: Direct Certificate Validation

Direct connection to `185.220.101.45:443`:

```bash
echo | openssl s_client -connect 185.220.101.45:443 -servername updates.cdn-distribution.com 2>/dev/null | openssl x509 -text -noout
```

The certificate presented on the direct IP is identical (same serial number, same SANs) to the certificate served through Cloudflare. Origin confirmed.

### Phase 6: Infrastructure Mapping

With the origin IP confirmed, standard infrastructure mapping (Module 0x02) proceeds:
- Reverse DNS of `185.220.101.45` → `vps-185-220-101-45.hetzner.com`
- Shodan scan history for the IP reveals open ports: 443, 8443, 50050 (Cobalt Strike default)
- Certificate SAN includes three additional domains
- Each additional domain shows the same DNS history pattern
- Infrastructure cluster identified: 4 domains, 2 IPs, all Hetzner ASN

---

## OPSEC Notes for Researchers

!!! warning "Authorized Use Only"
    All probing techniques in this module should be conducted only against infrastructure you own, have explicit written authorization to test, or are analyzing under responsible disclosure frameworks.

**CDN Logging:** Every request to a CDN-proxied domain is logged. Cloudflare logs include source IP, timestamp, request headers (including `User-Agent`), and `cf-ray` identifiers. WAF evasion attempts may trigger alert rules and notify the domain operator.

**Origin Probing:** Direct connections to suspected origin IPs may trigger host-based intrusion detection. If the origin is an active adversary's C2, your probe reveals your IP to the adversary.

**Distributed Probing:** Use separate infrastructure for probe traffic. Do not probe from corporate or personal networks. The CDN sees your real IP regardless of what headers you send.

**Rate Limiting:** CDNs enforce rate limits. Aggressive scanning triggers Cloudflare's `1015` error (rate limited) and may result in IP blocks that affect unrelated traffic from your IP range.

**Certificate Transparency:** Your Censys searches may be logged. Consider that searching for a specific certificate fingerprint signals investigative interest to any party monitoring Censys search patterns.

---

## 🛠️ Module Project: CDN & Edge Layer Analysis Tool

*Reference: Adversarial Tradecraft in Cybersecurity & Hacking APIs*

The capstone project expands the original SNI mismatch tester into a full CDN analysis toolkit covering detection, WAF fingerprinting, tunnel identification, and origin hypothesis testing.

### The Objective

1. **CDN Detection** — Identify which CDN (if any) fronts a target domain via response header analysis.
2. **WAF Fingerprinting** — Classify the WAF provider from header patterns and error page signatures.
3. **Cloudflare Tunnel Detection** — Resolve DNS to check for `cfargotunnel.com` CNAME patterns.
4. **Origin Verification** — Given a candidate origin IP, compare its TLS certificate to the CDN-served certificate.
5. **SNI Mismatch Test** — Replicate the original domain fronting test to confirm or deny fronting capability.
6. **Mock Mode** — Full offline demonstration with simulated CDN responses (Cloudflare, CloudFront, Akamai, direct-origin).

### Project Code

```python
#!/usr/bin/env python3
"""
Module 0x06 Capstone Project: CDN & Edge Layer Analysis Toolkit
AIH-C (Advanced Infrastructure & Adversary Hunting Curriculum)

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
        "origin_ip": None,  # Tunnel — no exposed origin IP
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

def detect_cdn_from_headers(headers: dict) -> tuple[Optional[str], list[str]]:
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
      false positive rate. The CDN with the highest signal count wins. Ties
      default to the first match.
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
      provide a secondary signal. Body matching is applied only when header
      signals are ambiguous or absent.
    """
    normalized_headers = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body.lower()

    # Cloudflare: error codes in body, cf-ray in headers
    if "cf-ray" in normalized_headers:
        for code in ["1020", "1010", "1015"]:
            if code in body:
                return f"Cloudflare WAF (block code {code})"
        return "Cloudflare WAF"

    # CloudFront
    if "x-amz-cf-id" in normalized_headers:
        if "request blocked" in body_lower or "error" in body_lower:
            return "AWS WAF / CloudFront"
        return "AWS CloudFront (WAF status unclear)"

    # Akamai — reference ID pattern in body
    if "x-akamai-session-info" in normalized_headers:
        return "Akamai WAF"
    if "reference #" in body_lower and "akamai" in body_lower:
        return "Akamai WAF (body pattern)"

    # Sucuri
    if "x-sucuri-id" in normalized_headers or "sucuri/cloudproxy" in normalized_headers.get("server", ""):
        return "Sucuri WAF"

    # Imperva/Incapsula
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

    Returns a dict with 'tunnel_detected', 'cname', 'tunnel_id'.
    """
    result = {"tunnel_detected": False, "cname": None, "tunnel_id": None, "method": None}

    # Mock path
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
        # Fallback: stdlib socket won't give CNAME, use getaddrinfo heuristic
        result["method"] = "skipped (dnspython not installed)"
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

def get_cert_fingerprint(host: str, port: int = 443, sni: Optional[str] = None) -> Optional[str]:
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
      comparison of the DER-encoded certificate is exact — it matches if and
      only if the same certificate is presented, eliminating wildcard false
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

    # Get CDN-served certificate (connect to domain, let DNS resolve)
    cdn_fp = get_cert_fingerprint(domain, port, sni=domain)
    result["cdn_fingerprint"] = cdn_fp

    # Get direct-origin certificate
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

def test_sni_mismatch(edge_ip: str, sni: str, host_header: str, port: int = 443) -> dict:
    """
    Connect to edge_ip with TLS SNI=sni, send HTTP request with Host=host_header.

    Tests whether the CDN routes based on the inner Host header independently
    of the outer SNI — the domain fronting primitive. This is the detection
    baseline: if the response differs from a normal request to host_header,
    the CDN enforces SNI/Host consistency.

    This function does NOT proxy traffic through an active C2; it probes
    CDN routing behavior for research purposes.
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

    Uses stdlib urllib to avoid external dependencies. Falls back to HTTP/1.1
    raw socket if urllib fails. HTTP/2 support requires httpx (optional).
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

    Exercises all detection functions (CDN identification, WAF fingerprinting,
    tunnel detection, origin comparison) without making any live network
    connections. Safe to run in any environment.

    @decision DEC-0x06-005
    @title Mock mode as default entry point
    @status accepted
    @rationale Requiring live targets for a curriculum demo creates friction and
      ethical concerns. Mock mode provides identical code paths with simulated
      data, demonstrating all detection logic without network access. Students
      see real output format before attempting live analysis.
    """
    print("=" * 72)
    print("  AIH-C Module 0x06 — CDN & Edge Layer Analysis (MOCK DEMO)")
    print("  Simulated responses — no live network connections")
    print("=" * 72)

    for domain, mock_data in MOCK_RESPONSES.items():
        print(f"\n{'─' * 72}")
        print(f"  Target: {domain}")
        print(f"{'─' * 72}")

        # Simulate HTTP probe
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
            print(f"{cdn_name} proxy confirmed. Pursue origin via DNS history, "
                  f"email headers, cert match.")
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
                   deep: bool = False) -> dict:
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
    probe = probe_domain(domain)
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
        origin_result = verify_origin_ip(domain, check_origin_ip)
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
        print(f"  CDN FP     : {origin.get('cdn_fingerprint', 'N/A')[:16]}...")
        print(f"  Origin FP  : {origin.get('origin_fingerprint', 'N/A')[:16]}...")


# ═══════════════════════════════════════════════════════════════════════════════
# Output Formatters
# ═══════════════════════════════════════════════════════════════════════════════

def format_results(results: list[dict], fmt: str) -> str:
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

    # Default: text (print_analysis_result handles this inline)
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
  python cdn_tester.py                          # Mock demo (offline)
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
        help="Candidate origin IP to verify via cert comparison",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep analysis (extended probes, HTTP/2 detection)",
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
                targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
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
        )
        all_results.append(result)

        if args.format == "text":
            print_analysis_result(result)

    # Non-text output
    if args.format in ("json", "csv"):
        print(format_results(all_results, args.format))


if __name__ == "__main__":
    main()
```

**Takeaway:** A modular CDN analysis toolkit that classifies CDN providers, fingerprints WAF deployments, detects Cloudflare Tunnels via DNS, and verifies origin IPs through certificate comparison — the complete edge-layer hunting workflow.
