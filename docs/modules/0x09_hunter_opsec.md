# Module 0x09: Hunter OPSEC

## Overview

Anti-scanning detection is a reality. Sophisticated actors monitor their own access logs for JARM/JA3 probes. If they see a specific scanner IP or fingerprint repeatedly, they will rotate their infra, block your range, or feed you false telemetry.

This module teaches the defensive researcher how to conduct authorized threat hunting without exposing their identity or tipping off the adversary. Every technique here serves one purpose: **protecting the researcher** while investigating adversary infrastructure identified through Modules 0x01-0x08.

!!! danger "Authorized Use Only"
    All scanning and probing techniques in this module are for **authorized defensive research only**. Document your scope, get written authorization, and follow your organization's rules of engagement. Unauthorized scanning is illegal under the CFAA (US), Computer Misuse Act (UK), and equivalent laws worldwide.

## Key Concepts

* **Identifying Researcher Traps**: Decoy C2 servers (honeypots) that actors monitor for visitors.
* **Distributed Hunting**: Using Serverless (AWS Lambda, Google Cloud Functions) to distribute outbound requests and avoid IP-based blocking.
* **Scanner Fingerprint Management**: Understanding how your tools' TLS and HTTP signatures identify you, and how to configure them to blend with normal traffic.
* **Legal Frameworks**: Operating within authorized scope with documented rules of engagement.

---

## How Actors Detect Researchers

Sophisticated threat actors actively monitor their infrastructure for scanning activity. Understanding their detection methods is essential for effective hunting.

### TLS Fingerprinting of Scanners

Every TLS client produces a JA3 fingerprint based on its Client Hello parameters (see Module 0x01). Common scanning tools have well-known JA3 hashes:

| Tool | JA3 Hash (Truncated) | Why It's Distinctive |
|------|----------------------|---------------------|
| Python `requests` (urllib3) | `769,47-53-5-10-49171...` | Limited cipher suites, no GREASE, Python-specific extension order |
| Python `httpx` | Similar to requests | Same underlying `ssl` module defaults |
| `curl` (default) | Varies by OpenSSL version | Stable per-version, documented in ja3er.com |
| Go `net/http` | Distinctive Go TLS stack | Unique cipher preference order |
| Shodan scanner | Known fingerprint | Documented by researchers |
| **Chrome 120+** | GREASE + many extensions | Complex, randomized — hard to fingerprint |

!!! tip "JA3 Lookup"
    Check your scanner's JA3 fingerprint at [ja3er.com](https://ja3er.com) before deploying. If your JA3 matches a known scanner, sophisticated actors will detect you.

### IP Reputation Monitoring

Actors check visitor IPs against reputation services:

- **VirusTotal**: Was this IP reported as a scanner?
- **AbuseIPDB**: Has this IP been flagged for scanning activity?
- **Shodan/Censys**: Is this IP itself a known research platform?
- **Cloud provider ranges**: AWS/GCP/Azure IP ranges are published — actors can check if visitors come from cloud infra

### Behavioral Detection

- **Scan timing**: Rapid sequential requests from a single IP = obvious scanner
- **Request patterns**: Hitting known-scanner paths (checksum8 URIs, `/cd`, `/__init__`) in sequence
- **Header anomalies**: Missing `Accept-Language`, unusual `Accept-Encoding`, no cookies on return visits
- **Volume**: More than a few requests to a C2 panel is suspicious — real victims connect once

### Honeypot Indicators

Actors deploy honeypots to identify researchers. Watch for:

- **Too-easy discovery**: Open directories that appear on Shodan within hours of deployment
- **Planted credentials**: Login pages with default creds that "work" — designed to track who tries them
- **Canary tokens**: Files that phone home when opened (canarytokens.org-style)
- **JavaScript fingerprinting**: C2 panels that run canvas fingerprinting, WebGL enumeration on visitors
- **Excessive telemetry**: Servers that log every header, full request body, timing data

!!! warning "Rule of Thumb"
    If a C2 panel seems too easy to find and too easy to access, it's likely a honeypot. Real actors protect their infrastructure.

---

## Distributed Scanning Architecture

Instead of scanning from a single IP, distribute your probes across cloud provider IP pools so each request originates from a different address.

### AWS Lambda Architecture

The core design:

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Researcher  │────▶│  API Gateway  │────▶│   Lambda     │──▶ Target
│  (hidden)    │     │  (trigger)    │     │  (us-east-1) │
└─────────────┘     └──────────────┘     └──────────────┘
                                          ┌──────────────┐
                                    ────▶ │   Lambda     │──▶ Target
                                          │  (eu-west-1) │
                                          └──────────────┘
                                          ┌──────────────┐
                                    ────▶ │   Lambda     │──▶ Target
                                          │ (ap-south-1) │
                                          └──────────────┘
                           Results ────▶  S3 Bucket (aggregation)
```

**Key properties:**
- Each Lambda invocation gets a new IP from the AWS pool
- Multi-region deployment means IPs from different geographic pools
- Stateless — no persistent connection to trace back
- Ephemeral — function dies after execution, no lingering process

### Cost Estimation

| Parameter | Value |
|-----------|-------|
| Memory | 128 MB |
| Avg duration | 500 ms |
| Cost per invocation | ~$0.0000002 (compute) + $0.0000002 (request) |
| **1,000 scans** | **~$0.21** |
| **10,000 scans** | **~$2.10** |
| Free tier | 1M requests/month, 400K GB-seconds |

For most research campaigns, Lambda scanning falls within the free tier.

### Multi-Cloud Alternatives

| Provider | Service | Deployment | IP Diversity |
|----------|---------|------------|-------------|
| AWS | Lambda | SAM/CDK | Excellent (large IP pool per region) |
| Google Cloud | Cloud Functions | gcloud CLI | Good |
| Azure | Azure Functions | Azure CLI | Good |
| Cloudflare | Workers | Wrangler CLI | Moderate (Cloudflare IP ranges) |

!!! tip "SAM Deployment"
    AWS SAM (Serverless Application Model) templates make Lambda deployment repeatable. The capstone project generates a `template.yaml` you can deploy with `sam deploy --guided`.

---

## TLS Fingerprint Management

### Why Python Stands Out

Python's `ssl` module uses OpenSSL defaults that produce a distinctive JA3:

- Limited cipher suite list (fewer than a browser)
- No GREASE values (browsers insert random GREASE extensions)
- Predictable extension ordering
- No ALPS, no ECH, no delegated credentials

This means any target running JA3 analysis will immediately identify your probe as "Python script, not a browser."

### Browser-Like TLS Stacks

| Library | Language | Approach | JA3 Match |
|---------|----------|----------|-----------|
| `curl_cffi` | Python (C binding) | Impersonates Chrome/Firefox TLS stack | Chrome, Firefox, Safari profiles |
| `tls-client` | Python (Go binding) | Uses utls (Go) for TLS mimicry | Chrome, Firefox, custom |
| `cloudscraper` | Python | TLS challenge solving | Varies |

```bash
# Install curl_cffi for browser-like TLS
pip install curl_cffi

# Install tls-client
pip install tls-client
```

### HTTP/2 Fingerprinting

Beyond TLS, HTTP/2 connection parameters also fingerprint clients:

- **SETTINGS frame**: Window size, max concurrent streams, header table size — browsers send specific values
- **PRIORITY frames**: Browser-specific priority tree construction
- **WINDOW_UPDATE**: Initial window update values differ between implementations

Python's `httpx` with HTTP/2 enabled sends different SETTINGS than Chrome. A sophisticated actor checking both JA3 and HTTP/2 fingerprints can detect this.

---

## Network-Level OPSEC

### VPN Selection for Research

| Criteria | Why It Matters |
|----------|---------------|
| No-log policy | Verified by audit (NordVPN, Mullvad) — logs can be subpoenaed |
| Jurisdiction | Avoid 14-Eyes countries for sensitive research |
| Kill switch | Prevents IP leak if VPN drops mid-scan |
| DNS leak prevention | DNS queries must route through VPN tunnel |
| Shared IP | Many users per IP = harder to attribute |

### Tor Integration

```bash
# Route scanning through Tor SOCKS5 proxy
export ALL_PROXY=socks5h://127.0.0.1:9050

# Or use proxychains
proxychains4 python scanner.py -t target.com
```

**Considerations:**
- Tor exit nodes are publicly listed — actors can block all of them
- Tor is slow — not suitable for bulk scanning
- Some exit nodes are monitored by researchers/LEA
- Best for initial reconnaissance, not sustained campaigns

### Cloud IP Diversity

Rotate across multiple cloud providers to avoid IP-range blocking:

1. **AWS Lambda** (multiple regions)
2. **GCP Cloud Functions** (different IP pool)
3. **Azure Functions** (different IP pool)
4. **DigitalOcean Functions** (different IP pool)

Cross-reference with Module 0x08: actors check IP intelligence databases. Cloud IPs are flagged as "datacenter" but are less suspicious than known scanner IPs.

---

## Researcher Trap Detection

### C2 Panel Visitor Logging

Modern C2 panels often include anti-researcher measures:

- **JavaScript fingerprinting**: Canvas fingerprint, WebGL renderer, screen resolution, timezone, installed fonts
- **Tracking pixels**: 1x1 images that log visitor IP and headers
- **Cookie planting**: Persistent cookies that track return visits across sessions
- **WebRTC leak**: JavaScript that extracts your real IP even through a VPN/proxy

!!! danger "Browser Isolation"
    Never visit a suspected C2 panel in your regular browser. Use:

    - Tor Browser (built-in fingerprint resistance)
    - A dedicated VM with a clean browser profile
    - `curl`/`wget` for initial checks (no JavaScript execution)
    - The headless techniques from this module's capstone project

### Identifying Decoy Infrastructure

| Indicator | What It Suggests |
|-----------|-----------------|
| Server responds to ANY URI with 200 OK | Honeypot — real C2s are selective |
| Open directory with organized samples by date | Researcher bait |
| Panel accepts any credentials | Tracking who tries to log in |
| Infrastructure has 100% uptime for months | Unlikely for real actor infra |
| Every file has a canarytoken.org hash | Planted canary tokens |
| Geofencing (different content by country) | Anti-analysis — try multi-region Lambda |

### Anti-Analysis Tricks

- **Time-bombing**: C2 only active during business hours in actor's timezone
- **Geofencing**: Different responses based on source country
- **Researcher IP blocklists**: Known scanner IPs, cloud ranges, Tor exits pre-blocked
- **Rate limiting**: Aggressive throttling after 2-3 requests
- **Null routing**: Infrastructure disappears after first probe

---

## Legal Considerations

### Authorized Scanning Frameworks

Before any scanning activity, document:

1. **Scope**: Exact IP ranges, domains, and ports authorized for scanning
2. **Rules of engagement**: What techniques are permitted (passive recon only? active probing? content download?)
3. **Authorization**: Written approval from the appropriate authority (CISO, legal, client)
4. **Time window**: When scanning is permitted
5. **Incident response**: What to do if you accidentally affect a system
6. **Data handling**: How collected data (screenshots, certificates, payloads) will be stored and destroyed

### Legal Boundaries

| Activity | US (CFAA) | UK (CMA) | EU (various) |
|----------|-----------|----------|---------------|
| Passive DNS lookup | Legal | Legal | Legal |
| CT log monitoring | Legal | Legal | Legal |
| Shodan/Censys search | Legal | Legal | Legal |
| Active port scan (authorized) | Legal with authorization | Legal with authorization | Varies by country |
| Active port scan (unauthorized) | **Felony** | **Criminal offense** | **Criminal in most countries** |
| Accessing open directory | Gray area | Gray area | Gray area |
| Downloading malware samples | Legal for research (with controls) | Legal for research | Legal for research |

!!! danger "The Golden Rule"
    If you don't have written authorization to scan a target, **don't scan it**. Use passive intelligence sources (Shodan, Censys, CT logs, pDNS) instead. They provide most of the same data without touching the target.

### Responsible Disclosure

If your research uncovers:
- **Compromised legitimate infrastructure**: Notify the owner and relevant CERT
- **Stolen credentials**: Report to the affected organization, never use them
- **Active criminal infrastructure**: Report to relevant law enforcement or CERT
- **Zero-day vulnerabilities**: Follow coordinated disclosure (90-day window standard)

---

## Tool References

| Tool | Purpose | Usage |
|------|---------|-------|
| **AWS SAM** | Lambda deployment automation | `sam init`, `sam deploy --guided` |
| **curl_cffi** | Browser-like TLS fingerprint | `pip install curl_cffi` — impersonate Chrome/Firefox |
| **tls-client** | Go-based TLS mimicry | `pip install tls-client` |
| **Tor** | Anonymous routing | `apt install tor`, SOCKS5 on 127.0.0.1:9050 |
| **proxychains** | Force tools through proxy | `proxychains4 python scanner.py` |
| **Shodan Monitor** | Passive alternative to scanning | Monitor IPs without active probing |
| **Censys Search** | Passive infrastructure search | Search without touching targets |
| **canarytokens.org** | Understand canary token mechanics | Know what traps look like |

---

## Case Study: Distributed Threat Hunting Campaign

**Scenario:** Your team has identified 50 suspected Cobalt Strike team servers from Module 0x04 analysis. You need to validate them without tipping off the operator.

### Phase 1: Passive Validation First

Before any active scanning, exhaust passive sources:
- Shodan historical data for each IP (no active probe)
- Censys certificate search (no active probe)
- pDNS records from SecurityTrails (no active probe)

**Result:** 35 of 50 IPs confirmed via passive data alone. 15 require active validation.

### Phase 2: Deploy Distributed Scanner

1. Generate SAM template with the capstone project's `--gen-sam` flag
2. Deploy to 3 AWS regions (us-east-1, eu-west-1, ap-southeast-1)
3. Configure API Gateway trigger with API key

### Phase 3: Scan with OPSEC

- Distribute 15 targets across 3 regions (5 per region)
- Space requests 30-60 seconds apart (avoid burst detection)
- Use browser-like User-Agent strings
- Single request per target (no repeated probing)

### Phase 4: Aggregate Results

Collect Lambda results from S3, merge into unified JSON, cross-reference with Module 0x03 clustering output.

### Phase 5: Report

Document findings with full provenance:
- Which targets were validated passively vs actively
- Scan timestamps and source regions
- Authorization documentation reference

!!! tip "80/20 Rule"
    In practice, 80% of threat hunting can be done passively using Shodan, Censys, CT logs, and pDNS. Active scanning should be a last resort for the remaining 20% that can't be validated any other way.

---

## OPSEC Checklist

Before any active scanning campaign:

- [ ] Written authorization documented and filed
- [ ] Scope clearly defined (IPs, domains, ports, techniques)
- [ ] Passive sources exhausted first
- [ ] Scanner TLS fingerprint checked (ja3er.com)
- [ ] Distributed infrastructure deployed (Lambda or equivalent)
- [ ] VPN/proxy configured with kill switch
- [ ] Browser isolation in place for panel visits
- [ ] Data handling policy defined
- [ ] Incident response plan ready
- [ ] Results storage encrypted

---

## Summary

Hunter OPSEC is about **protecting the researcher** while conducting authorized investigations. The key principles:

1. **Passive first** — Exhaust Shodan, Censys, CT logs, pDNS before touching any target
2. **Distribute active probes** — Never scan from your own IP or a single cloud instance
3. **Manage your fingerprint** — Your tools identify you through TLS and HTTP signatures
4. **Recognize traps** — Honeypots, canary tokens, and visitor logging are common
5. **Stay legal** — Authorization, scope, and documentation are non-negotiable
6. **Minimize contact** — One probe per target, not ten

Cross-reference: Module 0x01 (TLS fingerprinting — understand what identifies your scanner), Module 0x08 (Proxy layers — understand the infrastructure you're scanning through).

---

## Module Project: Distributed Scanner Deployment
*Reference: From Day Zero to Zero Day*

Instead of running a scanner script from your local machine, deploy it statelessly so it receives a new IP address every run from a pool of cloud provider endpoints.

### The Objective
1. Write a minimal Python script that probes a target's TLS configuration and extracts server metadata.
2. Wrap this script inside an AWS Lambda function (SAM template generated by the tool).
3. Simulate multi-region distributed scanning locally to demonstrate the concept.
4. Aggregate results from multiple simulated invocations.

### Running the Capstone Project

```bash
# Demo mode — simulates distributed scanning locally
python lambda_scanner.py

# Generate AWS SAM deployment template
python lambda_scanner.py --gen-sam

# Estimate cost for a scanning campaign
python lambda_scanner.py --estimate --targets 1000 --regions 3

# Simulate multi-region scanning
python lambda_scanner.py --simulate -t 1.2.3.4,5.6.7.8 --regions us-east-1,eu-west-1

# JSON output for pipeline integration
python lambda_scanner.py --simulate --format json
```

See `projects/0x09_lambda_scanner/lambda_scanner.py` for the full implementation.
