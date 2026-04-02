# Module 0x08: Proxy & Botnet Layers

## Overview

When malware executes, it rarely uses the target's direct internet connection—and threat actors rarely connect directly to their C2. Botnets act as massive proxy exits. Identifying residential proxy exit nodes and multi-tier backconnect architecture is paramount to hunting the true actor origin.

This module covers the full proxy and obfuscation stack: how residential proxy networks are built and abused, how SOCKS5 backconnect infrastructure is architected and detected, how BGP routing data reveals ownership and anomalies, and how to trace a C2 through multiple proxy layers back to its source.

## Key Concepts

* **Residential Proxies versus Datacenter Proxies**: Differentiating traffic routing via ASNs and IP reputation.
* **Socks5 Backconnects**: The infrastructure logic used by proxies like 911.re, VIP72, or modern variants.
* **Multi-tier Infrastructure**: Tracing traffic from the Target -> Residential IP -> Cloud VPS -> Actor C2.
* **BGP Routing Analysis**: Using AS path data and RPKI to validate legitimate infrastructure ownership.
* **Risk Scoring**: Composite classification of IPs across multiple intelligence sources.

---

## 1. Residential Proxy Ecosystem

### How Residential Proxies Are Built

Residential proxies are not server farms — they are ordinary consumer internet connections, on Comcast, AT&T, BT, Telstra, and similar ISPs, whose bandwidth and IP addresses have been co-opted for proxy traffic. Because their originating ASN is a legitimate residential ISP, they bypass most datacenter-based blocklists and appear as normal home user traffic.

Three mechanisms dominate the supply side:

**SDK-Based (Embedded in Free Apps)**
The most common supply mechanism. A mobile app or desktop utility offers a free service (VPN, battery optimizer, speed test, game booster) in exchange for the user agreeing—buried in the ToS—to share their unused bandwidth. The SDK from the proxy operator runs as a background process, connecting to the backconnect network whenever the device is idle and on Wi-Fi. Companies like Bright Data (formerly Luminati) were pioneers of this model; their SDK appeared in hundreds of popular mobile apps before scrutiny intensified.

The infected app continues to function normally. The user's IP appears as a proxy exit. The SDK operator sells access to that IP by the gigabyte or by the hour.

**Browser Extension Injection**
Browser extensions with broad permissions (`tabs`, `webRequest`, `proxy`) can intercept and reroute traffic, or inject the user's browser as a relay node. When extensions are sold or acquired after gaining a large install base, the new owner can push an update that silently enables proxy functionality. This is a variant of the supply-chain compromise pattern — the extension itself was never malicious, but becomes so post-acquisition.

**Mobile SDK Networks**
On mobile platforms (Android especially), the attack surface expands: apps with INTERNET permission can route traffic through the device. Some operators specifically target low-income markets with free data offers that require the device to act as a relay. The traffic routed through is often SOCKS5 or HTTP CONNECT proxied.

### Major Commercial Operators

The residential proxy market is large, commercially viable, and openly sold. Understanding the legitimate operators clarifies how abuse works:

| Operator | Scale (approx.) | Notes |
|----------|----------------|-------|
| Bright Data (Luminati) | 72M+ IPs | Largest operator; SDK historically embedded in consumer apps |
| Oxylabs | 100M+ IPs | Business-focused; strict use policies |
| SmartProxy | 55M+ IPs | Popular with lower-cost buyers |
| IPRoyal Pawns | 2M+ IPs | Opt-in desktop app (Pawns.app) pays users directly |
| Residential proxies (generic) | Varies | Dozens of resellers buy access from primary networks |

**How abuse works:** A threat actor purchases a residential proxy subscription — often with cryptocurrency, often through a reseller that doesn't enforce KYC. They receive a SOCKS5 or HTTP endpoint (e.g., `gate.smartproxy.com:7000`) with authentication credentials. When they connect through it, their traffic exits from a residential IP in a target country of their choosing. To defenders, the traffic looks like a home user in Ohio. The C2 server never receives a connection from a datacenter.

This breaks datacenter-based detection entirely. An actor using residential proxies for C2 communication will appear to come from ISPs like Charter, Comcast, or Vodafone — providers defenders are reluctant to wholesale-block.

---

## 2. SOCKS5 Infrastructure Analysis

### Backconnect Architecture

The "backconnect" model is the dominant architecture for large proxy pools. Rather than exposing each residential IP as an independent endpoint, the operator runs a gateway cluster:

```
Actor (client)
    |
    v
Entry Gateway (single IP, e.g., gate.provider.com:7000)
    |
    |  [credential routing / geotarget selection]
    v
Backconnect Infrastructure (internal pool management)
    |
    +----> Exit Node A (Residential IP, Chicago, Comcast)
    +----> Exit Node B (Residential IP, London, BT)
    +----> Exit Node C (Residential IP, Singapore, Singtel)
```

The actor connects to **one** stable entry gateway. The gateway authenticates the request, selects an exit node based on geotargeting parameters, and routes the traffic outbound through that residential IP. The actor's actual source IP never touches the target. The residential IP that appears in target logs is transient — it may rotate every request, every 10 minutes, or every session, depending on the operator's model.

Key architectural properties:

- **Single entry, many exits**: The gateway is the choke point; exits are ephemeral
- **Credential-based routing**: Username:password pairs encode geotarget, session type, and rotation policy
- **Port-per-exit model (alternative)**: Some operators, particularly illicit services, assign a unique port number to each exit IP on a single gateway host. Port 10001 = Exit IP A, Port 10002 = Exit IP B. This enables direct exit selection.
- **Geotargeting mechanisms**: Exit selection can be by country, state, city, ISP, or ASN. Username encodes `user-country-us-city-chicago-session-rotating`

### SOCKS5 vs HTTP Proxies for C2 Use

SOCKS5 is preferred over HTTP proxies for C2 because it is protocol-agnostic. HTTP proxies understand HTTP/HTTPS — they rewrite headers, may inject `X-Forwarded-For`, and are constrained to web protocols. SOCKS5 forwards raw TCP (and optionally UDP) without inspection, making it usable for any protocol: custom C2 protocols, DNS-over-TCP, SSH tunnels, or raw binary beacons.

| Feature | HTTP Proxy | SOCKS5 Proxy |
|---------|-----------|--------------|
| Protocol support | HTTP/HTTPS only | Any TCP/UDP |
| Header injection risk | Yes (X-Forwarded-For) | No |
| Authentication | Basic auth, Digest | Username/password |
| C2 compatibility | Limited (HTTP C2 only) | Universal |
| Latency overhead | Higher (proxy protocol) | Lower |

### Detecting SOCKS5 Open Proxies

Open SOCKS5 proxies (no authentication required) are valuable for intelligence gathering because they can be confirmed without credentials. The detection technique is a standard SOCKS5 handshake probe:

```
# SOCKS5 greeting: version=5, nmethods=1, method=0 (no auth)
Client → Server:  05 01 00
Server → Client:  05 00   (accept no-auth)
```

If a host responds `\x05\x00` to this probe on a given port, it is an open SOCKS5 proxy. Shodan and Censys index these continuously using similar probes. Common ports: 1080, 3128, 8080, 9050 (Tor), and high ephemeral ports.

For bulletproof proxy pools using the port-per-exit model, scanning a /24 for open SOCKS5 ports and seeing a large number of sequential ports respond positively is a strong indicator of a managed proxy pool rather than individual compromised hosts.

---

## 3. Bulletproof Proxy Hosting Identification

### Port Pattern Analysis

Legitimate servers run a small, predictable set of services. A host running SOCKS5 on ports 10000–10999 is not hosting a single proxy — it is a backconnect gateway where each port maps to a distinct exit IP. This pattern is directly observable in Shodan:

```
shodan search "SOCKS5" port:1080 has_screenshot:false
shodan search "Socks server" country:RU
```

Indicators of a managed proxy pool from port pattern analysis:
- Many consecutive high ports (10000–19999) responding to SOCKS5 handshake
- Same banner or no banner across all ports
- ASN is a known bulletproof or permissive hosting provider
- No PTR records or generic PTR (`host-45-32-x-x.choopa.net`)

### Banner and Handshake Analysis

SOCKS5 servers often produce a distinctive banner or handshake response that fingerprints the proxy software. Common indicators:

- `\x05\x00` (open SOCKS5, no auth required)
- `\x05\x02` (SOCKS5 with username/password auth — still confirms SOCKS5 service)
- Some implementations include a text preamble before the SOCKS5 negotiation
- 3proxy, Dante, Microsocks, and commercial proxy software each have distinct TLS/banner behaviors

### Known Bulletproof ASNs

Not all bulletproof hosting provides proxy services, but certain providers have documented histories of hosting proxy infrastructure:

| ASN | Provider | Notes |
|-----|---------|-------|
| AS20473 | Choopa / Vultr | Common VPS; frequent proxy/botnet hosting |
| AS16276 | OVH SAS | Large EU provider; high abuse volume |
| AS9009 | M247 | Frequently listed; proxy services documented |
| AS202425 | IP Volume / Serverius | Bulletproof-adjacent |
| AS59729 | NForce Entertainment | Long history of abuse complaints |
| AS36352 | ColoCrossing | US-based; historically high abuse |

Note: The presence of an ASN on this list does not mean all traffic from it is malicious — these are large providers with millions of legitimate customers. Treat ASN as one signal among many.

---

## 4. BGP Analysis for Infrastructure Hunting

### Why BGP Matters

BGP (Border Gateway Protocol) is the routing fabric of the internet. Every IP address belongs to a prefix (e.g., `45.32.0.0/16`) that is announced by an Autonomous System (AS). The AS is the authoritative attribution unit: it ties an IP range to a legal entity registered with a Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC).

For infrastructure hunters, BGP data answers questions that pure IP reputation cannot:
- Who actually owns this IP range?
- Has ownership recently changed (possible hijack or acquisition)?
- What other prefixes does this actor control?
- Is this prefix properly authorized (RPKI)?

### AS Path Analysis

When a prefix is announced, BGP records the sequence of ASNs it traverses from origin to destination — the AS path. Anomalies in AS paths can indicate:

- **Unexpected origin AS**: A prefix that was previously announced by AS-X now appears from AS-Y. This may indicate a BGP hijack, a subnet sale, or an actor setting up new infrastructure under a different AS.
- **Path lengthening**: An unusually long AS path for a geographically local route suggests traffic is being redirected.
- **Route leaks**: Prefixes appearing in paths where they should not be present.

Tools for AS path analysis:
- **RIPE RIS (Routing Information Service)**: BGP routing tables from 20+ global collectors. `https://stat.ripe.net/`
- **Hurricane Electric BGP Toolkit**: AS path lookups, prefix origin, looking glass. `https://bgp.he.net/`
- **BGPView API**: Programmatic access to current BGP state. `https://api.bgpview.io/`

### RPKI Validation

RPKI (Resource Public Key Infrastructure) is a cryptographic framework that lets RIR-registered resource holders sign Route Origin Authorizations (ROAs), which assert: "AS X is authorized to announce prefix P/len."

RPKI status for any prefix is one of three states:

| Status | Meaning |
|--------|---------|
| **Valid** | Prefix matches a ROA signed by the legitimate holder |
| **Invalid** | Prefix is announced by an AS not authorized in the ROA — possible hijack |
| **Not Found** | No ROA exists; origin cannot be cryptographically verified |

An IP with RPKI status `Invalid` deserves immediate scrutiny. Legitimate operators almost never let their ROAs lapse or mismatch. An invalid prefix may indicate BGP hijacking — a technique used by some nation-state actors to temporarily commandeer IP space for C2 activity.

Querying RPKI status:
```
https://stat.ripe.net/data/rpki-validation/data.json?resource=45.32.228.0/24&sourceapp=netthrunter
```

### BGPView API for Infrastructure Mapping

BGPView provides a clean REST API for ASN and prefix intelligence:

```python
# ASN details
GET https://api.bgpview.io/asn/20473

# Prefixes announced by an ASN
GET https://api.bgpview.io/asn/20473/prefixes

# IP address lookup (ASN, prefix, country)
GET https://api.bgpview.io/ip/45.32.228.0

# AS path (peers)
GET https://api.bgpview.io/asn/20473/peers
```

This is particularly useful when you have an IP from a proxy exit and want to enumerate the full prefix it belongs to, then check what else the same ASN is announcing. An ASN announcing 50 small /24s in 12 countries with no apparent business purpose is a different threat profile than a tier-1 ISP.

---

## 5. MaxMind GeoLite2 for Bulk IP Analysis

### Why Local Databases Matter

API-based lookups (ip-api.com, IPinfo, etc.) impose rate limits and, critically, reveal your hunting targets to the API provider. If you are investigating live C2 infrastructure, querying a commercial API with those IPs tells the API operator what you are investigating. This is an OPSEC concern — see Module [0x09 (Hunter OPSEC)](0x09_hunter_opsec.md).

MaxMind GeoLite2 provides free databases (with account registration) for offline, rate-limit-free, bulk IP analysis:

| Database | Contents | Size |
|----------|---------|------|
| GeoLite2-Country | Country-level geolocation | ~6 MB |
| GeoLite2-City | City, lat/lon, postal code | ~75 MB |
| GeoLite2-ASN | ASN name and number | ~10 MB |

The ASN database is the most immediately useful for proxy hunting: given any IP, it returns the ASN number and the registered name of the network operator. This lets you classify thousands of IPs in seconds without a single external API call.

### Setup

```bash
# Install the Python client
pip install geoip2

# Download databases (requires free MaxMind account)
# https://www.maxmind.com/en/geolite2/signup
# Download: GeoLite2-ASN.mmdb, GeoLite2-City.mmdb
```

### Usage Pattern

```python
import geoip2.database

with geoip2.database.Reader('GeoLite2-ASN.mmdb') as reader:
    response = reader.asn('45.32.228.0')
    print(response.autonomous_system_number)   # 20473
    print(response.autonomous_system_organization)  # "AS-CHOOPA"

with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
    response = reader.city('45.32.228.0')
    print(response.country.iso_code)     # US
    print(response.city.name)            # Miami
    print(response.location.latitude)
```

### Advantages for Hunters

- **No rate limits**: Process a million IPs in one run
- **No network calls**: Works air-gapped or in isolated analysis environments
- **No attribution of queries**: The target IPs never leave your machine
- **Weekly updates**: Databases refresh every Tuesday via automated download
- **Bulk-optimized**: The Python reader caches the mmdb in memory; sequential reads are very fast

---

## 6. Multi-Tier Proxy Tracing

### The Layered Model

Sophisticated actors do not use a single proxy layer. A typical C2 communication chain:

```
Victim endpoint
    │
    ▼
Tier 1: Residential proxy exit
    (appears as a home IP in Chicago on Comcast)
    │
    ▼
Tier 2: Commercial backconnect gateway
    (Bright Data / Oxylabs entry node; cloud VPS)
    │
    ▼
Tier 3: Bulletproof VPS
    (Choopa / OVH / M247; the actor's staging server)
    │
    ▼
Tier 4: Actor's true C2
    (may be on Tor, I2P, or another bulletproof host)
```

Each layer serves a purpose: Tier 1 defeats ISP-based blocking; Tier 2 provides geotargeting and rotation; Tier 3 provides abuse-resistant hosting; Tier 4 is the crown jewel the actor protects most carefully.

### Techniques Per Tier

**Tier 1 — Residential Exit Analysis**

The IP in your logs is the residential exit. You cannot directly attribute this to an actor — it may be an innocent home user whose device hosts proxy SDK. What you can do:

- Classify the ASN (residential ISP confirms it is a proxy exit, not direct connection)
- Check proxy/VPN detection APIs (IPQualityScore, ip-api.com) for proxy flag
- Check the IP against Spamhaus DROP/EDROP — if a residential IP is listed, it may be a known compromised range
- Look for the IP in passive DNS — does this IP have recent C2-related hostnames?

**Tier 2 — Backconnect Gateway**

The residential IP connects *outbound* to the backconnect gateway to register itself as an exit. You may see this in traffic analysis as:
- Persistent TCP connection from a residential IP to a datacenter IP on an unusual port
- The datacenter IP's ASN is a known proxy provider
- BGPView will confirm the prefix belongs to a commercial proxy operator

**Tier 3 — Bulletproof VPS**

This is where the actor's actual C2 payload lives before the final hop. Techniques:
- Certificate fingerprinting (Module [0x01](0x01_structural_fingerprinting.md)) — the VPS may share certs with other known actor infrastructure
- JARM fingerprint the TLS stack — if it matches known C2 frameworks, confirms hostile use
- ASN clustering (Module [0x03](0x03_overlap_clustering.md)) — does this ASN host other IPs with matching fingerprints?
- Shodan historical data — when did this IP first appear? What services has it run?

**Tier 4 — Actor C2**

At this layer, the actor may use:
- Tor hidden services (`.onion` — not directly observable from network logs)
- Domain fronting through CDN (see Module [0x06](0x06_edge_layer_obfuscation.md))
- Fast-flux DNS pointing to a rotating pool of VPS frontends
- Another commercial proxy network for inbound connections

---

## 7. Tool Reference

| Tool | Type | Use Case |
|------|------|---------|
| **MaxMind GeoLite2** | Local database | Bulk ASN/geo lookup; no API calls; OPSEC-safe |
| **IPinfo.io** | API | IP intelligence, ASN, abuse contact, hosted domains |
| **BGPView** | API | ASN details, prefix enumeration, routing, peers |
| **RIPE RIS / RIPE STAT** | API/Web | BGP routing tables, RPKI validation, historical routes |
| **Hurricane Electric BGP** | Web | AS path analysis, looking glass, neighbor graph |
| **Spamhaus DROP/EDROP** | Feed | Known-bad IP ranges; DROP = hijacked; EDROP = extended |
| **IPQualityScore** | API | Proxy/VPN/Tor detection with confidence scoring |
| **Shodan** | API/Web | Open SOCKS5/HTTP proxy detection, port fingerprinting |
| **RIPE Whois** | API | IP range registration, abuse contacts, org details |
| **ASRank (CAIDA)** | Web | ASN ranking and relationship data |

---

## 8. Case Study: Tracing a C2 Through Proxy Layers

### Scenario

A threat hunting rule fires on an endpoint: outbound HTTPS traffic to `138.68.0.0` on port 443. The beacon interval is 30 seconds — consistent with a C2 heartbeat. Initial IP triage shows this IP is in a DigitalOcean datacenter in Frankfurt.

### Step 1 — Classify the Exit IP

```
ip-api.com lookup: 138.68.0.0
  ASN: AS14061 - DIGITALOCEAN-ASN
  Hosting: true
  Proxy: false
  ISP: DigitalOcean
```

Classification: Datacenter VPS. This is likely Tier 3 (actor's staging VPS) or a proxy gateway, not the true origin.

### Step 2 — BGP/Prefix Analysis

```
BGPView: 138.68.0.0
  Prefix: 138.68.0.0/16
  ASN: AS14061 (DigitalOcean)
  RPKI Status: Valid (DigitalOcean maintains ROAs)
```

No BGP anomaly here — this is a legitimately announced prefix. The actor rented a VPS; they did not hijack the address space.

### Step 3 — Certificate Fingerprinting (Module 0x01)

JARM fingerprint of `138.68.0.0:443` matches a known Cobalt Strike profile. Shodan historical data shows this IP served a self-signed certificate with CN=`localhost` — consistent with CS default configuration.

Cross-reference with Module [0x03 clustering](0x03_overlap_clustering.md): query the certificate serial number against passive DNS. Three other IPs share the same certificate: `45.32.x.x`, `104.238.x.x`, `144.202.x.x` — all on Choopa/Vultr, all with the same JARM fingerprint. This is the actor's VPS cluster.

### Step 4 — Upstream Pivot

Passive DNS shows `138.68.0.0` has been resolving `c2-gate.example[.]com` since 6 weeks ago. WHOIS for that domain: registered via Njalla (privacy-preserving registrar), paid with Monero, 6 weeks ago. Registration date aligns with the cluster's first Shodan scan.

DNS resolvers queried for this domain: passive DNS shows the original lookup came from a Chicago Comcast residential IP — `76.102.x.x`. That IP resolves to a host that was flagged by IPQualityScore as a known residential proxy exit on the Bright Data network.

### Step 5 — Build the Chain

```
Victim endpoint (Chicago, endpoint logs)
    │
    ▼  [TLS to residential proxy exit]
76.102.x.x (Comcast residential — Bright Data exit node)
    │
    ▼  [SOCKS5 backconnect to gateway]
Bright Data backconnect gateway (cloud VPS, auto-rotating)
    │
    ▼  [direct TCP to C2]
138.68.0.0 (DigitalOcean Frankfurt — Cobalt Strike C2)
    │
    ▼  [C2 cluster lateral]
45.32.x.x, 104.238.x.x, 144.202.x.x (Choopa — additional C2 nodes)
```

The actor used residential proxy access to mask beaconing. The Bright Data exit was the visible IP in endpoint logs; the actual C2 is two hops removed. Without the proxy classification step, the residential IP would have been dismissed as a false positive.

### OPSEC Note

During this investigation, querying ip-api.com and IPQualityScore with the actor's IPs reveals those IPs to the API providers. If this is an active intrusion with ongoing monitoring, the actor may have contacts at or access to log data from commercial IP intelligence providers. For sensitive investigations, use MaxMind GeoLite2 locally for classification, and limit API lookups to IPs you have already confirmed as infrastructure — not suspected victim endpoints. See Module [0x09 (Hunter OPSEC)](0x09_hunter_opsec.md) for full guidance.

---

## 9. Proxy & Botnet Hunting OPSEC

Querying proxy intelligence APIs with your investigative targets carries risk:

1. **API logging**: All commercial API providers log queries. Your target IPs become associated with your API key and IP address.
2. **Notification risk**: Some proxy operators have arrangements with intelligence providers and may be alerted to interest in their infrastructure.
3. **Correlation risk**: If you query a dozen IPs in quick succession from a corporate IP, that query pattern may be detectable and could tip off an adversary monitoring for investigation activity.

**Mitigations:**
- Use MaxMind GeoLite2 locally for bulk classification (no external calls)
- For API-based enrichment, route queries through a dedicated research VPS separate from your corporate or home IP
- Batch queries to avoid temporal correlation
- Query only confirmed infrastructure IPs, not suspected victim/proxy exits you haven't characterized yet

---

## 🛠️ Module Project: Advanced Proxy & ASN Validator

*Reference: Art of Cyber Warfare*

Given a PCAP or list of IPs from an active investigation, rapidly classify each IP against multiple intelligence sources, score its risk, and identify multi-tier proxy chains.

### The Objective

1. Accept IPs from CLI arguments, comma-separated list, or file.
2. Classify each IP using MaxMind GeoLite2 (local, OPSEC-safe), with fallback to ip-api.com.
3. Enrich with BGP/ASN data from BGPView (with mock fallback).
4. Check against known proxy/datacenter ASNs and Spamhaus DROP/EDROP.
5. Calculate a composite risk score (0–100) based on multiple signals.
6. Support multiple output formats: text, JSON, CSV.
7. Include CIDR range analysis and deep BGP mode.
8. Run fully offline in mock/demo mode with no external dependencies.

See the full reference implementation in `projects/0x08_proxy_validator/proxy_validator.py`.

### Key Design Decisions

- **Local-first**: MaxMind GeoLite2 is the primary lookup; API is fallback. This is the OPSEC-correct approach.
- **Graceful degradation**: If geoip2 library or database is absent, falls back to ip-api.com; if that fails, uses mock data. The tool always produces output.
- **Risk scoring**: Rather than binary datacenter/residential, a 0–100 composite score weights multiple signals: datacenter flag, known-bad ASN, Spamhaus listing, proxy/VPN detection.
- **Extensibility**: The known ASN database and Spamhaus mock data are designed as dictionaries for easy expansion.

**Takeaway:** A production-quality triage tool that classifies outbound traffic across multiple intelligence layers, scores each IP for risk, and produces machine-readable output for downstream analysis pipelines.
