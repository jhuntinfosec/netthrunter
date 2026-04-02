# Module 0x02: Infrastructure Mapping

## Overview

Tracking IPs and domains requires looking into the past. In this module, we focus on Passive DNS (pDNS) pivoting, Certificate Transparency (CT) log monitoring, and WHOIS history to track actor staging infrastructure.

Where Module 0x01 showed how to fingerprint individual services by their TLS handshake behavior, Module 0x02 zooms out: given a known indicator (a domain, an IP, an email address), how do you find the rest of the actor's infrastructure? The answer is a set of forensic trails every operator leaves behind without realizing it.

## Key Concepts

* **Certificate Transparency (CT)**: Monitoring new TLS certs as they are issued in real-time.
* **pDNS**: Correlating domains to historical IP resolutions.
* **WHOIS patterns**: Tracking registrar and proxy behaviors.

---

## 1. Deep CT Log Mechanics

Certificate Transparency (CT), defined in RFC 6962, was created by Google to combat fraudulently issued TLS certificates. Every publicly trusted CA is now required to submit issued certificates to publicly auditable append-only logs. This requirement — meant to protect end-users — inadvertently created a real-time adversary infrastructure feed for defenders.

### How CT Works

When a CA issues a certificate, it submits either a **pre-certificate** or the **final certificate** to one or more CT logs:

- **Pre-certificate**: An almost-final cert with a "poison" critical extension, submitted before the final cert is signed. This is what most modern CAs submit, enabling SCT embedding.
- **Final certificate**: The real, browser-trusted cert. Some CAs submit this instead of, or in addition to, the pre-cert.

The CT log returns a **Signed Certificate Timestamp (SCT)** — a cryptographic promise that the cert was logged at a specific time. Browsers require SCTs to trust a cert; this is what forces CA compliance.

Each log is a **Merkle hash tree**. Entries are append-only and each leaf's position is permanent. This means:

1. A certificate's presence in a log is provable and unforgeable.
2. The issuance timestamp is cryptographically attested.
3. Log entries are publicly queryable by anyone.

### Major Log Operators

| Operator | Log Name | Notes |
|---|---|---|
| Google | Argon 2024, 2025 | High volume, widely trusted |
| Cloudflare | Nimbus 2024, 2025 | High uptime, good API |
| Let's Encrypt | Oak 2024, 2025 | Tracks LE cert issuance |
| DigiCert | Yeti, Nessie | Enterprise CA focus |
| Sectigo | Sabre, Mammoth | High LE volume |

crt.sh aggregates all major logs into a single searchable interface, which is why it's the practitioner's default pivot point.

### Why CT is Valuable for Threat Hunting

Adversaries need TLS certificates to make phishing and C2 infrastructure appear legitimate. Free CAs (especially Let's Encrypt and ZeroSSL) have near-zero friction — a cert can be issued in seconds via ACME automation. This means:

- An actor can stage a phishing domain, get a cert, and go live in under five minutes.
- CT logs capture this the moment it happens.
- CT data provides timestamps that correlate with campaign timelines.
- Wildcard certs (`*.actor-domain.com`) reveal the actor's subdomain naming conventions.

!!! tip "Hunting Trigger"
    Set up CT log monitoring for brand keywords, executive names, and product names. Any cert containing `[brand]-login`, `[brand]-secure`, or `[brand]-verify` is a phishing prep indicator worth investigating immediately.

!!! warning "Pre-cert Visibility"
    You will see pre-certificates in crt.sh results (identifiable by the `precert` label). These represent a commitment to issue — the domain may go live within minutes. Don't wait to investigate.

---

## 2. Passive DNS (pDNS) Pivoting

Standard DNS is ephemeral — a resolver answers a query and moves on. **Passive DNS** systems work by operating sensors at recursive resolvers, IXPs, and through ISP partnerships that silently record every DNS answer they observe. The result is a historical database: "this IP answered for this domain from date X to date Y."

### How pDNS Data is Collected

```
Client → [Recursive Resolver] → Authoritative NS → Answer
                  ↓
           [pDNS Sensor] → [pDNS Database]
```

Sensors capture the full answer RRset: the queried name, the returned records, TTL, and timestamp. Some providers also capture NXDOMAIN responses, which reveal domains that were registered but never resolved — useful for catching infrastructure that was set up but abandoned.

### Record Types as Pivot Points

**A/AAAA Records — IP History**

The primary pivot: "what IPs has this domain pointed to over time?"

If an actor migrates their C2 from 45.142.212.100 to 185.220.101.50, the pDNS record for their domain will show both IPs with date ranges. You can then reverse-pivot each IP: "what other domains pointed to 45.142.212.100 in that same timeframe?" This reveals infrastructure siblings — other domains the actor was running concurrently.

**NS Records — Hosting Provider Patterns**

Actors often use the same nameserver providers across campaigns. NS record history reveals:

- Nameserver hopping (moving between providers to evade abuse takedowns)
- Shared infrastructure (multiple domains using the same authoritative NS)
- Custom nameservers (actor-controlled NS indicates mature infrastructure)

**MX Records — Mail Infrastructure Correlation**

Phishing campaigns sometimes configure MX records for credential harvesting (receiving replies) or for authentication (passing SPF/DKIM checks). MX record history can cluster related phishing domains that share a mail provider, and can reveal whether the actor is operating their own mail infrastructure.

### pDNS Data Providers

| Provider | Access | Notes |
|---|---|---|
| SecurityTrails | API key (free tier available) | WHOIS + pDNS combined |
| VirusTotal | API key (free tier: 4 req/min) | pDNS under domain report |
| RiskIQ/PassiveTotal | API key (now Microsoft Defender TI) | Deep pDNS + infrastructure graph |
| Farsight DNSDB | Paid; ISP-grade sensor coverage | Broadest sensor network |
| CIRCL pDNS | Free, Luxembourg CERT | Good European coverage |
| Mnemonic pDNS | Free researcher access available | Nordic sensor coverage |

!!! warning "pDNS Coverage Gaps"
    pDNS coverage is not uniform. Sensors concentrated in North America and Europe may miss resolution activity in APAC or Africa. An actor operating exclusively in underserved regions may show sparse pDNS history even for active infrastructure.

---

## 3. WHOIS Deep Dive

WHOIS is the registration metadata for a domain: who registered it, when, through which registrar, and contact details. For threat hunting, the direct contact details are rarely useful (actors use privacy proxies), but the structural patterns in WHOIS data are extremely valuable.

### Registrar Clustering

Actors tend to reuse registrars across campaigns, often for operational reasons:

- Cryptocurrency payment acceptance (Namecheap, Njalla, 1984 Hosting)
- Lax abuse handling
- Bulk registration discounts
- Familiarity and operational comfort

A threat actor cluster found to use Namecheap with WhoisGuard privacy across five known phishing domains is likely to continue that pattern for new infrastructure. When a new suspicious domain appears with the same registrar+privacy combination, the prior pattern raises its priority for investigation.

### Privacy Proxy Services

Most actor domains use privacy proxies that replace registrant contact data with the proxy service's generic information:

| Service | Registrar | Identifying Pattern |
|---|---|---|
| WhoisGuard | Namecheap | `WhoisGuard Protected` registrant |
| Domains By Proxy | GoDaddy | `Domains By Proxy, LLC` registrant |
| Withheld for Privacy | ICANN compliant | `Withheld for Privacy ehf` registrant |
| Njalla | Independent | Njalla as listed owner |
| Privacy service abuse | Various | Nonsense strings, reused fake names |

Privacy proxies don't prevent hunting — they shift the pivot from the registrant to structural correlators: creation date clustering, registrar patterns, nameserver patterns, and certificate history.

### Date Clustering as Campaign Timing Indicators

**Creation date clusters** reveal campaign waves. If you find ten domains matching a phishing pattern and eight of them were registered within a 48-hour window, those eight domains were prepared for a single campaign. The remaining two may be earlier reconnaissance or re-registration after takedown.

**Update date correlation** can reveal when an actor activated dormant infrastructure. A domain registered months ago with a sudden WHOIS update (new nameservers, new DNS records) often signals the start of active use.

**Expiry date management** reveals actor sophistication: disciplined actors renew domains well before expiry; rushed actors let domains expire and re-register, sometimes losing them to domain squatters.

### Registrant Email Pivoting

Before GDPR enforcement made registrant emails widely redacted, a single registrant email could link dozens of domains across years of campaigns. Legacy WHOIS databases (DomainTools' historical WHOIS, for example) still contain pre-GDPR data. A single historical email address lookup can reveal an actor's full prior registration history.

Even with redaction, some actors forget to use privacy proxies on older registrations, or use different registrars inconsistently, leaving exposed emails that anchor the entire cluster.

### RDAP: The WHOIS Replacement

The Registration Data Access Protocol (RDAP) is the structured, JSON-based successor to WHOIS. Unlike WHOIS (which returns free-text with no standardized format), RDAP returns machine-readable JSON with defined field names.

```
# WHOIS query (human-readable, inconsistent)
whois example.com

# RDAP query (machine-readable JSON)
curl https://rdap.verisign.com/com/v1/domain/example.com
```

RDAP is important for automation: parsing WHOIS text requires brittle regex for each registrar's unique format; RDAP returns consistent JSON. For bulk hunting operations, use RDAP endpoints directly.

!!! tip "RDAP Bootstrap"
    IANA maintains an RDAP bootstrap registry at `https://data.iana.org/rdap/dns.json` that maps TLD to the authoritative RDAP server. This is the starting point for building TLD-aware RDAP lookups.

---

## 4. Subdomain Enumeration

A wildcard certificate (`*.actor-domain.com`) tells you the domain exists and the actor intends to use multiple subdomains. CT logs give you the actual subdomains as they are issued certificates. Combined with brute-force enumeration, you can map the full scope of a target's infrastructure.

### crt.sh Wildcard Queries

The `%` wildcard in crt.sh maps to SQL LIKE syntax:

```
# All subdomains of a domain
https://crt.sh/?q=%.target.com&output=json

# All domains containing a keyword
https://crt.sh/?q=%keyword%&output=json

# Exact match
https://crt.sh/?q=target.com&output=json
```

The JSON output includes `name_value` (the domain/SAN), `issuer_name`, `not_before` (issuance time), and `not_after` (expiry). Parse `name_value` carefully — a single certificate can contain dozens of SANs, and crt.sh returns one entry per SAN, so deduplication is required.

### Passive Subdomain Enumeration Tools

**Subfinder (Project Discovery)**

```bash
# Passive enumeration only — no DNS brute-forcing, just data source queries
subfinder -d target.com -silent -o subdomains.txt

# With specific sources
subfinder -d target.com -sources crtsh,virustotal,securitytrails -silent
```

Subfinder queries ~40 data sources (crt.sh, VirusTotal, SecurityTrails, Shodan, etc.) and aggregates results. It does not send any packets to the target.

**Amass (OWASP)**

```bash
# Passive mode — no active probing
amass enum -passive -d target.com -o amass-results.txt

# With configuration file for API keys
amass enum -passive -d target.com -config ~/.config/amass/config.yaml
```

Amass is more comprehensive but slower than Subfinder; it does graph analysis and can correlate ASN/IP data in addition to DNS names.

### DNS Brute-Force Trade-offs

Active DNS brute-forcing resolves a wordlist against the target domain:

```bash
# Using dnsx for fast resolution
cat wordlist.txt | dnsx -d target.com -silent -resp
```

**Pros**: Discovers subdomains not indexed in CT logs or pDNS (new subdomains, internal-facing services).

**Cons**: Generates DNS queries that appear in the target's authoritative server logs. For intelligence operations against adversary infrastructure, this reveals your interest in the target. Wildcard DNS responses can produce false positives that require filtering.

!!! danger "Brute-Force OPSEC"
    DNS brute-force queries resolve at the target's authoritative nameserver. If you are investigating actor infrastructure, a brute-force run tells the actor (or their hosting provider) that someone is enumerating their domains. Use passive CT log data and pDNS first. Reserve brute-force for cases where you've already assessed the target is unaware of your investigation, or where the operational benefit outweighs the visibility risk.

**Wordlist Selection**

- `SecLists/Discovery/DNS/subdomains-top1million-5000.txt` — General purpose, fast
- `SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt` — Larger coverage
- Custom wordlists derived from CT log patterns for the specific actor

---

## 5. Temporal Analysis: Infrastructure Staging Sequences

Adversaries stage infrastructure in a predictable sequence. Each step leaves a timestamp in a different data source. Correlating these timestamps across data sources produces a **staging timeline** that:

1. Confirms the relationship between indicators (they were set up together, therefore they belong to the same campaign)
2. Reveals preparation lead time (how far in advance the actor stages infrastructure before use)
3. Enables forward prediction (if staging typically happens 2-3 days before a campaign, newly staged infrastructure may indicate an imminent attack)

### The Staging Sequence

```
[WHOIS: domain registered]
        ↓  (minutes to hours)
[CT Log: certificate issued]
        ↓  (minutes to hours)
[pDNS: domain resolves to IP]
        ↓  (hours to days)
[Shodan/Censys: service appears in scan data]
        ↓  (hours to days after DNS)
[First seen in threat intel feeds]
```

### Time-Gap Analysis

For a set of related domains, calculate the gap between:

- WHOIS creation → first CT log entry (cert issuance speed indicates automation vs. manual setup)
- CT log entry → first pDNS resolution (propagation and activation timing)
- First pDNS → first malicious use observed (dwell time before activation)

Consistent time gaps across multiple domains from the same actor are a clustering signal. Two campaigns with identical `cert_issuance_to_first_use` timing suggest the same operator or tooling.

### Detecting Dormant Infrastructure Activation

Actors sometimes pre-register domains months before use to bypass domain-age-based reputation filters. A domain registered six months ago that suddenly:

- Receives a new TLS certificate
- Has its DNS updated to point to a VPS
- Starts appearing in pDNS records

...is activating dormant infrastructure. pDNS "first seen" timestamps combined with WHOIS creation dates reveal the gap. Domains where `first_dns_activity` significantly postdates `whois_creation` warrant investigation.

!!! tip "Bulk Date Analysis"
    When working with a set of 50+ related domains, export all WHOIS creation dates and CT issuance dates to a spreadsheet. Plot them on a timeline. Campaign waves will be visually obvious as date clusters — groups of domains registered or cert'd within the same 24-48 hour window.

---

## 6. Tool Reference

### crt.sh

**Web Interface:** `https://crt.sh/?q=QUERY`

**API Queries:**

```bash
# Domains containing keyword
curl -s "https://crt.sh/?q=%25keyword%25&output=json" | jq '.[].name_value'

# All subdomains of a domain
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u

# With cert metadata
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[] | [.name_value, .issuer_name, .not_before] | @tsv'

# Deduplicated domains, newest first
curl -s "https://crt.sh/?q=%25keyword%25&output=json" | \
  jq -r 'sort_by(.not_before) | reverse | .[].name_value' | sort -u
```

**Parsing Notes:** `name_value` can contain newline-separated SANs within a single entry. Parse with `.split('\n')` and flatten before deduplication.

### SecurityTrails API

```python
import requests

API_KEY = "YOUR_API_KEY"
BASE = "https://api.securitytrails.com/v1"
headers = {"APIKEY": API_KEY}

# Current subdomains
r = requests.get(f"{BASE}/domain/target.com/subdomains", headers=headers)

# Historical DNS (pDNS)
r = requests.get(f"{BASE}/history/target.com/dns/a", headers=headers)

# WHOIS history
r = requests.get(f"{BASE}/history/target.com/whois", headers=headers)

# Associated domains (reverse WHOIS by IP)
r = requests.get(f"{BASE}/domain/target.com/associated-domains", headers=headers)
```

**Free tier:** 50 API queries/month. Paid tiers provide full pDNS history and higher rate limits.

### VirusTotal

```bash
# Domain report (includes pDNS, subdomains, related URLs)
curl -s "https://www.virustotal.com/api/v3/domains/target.com" \
  -H "x-apikey: YOUR_VT_KEY" | jq .

# Passive DNS resolutions for a domain
curl -s "https://www.virustotal.com/api/v3/domains/target.com/resolutions" \
  -H "x-apikey: YOUR_VT_KEY" | jq '.data[].attributes'

# Files communicating with a domain (malware samples)
curl -s "https://www.virustotal.com/api/v3/domains/target.com/communicating_files" \
  -H "x-apikey: YOUR_VT_KEY" | jq '.data[].attributes.sha256'
```

**Free tier:** 4 requests/minute, 500/day. The `communicating_files` endpoint is particularly powerful — it links infrastructure to actual malware samples.

### RiskIQ / PassiveTotal (Microsoft Defender TI)

PassiveTotal merged into Microsoft Defender Threat Intelligence. The legacy PassiveTotal API remains accessible:

```python
import requests
from requests.auth import HTTPBasicAuth

auth = HTTPBasicAuth("user@email.com", "API_KEY")
BASE = "https://api.passivetotal.org/v2"

# Passive DNS
r = requests.get(f"{BASE}/dns/passive", auth=auth,
                 params={"query": "target.com"})

# WHOIS history
r = requests.get(f"{BASE}/whois/search/keyword",
                 auth=auth, params={"query": "registrant@email.com"})

# SSL certificates (pivot from IP to domains)
r = requests.get(f"{BASE}/ssl-certificate/history",
                 auth=auth, params={"query": "1.2.3.4"})
```

The SSL pivot is uniquely powerful: given an IP address, retrieve all SSL certificates that have been observed on that IP, then expand to all domains using those certificates.

### DomainTools

```python
# DomainTools API (paid)
import requests

BASE = "https://api.domaintools.com/v1"

# WHOIS history
r = requests.get(f"{BASE}/target.com/whois/history/",
                 params={"api_username": "user", "api_key": "key"})

# Reverse WHOIS (find domains registered by same registrant)
r = requests.get(f"{BASE}/reverse-whois/",
                 params={"terms": "registrant@email.com",
                         "api_username": "user", "api_key": "key"})

# Domain risk score
r = requests.get(f"{BASE}/target.com/risk/",
                 params={"api_username": "user", "api_key": "key"})
```

DomainTools' reverse WHOIS and WHOIS history are the deepest available. The `iris-investigate` endpoint provides a full infrastructure pivot graph in a single call.

### Subfinder / Amass

```bash
# Subfinder — fast passive enumeration
subfinder -d target.com -all -silent | tee subdomains-subfinder.txt

# With API keys configured in ~/.config/subfinder/provider-config.yaml
subfinder -d target.com -all -silent -pc ~/.config/subfinder/provider-config.yaml

# Amass — comprehensive, slower
amass enum -passive -d target.com 2>/dev/null | tee subdomains-amass.txt

# Combine and deduplicate
cat subdomains-subfinder.txt subdomains-amass.txt | sort -u > all-subdomains.txt

# Probe which subdomains resolve (without brute-forcing the target)
cat all-subdomains.txt | dnsx -silent -resp | tee resolved-subdomains.txt
```

---

## 7. Case Study: Tracking a Phishing Campaign Through CT Logs

This walkthrough demonstrates the full methodology on a hypothetical phishing campaign targeting a financial institution.

### Step 1: Keyword Alert Fires

A CT log monitor alerts on a new certificate containing the keyword `[bank]-secure`:

```
Domain: secure-[bank]-login.com
Issuer: Let's Encrypt
Issued: 2024-03-15T02:34:11Z
```

The issuance at 02:34 UTC (middle of the night for the target bank's region) is consistent with automated, adversarial cert issuance rather than legitimate IT activity.

### Step 2: Domain Resolution

```bash
# Resolve the domain
dig secure-[bank]-login.com A +short
# Returns: 185.220.101.77

# Check when it first appeared in pDNS
# (via SecurityTrails or VirusTotal pDNS API)
# First seen: 2024-03-15T03:01:00Z  (27 minutes after cert issuance)
```

The 27-minute gap from cert issuance to first DNS resolution indicates automated deployment — a human manually setting up infrastructure would take longer.

### Step 3: IP Mapping and Cluster Identification

```bash
# Check what else is hosted on 185.220.101.77
# Shodan lookup: shodan host 185.220.101.77
# Other domains at this IP (via PassiveTotal/pDNS):
#   - update-[bank]-account.com
#   - [bank]-verification-portal.net
#   - secure-payment-[bank].com
```

Three related domains on the same IP — same campaign, same infrastructure. Each has a certificate in CT logs issued within 6 hours of each other on the same day.

### Step 4: Registrant Pivot

```bash
# WHOIS all four domains
# Results:
#   Registrar: Namecheap, Inc. (all four)
#   Privacy: WhoisGuard Protected (all four)
#   Created: 2024-03-14 (all four, ~12 hours before cert issuance)
#   Nameservers: ns1.cloudflare.com (all four)
```

The registration preceded cert issuance by 12 hours, confirming these were registered in a batch before the campaign went live. All four domains use identical registrar, privacy service, and nameserver configuration — clear evidence of a shared operator.

### Step 5: Expand to Find Additional Domains

```bash
# Search crt.sh for the same registrar pattern with similar keywords
curl -s "https://crt.sh/?q=%25[bank]%25&output=json" | \
  jq -r '.[] | select(.not_before > "2024-03-14") | .name_value' | sort -u

# Also search for the IP range (185.220.101.0/24) in Shodan
# Pivot on the Cloudflare nameserver + Namecheap + WhoisGuard pattern
# in WHOIS history to find older domains from same actor
```

This expansion often reveals 10-30x more domains than the initial indicator — the full campaign infrastructure.

### Step 6: Timeline Reconstruction

| Timestamp | Event | Source |
|---|---|---|
| 2024-03-13 18:00 | VPS provisioned at 185.220.101.77 | Shodan first-seen |
| 2024-03-14 11:30 | All four domains registered | WHOIS creation date |
| 2024-03-15 02:34 | TLS certs issued (Let's Encrypt) | CT logs |
| 2024-03-15 03:01 | DNS resolves to VPS | pDNS first-seen |
| 2024-03-15 09:00 | First phishing email observed | Threat intel |

The 18-hour gap between VPS provisioning and domain registration suggests the actor staged hosting first, then acquired domains. The 12-hour gap between registration and cert issuance is consistent with ACME automation running on a delay (possibly a cron job at 02:30 UTC).

!!! tip "Attribution Note"
    This timeline pattern — VPS first, domains second, certs third, DNS last — is consistent with automated deployment tooling. Actors using manual methods show irregular time gaps. The consistency of automated patterns makes them more attributable across campaigns.

---

## 8. OPSEC for Infrastructure Hunters

!!! danger "DNS Queries Leave Traces"
    Every DNS lookup you make for an adversary domain resolves at one or more recursive resolvers and may also reach the target's authoritative nameserver (depending on cache TTL). If you are investigating active infrastructure:

    - Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to prevent your ISP or network from logging your queries.
    - Consider using a VPN or Tor exit node for DNS lookups against live adversary infrastructure.
    - Prefer looking up domains in pDNS databases rather than resolving them directly — this queries a historical database, not the adversary's DNS.

!!! warning "CT Log Queries Are Public"
    crt.sh queries are not private. While crt.sh itself does not log user queries with identifying information, the underlying CT logs are public by design. Additionally, if an adversary monitors their own CT log entries (a common practice for detecting hunter interest), they may observe lookups correlated with their domains.

    For sensitive investigations, perform initial triage offline using bulk CT log data exports rather than individual web queries.

!!! tip "Tool Fingerprints"
    Tools like Subfinder and Amass use distinctive User-Agent headers and query patterns. If you are investigating an actor who monitors their infrastructure (e.g., watches for port scans on their C2 servers), passive enumeration via third-party data sources is safer than direct active probing. See Module 0x09 for comprehensive hunter OPSEC methodology.

---

## 9. Module Project: CT Log Infrastructure Hunter

*Reference: Hacking APIs, OSINT Techniques*

The expanded capstone project demonstrates the full methodology: CT log hunting, DNS resolution, WHOIS enrichment, pDNS clustering, and multi-format output.

### Key Design Decisions

- **Offline-first architecture**: Every external call has a mock fallback so the tool works without network access or API keys in demo/training environments.
- **Multiple query modes**: Single keyword (`-q`) or keyword file (`-k`) for bulk hunting.
- **pDNS clustering**: Groups domains by resolved IP to surface shared infrastructure automatically.
- **Multi-format output**: Text (default), JSON (`--format json`), and CSV (`--format csv`) for integration with downstream tools.

### Core Architecture

```python
#!/usr/bin/env python3
"""
ct_hunter.py — Certificate Transparency Log Infrastructure Hunter
Module 0x02 Capstone Project | AIH-C Curriculum

@decision DEC-CT-001
@title Offline-first with mock fallbacks
@status accepted
@rationale Training environments lack network access and API keys.
  Mock fallbacks ensure every code path is exercisable in class.
  Real data paths are used when network is available.
"""

import argparse
import csv
import json
import socket
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple
```

### CLI Interface

```bash
# Demo mode — runs with built-in keywords, no args required
python ct_hunter.py

# Single keyword query
python ct_hunter.py -q "microsoft-update"

# Keyword file with DNS resolution and JSON output
python ct_hunter.py -k keywords.txt --resolve --format json

# CSV export for spreadsheet analysis
python ct_hunter.py -q "admin-portal" --resolve --format csv > results.csv
```

### pDNS Cluster Output

The tool groups discovered domains by resolved IP, revealing shared hosting:

```
[*] Infrastructure Cluster: 185.220.101.77
    - secure-bank-login.com          (cert: 2024-03-15)
    - update-bank-account.com        (cert: 2024-03-15)
    - bank-verification-portal.net   (cert: 2024-03-15)
```

Three domains resolving to the same IP within hours of each other is the staging sequence signature described in Section 5.

### Full Project Source

The complete, annotated project source is at `projects/0x02_ct_hunter/ct_hunter.py`. Key capabilities:

1. **CT log querying** — crt.sh JSON API with deduplication and sorting by issuance date
2. **DNS resolution** — A, AAAA, MX, NS records via `socket.getaddrinfo()`
3. **WHOIS enrichment** — `python-whois` if installed, mock fallback otherwise
4. **pDNS clustering** — Groups domains by IP for shared infrastructure detection
5. **Multi-format output** — Text/JSON/CSV with `--format` flag
6. **Keyword file support** — `-k keywords.txt` for bulk hunting campaigns

Run it:

```bash
cd projects/0x02_ct_hunter
python ct_hunter.py                          # demo mode
python ct_hunter.py -q "phishing-keyword"   # single query
python ct_hunter.py -k keywords.txt --resolve --format json
```

---

## Summary

Infrastructure mapping turns a single indicator into a campaign picture. The methodology:

1. **CT logs** reveal domains and certs at the moment of issuance — the earliest detectable signal.
2. **pDNS** maps the historical relationship between domains and IPs, enabling lateral pivoting.
3. **WHOIS** provides temporal clustering and registrar patterns that group related infrastructure.
4. **Subdomain enumeration** completes the picture for each discovered domain.
5. **Temporal analysis** converts individual indicators into a campaign timeline that supports attribution.

Combined with the TLS fingerprinting from Module 0x01, you can both detect infrastructure at registration time (CT logs) and confirm it as belonging to a known actor at connection time (JARM/JA3 fingerprints). The two modules are complementary: 0x01 identifies *what* is running; 0x02 finds *everything else the actor is running*.
