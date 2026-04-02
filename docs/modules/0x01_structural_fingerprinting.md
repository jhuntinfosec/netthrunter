# Module 0x01: Structural Fingerprinting

## Overview

Instead of blocking an IP, we block the **Server Response Pattern**. This module covers deep-dive techniques into JARM, JA3/S, JA4+, TLS handshake anomalies, SSH banner fingerprinting, HTTP/2 behavioral signatures, and how to operationalize these fingerprints at scale using Shodan and Censys.

The core insight: threat actors spin up new IPs constantly. But they reuse tools, frameworks, and default configurations. A default Cobalt Strike listener on any IP in any country produces the same JARM hash. Find the hash, find the infrastructure — globally, proactively.

## Key Concepts

* **JA3/JA3S**: Passive fingerprinting of TLS negotiation — client and server sides.
* **JARM**: Active TLS server fingerprinting using 10 crafted probes.
* **JA4+**: Next-generation fingerprinting family (TLS, HTTP, X.509, TCP).
* **HTTP/2 Fingerprinting**: SETTINGS frame ordering and WINDOW_UPDATE values as behavioral signatures.
* **HASSH**: SSH key exchange algorithm fingerprinting.

!!! tip "Hunter's Note"
    Many actors use default Go or Python TLS implementations without customization. Hunting the specific JARM hash of a default Sliver or Mythic C2 server allows global pre-emptive infrastructure mapping before any traffic is seen on your network.

---

## Deep Dive: JARM — Active TLS Server Fingerprinting

JARM was developed by Salesforce in 2020 as an **active** fingerprinting technique. Unlike passive methods that observe existing traffic, JARM deliberately sends 10 crafted TLS Client Hello packets to a server and records how it responds. The responses are hashed into a 62-character fingerprint that is remarkably stable across deployments of the same server software.

### The 10-Probe Mechanism

Each probe varies three dimensions of the TLS Client Hello:

| Probe | TLS Version | Cipher Suite Order | Extensions |
|-------|-------------|-------------------|------------|
| 1 | TLS 1.2 | Forward (standard order) | None |
| 2 | TLS 1.2 | Reverse | None |
| 3 | TLS 1.2 | Forward | Max Fragment Length |
| 4 | TLS 1.2 | Reverse | Max Fragment Length |
| 5 | TLS 1.1 | Forward | None |
| 6 | TLS 1.1 | Reverse | None |
| 7 | TLS 1.3 | Forward | None |
| 8 | TLS 1.3 | Reverse | None |
| 9 | TLS 1.3 | Forward | Key Share only |
| 10 | TLS 1.3 | Reverse | Key Share + Supported Versions |

The probes deliberately include invalid or unusual combinations (e.g., TLS 1.1 with TLS 1.3 cipher suites) to expose how the server implementation handles edge cases. A well-tuned OpenSSL server responds differently than a Go `crypto/tls` server, which responds differently than a Java JSSE server.

### Hash Construction

For each of the 10 probes, JARM records two values from the Server Hello response:

1. **The selected cipher suite** (2-byte hex value, e.g., `c02b`)
2. **An ALPN extension hash** — a truncated hash of the server's supported ALPN protocols

If the server does not respond (timeout, reset, or rejects the probe), that probe's slot is filled with `000000000000`.

The 10 cipher values and 10 ALPN hashes are concatenated, then the combined string is hashed with SHA-256. The first 30 hex characters of the SHA-256 hash form the second part of the JARM fingerprint. The full 62-character hash is:

```
<10 × 6-char cipher+version tokens>|<30-char SHA-256 prefix>
```

For example, the Cobalt Strike default JARM hash is:

```
07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
```

### Why C2 Frameworks Produce Unique Hashes

Different C2 frameworks embed different TLS stacks:

- **Cobalt Strike** (Java-based): JSSE cipher preference ordering, Java's specific extension handling
- **Metasploit** (Ruby): OpenSSL via Ruby's `openssl` bindings, specific cipher negotiation behavior
- **Sliver** (Go): Go's `crypto/tls` — famously opinionated about cipher suites and extensions
- **Havoc** (C++): Boost.Asio + OpenSSL, different cipher preference than vanilla OpenSSL
- **Mythic** (Python): Python's `ssl` module wrapping OpenSSL, specific to Python version

Even when operators change the certificate, the underlying TLS stack behavior remains the same. The JARM hash survives certificate rotation.

!!! warning "Caveats"
    JARM is not infallible. Experienced operators can customize TLS stack configurations. Modern Cobalt Strike with malleable C2 profiles can alter the TLS behavior. However, operators who don't read the documentation (the majority) run defaults.

---

## JA3 / JA3S Fingerprinting

JA3 was developed by Salesforce in 2017 as a **passive** fingerprinting technique. It operates on observed TLS traffic (packet captures, inline sensors) rather than active probing.

### JA3: Client Hello Fingerprinting

JA3 extracts five fields from the TLS Client Hello and hashes them:

```
MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
```

**Extraction process:**

1. **SSLVersion**: The TLS version in the Client Hello record (e.g., `769` for TLS 1.0, `771` for TLS 1.2)
2. **Ciphers**: Comma-separated decimal values of all proposed cipher suites, excluding GREASE values
3. **Extensions**: Comma-separated decimal values of extension types present
4. **EllipticCurves**: Comma-separated decimal values from the `supported_groups` extension
5. **EllipticCurvePointFormats**: Values from the `ec_point_formats` extension

The five values are joined with `-` delimiters and MD5-hashed:

```python
ja3_string = f"{ssl_ver},{ciphers},{extensions},{curves},{point_formats}"
ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
```

**Example raw string:**
```
771,4866-4867-4865-49196-...,0-23-65281-10-11-35-16-5-...,29-23-24,0
```

This string is deterministic for a given client implementation. Chrome 120 produces the same JA3 hash regardless of what website it visits. Malware families using hardcoded TLS configurations produce unique, stable JA3 hashes.

### JA3S: Server Hello Fingerprinting

JA3S is the server-side equivalent. It extracts:

```
MD5(SSLVersion,Cipher,Extensions)
```

Where `Cipher` is the single cipher suite the server selected, and `Extensions` are those present in the Server Hello. JA3S is most useful for identifying specific server implementations and correlating client-server pairs (a specific malware communicating with a specific C2 framework produces a unique JA3+JA3S pair).

### Operational Use: Identifying Malware Families

JA3 is most powerful when combined with behavioral context:

| Malware Family | Known JA3 Hash | Notes |
|---------------|----------------|-------|
| Trickbot | `6734f37431670b3ab4292b8f60f29984` | Default config |
| Emotet | `a0e9f5d64349fb13191bc781f81f42e1` | Variant dependent |
| AgentTesla | `de9f2c7fd25e1b3afad3e85a0bd17d9b` | .NET default |
| Cobalt Strike | `72a589da586844d7f0818ce684948eea` | Default profile |

!!! tip "JA3 Database Resources"
    - **ja3er.com**: Community-maintained JA3 hash database with application context
    - **SSLBL (abuse.ch)**: [sslbl.abuse.ch](https://sslbl.abuse.ch/ja3-fingerprints/) — curated malicious JA3 hashes
    - **trisul-hub**: Open-source JA3 Lua plugin for Suricata/Zeek

---

## JA4+ Family Overview

JA4+ is a next-generation fingerprinting family developed by FoxIO in 2023. It improves on JA3 by being more human-readable, sortable, and resistant to GREASE randomization. The family covers multiple protocol layers:

### JA4 (TLS Client Fingerprint)

Format: `t<version><sni_flag><num_ciphers><num_extensions><alpn>_<cipher_hash>_<extension_hash>`

```
t13d1516h2_8daaf6152771_e5627efa2ab1
│││││     │ └ cipher hash  └ extension hash
││││└─────┘ ALPN (h2 = HTTP/2)
│││└ 16 extensions
││└ 15 ciphers
│└ d = SNI domain present
└ t13 = TLS 1.3
```

Key improvements over JA3:
- Type prefix (`t` for TLS) makes it visually distinct from other JA4 types
- Version is human-readable (`13` for TLS 1.3, `12` for TLS 1.2)
- Two-part hash separates cipher preferences from extension set
- GREASE values excluded, preventing GREASE-based evasion

### JA4S (TLS Server Fingerprint)

Mirrors JA4 for server responses. Captures the server's selected cipher, supported extensions, and version negotiation choice.

### JA4H (HTTP Client Fingerprint)

Fingerprints HTTP/1.1 and HTTP/2 request headers:
- HTTP method, version, cookie presence
- Header count and order
- Language preference hash
- Accepted content type hash

This is powerful for identifying automated tools (curl, requests, httpx) even when they present legitimate User-Agent strings.

### JA4X (X.509 Certificate Fingerprint)

Fingerprints TLS certificate structure:
- Issuer and subject distinguished name field presence
- Extension OIDs in order
- Key algorithm and size

JA4X fingerprints self-signed certificates consistently — even when operators regenerate certificates with new keys and dates, the structural fingerprint remains the same if they use the same generation script.

### JA4T (TCP Fingerprint)

Operates at the TCP layer, capturing:
- Initial window size
- TCP options order (MSS, window scaling, SACK, timestamps)
- TTL class

JA4T correlates with operating system and TCP stack implementation. Useful for detecting hosts that claim to be one OS but have TCP behavior of another (VMs, containerized C2).

!!! tip "JA4+ Resources"
    Official implementation and hash database: [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)

---

## HTTP/2 Fingerprinting

HTTP/2 introduces frame-level multiplexing with configurable parameters. These parameters, and the order in which a client or server sends them, form a behavioral fingerprint. This technique is sometimes called the "Akamai fingerprint" from early research.

### SETTINGS Frame Fingerprinting

When an HTTP/2 connection is established, both sides send a SETTINGS frame announcing their capabilities. The fingerprint captures:

1. **SETTINGS parameter IDs and values** in transmission order
2. **WINDOW_UPDATE initial value** for the connection-level flow control window
3. **HEADERS frame pseudo-header order**: `:method`, `:authority`, `:scheme`, `:path`

**Example fingerprint string format:**
```
1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
```
Where:
- `1:65536;3:1000;4:6291456;6:262144` = SETTINGS id:value pairs
- `15663105` = WINDOW_UPDATE increment
- `0` = PRIORITY frame weight (if sent)
- `m,a,s,p` = pseudo-header order

### Why This Matters for C2 Detection

Go's `net/http` HTTP/2 implementation sends SETTINGS in a specific order with specific default values. Python's `httpx` sends different values. A C2 beacon using Go HTTP/2 transport will produce a consistent SETTINGS fingerprint even with a custom User-Agent.

Tools like **CICADA** and **hfinger** (open-source) extract HTTP/2 fingerprints from PCAP files. HTTP/2 fingerprinting is particularly valuable for:
- Identifying Go-based implants (Sliver, Merlin) behind HTTPS
- Detecting automated beaconing patterns from scripted tools
- Distinguishing operator interactive sessions from automated callbacks

---

## SSH Banner and Key Exchange Fingerprinting

SSH infrastructure hunting uses two complementary techniques: banner fingerprinting and HASSH.

### SSH Banner Analysis

The SSH version string (e.g., `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`) is sent in cleartext before any encryption. It reveals:
- **Software and version**: OpenSSH, Dropbear, libssh, paramiko
- **Platform hints**: Vendor-customized builds often include platform identifiers
- **Age indicators**: Older versions suggest unpatched systems

For C2 hunting, custom or non-standard SSH banners on port 22 or non-standard ports are strong indicators. Cobalt Strike's Beacon with SSH C2 channels, or custom droppers using paramiko, produce distinctive banners.

### HASSH: Hashing SSH Handshake Parameters

HASSH (developed by Salesforce, 2018) fingerprints the SSH key exchange by hashing the algorithm lists exchanged during `SSH_MSG_KEXINIT`:

**HASSH (client):**
```
MD5(kex_algorithms;encryption_algorithms_client_to_server;
    mac_algorithms_client_to_server;compression_algorithms_client_to_server)
```

**HASSHServer (server):**
```
MD5(kex_algorithms;encryption_algorithms_server_to_client;
    mac_algorithms_server_to_client;compression_algorithms_server_to_client)
```

Different SSH implementations negotiate algorithms in different orders with different preferences. Paramiko (Python SSH library, widely used in implants) produces a distinctive HASSH that differs from OpenSSH.

| Implementation | Known HASSH |
|----------------|-------------|
| OpenSSH 8.x client | `ec7378c1a92f5a8dde7e8b7a1ddf33d1` |
| Paramiko (Python) | `92674389fa1e47a27ddd8d9b63ecd42b` |
| Dropbear | `f2571c6c7bb5b0b5ab13b5ad15490cad` |

Shodan indexes HASSH values. Searching for non-standard HASSH hashes on internet-exposed SSH ports surfaces unusual server implementations that may be C2 infrastructure.

---

## Tool Reference: Operationalizing Fingerprints

### Shodan

Shodan scans the internet continuously and indexes TLS/SSH fingerprints. Key filters:

```
# Find all hosts with a specific JARM hash (Cobalt Strike default)
ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1

# Find all Sliver C2 default JARM
ssl.jarm:00000000000000000043d43d00043de2a97eabb398317329f027baae0867a

# Combine JARM with port for more precision
ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 port:443

# Filter by ASN to scope to specific hosting providers
ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 asn:AS20473

# JA3S fingerprint search
ssl.ja3s:ec7378c1a92f5a8dde7e8b7a1ddf33d1

# HASSH for SSH fingerprinting
hassh:92674389fa1e47a27ddd8d9b63ecd42b
```

Shodan API rate limits apply. Use `shodan search --fields ip_str,port,ssl.jarm` for bulk CSV export.

### Censys

Censys provides deep TLS certificate and handshake data:

```
# JA3S filter
services.tls.ja3s:"ec7378c1a92f5a8dde7e8b7a1ddf33d1"

# JARM in Censys
services.tls.jarm_fingerprint:"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"

# Certificate serial number clustering
services.tls.certificates.leaf_data.subject.common_name:"Major Cobalt Strike"

# Combine with port and protocol
services.port:8443 AND services.tls.jarm_fingerprint:"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
```

Censys provides 1 query/second on free tier; use the Python SDK with `CensysHosts` for bulk lookups.

### Abuse.ch SSLBL

The SSL Blacklist at [sslbl.abuse.ch](https://sslbl.abuse.ch) maintains:
- **JA3 Fingerprint Database**: Known malicious JA3 hashes with malware family attribution
- **SSL Certificate Blacklist**: Known malicious certificate SHA-1 fingerprints
- **JARM Hashes**: Select known-bad JARM hashes from tracked C2 infrastructure

Download the full JA3 blocklist in CSV format from `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv` for offline enrichment.

### ja3er.com

[ja3er.com](https://ja3er.com) is a community-maintained lookup service:
- `GET https://ja3er.com/search/<ja3_hash>` returns JSON with user-agent associations
- Useful for attributing unknown JA3 hashes to known applications
- API is unauthenticated, rate-limited to reasonable use

### Reference Implementations

| Tool | URL | Notes |
|------|-----|-------|
| JARM (original) | [github.com/salesforce/jarm](https://github.com/salesforce/jarm) | Salesforce reference implementation (Python) |
| jarm-py | [github.com/HD421/jarm-py](https://github.com/HD421/jarm-py) | Pip-installable JARM library |
| JA4+ | [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) | Full JA4 family (Zeek, Rust, Python) |
| HASSH | [github.com/salesforce/hassh](https://github.com/salesforce/hassh) | SSH fingerprinting (Zeek, Python) |
| ja3 (Zeek) | [github.com/salesforce/ja3](https://github.com/salesforce/ja3) | Zeek plugin for JA3 extraction |

---

## Real-World Case Study: Hunting Cobalt Strike at Scale

### The Default JARM Problem

Cobalt Strike ships with a default Java TLS configuration. Every default Cobalt Strike listener — regardless of operator, target sector, or geography — produces the same JARM hash:

```
07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
```

This hash is stable across Cobalt Strike versions 4.x (with some variation by Java version). The Shodan query above returns hundreds of active C2 servers globally at any given time.

### Default Metasploit JA3

Metasploit's default Meterpreter HTTPS listener uses Ruby's OpenSSL bindings with a specific cipher configuration. The resulting JA3 hash is:

```
92674389fa1e47a27ddd8d9b63ecd42b
```

This hash appears in the Abuse.ch SSLBL database attributed to multiple Metasploit campaigns.

### Step-by-Step: Mass C2 Discovery Workflow

```bash
# Step 1: Query Shodan for known-bad JARM hashes
shodan search --fields ip_str,port,ssl.jarm,timestamp \
  "ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1" \
  > cobalt_strike_candidates.csv

# Step 2: Verify with live JARM probe (reduces false positives)
python tls_fingerprint.py --targets cobalt_strike_candidates.csv \
  --format json --output verified_cs.json

# Step 3: Cross-reference certificate hashes with SSLBL
# (handled in Module 0x02 — Infrastructure Mapping)

# Step 4: Pivot on hosting ASN for related infrastructure
# (handled in Module 0x03 — Overlap Clustering)
```

### Known C2 JARM Hash Reference

| Framework | Default JARM Hash | Notes |
|-----------|------------------|-------|
| Cobalt Strike 4.x | `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` | Java JSSE default |
| Metasploit | `07d14d16d21d21d00007d14d16d21d218f67f00557ab8ac975a2abe8c4fe2b` | Ruby OpenSSL |
| Sliver (default) | `00000000000000000043d43d00043de2a97eabb398317329f027baae0867a` | Go crypto/tls |
| Havoc | `29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38` | Boost.Asio/OpenSSL |
| Mythic | `07d14d16d21d21d07c42d43d00041d2ef5d10e1457ab3ce4c6c0d3f3f39db` | Python ssl module |
| Brute Ratel C4 | `1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943` | Custom TLS |

!!! warning "Hash Drift"
    Operators with security awareness customize their TLS configurations. These hashes represent **default** deployments. Treat them as a starting point for clustering, not a definitive blocklist.

---

## OPSEC Note for Hunters

!!! danger "Your Scanner Has a Fingerprint Too"
    Every active probe you send — JARM, JA3, port scan — leaves a trace. Your scanner's own JA3 fingerprint is visible to the target server. A sophisticated operator monitoring their C2 infrastructure will see repeated TLS probes from the same source and may alert on them, burn their infrastructure, or worse, attempt attribution against your organization.

    Active scanning should always be conducted from isolated infrastructure. Cross-reference **Module 0x09: Hunter OPSEC** before running any active fingerprinting at scale. Key mitigations:

    - Use rotating egress IPs (Lambda scanners, covered in Module 0x09)
    - Throttle probe rates to blend with normal internet background noise
    - Never scan from your organization's production IP space
    - Consider using passive sources (Shodan/Censys) before any active probing

---

## Module Project: Active TLS Fingerprinting

*Reference: Black Hat Python 2E, Salesforce JARM Research*

Your task is to build a Python script that calculates the JARM hash of a given IP or list of IPs, extracts certificate metadata, computes a conceptual JA3-like fingerprint, and matches against a local database of known C2 hashes.

### The Objective

1. Connect to a target over TLS ports (443, 8443, etc.)
2. Extract certificate fields: issuer, subject CN, SANs, validity dates, serial number
3. Attempt JARM fingerprinting via `jarm` library (with mock fallback)
4. Compute a JA3-like fingerprint from SSL module cipher info
5. Match fingerprints against local known-C2 hash database
6. Output results as JSON or CSV
7. Optionally correlate with Shodan if `SHODAN_API_KEY` is set

### Key Functions and Design

```python
#!/usr/bin/env python3
"""
tls_fingerprint.py — Module 0x01 Capstone: Structural TLS Fingerprinting
Demonstrates JARM, JA3-concept, and certificate analysis for C2 hunting.

Usage:
  python tls_fingerprint.py                          # Default targets, demo mode
  python tls_fingerprint.py -t 1.2.3.4,5.6.7.8      # Comma-separated targets
  python tls_fingerprint.py -f targets.txt           # Targets from file
  python tls_fingerprint.py -t 1.2.3.4 --format csv # CSV output
"""
import argparse
import hashlib
import json
import ssl
import socket
import csv
import sys
import os
from datetime import datetime

# Known C2 JARM hash database for local matching
KNOWN_C2_JARMS = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": {
        "framework": "Cobalt Strike",
        "confidence": "high",
        "notes": "Default Java JSSE configuration, CS 4.x"
    },
    "07d14d16d21d21d00007d14d16d21d218f67f00557ab8ac975a2abe8c4fe2b": {
        "framework": "Metasploit",
        "confidence": "high",
        "notes": "Default Ruby OpenSSL Meterpreter HTTPS"
    },
    "00000000000000000043d43d00043de2a97eabb398317329f027baae0867a": {
        "framework": "Sliver",
        "confidence": "high",
        "notes": "Default Go crypto/tls"
    },
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": {
        "framework": "Havoc",
        "confidence": "medium",
        "notes": "Boost.Asio + OpenSSL"
    },
}

def get_cert_details(host: str, port: int = 443) -> dict:
    """
    Extract TLS certificate metadata and compute a JA3-like fingerprint.
    The ssl module gives us the negotiated cipher suite post-handshake,
    which is used to build a simplified fingerprint demonstrating the concept.
    True JA3 requires packet capture of the Client Hello.
    """
    ...

def get_jarm_hash(host: str, port: int = 443) -> str:
    """
    Attempt JARM fingerprinting. Uses jarm library if installed,
    falls back to a deterministic mock for offline/educational use.
    """
    ...

def match_known_c2(jarm_hash: str) -> dict | None:
    """Check JARM hash against local known-C2 database."""
    return KNOWN_C2_JARMS.get(jarm_hash)

def scan_target(host: str, port: int = 443) -> dict:
    """Orchestrate full fingerprint collection for a single target."""
    ...

def output_results(results: list, fmt: str, outfile=None):
    """Write results in the requested format (json or csv)."""
    ...
```

**Takeaway:** Running this script produces JSON or CSV output mapping hosts to their JARM hash, certificate fingerprint, and C2 match status — ready to feed into Shodan/Censys queries or the clustering module (0x03).

---

## Further Reading

- Salesforce JARM blog post: [engineering.salesforce.com/tls-fingerprinting-with-jarm](https://engineering.salesforce.com/tls-fingerprinting-with-jarm-e75a08a22f58)
- FoxIO JA4+ specification: [github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
- HASSH blog post: [engineering.salesforce.com/open-sourcing-hassh](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c)
- Shodan JARM hunting: [blog.shodan.io/identifying-cobalt-strike-servers](https://blog.shodan.io/identifying-cobalt-strike-servers/)
- HTTP/2 fingerprinting: [lwthiker.com/networks/2022/06/17/http2-fingerprinting.html](https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html)
