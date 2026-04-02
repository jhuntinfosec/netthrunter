# Module 0x04: C2 & Open Directories

## Overview

Identifying the exact Command and Control (C2) software allows us to understand the adversary's capabilities, lateral movement potential, and implant lifecycle. This module covers framework-specific fingerprints at depth — from cryptographic cert serial numbers to HTTP checksum algorithms — and teaches how to hunt for misconfigured, public open directories exposing malicious staged payloads.

This builds directly on Module 0x01 (TLS fingerprinting), Module 0x02 (infrastructure mapping), and Module 0x03 (overlap clustering). The techniques here transform a single IP address into a positively-identified C2 framework with high confidence.

## Key Concepts

* **Advanced Dorking**: Searching exposed file systems via Google, Shodan, or custom web scanners.
* **Framework Fingerprints**: Cobalt Strike (checksums, stagers, Malleable profiles), Sliver, Havoc, Mythic, Brute Ratel.
* **Stager Profiling**: Differentiating between default stagers and bespoke web servers.
* **Certificate Analysis**: Default TLS cert attributes unique to each framework's installer.
* **Header Fingerprinting**: Server response headers that reveal framework identity.

---

## Cobalt Strike: Deep Fingerprinting

Cobalt Strike remains the dominant commercial offensive framework encountered in threat intelligence. Its default configuration leaves multiple high-confidence indicators that survive across operator skill levels — even experienced red teamers routinely leave at least one.

### Default TLS Certificate

The single most reliable Cobalt Strike indicator is the default self-signed certificate issued during team server setup. Operators who forget to generate a custom certificate (or choose not to) expose a certificate with:

| Field | Default Value |
|-------|--------------|
| Serial Number | `146473198` |
| Subject CN | `Major Cobalt Strike` |
| Issuer O | `cobaltstrike` |
| Subject O | `cobaltstrike` |
| Validity | 1-year from install date |

The serial number `146473198` (hex `0x8BC3430E`) is hardcoded in the Cobalt Strike installer. A Shodan search surfaces thousands of active team servers:

```
ssl.cert.serial:146473198
```

Or using Censys certificate search:

```
parsed.serial_number: 146473198
```

This is not a guarantee of malicious use — some authorized red team engagements use default certs by choice — but in context with other indicators it becomes conclusive.

### Team Server Default Ports

| Port | Service |
|------|---------|
| 50050 | Team server operator console (Java Swing UI) |
| 80 | Default HTTP listener |
| 443 | Default HTTPS listener |
| 8080 | Alternate HTTP listener |

The operator console on 50050 does not speak HTTP — it is a custom binary protocol. A port scan revealing 50050 open, combined with the cert serial, is near-conclusive. Shodan indexes the 50050 banner:

```
product:"Cobalt Strike Beacon" port:50050
```

### The checksum8 Algorithm

This is the most technically interesting Cobalt Strike indicator. When a beacon stages itself, it makes an HTTP GET to a URI path that encodes whether it wants the x86 or x64 implant. The algorithm:

> For every character in the URI path, sum the ASCII values of each character. Take that sum modulo 256. If the result equals **92**, the server responds with the x86 stager. If the result equals **93**, the server responds with the x64 stager.

Python implementation (also in the module project):

```python
def checksum8(uri: str) -> int:
    """
    Compute the Cobalt Strike URI checksum.
    Returns 92 for x86, 93 for x64, or another value for non-stager URIs.
    """
    return sum(ord(c) for c in uri) % 256

def generate_stager_uri(target_checksum: int, length: int = 4) -> str:
    """
    Generate a URI path that satisfies the given checksum target (92 or 93).
    Uses simple alphanumeric characters.
    """
    import random
    import string
    chars = string.ascii_lowercase + string.digits
    while True:
        path = ''.join(random.choice(chars) for _ in range(length))
        if checksum8(path) == target_checksum:
            return path

# Example: validate a suspected stager URI
uri_path = "wPnl"  # strip leading slash before computing
print(checksum8(uri_path))  # Should be 92 or 93 for a real stager URI
```

**Why this matters for hunting:** When you observe a suspicious server, you can generate valid stager URIs and attempt to fetch them. A 200 response returning binary PE data (MZ header) with a checksum8-valid URI confirms the presence of a Cobalt Strike stager. The server will return a 404 or garbage for non-valid checksums.

Legitimate web applications do not implement this behavior. A positive checksum8 response is near-conclusive attribution.

### Malleable C2 Profile Detection

Malleable C2 profiles allow operators to customize Cobalt Strike's HTTP communication patterns — changing URIs, headers, response bodies, and more. This makes naive signature matching fail. However, the underlying checksum8 algorithm cannot be changed by Malleable profiles; only the URI namespace changes.

What Malleable profiles CAN change:
- URI paths (but checksum8 still governs which path = which stager)
- HTTP method (GET vs POST)
- HTTP headers (User-Agent, custom headers)
- Response body content (to mimic legitimate sites)
- Cookie names used for session tracking

What they CANNOT change:
- The checksum8 algorithm itself
- The binary format of the staged payload
- The MZ/PE header of the beacon executable
- The underlying beacon protocol structure

**Detection approach for malleable profiles:** Look for HTTP transactions where:
1. A specific URI path is requested that has no obvious content relationship to the server's apparent purpose
2. The server returns a 200 with binary data or encoded content disproportionate to a normal web response
3. Subsequent requests to related URIs use consistent URI patterns with checksum8-valid paths

### Default 404 Response

When Cobalt Strike's HTTP listener receives a request it doesn't recognize, it returns the default 404 page. The default body is:

```html
<html><head><title>404</title></head><body><h1>Not found</h1></body></html>
```

This minimal, distinct 404 body — combined with a 404 status code on requests that are not checksum8-valid — is itself a fingerprint. Most legitimate web servers return more elaborate 404 pages. A Shodan `http.html` search for this exact string isolates a significant fraction of Cobalt Strike deployments:

```
http.html:"<title>404</title>" http.html:"<h1>Not found</h1>"
```

### Beacon Staging Process

Understanding how beacons stage themselves clarifies what to look for in network traffic:

1. **Initial stager** executes on victim (shellcode, small executable)
2. Stager makes HTTP GET to team server with checksum8-valid URI
3. Team server responds with the full beacon DLL encoded in the response
4. Stager reflectively loads the DLL in memory
5. Beacon begins callback cycle to C2

For detection: the initial stager GET request will have a short URI (typically 4-8 characters) that satisfies checksum8. The response will be 200-300KB of binary data with MZ/PE headers. This traffic pattern is anomalous on any network.

---

## Sliver C2 Identification

Sliver is an open-source adversary simulation framework from BishopFox. It has become increasingly common in both authorized red team engagements and threat actor toolkits as a Cobalt Strike alternative.

### Default Certificate and Port

Sliver uses mutual TLS (mTLS) by default for operator-implant communication:

| Parameter | Default Value |
|-----------|--------------|
| Operator port | `31337` |
| HTTP C2 port | `80` / `443` |
| DNS C2 | port `53` |
| Certificate subject | Auto-generated per installation |

Unlike Cobalt Strike, Sliver generates unique certificates per install, so cert serial hunting is less reliable. However, the operator interface on port 31337 combined with specific TLS characteristics (client certificate requirement for mTLS) can be detected.

### HTTP C2 Response Patterns

Sliver's HTTP C2 implants use specific URI patterns by default:

```
/haiku.php
/login
/static/
/api/v1/
```

These are configurable but operators frequently use defaults. The server response typically includes specific content-type headers and response body structure that differs from legitimate web applications.

### Implant Staging URIs

Sliver uses a staged delivery model similar to Cobalt Strike. Generated stager URIs follow patterns like:

```
/[random_word]/[random_id].woff
/fonts/[random].woff2
/static/[random].js
```

The randomness is seeded per-campaign, meaning the pattern is consistent within a campaign but differs across operators.

### gRPC Operator Interface

The Sliver operator console communicates via gRPC over mTLS. This means:
- Port 31337 requires a client certificate for any meaningful interaction
- The TLS handshake will fail without the correct client cert
- A port scan will show 31337 open; a connection attempt returns TLS handshake failure

This behavior is itself a fingerprint: a service that accepts TLS connections on 31337 but immediately drops connections without a valid client cert.

---

## Havoc Framework

Havoc is an open-source C2 framework targeting the modern red team. It introduces a "Demon" agent and a teamserver web interface.

### Demon Agent HTTP Patterns

Havoc's Demon agent communicates over HTTP/HTTPS with characteristic patterns:

| Indicator | Default Value |
|-----------|--------------|
| Teamserver web UI port | `40056` |
| Default HTTP listener | `80` / `443` |
| Content-Type | `application/octet-stream` (for tasking) |
| Response to unknown requests | `403 Forbidden` |

The web UI on port 40056 is accessible via browser and does not require client certificates. A Shodan search:

```
port:40056 http.title:"Havoc"
```

### Default HTTP Headers

Havoc's default HTTP profile sends minimal headers. The server response for beacon callbacks includes:

```
Content-Type: application/octet-stream
Cache-Control: no-cache
```

This combination on a port serving binary content without obvious web application context is a weak indicator that strengthens with additional signals.

### Yaeger C2 Profile

Havoc supports "Yaeger profiles" (similar concept to Malleable C2) for customizing HTTP communication. The same caveat applies as with Cobalt Strike: profiles change surface appearance but not the underlying protocol structure. A consistent binary-returning endpoint that changes its URI pattern is more suspicious, not less.

---

## Mythic C2

Mythic is a multi-platform C2 framework with a web-based operator interface and an agent plugin architecture. It is used in both authorized engagements and has appeared in threat actor toolsets.

### Default Web UI

| Path | Purpose |
|------|---------|
| `/new/login` | Operator login page |
| `/new/` | Main operator dashboard |
| `/api/v1/` | REST API base |
| `/ws/` | WebSocket endpoint for real-time tasking |

The `/new/login` path with Mythic's characteristic login UI is indexable by Shodan:

```
http.title:"Mythic"
http.html:"/new/login"
```

### Default Ports

| Port | Service |
|------|---------|
| `7443` | HTTPS web UI and REST API |
| `80` / `443` | C2 listeners (configurable) |
| `5000` | Alternate API port (older versions) |

### Agent Callback Patterns

Mythic's HTTP-based agents (Apollo, Apfell, Poseidon etc.) use:

- JSON-formatted encrypted blobs as POST bodies
- Specific URI structures: `/api/v1/agent_message`
- Response: JSON with encrypted tasking data
- UUID-based agent identification in headers or URI

### WebSocket Usage

Mythic's operator interface uses persistent WebSocket connections for real-time task updates. A server with a web interface on 7443 that maintains WebSocket connections at `/ws/` is a moderate-confidence Mythic indicator.

---

## Other C2 Frameworks

### Brute Ratel C4

Brute Ratel ("BRC4") is a commercial offensive framework that gained notoriety for its use by state-level threat actors. Key indicators:

- Default badger callback URIs use patterns like `/path/to/[random]`
- Response returns JSON-encoded encrypted data
- TLS certificate may use custom CN/O fields that differ per operator
- Has appeared with legitimate organization names in cert fields (social engineering the cert chain)
- Default port: 443 with custom HTTP/S profile

BRC4 leaked versions circulate in threat actor communities, making it appear in non-commercial operations.

### Posh C2

PowerShell-oriented C2, common in older UK-origin threat actor campaigns. Indicators:
- PowerShell-based implants making HTTP requests with specific User-Agent patterns
- Default staging URIs: `/connect`, `/poll`
- Response content type: `text/plain`

### Covenant

.NET-based C2 framework. Indicators:
- Default web UI on port `7443` (same as Mythic — check page content to differentiate)
- Grunt implants using HTTP POST with Base64-encoded encrypted bodies
- Default staging URI: `/en-us/test.htm`

### Nighthawk

Commercial C2 framework from MDSec, rare in the wild. Indicators:
- Highly customized by design; fewer default fingerprints
- mTLS-based communication similar to Sliver
- HTTPS only; strong focus on OPSEC by default

---

## Open Directory Hunting

When operators stage payloads, they need to serve them somewhere. Misconfiguration, laziness, or operational tempo often results in the staging server's directory listing being exposed.

### Google Dork Patterns

```
intitle:"index of" "beacon" filetype:bin
intitle:"index of" "stager" filetype:exe
intitle:"index of" ".dll" "payload"
intitle:"index of" inurl:"/uploads/" ".bin"
intitle:"index of" ".ps1" "invoke"
```

For specific frameworks:

```
# Cobalt Strike staging
intitle:"index of" ".bin" "staging"
intitle:"index of" site:*.xyz (".exe" OR ".dll")

# Generic payload hosting
"Index of /" "parent directory" ".elf"
"Index of /" intext:".shellcode"
```

### Shodan Queries

```
# Open directory listings
http.title:"Index of /"

# Specific content in directory listings
http.html:"Index of /" http.html:".bin"
http.html:"Index of /" http.html:".ps1"

# Cobalt Strike combination
ssl.cert.serial:146473198 http.title:"Index of /"

# Sliver server
port:31337

# Havoc teamserver
port:40056

# Mythic
http.title:"Mythic" port:7443
```

### Directory Listing Detection

When scanning HTTP servers programmatically, look for these HTML patterns:

```python
OPEN_DIR_PATTERNS = [
    r"Index of /",                    # Apache, Nginx
    r"Directory listing for",         # Python http.server
    r"Directory: /",                  # Go file server
    r"\[To Parent Directory\]",       # IIS
    r"<title>.*Index of.*</title>",   # Various
]
```

A server returning one of these patterns is exposing its filesystem contents.

### Suspicious File Extensions in Open Directories

When you find an open directory, these extensions warrant immediate attention in a threat intelligence context:

| Extension | Relevance |
|-----------|-----------|
| `.bin` | Raw shellcode or packed PE |
| `.exe` | Windows executable / stager |
| `.dll` | Windows DLL / reflective loader |
| `.ps1` | PowerShell script / dropper |
| `.sh` | Shell script / Linux dropper |
| `.elf` | Linux/Unix executable |
| `.py` | Python payload or C2 component |
| `.vbs` | VBScript dropper |
| `.hta` | HTML Application (execution via mshta) |
| `.jar` | Java payload |
| `.bat` | Batch script dropper |
| `.iso` | Container for payload delivery |

Non-malicious hosting (software mirrors, CDNs) will have consistent naming, version numbers, and legitimate context. Malicious staging typically shows inconsistency: a directory with a single `.bin` file, random-looking filenames, or filenames matching known framework stager patterns.

### Identifying Staged Payloads vs Legitimate Files

Ask these questions when evaluating a file found in an open directory:

1. **Naming convention**: Is the filename a random string (e.g., `aB3xK.bin`) or a descriptive product name?
2. **File size**: Cobalt Strike stagers are typically 200-300KB. Full beacons are 100-400KB. Sliver implants vary more.
3. **Companion files**: Legitimate software distributions include checksums, READMEs, license files. Payload staging directories typically contain only executables.
4. **Server context**: Is the rest of the server consistent with a legitimate software host, or is the directory isolated/anomalous?
5. **Timestamp clustering**: Were all files in the directory placed there at the same time? Rapid-deploy staging often has tight timestamp clustering.
6. **Geographic context**: Is the server in an unexpected hosting jurisdiction for its apparent purpose?

---

## Server Header Analysis

HTTP Server response headers reveal framework and software versions without any active probing. This is passive intelligence gathering.

### Framework Default Headers

| C2 / Framework | Server Header | Notes |
|---------------|--------------|-------|
| Cobalt Strike default | `(none)` or custom | Profile-controlled |
| Cobalt Strike w/ default profile | Absent | Often deliberately removes header |
| Python http.server | `SimpleHTTP/0.6 Python/3.x.x` | Dead giveaway for staging |
| Python http.server (older) | `BaseHTTP/0.6 Python/2.7.x` | Legacy staging |
| Go net/http default | `(none)` | Go servers suppress by default |
| Sliver HTTP C2 | Configurable; often absent | |
| Havoc | `Apache/2.4` (spoofed by default profile) | Check against port/cert |
| Mythic | `nginx` (proxied) | |

**Python http.server** is a particularly important indicator. It is never appropriate for production web services; its presence indicates a manually-started staging server or a poorly-deployed C2 component. A server with `SimpleHTTP` as the Server header combined with an open directory listing and `.bin` files is essentially confirmed malicious infrastructure.

### nginx and Apache Version Disclosure

When nginx or Apache return version information:

```
Server: nginx/1.18.0
Server: Apache/2.4.41 (Ubuntu)
```

Cross-reference these versions against known C2 infrastructure patterns. Threat actors often use specific cloud provider AMIs or Docker images that result in consistent version strings across a campaign. If you observe the same Apache version string on multiple IPs in a suspected cluster, this is a weak clustering signal (covered in depth in Module 0x03).

### X-Powered-By Header

The `X-Powered-By` header can reveal:

```
X-Powered-By: PHP/7.4.3          # PHP-based panel/C2
X-Powered-By: Express             # Node.js-based C2
X-Powered-By: ASP.NET             # .NET-based C2 (Covenant, etc.)
```

These do not individually identify a C2, but in combination with port analysis, URI patterns, and open directory content, they build a framework attribution picture.

### Deliberate Header Removal

Sophisticated operators remove or spoof the Server header entirely. The absence of a Server header on a service that otherwise behaves like a web server is itself a weak indicator of deliberate OPSEC — which is more consistent with an adversary than with a legitimate service (legitimate services typically have consistent, predictable headers).

---

## Tool References

### Shodan

Shodan is the primary passive reconnaissance tool for this module. Key queries:

```
# Cobalt Strike
ssl.cert.serial:146473198
product:"Cobalt Strike"
http.html:"<title>404</title>" http.html:"<h1>Not found</h1>"

# Open directories
http.title:"Index of /"
http.html:"Index of /" http.html:".bin"

# Python staging servers
http.server:"SimpleHTTP"
http.server:"Python"

# Framework ports
port:50050                    # Cobalt Strike team server
port:31337                    # Sliver mTLS
port:40056                    # Havoc teamserver
port:7443 http.title:"Mythic" # Mythic C2

# Certificate-based
ssl.cert.subject.cn:"Major Cobalt Strike"
ssl.cert.subject.o:"cobaltstrike"
```

### Censys

Censys provides certificate and HTTP body search with higher fidelity than Shodan in some cases:

```
# Certificate search
parsed.serial_number: 146473198
parsed.subject.common_name: "Major Cobalt Strike"
parsed.subject.organization: cobaltstrike

# HTTP body search
80.http.response.body: "Index of /"
443.https.tls.certificate.parsed.serial_number: 146473198
```

### URLhaus (abuse.ch)

URLhaus is a malware URL database maintained by abuse.ch. Use it to:

- Look up suspected C2 URLs to see if they are already known
- Search by tag (e.g., `cobalt_strike`, `sliver`, `havoc`) to find recently reported infrastructure
- Submit newly discovered C2 URLs to contribute to community intelligence

URL: `https://urlhaus.abuse.ch/`

### MalwareBazaar

MalwareBazaar indexes malware samples with metadata including C2 information extracted from sandboxed execution. Use it to:

- Search for samples associated with a suspected C2 IP or domain
- Retrieve YARA rules associated with known C2 families
- Find samples that beacon to newly discovered infrastructure

URL: `https://bazaar.abuse.ch/`

### VirusTotal

VirusTotal aggregates AV detections and provides network graph information:

- Submit suspected payload URLs for detection analysis (never execute locally)
- Use the "Relations" tab to find other IPs/domains resolving to the same ASN or infrastructure cluster
- Check "Communicating files" on an IP to see if known malware has communicated with it

URL: `https://www.virustotal.com/`

### NMAP NSE Scripts

NMAP includes NSE scripts useful for C2 detection in authorized scanning:

```bash
# Check for Cobalt Strike team server
nmap -p 50050 --script ssl-cert <target>

# Extract certificate details
nmap -p 443 --script ssl-cert,ssl-enum-ciphers <target>

# HTTP headers
nmap -p 80,443,8080 --script http-headers <target>

# Directory listing detection
nmap -p 80,443 --script http-ls <target>
```

---

## Case Study: Discovering a Cobalt Strike Team Server

This walkthrough demonstrates the full identification chain from a single indicator to confirmed infrastructure.

### Step 1: Initial Discovery via Shodan

A Shodan alert triggers on a new host matching `ssl.cert.serial:146473198`. The result:

```
IP: 185.220.101.x
Port: 443
SSL Subject: CN=Major Cobalt Strike, O=cobaltstrike
SSL Serial: 146473198
```

Confidence at this stage: **moderate**. Default cert could be a test server or authorized engagement.

### Step 2: Port Enumeration

Additional Shodan data for this IP reveals:

```
Port 50050: open (no banner — custom protocol)
Port 443:   open (HTTPS, Cobalt Strike default cert)
Port 80:    open (HTTP, returning default CS 404 page)
```

Port 50050 open alongside the cert serial: **high confidence** Cobalt Strike team server.

### Step 3: checksum8 URI Validation

Generate a checksum8-valid URI and attempt a fetch:

```python
# We generate a known x86 stager URI
uri = generate_stager_uri(target_checksum=92, length=4)
# e.g., uri = "aaaN"
response = requests.get(f"http://185.220.101.x/{uri}")
```

If the response:
- Returns 200 with binary data starting with `MZ` (Windows PE header): **confirmed active Cobalt Strike stager**
- Returns 404 with `<h1>Not found</h1>`: **confirmed Cobalt Strike** (even if stager not active)
- Returns anything else: less certain, may be Malleable profile customization

> **OPSEC:** This HTTP request may trigger the operator's alerts. Use a non-attributable network for this step. See Module 0x09 for hunter OPSEC.

### Step 4: Open Directory Discovery

Check the same IP for directory listings:

```bash
curl -sk http://185.220.101.x/ | grep -i "index of"
curl -sk http://185.220.101.x/uploads/ | grep -i "index of"
```

If directory listing is exposed, enumerate:

```python
# Collect all href targets from the listing
links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
suspicious = [l for l in links if any(l.endswith(ext) for ext in
    ['.bin', '.exe', '.dll', '.ps1', '.sh', '.elf'])]
```

### Step 5: Payload Analysis

For each suspicious file found:
1. Note the filename and URL — **do not download to an attributed machine**
2. Submit the URL to URLhaus and VirusTotal
3. Check MalwareBazaar for existing samples from this server
4. If sample retrieval is necessary for research: use an isolated sandbox environment with no network connectivity to the analyst infrastructure

Never execute payloads. Analysis should be static (hash matching, YARA, string extraction) or sandbox-based.

### Step 6: Infrastructure Mapping

With the confirmed Cobalt Strike server, pivot to infrastructure:

1. **WHOIS**: Note registrar, registration date, registrant info
2. **ASN**: What hosting provider? Cross-reference with known C2 hosting ASNs from Module 0x02
3. **Certificate history**: Use crt.sh or Censys to find other certs issued to the same subject
4. **IP neighbors**: Shodan/Censys scan of nearby IPs in the same /24 — threat actors often cluster infrastructure
5. **DNS history**: Use SecurityTrails or DomainTools to find other domains resolved to this IP

Feed the results into the graph builder from Module 0x07 to visualize the infrastructure cluster.

---

## OPSEC Note

> **Warning:** These techniques involve probing infrastructure that may be actively operated by threat actors. Inappropriate interaction with C2 servers can:
>
> - Trigger alerts in the operator's console, revealing the investigation
> - Cause the operator to rotate infrastructure, destroying evidence
> - Result in the analyst's IP being logged by the C2 as a "victim" or "researcher"
> - In some jurisdictions, active probing of unauthorized systems violates computer crime law even when the system is malicious
>
> Recommended posture:
> 1. **Passive first** — Shodan, Censys, URLhaus, VirusTotal require no direct contact with the target
> 2. **Non-attributable for active** — Use Tor, VPN, or cloud burner infrastructure for any direct HTTP requests
> 3. **Never execute** — Downloaded payloads must never be executed outside a full sandbox environment
> 4. **Isolated analysis environment** — Air-gap or network-isolated VMs for payload analysis
> 5. **Legal authority** — Ensure your investigation has appropriate authorization before probing external systems
>
> See Module 0x09 for comprehensive hunter OPSEC practices.

---

## Module Project: C2 Framework Dorker & Classifier

*Reference: Black Hat Go & Black Hat Python*

The module project expands the original open directory scanner into a full framework identification tool with checksum8 validation, header classification, and structured output.

### Features

- **checksum8 computation** — validates and generates Cobalt Strike stager URIs
- **Framework signature database** — known patterns for CS, Sliver, Havoc, Mythic, BRC4
- **Server header classification** — identifies frameworks from HTTP response headers
- **Suspicious file highlighting** — flags dangerous extensions in directory listings
- **Target list from file** — `-f targets.txt`
- **Structured output** — JSON, CSV, and text formats
- **Mock/demo mode** — runs offline to demonstrate framework detection against synthetic responses

See `projects/0x04_c2_dorker/c2_dorker.py` for the full implementation.

### Quick Start

```bash
# Demo mode (no targets required)
python c2_dorker.py

# Single target
python c2_dorker.py -t http://target.example.com

# Target list with JSON output
python c2_dorker.py -f targets.txt --format json

# Enable checksum8 stager testing
python c2_dorker.py -f targets.txt --check-stagers --format json
```

### Example Output (Mock Mode)

```
[*] C2 Framework Dorker v2.0 — Mock Demo Mode
[*] Demonstrating framework detection against synthetic responses

--- Target: http://mock-cs-server.example.com ---
[!] OPEN DIRECTORY detected
[SUSPICIOUS] Files: beacon_x86.bin, beacon_x64.bin, stager.ps1
Framework: Cobalt Strike
Confidence: HIGH
Indicators: default cert serial, CS 404 body, checksum8 stager response

--- Target: http://mock-sliver.example.com ---
Framework: Sliver
Confidence: MEDIUM
Indicators: port 31337 response, mTLS pattern, staging URI match

--- Target: http://mock-havoc.example.com ---
Framework: Havoc
Confidence: MEDIUM
Indicators: port 40056 response, Demon agent headers
```

---

## Summary

This module equips you with a layered, high-confidence approach to C2 framework identification:

1. **Passive**: Cert serials, Shodan/Censys queries, URLhaus/VirusTotal lookups
2. **Semi-active**: Header extraction, directory listing enumeration
3. **Active** (use carefully): checksum8 URI testing, port-specific probing

The convergence of multiple weak indicators — a suspicious cert, an unexpected port, a Python-served open directory with `.bin` files — produces reliable attribution even when individual signals are ambiguous. This layered approach mirrors how professional threat intelligence analysts assess infrastructure.

From here, Module 0x07 (Graph-Based Hunting) extends this work into infrastructure cluster visualization, connecting multiple confirmed C2 servers into attributed campaigns.
