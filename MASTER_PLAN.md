# MASTER_PLAN: netthrunter

## Identity

**Type:** educational-curriculum
**Languages:** Python (85%), Markdown (15%)
**Root:** `/Users/slacker/dev/netthrunter`
**Created:** 2026-04-02
**Last updated:** 2026-04-02

Advanced Infrastructure & Adversary Hunting Curriculum (AIH-C) — a 10-module educational curriculum and engineering framework for proactively identifying, tracking, and mapping threat actor infrastructure. Targets senior threat researchers and security engineers. Each module pairs a teaching document with a runnable Python capstone project. Served via MkDocs with Material theme.

## Architecture

```
docs/modules/          — 10 teaching modules (theory, techniques, tool references, inline project code)
projects/              — 10 capstone Python project directories (1 script each, 70-99 LOC starters)
docs/index.md          — Landing page with curriculum overview and toolbelt reference
docs/projects.md       — Capstone projects overview and reference library integration
books/                 — Offline reference library (gitignored PDFs)
mkdocs.yml             — MkDocs configuration, nav structure, Material theme
.venv/                 — Python virtual environment (gitignored)
site/                  — MkDocs build output (gitignored)
```

## Original Intent

> Enhance all 10 curriculum modules sequentially from 0x01 through 0x0A. For each module: (1) expand the teaching doc with deeper, practitioner-level techniques and advanced detail, (2) add specific tool references (Shodan, Censys, Maltego, etc.) directly into the module doc, and (3) expand existing capstone projects and/or add new project files to match the deeper content. The result should be a professional-grade adversary hunting curriculum that a senior researcher can use as both a learning path and a working toolkit.

## Principles

1. **Practitioner Depth** — Every module must go deep enough that a senior threat researcher learns something new. Surface-level overviews are the current state; the target is operational tradecraft.
2. **Runnable Code Over Theory** — Projects must work out of the box with `python script.py`. Mock/offline fallbacks for API-dependent features. No broken imports, no placeholder functions.
3. **Sequential Building Blocks** — Later modules assume knowledge from earlier ones. Module 0x07 (Graph) can reference outputs from 0x01-0x03. Each enhancement is self-contained but fits the cumulative arc.
4. **Defensive Use Only** — All tools, techniques, and code serve authorized defensive research. OPSEC guidance protects the researcher, not the adversary.
5. **Single-File Simplicity** — Each project stays as a single main script unless complexity genuinely demands a helper module. Educational code should be readable top-to-bottom.

---

## Decision Log

| Date | DEC-ID | Initiative | Decision | Rationale |
|------|--------|-----------|----------|-----------|
| 2026-04-02 | DEC-STRUCT-001 | curriculum-enhancement | Sequential waves (one module per wave) rather than parallel | User explicitly requested sequential 0x01-0x0A ordering; each module builds on prior |
| 2026-04-02 | DEC-STRUCT-002 | curriculum-enhancement | Expand existing single script per project; add helper files only when needed | Maintains single-file simplicity principle; avoids unnecessary project restructuring |
| 2026-04-02 | DEC-STRUCT-003 | curriculum-enhancement | Keep project code embedded in module docs AND in project directories | Current pattern has code in both places; maintain consistency, update both locations |
| 2026-04-02 | DEC-STRUCT-004 | curriculum-enhancement | Mock/offline fallbacks for all API-dependent features | Educational code must run without API keys; real API integration as optional enhancement |
| 2026-04-02 | DEC-STRUCT-005 | curriculum-enhancement | No test suite or CI — validation is "does it run and produce output" | This is a curriculum repo, not production software; testing is manual execution |

---

## Active Initiatives

*No active initiatives.*

---

### Completed: Curriculum Deep Enhancement (0x01-0x0A)
**Status:** completed
**Started:** 2026-04-02
**Completed:** 2026-04-02
**Goal:** Transform all 10 modules from intermediate overviews into practitioner-grade adversary hunting references with production-quality capstone projects.

> The current curriculum has solid structure but intermediate depth. Module docs are ~2.5 pages each with surface-level concept coverage. Capstone projects are 70-99 LOC starters that demonstrate one technique per module. The enhancement brings each module to advanced practitioner level: deeper technique coverage, specific tool integration, and projects that implement the full technique set described in the teaching material.

**Dominant Constraint:** simplicity (educational clarity above all)

#### Goals
- REQ-GOAL-001: Each module doc expanded to 6-10 pages of practitioner-level content with tool references
- REQ-GOAL-002: Each capstone project implements 3-5 techniques (up from 1) with working code
- REQ-GOAL-003: All projects run successfully with `python script.py` (mock fallback for API features)
- REQ-GOAL-004: Tool references (Shodan, Censys, Maltego, SecurityTrails, etc.) integrated contextually into module docs
- REQ-GOAL-005: Module docs and project code stay synchronized (code embedded in doc matches project file)

#### Non-Goals
- REQ-NOGO-001: Production deployment of any scanner — this is educational code with mock fallbacks
- REQ-NOGO-002: Test suite or CI pipeline — validation is manual execution
- REQ-NOGO-003: Multi-file project restructuring — keep single-script simplicity unless genuinely necessary
- REQ-NOGO-004: API key provisioning or account setup — document how to get keys, but don't require them to run
- REQ-NOGO-005: MkDocs theme or nav restructuring — the site structure is stable

#### Requirements

**Must-Have (P0)**

- REQ-P0-001: Each module doc expanded with advanced techniques, real-world examples, and tool references
  Acceptance: Given a module doc, When reviewed by a practitioner, Then it contains techniques beyond what the current intermediate version covers, with specific tool commands and API examples
- REQ-P0-002: Each capstone project expanded to implement the full technique set described in its module doc
  Acceptance: Given a project script, When executed with `python script.py`, Then it runs without error and produces meaningful output demonstrating all described techniques
- REQ-P0-003: Module doc code blocks match the actual project file content
  Acceptance: Given module doc and project file, When compared, Then the code in the doc's boilerplate section matches the project file exactly

**Nice-to-Have (P1)**

- REQ-P1-001: Add sample data files (CSV, JSON) where projects benefit from realistic input data
- REQ-P1-002: Add MkDocs admonitions (tip, warning, danger) for OPSEC notes and common pitfalls

**Future Consideration (P2)**

- REQ-P2-001: Cross-module pipeline — output of 0x01 feeds into 0x03/0x07 as structured input
- REQ-P2-002: Docker-compose for Neo4j (0x07) and other service dependencies
- REQ-P2-003: Jupyter notebook companions for data science modules (0x03, 0x07, 0x0A)

#### Definition of Done

All 10 module docs expanded to practitioner depth with tool references. All 10 capstone projects enhanced with full technique implementations. All projects execute without error. Doc code blocks match project files. MkDocs site builds cleanly with `mkdocs build`.

#### Architectural Decisions

- DEC-STRUCT-001: Sequential waves (one module per wave) rather than parallel
  Addresses: REQ-GOAL-001, REQ-GOAL-002.
  Rationale: User requested sequential 0x01-0x0A ordering. Each module builds conceptually on prior modules. Serial execution ensures consistency and allows later modules to reference earlier enhancements.

- DEC-STRUCT-002: Expand existing single script per project; add helper files only when needed
  Addresses: REQ-P0-002.
  Rationale: Single-file projects are easier to read, copy, and learn from. Only split when a module genuinely needs a helper (e.g., sample data generator, utility functions exceeding 50 LOC).

- DEC-STRUCT-003: Keep project code embedded in module docs AND in project directories
  Addresses: REQ-P0-003.
  Rationale: Current pattern embeds code in the teaching doc as a "Boilerplate Setup" section. Readers expect to see the code inline. Both locations must stay in sync.

- DEC-STRUCT-004: Mock/offline fallbacks for all API-dependent features
  Addresses: REQ-GOAL-003.
  Rationale: A student running the project for the first time should see output, not an API key error. Real API paths exist as optional enhancements behind environment variable checks.

#### Waves

##### Initiative Summary
- **Total items:** 10
- **Critical path:** 10 waves (W1-1 -> W2-1 -> W3-1 -> W4-1 -> W5-1 -> W6-1 -> W7-1 -> W8-1 -> W9-1 -> W10-1)
- **Max width:** 1 (all waves)
- **Gates:** 0 review, 0 approve

##### Wave 1 — Module 0x01: Structural Fingerprinting
**Parallel dispatches:** 1

**W1-1: Enhance Module 0x01 — Structural Fingerprinting** — Weight: M, Gate: none
- **Doc expansion** (`docs/modules/0x01_structural_fingerprinting.md`):
  - Add deep JARM explanation: the 10-probe mechanism, how each probe varies TLS version/cipher/extension, how the 62-char hash is constructed from server responses
  - Add JA3/JA3S fingerprinting section: how client hello fields are hashed (SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats), JA3S server-side equivalent
  - Add JA4+ family overview: JA4 (TLS client), JA4S (server), JA4H (HTTP), JA4X (X.509), JA4T (TCP)
  - Add HTTP/2 fingerprinting section: SETTINGS frame ordering, WINDOW_UPDATE values, PRIORITY frame patterns (Akamai fingerprint)
  - Add SSH banner/key fingerprinting: Hassh algorithm (key exchange, encryption, MAC, compression)
  - Add tool references: Shodan `ssl.jarm:` filter, Censys `services.tls.ja3s:` filter, SSLBL abuse.ch lookup, `ja3er.com` database
  - Add real-world case study: default Cobalt Strike JARM hash, default Metasploit JA3 hash, how to hunt for them at scale
  - Add OPSEC note: scanning generates a JA3 fingerprint visible to the target; use Module 0x09 techniques
- **Project expansion** (`projects/0x01_jarm_scanner/tls_fingerprint.py`):
  - Current state: 86 LOC, cert SHA-256 hashing only, no actual JARM/JA3
  - Add: True JARM scanning using `jarm` library (10-probe with fallback mock)
  - Add: JA3 hash extraction from TLS handshake (using `ssl` module cipher info as proxy, or scapy if available)
  - Add: Certificate field extraction (issuer org, subject CN, SANs, validity dates, serial number)
  - Add: Bulk target support — read IPs from file or stdin
  - Add: JSON and CSV output modes
  - Add: Shodan API lookup for JARM hash correlation (with mock fallback)
  - Target: ~200-250 LOC
- **Integration:** Update code block in `docs/modules/0x01_structural_fingerprinting.md` to match expanded project file

##### Wave 2 — Module 0x02: Infrastructure Mapping
**Parallel dispatches:** 1
**Blocked by:** W1-1

**W2-1: Enhance Module 0x02 — Infrastructure Mapping** — Weight: M, Gate: none, Deps: W1-1
- **Doc expansion** (`docs/modules/0x02_infrastructure_mapping.md`):
  - Add deep CT log mechanics: how CT works (RFC 6962), log operators (Google Argon, Cloudflare Nimbus, Let's Encrypt Oak), SCT validation
  - Add pDNS pivoting section: A/AAAA record history, NS record changes as infrastructure migration indicators, MX record correlation
  - Add WHOIS deep dive: registrar patterns, privacy proxy services (WhoisGuard, Domains By Proxy), creation/update date clustering, registrant email pivoting
  - Add subdomain enumeration: crt.sh wildcard queries, Subfinder, Amass passive mode, DNS brute-forcing trade-offs
  - Add tool references: SecurityTrails API (pDNS, WHOIS history), VirusTotal domain reports, RiskIQ/PassiveTotal, DomainTools
  - Add temporal analysis: how to detect infrastructure staging (cert issued -> domain registered -> DNS pointed -> server deployed)
  - Add case study: tracking a phishing campaign through CT logs to origin infrastructure
- **Project expansion** (`projects/0x02_ct_hunter/ct_hunter.py`):
  - Current state: 70 LOC, crt.sh query only, no DNS resolution, no WHOIS
  - Add: DNS resolution for discovered domains (A, AAAA, MX, NS records using `socket` or `dnspython`)
  - Add: Keyword list from file (one keyword per line)
  - Add: WHOIS lookup integration (python-whois with mock fallback)
  - Add: pDNS correlation — group domains by resolved IP
  - Add: Output deduplication and sorting by issue date
  - Add: CSV export of results
  - Target: ~200-250 LOC
- **Integration:** Update code block in `docs/modules/0x02_infrastructure_mapping.md`

##### Wave 3 — Module 0x03: Overlap & Clustering
**Parallel dispatches:** 1
**Blocked by:** W2-1

**W3-1: Enhance Module 0x03 — Overlap & Clustering** — Weight: M, Gate: none, Deps: W2-1
- **Doc expansion** (`docs/modules/0x03_overlap_clustering.md`):
  - Add multi-indicator correlation theory: SSH key reuse, JARM hash overlap, cert serial sharing, WHOIS registrant overlap, ASN co-tenancy
  - Add bulletproof hosting deep dive: key ASNs (Choopa/Vultr AS20473, OVH AS16276, Hetzner AS24940), abuse response timelines, how actors select providers
  - Add clustering algorithms: Jaccard similarity for indicator sets, hierarchical clustering for infrastructure grouping
  - Add temporal correlation: infrastructure provisioning patterns (time-of-day, burst provisioning, rotation schedules)
  - Add tool references: Shodan facets for ASN aggregation, Censys aggregate reports, Maltego transforms for infrastructure pivoting
  - Add pivot techniques: from one SSH key -> all IPs -> all domains -> all certs -> all registrant emails
- **Project expansion** (`projects/0x03_overlap_clustering/ssh_cluster.py`):
  - Current state: 79 LOC, Shodan SSH hash lookup with mock fallback, ASN counter only
  - Add: Multi-indicator input (CSV: IP, domain, ASN, SSH key, JARM hash)
  - Add: Jaccard similarity calculation between indicator sets
  - Add: Cluster assignment (simple threshold-based grouping)
  - Add: NetworkX graph generation for cluster visualization (matplotlib output)
  - Add: CSV input from file
  - Add: Summary statistics (cluster count, largest cluster, most common ASN)
  - Target: ~200-250 LOC
- **Integration:** Update code block in `docs/modules/0x03_overlap_clustering.md`

##### Wave 4 — Module 0x04: C2 & Open Directories
**Parallel dispatches:** 1
**Blocked by:** W3-1

**W4-1: Enhance Module 0x04 — C2 & Open Directories** — Weight: L, Gate: none, Deps: W3-1
- **Doc expansion** (`docs/modules/0x04_c2_open_directories.md`):
  - Add Cobalt Strike fingerprinting deep dive: default cert serial (146473198), beacon checksum algorithm (92/93 URI paths), Malleable C2 profile detection, team server default ports
  - Add Sliver C2 identification: default mTLS patterns, HTTP C2 response headers, implant staging URIs
  - Add Havoc framework fingerprints: default Demon agent patterns, teamserver web interface detection
  - Add Mythic C2 detection: default Mythic web UI paths, agent callback patterns
  - Add open directory hunting: Google dork patterns, Shodan HTTP title/body filters, directory listing regex patterns, file extension filtering (.bin, .exe, .dll, .ps1, .sh)
  - Add stager URI checksum algorithm: the Cobalt Strike checksum8 algorithm (sum of ASCII values mod 256 = 92 for x86, 93 for x64)
  - Add tool references: Shodan `http.title:"Index of /"`, Censys HTTP body search, URLhaus, MalwareBazaar
  - Add server header analysis: default framework headers, nginx/Apache version fingerprinting
- **Project expansion** (`projects/0x04_c2_dorker/c2_dorker.py`):
  - Current state: 98 LOC, async directory listing checker only, no framework fingerprinting
  - Add: Cobalt Strike checksum8 URI generator and checker
  - Add: Server header extraction and known-framework matching
  - Add: File extension filtering in open directory listings
  - Add: Framework signature database (dict of known patterns per C2 framework)
  - Add: Target list from file
  - Add: Structured JSON output with framework classification
  - Target: ~250-300 LOC
- **Integration:** Update code block in `docs/modules/0x04_c2_open_directories.md`

##### Wave 5 — Module 0x05: Leak & Stealer Intel
**Parallel dispatches:** 1
**Blocked by:** W4-1

**W5-1: Enhance Module 0x05 — Leak & Stealer Intel** — Weight: M, Gate: none, Deps: W4-1
- **Doc expansion** (`docs/modules/0x05_leak_stealer_intel.md`):
  - Add stealer family deep dive: Redline (C# .NET, gRPC C2, SQLite browser DB theft), Vidar (C++, HTTP C2, Telegram dead drops), Lumma (C, anti-sandbox, process injection), Raccoon v2 (C/C++, DLL-based)
  - Add config extraction methods: embedded C2 URLs in .NET resources, XOR-decoded config blocks, Telegram bot token extraction from binary strings
  - Add Telegram bot intelligence: using `getMe`, `getUpdates`, `getChat` API calls to map operator infrastructure from leaked tokens
  - Add stealer log structure: typical directory layout (Passwords.txt, Cookies/*.txt, Autofill/*.txt, CC/*.txt, SystemInfo.txt), browser DB schema (login_data, cookies, web_data SQLite tables)
  - Add dark web telemetry: Telegram channels as distribution points, automated bot-driven marketplaces, Genesis Market clone patterns
  - Add tool references: VirusTotal, MalwareBazaar, Any.Run, Triage sandbox, abuse.ch URLhaus
  - Add OPSEC warning: handling leaked credentials legally and ethically, data destruction policies
- **Project expansion** (`projects/0x05_leak_parser/leak_parser.py`):
  - Current state: 81 LOC, regex extraction from mock text file only
  - Add: ZIP archive extraction and processing (zipfile module)
  - Add: Recursive directory scanning for stealer log artifacts
  - Add: Telegram bot token validation (HTTP GET to api.telegram.org/bot<TOKEN>/getMe with mock fallback)
  - Add: Browser credential URL extraction (regex for URL/Username/Password patterns in stealer logs)
  - Add: C2 panel URL extraction (regex for common panel paths)
  - Add: Stealer family detection heuristics (directory structure fingerprinting)
  - Add: Batch processing of multiple archives
  - Target: ~220-270 LOC
- **Integration:** Update code block in `docs/modules/0x05_leak_stealer_intel.md`

##### Wave 6 — Module 0x06: Edge Layer Obfuscation
**Parallel dispatches:** 1
**Blocked by:** W5-1

**W6-1: Enhance Module 0x06 — Edge Layer Obfuscation** — Weight: L, Gate: none, Deps: W5-1
- **Doc expansion** (`docs/modules/0x06_edge_layer_obfuscation.md`):
  - Add domain fronting deep explanation: SNI vs Host header routing at CDN edge, which CDNs still allow it (Azure CDN, some Fastly configs), which have blocked it (CloudFront since 2018, Google since 2018)
  - Add domain borrowing: using high-reputation domains on shared CDN infrastructure without fronting
  - Add Cloudflare Tunnel (Argo) detection: `cloudflared` binary patterns, TXT record detection, `cname.tunnel.cloudflare.com` resolution, HTTP response header analysis
  - Add WAF fingerprinting: distinguishing Cloudflare, Akamai, AWS WAF, Sucuri by response headers and error page patterns
  - Add CDN origin discovery: techniques to find origin IP behind CDN (DNS history, email headers, direct IP scanning, SSL cert matching)
  - Add HTTP/2 and HTTP/3 analysis: how CDNs handle ALPN negotiation, QUIC fingerprinting
  - Add tool references: CloudFlair, CrimeFlare, Censys certificate search for origin discovery, SecurityTrails DNS history
- **Project expansion** (`projects/0x06_edge_layer/cdn_tester.py`):
  - Current state: 77 LOC, raw socket SNI mismatch test only
  - Add: CDN detection (check for CDN-specific response headers: cf-ray, x-amz-cf-id, x-akamai-session-info)
  - Add: WAF fingerprint classification from response headers and error pages
  - Add: Cloudflare Tunnel detection (DNS TXT/CNAME resolution check)
  - Add: Origin IP hypothesis testing (connect directly to candidate IP, compare cert to CDN-served cert)
  - Add: HTTP/2 support using httpx
  - Add: Multi-target input from file
  - Target: ~220-270 LOC
- **Integration:** Update code block in `docs/modules/0x06_edge_layer_obfuscation.md`

##### Wave 7 — Module 0x07: Graph-Based Hunting
**Parallel dispatches:** 1
**Blocked by:** W6-1

**W7-1: Enhance Module 0x07 — Graph-Based Hunting** — Weight: L, Gate: none, Deps: W6-1
- **Doc expansion** (`docs/modules/0x07_graph_based_hunting.md`):
  - Add graph theory for threat intel: nodes (IP, domain, cert, SSH key, ASN, registrant, nameserver), edges (resolves-to, hosted-on, issued-by, signed-with, registered-by)
  - Add centrality measures deep dive: degree centrality (hub identification), betweenness centrality (bridge/pivot nodes), PageRank (recursive importance), eigenvector centrality
  - Add community detection: Louvain algorithm for cluster identification, modularity score interpretation, what high-modularity clusters mean for campaign attribution
  - Add Neo4j integration guide: Cypher query examples for threat hunting (MATCH paths, shortest path between IOCs, pattern matching), data model design, index optimization
  - Add interactive visualization: Gephi export (GEXF format), pyvis for HTML-based interactive graphs, vis.js integration
  - Add tool references: Neo4j Community Edition, Maltego transforms, Gephi, yEd, graph-tool
  - Add case study: building an actor infrastructure graph from Modules 0x01-0x03 output
- **Project expansion** (`projects/0x07_graph_builder/graph_builder.py`):
  - Current state: 89 LOC, NetworkX graph with matplotlib viz and degree centrality only
  - Add: CSV file input (IP,Domain,ASN,JARM,SSHKey format)
  - Add: Multiple centrality measures (betweenness, PageRank, eigenvector) with comparison output
  - Add: Community detection using NetworkX's Louvain implementation (or greedy modularity)
  - Add: Neo4j Cypher query generation (output .cypher file for import, not requiring live Neo4j)
  - Add: GEXF export for Gephi
  - Add: pyvis HTML interactive graph output (optional, with try/except import)
  - Add: Cluster summary statistics
  - Target: ~280-330 LOC
- **Integration:** Update code block in `docs/modules/0x07_graph_based_hunting.md`

##### Wave 8 — Module 0x08: Proxy & Botnet Layers
**Parallel dispatches:** 1
**Blocked by:** W7-1

**W8-1: Enhance Module 0x08 — Proxy & Botnet Layers** — Weight: M, Gate: none, Deps: W7-1
- **Doc expansion** (`docs/modules/0x08_proxy_botnet_layers.md`):
  - Add residential proxy ecosystem deep dive: how residential proxies work (SDK-based, browser extension injection, mobile SDK), major operators (Luminati/Bright Data, Oxylabs, SmartProxy), abuse patterns
  - Add SOCKS5 infrastructure analysis: backconnect architecture, port-per-exit model, credential-based routing, geotargeting mechanisms
  - Add bulletproof proxy hosting: identifying proxy infrastructure by port patterns, banner analysis, connection behavior
  - Add BGP analysis: AS path analysis, BGP hijacking detection, prefix origin validation, RPKI status checking
  - Add MaxMind GeoLite2 integration: local IP geolocation and ASN lookup without rate limits
  - Add multi-tier tracing: how to map Target -> Proxy Exit -> Cloud VPS -> Actor C2, layer-by-layer
  - Add tool references: MaxMind GeoLite2, IPinfo.io, BGPView, RIPE RIS, Hurricane Electric BGP toolkit, Spamhaus DROP list
- **Project expansion** (`projects/0x08_proxy_validator/proxy_validator.py`):
  - Current state: 77 LOC, ip-api.com classification (most complete of the starters)
  - Add: MaxMind GeoLite2 local database lookup (geoip2 module with fallback to ip-api.com)
  - Add: BGP/ASN prefix analysis (query BGPView API for ASN details)
  - Add: Known proxy/VPN provider database (dict of known datacenter ASNs and their classification)
  - Add: CIDR range scanning (expand a /24 and classify all IPs)
  - Add: Spamhaus DROP/EDROP list checking (download and match)
  - Add: IP list input from file
  - Add: Risk score calculation (composite of datacenter + proxy + known-bad ASN flags)
  - Target: ~250-300 LOC
- **Integration:** Update code block in `docs/modules/0x08_proxy_botnet_layers.md`

##### Wave 9 — Module 0x09: Hunter OPSEC
**Parallel dispatches:** 1
**Blocked by:** W8-1

**W9-1: Enhance Module 0x09 — Hunter OPSEC** — Weight: L, Gate: none, Deps: W8-1
- **Doc expansion** (`docs/modules/0x09_hunter_opsec.md`):
  - Add anti-detection deep dive: how actors detect scanners (JA3 fingerprint of Python requests/httpx, User-Agent patterns, scan timing analysis, IP reputation checking), honeypot indicators
  - Add distributed scanning architecture: AWS Lambda design (multi-region rotation, API Gateway triggering, S3 result aggregation), Google Cloud Functions equivalent, cost estimation per scan campaign
  - Add TLS fingerprint obfuscation: JA3 randomization techniques, using browser-like TLS stacks (curl_cffi, tls-client), HTTP/2 fingerprint matching (browser-like SETTINGS frames)
  - Add network-level OPSEC: VPN selection criteria (no-log policies, jurisdiction), Tor integration (SOCKS5 proxy, exit node selection), cloud provider IP diversity
  - Add researcher trap detection: analyzing C2 panels for visitor logging, detecting JavaScript-based fingerprinting on open directories, identifying decoy infrastructure
  - Add legal considerations: authorized scanning frameworks, scope documentation, responsible disclosure
  - Add tool references: AWS SAM/CDK for Lambda deployment, curl_cffi, tls-client, Tor, proxychains
- **Project expansion** (`projects/0x09_lambda_scanner/lambda_scanner.py`):
  - Current state: 93 LOC, Lambda handler with local simulation, no deployment tooling
  - Add: SAM template generation (output a `template.yaml` for AWS SAM deployment)
  - Add: Multi-region invocation logic (boto3 Lambda invoke across regions, with mock fallback)
  - Add: JA3 fingerprint randomization (randomize TLS extension order in handshake)
  - Add: User-Agent rotation from realistic browser UA database
  - Add: Cost estimation calculator (Lambda invocations * duration * memory)
  - Add: Result aggregation from multiple invocations (merge JSON outputs)
  - Add: Local simulation mode that demonstrates IP diversity concept
  - Target: ~250-300 LOC
- **Integration:** Update code block in `docs/modules/0x09_hunter_opsec.md`

##### Wave 10 — Module 0x0A: Data Science for Hunting
**Parallel dispatches:** 1
**Blocked by:** W9-1

**W10-1: Enhance Module 0x0A — Data Science for Hunting** — Weight: L, Gate: none, Deps: W9-1
- **Doc expansion** (`docs/modules/0x0A_data_science_hunting.md`):
  - Add Shannon entropy deep dive: mathematical derivation, entropy ranges for DGA families (random char = 4.0-4.5, dictionary-based DGA = 3.0-3.8, legitimate = 2.0-3.2), per-TLD analysis
  - Add K-Means clustering for infrastructure: feature vector construction (entropy, domain length, digit ratio, consonant ratio, TLD category), elbow method for K selection, silhouette score evaluation
  - Add anomaly detection: Isolation Forest for outlier detection in DNS logs, Local Outlier Factor, statistical approaches (z-score on feature distributions)
  - Add bulk DNS log processing: processing millions of DNS queries, feature extraction pipeline, sliding window analysis for temporal anomalies
  - Add model persistence: scikit-learn joblib serialization, model versioning, retraining triggers
  - Add visualization: matplotlib/seaborn for cluster visualization, confusion matrix for labeled data evaluation, ROC curves
  - Add tool references: scikit-learn, pandas, matplotlib, seaborn, DGA domain datasets (DGArchive, Netlab 360)
  - Add case study: building a DGA classifier from labeled domain data
- **Project expansion** (`projects/0x0A_entropy_classifier/entropy.py`):
  - Current state: 95 LOC, Shannon entropy calculation only, no ML
  - Add: Feature extraction pipeline (entropy, length, digit ratio, consonant ratio, unique char ratio)
  - Add: K-Means clustering with elbow method visualization
  - Add: Isolation Forest anomaly detection
  - Add: Bulk CSV processing (domain column input)
  - Add: Model training and persistence (joblib save/load)
  - Add: Classification report output (cluster assignments, anomaly scores)
  - Add: Mock dataset generation with labeled DGA and legitimate domains
  - Add: Matplotlib visualizations (cluster plot, feature distributions)
  - Target: ~300-350 LOC
- **Integration:** Update code block in `docs/modules/0x0A_data_science_hunting.md`

##### Critical Files
- `docs/modules/0x01_structural_fingerprinting.md` through `0x0A_data_science_hunting.md` — the 10 teaching modules being enhanced
- `projects/0x01_jarm_scanner/tls_fingerprint.py` through `projects/0x0A_entropy_classifier/entropy.py` — the 10 capstone project scripts being expanded
- `mkdocs.yml` — nav structure (should not need changes, but verify build after each wave)
- `docs/projects.md` — may need updates if new project files are added
- `docs/index.md` — landing page tool references may need cross-referencing

##### Decision Log
<!-- Guardian appends here after wave completion -->

#### Curriculum Enhancement Worktree Strategy

Main is sacred. Each wave dispatches a single worktree:
- **Wave 1:** `.worktrees/enhance-0x01` on branch `enhance/0x01-structural-fingerprinting`
- **Wave 2:** `.worktrees/enhance-0x02` on branch `enhance/0x02-infrastructure-mapping`
- **Wave 3:** `.worktrees/enhance-0x03` on branch `enhance/0x03-overlap-clustering`
- **Wave 4:** `.worktrees/enhance-0x04` on branch `enhance/0x04-c2-open-directories`
- **Wave 5:** `.worktrees/enhance-0x05` on branch `enhance/0x05-leak-stealer-intel`
- **Wave 6:** `.worktrees/enhance-0x06` on branch `enhance/0x06-edge-layer-obfuscation`
- **Wave 7:** `.worktrees/enhance-0x07` on branch `enhance/0x07-graph-based-hunting`
- **Wave 8:** `.worktrees/enhance-0x08` on branch `enhance/0x08-proxy-botnet-layers`
- **Wave 9:** `.worktrees/enhance-0x09` on branch `enhance/0x09-hunter-opsec`
- **Wave 10:** `.worktrees/enhance-0x0A` on branch `enhance/0x0A-data-science-hunting`

#### Curriculum Enhancement References

- MkDocs Material: https://squidfunk.github.io/mkdocs-material/
- JARM: https://github.com/salesforce/jarm
- JA4+: https://github.com/FoxIO-LLC/ja4
- Shodan API: https://developer.shodan.io/api
- Censys API: https://search.censys.io/api
- SecurityTrails API: https://securitytrails.com/corp/api
- abuse.ch SSLBL: https://sslbl.abuse.ch/
- crt.sh API: https://crt.sh
- MaxMind GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- scikit-learn: https://scikit-learn.org/stable/
- NetworkX: https://networkx.org/
- Neo4j Cypher: https://neo4j.com/docs/cypher-manual/current/
- pyvis: https://pyvis.readthedocs.io/

---

## Completed Initiatives

| Initiative | Period | Phases | Key Decisions | Archived |
|-----------|--------|--------|---------------|----------|
| Curriculum Deep Enhancement (0x01-0x0A) | 2026-04-02 | 10 waves (W1-W10) | DEC-STRUCT-001..005 | Inline above |

---

## Parked Issues

| Issue | Description | Reason Parked |
|-------|-------------|---------------|
