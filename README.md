# netthrunter

**Advanced Infrastructure & Adversary Hunting Curriculum (AIH-C)**

A 15-module technical curriculum and engineering framework for proactively identifying, tracking, and mapping threat actor infrastructure. Built for senior threat researchers and security engineers who want to move beyond static IOCs and focus on behavioral fingerprints and structural overlaps of adversary infrastructure.

## Quickstart

```bash
# Clone and set up
git clone https://github.com/jhuntinfosec/netthrunter.git
cd netthrunter
python3 -m venv .venv
source .venv/bin/activate

# Install core dependencies
pip install pandas networkx matplotlib scikit-learn httpx jupyterlab

# Start the background infrastructure (Neo4j for graphs, JupyterLab)
docker-compose up -d

# Run any capstone project (all work in demo/mock mode)
python projects/0x01_jarm_scanner/tls_fingerprint.py

# Modules can now be chained together via the unified IOC schema
python projects/0x01_jarm_scanner/tls_fingerprint.py | python projects/0x0F_ttp_profiler/ttp_profiler.py

# Interact with the data science modules via Jupyter Notebooks
jupyter lab

# Serve the curriculum docs locally
pip install mkdocs-material
mkdocs serve
```

## Curriculum

Each module pairs a teaching document (theory, techniques, tool references, case studies) with a runnable Python capstone project.

| Module | Focus | Capstone Project | LOC |
|--------|-------|-----------------|-----|
| **0x01** | [Structural Fingerprinting](docs/modules/0x01_structural_fingerprinting.md) | JARM/JA3 scanner with known C2 hash DB | 774 |
| **0x02** | [Infrastructure Mapping](docs/modules/0x02_infrastructure_mapping.md) | CT log hunter with DNS resolution & WHOIS | 669 |
| **0x03** | [Overlap & Clustering](docs/modules/0x03_overlap_clustering.md) | Jaccard similarity clustering with graph viz | 563 |
| **0x04** | [C2 & Open Directories](docs/modules/0x04_c2_open_directories.md) | C2 framework fingerprinter (7 frameworks) | 953 |
| **0x05** | [Leak & Stealer Intel](docs/modules/0x05_leak_stealer_intel.md) | Stealer log parser with family detection | 722 |
| **0x06** | [Edge Layer Obfuscation](docs/modules/0x06_edge_layer_obfuscation.md) | CDN/WAF fingerprinter & origin discovery | 946 |
| **0x07** | [Graph-Based Hunting](docs/modules/0x07_graph_based_hunting.md) | NetworkX graph builder with community detection | 588 |
| **0x08** | [Proxy & Botnet Layers](docs/modules/0x08_proxy_botnet_layers.md) | IP intelligence classifier with risk scoring | 888 |
| **0x09** | [Hunter OPSEC](docs/modules/0x09_hunter_opsec.md) | Distributed Lambda scanner with SAM templates | 610 |
| **0x0A** | [Data Science for Hunting](docs/modules/0x0A_data_science_hunting.md) | Entropy + K-Means + Isolation Forest classifier | 618 |
| **0x0B** | [Cloud Infrastructure Hunting](docs/modules/0x0B_cloud_infrastructure.md) | Map cloud IPs and identify open S3 buckets | 65 |
| **0x0C** | [Follow the Money (Crypto Tracking)](docs/modules/0x0C_crypto_tracking.md) | Traces transactions and clusters BTC wallets | 46 |
| **0x0D** | [LLM & AI-Assisted Threat Hunting](docs/modules/0x0D_llm_hunting.md) | Extract IOCs using local Ollama/Claude/Gemini | 62 |
| **0x0E** | [Active Defense & Deception](docs/modules/0x0E_active_defense.md) | Active honeypot listener logging scanners | 45 |
| **0x0F** | [Threat Profiling & TTP Matrix Mapping](docs/modules/0x0F_threat_profiling.md) | Maps IOCs to MITRE ATT&CK behavior profiles | 45 |

All projects run in **mock/demo mode** with zero configuration — no API keys required. Real API integrations (Shodan, crt.sh, ip-api.com, Telegram) activate via environment variables.

## Repository Structure

```
docs/
  modules/          15 teaching modules (Markdown, served via MkDocs)
  index.md          Landing page
  projects.md       Capstone projects overview
projects/
  0x01_jarm_scanner/        tls_fingerprint.py
  0x02_ct_hunter/           ct_hunter.py
  0x03_overlap_clustering/  ssh_cluster.py
  0x04_c2_dorker/           c2_dorker.py
  0x05_leak_parser/         leak_parser.py
  0x06_edge_layer/          cdn_tester.py
  0x07_graph_builder/       graph_builder.py
  0x08_proxy_validator/     proxy_validator.py
  0x09_lambda_scanner/      lambda_scanner.py
  0x0A_entropy_classifier/  entropy.py
  0x0B_cloud_mapper/        cloud_mapper.py
  0x0C_crypto_tracer/       crypto_tracer.py
  0x0D_intel_extractor/     intel_extractor.py
  0x0E_decoy_listener/      decoy_listener.py
  0x0F_ttp_profiler/        ttp_profiler.py
books/              Offline reference library (PDFs, gitignored)
mkdocs.yml          MkDocs Material configuration
```

## Key Techniques Covered

**Fingerprinting** — JARM (10-probe TLS), JA3/JA3S, JA4+ family, HTTP/2 SETTINGS fingerprinting, SSH HASSH

**Infrastructure Mapping** — Certificate Transparency logs, passive DNS pivoting, WHOIS history clustering, subdomain enumeration

**Clustering & Attribution** — Jaccard similarity, Union-Find grouping, bulletproof hosting ASN analysis, temporal provisioning patterns

**C2 Detection** — Cobalt Strike checksum8 algorithm, Sliver/Havoc/Mythic/BRC4 signatures, open directory hunting, stager identification

**Threat Intel from Leaks** — Stealer family detection (Redline, Vidar, Lumma, Raccoon), Telegram bot token validation, credential extraction

**Evasion Analysis** — Domain fronting mechanics, CDN origin discovery (6 techniques), WAF fingerprinting (5 providers), Cloudflare Tunnel detection

**Graph Analysis** — Degree/betweenness/PageRank centrality, Louvain community detection, Neo4j Cypher generation, GEXF/pyvis export

**Proxy Intelligence** — Residential vs datacenter classification, BGP/ASN analysis, Spamhaus DROP checking, composite risk scoring

**Data Science** — Shannon entropy for DGA detection, K-Means with elbow method, Isolation Forest anomaly detection, feature engineering pipeline

## Tools Referenced

The curriculum integrates these tools contextually within each module:

| Category | Tools |
|----------|-------|
| Scanning & Discovery | Shodan, Censys, FOFA, Subfinder, Amass |
| Fingerprinting | JARM, JA3/JA4+, SSLBL (abuse.ch), ja3er.com |
| Passive Intel | crt.sh, SecurityTrails, VirusTotal, PassiveTotal |
| Graphing | Neo4j, Maltego, Gephi, NetworkX, pyvis |
| IP Intelligence | MaxMind GeoLite2, IPinfo.io, BGPView, Spamhaus |
| Malware Analysis | MalwareBazaar, URLhaus, Any.Run, Triage |
| OPSEC | AWS Lambda/SAM, curl_cffi, Tor, proxychains |

## Dependencies

**Required:** Python 3.10+, pandas

**Recommended:** scikit-learn, networkx, matplotlib, httpx

**Optional (enhance specific modules):** jarm-py, shodan, python-whois, geoip2, pyvis

```bash
# Install everything
pip install pandas scikit-learn networkx matplotlib httpx jarm-py shodan python-whois pyvis
```

## Reference Library

The `books/` directory (gitignored) supports the curriculum with these texts:

- *Black Hat Python 2E* & *Hacking APIs* — Networking, TLS/cert scanners (Modules 1, 2, 4, 6)
- *The Threat Hunter's Query Playbook* — Overlap and clustering logic (Module 3)
- *Data Engineering for Cybersecurity* — Stealer log processing, graph modeling, entropy (Modules 5, 7, 10)
- *Art of Cyber Warfare* & *Adversarial Tradecraft* — Proxy analysis, OPSEC (Modules 8, 9)

## Ethics & Legal

This curriculum is for **authorized defensive research only**.

- Never scan infrastructure without written authorization
- Exhaust passive sources (Shodan, Censys, CT logs) before active scanning
- Never use stolen credentials found in stealer logs
- Report compromised legitimate infrastructure to the owner and relevant CERT
- Follow your organization's rules of engagement and applicable law (CFAA, CMA, etc.)

See Module 0x09 for comprehensive OPSEC and legal guidance.

## License

Private repository. All rights reserved.
