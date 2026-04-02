# GEMINI.md

# Advanced Infrastructure & Adversary Hunting Curriculum (AIH-C)

Welcome to the **AIH-C**. This repository is a technical curriculum and framework designed for senior threat researchers and security engineers. It moves beyond static Indicators of Compromise (IOCs) to focus on the **behavioral fingerprints** and **structural overlaps** of adversary infrastructure.

---

## 🎯 Mission Statement
To provide an engineering-centric methodology for proactively identifying, tracking, and mapping threat actor infrastructure. We aim to increase the "Cost of Operations" for adversaries by targeting the technical foundations of their Command and Control (C2) ecosystems.

---

## 🏛️ The Curriculum (10 Modules)

| Module | Focus Area | Key Concepts |
| :--- | :--- | :--- |
| **0x01** | **Structural Fingerprinting** | JARM, JA3/S, JA4+, TLS Handshake anomalies, and SSH/HTTP header signatures. |
| **0x02** | **Infrastructure Mapping** | Passive DNS (pDNS) pivoting, Certificate Transparency (CT) log monitoring, and WHOIS history. |
| **0x03** | **Overlap & Clustering** | ASN affinity, shared hosting provider trends, SSH key reuse, and Registrar patterns. |
| **0x04** | **C2 & Open Directories** | Advanced dorking, framework-specific fingerprints (Cobalt Strike, Sliver, Havoc), and stager identification. |
| **0x05** | **Leak & Stealer Intel** | Stealer log config extraction, Telegram/Dark Web telemetry, and automated C2 discovery from leaks. |
| **0x06** | **Edge Layer Obfuscation** | Domain Fronting/Borrowing, Cloudflare Tunnels (Argo), and WAF evasion fingerprinting. |
| **0x07** | **Graph-Based Hunting** | Node-relationship mapping (Neo4j), Centrality analysis, and high-fidelity cluster identification. |
| **0x08** | **Proxy & Botnet Layers** | Residential proxy exit nodes, Socks5 hunting, and multi-tier backconnect infrastructure. |
| **0x09** | **Hunter OPSEC** | Anti-scanning detection, distributed hunting (Lambda/Serverless), and identifying researcher traps. |
| **0x0A** | **Data Science for Hunting** | Shannon Entropy analysis, K-Means clustering of fingerprints, and anomaly detection. |

---

## 🐍 Engineer's Implementation Stack
This project emphasizes **Python-driven automation**. The following libraries form the core of the hunting toolkit:

* **Networking/Scraping:** `scapy`, `httpx` (HTTP/2 support), `beautifulsoup4`.
* **Fingerprinting:** `jarm-py`, `pytls`, `hashlib`.
* **Data Science:** `pandas`, `networkx` (for graph logic), `scikit-learn` (for clustering).
* **Automation:** `asyncio` for high-concurrency CT log consumption and API orchestration.

---

## 🛠️ The Hunter’s Toolbelt (Community & Open-Source)

To build this curriculum, we utilize tools that provide high-fidelity data without requiring enterprise-level budgets.

### 1. Global Scanning & Asset Discovery
* **Shodan / Censys / FOFA:** The "Big Three" for searching internet-facing infrastructure. Most offer a free community tier or low-cost "Researcher" licenses.
* **Odin (by Cyble):** A powerful rising engine for scanning and cataloging internet assets (excellent for exposed buckets and IP scanning).
* **Project Discovery (Chaos/Subfinder):** The gold standard for open-source subdomain and asset discovery.

### 2. Fingerprinting & Deep Packet Intel
* **JARM / JA3 / JA4:** (Salesforce/Open Source) The foundational algorithms for TLS fingerprinting.
* **SSLBL (abuse.ch):** A massive community repository of malicious JA3/JARM fingerprints.
* **Fingerprint.py:** Custom Python implementation for generating server-side fingerprints during active probes.

### 3. Passive Intelligence & CT Logs
* **crt.sh / Censys Search:** Free access to Certificate Transparency logs to find newly issued certificates.
* **SecurityTrails API:** Excellent free tier for Passive DNS (pDNS) and WHOIS history.
* **BGPView:** Essential for mapping ASN relationships and identifying "Bulletproof" hosting blocks.

### 4. Graphing & Analysis
* **Neo4j (Community Edition):** The industry standard for mapping infrastructure relationships (IPs ➔ Domains ➔ SSH Keys).
* **Maltego (Community Edition):** Best-in-class GUI for visual link analysis and infrastructure pivoting.
* **Gephi:** Open-source software for visualizing large-scale network graphs and clusters.

---

## 🔍 Deep Dive: Advanced Hunting Logic

### Structural Fingerprinting (Module 0x01)
Instead of blocking an IP, we block the **Server Response Pattern**. By utilizing **JARM**, we can identify the specific version of a C2 framework even if the actor changes the domain and IP daily.
> **Hunter's Note:** Many actors use default Go-lang or Python TLS implementations. Hunting for the specific JARM hash of a default Mythic or Sliver server allows for global pre-emptive mapping.

### Graph-Based Clustering (Module 0x07)
We move from flat lists to relationship graphs. If three IPs share an SSH key fingerprint and are hosted on the same "bulletproof" ASN, they are treated as a single cluster.
* **Tooling:** Use `networkx` to visualize these relationships and `Neo4j` for persistent storage of actor "neighborhoods."

### Behavioral Entropy (Module 0x0A)
Identifying malicious domains often relies on detecting high randomness in string generation. We apply Shannon Entropy to hostnames and URIs:

$$H = -\sum_{i=1}^{n} P(x_i) \log_b P(x_i)$$

High entropy ($H$) in a sub-domain or a TLS certificate "Common Name" is a primary trigger for further investigation into automated infrastructure generation.

---

## 🔍 Deep Dive: The Pivot Logic
A core tenet of this curriculum is the **Pivot Loop**. A hunter never stops at an IP; they use it as a seed:

1.  **Seed:** A malicious IP identified in a stealer log.
2.  **Fingerprint:** Generate its JARM and JA3S hashes.
3.  **Expand:** Query Shodan/Censys for that specific hash globally.
4.  **Cluster:** Identify shared SSH keys or TLS certificates among results.
5.  **Correlate:** Map the ASN and registration dates to find the adversary’s "purchase pattern."

---

## 🛠️ The Hunting Workflow

1.  **Hypothesis:** "A known APT group is using a specific Cloudflare Tunnel configuration to mask their backend."
2.  **Data Collection:** Query **Censys** and **Shodan** for specific HTTP response headers associated with that tunnel version.
3.  **Pivoting:** Identify the JARM hash of the servers behind those tunnels.
4.  **Clustering:** Use Python to find other IPs globally sharing that JARM hash, even those *not* using Cloudflare.
5.  **Action:** Ingest the identified "naked" IPs into blocklists and monitor CT logs for new certificates matching the identified patterns.

---

---

## 🛡️ OPSEC & Ethics
* **Distributed Scanning:** Never scan a suspected C2 from your corporate or home IP. Use ephemeral cloud functions to distribute the origin of your probes.
* **Anti-Hunter Detection:** Be aware that sophisticated actors monitor their own logs for JARM/JA3 probes. If they see a specific scanner fingerprint repeatedly, they will rotate their infra or feed you false telemetry.
* **Authorized Use:** This curriculum is for defensive researchers. Ensure you have the right to probe and analyze the infrastructure you are tracking.

---
