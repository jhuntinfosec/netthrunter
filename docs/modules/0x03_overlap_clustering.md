# Module 0x03: Overlap & Clustering

## Overview

We move from flat lists to relationship graphs. If three IPs share an SSH key fingerprint and are hosted on the same "bulletproof" ASN, they are treated as a single cluster. This module covers identifying structural overlaps across seemingly disparate assets — from the theoretical underpinning of multi-indicator correlation through to production-grade clustering code and a full pivot-chain case study.

**Prerequisites:** Modules [0x01 (Structural Fingerprinting)](0x01_structural_fingerprinting.md) and [0x02 (Infrastructure Mapping)](0x02_infrastructure_mapping.md) provide the raw indicators — JARM hashes, certificate serial numbers, ASN data — that feed the clustering techniques here.

---

## Key Concepts

* **ASN Affinity**: Many threat actors prefer specific hosting providers that ignore DMCA/Abuse complaints.
* **Shared SSH Keys**: Adversaries often use automated infrastructure pipelines (Ansible/Terraform) spreading identical SSH Host Keys across multiple C2s.
* **Registrar Trends**: Correlating WHOIS patterns and the usage of specific Privacy Protect providers.

---

## 1. Multi-Indicator Correlation Theory

No single indicator makes a cluster. The power lies in stacking multiple weak signals until the combined weight forces a confident attribution.

### 1.1 The Indicator Hierarchy

Indicators carry different confidence weights. Higher weight means stronger evidence of shared infrastructure or actor:

| Indicator | Confidence Weight | Notes |
|---|---|---|
| SSH host key (exact match) | **Very High** | Key reuse across IPs is nearly never accidental — automation artifacts |
| TLS certificate serial or fingerprint | **Very High** | Reused certs across domains/IPs are strong attribution anchors |
| JARM hash | **High** | Unique TLS stack fingerprint — see Module 0x01 |
| WHOIS registrant email | **High** | Even privacy-protected domains often share a real contact on older registrations |
| JA3/JA4+ client fingerprint | **Medium-High** | Shared when the same tool/framework generates the traffic |
| Certificate CN or SAN pattern | **Medium** | Actors reuse naming schemes; can be coincidence |
| ASN co-tenancy | **Low-Medium** | Thousands of actors share AS20473; valuable only in combination |
| Registrar preference | **Low** | Broad signal; useful for initial filtering, not attribution |

### 1.2 Indicator Combination and Confidence Escalation

The key insight is **multiplicative confidence** — each overlapping indicator reduces the probability that the overlap is coincidental. Consider:

- Two IPs on the same ASN: coincidence rate high. Score: weak.
- Two IPs on same ASN *and* sharing an SSH key: coincidence rate drops to near zero. Score: strong.
- Two IPs sharing SSH key, JARM, cert serial *and* a WHOIS registrant email: probability of accidental overlap is astronomically small. Score: definitive.

This is the operational basis for the Jaccard similarity scoring in the capstone project: each shared indicator is a vote, the ratio of shared votes to total possible votes is the cluster confidence.

### 1.3 False Positive Sources

Be aware of legitimate shared-indicator scenarios:

- **CDN infrastructure**: Multiple CDN edge nodes share certificates by design (see Module 0x06).
- **Cloud provider defaults**: Some VPS providers ship a default SSH host key in their base images — check if the key is a provider artifact.
- **Shared hosting**: Many tenants on one IP share a TLS certificate.
- **Automation frameworks**: Open-source Ansible roles can produce identical SSH configs across unrelated customers.

Mitigation: Cross-reference the overlapping indicator value against Shodan/Censys for total prevalence. If 50,000 IPs share the JARM hash, it is a framework fingerprint, not an actor fingerprint.

---

## 2. Bulletproof Hosting Deep Dive

### 2.1 What Makes a Provider "Bulletproof"?

Bulletproof hosting (BPH) providers tolerate abuse reports or respond so slowly that malicious infrastructure remains operative for weeks. The key selection criteria actors use:

1. **Abuse response time**: How many hours/days before takedown? BPH providers aim for infinite.
2. **Anonymity of registration**: Accepts crypto, no ID verification, offshore jurisdiction.
3. **Network peering**: Well-peered ASNs keep latency low for C2 beaconing.
4. **Price**: Low-cost providers attract both actors and legitimate bulk purchasers — good cover.

### 2.2 Key ASNs in Threat Actor Infrastructure

The following ASNs appear repeatedly in threat intelligence reporting. **Their inclusion here is for defensive identification — all are legitimate providers used by millions of benign customers.**

| ASN | Provider | Abuse Tolerance | Common Actor Use |
|---|---|---|---|
| AS20473 | Choopa / Vultr | Moderate | C2 nodes, drop servers, widespread |
| AS16276 | OVH SAS | Moderate | European actor preference; DDoS-for-hire |
| AS24940 | Hetzner Online | Moderate | Low-cost servers; used in ransomware campaigns |
| AS14061 | DigitalOcean | Low-Moderate | Phishing, credential harvesting; easy API provisioning |
| AS49505 | Selectel | High | Russian-nexus actors; fewer INTERPOL takedown routes |
| AS398324 | HostHatch | High | Bulletproof VPS reseller |
| AS59642 | NForce Entertainment | Very High | Historically abuse-tolerant; DDoS and spam |
| AS206485 | Frantech / BuyVM | High | DMCA-ignored; used by ransomware operators |

!!! warning "ASN ≠ Actor"
    High presence of actor infrastructure on an ASN does not make that provider malicious. These are shared environments. Never use ASN membership alone for attribution. Use it as a filter to prioritize manual review.

### 2.3 Abuse Response Timelines

Approximate operational timelines based on published threat intelligence and provider abuse desk responsiveness:

- **Tier 1 legitimate providers** (AWS, Azure, GCP): 2-24 hours typical takedown after valid report.
- **Mid-tier providers** (Vultr, Hetzner, DO): 24-72 hours. Many actors rotate infrastructure before takedown completes.
- **Bulletproof providers**: Days to never. Actors select these specifically for stability of C2 infrastructure during long campaigns.

This is why **temporal analysis** (Section 4) matters: actors on reliable BPH providers provision slowly and rotate infrequently. Actors on mid-tier providers provision in bursts and rotate weekly.

### 2.4 Reputation Scoring for Hosting Providers

When building a threat hunt scoring system, assign a **provider reputation factor** based on:

```
provider_score = (abuse_tolerance_weight * 0.4)
              + (takedown_difficulty * 0.3)
              + (historical_actor_presence * 0.3)
```

Multiply this factor against your cluster confidence score to produce a final **infrastructure risk score**. A high-Jaccard cluster hosted entirely on AS49505 (Selectel) is treated with higher urgency than the same cluster spread across AWS.

---

## 3. Clustering Algorithms

### 3.1 Jaccard Similarity for Indicator Set Comparison

Given two infrastructure nodes **A** and **B**, each represented as a set of indicators (SSH key, JARM hash, ASN, registrant email, cert serial), the Jaccard similarity is:

```
J(A, B) = |A ∩ B| / |A ∪ B|
```

Where:
- `|A ∩ B|` = number of indicators shared by both nodes.
- `|A ∪ B|` = total unique indicators across both nodes.

**J = 0** means no overlap whatsoever. **J = 1** means identical indicator sets (the same actor machine re-IP'd, or a direct clone).

Example:
```
Node 1 indicators: {ssh:sk-BEAR-01, jarm:jarm-BEAR, asn:AS20473}
Node 2 indicators: {ssh:sk-BEAR-01, jarm:jarm-BEAR, asn:AS20473}
J(1,2) = 3/3 = 1.0  ← perfect match

Node 1 indicators: {ssh:sk-BEAR-01, jarm:jarm-BEAR, asn:AS20473}
Node 3 indicators: {ssh:sk-PANDA-01, jarm:jarm-BEAR, asn:AS16276}
J(1,3) = 1/5 = 0.2  ← weak overlap (shared JARM only)
```

### 3.2 Threshold-Based Cluster Assignment

After computing all pairwise Jaccard scores, apply a threshold to determine cluster membership:

```
if J(A, B) >= threshold:
    merge(cluster_of(A), cluster_of(B))
```

**Threshold selection:**

| Threshold | Effect |
|---|---|
| 0.15 | Very aggressive — ASN alone may create false clusters |
| 0.30 | Default — requires 1-2 shared indicators |
| 0.50 | Conservative — requires 2+ strong indicators |
| 0.75 | Strict — nearly identical infrastructure only |

Union-Find (disjoint set) implements the merge operation in near-constant amortized time, making this tractable for datasets of thousands of nodes.

### 3.3 Hierarchical Clustering

For larger datasets (10,000+ nodes) where you need to explore the full similarity structure, hierarchical agglomerative clustering is the right tool:

```python
from scipy.cluster.hierarchy import linkage, fcluster
from scipy.spatial.distance import squareform

# Build pairwise distance matrix (distance = 1 - Jaccard)
n = len(nodes)
dist_matrix = np.zeros((n, n))
for i, j in combinations(range(n), 2):
    dist = 1 - jaccard(indicator_sets[i], indicator_sets[j])
    dist_matrix[i][j] = dist_matrix[j][i] = dist

# Cluster with complete linkage (conservative: max intra-cluster distance)
linkage_matrix = linkage(squareform(dist_matrix), method='complete')
labels = fcluster(linkage_matrix, t=0.7, criterion='distance')
```

The resulting **dendrogram** shows the full merge tree — you cut at different heights to get different cluster granularities. This is useful when presenting to stakeholders: you can show the same data at "confirmed cluster" and "probable cluster" thresholds.

**When to use each approach:**

| Approach | Best For |
|---|---|
| Threshold + Union-Find | Real-time hunting, dashboards, <1000 nodes |
| Hierarchical (scipy) | Exploratory analysis, large datasets, dendrogram reporting |
| DBSCAN (sklearn) | Noise-tolerant clustering when indicator coverage is uneven |

### 3.4 Handling Partial Overlaps

Partial overlaps are the hardest case: Node A shares JARM with Cluster 1 and shares SSH key with Cluster 2. Three interpretations:

1. **Same actor, two infrastructure segments** → merge the clusters.
2. **Two actors using the same commercial BPH provider** → shared JARM is a provider artifact, not an actor artifact.
3. **Shared tool/framework** → the TLS stack is identical because the same open-source C2 is in use.

Resolution: Check the **prevalence** of each shared indicator in Shodan/Censys. If the shared JARM appears on 500,000 IPs, it is framework noise. If it appears on 12 IPs, it is a real cluster signal.

---

## 4. Temporal Correlation

Infrastructure doesn't appear instantaneously. Provisioning patterns reveal actor rhythms.

### 4.1 Time-of-Day Analysis

Actors work during their local business hours, even when targeting other timezones. Provisioning events — domain registration, certificate issuance, VPS deployment — cluster around 09:00–18:00 in the actor's local timezone.

Technique: Collect CT log `not_before` timestamps (from Module 0x02) and WHOIS creation timestamps for all domains in a cluster. Plot the distribution of creation times in UTC. The peak hours (adjusted by a fixed offset) reveal the actor's likely timezone.

```
Certificate issuance times (UTC) for 23 domains in cluster:
  01:00-03:00 UTC → 14 certificates   ← dense cluster
  14:00-16:00 UTC → 3 certificates
  Others          → 6 certificates

UTC+8 (China/Russia Far East): 09:00-11:00 local
UTC+3 (Russia/Eastern Europe): 04:00-06:00 local  ← less likely
```

This is soft attribution evidence — not definitive, but it narrows the hypothesis space.

### 4.2 Burst Provisioning

When a threat actor deploys a new campaign, they provision multiple servers in rapid succession. A burst of 10-20 new VPS instances within a 1-2 hour window, all on the same ASN, is a strong cluster signal even before SSH or JARM analysis.

Detection: Query Shodan's historical scan data or Censys for first-seen dates within your target indicator set. Burst provisioning produces distinct temporal spikes.

### 4.3 Rotation Schedules

Actors with good OPSEC rotate infrastructure on schedules:

- **Weekly**: Common in commodity malware operations. Domain generation algorithms (DGAs) update weekly.
- **Monthly**: APT actors with stable campaigns; infrastructure persists longer.
- **On-detection**: Some actors rotate only when they appear in public threat feeds (automated monitoring for mentions of their IPs/domains).

Temporal analysis of rotation: Compare cluster membership across multiple Shodan/Censys snapshots. Nodes that disappear and reappear on new IPs but with the same SSH key are rotating actors.

### 4.4 Campaign Lifecycle Model

```
T+0h    → Provisioning burst (VPS + domains registered)
T+6h    → Certificates issued (CT logs light up)
T+24h   → Infrastructure operational (first C2 beacon seen)
T+7d    → Mid-cycle rotation (some nodes retired, new IPs provisioned)
T+30d   → Campaign ends or full rotation
```

Hunters who monitor CT logs continuously (Module 0x02) can detect the T+6h window — before infrastructure is operational.

---

## 5. Pivot Techniques

### 5.1 The Pivot Chain Concept

A pivot chain starts from one confirmed indicator and expands outward through overlapping attributes until the full actor infrastructure map is visible:

```
SSH key fingerprint
    → All IPs sharing this SSH key (Shodan: ssh.fingerprint:<hash>)
        → All domains resolving to those IPs (passive DNS)
            → All TLS certs on those domains (Censys cert search)
                → All registrant emails on those certs (WHOIS / passive total)
                    → All other domains registered by that email
                        → All IPs hosting those domains
                            → New IPs → validate against initial SSH key
                                        (close the loop or find new clusters)
```

Each arrow is a pivot step. The chain terminates when you either:
- Return to already-known nodes (the cluster is fully mapped), or
- Hit a node with no new indicators (likely a CDN or shared infrastructure boundary).

### 5.2 Pivot Step Reference

| Start | Pivot | Tool | Query |
|---|---|---|---|
| SSH key fingerprint | IPs sharing key | Shodan | `ssh.fingerprint:<hash>` |
| IP | Domains (passive) | PassiveTotal, DNSDB | Passive DNS lookup |
| Domain | Certificate (current) | Censys, crt.sh | `parsed.names:<domain>` |
| Certificate serial | All domains on cert | Censys | `parsed.fingerprint_sha256:<hash>` |
| Cert registrant email | Other domains | PassiveTotal | WHOIS email pivot |
| Registrant email | WHOIS history | PassiveTotal | Historical registrant data |
| JARM hash | IPs sharing hash | Shodan | `ssl.jarm:<jarm>` |
| IP | Historical IPs (same actor) | Shodan historical, Censys | First/last seen diff |

### 5.3 Boundary Recognition

Not every pivot produces actor infrastructure. Stop expanding when:
1. **Domain resolves to a CDN IP** (AS13335 Cloudflare, AS16509 AWS CloudFront) — the CDN masks the origin.
2. **Certificate is a wildcard** (`*.amazonaws.com`) — infrastructure noise.
3. **Shodan returns >1000 results** for the indicator — the indicator is a commodity fingerprint.
4. **WHOIS email is a privacy proxy** with no historical registrations — dead end on that pivot.

Document the stopping condition clearly in your hunt notes. An unexplained dead end can become relevant later.

---

## 6. Tool Reference

### 6.1 Shodan

Shodan's facet and filter capabilities are central to infrastructure clustering.

**ASN aggregation:**
```bash
# Count infrastructure by ASN for a JARM hash
shodan stats --facets asn ssl.jarm:27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d

# Top 10 ASNs hosting Cobalt Strike default JARM
shodan stats --facets asn,port ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
```

**SSH key search:**
```bash
# Find all IPs sharing an Ed25519 host key fingerprint
shodan search ssh.fingerprint:ab:cd:ef:12:34:56:78:90

# Using the Python API
import shodan
api = shodan.Shodan(os.environ['SHODAN_API_KEY'])
results = api.search('ssh.fingerprint:ab:cd:ef:12:34:56:78:90')
for match in results['matches']:
    print(match['ip_str'], match.get('asn'), match.get('isp'))
```

**Bulk API for large datasets:**
```python
# Use the streaming API to avoid result limits
for result in api.search_cursor('ssl.jarm:<jarm_hash>'):
    process(result)
```

**Shodan facet query for JARM clustering:**
```
ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 port:443
```

### 6.2 Censys

Censys provides structured certificate and host data with powerful aggregate reports.

```python
from censys.search import CensysHosts

h = CensysHosts()
# Find all hosts with a specific certificate fingerprint
for page in h.search("services.tls.certificates.leaf_data.fingerprint: <sha256>",
                      fields=["ip", "services.port", "autonomous_system.asn"]):
    for host in page:
        print(host)
```

**Aggregate reports** (Censys v2 API):
```python
# Count hosts by ASN for a JARM hash
query = "services.jarm.fingerprint: <jarm>"
report = h.aggregate(query, field="autonomous_system.asn", num_buckets=25)
for bucket in report["buckets"]:
    print(bucket["key"], bucket["count"])
```

### 6.3 Maltego

Maltego provides a visual pivot chain environment. Key transforms for infrastructure pivoting:

- **ShodanTransform**: IP → Shodan data → related IPs by fingerprint.
- **PassiveTotal transforms**: Domain → WHOIS history → registrant email → related domains.
- **Censys transforms**: Certificate → all domains → related certificates.
- **VirusTotal Graph**: Domain → IP → Certificate → Registrant chain.

For automated hunts, export Maltego graph data as GraphML and ingest into NetworkX (see the capstone project below).

### 6.4 PassiveTotal / RiskIQ

PassiveTotal is the canonical tool for WHOIS and SSL certificate history pivots.

```python
from passivetotal import GenericRequest

client = GenericRequest.from_config()

# WHOIS email pivot: find all domains registered by an email
result = client.get_whois_search(query="threatactor@protonmail.com", field="email")
for domain in result.get("results", []):
    print(domain["domain"])
```

Key PassiveTotal capabilities:
- Historical WHOIS (captures registrant emails before privacy protection was added).
- SSL certificate history (when a certificate was first seen, all IPs it appeared on).
- Passive DNS (historical A/CNAME records).

### 6.5 BGPView

For ASN and prefix analysis:

```bash
# Get all prefixes for an ASN
curl -s "https://api.bgpview.io/asn/20473/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# Get ASN details
curl -s "https://api.bgpview.io/asn/20473" | jq '.data | {name, description, country_code}'

# Find ASN by IP
curl -s "https://api.bgpview.io/ip/45.77.10.1" | jq '.data.prefixes[0] | {asn: .asn.asn, name: .asn.name}'
```

BGPView is unauthenticated and rate-limit friendly — suitable for bulk enrichment of IP lists.

---

## 7. Case Study: From SSH Key to Full Actor Map

This case study demonstrates the complete pivot chain methodology, starting from a single SSH key fingerprint found during a routine Shodan sweep.

### 7.1 Initial Discovery

During a hunt for Cobalt Strike C2s using the default JARM hash, analyst finds IP `45.77.10.1` with an unusual Ed25519 host key that also appears on five other IPs. The SSH key fingerprint becomes the anchor.

**Shodan query:** `ssh.fingerprint:ab:cd:ef:12:34:56:78:90`

Result: 8 IPs. All on AS20473 (Vultr/Choopa). This is the first cluster signal.

### 7.2 Pivot Step 1: SSH Key → IP Cluster

```python
# Using the capstone project
nodes = search_ssh_hash("ab:cd:ef:12:34:56:78:90")
# Returns 8 IPs, all AS20473

analyze_clusters(nodes)
# Output: AS20473 | Vultr/Choopa | 8 nodes | Affinity: 100%
# [!] HIGH CONFIDENCE CLUSTER DETECTED
```

ASN affinity at 100% is strong. But the SSH key is the real anchor — the ASN just corroborates.

### 7.3 Pivot Step 2: IPs → Domains (Passive DNS)

Run each of the 8 IPs through PassiveTotal passive DNS:

```
45.77.10.1 → update-pkg[.]org, cdn-static[.]net
45.77.10.2 → metrics-relay[.]io
108.61.200.5 → logstash-ingest[.]net
... (4 more)
```

Result: 11 unique domains. Note the naming pattern: all mimic legitimate infrastructure management terminology. This is a naming convention fingerprint.

### 7.4 Pivot Step 3: Domains → TLS Certificates

Query Censys for current certificates on each domain:

```python
# Certificate fingerprints for the 11 domains
certs_found = censys_cert_search(domains)
# Returns 3 unique certificate fingerprints
# Certificate A: covers update-pkg[.]org AND cdn-static[.]net (SAN)
# Certificate B: covers metrics-relay[.]io AND logstash-ingest[.]net
# Certificate C: single domain cert on outlier IP
```

Certs A and B are multi-SAN certs, confirming the actor grouped these domains together during provisioning.

### 7.5 Pivot Step 4: Certificates → Registrant Email

PassiveTotal historical WHOIS on all 11 domains:

```
Domain          | Current Registrant | Historical WHOIS Contact
update-pkg.org  | Privacy proxy      | threatops2021@outlook.com (2019)
cdn-static.net  | Privacy proxy      | threatops2021@outlook.com (2019)
metrics-relay.io| Privacy proxy      | —
logstash-ingest.net | Privacy proxy  | threatops2021@outlook.com (2020)
```

Three domains share a historical registrant email. Privacy protection was added later — a common mistake. The email is the new anchor.

### 7.6 Pivot Step 5: Email → Additional Domains

```python
# PassiveTotal WHOIS pivot
result = client.get_whois_search(query="threatops2021@outlook.com", field="email")
# Returns 34 additional domains registered 2018-2022
```

34 new domains. Filter by registration date — the 2021-2022 batch aligns with the campaign timeline. New domains include a different naming scheme: `svc-telemetry-*.xyz` pattern.

### 7.7 Pivot Step 6: New Domains → New IPs

Passive DNS on the `svc-telemetry-*.xyz` domains reveals 12 new IPs. These are on AS24940 (Hetzner) and AS16276 (OVH) — the actor diversified providers for the second campaign wave.

Run new IPs through SSH key lookup:

```
Hetzner IPs: 5 of 7 share SSH key sk-BEAR-02 (variant key, same actor)
OVH IPs: 3 of 5 share JARM hash with original Vultr cluster
```

The loop closes. Same actor, two infrastructure waves, three hosting providers, one actor identity confirmed.

### 7.8 Final Cluster Map

```
CLUSTER A (Vultr, Wave 1):
  8 IPs | SSH key sk-BEAR-01 | JARM jarm-BEAR
  Domains: update-pkg[.]org, cdn-static[.]net, metrics-relay[.]io ...
  Registrant: threatops2021@outlook.com

CLUSTER A-2 (Hetzner/OVH, Wave 2):
  12 IPs | SSH key sk-BEAR-02 | JARM jarm-BEAR (same)
  Domains: svc-telemetry-*.xyz pattern
  Registrant: privacy-protected (but linked via email pivot)

Pivot chain: sk-BEAR-01 → 8 IPs → 11 domains → 3 certs
           → threatops2021@outlook.com → 34 domains
           → 12 new IPs → sk-BEAR-02 → JARM jarm-BEAR ← closes loop
```

Total actor infrastructure mapped: **20 IPs, 45 domains, 3 hosting providers** — from a single SSH key fingerprint.

---

## 8. OPSEC Note for Hunters

!!! warning "Automated Pivoting Generates a Detectable Query Footprint"
    Rapid programmatic pivoting through Shodan, Censys, PassiveTotal, and passive DNS creates a query pattern that:

    1. Depletes API credits rapidly — budget accordingly.
    2. May be logged by threat intelligence platforms — some actors monitor for searches of their infrastructure.
    3. Can trigger rate limits that make your queries visible to platform operators.

**Mitigations:**

- **Rate-limit queries:** Add `time.sleep(1.0)` between API calls. Distribute queries over hours, not seconds.
- **Use separate API accounts** for different hunt operations — query isolation.
- **Batch lookups** where the API supports it (Shodan bulk host API, Censys bulk certificate lookup).
- **Pre-cache data** — download full Shodan datasets for a search term once, analyze offline.
- **Sanitize your hunt environment** — do not pivot from a machine or IP that can be attributed to your organization.

Full OPSEC considerations for the hunter are in [Module 0x09](0x09_hunter_opsec.md).

---

## 9. Module Project: Multi-Indicator Clustering Engine

The capstone project expands the original SSH-key clustering script into a full multi-indicator analysis engine with Jaccard similarity, graph visualization, and pivot chain reporting.

### 9.1 Architecture

```
Input (CSV or mock dataset)
    ↓
build_indicator_sets()     # SSH key, JARM, ASN → frozenset per node
    ↓
compute_clusters()         # Pairwise Jaccard + Union-Find
    ↓
build_pivot_chains()       # Which indicators connect which nodes
    ↓
Output (text / JSON / CSV) + optional PNG graph
```

### 9.2 CSV Input Format

```csv
ip,domain,asn,ssh_key,jarm_hash
45.77.10.1,update-pkg.org,AS20473,sk-BEAR-01,jarm-BEAR
45.77.10.2,cdn-static.net,AS20473,sk-BEAR-01,jarm-BEAR
51.77.50.10,proxy-east.pw,AS16276,sk-PANDA-01,jarm-PANDA
```

### 9.3 Full Reference Implementation

```python
#!/usr/bin/env python3
"""
Module 0x03 Capstone Project: Multi-Indicator Overlap & Clustering Engine

@decision DEC-CLUSTER-001
@title Jaccard similarity over cosine for sparse binary indicator vectors
@status accepted
@rationale Infrastructure indicator sets are sparse and binary. Jaccard
  similarity |A ∩ B| / |A ∪ B| is canonical for set-overlap problems.
  Cosine similarity weights magnitude, which is meaningless here.
"""
import argparse, csv, json, os, sys
from collections import Counter, defaultdict
from itertools import combinations

try:
    import networkx as nx
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_VIZ = True
except ImportError:
    HAS_VIZ = False

INDICATOR_FIELDS = ("ssh_key", "jarm_hash", "asn")

def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)

class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))
        self.rank = [0] * n
    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x
    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx == ry: return
        if self.rank[rx] < self.rank[ry]: rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]: self.rank[rx] += 1

def build_indicator_sets(nodes):
    return [
        {f"{f}:{node[f]}" for f in INDICATOR_FIELDS if node.get(f)}
        for node in nodes
    ]

def compute_clusters(indicator_sets, threshold=0.3):
    n = len(indicator_sets)
    uf = UnionFind(n)
    edges = []
    for i, j in combinations(range(n), 2):
        sim = jaccard(indicator_sets[i], indicator_sets[j])
        if sim >= threshold:
            uf.union(i, j)
            edges.append((i, j, sim))
    root_to_label = {}
    labels = []
    for i in range(n):
        root = uf.find(i)
        if root not in root_to_label:
            root_to_label[root] = len(root_to_label)
        labels.append(root_to_label[root])
    return labels, edges
```

### 9.4 Running the Project

```bash
# Activate the virtual environment
source .venv/bin/activate

# Run with built-in mock dataset (18 nodes, 3-4 clusters)
python projects/0x03_overlap_clustering/ssh_cluster.py

# Load real data from CSV
python projects/0x03_overlap_clustering/ssh_cluster.py -f targets.csv

# Adjust similarity threshold (more conservative)
python projects/0x03_overlap_clustering/ssh_cluster.py --threshold 0.5

# JSON output for pipeline integration
python projects/0x03_overlap_clustering/ssh_cluster.py --format json

# Generate PNG cluster graph
python projects/0x03_overlap_clustering/ssh_cluster.py --graph --graph-out hunt_clusters.png
```

### 9.5 Sample Text Output

```
======================================================================
  Module 0x03 — Overlap & Clustering Engine
  Jaccard threshold: 0.30  |  Nodes: 18
======================================================================

[+] CLUSTER-00  (8 nodes)
    IP: 45.77.10.1         domain: update-pkg[.]org
         ASN: AS20473       ssh: sk-BEAR-01          jarm: jarm-BEAR
    IP: 45.77.10.2         domain: cdn-static[.]net
    ...
  Pivot chain:
    [asn:AS20473] shared by 6 nodes: 45.77.10.1, 45.77.10.2, ...
    [jarm_hash:jarm-BEAR] shared by 8 nodes: 45.77.10.1, ...
    [ssh_key:sk-BEAR-01] shared by 4 nodes: 45.77.10.1, ...

[+] CLUSTER-01  (5 nodes)
    IP: 51.77.50.10        domain: proxy-east[.]pw
    ...

[!] SINGLETON  (1 node)
    IP: 203.0.113.99       domain: darknode[.]onion-gw

----------------------------------------------------------------------
  Summary Statistics
----------------------------------------------------------------------
  Total nodes         : 18
  Clusters found      : 5
  Largest cluster     : 8 nodes
  Singletons          : 1
  Most common ASN     : AS20473 (8 nodes)
  Most reused SSH key : sk-BEAR-01 (4 nodes)
======================================================================
```

---

**Takeaway:** Multi-indicator correlation transforms isolated IoCs into actor infrastructure maps. A single SSH key fingerprint, combined with JARM analysis, passive DNS, and WHOIS pivoting, can expose an entire campaign's backend within hours.

**Next:** [Module 0x04 — C2 & Open Directories](0x04_c2_open_directories.md) — hunting for misconfigured C2 frameworks and accidentally-exposed directory listings.
