# Module 0x07: Graph-Based Hunting

## Overview

Flat lists of IPs and domains are incredibly difficult to analyze for wide-scale threat actor operations. In this module, we introduce node-relationship mapping, centrality analysis, and high-fidelity clustering to visually and programmatically chart adversary environments.

By the end of this module you will be able to model adversary infrastructure as a property graph, apply multiple centrality measures to identify critical nodes, run community detection to separate campaigns, and export your findings to Neo4j, Gephi, and interactive HTML for analyst review.

**Cross-references:** This module builds directly on the output of earlier modules:
- Module 0x01 (JARM fingerprinting) provides TLS fingerprint edges
- Module 0x02 (CT log hunting) provides domain-to-certificate edges
- Module 0x03 (Overlap clustering) provides SSH key and ASN sharing edges

---

## Key Concepts

- **Node-Relationship Mapping**: Representing physical threat objects (IPs, Certificates, domains, files, ASNs) as interconnected nodes in a property graph.
- **Centrality Analysis**: Identifying the most critical nodes — the primary C2 server that everything routes through, or the pivot node that links two separate campaigns.
- **High-Fidelity Clustering**: Distinguishing random internet overlaps from intentional adversary architecture using community detection.

---

## Graph Theory for Threat Intelligence

### Why Graphs Beat Flat IOC Lists

A flat IOC list is a set. A graph is a map. When you have 500 IPs and 2,000 domains, a flat list tells you what exists. A graph tells you how everything connects — and the connections are where campaigns reveal themselves.

Consider three domains that each resolve to the same IP. On a flat list, that IP appears three times. In a graph, those three domains are visibly clustered around one central node. If that IP also shares an SSH host key with two other IPs on the same ASN, the graph surfaces that relationship instantly. Flat lists would require manual cross-referencing across three separate data sources.

The analytical power compounds: once you identify that a registrant email appears in two separate clusters, you can query the graph for every node connected (directly or indirectly) to that email. In Neo4j, that is one Cypher query. In a spreadsheet, that is hours of pivot tables.

### Node Types

| Node Type | Description | Primary Source |
|-----------|-------------|----------------|
| `IP` | IPv4/IPv6 address hosting infrastructure | Passive DNS, JARM scans (Module 0x01) |
| `Domain` | FQDN — C2 hostname, phishing domain, staging domain | CT logs (Module 0x02), passive DNS |
| `Certificate` | TLS certificate, identified by SHA-256 fingerprint | CT logs (Module 0x02), direct TLS scan |
| `SSHKey` | SSH host key fingerprint (RSA/Ed25519) | Shodan, Censys, Module 0x03 |
| `ASN` | Autonomous System Number — hosting provider | BGP lookup, passive DNS enrichment |
| `Email` | Registrant or abuse contact email | WHOIS, domain registration records |
| `Nameserver` | Authoritative nameserver for a domain | DNS SOA/NS record lookup |
| `JARM` | TLS fingerprint identifying server software stack | Module 0x01 JARM scanner |

### Edge Types

| Edge Type | Meaning | Detection Signal |
|-----------|---------|-----------------|
| `RESOLVES_TO` | Domain → IP resolution | Passive DNS, active resolution |
| `HOSTED_ON` | IP → ASN/hosting provider | BGP/WHOIS lookup |
| `ISSUED_BY` | Domain/IP → TLS certificate | CT log monitoring |
| `SIGNED_WITH` | IP → SSH host key | Shodan SSH banner grab |
| `REGISTERED_BY` | Domain → registrant email | WHOIS lookup |
| `SHARES_KEY_WITH` | IP ↔ IP (same SSH key) | Derived from SIGNED_WITH edges |
| `USES_NS` | Domain → nameserver | DNS NS record |
| `HAS_JARM` | IP → JARM fingerprint | Module 0x01 scanner output |

### Property Graph Model vs Simple Graph

A **simple graph** stores only node IDs and edges — it cannot distinguish between a domain resolving to an IP and a domain being registered to that IP. For threat intelligence, edge labels are critical.

A **property graph** stores:
- **Node properties**: `{type: "IP", value: "185.220.101.1", asn: "AS20473", country: "NL", first_seen: "2024-01-15"}`
- **Edge properties**: `{relationship: "RESOLVES_TO", first_seen: "2024-01-15", last_seen: "2024-03-20", confidence: 0.95}`

Neo4j is a native property graph database. NetworkX supports arbitrary node and edge attributes, making it suitable for the same model in Python.

The property graph model is the foundation of **threat intelligence platforms** like MISP, OpenCTI, and commercial tools like Recorded Future and Maltego. Understanding the data model means you can query and extend any of these platforms.

---

## Centrality Measures Deep Dive

Centrality is a measure of node importance within a graph. Different measures reveal different roles in adversary infrastructure. Applying all four measures and comparing their rankings exposes far more signal than any single measure alone.

### Degree Centrality — Hub Identification

**Formula:** `C_d(v) = deg(v) / (n - 1)` where `n` is total node count.

Degree centrality counts how many direct connections a node has, normalized to the graph size. A node with degree centrality 1.0 connects to every other node (a hub or star center).

**Threat Intel Interpretation:**
- An IP with degree centrality 0.4 that resolves 8 domains is likely a **C2 hosting server** — attackers host multiple campaigns on one IP to reduce operational cost.
- An ASN node with high degree centrality appears in many infrastructure clusters — indicates a **favored hosting provider** for that actor or a provider with lax abuse reporting.
- A JARM fingerprint with high degree centrality means many IPs share the same TLS stack — strong **fingerprinting signal** for campaign attribution (cross-reference Module 0x01).

**When to use:** First pass. Sort all nodes by degree centrality and examine the top 10. These are your investigation anchors.

### Betweenness Centrality — Bridge and Pivot Nodes

**Formula:** `C_b(v) = sum over all s,t pairs of [shortest paths through v] / [total shortest paths s→t]`

Betweenness centrality measures how often a node lies on the shortest path between two other nodes. A node with high betweenness is a **bridge** — remove it and many pairs of nodes can no longer communicate efficiently.

**Threat Intel Interpretation:**
- An IP with high betweenness that connects two otherwise separate clusters of domains is a **pivot node** — evidence of infrastructure reuse across campaigns, or a shared resource like a bulletproof VPN endpoint.
- Bridge nodes are the most tactically valuable for defenders: **blocking or monitoring the bridge node disrupts multiple campaigns simultaneously**.
- In attribution analysis, bridge nodes often reveal the actor's **operational security failures** — they reused infrastructure between two campaigns that they intended to keep separate.

**When to use:** After identifying communities. Look for nodes with high betweenness that belong to community boundaries. These are cross-cluster connections that merit investigation.

**Computational note:** Betweenness centrality is O(VE) for unweighted graphs. For very large graphs (>10,000 nodes), use the `k` parameter in NetworkX for approximate betweenness via sampling.

### PageRank — Recursive Importance

**Algorithm:** Iterative random-walk model. A node's score is proportional to the sum of scores of nodes pointing to it, normalized by their out-degree.

PageRank was originally designed for web page ranking. In a threat intelligence graph, it captures a different signal from degree centrality: **being connected to important nodes makes you important**, even if you have few direct connections yourself.

**Threat Intel Interpretation:**
- An IP with moderate degree but high PageRank is likely connected to other high-degree nodes — it is part of the **core infrastructure cluster**, not a peripheral node.
- A certificate with high PageRank that is shared across multiple high-degree IPs is a strong **campaign attribution anchor** — it ties together core infrastructure through a non-trivial shared attribute.
- PageRank-high nodes are the best candidates for **pivot investigation**: "what else is connected to this node?"

**When to use:** When degree centrality alone produces obvious results (the shared ASN has the highest degree), PageRank can surface less obvious but equally significant relationships.

### Eigenvector Centrality — Influence Propagation

**Algorithm:** The eigenvector corresponding to the largest eigenvalue of the adjacency matrix. Computed iteratively.

Eigenvector centrality is conceptually similar to PageRank but uses the undirected graph and does not apply the teleportation damping factor. It measures how well-connected a node's neighbors are.

**Threat Intel Interpretation:**
- High eigenvector centrality identifies nodes embedded in a **densely interconnected cluster** — the infrastructure core, not the periphery.
- Nodes with high eigenvector but low betweenness are **deep inside one community** — core campaign infrastructure that is well-connected internally but does not bridge to other clusters.
- Nodes with high eigenvector AND high betweenness are the most analytically significant: they are central within their cluster **and** connect to other clusters.

**Caveat:** Eigenvector centrality can fail to converge on disconnected graphs or graphs with very sparse connectivity. Always run with error handling; fall back to degree centrality if convergence fails.

### Centrality Comparison Summary

| Measure | Identifies | Best For |
|---------|-----------|---------|
| Degree | Hubs with many direct connections | First-pass C2 server / hosting node identification |
| Betweenness | Bridge/pivot nodes between clusters | Cross-campaign reuse, pivot investigation |
| PageRank | Recursively important nodes | Campaign core infrastructure |
| Eigenvector | Deeply embedded cluster nodes | Identifying infrastructure generations |

**Operational rule of thumb:** A node that ranks in the top 5 across all four measures is almost certainly **operationally significant** — it is a hub, a bridge, recursively important, and embedded in the dense core. That node deserves immediate manual investigation.

---

## Community Detection

Community detection algorithms partition a graph into clusters where nodes are more densely connected to each other than to the rest of the graph. For threat intelligence, communities map to **campaigns, infrastructure generations, or actor sub-teams**.

### Modularity Score

Modularity `Q` measures partition quality:

```
Q = (edges within communities) / (total edges) - (expected edges within communities by chance)
```

| Modularity Score | Interpretation |
|-----------------|----------------|
| < 0.2 | No meaningful community structure |
| 0.2 – 0.4 | Weak communities |
| 0.4 – 0.7 | Strong communities — likely meaningful campaigns |
| > 0.7 | Very strong communities — distinct, well-separated infrastructure |

A modularity above 0.4 with 2-4 communities typically indicates **distinct campaign infrastructure** that shares only a few bridge nodes. This is the pattern you expect when a prolific actor runs simultaneous campaigns with deliberate operational separation.

### Louvain Algorithm

Louvain is a hierarchical agglomerative algorithm that optimizes modularity at each pass. It is the standard for large-scale community detection and is available via `python-louvain`:

```bash
pip install python-louvain
```

```python
import community as community_louvain

partition = community_louvain.best_partition(G)
# partition: {node_id: community_id}

modularity = community_louvain.modularity(partition, G)
```

Louvain is **non-deterministic** — results vary slightly between runs. For reproducible analysis, use `random_state` if your version supports it, or run multiple times and compare.

### Greedy Modularity (NetworkX built-in)

If `python-louvain` is unavailable, NetworkX includes greedy modularity communities:

```python
from networkx.algorithms.community import greedy_modularity_communities

communities = list(greedy_modularity_communities(G))
# communities: list of frozensets
```

Greedy modularity is deterministic but produces slightly lower modularity scores than Louvain on sparse graphs.

### Interpreting Communities in Threat Intel

**Hypothesis 1 — Temporal campaigns:** Each community represents a different operational period. The actor reuses infrastructure components (same ASN, same registrar) but deploys fresh IPs and domains per campaign. Bridge nodes are shared utilities — VPN endpoints, shared tooling servers.

**Hypothesis 2 — Functional separation:** Communities reflect functional roles — one cluster is C2 beaconing, another is phishing credential harvesting, another is exfiltration staging. Bridge nodes are the actor's operational machines that touch multiple functions.

**Hypothesis 3 — Actor sub-teams:** In APT operations, different operators may manage different infrastructure clusters. Bridge nodes represent shared resources (bulletproof hosters, common tooling). High modularity across many small communities suggests **compartmentalization by design**.

Use community detection results as a **hypothesis generator**, not a conclusion. Always verify community membership with timeline analysis (when were these nodes active?) and behavioral analysis (what were these nodes doing?).

---

## Neo4j Integration Guide

Neo4j is a native property graph database with a powerful declarative query language called Cypher. It scales to billions of nodes and is the industry standard for threat intelligence graph analysis.

### Data Model Design

Design your Neo4j schema around the node types and edge types defined above. The key principle: **use MERGE, not CREATE**. IOC data arrives from multiple pipelines — the same IP will be ingested from passive DNS, Shodan, and your own JARM scanner. MERGE is idempotent; CREATE produces duplicates.

```cypher
// Create or update an IP node
MERGE (ip:IP {value: '185.220.101.1'})
ON CREATE SET ip.first_seen = datetime()
ON MATCH  SET ip.last_seen  = datetime();

// Create or update a domain node
MERGE (d:Domain {value: 'c2panel.xyz'})
ON CREATE SET d.first_seen = datetime();

// Create the RESOLVES_TO relationship
MATCH (d:Domain {value: 'c2panel.xyz'}), (ip:IP {value: '185.220.101.1'})
MERGE (d)-[:RESOLVES_TO]->(ip);
```

### Index Optimization

Index the `value` property on every node type. Without indexes, every MATCH query performs a full table scan:

```cypher
CREATE INDEX FOR (n:IP)     ON (n.value);
CREATE INDEX FOR (n:Domain) ON (n.value);
CREATE INDEX FOR (n:ASN)    ON (n.value);
CREATE INDEX FOR (n:SSHKey) ON (n.value);
CREATE INDEX FOR (n:Email)  ON (n.value);
```

Run these once at database initialization. Check index status with `SHOW INDEXES`.

### Cypher Query Patterns

**Find all IPs on a specific ASN:**

```cypher
MATCH (ip:IP)-[:HOSTED_ON]->(asn:ASN)
WHERE asn.value = 'AS20473'
RETURN ip.value, count(*) AS ip_count
ORDER BY ip_count DESC;
```

**Find all domains resolving to IPs on the same ASN:**

```cypher
MATCH (ip:IP)-[:HOSTED_ON]->(asn:ASN {value: 'AS20473'})
MATCH (d:Domain)-[:RESOLVES_TO]->(ip)
RETURN asn.value, ip.value, collect(d.value) AS domains;
```

**Shortest path between two IOCs — the attribution bridge query:**

```cypher
MATCH p = shortestPath(
  (a:IP {value: '185.220.101.1'})-[*]-(b:IP {value: '167.99.55.10'})
)
RETURN p;
```

**Find all nodes sharing an SSH host key — Module 0x03 correlation in Neo4j:**

```cypher
MATCH (n)-[:SIGNED_WITH]->(k:SSHKey)
RETURN k.value AS ssh_key, collect(n.value) AS infrastructure
ORDER BY size(collect(n.value)) DESC;
```

**Find registrant email reuse across campaigns:**

```cypher
MATCH (d:Domain)-[:REGISTERED_BY]->(e:Email)
RETURN e.value AS registrant, count(d) AS domain_count,
       collect(d.value) AS domains
ORDER BY domain_count DESC;
```

**Detect C2 pattern — IP with JARM fingerprint hosting multiple domains:**

```cypher
MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IP)-[:HAS_JARM]->(j:JARM)
WHERE j.value = 'jarm:07d14d16d21d21d'
RETURN ip.value, j.value, collect(d.value) AS domains,
       count(d) AS hosted_domain_count
ORDER BY hosted_domain_count DESC;
```

**Find all-paths between a known malicious IP and an unknown IP:**

```cypher
MATCH p = allShortestPaths(
  (a:IP {value: '185.220.101.1'})-[*..5]-(b:IP {value: '10.20.30.40'})
)
RETURN p;
```

### Running Neo4j Locally

```bash
# Docker (fastest setup)
docker run \
  --publish=7474:7474 --publish=7687:7687 \
  --env=NEO4J_AUTH=none \
  neo4j:community

# Or via Neo4j Desktop (GUI)
# https://neo4j.com/download/

# Import a Cypher file generated by graph_builder.py
cypher-shell -u neo4j -p password -f import.cypher
```

Access Neo4j Browser at `http://localhost:7474` after startup.

---

## Interactive Visualization

Different audiences require different visualization approaches. Choose the right tool for the context.

### pyvis — HTML Interactive Graphs

pyvis wraps vis.js and produces self-contained HTML files. The output is shareable with any analyst who has a browser — no software installation required.

```python
from pyvis.network import Network

net = Network(height="750px", width="100%", bgcolor="#1a1a2e", font_color="white")
net.barnes_hut(spring_strength=0.04)

for node in G.nodes():
    net.add_node(node, label=node, color="#e74c3c", size=15)

for src, dst in G.edges():
    net.add_edge(src, dst, color="#555555")

net.show("graph.html")
```

**Best for:** Analyst briefings, sharing with non-technical stakeholders, quick exploration of small-to-medium graphs (<2,000 nodes).

**Limitation:** Performance degrades above ~5,000 nodes. Use Gephi for large graphs.

### Gephi — Large-Scale Graph Visualization

Gephi is a desktop application for graph visualization and analysis. It handles millions of nodes and supports layout algorithms (ForceAtlas2, Fruchterman-Reingold, Yifan Hu) that produce publication-quality images.

Export GEXF from the capstone script (`--gexf graph.gexf`), then in Gephi:

1. File → Open → select the `.gexf` file
2. Layout panel → select ForceAtlas2 → Run
3. Appearance panel → Nodes → Partition → select `community` attribute → Apply
4. Preview panel → adjust settings → Export SVG/PDF

**Best for:** Large graphs (>1,000 nodes), publication-quality images, presentations, timeline analysis with the Gephi Timeline plugin.

### Matplotlib — Static PNG Output

The capstone script generates PNG output via matplotlib. This is the zero-dependency option — suitable for automated pipeline output, report embedding, and headless server environments.

Node size is proportional to degree (larger = more connections). Node color represents community membership. Edge labels are omitted for readability at scale.

### Choosing the Right Tool

| Audience / Context | Tool |
|---------------------|------|
| Python pipeline / automated reports | matplotlib PNG |
| Analyst briefing / sharing | pyvis HTML |
| Large graph (>1,000 nodes) | Gephi |
| Neo4j Browser | Native Neo4j visualization |
| Lightweight graph editing | yEd |

---

## Tool References

### NetworkX

Python-native graph analysis library. Ships with every scientific Python environment.

```bash
pip install networkx
```

Key capabilities: graph construction, centrality analysis, community detection (greedy modularity built-in), GEXF/GraphML/GML import/export, graph algorithms (shortest path, connected components, isomorphism).

### Neo4j Community Edition

Open-source graph database. Free for single-instance use. Available at [https://neo4j.com/download/](https://neo4j.com/download/).

Key capabilities: property graph storage, Cypher query language, APOC procedures library (advanced graph algorithms), Bloom graph visualization, GDS (Graph Data Science) library for centrality/community detection at scale.

### Maltego

Commercial OSINT and link analysis platform. Transforms connect to external data sources (Shodan, VirusTotal, Censys, WHOIS) and pull structured data directly into the graph. Free Community Edition is available with limited transform calls.

Key capabilities: infrastructure pivoting via transforms, automated enrichment, MISP/OpenCTI integration, graph export to common formats.

**Workflow for threat infrastructure mapping:**
1. Start with a known C2 IP entity
2. Run "To DNS (passive)" transform → expands to historical domains
3. Run "To Shodan" → expands to SSH keys, TLS certs, open ports
4. Run "To WHOIS registrant" → expands to email, registrar
5. Iteratively expand until the cluster boundary is found

### Gephi

Open-source graph visualization and analysis. Available at [https://gephi.org/](https://gephi.org/).

Key capabilities: ForceAtlas2/Fruchterman-Reingold layouts, partition-based coloring, temporal graph analysis, modularity-based community detection, SVG/PDF export.

### yEd Graph Editor

Free desktop graph editor from yWorks. Lightweight alternative to Gephi for smaller graphs. Supports automatic layouts and is useful for manually constructed graphs or diagrams.

Available at [https://www.yworks.com/products/yed](https://www.yworks.com/products/yed).

### pyvis

Python wrapper for vis.js that produces interactive HTML graphs.

```bash
pip install pyvis
```

Supports physics-based layout (Barnes-Hut, repulsion), edge labels, node hover tooltips, and graph manipulation in the browser.

---

## Case Study: Building an Actor Infrastructure Graph from Modules 0x01–0x03

This walkthrough demonstrates integrating outputs from the first three modules into a unified graph that reveals campaign attribution.

### Step 1 — Collect JARM fingerprints (Module 0x01)

Run the JARM scanner against a CIDR range associated with a suspicious ASN. Output: a CSV mapping IPs to JARM fingerprints.

```
IP,JARM
185.220.101.1,07d14d16d21d21d...
185.220.101.2,07d14d16d21d21d...
185.220.101.5,00000000000000...
```

Two IPs share the same JARM fingerprint — they are running identical TLS stacks. This is the first clustering signal.

### Step 2 — Collect CT log domains (Module 0x02)

Query crt.sh for certificates issued to the suspicious ASN's IP range. Output: domains with their associated IPs and certificate fingerprints.

```
Domain,IP,Certificate
update-service.net,185.220.101.1,sha256:aabbcc...
cdn-delivery.org,185.220.101.2,sha256:aabbcc...
patch-manager.io,185.220.101.1,sha256:ddeeff...
```

Two domains share the same certificate — issued at the same time, likely from the same operator. `update-service.net` and `patch-manager.io` both resolve to the same IP, confirming co-location.

### Step 3 — Collect SSH host keys (Module 0x03)

Run the SSH key overlap scanner against the same IP range. Output: IPs sharing SSH host keys.

```
IP,SSHKey
185.220.101.1,ssh-key:aa11bb22
185.220.101.2,ssh-key:aa11bb22
45.77.33.100,ssh-key:aa11bb22
```

A third IP (`45.77.33.100`) shares the same SSH host key — it was provisioned from the same base image or cloned from one of the existing servers. This is a **pivot point**: an IP not in the original ASN scan that is provably linked to the cluster.

### Step 4 — Build the graph

Convert all three outputs to the CSV format expected by `graph_builder.py`:

```csv
source_type,source_value,relationship,target_type,target_value
IP,185.220.101.1,HAS_JARM,JARM,07d14d16d21d21d
IP,185.220.101.2,HAS_JARM,JARM,07d14d16d21d21d
Domain,update-service.net,RESOLVES_TO,IP,185.220.101.1
Domain,cdn-delivery.org,RESOLVES_TO,IP,185.220.101.2
Domain,update-service.net,ISSUED_BY,Certificate,sha256:aabbcc
Domain,cdn-delivery.org,ISSUED_BY,Certificate,sha256:aabbcc
IP,185.220.101.1,SIGNED_WITH,SSHKey,ssh-key:aa11bb22
IP,45.77.33.100,SIGNED_WITH,SSHKey,ssh-key:aa11bb22
```

```bash
python graph_builder.py -f combined_iocs.csv \
  --graph campaign_graph.png \
  --cypher campaign.cypher \
  --gexf campaign.gexf
```

### Step 5 — Analyze centrality

Betweenness centrality immediately highlights `ssh-key:aa11bb22` — it sits on the shortest path between the known C2 IPs and the pivot IP `45.77.33.100`. This is the analytical confirmation that `45.77.33.100` belongs to the same actor cluster.

Degree centrality highlights `185.220.101.1` — hosting two domains, sharing the SSH key, and having the JARM fingerprint. This is the **primary C2 server** for this infrastructure generation.

### Step 6 — Import to Neo4j and expand

Import the generated Cypher file into Neo4j, then run expansion queries:

```cypher
// Who else registered domains with the same registrant email?
MATCH (d:Domain)-[:REGISTERED_BY]->(e:Email)
WHERE d.value IN ['update-service.net', 'cdn-delivery.org']
MATCH (d2:Domain)-[:REGISTERED_BY]->(e)
WHERE d2.value <> d.value
RETURN e.value AS registrant, collect(DISTINCT d2.value) AS related_domains;
```

This query pivots from known domains to the registrant email, then expands to all domains registered by the same email — potentially exposing campaign infrastructure across multiple operations.

### Step 7 — Community detection reveals campaign generations

Run community detection on the expanded graph. If the modularity score is above 0.4 with two or more distinct communities, you are looking at **multiple campaigns or infrastructure generations** sharing a small number of bridge nodes. Those bridge nodes — often a bulletproof hoster's ASN or a shared registrant email — are the attribution anchors.

---

## OPSEC Note

Graph databases can contain some of the most sensitive intelligence your team produces. A graph that links a real-world registrant email to a cluster of C2 infrastructure, or reveals the pivot chain between two separate campaigns, must be protected accordingly.

- **Never expose Neo4j instances to the public internet.** The default Neo4j configuration listens on all interfaces. Bind to localhost or a VPN-only interface with `dbms.default_listen_address=127.0.0.1` in `neo4j.conf`.
- **Enable authentication.** Disable `NEO4J_AUTH=none` in production. Use strong credentials and rotate them.
- **Control access to exported files.** GEXF and Cypher files contain your raw intelligence. Apply the same handling policy as raw IOC reports.
- **Classify graph output.** Interactive HTML graphs generated by pyvis are self-contained and shareable — which is a feature and a risk. Apply TLP markings to shared graphs. Treat a graph that links OPSEC-sensitive IOCs as TLP:AMBER or higher.
- **Sanitize before briefing.** Remove real victim data before sharing graphs with external parties. Replace node values with anonymized labels where necessary.

For detailed OPSEC guidance on conducting research without exposing your analyst infrastructure, see Module 0x09.

---

## Module Project: Advanced Graph-Based Infrastructure Hunter

**Reference project:** `projects/0x07_graph_builder/graph_builder.py`

### Capabilities

The capstone project extends the original boilerplate with:

- **CSV file input** (`-f data.csv`) — reads structured IOC edge data
- **Four centrality measures** — degree, betweenness, PageRank, eigenvector with ranked comparison output
- **Community detection** — Louvain (if available) or greedy modularity, with modularity score
- **Neo4j Cypher export** (`--cypher import.cypher`) — MERGE-based import file, no live Neo4j required
- **GEXF export** (`--gexf graph.gexf`) — Gephi-compatible with community attributes
- **pyvis HTML output** (`--html graph.html`) — interactive browser visualization
- **JSON output mode** (`--format json`) — machine-parseable results for pipeline integration
- **Cluster summary** — community count, nodes per community, bridge nodes, hub nodes
- **Mock dataset** — 25-node, 3-community realistic scenario when run without arguments

### Running the Project

```bash
# Basic run — mock dataset, text output
python projects/0x07_graph_builder/graph_builder.py

# Load real IOC data
python projects/0x07_graph_builder/graph_builder.py -f my_iocs.csv

# Full export pipeline
python projects/0x07_graph_builder/graph_builder.py \
  -f my_iocs.csv \
  --graph campaign.png \
  --html campaign.html \
  --cypher neo4j_import.cypher \
  --gexf gephi_export.gexf \
  --top 10

# JSON output for pipeline integration
python projects/0x07_graph_builder/graph_builder.py --format json | jq '.summary'
```

### CSV Input Format

```csv
source_type,source_value,relationship,target_type,target_value
IP,185.220.101.1,RESOLVES_TO,Domain,c2panel.xyz
Domain,c2panel.xyz,ISSUED_BY,Certificate,sha256:aabbcc
IP,185.220.101.1,SIGNED_WITH,SSHKey,ssh-key:aa11bb22
IP,185.220.101.1,HOSTED_ON,ASN,AS20473
Domain,c2panel.xyz,REGISTERED_BY,Email,attacker@proton.me
```

### Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `networkx` | Yes | Graph construction and analysis |
| `matplotlib` | Optional | PNG visualization |
| `pyvis` | Optional | Interactive HTML output |
| `python-louvain` | Optional | Higher-quality community detection |

```bash
pip install networkx matplotlib pyvis python-louvain
```

The script degrades gracefully — running without optional packages produces text output and skips the unavailable export formats.

### Original Boilerplate

```python
#!/usr/bin/env python3
# Module 0x07 Capstone Project: Graphical Neo4j Builder Template
# Fully Working Reference Solution

import networkx as nx
import matplotlib.pyplot as plt

def build_cluster_graph(csv_data: list) -> nx.Graph:
    """
    Takes flat IOC arrays and maps them into a relationship node map.
    Centrality analysis will instantly reveal the primary hosting provider (ASN) or Drop Server.
    """
    G = nx.Graph()

    for row in csv_data:
        ip, domain, asn, jarm_hash = row.split(',')

        # Add the physical threat entities as Nodes, categorized by type
        G.add_node(ip, type='IP', color='red')
        G.add_node(domain, type='Domain', color='orange')
        G.add_node(asn, type='ASN', color='blue')
        G.add_node(jarm_hash, type='JARM', color='purple')

        # Link the relationships mathematically
        G.add_edge(domain, ip)
        G.add_edge(ip, asn)
        G.add_edge(ip, jarm_hash)

    return G

def analyze_graph(G: nx.Graph):
    """
    Uses Data Science algorithms to find the most "important" node in the adversary network.
    """
    print("\n--- NetworkX Degree Centrality ---")
    centrality = nx.degree_centrality(G)
    sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
    for node, score in sorted_nodes:
        node_type = G.nodes[node].get('type', 'Unknown')
        print(f"[{node_type}] {node:<20} | Score: {score:.3f}")

def visualize(G: nx.Graph):
    """Plots the graph visually using Matplotlib."""
    plt.figure(figsize=(10, 8))
    colors = [G.nodes[n].get('color', 'gray') for n in G.nodes()]
    pos = nx.spring_layout(G, seed=42, k=0.5)
    nx.draw(G, pos, with_labels=True, node_color=colors,
            node_size=2000, font_size=10, font_weight="bold", edge_color="gray")
    plt.title("Adversary Infrastructure Knowledge Graph", fontsize=15)
    output_file = "cluster_map.png"
    plt.savefig(output_file)
    print(f"\n[+] Saved visualization to: {output_file}")
    print("[*] Red=IP, Orange=Domain, Blue=ASN, Purple=JARM Hash")

if __name__ == "__main__":
    print("[*] Starting Graph Processor...")
    threat_intel_feed = [
        "192.168.1.1,malicious.com,AS20473,00000abcde",
        "192.168.1.2,phishing.net,AS20473,00000abcde",
        "10.0.0.1,benign.com,AS9999,ef56ghzzzz",
        "192.168.1.1,secondary.org,AS20473,00000abcde",
        "1.1.1.1,cloudflare.com,AS13335,0011223344"
    ]
    graph = build_cluster_graph(threat_intel_feed)
    print(f"[*] Graph generated with {graph.number_of_nodes()} Nodes and {graph.number_of_edges()} Edges.")
    analyze_graph(graph)
    visualize(graph)
```

**Takeaway:** The ability to visualize and identify clusters where multiple different campaigns share a single hosting provider or specific cryptographic fingerprint enables attribution that is impossible from flat IOC lists alone.
