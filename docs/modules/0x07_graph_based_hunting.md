# Module 0x07: Graph-Based Hunting

## Overview

Flat lists of IPs and domains are incredibly difficult to analyze for wide-scale threat actor operations. In this module, we introduce node-relationship mapping, Centrality analysis, and high-fidelity clustering to visually and programmatically chart adversary environments.

## Key Concepts
* **Node-Relationship Mapping**: Representing physical objects (IPs, Certificates, domains, files, ASNs) as interconnected dots in Neo4j.
* **Centrality Analysis**: Identifying the most critical nodes (e.g., the primary drop server that everything points to).
* **High-fidelity Clustering**: Distinguishing random internet overlaps from intentional adversary architecture.

---
## 🛠️ Module Project: Neo4j Data Pipeline for IP Correlation
*Reference: Data Engineering for Cybersecurity*

We will ingest flat IOCs (Indicators of Compromise) into a graph format using `networkx` or directly feeding Neo4j, exposing the hidden overlaps.

### The Objective
1. Setup a local Neo4j desktop or Docker instance.
2. Read a simplistic CSV of format: `IP, Domain, ASN, SSH_Key`.
3. Create a python generator that uses the `networkx` library to build the graphical relationships and display a central node.

### Boilerplate Setup
```python
# graph_builder.py
import networkx as nx
import matplotlib.pyplot as plt

def build_cluster(csv_data):
    # This represents 'IP,Domain,ASN,JARM'
    G = nx.Graph()
    
    for row in csv_data:
        ip, domain, asn, hash_val = row.split(',')
        G.add_node(ip, type='IP')
        G.add_node(domain, type='Domain')
        G.add_node(asn, type='ASN')
        G.add_node(hash_val, type='Hash')
        
        # Link them
        G.add_edge(domain, ip)
        G.add_edge(ip, asn)
        G.add_edge(ip, hash_val)
        
    return G

if __name__ == "__main__":
    mock_data = [
        "192.168.1.1,malicious.com,AS1234,ab12cd",
        "192.168.1.2,phishing.net,AS1234,ab12cd",
        "10.0.0.1,benign.com,AS9999,ef56gh"
    ]
    graph = build_cluster(mock_data)
    
    # Calculate degree centrality - which node is the most connected?
    centrality = nx.degree_centrality(graph)
    print(sorted(centrality.items(), key=lambda x: x[1], reverse=True))
    
    # Optional: Plot the graph
    nx.draw(graph, with_labels=True)
    plt.show()
```

**Takeaway:** The ability to visualize and identify clusters where multiple different campaigns share a single hosting provider or specific cryptographic fingerprint.
