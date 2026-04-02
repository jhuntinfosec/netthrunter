#!/usr/bin/env python3
"""
Module 0x07 Capstone Project: Advanced Graph-Based Infrastructure Hunter
========================================================================

Builds a threat intelligence property graph from CSV IOC data (or a built-in
mock dataset), computes multiple centrality measures, runs community detection,
and exports results in multiple formats: PNG, interactive HTML, Neo4j Cypher,
and Gephi GEXF.

@decision DEC-GRAPH-001
@title NetworkX as primary graph engine with optional pyvis / community
@status accepted
@rationale NetworkX ships with every Python environment that already has
  scikit-learn (core curriculum dependency). pyvis and python-louvain
  (community) are optional; graceful degradation keeps the script runnable
  in minimal environments. No live Neo4j connection is required — Cypher
  output is file-based so learners can experiment without a running instance.

Usage examples
--------------
  python graph_builder.py                        # mock dataset, text output
  python graph_builder.py -f iocs.csv            # load real data
  python graph_builder.py --graph out.png        # save PNG visualization
  python graph_builder.py --html graph.html      # interactive HTML (pyvis)
  python graph_builder.py --cypher import.cypher # Neo4j import file
  python graph_builder.py --gexf graph.gexf      # Gephi export
  python graph_builder.py --format json          # JSON report
  python graph_builder.py --top 10               # top-10 nodes per metric

CSV format (header row required)
---------------------------------
  source_type,source_value,relationship,target_type,target_value
  IP,185.220.101.1,RESOLVES_TO,Domain,c2panel.xyz
  Domain,c2panel.xyz,ISSUED_BY,Certificate,sha256:aabbcc...
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Required dependency
# ---------------------------------------------------------------------------
try:
    import networkx as nx
except ImportError:
    print("[!] networkx is required: pip install networkx", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Optional dependencies — degrade gracefully
# ---------------------------------------------------------------------------
try:
    import matplotlib
    matplotlib.use("Agg")  # headless — no display required
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    from pyvis.network import Network
    HAS_PYVIS = True
except ImportError:
    HAS_PYVIS = False

# Louvain community detection (python-louvain package installs as `community`)
try:
    import community as community_louvain
    HAS_LOUVAIN = True
except ImportError:
    HAS_LOUVAIN = False

# ---------------------------------------------------------------------------
# Node-type visual palette
# ---------------------------------------------------------------------------
NODE_COLORS = {
    "IP":          "#e74c3c",   # red
    "Domain":      "#e67e22",   # orange
    "ASN":         "#3498db",   # blue
    "Certificate": "#9b59b6",   # purple
    "SSHKey":      "#1abc9c",   # teal
    "Email":       "#f1c40f",   # yellow
    "Nameserver":  "#2ecc71",   # green
    "JARM":        "#e91e63",   # pink
    "Unknown":     "#95a5a6",   # gray
}

# ---------------------------------------------------------------------------
# Mock dataset — realistic APT-style infrastructure graph (3 clusters)
# ---------------------------------------------------------------------------

def build_mock_dataset() -> list[dict]:
    """
    Returns a list of edge-dicts representing a plausible adversary environment.

    Three communities are embedded:
      Cluster A — Cobalt Strike team servers (AS20473/Vultr)
      Cluster B — Phishing kit infrastructure (AS14061/DigitalOcean)
      Cluster C — Shared-key pivot nodes bridging A and B

    Cross-cluster edges are intentionally sparse so community detection
    correctly separates the campaigns, while bridge nodes surface in
    betweenness centrality analysis.
    """
    return [
        # ----- Cluster A: Cobalt Strike beaconing infrastructure -----
        {"source_type": "Domain",      "source_value": "update-service.net",     "relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "185.220.101.1"},
        {"source_type": "Domain",      "source_value": "cdn-delivery.org",       "relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "185.220.101.2"},
        {"source_type": "Domain",      "source_value": "patch-manager.io",       "relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "185.220.101.1"},
        {"source_type": "IP",          "source_value": "185.220.101.1",          "relationship": "HOSTED_ON",    "target_type": "ASN",   "target_value": "AS20473"},
        {"source_type": "IP",          "source_value": "185.220.101.2",          "relationship": "HOSTED_ON",    "target_type": "ASN",   "target_value": "AS20473"},
        {"source_type": "IP",          "source_value": "185.220.101.1",          "relationship": "SIGNED_WITH",  "target_type": "SSHKey","target_value": "ssh-key:aa11bb22"},
        {"source_type": "IP",          "source_value": "185.220.101.2",          "relationship": "SIGNED_WITH",  "target_type": "SSHKey","target_value": "ssh-key:aa11bb22"},
        {"source_type": "Domain",      "source_value": "update-service.net",     "relationship": "ISSUED_BY",    "target_type": "Certificate", "target_value": "cert:vultr-tls-01"},
        {"source_type": "Domain",      "source_value": "cdn-delivery.org",       "relationship": "ISSUED_BY",    "target_type": "Certificate", "target_value": "cert:vultr-tls-01"},
        # JARM fingerprints tie the Cobalt Strike servers together
        {"source_type": "IP",          "source_value": "185.220.101.1",          "relationship": "HAS_JARM",     "target_type": "JARM",  "target_value": "jarm:07d14d16d21d21d"},
        {"source_type": "IP",          "source_value": "185.220.101.2",          "relationship": "HAS_JARM",     "target_type": "JARM",  "target_value": "jarm:07d14d16d21d21d"},

        # ----- Cluster B: Phishing infrastructure -----
        {"source_type": "Domain",      "source_value": "secure-login-verify.com","relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "167.99.55.10"},
        {"source_type": "Domain",      "source_value": "account-confirm.biz",    "relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "167.99.55.11"},
        {"source_type": "Domain",      "source_value": "verify-identity.info",   "relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "167.99.55.10"},
        {"source_type": "IP",          "source_value": "167.99.55.10",           "relationship": "HOSTED_ON",    "target_type": "ASN",   "target_value": "AS14061"},
        {"source_type": "IP",          "source_value": "167.99.55.11",           "relationship": "HOSTED_ON",    "target_type": "ASN",   "target_value": "AS14061"},
        {"source_type": "Domain",      "source_value": "secure-login-verify.com","relationship": "REGISTERED_BY","target_type": "Email", "target_value": "reg@protonmail.com"},
        {"source_type": "Domain",      "source_value": "account-confirm.biz",    "relationship": "REGISTERED_BY","target_type": "Email", "target_value": "reg@protonmail.com"},
        {"source_type": "Domain",      "source_value": "secure-login-verify.com","relationship": "USES_NS",      "target_type": "Nameserver","target_value": "ns1.hostinger.com"},
        {"source_type": "Domain",      "source_value": "verify-identity.info",   "relationship": "USES_NS",      "target_type": "Nameserver","target_value": "ns1.hostinger.com"},

        # ----- Cluster C: Bridge / pivot infrastructure (cross-cluster) -----
        # This IP shares the SSH key with Cluster A but ASN with Cluster B
        # — classic infrastructure reuse signal
        {"source_type": "IP",          "source_value": "45.77.33.100",           "relationship": "SIGNED_WITH",  "target_type": "SSHKey","target_value": "ssh-key:aa11bb22"},
        {"source_type": "IP",          "source_value": "45.77.33.100",           "relationship": "HOSTED_ON",    "target_type": "ASN",   "target_value": "AS20473"},
        {"source_type": "Domain",      "source_value": "bridge-node-alpha.net",  "relationship": "RESOLVES_TO",  "target_type": "IP",    "target_value": "45.77.33.100"},
        {"source_type": "Domain",      "source_value": "bridge-node-alpha.net",  "relationship": "REGISTERED_BY","target_type": "Email", "target_value": "reg@protonmail.com"},
        # Shared certificate ties bridge to phishing cluster
        {"source_type": "IP",          "source_value": "45.77.33.100",           "relationship": "ISSUED_BY",    "target_type": "Certificate","target_value": "cert:lets-encrypt-99"},
        {"source_type": "IP",          "source_value": "167.99.55.10",           "relationship": "ISSUED_BY",    "target_type": "Certificate","target_value": "cert:lets-encrypt-99"},
    ]


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph(edges: list[dict]) -> nx.Graph:
    """
    Constructs a NetworkX undirected property graph from a list of edge dicts.

    Each dict must have keys: source_type, source_value, relationship,
    target_type, target_value.

    Node attributes stored: type, color.
    Edge attributes stored: relationship.
    """
    G = nx.Graph()
    for edge in edges:
        src = edge["source_value"].strip()
        dst = edge["target_value"].strip()
        src_type = edge["source_type"].strip()
        dst_type = edge["target_type"].strip()
        rel = edge["relationship"].strip()

        G.add_node(src, type=src_type, color=NODE_COLORS.get(src_type, NODE_COLORS["Unknown"]))
        G.add_node(dst, type=dst_type, color=NODE_COLORS.get(dst_type, NODE_COLORS["Unknown"]))
        G.add_edge(src, dst, relationship=rel)

    return G


def load_csv(filepath: str) -> list[dict]:
    """
    Reads IOC edges from a CSV file. Expected header:
      source_type,source_value,relationship,target_type,target_value
    """
    edges = []
    path = Path(filepath)
    if not path.exists():
        print(f"[!] CSV file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        required = {"source_type", "source_value", "relationship", "target_type", "target_value"}
        if not required.issubset(set(reader.fieldnames or [])):
            print(f"[!] CSV must have columns: {', '.join(sorted(required))}", file=sys.stderr)
            sys.exit(1)
        for row in reader:
            edges.append(row)

    return edges


# ---------------------------------------------------------------------------
# Centrality analysis
# ---------------------------------------------------------------------------

def compute_centrality(G: nx.Graph, top_n: int = 5) -> dict:
    """
    Computes degree, betweenness, PageRank, and eigenvector centrality.

    Returns a dict keyed by measure name, each value being a sorted list of
    (node, score) tuples (descending).

    @decision DEC-GRAPH-002
    @title Eigenvector centrality with fallback to degree on convergence failure
    @status accepted
    @rationale nx.eigenvector_centrality raises PowerIterationFailedConvergence
      on disconnected or poorly conditioned graphs. Falling back to degree
      centrality preserves usability while signalling the issue to the learner.
    """
    results = {}

    # Degree centrality — who has the most direct connections?
    deg = nx.degree_centrality(G)
    results["degree"] = sorted(deg.items(), key=lambda x: x[1], reverse=True)[:top_n]

    # Betweenness centrality — which nodes are bridge/pivot points?
    bet = nx.betweenness_centrality(G)
    results["betweenness"] = sorted(bet.items(), key=lambda x: x[1], reverse=True)[:top_n]

    # PageRank — recursive importance (connected-to-important = important)
    pr = nx.pagerank(G)
    results["pagerank"] = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:top_n]

    # Eigenvector centrality — influence via neighbor influence
    try:
        ev = nx.eigenvector_centrality(G, max_iter=1000)
    except nx.PowerIterationFailedConvergence:
        print("[!] Eigenvector centrality did not converge; using degree as proxy.", file=sys.stderr)
        ev = nx.degree_centrality(G)
    results["eigenvector"] = sorted(ev.items(), key=lambda x: x[1], reverse=True)[:top_n]

    return results


def print_centrality_report(G: nx.Graph, centrality: dict) -> None:
    """Renders a human-readable centrality comparison to stdout."""
    labels = {
        "degree":      ("Degree Centrality",      "Hub identification — nodes with most direct connections (potential C2 servers)"),
        "betweenness": ("Betweenness Centrality",  "Bridge/pivot nodes — infrastructure connecting separate clusters"),
        "pagerank":    ("PageRank",                "Recursive importance — nodes linked to important nodes score higher"),
        "eigenvector": ("Eigenvector Centrality",  "Influence score — weighted by quality of neighbors"),
    }

    for key, (title, description) in labels.items():
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"  {description}")
        print(f"{'='*60}")
        for node, score in centrality[key]:
            node_type = G.nodes[node].get("type", "Unknown")
            print(f"  [{node_type:<12}] {node:<35} | {score:.5f}")


# ---------------------------------------------------------------------------
# Community detection
# ---------------------------------------------------------------------------

def detect_communities(G: nx.Graph) -> tuple[dict, float]:
    """
    Assigns each node a community ID. Returns (node->community dict, modularity).

    Prefers Louvain algorithm (python-louvain) for quality; falls back to
    NetworkX greedy modularity communities which is always available.

    @decision DEC-GRAPH-003
    @title Louvain preferred, greedy modularity as fallback
    @status accepted
    @rationale Louvain produces higher modularity scores on sparse threat intel
      graphs. Greedy modularity is deterministic and ships with NetworkX —
      important for reproducible curriculum exercises.
    """
    if HAS_LOUVAIN:
        partition = community_louvain.best_partition(G)
        modularity = community_louvain.modularity(partition, G)
        return partition, modularity
    else:
        communities = list(nx.algorithms.community.greedy_modularity_communities(G))
        partition = {}
        for comm_id, nodes in enumerate(communities):
            for node in nodes:
                partition[node] = comm_id
        modularity = nx.algorithms.community.modularity(G, communities)
        return partition, modularity


def print_community_report(G: nx.Graph, partition: dict, modularity: float) -> None:
    """Renders community membership and cluster statistics to stdout."""
    community_groups: dict[int, list] = defaultdict(list)
    for node, comm_id in partition.items():
        community_groups[comm_id].append(node)

    print(f"\n{'='*60}")
    print(f"  Community Detection Results")
    print(f"  Modularity score: {modularity:.4f}  (>0.3 = meaningful separation)")
    print(f"  Communities found: {len(community_groups)}")
    print(f"{'='*60}")

    for comm_id in sorted(community_groups):
        members = community_groups[comm_id]
        types = defaultdict(list)
        for node in members:
            types[G.nodes[node].get("type", "Unknown")].append(node)

        print(f"\n  Cluster {comm_id}  ({len(members)} nodes)")
        for type_name, nodes in sorted(types.items()):
            print(f"    {type_name:<14}: {', '.join(nodes)}")


def cluster_summary(G: nx.Graph, partition: dict, centrality: dict, top_n: int = 3) -> dict:
    """
    Returns a structured summary dict with bridge nodes, hub nodes, and
    per-community statistics — suitable for JSON export.
    """
    community_groups: dict[int, list] = defaultdict(list)
    for node, comm_id in partition.items():
        community_groups[comm_id].append(node)

    bridge_nodes = [node for node, _ in centrality["betweenness"][:top_n]]
    hub_nodes    = [node for node, _ in centrality["degree"][:top_n]]

    return {
        "node_count":  G.number_of_nodes(),
        "edge_count":  G.number_of_edges(),
        "communities": len(community_groups),
        "nodes_per_community": {str(k): len(v) for k, v in community_groups.items()},
        "bridge_nodes": bridge_nodes,
        "hub_nodes":    hub_nodes,
    }


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def visualize_png(G: nx.Graph, partition: dict, output_path: str) -> None:
    """
    Renders the graph to a PNG. Nodes are colored by community membership.
    Requires matplotlib.
    """
    if not HAS_MATPLOTLIB:
        print("[!] matplotlib not installed; skipping PNG output. pip install matplotlib", file=sys.stderr)
        return

    # Build a community-color map
    n_communities = len(set(partition.values()))
    cmap = matplotlib.colormaps.get_cmap("Set2").resampled(n_communities)
    node_colors = [cmap(partition.get(n, 0)) for n in G.nodes()]

    # Node size proportional to degree
    degrees = dict(G.degree())
    max_deg = max(degrees.values()) if degrees else 1
    node_sizes = [300 + 2000 * (degrees[n] / max_deg) for n in G.nodes()]

    fig, ax = plt.subplots(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42, k=1.2)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.85, ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color="#cccccc", width=1.2, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=7, font_weight="bold", ax=ax)

    # Legend: node types
    type_seen = {}
    for node in G.nodes():
        t = G.nodes[node].get("type", "Unknown")
        if t not in type_seen:
            type_seen[t] = NODE_COLORS.get(t, NODE_COLORS["Unknown"])
    patches = [mpatches.Patch(color=c, label=t) for t, c in type_seen.items()]
    ax.legend(handles=patches, loc="upper left", fontsize=8)

    ax.set_title("Adversary Infrastructure Knowledge Graph\n(node size = degree; color = community)", fontsize=13)
    ax.axis("off")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"[+] PNG saved: {output_path}")


def visualize_html(G: nx.Graph, partition: dict, output_path: str) -> None:
    """
    Generates an interactive HTML graph using pyvis.
    Requires: pip install pyvis
    """
    if not HAS_PYVIS:
        print("[!] pyvis not installed; skipping HTML output. pip install pyvis", file=sys.stderr)
        return

    n_communities = len(set(partition.values()))
    # Simple palette for up to 8 communities
    palette = ["#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6",
               "#1abc9c", "#e67e22", "#e91e63"]

    net = Network(height="750px", width="100%", bgcolor="#1a1a2e", font_color="white")
    net.barnes_hut(spring_strength=0.04)

    for node in G.nodes():
        node_data = G.nodes[node]
        comm_id = partition.get(node, 0)
        color = palette[comm_id % len(palette)]
        title = f"Type: {node_data.get('type', 'Unknown')}<br>Community: {comm_id}"
        net.add_node(node, label=node, color=color, title=title,
                     size=10 + G.degree(node) * 5)

    for src, dst, data in G.edges(data=True):
        net.add_edge(src, dst, title=data.get("relationship", ""), color="#555555")

    net.show_buttons(filter_=["physics"])
    net.save_graph(output_path)
    print(f"[+] Interactive HTML saved: {output_path}")


# ---------------------------------------------------------------------------
# Export formats
# ---------------------------------------------------------------------------

def export_cypher(G: nx.Graph, output_path: str) -> None:
    """
    Writes a Neo4j Cypher import script (CREATE statements).

    The generated file can be pasted directly into Neo4j Browser or executed
    via cypher-shell:  cypher-shell -f import.cypher

    @decision DEC-GRAPH-004
    @title MERGE over CREATE for idempotent Neo4j imports
    @status accepted
    @rationale MERGE prevents duplicate nodes when the same IOC appears in
      multiple data pipelines — critical for incremental threat intel ingestion.
    """
    lines = [
        "// Neo4j Cypher import generated by graph_builder.py",
        "// Run with: cypher-shell -f import.cypher",
        "// Or paste into Neo4j Browser",
        "",
        "// ----- Nodes -----",
    ]
    for node in G.nodes():
        node_type = G.nodes[node].get("type", "Unknown")
        safe_val = node.replace("'", "\\'")
        lines.append(f"MERGE (n:{node_type} {{value: '{safe_val}'}});")

    lines += ["", "// ----- Relationships -----"]
    for src, dst, data in G.edges(data=True):
        rel = data.get("relationship", "RELATED_TO").replace(" ", "_").upper()
        src_type = G.nodes[src].get("type", "Unknown")
        dst_type = G.nodes[dst].get("type", "Unknown")
        safe_src = src.replace("'", "\\'")
        safe_dst = dst.replace("'", "\\'")
        lines.append(
            f"MATCH (a:{src_type} {{value: '{safe_src}'}}), (b:{dst_type} {{value: '{safe_dst}'}})"
        )
        lines.append(f"MERGE (a)-[:{rel}]->(b);")

    lines += [
        "",
        "// ----- Useful query patterns -----",
        "// Find all IPs on a given ASN:",
        "// MATCH (ip:IP)-[:HOSTED_ON]->(asn:ASN) WHERE asn.value = 'AS20473' RETURN ip, asn",
        "",
        "// Find shortest path between two IOCs:",
        "// MATCH p=shortestPath((a:IP {value:'185.220.101.1'})-[*]-(b:IP {value:'167.99.55.10'})) RETURN p",
        "",
        "// Discover all nodes sharing an SSH key:",
        "// MATCH (n)-[:SIGNED_WITH]->(k:SSHKey) RETURN k.value, collect(n.value) AS nodes",
        "",
        "// Find registrant email reuse across campaigns:",
        "// MATCH (d:Domain)-[:REGISTERED_BY]->(e:Email) RETURN e.value, count(d) AS domain_count ORDER BY domain_count DESC",
    ]

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Neo4j Cypher file saved: {output_path}")


def export_gexf(G: nx.Graph, partition: dict, output_path: str) -> None:
    """
    Exports the graph in GEXF format for Gephi.

    Community ID is stored as a node attribute so Gephi can apply
    partition-based coloring automatically.
    """
    G_export = G.copy()
    for node in G_export.nodes():
        G_export.nodes[node]["community"] = partition.get(node, 0)
        # GEXF color attributes must be stored as separate r/g/b integers
        hex_color = G_export.nodes[node].get("color", "#95a5a6").lstrip("#")
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
        G_export.nodes[node]["r"] = r
        G_export.nodes[node]["g"] = g
        G_export.nodes[node]["b"] = b

    nx.write_gexf(G_export, output_path)
    print(f"[+] GEXF (Gephi) file saved: {output_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Module 0x07: Graph-Based Adversary Infrastructure Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-f", "--file",   metavar="CSV",  help="IOC edge CSV file to load")
    parser.add_argument("--format",       choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--graph",        metavar="PATH", help="Save PNG visualization to PATH")
    parser.add_argument("--html",         metavar="PATH", help="Save interactive pyvis HTML to PATH")
    parser.add_argument("--cypher",       metavar="PATH", help="Save Neo4j Cypher import file to PATH")
    parser.add_argument("--gexf",         metavar="PATH", help="Save GEXF file for Gephi to PATH")
    parser.add_argument("--top",          metavar="N",    type=int, default=5, help="Top-N nodes per centrality metric (default: 5)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # ---- Data ingestion ----
    if args.file:
        edges = load_csv(args.file)
        print(f"[*] Loaded {len(edges)} edges from {args.file}")
    else:
        edges = build_mock_dataset()
        print("[*] No CSV provided — using built-in mock threat intel dataset")
        print("    (3 communities: Cobalt Strike C2, Phishing kit, Bridge/pivot nodes)")

    # ---- Graph construction ----
    G = build_graph(edges)
    print(f"[*] Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # ---- Analysis ----
    centrality = compute_centrality(G, top_n=args.top)
    partition, modularity = detect_communities(G)
    summary = cluster_summary(G, partition, centrality)

    # ---- Output ----
    if args.format == "json":
        output = {
            "summary": summary,
            "modularity": modularity,
            "centrality": {
                measure: [{"node": n, "score": s} for n, s in entries]
                for measure, entries in centrality.items()
            },
        }
        print(json.dumps(output, indent=2))
    else:
        print_centrality_report(G, centrality)
        print_community_report(G, partition, modularity)

        print(f"\n{'='*60}")
        print("  Cluster Summary")
        print(f"{'='*60}")
        print(f"  Nodes         : {summary['node_count']}")
        print(f"  Edges         : {summary['edge_count']}")
        print(f"  Communities   : {summary['communities']}")
        print(f"  Bridge nodes  : {', '.join(summary['bridge_nodes'])}")
        print(f"  Hub nodes     : {', '.join(summary['hub_nodes'])}")

    # ---- Export / visualization ----
    if args.graph:
        visualize_png(G, partition, args.graph)
    elif not args.file:
        # Auto-generate PNG in mock mode so there is always tangible output
        auto_png = "cluster_map.png"
        visualize_png(G, partition, auto_png)

    if args.html:
        visualize_html(G, partition, args.html)

    if args.cypher:
        export_cypher(G, args.cypher)

    if args.gexf:
        export_gexf(G, partition, args.gexf)


if __name__ == "__main__":
    main()
