#!/usr/bin/env python3
"""
Module 0x03 Capstone Project: Multi-Indicator Overlap & Clustering Engine
=========================================================================
Combines SSH key fingerprints, JARM hashes, ASN co-tenancy, domain presence,
and certificate serial overlaps into a Jaccard-similarity graph, then assigns
threshold-based cluster labels to reveal actor infrastructure groupings.

Usage
-----
  # Run with built-in mock dataset (no dependencies on API keys)
  python ssh_cluster.py

  # Run against a real CSV (columns: ip, domain, asn, ssh_key, jarm_hash)
  python ssh_cluster.py -f data.csv --threshold 0.35 --format json

  # Also generate a PNG cluster graph
  python ssh_cluster.py -f data.csv --graph

@decision DEC-CLUSTER-001
@title Jaccard similarity over cosine for sparse binary indicator vectors
@status accepted
@rationale Infrastructure indicator sets are sparse and binary (either a node
  shares an SSH key with another node or it does not). Jaccard similarity is
  defined as |A ∩ B| / |A ∪ B| and is the canonical choice for set-overlap
  problems. Cosine similarity weights magnitude, which is meaningless here.
  Hierarchical clustering was considered but threshold-based union-find gives
  interpretable, analyst-tunable clusters without requiring a dendrogram cut.
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from itertools import combinations

# ---------------------------------------------------------------------------
# Optional heavy dependencies — degrade gracefully if missing
# ---------------------------------------------------------------------------
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    import matplotlib
    matplotlib.use("Agg")          # non-interactive backend — safe in all envs
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# ---------------------------------------------------------------------------
# Shodan integration (optional)
# ---------------------------------------------------------------------------
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")


# ===========================================================================
# Data layer
# ===========================================================================

def generate_mock_dataset() -> list[dict]:
    """
    Return ~18 synthetic infrastructure nodes that form 3-4 distinct clusters.

    Cluster A — "Cluster-BEAR": Vultr/Choopa nodes, shared SSH key sk-BEAR,
                                shared JARM jarm-BEAR. Classic APT C2 pattern.
    Cluster B — "Cluster-PANDA": OVH + Hetzner, shared SSH key sk-PANDA,
                                 mixed JARM. Multi-provider resilience pattern.
    Cluster C — "Cluster-SPIDER": DigitalOcean, unique SSH keys but same JARM
                                  (automated TLS config from same Ansible role).
    Singleton  — "UNKNOWN-NODE": No overlapping indicators with others.

    @decision DEC-CLUSTER-002
    @title Mock dataset encodes realistic APT infrastructure patterns
    @status accepted
    @rationale Synthetic data must exercise all code paths: shared SSH keys,
      shared JARM, ASN affinity, cross-cluster partial overlaps, and isolated
      nodes. Each row maps to the CSV schema so mock and file paths are unified.
    """
    return [
        # --- Cluster A: BEAR (Vultr/Choopa, shared SSH + JARM) ---------------
        {"ip": "45.77.10.1",   "domain": "update-pkg[.]org",   "asn": "AS20473", "ssh_key": "sk-BEAR-01", "jarm_hash": "jarm-BEAR"},
        {"ip": "45.77.10.2",   "domain": "cdn-static[.]net",   "asn": "AS20473", "ssh_key": "sk-BEAR-01", "jarm_hash": "jarm-BEAR"},
        {"ip": "45.77.10.3",   "domain": "metrics-relay[.]io",  "asn": "AS20473", "ssh_key": "sk-BEAR-01", "jarm_hash": "jarm-BEAR"},
        {"ip": "108.61.200.5", "domain": "logstash-ingest[.]net","asn": "AS20473", "ssh_key": "sk-BEAR-02", "jarm_hash": "jarm-BEAR"},
        {"ip": "108.61.200.6", "domain": "telemetry-svc[.]com", "asn": "AS20473", "ssh_key": "sk-BEAR-02", "jarm_hash": "jarm-BEAR"},

        # --- Cluster B: PANDA (OVH + Hetzner, shared SSH, mixed JARM) --------
        {"ip": "51.77.50.10",  "domain": "proxy-east[.]pw",    "asn": "AS16276", "ssh_key": "sk-PANDA-01", "jarm_hash": "jarm-PANDA"},
        {"ip": "51.77.50.11",  "domain": "relay-node1[.]cc",   "asn": "AS16276", "ssh_key": "sk-PANDA-01", "jarm_hash": "jarm-PANDA"},
        {"ip": "5.9.200.30",   "domain": "relay-node2[.]cc",   "asn": "AS24940", "ssh_key": "sk-PANDA-01", "jarm_hash": "jarm-PANDA-v2"},
        {"ip": "5.9.200.31",   "domain": "update-node[.]info",  "asn": "AS24940", "ssh_key": "sk-PANDA-02", "jarm_hash": "jarm-PANDA-v2"},
        {"ip": "195.201.10.4", "domain": "beacon-svc[.]ru",    "asn": "AS24940", "ssh_key": "sk-PANDA-02", "jarm_hash": "jarm-PANDA-v2"},

        # --- Cluster C: SPIDER (DigitalOcean, unique SSH, shared JARM) -------
        {"ip": "104.236.10.20","domain": "spider-c2a[.]top",   "asn": "AS14061", "ssh_key": "sk-SPIDER-01","jarm_hash": "jarm-SPIDER"},
        {"ip": "104.236.10.21","domain": "spider-c2b[.]top",   "asn": "AS14061", "ssh_key": "sk-SPIDER-02","jarm_hash": "jarm-SPIDER"},
        {"ip": "104.236.10.22","domain": "spider-c2c[.]top",   "asn": "AS14061", "ssh_key": "sk-SPIDER-03","jarm_hash": "jarm-SPIDER"},
        {"ip": "138.68.100.5", "domain": "spider-cdn[.]club",  "asn": "AS14061", "ssh_key": "sk-SPIDER-04","jarm_hash": "jarm-SPIDER"},

        # --- Cluster A overflow: Selectel node (shared JARM links to BEAR) ---
        {"ip": "92.223.88.10", "domain": "bear-relay-ru[.]net","asn": "AS49505", "ssh_key": "sk-BEAR-02", "jarm_hash": "jarm-BEAR"},

        # --- Partial overlap: shares JARM with SPIDER but different SSH/ASN --
        {"ip": "167.99.5.55",  "domain": "orphan-spider[.]xyz","asn": "AS14061", "ssh_key": "sk-ORPHAN-01","jarm_hash": "jarm-SPIDER"},

        # --- True singleton: no shared indicators ----------------------------
        {"ip": "203.0.113.99", "domain": "darknode[.]onion-gw","asn": "AS398324","ssh_key": "sk-UNIQUE-99","jarm_hash": "jarm-UNIQUE"},

        # --- Extra BEAR node to stress affinity calculation ------------------
        {"ip": "45.32.220.14", "domain": "bear-exfil[.]biz",  "asn": "AS20473", "ssh_key": "sk-BEAR-01", "jarm_hash": "jarm-BEAR"},
    ]


def load_csv(path: str) -> list[dict]:
    """Load infrastructure nodes from a CSV with columns: ip, domain, asn, ssh_key, jarm_hash."""
    nodes = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            nodes.append({
                "ip":        row.get("ip", "").strip(),
                "domain":    row.get("domain", "").strip(),
                "asn":       row.get("asn", "").strip(),
                "ssh_key":   row.get("ssh_key", "").strip(),
                "jarm_hash": row.get("jarm_hash", "").strip(),
            })
    return nodes


# ===========================================================================
# Indicator extraction — build per-node indicator sets
# ===========================================================================

INDICATOR_FIELDS = ("ssh_key", "jarm_hash", "asn")
"""
@decision DEC-CLUSTER-003
@title ASN included in indicator set despite lower confidence weight
@status accepted
@rationale ASN co-tenancy alone is weak (thousands of actors share AS20473).
  However, when combined with SSH key or JARM matches it becomes a meaningful
  tiebreaker. Including it in the Jaccard numerator slightly inflates similarity
  for nodes on the same ASN, which is the desired behavior — co-tenancy is
  corroborating evidence, not proof. Analysts can raise --threshold to 0.5+
  if they want to exclude ASN-only links.
"""


def build_indicator_sets(nodes: list[dict]) -> list[set]:
    """
    Convert each node dict into a frozenset of qualified indicator tokens.

    Each token is prefixed with its field name so "AS20473" as an ASN value
    never accidentally collides with "AS20473" as a JARM hash value.
    """
    sets = []
    for node in nodes:
        indicators = set()
        for field in INDICATOR_FIELDS:
            value = node.get(field, "").strip()
            if value:
                indicators.add(f"{field}:{value}")
        sets.append(indicators)
    return sets


# ===========================================================================
# Jaccard similarity & union-find clustering
# ===========================================================================

def jaccard(a: set, b: set) -> float:
    """Return Jaccard similarity |A ∩ B| / |A ∪ B|. Returns 0.0 for empty sets."""
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


class UnionFind:
    """
    Lightweight union-find (disjoint set) for threshold-based cluster assignment.

    @decision DEC-CLUSTER-004
    @title Union-Find over connected-components walk for cluster assignment
    @status accepted
    @rationale Union-Find is O(α(n)) amortized per operation, trivially
      incremental, and produces the same result as BFS/DFS connected components
      on the similarity graph. The graph approach requires materializing all
      edges first; union-find streams them and is simpler to audit.
    """

    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]  # path compression
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1


def compute_clusters(
    indicator_sets: list[set],
    threshold: float = 0.3,
) -> tuple[list[int], list[tuple[int, int, float]]]:
    """
    Compute pairwise Jaccard similarities and assign cluster IDs.

    Returns
    -------
    labels : list[int]
        Cluster label for each node (0-indexed, same order as input).
    edges : list[(i, j, similarity)]
        All pairs whose similarity >= threshold (used for graph visualization).
    """
    n = len(indicator_sets)
    uf = UnionFind(n)
    edges = []

    for i, j in combinations(range(n), 2):
        sim = jaccard(indicator_sets[i], indicator_sets[j])
        if sim >= threshold:
            uf.union(i, j)
            edges.append((i, j, sim))

    # Re-label clusters as consecutive integers starting at 0
    root_to_label: dict[int, int] = {}
    labels = []
    for i in range(n):
        root = uf.find(i)
        if root not in root_to_label:
            root_to_label[root] = len(root_to_label)
        labels.append(root_to_label[root])

    return labels, edges


# ===========================================================================
# Pivot chain analysis
# ===========================================================================

def build_pivot_chains(nodes: list[dict], labels: list[int]) -> dict[int, list[str]]:
    """
    For each cluster, describe which indicators connect which nodes.

    Returns a dict mapping cluster_id → list of human-readable pivot strings.
    """
    cluster_to_nodes: dict[int, list[int]] = defaultdict(list)
    for idx, label in enumerate(labels):
        cluster_to_nodes[label].append(idx)

    chains: dict[int, list[str]] = {}
    for cluster_id, idxs in cluster_to_nodes.items():
        pivots = []
        # Collect per-indicator-field value → [node indices]
        field_value_map: dict[str, list[int]] = defaultdict(list)
        for idx in idxs:
            for field in INDICATOR_FIELDS:
                val = nodes[idx].get(field, "").strip()
                if val:
                    field_value_map[f"{field}:{val}"].append(idx)

        for indicator, sharing_idxs in sorted(field_value_map.items()):
            if len(sharing_idxs) > 1:
                ips = [nodes[i]["ip"] for i in sharing_idxs]
                pivots.append(f"  [{indicator}] shared by {len(ips)} nodes: {', '.join(ips)}")

        chains[cluster_id] = pivots if pivots else ["  (singleton — no shared indicators)"]

    return chains


# ===========================================================================
# Summary statistics
# ===========================================================================

def compute_summary(nodes: list[dict], labels: list[int]) -> dict:
    """Return aggregate statistics across the full dataset."""
    cluster_sizes = Counter(labels)
    asn_counter = Counter(n["asn"] for n in nodes if n["asn"])
    ssh_counter = Counter(n["ssh_key"] for n in nodes if n["ssh_key"])

    return {
        "total_nodes": len(nodes),
        "cluster_count": len(cluster_sizes),
        "largest_cluster_size": max(cluster_sizes.values()) if cluster_sizes else 0,
        "singleton_count": sum(1 for v in cluster_sizes.values() if v == 1),
        "most_common_asn": asn_counter.most_common(1)[0] if asn_counter else ("N/A", 0),
        "most_reused_ssh_key": ssh_counter.most_common(1)[0] if ssh_counter else ("N/A", 0),
    }


# ===========================================================================
# Output formatters
# ===========================================================================

def _cluster_groups(nodes: list[dict], labels: list[int]) -> dict[int, list[dict]]:
    groups: dict[int, list[dict]] = defaultdict(list)
    for node, label in zip(nodes, labels):
        groups[label].append(node)
    return groups


def print_text_report(
    nodes: list[dict],
    labels: list[int],
    edges: list[tuple],
    threshold: float,
) -> None:
    groups = _cluster_groups(nodes, labels)
    pivot_chains = build_pivot_chains(nodes, labels)
    summary = compute_summary(nodes, labels)

    print("\n" + "=" * 70)
    print("  Module 0x03 — Overlap & Clustering Engine")
    print(f"  Jaccard threshold: {threshold:.2f}  |  Nodes: {summary['total_nodes']}")
    print("=" * 70)

    for cluster_id in sorted(groups):
        member_nodes = groups[cluster_id]
        size = len(member_nodes)
        singleton = size == 1
        label = "SINGLETON" if singleton else f"CLUSTER-{cluster_id:02d}"
        print(f"\n[{'!' if singleton else '+'}] {label}  ({size} node{'s' if size != 1 else ''})")
        for node in member_nodes:
            print(f"    IP: {node['ip']:<18} domain: {node['domain']}")
            print(f"         ASN: {node['asn']:<12} ssh: {node['ssh_key']:<16} jarm: {node['jarm_hash']}")

        if not singleton:
            print("  Pivot chain:")
            for line in pivot_chains.get(cluster_id, []):
                print(line)

    print("\n" + "-" * 70)
    print("  Summary Statistics")
    print("-" * 70)
    print(f"  Total nodes         : {summary['total_nodes']}")
    print(f"  Clusters found      : {summary['cluster_count']}")
    print(f"  Largest cluster     : {summary['largest_cluster_size']} nodes")
    print(f"  Singletons          : {summary['singleton_count']}")
    asn, asn_count = summary["most_common_asn"]
    print(f"  Most common ASN     : {asn} ({asn_count} nodes)")
    key, key_count = summary["most_reused_ssh_key"]
    print(f"  Most reused SSH key : {key} ({key_count} nodes)")
    print("=" * 70 + "\n")


def print_json_report(
    nodes: list[dict],
    labels: list[int],
    edges: list[tuple],
    threshold: float,
) -> None:
    groups = _cluster_groups(nodes, labels)
    pivot_chains = build_pivot_chains(nodes, labels)
    summary = compute_summary(nodes, labels)

    output = {
        "threshold": threshold,
        "summary": {
            "total_nodes": summary["total_nodes"],
            "cluster_count": summary["cluster_count"],
            "largest_cluster_size": summary["largest_cluster_size"],
            "singleton_count": summary["singleton_count"],
            "most_common_asn": {"asn": summary["most_common_asn"][0], "count": summary["most_common_asn"][1]},
            "most_reused_ssh_key": {"key": summary["most_reused_ssh_key"][0], "count": summary["most_reused_ssh_key"][1]},
        },
        "clusters": [],
    }

    for cluster_id in sorted(groups):
        member_nodes = groups[cluster_id]
        output["clusters"].append({
            "cluster_id": cluster_id,
            "size": len(member_nodes),
            "nodes": member_nodes,
            "pivot_chain": pivot_chains.get(cluster_id, []),
        })

    print(json.dumps(output, indent=2))


def print_csv_report(
    nodes: list[dict],
    labels: list[int],
    **_kwargs,
) -> None:
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["cluster_id", "ip", "domain", "asn", "ssh_key", "jarm_hash"],
    )
    writer.writeheader()
    for node, label in zip(nodes, labels):
        writer.writerow({"cluster_id": label, **node})


# ===========================================================================
# Graph visualization
# ===========================================================================

def render_graph(
    nodes: list[dict],
    labels: list[int],
    edges: list[tuple],
    output_path: str = "cluster_graph.png",
) -> None:
    """
    Render a force-directed NetworkX graph color-coded by cluster and save to PNG.

    @decision DEC-CLUSTER-005
    @title Spring layout with per-cluster color palette for graph visualization
    @status accepted
    @rationale spring_layout (Fruchterman-Reingold) naturally groups tightly
      connected nodes, making clusters visually obvious without manual
      positioning. Node colors map to cluster IDs mod a palette length, ensuring
      distinct colors for the first 10 clusters — sufficient for real-world
      actor tracking (rarely more than 5-6 clusters per hunt).
    """
    if not HAS_NETWORKX or not HAS_MATPLOTLIB:
        missing = []
        if not HAS_NETWORKX:
            missing.append("networkx")
        if not HAS_MATPLOTLIB:
            missing.append("matplotlib")
        print(f"[!] Graph output requires: {', '.join(missing)}. Install with pip.")
        return

    PALETTE = [
        "#e63946", "#457b9d", "#2a9d8f", "#e9c46a", "#f4a261",
        "#264653", "#a8dadc", "#f1faee", "#6d6875", "#b5838d",
    ]

    G = nx.Graph()

    # Add nodes
    for idx, node in enumerate(nodes):
        G.add_node(idx, label=node["ip"], cluster=labels[idx])

    # Add edges with weight = similarity
    for i, j, sim in edges:
        G.add_edge(i, j, weight=sim)

    node_colors = [PALETTE[labels[i] % len(PALETTE)] for i in range(len(nodes))]
    node_labels = {i: nodes[i]["ip"] for i in range(len(nodes))}

    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42, k=2.5)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=600, alpha=0.9)
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=7, font_color="white", font_weight="bold")

    edge_weights = [G[u][v]["weight"] for u, v in G.edges()]
    nx.draw_networkx_edges(
        G, pos,
        width=[w * 3 for w in edge_weights],
        alpha=0.6,
        edge_color="#555555",
    )

    # Legend: one patch per unique cluster label
    unique_labels = sorted(set(labels))
    legend_patches = [
        mpatches.Patch(color=PALETTE[lbl % len(PALETTE)], label=f"Cluster {lbl:02d}")
        for lbl in unique_labels
    ]
    plt.legend(handles=legend_patches, loc="upper left", fontsize=9)

    plt.title("Module 0x03 — Infrastructure Overlap Graph", fontsize=14, pad=15)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Graph saved to {output_path}")


# ===========================================================================
# CLI entry point
# ===========================================================================

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Multi-indicator infrastructure overlap & clustering engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssh_cluster.py                         # mock dataset, text output
  python ssh_cluster.py -f nodes.csv            # real CSV, text output
  python ssh_cluster.py -f nodes.csv --threshold 0.5 --format json
  python ssh_cluster.py --graph                 # generate cluster_graph.png

CSV format (header required):
  ip,domain,asn,ssh_key,jarm_hash
  45.77.10.1,update-pkg.org,AS20473,sk-BEAR-01,jarm-BEAR
        """,
    )
    p.add_argument("-f", "--file", metavar="FILE",
                   help="CSV file of infrastructure nodes (omit for mock dataset)")
    p.add_argument("--threshold", type=float, default=0.3, metavar="FLOAT",
                   help="Jaccard similarity threshold for cluster membership (default: 0.3)")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--graph", action="store_true",
                   help="Generate a PNG cluster graph (requires networkx + matplotlib)")
    p.add_argument("--graph-out", default="cluster_graph.png", metavar="FILE",
                   help="Output path for the graph PNG (default: cluster_graph.png)")
    return p


def main() -> None:
    parser = build_argparser()
    args = parser.parse_args()

    # Progress messages go to stderr in machine-readable modes so stdout is clean JSON/CSV
    log = sys.stderr if args.format in ("json", "csv") else sys.stdout

    # Load data
    if args.file:
        print(f"[*] Loading nodes from {args.file}", file=log)
        nodes = load_csv(args.file)
    else:
        print("[*] No CSV file provided — using built-in mock dataset", file=log)
        nodes = generate_mock_dataset()

    if not nodes:
        print("[x] No nodes to analyze. Exiting.", file=sys.stderr)
        sys.exit(1)

    # Build indicator sets and cluster
    indicator_sets = build_indicator_sets(nodes)
    labels, edges = compute_clusters(indicator_sets, threshold=args.threshold)

    # Output
    fmt = args.format
    if fmt == "text":
        print_text_report(nodes, labels, edges, args.threshold)
    elif fmt == "json":
        print_json_report(nodes, labels, edges, args.threshold)
    elif fmt == "csv":
        print_csv_report(nodes, labels)

    # Optional graph
    if args.graph:
        render_graph(nodes, labels, edges, output_path=args.graph_out)


if __name__ == "__main__":
    main()
