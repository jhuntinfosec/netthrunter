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
    
    # Degree Centrality: Who has the most links?
    centrality = nx.degree_centrality(G)
    
    # Sort and take top 5
    sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
    
    for node, score in sorted_nodes:
        # Pull the attribute type if we stored it
        node_type = G.nodes[node].get('type', 'Unknown')
        print(f"[{node_type}] {node:<20} | Score: {score:.3f}")

def visualize(G: nx.Graph):
    """
    Plots the graph visually using Matplotlib.
    """
    plt.figure(figsize=(10, 8))
    
    # Assign colors based on our type mapping
    colors = [G.nodes[n].get('color', 'gray') for n in G.nodes()]
    
    # Use a spring layout for clusters
    pos = nx.spring_layout(G, seed=42, k=0.5)
    
    # Draw Nodes and Labels
    nx.draw(G, pos, with_labels=True, node_color=colors,
            node_size=2000, font_size=10, font_weight="bold", edge_color="gray")
            
    plt.title("Adversary Infrastructure Knowledge Graph", fontsize=15)
    
    # Save the output to disk so it can be viewed without X11 forwarding
    output_file = "cluster_map.png"
    plt.savefig(output_file)
    print(f"\n[+] Saved visualization to: {output_file}")
    print("[*] Red=IP, Orange=Domain, Blue=ASN, Purple=JARM Hash")

if __name__ == "__main__":
    print("[*] Starting Graph Processor...")
    
    # Formatting: "IP,Domain,ASN,JARM_Hash"
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
