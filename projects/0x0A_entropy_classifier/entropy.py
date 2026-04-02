#!/usr/bin/env python3
"""
entropy.py — Module 0x0A Capstone: Data Science for Threat Hunting
===================================================================
Implements Shannon entropy analysis, multi-feature extraction, K-Means
clustering, and Isolation Forest anomaly detection for DGA domain
classification.

Usage:
  python entropy.py                                  # Demo mode
  python entropy.py -f domains.csv                   # Process CSV file
  python entropy.py --cluster --graph                # K-Means with viz
  python entropy.py --anomaly                        # Isolation Forest
  python entropy.py --cluster --anomaly --format json # Full pipeline

Dependencies:
  pandas          — pip install pandas  (required)
  scikit-learn    — pip install scikit-learn  (optional, for clustering/anomaly)
  matplotlib      — pip install matplotlib  (optional, for visualization)
  joblib          — included with scikit-learn  (for model persistence)

@decision DEC-DS-001
@title Pandas required, scikit-learn and matplotlib optional
@status accepted
@rationale Entropy analysis works with pandas alone. ML features (K-Means,
  Isolation Forest) gracefully degrade if scikit-learn is missing. Graph
  output degrades if matplotlib is missing. This layered dependency model
  lets students start with just pandas and add ML later.

@decision DEC-DS-002
@title Feature extraction before clustering, not entropy-only
@status accepted
@rationale Single-feature (entropy) classification has high false positive
  rate. The 6-feature vector (entropy, length, digit_ratio, consonant_ratio,
  unique_ratio, vowel_consonant_ratio) provides much better separation
  between DGA families and legitimate domains.
"""

import argparse
import csv
import json
import math
import os
import sys
import textwrap
from collections import Counter
from io import StringIO
from typing import Optional

# Pandas is required
try:
    import pandas as pd
except ImportError:
    print("[!] pandas is required: pip install pandas", file=sys.stderr)
    sys.exit(1)

# scikit-learn is optional (for clustering and anomaly detection)
try:
    from sklearn.cluster import KMeans
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import silhouette_score

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# matplotlib is optional (for visualization)
try:
    import matplotlib

    matplotlib.use("Agg")  # Non-interactive backend for file output
    import matplotlib.pyplot as plt

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# joblib for model persistence (comes with scikit-learn)
try:
    import joblib

    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

# ---------------------------------------------------------------------------
# Mock dataset — realistic mix of legitimate and DGA domains
# ---------------------------------------------------------------------------

MOCK_DOMAINS = [
    # Legitimate domains (low entropy, readable)
    "google.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "amazon.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "linkedin.com",
    "twitter.com",
    "facebook.com",
    "netflix.com",
    "reddit.com",
    "youtube.com",
    "dropbox.com",
    # Random-char DGA (high entropy)
    "x18jdfx1zz.su",
    "ab0cx939js83n.ru",
    "jhsd88f3h12d.com",
    "1298418abcc22.xyz",
    "qw3rt7yz8x.top",
    "m9k2j8d4f1.net",
    "p7x3v9c1n5.tk",
    "z8q2w5r1t4.cc",
    # Dictionary-based DGA (medium entropy)
    "horsestablebattery.com",
    "reddoorbluewindow.net",
    "sunflowergreenleaf.org",
    "mountainriverstone.xyz",
    # Borderline / suspicious
    "login-auth-portal-v2.tk",
    "service-update-99.net",
    "secure-banking-verify.com",
    "account-recovery-help.xyz",
    # Hex-encoded (very high entropy)
    "a3f2c1d8e9b04f7a.com",
    "deadbeef01234567.net",
]


# ---------------------------------------------------------------------------
# Core: Shannon entropy
# ---------------------------------------------------------------------------


def shannon_entropy(data_string: str) -> float:
    """
    Calculate Shannon entropy (H) of a string in bits.

    H = -sum(p(x) * log2(p(x))) for each unique character x.
    Higher values indicate more randomness.
    """
    if not data_string:
        return 0.0
    n = len(data_string)
    entropy = 0.0
    for count in Counter(data_string).values():
        p_x = count / n
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def extract_features(domain: str) -> dict:
    """
    Extract a feature vector from a domain name for ML classification.

    Features:
    - entropy: Shannon entropy of root domain (strip TLD)
    - length: Character count of root domain
    - digit_ratio: Proportion of digits
    - consonant_ratio: Proportion of consonants among alpha chars
    - unique_ratio: Proportion of unique characters
    - vowel_consonant_ratio: Vowels / consonants
    """
    # Strip TLD to analyze the meaningful part
    parts = domain.split(".")
    root = parts[0] if parts else domain

    alpha_chars = [c for c in root.lower() if c.isalpha()]
    vowels = sum(1 for c in root.lower() if c in "aeiou")
    consonants = sum(
        1 for c in root.lower() if c.isalpha() and c not in "aeiou"
    )
    digits = sum(1 for c in root if c.isdigit())

    return {
        "domain": domain,
        "root": root,
        "entropy": shannon_entropy(root),
        "length": len(root),
        "digit_ratio": round(digits / max(len(root), 1), 4),
        "consonant_ratio": round(consonants / max(len(alpha_chars), 1), 4),
        "unique_ratio": round(len(set(root)) / max(len(root), 1), 4),
        "vowel_consonant_ratio": round(vowels / max(consonants, 1), 4),
    }


# Feature columns used for ML (excludes domain, root which are identifiers)
FEATURE_COLS = [
    "entropy",
    "length",
    "digit_ratio",
    "consonant_ratio",
    "unique_ratio",
    "vowel_consonant_ratio",
]


# ---------------------------------------------------------------------------
# K-Means clustering
# ---------------------------------------------------------------------------


def run_kmeans(
    df: pd.DataFrame,
    max_k: int = 8,
    chosen_k: Optional[int] = None,
) -> tuple:
    """
    Run K-Means clustering on feature matrix.

    If chosen_k is None, uses elbow method to find optimal K.
    Returns (labels, model, scaler, inertias_for_elbow).
    """
    if not HAS_SKLEARN:
        print(
            "[!] scikit-learn not installed — skipping clustering",
            file=sys.stderr,
        )
        return None, None, None, None

    X = df[FEATURE_COLS].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Elbow method: compute inertias for K=2..max_k
    inertias = []
    for k in range(2, max_k + 1):
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        km.fit(X_scaled)
        inertias.append((k, km.inertia_))

    # Choose K: use provided value, or find elbow heuristically
    if chosen_k is None:
        # Simple elbow heuristic: largest inertia drop
        drops = []
        for i in range(1, len(inertias)):
            drop = inertias[i - 1][1] - inertias[i][1]
            drops.append((inertias[i][0], drop))
        # K where the marginal improvement drops most
        if drops:
            chosen_k = max(drops, key=lambda x: x[1])[0]
            # Clamp: usually elbow is at K-1
            chosen_k = max(2, chosen_k - 1)
        else:
            chosen_k = 3

    # Fit final model
    km = KMeans(n_clusters=chosen_k, random_state=42, n_init=10)
    labels = km.fit_predict(X_scaled)

    sil = silhouette_score(X_scaled, labels) if len(set(labels)) > 1 else 0.0

    return labels, km, scaler, inertias, sil, chosen_k


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


def run_anomaly_detection(
    df: pd.DataFrame,
    contamination: float = 0.1,
) -> Optional[list]:
    """
    Run Isolation Forest anomaly detection on feature matrix.

    Returns list of -1 (anomaly) or 1 (normal) per row.
    """
    if not HAS_SKLEARN:
        print(
            "[!] scikit-learn not installed — skipping anomaly detection",
            file=sys.stderr,
        )
        return None

    X = df[FEATURE_COLS].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
    )
    labels = clf.fit_predict(X_scaled)
    return labels.tolist()


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------


def plot_clusters(
    df: pd.DataFrame,
    labels: list,
    output_path: str = "clusters.png",
):
    """Plot cluster scatter: entropy vs length, colored by cluster."""
    if not HAS_MATPLOTLIB:
        print(
            "[!] matplotlib not installed — skipping graph",
            file=sys.stderr,
        )
        return

    fig, ax = plt.subplots(1, 1, figsize=(10, 7))

    scatter = ax.scatter(
        df["entropy"],
        df["length"],
        c=labels,
        cmap="viridis",
        alpha=0.7,
        s=60,
        edgecolors="black",
        linewidth=0.5,
    )

    # Annotate each point with domain name
    for _, row in df.iterrows():
        ax.annotate(
            row["domain"],
            (row["entropy"], row["length"]),
            fontsize=6,
            alpha=0.7,
            xytext=(3, 3),
            textcoords="offset points",
        )

    plt.colorbar(scatter, ax=ax, label="Cluster")
    ax.set_xlabel("Shannon Entropy", fontsize=12)
    ax.set_ylabel("Domain Length (root)", fontsize=12)
    ax.set_title("Domain Clustering: DGA Detection", fontsize=14)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"[+] Cluster plot saved: {output_path}", file=sys.stderr)


def plot_elbow(inertias: list, output_path: str = "elbow.png"):
    """Plot elbow method chart."""
    if not HAS_MATPLOTLIB or not inertias:
        return

    ks = [x[0] for x in inertias]
    vals = [x[1] for x in inertias]

    fig, ax = plt.subplots(1, 1, figsize=(8, 5))
    ax.plot(ks, vals, "bo-", linewidth=2)
    ax.set_xlabel("Number of Clusters (K)", fontsize=12)
    ax.set_ylabel("Inertia", fontsize=12)
    ax.set_title("Elbow Method for Optimal K", fontsize=14)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"[+] Elbow plot saved: {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def format_text(df: pd.DataFrame, threshold: float) -> str:
    """Human-readable text output."""
    lines = []

    # Full table
    lines.append("[*] Feature Analysis (all domains):")
    display_cols = ["domain", "entropy", "length", "digit_ratio"]
    if "cluster" in df.columns:
        display_cols.append("cluster")
    if "anomaly" in df.columns:
        display_cols.append("anomaly")
    lines.append(
        df.sort_values("entropy", ascending=False)[display_cols].to_string(
            index=False
        )
    )

    # High entropy alerts
    dga = df[df["entropy"] >= threshold]
    lines.append(
        f"\n[!] HIGH ENTROPY domains (threshold {threshold}): {len(dga)}"
    )
    if not dga.empty:
        lines.append(
            dga.sort_values("entropy", ascending=False)[
                ["domain", "entropy"]
            ].to_string(index=False)
        )

    # Cluster summary
    if "cluster" in df.columns:
        lines.append("\n[*] Cluster Summary:")
        for cid in sorted(df["cluster"].unique()):
            members = df[df["cluster"] == cid]
            avg_ent = members["entropy"].mean()
            lines.append(
                f"    Cluster {cid}: {len(members)} domains, "
                f"avg entropy {avg_ent:.3f}"
            )
            for _, row in members.iterrows():
                lines.append(f"      - {row['domain']} (H={row['entropy']:.3f})")

    # Anomaly summary
    if "anomaly" in df.columns:
        anomalies = df[df["anomaly"] == -1]
        lines.append(f"\n[!] Anomalies detected: {len(anomalies)}")
        for _, row in anomalies.iterrows():
            lines.append(f"    - {row['domain']} (H={row['entropy']:.3f})")

    return "\n".join(lines)


def format_json(df: pd.DataFrame) -> str:
    """JSON output."""
    records = df.to_dict(orient="records")
    return json.dumps(records, indent=2, default=str)


def format_csv_output(df: pd.DataFrame) -> str:
    """CSV output."""
    return df.to_csv(index=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Module 0x0A: Data Science Domain Classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s                              Demo mode (mock data)
              %(prog)s -f domains.csv               Process CSV file
              %(prog)s --cluster --graph             K-Means with visualization
              %(prog)s --anomaly                     Isolation Forest detection
              %(prog)s --cluster --anomaly --format json  Full pipeline
        """),
    )
    parser.add_argument("-f", "--file", help="CSV file with 'domain' column")
    parser.add_argument(
        "--threshold",
        type=float,
        default=3.5,
        help="Entropy threshold for DGA flagging (default: 3.5)",
    )
    parser.add_argument(
        "--cluster",
        action="store_true",
        help="Run K-Means clustering (requires scikit-learn)",
    )
    parser.add_argument(
        "--anomaly",
        action="store_true",
        help="Run Isolation Forest anomaly detection (requires scikit-learn)",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Generate cluster visualization PNG (requires matplotlib)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="Anomaly contamination rate (default: 0.1)",
    )
    parser.add_argument(
        "-k",
        "--num-clusters",
        type=int,
        default=None,
        help="Number of clusters (default: auto via elbow method)",
    )
    parser.add_argument(
        "--save-model",
        help="Save trained K-Means model to file (requires joblib)",
    )
    parser.add_argument(
        "--load-model",
        help="Load pre-trained model for classification",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # --- Load or generate data ---
    if args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        df_raw = pd.read_csv(args.file)
        if "domain" not in df_raw.columns:
            print("[!] CSV must have a 'domain' column", file=sys.stderr)
            sys.exit(1)
        domains = df_raw["domain"].dropna().tolist()
    else:
        domains = MOCK_DOMAINS
        if args.format == "text":
            print("[*] Data Science Domain Classifier — Module 0x0A", file=sys.stderr)
            print(f"[*] No input file — using {len(domains)} mock domains", file=sys.stderr)
            if not HAS_SKLEARN:
                print(
                    "[!] scikit-learn not installed — entropy analysis only",
                    file=sys.stderr,
                )
                print(
                    "[!] pip install scikit-learn for clustering/anomaly",
                    file=sys.stderr,
                )
            if not HAS_MATPLOTLIB:
                print(
                    "[!] matplotlib not installed — no graph output",
                    file=sys.stderr,
                )
            print(file=sys.stderr)

    # --- Feature extraction ---
    features = [extract_features(d) for d in domains]
    df = pd.DataFrame(features)

    # --- K-Means clustering ---
    if args.cluster:
        result = run_kmeans(df, chosen_k=args.num_clusters)
        if result[0] is not None:
            labels, model, scaler, inertias, sil, chosen_k = result
            df["cluster"] = labels

            if args.format == "text":
                print(
                    f"[*] K-Means: K={chosen_k}, silhouette={sil:.3f}",
                    file=sys.stderr,
                )

            # Save model if requested
            if args.save_model and HAS_JOBLIB:
                joblib.dump(
                    {"model": model, "scaler": scaler, "features": FEATURE_COLS},
                    args.save_model,
                )
                print(
                    f"[+] Model saved to {args.save_model}", file=sys.stderr
                )

            # Generate plots
            if args.graph:
                plot_clusters(df, labels)
                if inertias:
                    plot_elbow(inertias)

    # --- Anomaly detection ---
    if args.anomaly:
        anomaly_labels = run_anomaly_detection(
            df, contamination=args.contamination
        )
        if anomaly_labels is not None:
            df["anomaly"] = anomaly_labels
            num_anomalies = sum(1 for x in anomaly_labels if x == -1)
            if args.format == "text":
                print(
                    f"[*] Isolation Forest: {num_anomalies} anomalies detected",
                    file=sys.stderr,
                )

    # --- Output ---
    if args.format == "json":
        print(format_json(df))
    elif args.format == "csv":
        print(format_csv_output(df))
    else:
        print(format_text(df, args.threshold))

        # Summary stats
        print(f"\n[*] Summary:")
        print(f"    Total domains:    {len(df)}")
        print(f"    Mean entropy:     {df['entropy'].mean():.3f}")
        print(f"    Median entropy:   {df['entropy'].median():.3f}")
        print(
            f"    High entropy (>{args.threshold}): "
            f"{len(df[df['entropy'] >= args.threshold])}"
        )
        if "cluster" in df.columns:
            print(f"    Clusters:         {df['cluster'].nunique()}")
        if "anomaly" in df.columns:
            print(
                f"    Anomalies:        {sum(1 for x in df['anomaly'] if x == -1)}"
            )


if __name__ == "__main__":
    main()
