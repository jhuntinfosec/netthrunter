#!/usr/bin/env python3
"""
crypto_tracer.py - Module 0x0C Capstone: Crypto Tracking
=========================================================
Builds a mock transaction graph, applies common-input and mixer heuristics,
tags known services, and emits AIH-C indicators for downstream profiling.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


MOCK_TXS = [
    {
        "txid": "tx100",
        "timestamp": "2026-05-17T02:12:00Z",
        "inputs": ["bc1q_victim_a"],
        "outputs": [{"address": "bc1q_actor", "amount": 0.85}, {"address": "bc1q_change_a", "amount": 0.01}],
    },
    {
        "txid": "tx101",
        "timestamp": "2026-05-17T02:24:00Z",
        "inputs": ["bc1q_victim_b"],
        "outputs": [{"address": "bc1q_actor", "amount": 1.25}],
    },
    {
        "txid": "tx102",
        "timestamp": "2026-05-17T03:01:00Z",
        "inputs": ["bc1q_actor", "bc1q_actor_aux"],
        "outputs": [{"address": "bc1q_mixer", "amount": 2.0}, {"address": "bc1q_actor_change", "amount": 0.08}],
    },
    {
        "txid": "tx103",
        "timestamp": "2026-05-17T04:30:00Z",
        "inputs": ["bc1q_mixer"],
        "outputs": [
            {"address": "bc1q_mix_out1", "amount": 0.49},
            {"address": "bc1q_mix_out2", "amount": 0.49},
            {"address": "bc1q_mix_out3", "amount": 0.49},
            {"address": "bc1q_exchange", "amount": 0.49},
        ],
    },
]

SERVICE_TAGS = {
    "bc1q_mixer": {"service": "MockMixer", "category": "mixer"},
    "bc1q_exchange": {"service": "ExampleExchange", "category": "exchange"},
}


@dataclass
class WalletFinding:
    wallet: str
    related_transactions: list[dict]
    related_wallets: list[str]
    cluster: list[str]
    service_tags: dict
    heuristics: list[str]
    confidence: str


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def tx_touches_wallet(tx: dict, wallet: str) -> bool:
    return wallet in tx["inputs"] or any(out["address"] == wallet for out in tx["outputs"])


def neighbors(wallet: str) -> set[str]:
    linked: set[str] = set()
    for tx in MOCK_TXS:
        if tx_touches_wallet(tx, wallet):
            linked.update(tx["inputs"])
            linked.update(out["address"] for out in tx["outputs"])
    linked.discard(wallet)
    return linked


def trace_wallet(seed: str, hops: int) -> tuple[list[dict], set[str]]:
    seen_wallets = {seed}
    seen_txs = {}
    queue = deque([(seed, 0)])
    while queue:
        wallet, depth = queue.popleft()
        for tx in MOCK_TXS:
            if tx_touches_wallet(tx, wallet):
                seen_txs[tx["txid"]] = tx
        if depth >= hops:
            continue
        for nxt in neighbors(wallet):
            if nxt not in seen_wallets:
                seen_wallets.add(nxt)
                queue.append((nxt, depth + 1))
    return list(seen_txs.values()), seen_wallets


def common_input_clusters(txs: Iterable[dict]) -> list[set[str]]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(a: str, b: str) -> None:
        parent[find(b)] = find(a)

    for tx in txs:
        inputs = tx["inputs"]
        if len(inputs) > 1:
            for other in inputs[1:]:
                union(inputs[0], other)

    groups: dict[str, set[str]] = defaultdict(set)
    for wallet in parent:
        groups[find(wallet)].add(wallet)
    return list(groups.values())


def looks_like_mixer(tx: dict) -> bool:
    outputs = [out["amount"] for out in tx["outputs"]]
    if len(outputs) < 4:
        return False
    return len({round(amount, 8) for amount in outputs}) <= 2


def analyze_wallet(wallet: str, hops: int) -> WalletFinding:
    txs, wallets = trace_wallet(wallet, hops)
    clusters = common_input_clusters(txs)
    seed_cluster = next((cluster for cluster in clusters if wallet in cluster), {wallet})
    heuristics: list[str] = []

    if any(wallet in tx["inputs"] and len(tx["inputs"]) > 1 for tx in txs):
        heuristics.append("Seed appears in a multi-input transaction")
    if any(looks_like_mixer(tx) for tx in txs):
        heuristics.append("Mixer-like equal-output transaction observed")
    if any(out["address"] in SERVICE_TAGS for tx in txs for out in tx["outputs"]):
        heuristics.append("Funds touch a tagged service")
    if len(txs) > 1:
        heuristics.append("Multiple related transactions found")

    service_tags = {addr: SERVICE_TAGS[addr] for addr in wallets if addr in SERVICE_TAGS}
    confidence = "high" if len(heuristics) >= 3 else "medium" if len(heuristics) == 2 else "low"
    return WalletFinding(
        wallet=wallet,
        related_transactions=txs,
        related_wallets=sorted(wallets - {wallet}),
        cluster=sorted(seed_cluster),
        service_tags=service_tags,
        heuristics=heuristics,
        confidence=confidence,
    )


def output_table(findings: Iterable[WalletFinding]) -> None:
    print(f"{'WALLET':20} {'TXS':>3} {'RELATED':>7} {'CONF':8} HEURISTICS")
    print("-" * 90)
    for item in findings:
        print(
            f"{item.wallet[:20]:20} {len(item.related_transactions):>3} "
            f"{len(item.related_wallets):>7} {item.confidence:8} {', '.join(item.heuristics)}"
        )


def output_csv(findings: Iterable[WalletFinding]) -> None:
    writer = csv.DictWriter(__import__("sys").stdout, fieldnames=["wallet", "tx_count", "related_count", "confidence"])
    writer.writeheader()
    for item in findings:
        writer.writerow(
            {
                "wallet": item.wallet,
                "tx_count": len(item.related_transactions),
                "related_count": len(item.related_wallets),
                "confidence": item.confidence,
            }
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Crypto transaction tracer")
    parser.add_argument("-w", "--wallet", action="append", help="Seed wallet. Repeatable.")
    parser.add_argument("--hops", type=int, default=1, help="Graph expansion hops")
    parser.add_argument("--format", choices=["json", "table", "csv"], default="json")
    args = parser.parse_args()

    findings = [analyze_wallet(wallet, args.hops) for wallet in (args.wallet or ["bc1q_actor"])]
    if args.format == "table":
        output_table(findings)
        return
    if args.format == "csv":
        output_csv(findings)
        return

    print(
        json.dumps(
            {
                "metadata": {"source_module": "0x0C_crypto_tracer", "generated_at": now_utc()},
                "indicators": [
                    {"type": "wallet", "value": item.wallet, "context": asdict(item)}
                    for item in findings
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
