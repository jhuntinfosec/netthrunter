#!/usr/bin/env python3
"""
crypto_tracer.py — Crypto Tracking and Clustering
Module 0x0C Capstone Project | AIH-C Curriculum

Traces transactions and clusters wallets based on mock blockchain data.
"""

import argparse
import json
from datetime import datetime, timezone

# Mock Blockchain Graph
MOCK_TXS = [
    {"txid": "tx1", "inputs": ["bc1q_actor"], "outputs": [{"address": "bc1q_mixer", "amount": 5.0}]},
    {"txid": "tx2", "inputs": ["bc1q_mixer"], "outputs": [{"address": "bc1q_exchange", "amount": 4.9}]},
]

def trace_wallet(wallet: str) -> list:
    """Mock trace to find related transactions and addresses."""
    related = []
    for tx in MOCK_TXS:
        if wallet in tx["inputs"] or any(out["address"] == wallet for out in tx["outputs"]):
            related.append(tx)
    return related

def main():
    parser = argparse.ArgumentParser(description="Crypto Tracer")
    parser.add_argument("-w", "--wallet", required=True, help="Target BTC Wallet Address")
    args = parser.parse_args()

    txs = trace_wallet(args.wallet)

    # Output using IOC schema format
    ioc_output = {
        "metadata": {
            "source_module": "0x0C_crypto_tracer",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "indicators": [
            {
                "type": "hash",
                "value": args.wallet,
                "context": {"transactions": txs}
            }
        ]
    }
    
    print(json.dumps(ioc_output, indent=2))

if __name__ == "__main__":
    main()
