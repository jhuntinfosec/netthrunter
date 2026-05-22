# Module 0x0C: Follow the Money (Crypto Tracking)

Adversary infrastructure is often funded by cryptocurrency (Bitcoin, Monero). This module focuses on using blockchain heuristics to cluster wallets, identify mixing services, and trace ransomware affiliate payments back to infrastructure purchases.

## Key Concepts

1. **Transaction Graphs:** Modeling the blockchain as a graph of inputs and outputs.
2. **Address Clustering:** Heuristics like common-input ownership to group addresses into a single entity.
3. **Mixing & Tumbling:** Identifying patterns typical of CoinJoin or other mixing services.
4. **Cash-Out Nodes:** Tracking funds to known exchanges.

## Target Audience
Researchers needing to pivot from technical IOCs (e.g., a Bitcoin address found in a stealer log or ransomware note) to broader financial infrastructure.

## Boilerplate Setup
The capstone project, `crypto_tracer.py`, builds a mock transaction graph and identifies clusters.

```bash
cd projects/0x0C_crypto_tracer
python crypto_tracer.py -w bc1q_mock_wallet
```



```python
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
```
