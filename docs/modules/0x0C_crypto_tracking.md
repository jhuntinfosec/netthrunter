# Module 0x0C: Follow the Money (Crypto Tracking)

## Overview

Financial infrastructure is part of adversary infrastructure. Ransomware notes, stealer panels, phishing kits, bulletproof hosting invoices, and marketplace profiles often contain cryptocurrency addresses. This module teaches careful, evidence-based blockchain analysis for clustering wallets, identifying service touchpoints, and enriching technical infrastructure leads.

The curriculum remains defensive: students learn graph and heuristic techniques without attempting deanonymization beyond lawful open-source analysis.

## Key Concepts

1. **Transaction graphs:** Model wallets, transactions, services, and cash-out points as a directed graph.
2. **Common-input clustering:** Multiple inputs in one transaction may indicate common control, with important exceptions.
3. **Change address heuristics:** Infer likely change outputs by amount, address reuse, and script type.
4. **Mixer and CoinJoin detection:** Recognize many-input/many-output patterns and uniform output amounts.
5. **Service tagging:** Mark known exchange, mixer, marketplace, donation, and ransomware collection addresses from trusted datasets.
6. **Infrastructure linkage:** Connect wallets to domains, leak records, ransom notes, hosting invoices, and actor profiles.

## Analysis Workflow

### 1. Seed Collection

Wallet seeds can come from:

- Ransom notes or extortion portals.
- Stealer logs and bot configs.
- Public reporting and sanctions lists.
- Marketplace profiles.
- Malware configuration extraction.

Always preserve source context and confidence. A wallet in a paste is weaker evidence than a wallet embedded in a ransom note delivered to a confirmed victim.

### 2. Graph Expansion

Expand cautiously:

- One hop from a seed wallet is usually safe for training.
- Multi-hop expansion should require service tagging and analyst review.
- Known high-volume services should stop expansion, not create attribution.

### 3. Heuristic Scoring

Useful signals:

- Shared transaction inputs.
- Repeated collection-wallet behavior.
- Fan-in from many victims.
- Fan-out to exchanges.
- Mixer-like equal outputs.
- Temporal proximity to campaign infrastructure creation.

### 4. Reporting

Financial findings should use careful language:

- “Wallet observed in actor-controlled note” is evidence.
- “Likely related wallet by common-input heuristic” is an inference.
- “Exchange deposit address” usually means a service touchpoint, not actor identity.

## Module Project: Crypto Tracer

The capstone project, `crypto_tracer.py`, builds a mock transaction graph, applies common-input and mixer heuristics, tags known services, and emits AIH-C indicators that can be fed into graph and profiling modules.

```bash
cd projects/0x0C_crypto_tracer
python crypto_tracer.py -w bc1q_actor
python crypto_tracer.py -w bc1q_actor --hops 2 --format table
```

## OPSEC & Ethics

Do not interact with adversary wallets. Do not send dust transactions. Do not publish victim payment details without authorization. Treat wallet clusters as analytic leads, not definitive identity claims.
