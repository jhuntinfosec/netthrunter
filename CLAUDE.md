# CLAUDE.md — netthrunter

## Project Identity

**Advanced Infrastructure & Adversary Hunting Curriculum (AIH-C)** — an educational curriculum and engineering framework for proactively identifying, tracking, and mapping threat actor infrastructure. Targets senior threat researchers and security engineers. Purely defensive and authorized-use.

## Build & Serve

```bash
# Activate the Python virtual environment
source .venv/bin/activate

# Serve docs locally (hot-reload)
mkdocs serve

# Build static site to site/
mkdocs build

# Run any capstone project
python projects/0x01_jarm_scanner/tls_fingerprint.py
```

**Dependencies:** MkDocs Material theme (`mkdocs-material`), plus `pymdownx` extensions. Python libraries vary per project — core stack is `scapy`, `httpx`, `beautifulsoup4`, `jarm-py`, `pandas`, `networkx`, `scikit-learn`, `asyncio`.

## Architecture

```
docs/                          # MkDocs source — curriculum modules + index
  modules/0x01_..0x0A_*.md     # 10 teaching modules (theory + concepts)
  projects.md                  # Capstone projects overview
  index.md                     # Landing page
projects/                      # Capstone Python projects (1 per module)
  0x01_jarm_scanner/           # TLS fingerprinting (JARM/JA3/JA4+)
  0x02_ct_hunter/              # Certificate Transparency log hunter
  0x03_overlap_clustering/     # SSH key / ASN overlap clustering
  0x04_c2_dorker/              # C2 framework dorking & identification
  0x05_leak_parser/            # Stealer log & leak data parser
  0x06_edge_layer/             # CDN / domain fronting tester
  0x07_graph_builder/          # Neo4j / networkx graph builder
  0x08_proxy_validator/        # Proxy & SOCKS5 validator
  0x09_lambda_scanner/         # Distributed serverless scanner
  0x0A_entropy_classifier/     # Shannon entropy & K-Means classifier
books/                         # Offline reference library (PDFs, gitignored)
site/                          # MkDocs build output (gitignored)
mkdocs.yml                     # MkDocs configuration & nav
```

Each module `0x01`..`0x0A` has a paired doc (`docs/modules/`) and project (`projects/`). Module numbering is hex.

## Conventions

- **No tests or CI yet** — this is a curriculum repo, not a production codebase
- **One script per project** — each capstone is a single Python file (boilerplate/starter code)
- **books/ is gitignored** — proprietary PDFs, never committed
- **site/ is gitignored** — generated MkDocs output
- **Python venv** at `.venv/` (gitignored) — activate before running projects or mkdocs
- **GEMINI.md** exists at root — extended curriculum overview (Gemini-format context doc)
- **Defensive use only** — all scanning/probing tools are for authorized research; OPSEC guidance in Module 0x09
