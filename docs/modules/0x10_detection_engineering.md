# Module 0x10: Detection Engineering & Telemetry Normalization

## Overview

Infrastructure hunting has more impact when findings become repeatable detections. This module teaches how to convert AIH-C indicators and behavioral context into portable detection content, normalized telemetry examples, and SOC-ready hunt packages.

The focus is practical: take outputs from earlier modules, preserve evidence, write behavior-first Sigma rules, and map findings into common schemas such as OCSF.

## Key Concepts

1. **Behavior-first detections:** Prefer durable behaviors over brittle one-off indicators.
2. **Sigma rule design:** Write shareable, SIEM-agnostic rules with clear logsource, detection, false positives, level, and ATT&CK tags.
3. **OCSF normalization:** Represent findings using vendor-neutral event classes and consistent attributes.
4. **Detection quality:** Capture confidence, data requirements, false-positive notes, and validation steps.
5. **Hunt package structure:** Bundle indicators, rules, normalized examples, and analyst notes.

## Workflow

### 1. Ingest AIH-C Output

Accept JSON from modules such as TLS fingerprinting, cloud mapping, LLM extraction, decoy telemetry, and TTP profiling.

### 2. Select Detection Candidates

Good candidates:

- Reused infrastructure patterns.
- Cloud storage listing plus suspicious object names.
- Scanner path sequences.
- C2 role labels corroborated by multiple indicators.
- High-confidence ATT&CK mappings.

Poor candidates:

- Single IPs with no context.
- Shared CDNs or common cloud services without additional evidence.
- LLM-only claims.

### 3. Generate Portable Content

Each generated detection should include:

- Sigma YAML.
- OCSF-style example event.
- ATT&CK tags.
- False-positive notes.
- Recommended validation query.

## Module Project: Detection Pack Builder

The capstone project, `detection_pack_builder.py`, ingests AIH-C JSON and emits a compact detection pack containing Sigma-like YAML rules and OCSF-style JSON examples.

```bash
cd projects/0x10_detection_pack
python detection_pack_builder.py
python detection_pack_builder.py -i ../sample_findings.json --format json
```

## OPSEC & Ethics

Detection content can expose what defenders know. Share externally only after removing sensitive sources, victim-specific details, and collection tradecraft.
