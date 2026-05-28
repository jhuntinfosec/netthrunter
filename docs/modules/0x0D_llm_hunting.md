# Module 0x0D: LLM & AI-Assisted Threat Hunting

## Overview

Threat researchers often need to process messy text: vendor reports, raw pastes, stealer logs, sandbox output, abuse reports, chat exports, and analyst notes. LLMs can accelerate extraction and triage, but they also introduce hallucination, privacy, and provenance risks.

This module teaches a local-first, schema-first workflow for using LLMs as assistants in defensive hunting pipelines. The model suggests structure; deterministic validators decide what enters the case record.

## Key Concepts

1. **Local-first analysis:** Prefer local models or offline regex extraction when content includes sensitive victim data.
2. **Schema-constrained extraction:** Ask for strict JSON, then validate and repair with deterministic code.
3. **Evidence preservation:** Keep source spans and confidence scores for every extracted indicator.
4. **Prompt injection resistance:** Treat untrusted reports and logs as data, not instructions.
5. **Hybrid extraction:** Combine regex, parsers, and LLMs rather than relying on model output alone.
6. **STIX/TAXII readiness:** Normalize outputs so they can later become STIX 2.1 bundles or TAXII-shared intelligence.

## Analyst Workflow

### 1. Pre-Parse Deterministically

Before involving a model:

- Extract IPs, domains, URLs, hashes, emails, CVEs, and wallet addresses with regex.
- Deduplicate and normalize obvious variants.
- Preserve the original source line or span.

This reduces model cost and makes the output auditable.

### 2. Ask the Model for Structure, Not Truth

Useful LLM tasks:

- Group related indicators into infrastructure clusters.
- Summarize likely roles such as `c2`, `stager`, `redirector`, or `panel`.
- Extract prose evidence supporting a hypothesis.
- Draft analyst notes from structured facts.

Unsafe LLM tasks:

- Making attribution claims without evidence.
- Inventing enrichment data.
- Deciding legal handling of leaked credentials.

### 3. Validate Everything

Validation checks should include:

- JSON parseability.
- Schema conformance.
- Indicator type validation.
- Domain/IP/hash normalization.
- Confidence bounds.
- Source span presence.

### 4. Keep Provenance

Every indicator should carry:

- Source document name.
- Extracted line or span.
- Extraction method: regex, LLM, parser, or analyst.
- Confidence and rationale.

## Module Project: Intel Extractor

The capstone project, `intel_extractor.py`, performs deterministic IOC extraction first, optionally asks a local/provider model for role labels, validates output, and emits the AIH-C schema.

```bash
cd projects/0x0D_intel_extractor
python intel_extractor.py --text "C2 was observed at 185.220.101.77 and payload hash a1b2c3d4..."
python intel_extractor.py -f report.txt --provider mock
python intel_extractor.py -f report.txt --provider ollama --format table
```

## OPSEC & Ethics

Never paste sensitive incident data, leaked credentials, customer names, or private reports into a hosted model unless policy and contracts explicitly allow it. Treat model output as untrusted until validated.
