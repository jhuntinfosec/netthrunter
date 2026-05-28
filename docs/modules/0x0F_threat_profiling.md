# Module 0x0F: Threat Profiling & TTP Matrix Mapping

## Overview

Infrastructure hunting becomes finished intelligence when raw indicators are turned into a defensible behavioral profile. This module teaches how to aggregate evidence from previous modules, map infrastructure behavior to MITRE ATT&CK Enterprise Reconnaissance and Resource Development techniques, score confidence, and produce an actor dossier.

MITRE retired PRE-ATT&CK in 2020. Modern mapping should use Enterprise ATT&CK tactics such as Reconnaissance and Resource Development for pre-compromise infrastructure behavior.

## Key Concepts

1. **Infrastructure as behavior:** Provider choice, TLS defaults, registrar patterns, CDN usage, and staging cadence are repeatable operational habits.
2. **Technique mapping:** Map observations to ATT&CK techniques such as `T1583.001 Acquire Infrastructure: Domains`, `T1583.006 Web Services`, `T1588.004 Digital Certificates`, and `T1596.003 Digital Certificates`.
3. **Evidence weighting:** Separate direct observations, enrichments, weak pivots, and analyst inferences.
4. **Actor dossier structure:** Summarize infrastructure, tooling, timelines, confidence, gaps, and recommended hunts.
5. **Competing hypotheses:** Document alternate explanations and false-positive risks.
6. **Case handoff:** Produce JSON, Markdown, and graph-friendly outputs that downstream modules can turn into detections and reports.

## Profiling Workflow

### 1. Normalize Inputs

Accept AIH-C IOC schema from all previous modules. Normalize:

- Indicator type and value.
- Source module.
- Collection timestamp.
- Evidence type.
- Confidence.
- Related indicators.

### 2. Extract Behaviors

Examples:

- Multiple domains registered together -> campaign staging.
- Shared JARM and SSH key -> common deployment automation.
- CloudFront plus API Gateway redirector -> web-service fronting pattern.
- Reused wallet in extortion notes -> financial infrastructure link.

### 3. Map Techniques

Use ATT&CK as a vocabulary, not a substitute for evidence. A domain indicator may map to `Acquire Infrastructure: Domains`, but the dossier should still explain why the domain appears actor-controlled.

### 4. Score Confidence

Suggested scale:

- **High:** Multiple independent indicators, direct infrastructure behavior, and temporal consistency.
- **Medium:** Strong pivots but missing one corroborating source.
- **Low:** Single-source or weak similarity only.

### 5. Produce the Dossier

A useful dossier includes:

- Executive summary.
- Infrastructure table.
- Technique mapping table.
- Timeline.
- Confidence and gaps.
- Next hunts.

## Module Project: TTP Profiler

The capstone project, `ttp_profiler.py`, ingests one or more AIH-C JSON files, maps indicators and context to ATT&CK techniques, computes confidence, and emits a Markdown or JSON actor profile.

```bash
cd projects/0x0F_ttp_profiler
python ttp_profiler.py
python ../0x0B_cloud_mapper/cloud_mapper.py | python ttp_profiler.py --format markdown
python ttp_profiler.py -i findings/*.json --format markdown
```

## OPSEC & Ethics

Avoid over-attribution. Infrastructure overlap can suggest common operators, shared tooling, shared hosting, or coincidence. State what the evidence supports and where uncertainty remains.
