# Module 0x13: Exploited Vulnerability-to-Infrastructure Correlation

## Overview

Known exploited vulnerabilities often create the first observable wave of adversary infrastructure. Hunters can correlate vulnerable products, CISA KEV entries, internet-exposed fingerprints, exploit timing, and infrastructure reuse to prioritize leads.

This module teaches how to use exploited-vulnerability intelligence as a hunting input, not as a vulnerability scanner.

## Key Concepts

1. **KEV-first prioritization:** Focus on vulnerabilities with evidence of exploitation in the wild.
2. **Product fingerprinting:** Map banners, headers, titles, certificates, and paths to vulnerable products.
3. **Exploit wave timing:** Compare disclosure, KEV addition, mass scanning, and infrastructure staging.
4. **Campaign correlation:** Link exploit-facing infrastructure to C2, payload hosting, wallets, and proxy layers.
5. **Exposure scoring:** Combine product evidence, KEV match, internet exposure, and exploit maturity.
6. **Defender handoff:** Produce remediation and hunt recommendations without publishing exploit details.

## Workflow

### 1. Normalize Vulnerability Intelligence

Track:

- CVE ID.
- Vendor and product.
- KEV date and due date.
- Known ransomware use, when available.
- Required action.

### 2. Match Infrastructure Evidence

Product evidence may come from:

- HTTP title/body.
- Server headers.
- TLS certificate subject names.
- Favicons.
- Known URL paths.
- Internal CMDB exports.

### 3. Score Correlation

Strong matches have:

- Exact product fingerprint.
- KEV-listed CVE.
- Public exposure.
- Recent scan or exploit telemetry.
- Related payload/C2 indicators.

### 4. Output Hunt Leads

Each lead should include:

- Asset or indicator.
- CVE and product.
- Evidence.
- Risk score.
- Recommended hunt and remediation action.

## Module Project: KEV Infrastructure Correlator

The capstone project, `kev_infra_correlator.py`, joins mock KEV data with mock exposed-service fingerprints, scores risk, and emits AIH-C indicators.

```bash
cd projects/0x13_kev_correlator
python kev_infra_correlator.py
python kev_infra_correlator.py --format table
```

## OPSEC & Ethics

Avoid exploit reproduction. This module prioritizes already-known exploited vulnerabilities and defensive correlation. Do not probe third-party systems without authorization.
