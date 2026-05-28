# Module 0x0B: Cloud Infrastructure Hunting

## Overview

Adversaries frequently rent, compromise, or blend into public cloud infrastructure because cloud providers offer rapid provisioning, global reach, reputable IP space, managed TLS, and disposable serverless services. This module teaches hunters to pivot from a single cloud-hosted indicator into provider ownership, service exposure, control-plane artifacts, storage abuse, and adjacent cloud resources.

The goal is not unauthorized cloud enumeration. The goal is to enrich infrastructure leads, identify abuse patterns, and produce defensible findings that can be handed to internal responders, cloud abuse desks, or a CERT.

## Key Concepts

1. **Provider range attribution:** Map IPs to AWS, Azure, GCP, Oracle Cloud, Cloudflare, Fastly, and other providers using published ranges or local mock ranges.
2. **Managed service fingerprints:** Recognize S3, Azure Blob, CloudFront, API Gateway, Lambda URLs, Google Cloud Run, Firebase, and Functions endpoints.
3. **Bucket and object-store exposure:** Detect public listing behavior, suspicious object names, payload staging patterns, and ownership clues without downloading sensitive content.
4. **Serverless redirectors:** Identify domains and URLs that look like disposable redirectors, short-lived functions, or API Gateway front doors.
5. **Cloud temporal correlation:** Compare certificate issuance, DNS creation, cloud provider, and object-store timestamps to spot campaign staging.
6. **Abuse reporting artifacts:** Preserve enough evidence for provider abuse teams without collecting unnecessary victim data.

## Hunting Workflow

### 1. Attribute the IP or Host

Start with cloud range attribution. In production, use provider-published JSON feeds such as AWS `ip-ranges.json`, Azure service tags, and Google Cloud IP ranges. In the capstone, the lookup is mock-first so the exercise works offline.

Enrichment fields to capture:

- Provider and service family.
- Region, when known.
- ASN and prefix.
- Whether the asset is edge/CDN, compute, serverless, or storage.
- Confidence and evidence source.

### 2. Classify the Cloud Service

Cloud services leak structure through hostnames and HTTP headers:

- `*.s3.amazonaws.com`, `*.s3-website-*`, and `x-amz-*` headers.
- `*.blob.core.windows.net` and `x-ms-*` headers.
- `*.cloudfront.net`, `*.execute-api.*.amazonaws.com`, `*.lambda-url.*.on.aws`.
- `*.run.app`, `*.cloudfunctions.net`, `*.firebaseapp.com`.
- `*.azurewebsites.net`, `*.trafficmanager.net`, `*.azureedge.net`.

Classification should stay evidence-based. A CNAME to CloudFront is not attribution by itself; it is one feature in a larger infrastructure picture.

### 3. Evaluate Storage Exposure Safely

The safe approach is metadata-first:

- Check whether the endpoint returns a public bucket listing.
- Record filenames, sizes, ETags, and last-modified timestamps only when exposed by listing metadata.
- Flag suspicious names such as `config`, `payload`, `stager`, `beacon`, `bot`, `panel`, `wallet`, or archive bundles.
- Avoid downloading private data, credentials, logs, or payloads unless explicitly authorized by rules of engagement.

### 4. Identify Serverless Abuse

Serverless abuse commonly appears as:

- Redirectors in front of C2 or phishing kits.
- Disposable API Gateway endpoints that proxy to external infrastructure.
- Cloud Run or Functions endpoints with generic auto-generated domains.
- Short-lived infrastructure that appears immediately after certificate issuance or DNS setup.

Useful pivots include response headers, URL path behavior, DNS history, TLS certificate subject names, and redirect chains.

### 5. Produce a Cloud Abuse Report

A good report includes:

- Indicator and cloud provider.
- Service classification and confidence.
- Evidence snippets such as headers, public listing metadata, and redirect targets.
- First-seen/last-seen timestamps.
- Risk summary and recommended recipient.

## Module Project: Cloud Infrastructure Mapper

The capstone project, `cloud_mapper.py`, maps targets to cloud providers, classifies likely managed services, simulates storage exposure checks, scores risk, and emits the unified AIH-C IOC schema.

```bash
cd projects/0x0B_cloud_mapper
python cloud_mapper.py -t 13.248.118.1
python cloud_mapper.py -t malicious-update.s3.amazonaws.com
python cloud_mapper.py -f targets.txt --format table
```

## OPSEC & Ethics

Cloud hunting should be passive or metadata-only unless you have explicit authorization. Do not brute-force bucket names outside an approved scope. Do not retrieve exposed private files. When reporting abuse, include enough evidence for triage and no more.
