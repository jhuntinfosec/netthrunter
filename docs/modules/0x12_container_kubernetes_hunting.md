# Module 0x12: Container, Kubernetes & Registry Hunting

## Overview

Container platforms create infrastructure signals that look different from traditional servers: exposed Kubernetes APIs, permissive dashboards, malicious images, CI runner drift, registry abuse, service-account tokens, and metadata access from workloads.

This module teaches safe discovery and analysis patterns for containerized infrastructure without attempting exploitation.

## Key Concepts

1. **Kubernetes exposure:** API server, kubelet, dashboard, ingress controllers, and service endpoints.
2. **Registry intelligence:** Image names, tags, digests, creation timestamps, suspicious entrypoints, and typosquatted namespaces.
3. **Cluster role drift:** Overbroad roles, anonymous access, privileged pods, and hostPath mounts.
4. **Cloud linkage:** Service account tokens, workload identity, node metadata, and cloud provider annotations.
5. **Runtime signals:** Crypto-mining images, suspicious outbound destinations, and unexpected exposed services.
6. **ATT&CK mapping:** Container-specific behaviors such as malicious image deployment, container API abuse, and escape-to-host risk.

## Workflow

### 1. Inventory Safely

Use passive data where possible:

- Internet scan metadata.
- Certificate transparency.
- Registry metadata.
- Cloud asset inventory.
- Internal authorized cluster audit exports.

### 2. Score Exposure

Risk increases with:

- Public API endpoints.
- Anonymous or default access.
- Privileged workloads.
- HostPath mounts.
- Suspicious image names or digests.
- External IP services.

### 3. Generate Pivots

Useful pivots:

- Registry namespace.
- Image digest.
- Ingress hostname.
- TLS certificate.
- Cloud project or account marker.
- Service account name.

## Module Project: Kubernetes Exposure Mapper

The capstone project, `k8s_exposure_mapper.py`, evaluates mock Kubernetes and registry metadata, scores risky resources, and exports AIH-C indicators.

```bash
cd projects/0x12_k8s_mapper
python k8s_exposure_mapper.py
python k8s_exposure_mapper.py --format table
```

## OPSEC & Ethics

Do not query Kubernetes APIs outside explicit authorization. Treat tokens, kubeconfigs, and registry credentials as secrets. This module uses offline mock data by default.
