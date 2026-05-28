# Module 0x11: Identity, SaaS & OAuth Infrastructure Hunting

## Overview

Modern adversary infrastructure is not always a server. It may be an OAuth application, a compromised mailbox, a malicious tenant, a SaaS forwarding rule, or an identity provider configuration. This module expands infrastructure hunting into cloud identity and business SaaS telemetry.

## Key Concepts

1. **OAuth application abuse:** Malicious app registrations, excessive consent grants, and suspicious redirect URIs.
2. **SaaS audit trails:** Sign-ins, mailbox rules, file sharing, admin actions, API token creation, and app consent.
3. **Tenant and domain pivots:** Verified domains, app publisher names, redirect domains, and support emails.
4. **Identity infrastructure:** IdP tenants, SSO metadata, certificate rollover, service principals, and federation artifacts.
5. **Detection surfaces:** Entra ID, Okta, Google Workspace, M365 Unified Audit Log, and SaaS API logs.
6. **Defensive scoping:** Determine whether a suspicious app is benign automation, third-party SaaS, or adversary infrastructure.

## Workflow

### 1. Normalize Audit Events

Collect identity and SaaS events into a common shape:

- Actor.
- Action.
- Target app or resource.
- IP, ASN, and user agent.
- Consent scopes.
- Redirect URI or verified domain.
- Timestamp.

### 2. Score App and Tenant Risk

High-risk signs:

- Broad scopes such as mail read/write or offline access.
- New publisher with unverified domains.
- Redirect URI on suspicious infrastructure.
- Admin consent soon after phishing activity.
- Sign-ins from known proxy or cloud exit nodes.

### 3. Pivot Back to Infrastructure

Identity artifacts can point back to:

- Redirect domains.
- App logo hosting.
- Support email domains.
- Publisher homepage.
- TLS certificates for app callback endpoints.

## Module Project: SaaS Audit Hunter

The capstone project, `saas_audit_hunter.py`, analyzes mock SaaS/identity audit events, scores OAuth app risk, extracts infrastructure pivots, and emits AIH-C indicators.

```bash
cd projects/0x11_saas_identity_hunter
python saas_audit_hunter.py
python saas_audit_hunter.py --format table
```

## OPSEC & Ethics

Identity logs contain personal data. Minimize user details in exports, preserve tenant confidentiality, and avoid sending SaaS audit logs to hosted models without explicit approval.
