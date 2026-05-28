# Module 0x0E: Active Defense & Deception

## Overview

Deception infrastructure lets defenders collect adversary and scanner telemetry passively. Well-designed decoys can reveal scanning infrastructure, tooling fingerprints, payload staging behavior, and targeting patterns without probing suspected adversary systems.

This module focuses on low-risk, authorized deception: lightweight canaries, fake directory listings, honeypot telemetry, enrichment, and evidence handling.

## Key Concepts

1. **Low vs high interaction:** Low-interaction decoys are safer and easier to operate; high-interaction systems collect richer behavior but increase containment risk.
2. **Scanner fingerprinting:** Capture source IP, user agent, requested path, header order, TLS client fingerprint when available, and timing behavior.
3. **Canary design:** Expose plausible but harmless resources such as fake config names, fake panels, or synthetic bucket listings.
4. **Telemetry enrichment:** Classify scanner IPs by ASN, cloud provider, proxy indicators, and known research networks.
5. **Containment:** Decoys must not become launch points, credential stores, or real vulnerable services.
6. **Legal handling:** Clearly separate internal canary telemetry from third-party victim data.

## Deception Patterns

### Directory Listing Decoy

Expose a harmless listing with filenames that attract commodity scanners:

- `config.json`
- `.env`
- `backup.zip`
- `payload.bin`
- `panel/`

The lesson is in who asks for what, in what order, and from where.

### Cloud Storage Canary

Use a controlled bucket name and public object metadata to identify enumeration tooling. Never place secrets or real payloads in the bucket.

### Login Panel Canary

Expose a fake login surface that records requests and never authenticates. Avoid collecting passwords beyond synthetic honey credentials that your own team created.

### Header and Timing Capture

Useful features:

- User-Agent and Accept headers.
- Path sequence.
- Inter-request timing.
- ASN and cloud provider.
- Repeated probes across decoys.

## Module Project: Decoy Listener

The capstone project, `decoy_listener.py`, can run in demo mode or serve a local decoy HTTP listener. It classifies path probes, enriches scanner IPs with mock provider/ASN data, computes a scanner profile, and exports AIH-C indicators.

```bash
cd projects/0x0E_decoy_listener
python decoy_listener.py --demo
python decoy_listener.py --port 8080
```

## OPSEC & Ethics

Do not deploy vulnerable services as bait unless your organization explicitly authorizes high-interaction honeypots and containment is in place. Keep decoy data synthetic. Do not entrap users or collect unrelated personal data.
