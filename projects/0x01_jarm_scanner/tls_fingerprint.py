#!/usr/bin/env python3
"""
tls_fingerprint.py — Module 0x01 Capstone: Structural TLS Fingerprinting
=========================================================================
Demonstrates JARM, JA3-concept fingerprinting, and X.509 certificate
analysis for adversary infrastructure hunting.

This script is intentionally educational: every fallback is documented,
and the conceptual JA3 implementation explains why packet capture is
needed for true JA3 extraction.

Usage:
  python tls_fingerprint.py                          # Demo mode (hardcoded targets)
  python tls_fingerprint.py -t 1.2.3.4               # Single target
  python tls_fingerprint.py -t 1.2.3.4,1.2.3.5      # Comma-separated targets
  python tls_fingerprint.py -f targets.txt           # Targets from file (one per line)
  python tls_fingerprint.py -t 1.2.3.4 --format csv # CSV output
  python tls_fingerprint.py -t 1.2.3.4 --port 8443  # Non-standard port

Environment Variables:
  SHODAN_API_KEY  — If set, look up JARM hashes in Shodan for correlation

Dependencies (all optional with fallbacks):
  jarm            — pip install jarm-py  (JARM fingerprinting)
  shodan          — pip install shodan   (Shodan API correlation)

@decision DEC-TLS-001
@title Mock-first fallback pattern for optional dependencies
@status accepted
@rationale Educational tools must run offline without any API keys or
  special libraries. Every integration point (JARM library, Shodan API)
  has an explicit mock fallback that demonstrates what real output looks
  like, with inline comments explaining the difference.
"""

import argparse
import csv
import hashlib
import json
import os
import socket
import ssl
import sys
from datetime import datetime, timezone
from io import StringIO
from typing import Optional

# ---------------------------------------------------------------------------
# Known C2 JARM Hash Database
# ---------------------------------------------------------------------------
# These are the default JARM hashes produced by common C2 frameworks when
# run with out-of-the-box configuration. Operators who customize their TLS
# stack (e.g., Cobalt Strike malleable C2 with custom SSL config) will NOT
# match these. This database targets the majority who run defaults.
#
# Sources:
#   - Salesforce JARM research (2020)
#   - Recorded Future C2 tracking
#   - Team Cymru threat intel reports
# ---------------------------------------------------------------------------
KNOWN_C2_JARMS: dict[str, dict] = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": {
        "framework": "Cobalt Strike",
        "confidence": "high",
        "notes": "Default Java JSSE configuration, Cobalt Strike 4.x"
    },
    "07d14d16d21d21d00007d14d16d21d218f67f00557ab8ac975a2abe8c4fe2b": {
        "framework": "Metasploit",
        "confidence": "high",
        "notes": "Default Ruby OpenSSL, Meterpreter HTTPS handler"
    },
    "00000000000000000043d43d00043de2a97eabb398317329f027baae0867a": {
        "framework": "Sliver",
        "confidence": "high",
        "notes": "Default Go crypto/tls — all-zero cipher prefix is Go signature"
    },
    "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": {
        "framework": "Havoc",
        "confidence": "medium",
        "notes": "Boost.Asio + OpenSSL default configuration"
    },
    "07d14d16d21d21d07c42d43d00041d2ef5d10e1457ab3ce4c6c0d3f3f39db": {
        "framework": "Mythic",
        "confidence": "medium",
        "notes": "Python ssl module wrapping OpenSSL, Mythic default profile"
    },
    "1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943": {
        "framework": "Brute Ratel C4",
        "confidence": "medium",
        "notes": "Custom TLS stack, BRC4 default deployment"
    },
}

# ---------------------------------------------------------------------------
# JARM Fingerprinting
# ---------------------------------------------------------------------------

def _jarm_mock(host: str, port: int) -> str:
    """
    Deterministic mock JARM hash for offline/educational use.

    A real JARM implementation sends 10 crafted TLS Client Hello packets,
    each varying TLS version, cipher suite ordering, and extensions. The
    server's selected cipher and ALPN response are recorded per probe, then
    hashed. This mock produces a plausible-looking hash from the host string
    to enable offline demonstration.

    Install jarm-py for real JARM: pip install jarm-py
    """
    # Produce a deterministic 62-char hex string derived from the target.
    # Format mirrors real JARM: 32 chars of cipher tokens + 30 chars of hash.
    seed = f"{host}:{port}".encode()
    h = hashlib.sha256(seed).hexdigest()
    # Real JARM first 32 chars are 10 probes × 3-char cipher tokens (with some 6-char)
    # We simulate with a plausible-looking pattern
    mock_hash = h[:32] + hashlib.md5(seed).hexdigest()[:30]
    return mock_hash


def get_jarm_hash(host: str, port: int = 443) -> tuple[str, bool]:
    """
    Attempt JARM fingerprinting against a target.

    Returns:
        (jarm_hash, is_real) — is_real=False indicates mock/fallback was used.

    Tries the jarm library first. If not installed or if the scan fails
    (e.g., timeout, connection refused), falls back to the deterministic mock.
    The mock is clearly flagged in output so analysts know not to use it for
    real threat intelligence correlation.
    """
    try:
        # jarm-py: pip install jarm-py
        # Scanner.scan() returns a 62-character JARM hash string
        from jarm.scanner.scanner import Scanner  # type: ignore
        result = Scanner.scan(host, port)
        if result and len(result) == 62:
            return result, True
        # Empty result (e.g., host refused all 10 probes) is still valid JARM
        if result is not None:
            return result, True
    except ImportError:
        pass  # Library not installed — use mock
    except Exception:
        pass  # Scan failed (timeout, unreachable) — use mock

    return _jarm_mock(host, port), False


# ---------------------------------------------------------------------------
# JA3-Concept Fingerprinting
# ---------------------------------------------------------------------------

def compute_ja3_concept(cipher_name: str, tls_version: str) -> str:
    """
    Compute a simplified JA3-like fingerprint from post-handshake SSL info.

    IMPORTANT: This is NOT true JA3. Real JA3 requires capturing the raw
    TLS Client Hello packet before the handshake completes — the ssl module
    only exposes the *negotiated* result (what the server selected), not the
    full list of ciphers and extensions the client offered.

    This function demonstrates the fingerprinting concept using the data the
    ssl module does expose. For true JA3, use Zeek with the JA3 plugin, or
    Scapy to capture and parse the Client Hello directly.

    The fingerprint produced here is useful for:
    - Identifying the server's TLS stack (via selected cipher)
    - Detecting unusual cipher/version combinations
    - Demonstrating the MD5-hash pattern used by JA3

    Args:
        cipher_name: The negotiated cipher suite name (e.g., 'ECDHE-RSA-AES256-GCM-SHA384')
        tls_version: The negotiated TLS version string (e.g., 'TLSv1.3')

    Returns:
        MD5 hex digest of the cipher+version string (conceptual JA3-like value)
    """
    # Map TLS version strings to numeric codes used in real JA3
    version_map = {
        "TLSv1":   769,
        "TLSv1.1": 770,
        "TLSv1.2": 771,
        "TLSv1.3": 772,
    }
    version_code = version_map.get(tls_version, 0)

    # Build a simplified fingerprint string — real JA3 uses the full cipher list
    # from the Client Hello, not just the negotiated cipher
    fingerprint_string = f"{version_code},{cipher_name}"
    return hashlib.md5(fingerprint_string.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Certificate Metadata Extraction
# ---------------------------------------------------------------------------

def _connect_tls(host: str, port: int, verify_mode: int, timeout: float = 8.0):
    """
    Helper: open a TLS connection with the given verify mode.

    Returns (secure_sock, raw_sock) on success, raises on failure.
    Caller is responsible for closing both sockets.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = verify_mode

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    ip = socket.gethostbyname(host)
    secure_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    secure_sock.connect((ip, port))
    return secure_sock, raw_sock


def extract_cert_details(host: str, port: int = 443) -> dict:
    """
    Connect to a TLS endpoint and extract certificate metadata.

    Extracts:
    - SHA-256 of the raw DER-encoded certificate (unique per cert issuance)
    - Issuer organization and CN
    - Subject CN and organization
    - Subject Alternative Names (SANs)
    - Validity window (not-before, not-after)
    - Serial number
    - Negotiated TLS version and cipher suite
    - Conceptual JA3-like fingerprint

    Connection strategy (two-pass):
    1. First try ssl.CERT_OPTIONAL — requests cert but does NOT verify it.
       Python's ssl module returns a parsed cert dict with CERT_OPTIONAL,
       giving us issuer/subject/SANs/validity even for self-signed certs.
    2. If CERT_OPTIONAL fails (rare: server rejects non-verified clients),
       fall back to CERT_NONE — still gets the raw DER bytes for SHA-256.

    Why not CERT_NONE directly? With CERT_NONE, ssl.getpeercert() returns
    an empty dict — the parsed fields are unavailable. We get the binary
    cert but cannot extract human-readable fields without the cryptography
    or pyOpenSSL library (not required as dependencies here).
    """
    result: dict = {
        "target": f"{host}:{port}",
        "connected": False,
        "cert_sha256": None,
        "issuer_cn": None,
        "issuer_org": None,
        "subject_cn": None,
        "subject_org": None,
        "sans": [],
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "tls_version": None,
        "cipher_suite": None,
        "ja3_concept": None,
        "error": None,
    }

    # Resolve hostname once, reuse for both passes
    try:
        socket.gethostbyname(host)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        return result

    secure_sock = None
    raw_sock = None

    try:
        # Pass 1: CERT_OPTIONAL — parsed cert dict available
        try:
            secure_sock, raw_sock = _connect_tls(host, port, ssl.CERT_OPTIONAL)
        except (ssl.SSLError, OSError):
            # Fall back to CERT_NONE (no parsed dict, but raw bytes available)
            secure_sock, raw_sock = _connect_tls(host, port, ssl.CERT_NONE)

        result["connected"] = True

        # Negotiated TLS parameters
        cipher_info = secure_sock.cipher()
        if cipher_info:
            result["cipher_suite"] = cipher_info[0]   # e.g., 'TLS_AES_256_GCM_SHA384'
            result["tls_version"] = cipher_info[1]    # e.g., 'TLSv1.3'
            result["ja3_concept"] = compute_ja3_concept(cipher_info[0], cipher_info[1])

        # Raw DER cert for SHA-256 fingerprint (works with any verify mode)
        cert_bin = secure_sock.getpeercert(binary_form=True)
        if cert_bin:
            result["cert_sha256"] = hashlib.sha256(cert_bin).hexdigest()

        # Parsed cert dict (populated by CERT_OPTIONAL; empty with CERT_NONE)
        cert_dict = secure_sock.getpeercert()
        if cert_dict:
            issuer_fields = {k: v for tup in cert_dict.get("issuer", []) for k, v in tup}
            result["issuer_cn"] = issuer_fields.get("commonName")
            result["issuer_org"] = issuer_fields.get("organizationName")

            subject_fields = {k: v for tup in cert_dict.get("subject", []) for k, v in tup}
            result["subject_cn"] = subject_fields.get("commonName")
            result["subject_org"] = subject_fields.get("organizationName")

            sans = cert_dict.get("subjectAltName", [])
            result["sans"] = [v for _, v in sans]

            result["not_before"] = cert_dict.get("notBefore")
            result["not_after"] = cert_dict.get("notAfter")

            serial = cert_dict.get("serialNumber")
            if serial:
                result["serial_number"] = serial

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = f"OS error: {e}"
    finally:
        if secure_sock:
            try:
                secure_sock.close()
            except Exception:
                pass
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------------
# Shodan Correlation
# ---------------------------------------------------------------------------

def _shodan_mock_lookup(jarm_hash: str) -> dict:
    """
    Mock Shodan JARM lookup for offline demonstration.

    A real Shodan lookup uses:
      api = shodan.Shodan(os.environ['SHODAN_API_KEY'])
      results = api.search(f'ssl.jarm:{jarm_hash}')

    This mock returns example output to show what real results look like,
    including the fields analysts care about: IP, port, ASN, country, org.
    """
    return {
        "source": "mock_shodan",
        "query": f"ssl.jarm:{jarm_hash}",
        "total": 3,
        "example_results": [
            {
                "ip_str": "203.0.113.10",
                "port": 443,
                "org": "Example Hosting LLC",
                "asn": "AS64496",
                "country_code": "NL",
                "timestamp": "2026-03-15T12:00:00"
            },
            {
                "ip_str": "198.51.100.22",
                "port": 8443,
                "org": "Example VPS Provider",
                "asn": "AS64497",
                "country_code": "DE",
                "timestamp": "2026-03-14T08:30:00"
            },
        ],
        "note": "Install shodan library and set SHODAN_API_KEY for real results"
    }


def shodan_jarm_lookup(jarm_hash: str) -> dict:
    """
    Look up a JARM hash in Shodan to find other hosts sharing the same fingerprint.

    Requires:
    - pip install shodan
    - SHODAN_API_KEY environment variable set

    Falls back to mock data with instructive example output if either
    prerequisite is missing.

    Shodan query syntax: ssl.jarm:<hash>
    This returns all indexed hosts that responded with the given JARM fingerprint,
    enabling geographic and ASN clustering of related infrastructure.
    """
    api_key = os.environ.get("SHODAN_API_KEY")

    if not api_key:
        return _shodan_mock_lookup(jarm_hash)

    try:
        import shodan  # type: ignore
        api = shodan.Shodan(api_key)
        results = api.search(f"ssl.jarm:{jarm_hash}", limit=10)
        return {
            "source": "shodan_live",
            "query": f"ssl.jarm:{jarm_hash}",
            "total": results.get("total", 0),
            "results": [
                {
                    "ip_str": r.get("ip_str"),
                    "port": r.get("port"),
                    "org": r.get("org"),
                    "asn": r.get("asn"),
                    "country_code": r.get("location", {}).get("country_code"),
                    "timestamp": r.get("timestamp"),
                }
                for r in results.get("matches", [])
            ]
        }
    except ImportError:
        return _shodan_mock_lookup(jarm_hash)
    except Exception as e:
        return {"source": "shodan_error", "error": str(e)}


# ---------------------------------------------------------------------------
# Target Scanning Orchestration
# ---------------------------------------------------------------------------

def scan_target(host: str, port: int = 443, shodan_correlate: bool = False) -> dict:
    """
    Run the full fingerprint collection pipeline for a single target.

    Pipeline:
    1. Extract TLS certificate metadata and concept JA3
    2. Compute JARM fingerprint (real or mock)
    3. Match JARM against local known-C2 database
    4. Optionally correlate JARM with Shodan

    Args:
        host: Hostname or IP address
        port: TLS port (default 443)
        shodan_correlate: If True, query Shodan for JARM correlation

    Returns:
        Dict with all fingerprint fields plus c2_match and shodan fields
    """
    print(f"  [*] Probing {host}:{port}...", end="", flush=True)

    # Step 1: Certificate and cipher details
    result = extract_cert_details(host, port)

    # Step 2: JARM fingerprinting (separate connection, separate probe sequence)
    jarm_hash, jarm_is_real = get_jarm_hash(host, port)
    result["jarm_hash"] = jarm_hash
    result["jarm_is_real"] = jarm_is_real

    # Step 3: Local C2 database match
    c2_match = KNOWN_C2_JARMS.get(jarm_hash)
    result["c2_match"] = c2_match  # None if no match

    # Step 4: Shodan correlation (only if connected or forced)
    if shodan_correlate and jarm_is_real:
        result["shodan"] = shodan_jarm_lookup(jarm_hash)
    elif shodan_correlate:
        # Don't waste Shodan credits on mock hashes
        result["shodan"] = {"note": "Shodan lookup skipped — JARM hash is mock (target unreachable)"}

    # Print status indicator
    if result.get("connected"):
        c2_flag = " [C2 MATCH: {}]".format(c2_match["framework"]) if c2_match else ""
        print(f" connected — {result.get('tls_version', 'unknown')}{c2_flag}")
    else:
        print(f" failed — {result.get('error', 'unknown error')}")

    return result


def load_targets(args) -> list[tuple[str, int]]:
    """
    Parse target list from CLI arguments.

    Priority:
    1. -f / --file: one host[:port] per line
    2. -t / --targets: comma-separated host[:port] values
    3. Default demo targets (hardcoded, always reachable for testing)

    Port defaults to 443 if not specified.
    """
    targets = []

    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.rsplit(":", 1)
                    host = parts[0]
                    port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else args.port
                    targets.append((host, port))
        except FileNotFoundError:
            print(f"[!] Target file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    elif args.targets:
        for entry in args.targets.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else args.port
            targets.append((host, port))

    else:
        # Demo mode: well-known reliable TLS endpoints
        # These are public resolvers and CDN edges — always available for testing
        print("[*] No targets specified — running in demo mode against known-good public TLS servers")
        print("[*] In practice, replace these with suspected C2 IPs from threat intel feeds")
        targets = [
            ("8.8.8.8", 443),     # Google DNS (HTTPS)
            ("1.1.1.1", 443),     # Cloudflare DNS (HTTPS)
            ("example.com", 443), # IANA example domain
        ]

    return targets


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

def format_json(results: list[dict]) -> str:
    """Serialize results to indented JSON using the AIH-C IOC Schema."""
    indicators = []
    for r in results:
        target_ip = r.get("target", "").split(":")[0]
        indicators.append({
            "type": "ip",
            "value": target_ip,
            "context": r
        })
        if r.get("jarm_hash"):
            indicators.append({
                "type": "jarm",
                "value": r.get("jarm_hash"),
                "context": {"target": target_ip, "c2_match": r.get("c2_match")}
            })

    output = {
        "metadata": {
            "source_module": "0x01_tls_fingerprint",
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "indicators": indicators
    }
    return json.dumps(output, indent=2, default=str)


def format_csv(results: list[dict]) -> str:
    """
    Serialize results to CSV.

    Flattens nested fields (c2_match dict, sans list) into string columns.
    """
    if not results:
        return ""

    # Define columns — flatten nested structures
    fieldnames = [
        "target", "connected", "jarm_hash", "jarm_is_real",
        "c2_match_framework", "c2_match_confidence",
        "cert_sha256", "tls_version", "cipher_suite", "ja3_concept",
        "issuer_cn", "issuer_org", "subject_cn", "subject_org",
        "sans", "not_before", "not_after", "serial_number", "error"
    ]

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for r in results:
        flat = dict(r)
        # Flatten c2_match dict
        c2 = r.get("c2_match") or {}
        flat["c2_match_framework"] = c2.get("framework", "")
        flat["c2_match_confidence"] = c2.get("confidence", "")
        # Flatten SANs list to semicolon-separated string
        flat["sans"] = "; ".join(r.get("sans", []))
        writer.writerow(flat)

    return buf.getvalue()


def output_results(results: list[dict], fmt: str, outfile: Optional[str] = None) -> None:
    """
    Write results to stdout or a file in the requested format.

    Args:
        results: List of scan result dicts
        fmt: 'json' or 'csv'
        outfile: Optional file path; if None, writes to stdout
    """
    if fmt == "csv":
        output = format_csv(results)
    else:
        output = format_json(results)

    if outfile:
        with open(outfile, "w") as f:
            f.write(output)
        print(f"\n[+] Results written to {outfile}")
    else:
        print("\n--- Results ---")
        print(output)


# ---------------------------------------------------------------------------
# Summary Reporting
# ---------------------------------------------------------------------------

def print_summary(results: list[dict]) -> None:
    """
    Print a human-readable summary of scan results.

    Highlights:
    - Total targets and connection success rate
    - Any C2 matches from the local database
    - Next steps for Shodan/Censys correlation
    """
    total = len(results)
    connected = sum(1 for r in results if r.get("connected"))
    c2_matches = [r for r in results if r.get("c2_match")]
    real_jarms = sum(1 for r in results if r.get("jarm_is_real"))

    print(f"\n{'='*60}")
    print(f"SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Targets scanned : {total}")
    print(f"  Connected       : {connected}/{total}")
    print(f"  Real JARM hashes: {real_jarms} (mock: {total - real_jarms})")

    if c2_matches:
        print(f"\n  [!] C2 MATCHES DETECTED: {len(c2_matches)}")
        for r in c2_matches:
            match = r["c2_match"]
            print(f"      {r['target']} -> {match['framework']} "
                  f"(confidence: {match['confidence']})")
            print(f"      JARM: {r['jarm_hash']}")
            print(f"      Notes: {match['notes']}")
    else:
        print(f"\n  No known C2 JARM hashes matched in local database")

    if real_jarms > 0:
        print(f"\n  Next steps:")
        print(f"  1. Feed JARM hashes to Shodan: ssl.jarm:<hash>")
        print(f"  2. Feed JARM hashes to Censys: services.tls.jarm_fingerprint:<hash>")
        print(f"  3. Check cert SHA-256 against SSLBL: https://sslbl.abuse.ch")
        print(f"  4. Pivot on ASN/org in Module 0x03 (Overlap Clustering)")
    else:
        print(f"\n  Note: All JARM hashes are mocks (targets unreachable or jarm-py not installed)")
        print(f"  Install jarm-py for real fingerprinting: pip install jarm-py")

    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with educational help text."""
    parser = argparse.ArgumentParser(
        description=(
            "TLS Structural Fingerprinter — Module 0x01 Capstone\n"
            "Extracts JARM, JA3-concept, and certificate fingerprints\n"
            "for adversary infrastructure hunting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python tls_fingerprint.py                        # Demo mode\n"
            "  python tls_fingerprint.py -t 1.2.3.4             # Single target\n"
            "  python tls_fingerprint.py -t 1.2.3.4,5.6.7.8    # Multiple\n"
            "  python tls_fingerprint.py -f ips.txt             # From file\n"
            "  python tls_fingerprint.py -t 1.2.3.4 -o out.csv --format csv\n"
            "\n"
            "Set SHODAN_API_KEY env var to enable Shodan JARM correlation.\n"
            "Install jarm-py for real JARM fingerprinting: pip install jarm-py\n"
        )
    )

    parser.add_argument(
        "-t", "--targets",
        metavar="TARGETS",
        help="Comma-separated list of host[:port] targets"
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="File with one host[:port] per line"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="Default port if not specified per-target (default: 443)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format: json (default) or csv"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout"
    )
    parser.add_argument(
        "--shodan",
        action="store_true",
        help="Correlate JARM hashes with Shodan (requires SHODAN_API_KEY; uses mock if absent)"
    )
    parser.add_argument(
        "--list-c2-db",
        action="store_true",
        help="Print the local known-C2 JARM database and exit"
    )

    return parser


def main() -> None:
    """
    Main entry point.

    Flow:
    1. Parse CLI arguments
    2. Load target list
    3. Scan each target (cert + JARM + C2 match)
    4. Output results in requested format
    5. Print human-readable summary
    """
    parser = build_parser()
    args = parser.parse_args()

    # Show C2 database and exit
    if args.list_c2_db:
        print("\nKnown C2 JARM Hash Database")
        print("=" * 60)
        for jarm, info in KNOWN_C2_JARMS.items():
            print(f"\nFramework : {info['framework']}")
            print(f"Confidence: {info['confidence']}")
            print(f"JARM Hash : {jarm}")
            print(f"Notes     : {info['notes']}")
        print()
        return

    print("\n[*] TLS Structural Fingerprinter — Module 0x01")
    print(f"[*] Timestamp: {datetime.now(timezone.utc).isoformat()}")

    # Check for optional dependencies and advise
    try:
        import jarm  # noqa: F401
        print("[+] jarm-py detected — real JARM fingerprinting enabled")
    except ImportError:
        print("[!] jarm-py not installed — using mock JARM hashes (pip install jarm-py for real)")

    if os.environ.get("SHODAN_API_KEY"):
        print("[+] SHODAN_API_KEY detected — Shodan correlation enabled")
    elif args.shodan:
        print("[!] --shodan flag set but SHODAN_API_KEY not set — using mock Shodan data")

    print()

    # Load targets
    targets = load_targets(args)
    print(f"[*] Scanning {len(targets)} target(s)...\n")

    # Scan each target
    results = []
    for host, port in targets:
        result = scan_target(host, port, shodan_correlate=args.shodan)
        results.append(result)

    # Output results
    output_results(results, args.format, args.output)

    # Human-readable summary
    print_summary(results)


if __name__ == "__main__":
    main()
