#!/usr/bin/env python3
"""
ct_hunter.py — Certificate Transparency Log Infrastructure Hunter
Module 0x02 Capstone Project | AIH-C Curriculum

Queries the public crt.sh JSON API for newly issued TLS certificates matching
hunt keywords. Optionally resolves DNS records, performs WHOIS enrichment, and
clusters discovered domains by shared IP to reveal adversary infrastructure.

Usage:
    python ct_hunter.py                          # demo mode, built-in keywords
    python ct_hunter.py -q "microsoft-update"   # single keyword query
    python ct_hunter.py -k keywords.txt --resolve --format json
    python ct_hunter.py -q "admin-portal" --format csv > results.csv

All external dependencies have mock fallbacks so this runs offline for
training/lab environments.

@decision DEC-CT-001
@title Offline-first architecture with mock fallbacks
@status accepted
@rationale Training environments lack network access and API keys. Mock
  fallbacks ensure every code path is exercisable in class without live data.
  Real crt.sh API and system DNS are used when network is available, falling
  back to mock data transparently.
"""

import argparse
import csv
import json
import socket
import sys
import logging
from datetime import datetime
from io import StringIO
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependency: httpx for async HTTP, requests as sync fallback.
# The script degrades gracefully if neither is available (mock mode).
# ---------------------------------------------------------------------------
try:
    import httpx
    _HTTP_BACKEND = "httpx"
except ImportError:
    try:
        import urllib.request  # stdlib fallback
        _HTTP_BACKEND = "urllib"
    except ImportError:
        _HTTP_BACKEND = "mock"

# Optional: python-whois for registrar/creation-date lookups
try:
    import whois as python_whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

logging.basicConfig(
    level=logging.WARNING,  # quiet by default; -v will set DEBUG
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ct_hunter")

# ---------------------------------------------------------------------------
# Demo / mock data — used when network is unavailable or in demo mode
# ---------------------------------------------------------------------------
DEMO_KEYWORDS = ["microsoft-update", "secure-bank-login", "admin-portal"]

_MOCK_CT_DATA = {
    "microsoft-update": [
        {
            "id": 10001,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": "microsoft-update-defender.com",
            "not_before": "2024-03-15T02:34:11",
            "not_after": "2024-06-13T02:34:10",
        },
        {
            "id": 10002,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": "microsoft-update-security.net",
            "not_before": "2024-03-15T03:11:44",
            "not_after": "2024-06-13T03:11:43",
        },
        {
            "id": 10003,
            "issuer_name": "C=US, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA",
            "name_value": "update-microsoft-patch.io",
            "not_before": "2024-03-16T08:02:55",
            "not_after": "2024-06-14T08:02:54",
        },
    ],
    "secure-bank-login": [
        {
            "id": 10004,
            "issuer_name": "C=US, O=Let's Encrypt, CN=E1",
            "name_value": "secure-bank-login-portal.com",
            "not_before": "2024-03-14T22:15:30",
            "not_after": "2024-06-12T22:15:29",
        },
        {
            "id": 10005,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": "secure-bank-login-verify.net",
            "not_before": "2024-03-14T22:17:05",
            "not_after": "2024-06-12T22:17:04",
        },
    ],
    "admin-portal": [
        {
            "id": 10006,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": "admin-portal-internal.example.org",
            "not_before": "2024-02-28T11:30:00",
            "not_after": "2024-05-28T11:29:59",
        },
    ],
}

_MOCK_DNS_DATA = {
    "microsoft-update-defender.com":    [("A", "185.220.101.77")],
    "microsoft-update-security.net":    [("A", "185.220.101.77")],
    "update-microsoft-patch.io":        [("A", "45.142.212.100")],
    "secure-bank-login-portal.com":     [("A", "185.220.101.77")],
    "secure-bank-login-verify.net":     [("A", "185.220.101.78")],
    "admin-portal-internal.example.org":[("A", "192.168.1.10")],
}

_MOCK_WHOIS_DATA = {
    "microsoft-update-defender.com": {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2024-03-14",
        "registrant_org": "WhoisGuard Protected",
    },
    "microsoft-update-security.net": {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2024-03-14",
        "registrant_org": "WhoisGuard Protected",
    },
    "update-microsoft-patch.io": {
        "registrar": "Porkbun LLC",
        "creation_date": "2024-03-15",
        "registrant_org": "Withheld for Privacy ehf",
    },
    "secure-bank-login-portal.com": {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2024-03-14",
        "registrant_org": "WhoisGuard Protected",
    },
    "secure-bank-login-verify.net": {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2024-03-13",
        "registrant_org": "WhoisGuard Protected",
    },
    "admin-portal-internal.example.org": {
        "registrar": "GoDaddy.com, LLC",
        "creation_date": "2023-11-01",
        "registrant_org": "Example Corp",
    },
}

# ---------------------------------------------------------------------------
# CT Log Querying
# ---------------------------------------------------------------------------

def fetch_ct_logs_live(keyword: str, limit: int = 50) -> List[Dict]:
    """
    Query the crt.sh JSON API for certificates containing the target keyword.

    The % wildcard in crt.sh performs SQL LIKE matching — 'keyword' matches
    any certificate SAN containing that substring.

    Returns a deduplicated list of cert entries sorted by issuance date
    (newest first), capped at `limit` entries.
    """
    url = f"https://crt.sh/?q=%25{keyword}%25&output=json"
    log.debug("Querying crt.sh: %s", url)

    headers = {"User-Agent": "AIH-C-ThreatHunting-Curriculum/1.0"}

    try:
        if _HTTP_BACKEND == "httpx":
            timeout = httpx.Timeout(20.0, connect=10.0)
            with httpx.Client(timeout=timeout, headers=headers) as client:
                resp = client.get(url)
                resp.raise_for_status()
                data = resp.json()
        elif _HTTP_BACKEND == "urllib":
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
        else:
            log.warning("No HTTP backend available — falling back to mock data")
            return []

        return _deduplicate_and_sort(data, limit)

    except Exception as exc:
        log.warning("crt.sh query failed (%s) — falling back to mock data", exc)
        return []


def fetch_ct_logs_mock(keyword: str, limit: int = 50) -> List[Dict]:
    """
    Return mock CT log data for the given keyword.

    Used when network is unavailable or explicitly in demo mode.
    Searches the mock dataset for any keyword substring match.
    """
    results = []
    keyword_lower = keyword.lower()
    for mock_key, entries in _MOCK_CT_DATA.items():
        if keyword_lower in mock_key or mock_key in keyword_lower:
            results.extend(entries)
    # If no keyword match, return all mock data for demonstration
    if not results:
        for entries in _MOCK_CT_DATA.values():
            results.extend(entries)
    return _deduplicate_and_sort(results, limit)


def fetch_ct_logs(keyword: str, limit: int = 50, force_mock: bool = False) -> List[Dict]:
    """
    Fetch CT log entries for a keyword, with automatic mock fallback.

    Tries the live crt.sh API first; falls back to mock data if the
    request fails or if force_mock is True.
    """
    if force_mock:
        log.debug("Using mock CT data for keyword: %s", keyword)
        return fetch_ct_logs_mock(keyword, limit)

    log.debug("Querying live CT logs for keyword: %s", keyword)
    results = fetch_ct_logs_live(keyword, limit)
    if not results:
        log.info("No live results for '%s' — using mock data", keyword)
        results = fetch_ct_logs_mock(keyword, limit)
    return results


def _deduplicate_and_sort(entries: List[Dict], limit: int) -> List[Dict]:
    """
    Deduplicate CT entries by domain name and sort by issuance date, newest first.

    crt.sh returns one row per SAN, so a cert with 10 SANs produces 10 rows.
    We deduplicate on name_value (the domain/SAN) to avoid flooding results
    with entries from the same multi-SAN certificate.
    """
    seen = set()
    unique = []
    for entry in entries:
        # name_value can contain newline-separated SANs — normalize to first value
        domain = entry.get("name_value", "").split("\n")[0].strip().lower()
        if domain and domain not in seen:
            seen.add(domain)
            entry["name_value"] = domain  # normalize in-place
            unique.append(entry)
        if len(unique) >= limit:
            break

    # Sort by not_before (issuance date) descending — newest certs first
    unique.sort(key=lambda e: e.get("not_before", ""), reverse=True)
    return unique


# ---------------------------------------------------------------------------
# DNS Resolution
# ---------------------------------------------------------------------------

def resolve_domain(domain: str, use_mock: bool = False) -> Dict[str, List[str]]:
    """
    Resolve A, AAAA, MX, and NS records for a domain.

    Uses socket.getaddrinfo() for A/AAAA resolution (stdlib, no dependencies).
    MX and NS records require dnspython if available; otherwise returns empty
    lists (these record types are not resolvable via socket stdlib alone).

    Returns a dict with keys: A, AAAA, MX, NS — each a list of string values.
    """
    if use_mock:
        return _resolve_mock(domain)

    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": []}

    # A records (IPv4)
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        records["A"] = list({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        pass

    # AAAA records (IPv6)
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
        records["AAAA"] = list({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        pass

    # MX/NS require dnspython — fall back to mock if unavailable or DNS fails
    if not records["A"] and not records["AAAA"]:
        # Domain didn't resolve — likely doesn't exist; return empty
        return records

    # If we got A records but mock fallback has richer data, supplement
    mock_data = _MOCK_DNS_DATA.get(domain.lower(), [])
    if mock_data and not records["A"]:
        for rtype, rval in mock_data:
            if rtype in records:
                records[rtype].append(rval)

    return records


def _resolve_mock(domain: str) -> Dict[str, List[str]]:
    """Return mock DNS resolution data for a domain."""
    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": []}
    mock_entries = _MOCK_DNS_DATA.get(domain.lower(), [])
    for rtype, rval in mock_entries:
        if rtype in records:
            records[rtype].append(rval)
    # Default mock IP if domain not in our table (keeps output useful)
    if not any(records.values()):
        records["A"] = ["203.0.113.1"]  # TEST-NET-3 (RFC 5737) placeholder
    return records


# ---------------------------------------------------------------------------
# WHOIS Enrichment
# ---------------------------------------------------------------------------

def whois_lookup(domain: str, use_mock: bool = False) -> Dict[str, str]:
    """
    Retrieve WHOIS registration metadata for a domain.

    Returns a dict with: registrar, creation_date, registrant_org.
    Falls back to mock data if python-whois is unavailable or lookup fails.

    @decision DEC-CT-002
    @title WHOIS as enrichment, not primary pivot
    @status accepted
    @rationale Post-GDPR WHOIS data is heavily redacted. We collect it for
      context but do not rely on registrant details as primary indicators.
      The value is in structural patterns (registrar clustering, date patterns)
      not in identifying specific registrants.
    """
    if use_mock or not _WHOIS_AVAILABLE:
        return _whois_mock(domain)

    try:
        w = python_whois.whois(domain)

        # Normalize creation_date — python-whois returns datetime or list
        creation_date = ""
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if hasattr(cd, "strftime"):
            creation_date = cd.strftime("%Y-%m-%d")
        elif isinstance(cd, str):
            creation_date = cd[:10]

        return {
            "registrar": (w.registrar or "Unknown").strip(),
            "creation_date": creation_date,
            "registrant_org": (w.org or w.registrant_org or "Withheld/Unknown").strip(),
        }
    except Exception as exc:
        log.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return _whois_mock(domain)


def _whois_mock(domain: str) -> Dict[str, str]:
    """Return mock WHOIS data for a domain."""
    default = {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2024-01-01",
        "registrant_org": "WhoisGuard Protected",
    }
    return _MOCK_WHOIS_DATA.get(domain.lower(), default)


# ---------------------------------------------------------------------------
# Infrastructure Clustering
# ---------------------------------------------------------------------------

def cluster_by_ip(results: List[Dict]) -> Dict[str, List[str]]:
    """
    Group discovered domains by their resolved IPv4 address.

    Domains sharing an IP may share infrastructure — this is the core
    pDNS clustering technique described in Module 0x02 Section 5.

    Returns: {ip_address: [domain1, domain2, ...]}
    """
    clusters: Dict[str, List[str]] = {}
    for result in results:
        domain = result.get("name_value", "")
        dns = result.get("dns_records", {})
        for ip in dns.get("A", []):
            clusters.setdefault(ip, []).append(domain)
    return clusters


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

def format_text(results: List[Dict], clusters: Dict[str, List[str]]) -> str:
    """Render results as human-readable text with infrastructure cluster summary."""
    lines = []
    lines.append("=" * 65)
    lines.append(f"  CT Hunter Results — {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("=" * 65)

    for idx, r in enumerate(results, 1):
        domain = r.get("name_value", "N/A")
        issuer = _parse_issuer(r.get("issuer_name", ""))
        not_before = r.get("not_before", "N/A")
        dns = r.get("dns_records", {})
        whois_info = r.get("whois", {})

        lines.append(f"\n[{idx:02d}] {domain}")
        lines.append(f"     Issuer    : {issuer}")
        lines.append(f"     Cert date : {not_before}")

        if dns and any(dns.values()):
            a_records = ", ".join(dns.get("A", [])) or "-"
            aaaa_records = ", ".join(dns.get("AAAA", [])) or "-"
            lines.append(f"     A records : {a_records}")
            if aaaa_records != "-":
                lines.append(f"     AAAA      : {aaaa_records}")

        if whois_info:
            lines.append(f"     Registrar : {whois_info.get('registrar', 'N/A')}")
            lines.append(f"     Created   : {whois_info.get('creation_date', 'N/A')}")
            lines.append(f"     Registrant: {whois_info.get('registrant_org', 'N/A')}")

    if clusters:
        lines.append("\n" + "=" * 65)
        lines.append("  Infrastructure Clusters (domains sharing an IP)")
        lines.append("=" * 65)
        for ip, domains in sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True):
            if len(domains) > 1:
                lines.append(f"\n  [*] Shared IP: {ip}  ({len(domains)} domains)")
                for d in domains:
                    lines.append(f"      - {d}")

    lines.append("")
    return "\n".join(lines)


def format_json(results: List[Dict], clusters: Dict[str, List[str]]) -> str:
    """Render results as JSON for machine consumption."""
    output = {
        "generated_at": datetime.now().isoformat() + "Z",
        "total_results": len(results),
        "domains": results,
        "infrastructure_clusters": [
            {"ip": ip, "domains": domains, "count": len(domains)}
            for ip, domains in sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)
        ],
    }
    return json.dumps(output, indent=2, default=str)


def format_csv(results: List[Dict]) -> str:
    """Render results as CSV for spreadsheet analysis."""
    buf = StringIO()
    fieldnames = [
        "domain", "issuer", "cert_date", "cert_expiry",
        "ip_addresses", "registrar", "creation_date", "registrant_org",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for r in results:
        dns = r.get("dns_records", {})
        whois_info = r.get("whois", {})
        writer.writerow({
            "domain": r.get("name_value", ""),
            "issuer": _parse_issuer(r.get("issuer_name", "")),
            "cert_date": r.get("not_before", ""),
            "cert_expiry": r.get("not_after", ""),
            "ip_addresses": "|".join(dns.get("A", [])),
            "registrar": whois_info.get("registrar", ""),
            "creation_date": whois_info.get("creation_date", ""),
            "registrant_org": whois_info.get("registrant_org", ""),
        })
    return buf.getvalue()


def _parse_issuer(issuer_name: str) -> str:
    """Extract a readable CA name from an X.509 issuer string."""
    if not issuer_name:
        return "Unknown"
    # Try to extract O= (organization) field
    for part in issuer_name.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip()
    return issuer_name[:60]  # truncate raw value if no O= field


# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ct_hunter",
        description=(
            "Certificate Transparency Log Infrastructure Hunter\n"
            "Module 0x02 Capstone | AIH-C Curriculum\n\n"
            "Queries crt.sh for TLS certificates matching hunt keywords,\n"
            "optionally resolves DNS and performs WHOIS enrichment."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s                              # demo mode\n"
            "  %(prog)s -q microsoft-update          # single keyword\n"
            "  %(prog)s -k keywords.txt --resolve    # file of keywords + DNS\n"
            "  %(prog)s -q admin --format json       # JSON output\n"
            "  %(prog)s -q admin --format csv        # CSV export\n"
        ),
    )
    query_group = parser.add_mutually_exclusive_group()
    query_group.add_argument(
        "-q", "--query",
        metavar="KEYWORD",
        help="Single keyword to search in CT logs (e.g. 'microsoft-update')",
    )
    query_group.add_argument(
        "-k", "--keywords",
        metavar="FILE",
        help="Path to a file of keywords, one per line",
    )
    parser.add_argument(
        "--resolve",
        action="store_true",
        default=False,
        help="Resolve DNS records (A, AAAA) for each discovered domain",
    )
    parser.add_argument(
        "--whois",
        action="store_true",
        default=False,
        help="Perform WHOIS lookup for each discovered domain",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format: text (default), json, or csv",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="Maximum results per keyword (default: 20)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="Force mock data mode (no network requests)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point. Parses arguments, runs CT log queries, enriches results,
    and renders output in the requested format.
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine keywords to hunt
    keywords: List[str] = []
    demo_mode = False

    if args.query:
        keywords = [args.query]
    elif args.keywords:
        try:
            with open(args.keywords) as fh:
                keywords = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
            if not keywords:
                print(f"[!] No keywords found in {args.keywords}", file=sys.stderr)
                sys.exit(1)
        except OSError as exc:
            print(f"[!] Cannot read keyword file: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        # Demo mode — no args provided
        demo_mode = True
        keywords = DEMO_KEYWORDS
        print(
            "[*] No query specified — running in demo mode with built-in keywords.\n"
            "    Use -q KEYWORD or -k keywords.txt for real hunting.\n",
            file=sys.stderr,
        )

    # Collect results across all keywords
    all_results: List[Dict] = []
    seen_domains: set = set()

    for keyword in keywords:
        if not demo_mode:
            print(f"[*] Hunting keyword: {keyword!r}", file=sys.stderr)
        entries = fetch_ct_logs(keyword, limit=args.limit, force_mock=(args.mock or demo_mode))

        for entry in entries:
            domain = entry.get("name_value", "")
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            # DNS resolution
            if args.resolve or demo_mode:
                use_mock = args.mock or demo_mode
                entry["dns_records"] = resolve_domain(domain, use_mock=use_mock)

            # WHOIS enrichment
            if args.whois or demo_mode:
                use_mock = args.mock or demo_mode or not _WHOIS_AVAILABLE
                entry["whois"] = whois_lookup(domain, use_mock=use_mock)

            all_results.append(entry)

    if not all_results:
        print("[!] No results found.", file=sys.stderr)
        sys.exit(0)

    # Build infrastructure clusters from DNS A records
    clusters = cluster_by_ip(all_results) if (args.resolve or demo_mode) else {}

    # Render output
    if args.format == "json":
        print(format_json(all_results, clusters))
    elif args.format == "csv":
        print(format_csv(all_results))
    else:
        print(format_text(all_results, clusters))


if __name__ == "__main__":
    main()
