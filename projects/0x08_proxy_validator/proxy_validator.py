#!/usr/bin/env python3
"""
Module 0x08 Capstone Project: Advanced Proxy & ASN Validator
Educational reference implementation for adversary infrastructure hunting.

Usage:
    python proxy_validator.py                        # mock demo mode
    python proxy_validator.py -t 45.32.228.0         # single IP
    python proxy_validator.py -t 1.1.1.1,8.8.8.8    # comma-separated
    python proxy_validator.py -f ips.txt             # file input
    python proxy_validator.py -t 45.32.228.0 --deep  # include BGP analysis
    python proxy_validator.py --cidr 45.32.228.0/24  # CIDR range analysis
    python proxy_validator.py -t 1.1.1.1 --format json
    python proxy_validator.py -t 1.1.1.1 --format csv

@decision DEC-0x08-001
@title Local-first lookup with graceful API fallback
@status accepted
@rationale Querying external APIs with investigative targets is an OPSEC risk —
    it attributes your investigation to your IP/API key and may alert the target.
    MaxMind GeoLite2 is checked first (local, no network), then ip-api.com as
    fallback, then synthetic mock data. The tool always produces output.

@decision DEC-0x08-002
@title Composite risk scoring (0-100) over binary classification
@status accepted
@rationale Binary datacenter/residential misses nuance. A datacenter IP on a
    known-bad ASN that is Spamhaus-listed and proxy-flagged is fundamentally
    different from a datacenter IP hosting a legitimate SaaS. The composite
    score weights each signal independently so analysts can tune thresholds.
"""

import argparse
import csv
import ipaddress
import json
import sys
import time
from io import StringIO
from typing import Optional

# ---------------------------------------------------------------------------
# Optional import: geoip2 (MaxMind GeoLite2)
# ---------------------------------------------------------------------------
try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# ---------------------------------------------------------------------------
# Optional import: requests (for live API fallback)
# ---------------------------------------------------------------------------
try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Known ASN database
# Key: ASN number (int). Value: dict with provider name and classification.
#
# @decision DEC-0x08-003
# @title Static known-ASN dict for offline classification
# @status accepted
# @rationale A small curated dict of high-signal ASNs enables offline risk
#     scoring without any API dependency. This covers the most commonly
#     abused VPS providers and major residential ISPs for baseline confidence.
# ---------------------------------------------------------------------------
KNOWN_ASNS: dict[int, dict] = {
    # --- Commercial VPS / Cloud (Datacenter) ---
    14061:  {"name": "DigitalOcean",       "type": "datacenter", "risk": "medium"},
    20473:  {"name": "Choopa/Vultr",        "type": "datacenter", "risk": "high"},
    16276:  {"name": "OVH SAS",             "type": "datacenter", "risk": "medium"},
    24940:  {"name": "Hetzner Online",      "type": "datacenter", "risk": "medium"},
    16509:  {"name": "Amazon AWS",          "type": "datacenter", "risk": "low"},
    15169:  {"name": "Google Cloud",        "type": "datacenter", "risk": "low"},
    8075:   {"name": "Microsoft Azure",     "type": "datacenter", "risk": "low"},
    13335:  {"name": "Cloudflare",          "type": "cdn",        "risk": "low"},
    54113:  {"name": "Fastly CDN",          "type": "cdn",        "risk": "low"},
    # --- Bulletproof / Abuse-permissive ---
    9009:   {"name": "M247 Ltd",            "type": "bulletproof", "risk": "high"},
    202425: {"name": "IP Volume/Serverius", "type": "bulletproof", "risk": "high"},
    59729:  {"name": "NForce Entertainment","type": "bulletproof", "risk": "high"},
    36352:  {"name": "ColoCrossing",        "type": "bulletproof", "risk": "high"},
    62282:  {"name": "xTom GmbH",           "type": "datacenter", "risk": "high"},
    # --- Residential ISPs (US) ---
    7922:   {"name": "Comcast",             "type": "residential", "risk": "low"},
    20001:  {"name": "Charter/Spectrum",    "type": "residential", "risk": "low"},
    7018:   {"name": "AT&T",               "type": "residential", "risk": "low"},
    701:    {"name": "Verizon",             "type": "residential", "risk": "low"},
    # --- Residential ISPs (EU) ---
    2856:   {"name": "BT UK",              "type": "residential", "risk": "low"},
    3209:   {"name": "Vodafone DE",         "type": "residential", "risk": "low"},
    # --- Known proxy/VPN ASNs ---
    9299:   {"name": "Bright Data (Luminati)","type": "proxy",    "risk": "high"},
    22552:  {"name": "Zenlayer",            "type": "proxy",      "risk": "medium"},
    394711: {"name": "PacketHub",           "type": "proxy",      "risk": "high"},
}

# ---------------------------------------------------------------------------
# Spamhaus DROP/EDROP mock entries
# In production: download from https://www.spamhaus.org/drop/drop.txt
# and https://www.spamhaus.org/drop/edrop.txt
# ---------------------------------------------------------------------------
SPAMHAUS_DROP_MOCK: list[str] = [
    "185.220.100.0/22",   # Tor exit / abuse
    "45.142.212.0/22",    # Known C2 hosting range
    "194.165.16.0/22",    # Bulletproof hosting
    "91.108.56.0/22",     # Known abuse range
    "5.188.206.0/24",     # Historical botnet range
]

# ---------------------------------------------------------------------------
# Synthetic mock data for demo / offline mode
# Represents a realistic mix: residential, datacenter, proxy, VPN, Tor exit
# ---------------------------------------------------------------------------
MOCK_DATABASE: dict[str, dict] = {
    "104.16.0.0": {
        "asn": 13335, "asn_name": "Cloudflare Inc",
        "country": "US", "isp": "Cloudflare, Inc.",
        "is_datacenter": True, "is_mobile": False,
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "city": "San Francisco", "proxy_score": 0,
    },
    "172.217.164.110": {
        "asn": 15169, "asn_name": "Google LLC",
        "country": "US", "isp": "Google LLC",
        "is_datacenter": True, "is_mobile": False,
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "city": "Mountain View", "proxy_score": 0,
    },
    "76.102.103.104": {
        "asn": 7922, "asn_name": "Comcast Cable",
        "country": "US", "isp": "Comcast Cable Communications",
        "is_datacenter": False, "is_mobile": False,
        "is_proxy": True, "is_vpn": False, "is_tor": False,
        "city": "Chicago", "proxy_score": 72,
    },
    "45.32.228.0": {
        "asn": 20473, "asn_name": "AS-CHOOPA",
        "country": "US", "isp": "Choopa, LLC",
        "is_datacenter": True, "is_mobile": False,
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "city": "Miami", "proxy_score": 15,
    },
    "185.220.101.50": {
        "asn": 205100, "asn_name": "F3 Netze e.V.",
        "country": "DE", "isp": "F3 Netze e.V.",
        "is_datacenter": True, "is_mobile": False,
        "is_proxy": True, "is_vpn": False, "is_tor": True,
        "city": "Frankfurt", "proxy_score": 98,
    },
    "77.90.185.100": {
        "asn": 9009, "asn_name": "M247 Ltd",
        "country": "RO", "isp": "M247 Ltd",
        "is_datacenter": True, "is_mobile": False,
        "is_proxy": True, "is_vpn": True, "is_tor": False,
        "city": "Bucharest", "proxy_score": 88,
    },
    "86.104.194.20": {
        "asn": 202425, "asn_name": "IP Volume inc",
        "country": "NL", "isp": "IP Volume inc",
        "is_datacenter": True, "is_mobile": False,
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "city": "Amsterdam", "proxy_score": 30,
    },
    "94.102.49.200": {
        "asn": 9299, "asn_name": "Bright Data Network",
        "country": "US", "isp": "Bright Data Ltd",
        "is_datacenter": False, "is_mobile": False,
        "is_proxy": True, "is_vpn": False, "is_tor": False,
        "city": "Los Angeles", "proxy_score": 95,
    },
    "10.0.0.1": {
        "asn": 0, "asn_name": "RFC1918 Private",
        "country": "ZZ", "isp": "Private Network",
        "is_datacenter": False, "is_mobile": False,
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "city": "Private", "proxy_score": 0,
    },
}

# BGPView mock responses for --deep mode
MOCK_BGP_DATABASE: dict[int, dict] = {
    13335: {
        "name": "CLOUDFLARENET",
        "description": "Cloudflare, Inc.",
        "website": "https://www.cloudflare.com",
        "prefix_count": 1847,
        "country": "US",
        "rir": "ARIN",
        "peers_v4": 7400,
    },
    20473: {
        "name": "AS-CHOOPA",
        "description": "Choopa, LLC — Vultr Holdings LLC",
        "website": "https://www.vultr.com",
        "prefix_count": 312,
        "country": "US",
        "rir": "ARIN",
        "peers_v4": 890,
    },
    9009: {
        "name": "M247",
        "description": "M247 Ltd — Transit and hosting, frequent abuse complaints",
        "website": "https://m247.com",
        "prefix_count": 428,
        "country": "GB",
        "rir": "RIPE",
        "peers_v4": 620,
    },
    7922: {
        "name": "COMCAST-7922",
        "description": "Comcast Cable Communications, LLC",
        "website": "https://www.comcast.com",
        "prefix_count": 3102,
        "country": "US",
        "rir": "ARIN",
        "peers_v4": 210,
    },
}


# ---------------------------------------------------------------------------
# IP Intelligence lookup — local GeoIP2 → ip-api.com → mock
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    """Return True if IP is RFC1918 / loopback / link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def lookup_geoip2(ip: str, asn_db_path: str = "GeoLite2-ASN.mmdb",
                  city_db_path: str = "GeoLite2-City.mmdb") -> Optional[dict]:
    """
    Query MaxMind GeoLite2 local databases.
    Returns None if geoip2 is not installed or databases are not present.

    @decision DEC-0x08-001 (see module docstring)
    """
    if not GEOIP2_AVAILABLE:
        return None
    result = {"asn": 0, "asn_name": "Unknown", "country": "ZZ",
              "isp": "Unknown", "city": "Unknown",
              "is_datacenter": False, "is_mobile": False,
              "is_proxy": False, "is_vpn": False, "is_tor": False,
              "proxy_score": 0}
    try:
        with geoip2.database.Reader(asn_db_path) as reader:
            r = reader.asn(ip)
            result["asn"] = r.autonomous_system_number or 0
            result["asn_name"] = r.autonomous_system_organization or "Unknown"
    except Exception:
        return None  # database file not present; fall through to API

    try:
        with geoip2.database.Reader(city_db_path) as reader:
            r = reader.city(ip)
            result["country"] = r.country.iso_code or "ZZ"
            result["city"] = r.city.name or "Unknown"
    except Exception:
        pass  # city DB optional; ASN is sufficient for classification

    result["isp"] = result["asn_name"]

    # Augment with known ASN classification
    known = KNOWN_ASNS.get(result["asn"])
    if known:
        result["is_datacenter"] = known["type"] in ("datacenter", "cdn", "bulletproof")
        result["is_proxy"] = known["type"] in ("proxy",)

    return result


def lookup_ipapi(ip: str) -> Optional[dict]:
    """
    Query ip-api.com for IP intelligence. Rate-limited to ~45 req/min.
    Returns None on failure.
    """
    if not REQUESTS_AVAILABLE:
        return None
    url = (f"http://ip-api.com/json/{ip}"
           f"?fields=status,message,country,isp,org,as,mobile,proxy,hosting,city")
    try:
        resp = _requests.get(url, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    if data.get("status") != "success":
        return None

    asn_str = data.get("as", "AS0 Unknown")
    try:
        asn_num = int(asn_str.split()[0].replace("AS", ""))
    except (ValueError, IndexError):
        asn_num = 0

    return {
        "asn": asn_num,
        "asn_name": asn_str,
        "country": data.get("country", "ZZ"),
        "isp": data.get("isp", "Unknown"),
        "city": data.get("city", "Unknown"),
        "is_datacenter": data.get("hosting", False),
        "is_mobile": data.get("mobile", False),
        "is_proxy": data.get("proxy", False),
        "is_vpn": False,   # ip-api free tier does not distinguish VPN
        "is_tor": False,
        "proxy_score": 0,
    }


def lookup_mock(ip: str) -> dict:
    """
    Return synthetic mock data for demo/offline mode.
    If the exact IP is not in the mock database, generate a plausible entry.
    """
    if ip in MOCK_DATABASE:
        return dict(MOCK_DATABASE[ip])

    # Generate a deterministic pseudo-random entry for unknown IPs
    ip_hash = sum(int(o) for o in ip.split(".") if o.isdigit())
    types = [
        {"asn": 14061, "asn_name": "DigitalOcean", "country": "NL",
         "isp": "DigitalOcean, LLC", "city": "Amsterdam",
         "is_datacenter": True, "is_mobile": False,
         "is_proxy": False, "is_vpn": False, "is_tor": False, "proxy_score": 10},
        {"asn": 7922, "asn_name": "Comcast Cable", "country": "US",
         "isp": "Comcast Cable Communications", "city": "Denver",
         "is_datacenter": False, "is_mobile": False,
         "is_proxy": False, "is_vpn": False, "is_tor": False, "proxy_score": 0},
        {"asn": 9009, "asn_name": "M247 Ltd", "country": "RO",
         "isp": "M247 Ltd", "city": "Bucharest",
         "is_datacenter": True, "is_mobile": False,
         "is_proxy": True, "is_vpn": True, "is_tor": False, "proxy_score": 82},
    ]
    return dict(types[ip_hash % len(types)])


def get_ip_intelligence(ip: str, use_mock: bool = False) -> dict:
    """
    Main lookup dispatcher. Tries: GeoIP2 local → ip-api.com → mock.
    Always returns a result dict — never raises.
    """
    if use_mock or _is_private(ip):
        return lookup_mock(ip)

    result = lookup_geoip2(ip)
    if result:
        return result

    result = lookup_ipapi(ip)
    if result:
        time.sleep(1.2)   # respect ip-api free tier rate limit
        return result

    return lookup_mock(ip)


# ---------------------------------------------------------------------------
# BGP / ASN enrichment via BGPView API
# ---------------------------------------------------------------------------

def get_bgp_asn_details(asn: int, use_mock: bool = False) -> dict:
    """
    Fetch ASN details from BGPView API.
    Endpoint: https://api.bgpview.io/asn/{asn}

    Falls back to mock data if the API is unavailable or use_mock is set.
    """
    if not use_mock and REQUESTS_AVAILABLE:
        try:
            resp = _requests.get(
                f"https://api.bgpview.io/asn/{asn}", timeout=6.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "name": data.get("name", "Unknown"),
                    "description": data.get("description_short", "Unknown"),
                    "website": data.get("website", ""),
                    "prefix_count": data.get("rir_allocation", {}).get(
                        "prefix", 0),
                    "country": data.get("country_code", "ZZ"),
                    "rir": data.get("rir_allocation", {}).get("rir_name", "?"),
                    "peers_v4": 0,  # requires separate peers call
                }
        except Exception:
            pass

    # Mock fallback
    mock = MOCK_BGP_DATABASE.get(asn)
    if mock:
        return dict(mock)

    return {
        "name": f"AS{asn}",
        "description": "Unknown AS (mock fallback)",
        "website": "",
        "prefix_count": 0,
        "country": "ZZ",
        "rir": "Unknown",
        "peers_v4": 0,
    }


# ---------------------------------------------------------------------------
# Spamhaus DROP/EDROP checking
# ---------------------------------------------------------------------------

def load_spamhaus_drop(use_mock: bool = False) -> list[ipaddress.IPv4Network]:
    """
    Download and parse Spamhaus DROP list, or use mock entries.

    Production URLs:
        https://www.spamhaus.org/drop/drop.txt
        https://www.spamhaus.org/drop/edrop.txt
    """
    networks: list[ipaddress.IPv4Network] = []

    if not use_mock and REQUESTS_AVAILABLE:
        for url in ("https://www.spamhaus.org/drop/drop.txt",
                    "https://www.spamhaus.org/drop/edrop.txt"):
            try:
                resp = _requests.get(url, timeout=8.0)
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    cidr = line.split(";")[0].strip()
                    try:
                        networks.append(ipaddress.IPv4Network(cidr, strict=False))
                    except ValueError:
                        pass
                return networks
            except Exception:
                pass

    # Mock fallback
    for cidr in SPAMHAUS_DROP_MOCK:
        try:
            networks.append(ipaddress.IPv4Network(cidr, strict=False))
        except ValueError:
            pass
    return networks


def check_spamhaus(ip: str, drop_list: list[ipaddress.IPv4Network]) -> bool:
    """Return True if IP falls within any Spamhaus DROP/EDROP prefix."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in net for net in drop_list)


# ---------------------------------------------------------------------------
# Risk score calculation
#
# @decision DEC-0x08-002 (see module docstring)
# ---------------------------------------------------------------------------

def calculate_risk_score(intel: dict, in_drop: bool, asn_info: Optional[dict]) -> int:
    """
    Composite risk score 0-100 from multiple independent signals.

    Weights:
      30 — Datacenter hosting flag
      25 — Known-bad ASN (bulletproof / proxy type)
      20 — Proxy or VPN detection flag
      15 — Spamhaus DROP/EDROP listing
       5 — Tor exit node flag
       5 — proxy_score passthrough (from api, if available, scaled to 5pts)

    Score is additive, capped at 100.
    """
    score = 0

    if intel.get("is_datacenter"):
        score += 30

    # Known ASN risk level
    asn_num = intel.get("asn", 0)
    known = KNOWN_ASNS.get(asn_num)
    if known:
        if known["type"] in ("bulletproof", "proxy"):
            score += 25
        elif known["type"] == "datacenter" and known["risk"] == "high":
            score += 15
        elif known["type"] == "datacenter":
            score += 5

    if intel.get("is_proxy") or intel.get("is_vpn"):
        score += 20

    if in_drop:
        score += 15

    if intel.get("is_tor"):
        score += 5

    # proxy_score passthrough (0-100 from some APIs) scaled to 5 pts max
    ps = intel.get("proxy_score", 0)
    if ps and isinstance(ps, (int, float)):
        score += min(5, int(ps / 20))

    return min(score, 100)


def risk_label(score: int) -> str:
    """Human-readable risk label for console output."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def classify_ip_type(intel: dict) -> str:
    """
    Derive a human-readable classification from intel signals.
    Ordered from highest-confidence to lowest.
    """
    if intel.get("is_tor"):
        return "Tor Exit Node"
    if intel.get("is_proxy") and intel.get("is_datacenter"):
        return "Datacenter Proxy / Backconnect Exit"
    if intel.get("is_vpn") and intel.get("is_datacenter"):
        return "Commercial VPN (Datacenter)"
    if intel.get("is_proxy") and not intel.get("is_datacenter"):
        return "Residential Proxy Exit (SDK/Extension)"
    if intel.get("is_vpn") and not intel.get("is_datacenter"):
        return "Residential VPN Exit"
    if intel.get("is_datacenter"):
        asn_num = intel.get("asn", 0)
        known = KNOWN_ASNS.get(asn_num)
        if known and known["type"] == "bulletproof":
            return "Bulletproof Hosting (Datacenter)"
        if known and known["type"] == "cdn":
            return "CDN / Edge Node"
        return "Datacenter / VPS"
    if intel.get("is_mobile"):
        return "Residential Mobile"
    return "Residential ISP"


# ---------------------------------------------------------------------------
# Analysis pipeline — single IP
# ---------------------------------------------------------------------------

def analyze_ip(ip: str, drop_list: list[ipaddress.IPv4Network],
               use_mock: bool = False, deep: bool = False) -> dict:
    """
    Full analysis pipeline for a single IP address.
    Returns a result dict suitable for all output formatters.
    """
    ip = ip.strip()

    # Validate
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "Invalid IP address", "risk_score": 0,
                "risk_label": "UNKNOWN", "classification": "INVALID"}

    intel = get_ip_intelligence(ip, use_mock=use_mock)
    in_drop = check_spamhaus(ip, drop_list)

    # BGP enrichment (--deep or if ASN found)
    bgp_info = None
    if deep and intel.get("asn", 0) > 0:
        bgp_info = get_bgp_asn_details(intel["asn"], use_mock=use_mock)

    score = calculate_risk_score(intel, in_drop, bgp_info)
    label = risk_label(score)
    ip_type = classify_ip_type(intel)

    result = {
        "ip": ip,
        "classification": ip_type,
        "risk_score": score,
        "risk_label": label,
        "asn": intel.get("asn", 0),
        "asn_name": intel.get("asn_name", "Unknown"),
        "isp": intel.get("isp", "Unknown"),
        "country": intel.get("country", "ZZ"),
        "city": intel.get("city", "Unknown"),
        "is_datacenter": intel.get("is_datacenter", False),
        "is_proxy": intel.get("is_proxy", False),
        "is_vpn": intel.get("is_vpn", False),
        "is_tor": intel.get("is_tor", False),
        "is_mobile": intel.get("is_mobile", False),
        "in_spamhaus_drop": in_drop,
        "proxy_score": intel.get("proxy_score", 0),
    }

    if bgp_info:
        result["bgp"] = bgp_info

    return result


# ---------------------------------------------------------------------------
# CIDR range analysis
# ---------------------------------------------------------------------------

def analyze_cidr(cidr: str, drop_list: list[ipaddress.IPv4Network],
                 use_mock: bool = False) -> list[dict]:
    """
    Classify all IPs in a CIDR block.
    For large ranges (>/16), limits to first 256 addresses as a sample.

    @decision DEC-0x08-004
    @title Sample large CIDR ranges rather than exhaustive enumeration
    @status accepted
    @rationale A /8 contains 16M IPs — exhaustive analysis is impractical.
        For educational purposes, a /24 sample of 256 IPs demonstrates the
        concept while remaining runnable. Production use would require
        async/batch processing with a local GeoLite2 database.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        print(f"[!] Invalid CIDR: {cidr}", file=sys.stderr)
        return []

    hosts = list(network.hosts())
    if len(hosts) > 256:
        print(f"[*] Range {cidr} has {len(hosts)} hosts — sampling first 256",
              file=sys.stderr)
        hosts = hosts[:256]

    print(f"[*] Analyzing {len(hosts)} IPs in {cidr} ...", file=sys.stderr)
    results = []
    for ip in hosts:
        r = analyze_ip(str(ip), drop_list, use_mock=use_mock)
        results.append(r)

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _score_bar(score: int) -> str:
    """Simple ASCII progress bar for risk score."""
    filled = int(score / 10)
    return f"[{'#' * filled}{'.' * (10 - filled)}]"


def format_text(results: list[dict], deep: bool = False) -> str:
    """Human-readable console output."""
    lines = []
    lines.append(f"\n{'=' * 66}")
    lines.append("  PROXY & ASN VALIDATOR — netthrunter Module 0x08")
    lines.append(f"{'=' * 66}")
    lines.append(f"  {len(results)} IP(s) analyzed\n")

    for r in results:
        if "error" in r:
            lines.append(f"[!] {r['ip']} — {r['error']}")
            continue

        score = r["risk_score"]
        label = r["risk_label"]
        lines.append(f"{'─' * 66}")
        lines.append(f"  IP       : {r['ip']}")
        lines.append(f"  Type     : {r['classification']}")
        lines.append(
            f"  Risk     : {_score_bar(score)} {score}/100  [{label}]")
        lines.append(
            f"  ASN      : AS{r['asn']} — {r['asn_name']}")
        lines.append(
            f"  ISP      : {r['isp']}  ({r['country']}, {r['city']})")

        flags = []
        if r["is_datacenter"]:
            flags.append("DATACENTER")
        if r["is_proxy"]:
            flags.append("PROXY")
        if r["is_vpn"]:
            flags.append("VPN")
        if r["is_tor"]:
            flags.append("TOR-EXIT")
        if r["is_mobile"]:
            flags.append("MOBILE")
        if r["in_spamhaus_drop"]:
            flags.append("SPAMHAUS-DROP")

        if flags:
            lines.append(f"  Flags    : {', '.join(flags)}")

        if deep and "bgp" in r:
            bgp = r["bgp"]
            lines.append(f"  BGP      : {bgp.get('name', '?')} — "
                         f"{bgp.get('description', '?')}")
            lines.append(f"           : {bgp.get('prefix_count', 0)} prefixes"
                         f" | RIR: {bgp.get('rir', '?')}"
                         f" | Country: {bgp.get('country', '?')}")
        lines.append("")

    lines.append(f"{'─' * 66}")
    lines.append("  OPSEC NOTE: API lookups reveal your targets to the API")
    lines.append("  provider. Use --local (MaxMind GeoLite2) for sensitive")
    lines.append("  investigations. See Module 0x09 for full OPSEC guidance.")
    lines.append(f"{'=' * 66}\n")

    return "\n".join(lines)


def format_json(results: list[dict]) -> str:
    """JSON output for pipeline integration."""
    return json.dumps(results, indent=2)


def format_csv(results: list[dict]) -> str:
    """CSV output for spreadsheet import."""
    if not results:
        return ""

    fields = ["ip", "classification", "risk_score", "risk_label",
              "asn", "asn_name", "isp", "country", "city",
              "is_datacenter", "is_proxy", "is_vpn", "is_tor",
              "is_mobile", "in_spamhaus_drop", "proxy_score"]

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        writer.writerow(r)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy_validator.py",
        description=(
            "Module 0x08: Proxy & ASN Validator — "
            "adversary infrastructure classification tool"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python proxy_validator.py                        demo mode (no args)
  python proxy_validator.py -t 45.32.228.0
  python proxy_validator.py -t 1.1.1.1,8.8.8.8
  python proxy_validator.py -f ips.txt
  python proxy_validator.py -t 45.32.228.0 --deep
  python proxy_validator.py --cidr 45.32.228.0/24
  python proxy_validator.py -t 1.1.1.1 --format json
  python proxy_validator.py -t 1.1.1.1 --format csv
        """,
    )
    parser.add_argument(
        "-t", "--targets",
        metavar="IP[,IP...]",
        help="Single IP or comma-separated list of IPs to analyze",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="Text file with one IP per line",
    )
    parser.add_argument(
        "--cidr",
        metavar="CIDR",
        help="Analyze all IPs in a CIDR range (e.g. 45.32.228.0/24)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Include BGP/ASN deep analysis via BGPView API",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Force mock/demo mode (no network calls)",
    )
    return parser


def collect_ips(args: argparse.Namespace) -> list[str]:
    """Collect IP list from all input sources, deduplicated, in order."""
    ips: list[str] = []
    seen: set[str] = set()

    def add(ip: str) -> None:
        ip = ip.strip()
        if ip and ip not in seen:
            ips.append(ip)
            seen.add(ip)

    if args.targets:
        for ip in args.targets.split(","):
            add(ip)

    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        add(line)
        except OSError as e:
            print(f"[!] Cannot read file {args.file}: {e}", file=sys.stderr)

    return ips


def run_demo() -> None:
    """
    Demo mode: analyze the full mock database to show all classification types.
    No arguments required — this is the default when proxy_validator.py is
    run without any flags.
    """
    print("\n[*] Running in DEMO / MOCK mode — no network calls will be made.")
    print("[*] Demonstrating all IP classification types:\n")

    demo_ips = list(MOCK_DATABASE.keys())
    drop_list = load_spamhaus_drop(use_mock=True)
    results = [analyze_ip(ip, drop_list, use_mock=True, deep=False)
               for ip in demo_ips]
    print(format_text(results, deep=False))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # No-argument invocation: run demo mode
    if not args.targets and not args.file and not args.cidr:
        run_demo()
        return

    use_mock = args.mock

    # Load Spamhaus DROP list once
    print("[*] Loading Spamhaus DROP/EDROP list ...", file=sys.stderr)
    drop_list = load_spamhaus_drop(use_mock=use_mock)
    print(f"[*] Loaded {len(drop_list)} DROP/EDROP prefixes", file=sys.stderr)

    results: list[dict] = []

    if args.cidr:
        results = analyze_cidr(args.cidr, drop_list, use_mock=use_mock)
    else:
        ips = collect_ips(args)
        if not ips:
            print("[!] No IP addresses provided.", file=sys.stderr)
            parser.print_help()
            sys.exit(1)

        print(f"[*] Analyzing {len(ips)} IP(s) ...", file=sys.stderr)
        for ip in ips:
            r = analyze_ip(ip, drop_list, use_mock=use_mock, deep=args.deep)
            results.append(r)

    # Output
    if args.format == "json":
        print(format_json(results))
    elif args.format == "csv":
        print(format_csv(results), end="")
    else:
        print(format_text(results, deep=args.deep))


if __name__ == "__main__":
    main()
