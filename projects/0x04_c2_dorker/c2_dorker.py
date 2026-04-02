#!/usr/bin/env python3
"""
Module 0x04 Capstone Project: C2 Framework Dorker & Classifier
================================================================
Identifies C2 framework infrastructure through:
  - Cobalt Strike checksum8 URI validation
  - HTTP response header fingerprinting
  - Open directory listing detection and suspicious file enumeration
  - Framework signature matching (CS, Sliver, Havoc, Mythic, BRC4, Posh C2)
  - Structured JSON/CSV/text output

Usage:
    python c2_dorker.py                        # Demo / mock mode
    python c2_dorker.py -t http://target.com   # Single target
    python c2_dorker.py -f targets.txt         # Target list
    python c2_dorker.py -f targets.txt --format json --check-stagers

@decision DEC-C2DORKER-001
@title Mock-first architecture — all detection logic testable offline
@status accepted
@rationale The detection algorithms (checksum8, header matching, regex patterns)
  must be verifiable without connecting to real C2 infrastructure. By building
  mock HTTP responses that mirror real framework defaults, the tool demonstrates
  its capabilities safely and allows curriculum students to understand exactly
  what each signature catches. Real scanning activates only when targets are
  explicitly provided via -t or -f flags.

@decision DEC-C2DORKER-002
@title Classification uses evidence aggregation, not single-indicator matching
@status accepted
@rationale Single indicators (e.g., port 31337 alone) produce false positives.
  The classifier accumulates multiple weak signals into a confidence score:
  LOW (1 indicator), MEDIUM (2-3 indicators), HIGH (4+ indicators). This mirrors
  how professional threat intelligence analysts assess infrastructure and avoids
  the "one weird trick" attribution problem.

For authorized defensive research and education only.
Never execute payloads discovered by this tool.
Use Module 0x09 OPSEC practices before any active scanning.
"""

import asyncio
import json
import csv
import io
import re
import sys
import string
import random
import argparse
from dataclasses import dataclass, field, asdict
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# checksum8 algorithm
# ---------------------------------------------------------------------------

def checksum8(uri_path: str) -> int:
    """
    Compute the Cobalt Strike URI checksum8 value.

    Algorithm: sum ASCII values of each character in the URI path, mod 256.
    Result 92 → x86 stager, 93 → x64 stager.

    Note: Strip the leading slash before passing — the algorithm operates
    on the path component only, not the full URL.

    Example:
        checksum8("wPnl") → 92  (valid x86 stager URI)
        checksum8("wPnm") → 93  (valid x64 stager URI)
    """
    return sum(ord(c) for c in uri_path) % 256


def generate_stager_uri(target_checksum: int, length: int = 4) -> str:
    """
    Generate a URI path (no leading slash) whose checksum8 equals target_checksum.

    Used to construct valid x86 (92) or x64 (93) stager probe URIs.
    The generated URI uses only lowercase alphanumerics for maximum compatibility
    with Malleable C2 URI constraints.

    Args:
        target_checksum: 92 for x86, 93 for x64
        length: desired URI length (default 4, matching common CS defaults)

    Returns:
        A path string suitable for appending after a forward slash.
    """
    chars = string.ascii_lowercase + string.digits
    for _ in range(100_000):
        path = ''.join(random.choice(chars) for _ in range(length))
        if checksum8(path) == target_checksum:
            return path
    raise ValueError(f"Could not find URI with checksum8={target_checksum} in 100k attempts")


def is_valid_stager_uri(uri_path: str) -> Optional[str]:
    """
    Check if a URI path is a valid Cobalt Strike stager URI.

    Returns 'x86', 'x64', or None.
    """
    val = checksum8(uri_path)
    if val == 92:
        return "x86"
    if val == 93:
        return "x64"
    return None


# ---------------------------------------------------------------------------
# Framework signature database
# ---------------------------------------------------------------------------

# @decision DEC-C2DORKER-003
# @title Signature database as a plain dict — no ORM or external schema
# @status accepted
# @rationale This is curriculum code. A dict comprehended at module load time
#   is readable, diffable in git, and requires no dependencies. Adding a new
#   framework means adding one dict entry. The trade-off (no schema validation)
#   is acceptable for an educational project.

FRAMEWORK_SIGNATURES = {
    "cobalt_strike": {
        "display_name": "Cobalt Strike",
        "default_ports": [50050, 443, 80, 8080],
        "cert_serial": "146473198",
        "cert_cn": "major cobalt strike",
        "cert_org": "cobaltstrike",
        # HTTP response body pattern for the default 404 page
        "body_patterns": [
            r"<title>404</title>",
            r"<h1>Not found</h1>",
        ],
        # Server header patterns (CS suppresses server header in default profile)
        "server_headers": [],
        # Custom response headers that appear in some profiles
        "response_headers": {},
        # Stager architecture validated via checksum8
        "uses_checksum8": True,
        # URIs that suggest framework presence (regexes)
        "uri_patterns": [
            r"^/[a-z0-9]{4,8}$",        # Short alphanumeric — typical stager path
        ],
        "notes": "Default cert serial 146473198 is the strongest single indicator.",
    },
    "sliver": {
        "display_name": "Sliver",
        "default_ports": [31337, 443, 80, 53],
        "cert_serial": None,            # Generated per install; not a stable indicator
        "cert_cn": None,
        "cert_org": None,
        "body_patterns": [],
        "server_headers": [],
        "response_headers": {},
        "uses_checksum8": False,
        "uri_patterns": [
            r"^/haiku\.php$",
            r"^/fonts/.*\.woff2?$",
            r"^/static/.*\.js$",
        ],
        "notes": "Port 31337 with mTLS (client cert required) is primary indicator.",
    },
    "havoc": {
        "display_name": "Havoc",
        "default_ports": [40056, 443, 80],
        "cert_serial": None,
        "cert_cn": None,
        "cert_org": None,
        "body_patterns": [
            r"Havoc",
        ],
        "server_headers": [],
        "response_headers": {
            "Content-Type": "application/octet-stream",
        },
        "uses_checksum8": False,
        "uri_patterns": [],
        "notes": "Web UI on port 40056. Default HTTP profile spoofs Apache.",
    },
    "mythic": {
        "display_name": "Mythic C2",
        "default_ports": [7443, 443, 80],
        "cert_serial": None,
        "cert_cn": None,
        "cert_org": None,
        "body_patterns": [
            r"Mythic",
            r"/new/login",
            r"/api/v1/agent_message",
        ],
        # nginx alone is too broad a signal — only flag when body also matches Mythic patterns
        "server_headers": [],
        "response_headers": {},
        "uses_checksum8": False,
        "uri_patterns": [
            r"^/new/login$",
            r"^/api/v1/",
            r"^/ws/",
        ],
        "notes": "Web UI at /new/login on port 7443. Uses WebSockets for real-time tasking.",
    },
    "brute_ratel": {
        "display_name": "Brute Ratel C4",
        "default_ports": [443, 80],
        "cert_serial": None,
        "cert_cn": None,
        "cert_org": None,
        "body_patterns": [
            r'"status"\s*:\s*"ok"',      # JSON response pattern
        ],
        "server_headers": [],
        "response_headers": {
            "Content-Type": "application/json",
        },
        "uses_checksum8": False,
        "uri_patterns": [
            r"^/[a-zA-Z0-9_\-/]+/[a-f0-9]{8,}$",  # UUID-style path
        ],
        "notes": "Leaked versions widely used. JSON-encoded encrypted responses.",
    },
    "posh_c2": {
        "display_name": "Posh C2",
        "default_ports": [443, 80],
        "cert_serial": None,
        "cert_cn": None,
        "cert_org": None,
        "body_patterns": [],
        "server_headers": [],
        "response_headers": {
            "Content-Type": "text/plain",
        },
        "uses_checksum8": False,
        "uri_patterns": [
            r"^/connect$",
            r"^/poll$",
        ],
        "notes": "PowerShell-based. Common in UK-origin threat actor campaigns.",
    },
    "python_staging": {
        "display_name": "Python http.server (staging)",
        "default_ports": [80, 8000, 8080, 443],
        "cert_serial": None,
        "cert_cn": None,
        "cert_org": None,
        "body_patterns": [
            r"Directory listing for",   # Python http.server default
        ],
        "server_headers": [
            "SimpleHTTP",
            "BaseHTTP",
            "Python",
        ],
        "response_headers": {},
        "uses_checksum8": False,
        "uri_patterns": [],
        "notes": "Python http.server is never legitimate in production. Immediate escalation indicator.",
    },
}


# ---------------------------------------------------------------------------
# Suspicious file extensions
# ---------------------------------------------------------------------------

SUSPICIOUS_EXTENSIONS = {
    ".bin": "Raw shellcode or packed PE",
    ".exe": "Windows executable / stager",
    ".dll": "Windows DLL / reflective loader",
    ".ps1": "PowerShell dropper/script",
    ".sh":  "Shell script / Linux dropper",
    ".elf": "Linux/Unix ELF executable",
    ".py":  "Python payload or C2 component",
    ".vbs": "VBScript dropper",
    ".hta": "HTML Application (mshta execution)",
    ".jar": "Java payload",
    ".bat": "Batch script dropper",
    ".iso": "Container for payload delivery",
}

OPEN_DIR_PATTERNS = [
    r"Index of /",
    r"Directory listing for",
    r"Directory: /",
    r"\[To Parent Directory\]",
    r"<title>.*Index of.*</title>",
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    url: str
    reachable: bool = False
    open_directory: bool = False
    files_found: list = field(default_factory=list)
    suspicious_files: list = field(default_factory=list)
    framework: str = "Unknown"
    confidence: str = "NONE"
    indicators: list = field(default_factory=list)
    server_header: str = ""
    stager_arch: Optional[str] = None   # 'x86', 'x64', or None
    error: str = ""


# ---------------------------------------------------------------------------
# Framework classifier
# ---------------------------------------------------------------------------

def classify_framework(
    url: str,
    response_body: str,
    response_headers: dict,
    open_directory: bool,
    suspicious_files: list,
    stager_arch: Optional[str] = None,
) -> tuple[str, str, list]:
    """
    Classify a target into a C2 framework based on accumulated indicators.

    Returns (framework_name, confidence, indicators_list).
    Confidence scale: NONE → LOW (1 indicator) → MEDIUM (2-3) → HIGH (4+).

    @decision DEC-C2DORKER-002 — see module docstring.
    """
    server_header = response_headers.get("server", "").lower()
    content_type = response_headers.get("content-type", "").lower()

    scores = {}
    evidence = {}

    for fw_key, sig in FRAMEWORK_SIGNATURES.items():
        hits = []

        # Body pattern matching
        for pattern in sig.get("body_patterns", []):
            if re.search(pattern, response_body, re.IGNORECASE):
                hits.append(f"body matches '{pattern}'")

        # Server header matching
        for sh in sig.get("server_headers", []):
            if sh.lower() in server_header:
                hits.append(f"Server header contains '{sh}'")

        # Response header matching
        for hk, hv in sig.get("response_headers", {}).items():
            actual = response_headers.get(hk.lower(), "")
            if hv.lower() in actual.lower():
                hits.append(f"Header {hk}: {hv}")

        # Open directory + suspicious files — strong signal for staging servers
        if open_directory and suspicious_files and fw_key == "python_staging":
            if "SimpleHTTP" in response_headers.get("server", "") or \
               "Python" in response_headers.get("server", ""):
                hits.append("Python http.server + open directory + suspicious files")

        # checksum8 stager response
        if sig.get("uses_checksum8") and stager_arch is not None:
            hits.append(f"checksum8 stager response: {stager_arch}")

        if hits:
            scores[fw_key] = hits
            evidence[fw_key] = hits

    if not scores:
        return "Unknown", "NONE", []

    # Pick the framework with the most indicators
    best_fw = max(scores, key=lambda k: len(scores[k]))
    best_hits = scores[best_fw]

    n = len(best_hits)
    if n >= 4:
        confidence = "HIGH"
    elif n >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    display = FRAMEWORK_SIGNATURES[best_fw]["display_name"]
    return display, confidence, best_hits


# ---------------------------------------------------------------------------
# Directory listing parser
# ---------------------------------------------------------------------------

def parse_directory_listing(html: str) -> tuple[bool, list, list]:
    """
    Parse an HTTP response body for open directory listing indicators.

    Returns (is_open_dir, all_files, suspicious_files).
    """
    is_open = any(re.search(p, html, re.IGNORECASE) for p in OPEN_DIR_PATTERNS)
    if not is_open:
        return False, [], []

    # Extract hrefs
    links = re.findall(r'href=[\'"]?([^\'" >?]+)', html)
    skip = {"/", "../", "./", ""}
    files = [l for l in links if l not in skip and not l.startswith("?")]

    suspicious = []
    for f in files:
        fname = f.lower().split("?")[0]
        for ext, desc in SUSPICIOUS_EXTENSIONS.items():
            if fname.endswith(ext):
                suspicious.append(f"{f} [{desc}]")
                break

    return True, files, suspicious


# ---------------------------------------------------------------------------
# Mock responses for demo mode
# ---------------------------------------------------------------------------

def _make_mock_response(status_code: int, body: str, headers: dict):
    """Create a minimal mock object that mimics httpx.Response fields."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    resp.headers = {k.lower(): v for k, v in headers.items()}
    return resp


MOCK_TARGETS = [
    {
        "url": "http://mock-cs-default.example.com",
        "description": "Cobalt Strike — open dir on /files/, default 404 on root",
        # This simulates hitting /files/ which has an open dir, while root returns the CS default 404.
        # The classifier sees: CS 404 body + CS title pattern + open dir with .bin files
        "response": _make_mock_response(
            200,
            """
            <html><head><title>404</title></head>
            <body>
            <h1>Not found</h1>

            <h1>Index of /files/</h1>
            <pre>
            <a href="../">../</a>
            <a href="beacon_x86.bin">beacon_x86.bin</a>
            <a href="beacon_x64.bin">beacon_x64.bin</a>
            <a href="stager.ps1">stager.ps1</a>
            <a href="loader.exe">loader.exe</a>
            </pre>
            </body></html>
            """,
            {"Server": ""},
        ),
        "stager_response": _make_mock_response(
            200,
            "MZ\x90\x00" + "A" * 300,   # Fake PE structure header — never real payload
            {"Content-Type": "application/octet-stream"},
        ),
    },
    {
        "url": "http://mock-cs-404.example.com",
        "description": "Cobalt Strike — default 404 response (no open dir)",
        "response": _make_mock_response(
            404,
            "<html><head><title>404</title></head><body><h1>Not found</h1></body></html>",
            {"Server": ""},
        ),
        "stager_response": None,
    },
    {
        "url": "http://mock-python-staging.example.com:8000",
        "description": "Python http.server — open directory with payloads",
        "response": _make_mock_response(
            200,
            """
            <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
            <html><head><title>Directory listing for /</title></head>
            <body>
            <h1>Directory listing for /</h1>
            <hr>
            <ul>
            <li><a href="update.exe">update.exe</a></li>
            <li><a href="loader.dll">loader.dll</a></li>
            <li><a href="dropper.ps1">dropper.ps1</a></li>
            <li><a href="linux_implant.elf">linux_implant.elf</a></li>
            </ul>
            <hr>
            </body></html>
            """,
            {"Server": "SimpleHTTP/0.6 Python/3.11.2"},
        ),
        "stager_response": None,
    },
    {
        "url": "http://mock-mythic.example.com:7443",
        "description": "Mythic C2 — web UI exposed",
        "response": _make_mock_response(
            200,
            """
            <html><head><title>Mythic</title></head>
            <body>
            <div id="app">
              <a href="/new/login">Login</a>
            </div>
            </body></html>
            """,
            {"Server": "nginx/1.18.0", "Content-Type": "text/html"},
        ),
        "stager_response": None,
    },
    {
        "url": "http://mock-havoc.example.com:40056",
        "description": "Havoc framework — teamserver web UI",
        "response": _make_mock_response(
            200,
            "<html><head><title>Havoc</title></head><body>Havoc Teamserver</body></html>",
            {"Server": "Apache/2.4.51", "Content-Type": "text/html"},
        ),
        "stager_response": None,
    },
    {
        "url": "http://mock-unknown.example.com",
        "description": "Unknown server — no indicators",
        "response": _make_mock_response(
            200,
            "<html><head><title>Welcome</title></head><body>Under construction.</body></html>",
            {"Server": "nginx/1.20.0", "Content-Type": "text/html"},
        ),
        "stager_response": None,
    },
]


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

async def scan_target(
    url: str,
    client,
    check_stagers: bool = False,
    mock_data: Optional[dict] = None,
) -> ScanResult:
    """
    Scan a single URL and return a populated ScanResult.

    In mock mode, mock_data provides pre-built responses. In real mode,
    async HTTP requests are made via the httpx client.

    @decision DEC-C2DORKER-001 — see module docstring.
    """
    result = ScanResult(url=url)

    try:
        if mock_data:
            response = mock_data["response"]
        else:
            if not url.startswith("http"):
                url = f"http://{url}"
                result.url = url
            response = await client.get(url)

        result.reachable = True
        body = response.text
        headers = dict(response.headers)
        result.server_header = headers.get("server", "")

        # Open directory detection
        is_open, files, suspicious = parse_directory_listing(body)
        result.open_directory = is_open
        result.files_found = files
        result.suspicious_files = suspicious

        # Stager check (Cobalt Strike checksum8)
        stager_arch = None
        if check_stagers:
            if mock_data and mock_data.get("stager_response"):
                stager_resp = mock_data["stager_response"]
                stager_body = stager_resp.text
                if stager_body.startswith("MZ"):
                    stager_arch = "x86 (mock)"
            elif not mock_data:
                probe_uri = generate_stager_uri(92, length=4)
                try:
                    stager_resp = await client.get(f"{url}/{probe_uri}")
                    if stager_resp.status_code == 200 and stager_resp.text.startswith("MZ"):
                        stager_arch = "x86"
                    else:
                        probe_uri64 = generate_stager_uri(93, length=4)
                        stager_resp64 = await client.get(f"{url}/{probe_uri64}")
                        if stager_resp64.status_code == 200 and stager_resp64.text.startswith("MZ"):
                            stager_arch = "x64"
                except Exception:
                    pass

        result.stager_arch = stager_arch

        # Framework classification
        framework, confidence, indicators = classify_framework(
            url=url,
            response_body=body,
            response_headers=headers,
            open_directory=is_open,
            suspicious_files=suspicious,
            stager_arch=stager_arch,
        )
        result.framework = framework
        result.confidence = confidence
        result.indicators = indicators

    except Exception as e:
        result.error = str(e)

    return result


async def scan_all(
    targets: list[str],
    concurrency: int = 10,
    check_stagers: bool = False,
    mock_lookup: Optional[dict] = None,
) -> list[ScanResult]:
    """
    Scan all targets concurrently. Returns list of ScanResult objects.

    mock_lookup maps URL → mock_data dict for offline demo mode.
    When all targets have entries in mock_lookup, httpx is never imported,
    allowing the tool to run without network dependencies in demo mode.

    @decision DEC-C2DORKER-001 — see module docstring.
    """
    # Fast path: if every target has mock data, skip httpx entirely
    if mock_lookup and all(url in mock_lookup for url in targets):
        results = []
        for url in targets:
            result = await scan_target(
                url, client=None, check_stagers=check_stagers,
                mock_data=mock_lookup[url],
            )
            results.append(result)
        return results

    # Real-network path: import httpx only when needed
    import httpx

    queue = asyncio.Queue()
    results = []

    for t in targets:
        queue.put_nowait(t)

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    timeout = httpx.Timeout(10.0)

    async def worker():
        while True:
            url = await queue.get()
            mock = mock_lookup.get(url) if mock_lookup else None
            result = await scan_target(url, client, check_stagers=check_stagers, mock_data=mock)
            results.append(result)
            queue.task_done()

    async with httpx.AsyncClient(limits=limits, timeout=timeout, verify=False) as client:
        tasks = [asyncio.create_task(worker()) for _ in range(min(concurrency, len(targets)))]
        await queue.join()
        for t in tasks:
            t.cancel()

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_text(results: list[ScanResult]) -> str:
    """Render results as human-readable text."""
    lines = []
    for r in results:
        lines.append(f"\n{'='*60}")
        lines.append(f"Target:    {r.url}")
        lines.append(f"Reachable: {'Yes' if r.reachable else 'No'}")
        if r.error:
            lines.append(f"Error:     {r.error}")
            continue
        lines.append(f"Open Dir:  {'YES [!]' if r.open_directory else 'No'}")
        if r.suspicious_files:
            lines.append(f"Suspicious files:")
            for f in r.suspicious_files:
                lines.append(f"  [!] {f}")
        elif r.files_found:
            lines.append(f"Files found: {len(r.files_found)}")
        lines.append(f"Framework: {r.framework}")
        lines.append(f"Confidence:{r.confidence}")
        if r.indicators:
            lines.append("Indicators:")
            for ind in r.indicators:
                lines.append(f"  - {ind}")
        if r.stager_arch:
            lines.append(f"Stager:    {r.stager_arch}")
        if r.server_header:
            lines.append(f"Server:    {r.server_header}")
    lines.append(f"\n{'='*60}")
    return "\n".join(lines)


def format_json(results: list[ScanResult]) -> str:
    """Render results as JSON."""
    return json.dumps([asdict(r) for r in results], indent=2)


def format_csv(results: list[ScanResult]) -> str:
    """Render results as CSV."""
    buf = io.StringIO()
    fieldnames = [
        "url", "reachable", "open_directory", "framework",
        "confidence", "stager_arch", "server_header",
        "suspicious_files_count", "indicators_count", "error",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        writer.writerow({
            "url": r.url,
            "reachable": r.reachable,
            "open_directory": r.open_directory,
            "framework": r.framework,
            "confidence": r.confidence,
            "stager_arch": r.stager_arch or "",
            "server_header": r.server_header,
            "suspicious_files_count": len(r.suspicious_files),
            "indicators_count": len(r.indicators),
            "error": r.error,
        })
    return buf.getvalue()


FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "csv": format_csv,
}


# ---------------------------------------------------------------------------
# Mock demo runner
# ---------------------------------------------------------------------------

async def run_mock_demo(output_format: str, check_stagers: bool) -> None:
    """
    Run the scanner in offline demo mode against synthetic mock responses.

    Each mock target represents a real framework's default HTTP behavior,
    allowing students to understand what each detection signature catches
    without connecting to real C2 infrastructure.
    """
    print("[*] C2 Framework Dorker v2.0 — Mock Demo Mode")
    print("[*] Demonstrating framework detection against synthetic responses")
    print("[*] No network connections will be made in this mode\n")

    targets = [m["url"] for m in MOCK_TARGETS]
    mock_lookup = {m["url"]: m for m in MOCK_TARGETS}

    for m in MOCK_TARGETS:
        print(f"  > {m['url']}")
        print(f"    Scenario: {m['description']}")

    print()

    results = await scan_all(
        targets=targets,
        concurrency=len(targets),
        check_stagers=check_stagers,
        mock_lookup=mock_lookup,
    )

    formatter = FORMATTERS.get(output_format, format_text)
    print(formatter(results))

    # Summary statistics
    detected = [r for r in results if r.framework != "Unknown"]
    open_dirs = [r for r in results if r.open_directory]
    suspicious_total = sum(len(r.suspicious_files) for r in results)

    print(f"\n[*] Summary: {len(results)} targets scanned")
    print(f"    Frameworks identified: {len(detected)}/{len(results)}")
    print(f"    Open directories:      {len(open_dirs)}")
    print(f"    Suspicious files:      {suspicious_total}")


# ---------------------------------------------------------------------------
# Real target runner
# ---------------------------------------------------------------------------

async def run_real_scan(
    targets: list[str],
    output_format: str,
    check_stagers: bool,
    concurrency: int,
) -> None:
    """
    Scan real targets. Requires explicit user invocation via -t or -f.

    See Module 0x09 for OPSEC guidance before scanning external targets.
    """
    print(f"[*] C2 Framework Dorker v2.0")
    print(f"[*] Scanning {len(targets)} target(s)  |  stager check: {check_stagers}")
    print(f"[!] Ensure you have authorization to scan these targets")
    print(f"[!] See Module 0x09 for OPSEC recommendations\n")

    results = await scan_all(
        targets=targets,
        concurrency=concurrency,
        check_stagers=check_stagers,
        mock_lookup=None,
    )

    formatter = FORMATTERS.get(output_format, format_text)
    print(formatter(results))

    detected = [r for r in results if r.framework != "Unknown"]
    open_dirs = [r for r in results if r.open_directory]

    print(f"\n[*] Done. {len(detected)} framework(s) identified, {len(open_dirs)} open director(ies) found.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="c2_dorker.py",
        description=(
            "C2 Framework Dorker & Classifier — Module 0x04 Capstone\n"
            "Identifies C2 infrastructure via header fingerprinting, checksum8,\n"
            "and open directory analysis. For authorized defensive research only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-t", "--target",
        metavar="URL",
        help="Single target URL (e.g. http://target.example.com)",
    )
    p.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="File containing one target URL per line",
    )
    p.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--check-stagers",
        action="store_true",
        default=False,
        help="Probe for Cobalt Strike stager URIs using checksum8 algorithm",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=10,
        metavar="N",
        help="Number of concurrent requests (default: 10)",
    )
    p.add_argument(
        "--demo-checksum8",
        action="store_true",
        default=False,
        help="Print checksum8 algorithm explanation and examples, then exit",
    )
    return p


def demo_checksum8() -> None:
    """Print a standalone explanation of the checksum8 algorithm."""
    print("=" * 60)
    print("Cobalt Strike checksum8 URI Algorithm")
    print("=" * 60)
    print()
    print("Algorithm:")
    print("  For each character in the URI path (no leading slash),")
    print("  sum the ASCII values. Take that sum mod 256.")
    print("  Result 92 → server returns x86 stager payload.")
    print("  Result 93 → server returns x64 stager payload.")
    print()
    print("Python implementation:")
    print("  def checksum8(uri_path): return sum(ord(c) for c in uri_path) % 256")
    print()

    # Generate examples
    x86_uri = generate_stager_uri(92, 4)
    x64_uri = generate_stager_uri(93, 4)

    print(f"Example x86 stager URI: /{x86_uri}")
    print(f"  checksum8('{x86_uri}') = {checksum8(x86_uri)}  (== 92, x86)")
    print()
    print(f"Example x64 stager URI: /{x64_uri}")
    print(f"  checksum8('{x64_uri}') = {checksum8(x64_uri)}  (== 93, x64)")
    print()
    print("Validation examples:")
    # Use the generated URIs so the demo always shows actual valid stager paths
    for path, expected_label in [(x86_uri, "x86 stager"), (x64_uri, "x64 stager"), ("ABCD", None)]:
        val = checksum8(path)
        arch = is_valid_stager_uri(path)
        note = f"→ {arch} stager (valid)" if arch else "→ not a stager URI"
        print(f"  checksum8('{path}') = {val}  {note}")
    print()
    print("Note: Malleable C2 profiles change URI namespaces but cannot")
    print("change the checksum8 algorithm itself. Any short URI returning")
    print("binary PE data (MZ header) on a suspicious server is strong")
    print("evidence of active Cobalt Strike staging.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.demo_checksum8:
        demo_checksum8()
        sys.exit(0)

    # Collect targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] Target file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        # No targets provided — run offline demo
        asyncio.run(run_mock_demo(args.format, args.check_stagers))
    else:
        asyncio.run(run_real_scan(targets, args.format, args.check_stagers, args.concurrency))


if __name__ == "__main__":
    main()
