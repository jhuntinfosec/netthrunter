#!/usr/bin/env python3
"""
Module 0x05 Capstone Project: Automated Stealer Leak Parser
============================================================
Educational tool for parsing stealer log archives and extracting
threat-intelligence indicators: Telegram bot tokens, C2 URLs,
Discord webhooks, and external IP addresses.

Defensive use only. See Module 0x05 OPSEC & Ethics section.

@decision DEC-0x05-001
@title Mock mode as primary safe default
@status accepted
@rationale Real stealer log data contains PII. Running without arguments
  or with --mock generates synthetic data so the pipeline can be studied
  without any real credentials or victim data in scope. This mirrors
  best-practice sandbox isolation described in the ethics section.

@decision DEC-0x05-002
@title HTTP validation uses mock fallback, never real tokens
@status accepted
@rationale --validate-tokens in demo mode calls a local mock function
  rather than api.telegram.org. This ensures classroom use never
  inadvertently contacts live operator infrastructure or leaks
  researcher IP to an active C2.

@decision DEC-0x05-003
@title Stealer family detection via directory heuristics
@status accepted
@rationale Each major stealer family produces a recognizable artifact
  set. Directory-presence scoring is simpler and more robust than
  filename regex for this use case — heuristics table in detect_family().
"""

import argparse
import csv
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Telegram Bot API token: <8-11 digit id>:<35-char alphanumeric string>
RE_TELEGRAM = re.compile(r"\b([0-9]{8,11}:[A-Za-z0-9_-]{35})\b")

# Standard IPv4 address (word-boundary anchored to reduce false positives)
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# Discord webhook URL
RE_DISCORD = re.compile(
    r"https?://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
)

# Browser credential block: URL / Username / Password triplet
RE_CRED_URL = re.compile(r"^URL:\s*(.+)$", re.MULTILINE | re.IGNORECASE)

# Common C2 panel path patterns embedded in log content
RE_C2_PATH = re.compile(
    r"https?://[^\s\"'<>]+(?:/panel|/gate\.php|/admin|/login\.php|/index\.php)[^\s\"'<>]*",
    re.IGNORECASE,
)

# Private / reserved IP prefixes to filter out
PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
)

# ---------------------------------------------------------------------------
# Stealer family detection heuristics
# @decision DEC-0x05-003
# ---------------------------------------------------------------------------

FAMILY_SIGNATURES: Dict[str, List[str]] = {
    "Redline": [
        "Passwords.txt", "Cookies", "Autofill", "CC",
        "FileGrabber", "Screenshot.jpg",
    ],
    "Vidar": [
        "Passwords.txt", "Cookies", "wallets", "Screenshot.jpg",
        "autofill",
    ],
    "Raccoon": [
        "Passwords.txt", "Cookies", "FileGrabber", "SystemInfo.txt",
        "Wallets",
    ],
    "Lumma": [
        "Passwords.txt", "Cookies", "Network", "Autofill",
        "BrowserExtensions",
    ],
}


def detect_family(directory: Path) -> str:
    """
    Score artifact presence against known stealer family signatures.
    Returns the best-match family name or 'Unknown'.

    Each matching artifact adds one point. Ties go to the family listed
    first in FAMILY_SIGNATURES (alphabetically arbitrary — acceptable for
    a heuristic tool).
    """
    entries = {p.name for p in directory.iterdir()} if directory.is_dir() else set()
    scores: Dict[str, int] = {}
    for family, artifacts in FAMILY_SIGNATURES.items():
        score = sum(1 for a in artifacts if a in entries)
        scores[family] = score
    best_family = max(scores, key=lambda k: scores[k])
    best_score = scores[best_family]
    return best_family if best_score >= 2 else "Unknown"


# ---------------------------------------------------------------------------
# IP filtering
# ---------------------------------------------------------------------------

def is_external_ip(ip: str) -> bool:
    """Return True if the IPv4 address is not in a private/reserved range."""
    # Validate octet ranges
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        if not all(0 <= int(p) <= 255 for p in parts):
            return False
    except ValueError:
        return False
    return not any(ip.startswith(pfx) for pfx in PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

def extract_indicators(text: str) -> Dict[str, List[str]]:
    """
    Run all regex patterns against a text blob.
    Returns deduplicated lists per indicator type.
    """
    telegram_tokens = list(set(RE_TELEGRAM.findall(text)))
    discord_webhooks = list(set(RE_DISCORD.findall(text)))
    all_ips = list(set(RE_IPV4.findall(text)))
    external_ips = [ip for ip in all_ips if is_external_ip(ip)]
    c2_urls = list(set(RE_C2_PATH.findall(text)))
    credential_urls = list(set(RE_CRED_URL.findall(text)))

    return {
        "telegram_tokens": telegram_tokens,
        "discord_webhooks": discord_webhooks,
        "external_ips": external_ips,
        "c2_panel_urls": c2_urls,
        "credential_urls": credential_urls[:20],  # cap to avoid noise in huge files
    }


# ---------------------------------------------------------------------------
# File and directory processing
# ---------------------------------------------------------------------------

def read_text_file(filepath: Path) -> str:
    """Read a text file safely, ignoring undecodable bytes."""
    try:
        return filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        print(f"[!] Cannot read {filepath}: {exc}", file=sys.stderr)
        return ""


def process_single_file(filepath: Path) -> Tuple[Dict, str]:
    """
    Process a single text file.
    Returns (indicators_dict, family_hint).
    """
    print(f"[*] Processing file: {filepath}")
    text = read_text_file(filepath)
    print(f"    {len(text):,} bytes")
    indicators = extract_indicators(text)
    return indicators, "N/A"


def process_directory(directory: Path) -> Tuple[Dict, str]:
    """
    Walk a directory, collect text from all .txt files, extract indicators.
    Also attempts stealer family detection from the directory structure.
    """
    print(f"[*] Scanning directory: {directory}")
    combined_text = []
    file_count = 0

    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix.lower() in (".txt", ".log", ".csv"):
            combined_text.append(read_text_file(path))
            file_count += 1

    print(f"    {file_count} text files found")
    text = "\n".join(combined_text)
    print(f"    {len(text):,} total bytes")

    indicators = extract_indicators(text)
    family = detect_family(directory)
    return indicators, family


def extract_zip_archive(zip_path: Path, extract_to: Path) -> List[Path]:
    """
    Extract a ZIP archive (including nested ZIPs) to extract_to.
    Returns list of all extracted top-level directories.

    @decision DEC-0x05-004
    @title Nested ZIP extraction with depth guard
    @status accepted
    @rationale Stealer log ZIPs sometimes contain per-victim sub-ZIPs.
      A depth limit of 2 prevents infinite recursion on malformed archives.
    """
    print(f"[*] Extracting archive: {zip_path.name}")
    extract_to.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_to)
    except zipfile.BadZipFile as exc:
        print(f"[!] Bad ZIP file {zip_path}: {exc}", file=sys.stderr)
        return []

    # Recurse into nested ZIPs (depth = 1 additional level)
    for nested in sorted(extract_to.rglob("*.zip")):
        nested_dir = nested.parent / nested.stem
        if not nested_dir.exists():
            print(f"    Extracting nested: {nested.name}")
            try:
                with zipfile.ZipFile(nested, "r") as zf:
                    zf.extractall(nested_dir)
            except zipfile.BadZipFile:
                pass

    return [p for p in extract_to.iterdir() if p.is_dir()]


def process_archive(zip_path: Path, tmp_dir: Path) -> List[Tuple[Dict, str, str]]:
    """
    Extract a ZIP and process each top-level victim folder.
    Returns list of (indicators, family, victim_id) tuples.
    """
    victim_dirs = extract_zip_archive(zip_path, tmp_dir)

    if not victim_dirs:
        # Flat archive — treat the whole extract_to as one victim
        indicators, family = process_directory(tmp_dir)
        return [(indicators, family, zip_path.stem)]

    results = []
    for victim_dir in victim_dirs:
        indicators, family = process_directory(victim_dir)
        results.append((indicators, family, victim_dir.name))
    return results


# ---------------------------------------------------------------------------
# Telegram bot token validation
# @decision DEC-0x05-002
# ---------------------------------------------------------------------------

def validate_token_mock(token: str) -> Dict:
    """
    Mock implementation of Telegram getMe validation.
    Returns synthetic bot metadata without contacting any real API.
    Used in --mock mode and during classroom exercises.
    """
    # Derive a stable fake bot ID from the token string for reproducibility
    fake_id = sum(ord(c) for c in token) % 90000 + 10000000
    return {
        "ok": True,
        "result": {
            "id": fake_id,
            "is_bot": True,
            "first_name": "ResearchMockBot",
            "username": "research_mock_bot",
            "can_join_groups": True,
            "can_read_all_group_messages": False,
            "supports_inline_queries": False,
        },
        "_mock": True,
        "_note": "This is synthetic data. Real validation requires: "
                 "GET https://api.telegram.org/bot<TOKEN>/getMe",
    }


def validate_token_live(token: str) -> Dict:
    """
    Validate a Telegram bot token via the real Bot API.
    Only called when --validate-tokens is set and --mock is not.

    Requires the 'urllib' standard library (no third-party deps).
    Caller is responsible for ensuring token handling follows the
    researcher OPSEC guidelines in Module 0x05.
    """
    import urllib.request
    import urllib.error

    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error_code": exc.code, "description": str(exc.reason)}
    except Exception as exc:
        return {"ok": False, "error_code": -1, "description": str(exc)}


def validate_tokens(tokens: List[str], use_mock: bool = True) -> Dict[str, Dict]:
    """
    Validate a list of tokens, returning a mapping of token → API response.
    In mock mode, no network requests are made.
    """
    results = {}
    for token in tokens:
        if use_mock:
            results[token] = validate_token_mock(token)
        else:
            results[token] = validate_token_live(token)
    return results


# ---------------------------------------------------------------------------
# Mock stealer log generation
# @decision DEC-0x05-001
# ---------------------------------------------------------------------------

def create_mock_stealer_dump(base_dir: Path) -> Path:
    """
    Generate a realistic synthetic stealer log directory tree.
    All values are obviously fake — no real credentials, real tokens,
    or real IPs (uses documentation ranges per RFC 5737 / RFC 3849).
    """
    victim_dir = base_dir / "DESKTOP-MOCK01_JohnDoe"
    victim_dir.mkdir(parents=True, exist_ok=True)

    # SystemInfo.txt — uses TEST-NET-3 (203.0.113.0/24) per RFC 5737
    (victim_dir / "SystemInfo.txt").write_text(
        "Date: 2024-01-15 14:32:11\n"
        "MachineID: DESKTOP-MOCK01\\JohnDoe\n"
        "HWID: FAKEHWID1234567890ABCDEF\n"
        "OS: Windows 10 Pro x64 (Build 19045)\n"
        "CPU: Intel Core i7-MOCK\n"
        "RAM: 16 GB\n"
        "Resolution: 1920x1080\n"
        "IP (external): 203.0.113.42\n"
        "Country: US\n"
        "Timezone: America/New_York\n"
        "Antivirus: Windows Defender\n"
        "Installed Browsers: Chrome 120, Firefox 121\n",
        encoding="utf-8",
    )

    # Passwords.txt — fake credentials with obviously synthetic values
    (victim_dir / "Passwords.txt").write_text(
        "URL: https://mail.example-fake.com/login\n"
        "Username: mockuser@example-fake.com\n"
        "Password: FAKE_PASSWORD_DO_NOT_USE\n"
        "Application: Google Chrome\n"
        "\n"
        "URL: https://panel.fake-c2-example.com/admin\n"
        "Username: operator_mock\n"
        "Password: FAKE_PANEL_PASS_DO_NOT_USE\n"
        "Application: Google Chrome\n"
        "\n"
        "URL: https://banking-fake.example-test.com\n"
        "Username: testuser_mock\n"
        "Password: FAKE_BANKING_PASS\n"
        "Application: Mozilla Firefox\n",
        encoding="utf-8",
    )

    # Cookies directory
    cookies_dir = victim_dir / "Cookies"
    cookies_dir.mkdir(exist_ok=True)
    (cookies_dir / "Chrome_Default.txt").write_text(
        "# Fake cookie data for parsing demonstration\n"
        ".example-fake.com\tTRUE\t/\tFALSE\t9999999999\tsession_id\tFAKE_COOKIE_VALUE\n",
        encoding="utf-8",
    )

    # Autofill directory
    autofill_dir = victim_dir / "Autofill"
    autofill_dir.mkdir(exist_ok=True)
    (autofill_dir / "Chrome_Default.txt").write_text(
        "Name: John Doe\nEmail: mockuser@example-fake.com\nPhone: 555-0100\n",
        encoding="utf-8",
    )

    # Important.txt — simulates stealer internal log with fake bot tokens
    # Token format is real format, but IDs are in reserved/documentation ranges
    (victim_dir / "Important.txt").write_text(
        "=== Stealer Runtime Log (MOCK) ===\n"
        "BOT ID: 98127391-MOCK\n"
        "SYS: Windows 10 x64\n"
        "IP: 203.0.113.42\n"
        "==================================\n"
        "[C2 Config]\n"
        "gate: https://203.0.113.99/gate.php\n"
        "build: campaign_mock_2024\n"
        "[Telegram Config]\n"
        "token=12345678901:fake-bot-token-AAABBBCCC12345678901\n"
        "chat_id=-1001234567890\n"
        "[Discord]\n"
        "webhook: https://discord.com/api/webhooks/111222333444555/FakeWebhookTokenABCDEFGHIJKLMN\n"
        "[Connection]\n"
        "Connecting to drop zone -> 203.0.113.88:8080\n"
        "Internal staging: 192.168.1.10\n"
        "Loopback check: 127.0.0.1\n",
        encoding="utf-8",
    )

    # Screenshot placeholder
    (victim_dir / "Screenshot.jpg").write_bytes(b"FAKE_JPEG_PLACEHOLDER")

    print(f"[+] Mock stealer dump created at: {victim_dir}")
    return victim_dir


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def merge_indicators(results: List[Tuple[Dict, str, str]]) -> Dict:
    """Merge indicator lists from multiple victim folders into one summary."""
    merged: Dict[str, set] = {
        "telegram_tokens": set(),
        "discord_webhooks": set(),
        "external_ips": set(),
        "c2_panel_urls": set(),
        "credential_urls": set(),
    }
    families: List[str] = []
    victims: List[str] = []

    for indicators, family, victim_id in results:
        for key in merged:
            merged[key].update(indicators.get(key, []))
        families.append(family)
        victims.append(victim_id)

    return {
        "victims": victims,
        "family_detections": families,
        "indicators": {k: sorted(v) for k, v in merged.items()},
        "summary": {
            "victim_count": len(victims),
            "token_count": len(merged["telegram_tokens"]),
            "ip_count": len(merged["external_ips"]),
            "c2_url_count": len(merged["c2_panel_urls"]),
            "credential_url_count": len(merged["credential_urls"]),
        },
    }


def format_text(data: Dict, token_validation: Optional[Dict] = None) -> str:
    """Human-readable text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  Stealer Log Parser — Extracted Indicators")
    lines.append("=" * 60)

    summary = data.get("summary", {})
    lines.append(f"\n[+] Victims processed : {summary.get('victim_count', 0)}")
    lines.append(f"[+] Telegram tokens   : {summary.get('token_count', 0)}")
    lines.append(f"[+] External IPs      : {summary.get('ip_count', 0)}")
    lines.append(f"[+] C2 panel URLs     : {summary.get('c2_url_count', 0)}")
    lines.append(f"[+] Credential URLs   : {summary.get('credential_url_count', 0)}")

    families = data.get("family_detections", [])
    if families:
        family_counts: Dict[str, int] = {}
        for f in families:
            family_counts[f] = family_counts.get(f, 0) + 1
        lines.append("\n[+] Stealer Family Detection:")
        for fam, count in sorted(family_counts.items()):
            lines.append(f"    {fam}: {count} victim(s)")

    indicators = data.get("indicators", {})

    if indicators.get("telegram_tokens"):
        lines.append("\n[+] Telegram Bot Tokens:")
        for token in indicators["telegram_tokens"]:
            # Partially redact for display — preserve first 12 chars + suffix hint
            redacted = token[:12] + "..." + token[-4:]
            lines.append(f"    {redacted}")
            if token_validation and token in token_validation:
                val = token_validation[token]
                if val.get("ok"):
                    result = val["result"]
                    lines.append(f"      -> Bot: @{result.get('username', 'unknown')} "
                                  f"(ID: {result.get('id', '?')})")
                    if val.get("_mock"):
                        lines.append("      -> [MOCK response — no real API call made]")
                else:
                    lines.append(f"      -> Validation failed: {val.get('description', '')}")

    if indicators.get("discord_webhooks"):
        lines.append("\n[+] Discord Webhooks:")
        for wh in indicators["discord_webhooks"]:
            lines.append(f"    {wh[:60]}...")

    if indicators.get("external_ips"):
        lines.append("\n[+] External IPs:")
        for ip in indicators["external_ips"]:
            lines.append(f"    {ip}")

    if indicators.get("c2_panel_urls"):
        lines.append("\n[+] C2 Panel URLs:")
        for url in indicators["c2_panel_urls"]:
            lines.append(f"    {url}")

    if indicators.get("credential_urls"):
        lines.append(f"\n[+] Credential URLs (first {len(indicators['credential_urls'])}):")
        for url in indicators["credential_urls"]:
            lines.append(f"    {url}")

    lines.append("\n" + "=" * 60)
    lines.append("[!] Next steps:")
    lines.append("    1. Validate tokens: GET https://api.telegram.org/bot<TOKEN>/getMe")
    lines.append("    2. Map IPs to ASN/hosting via BGP lookup")
    lines.append("    3. JARM-scan C2 IPs (Module 0x01) for fingerprinting")
    lines.append("    4. Cluster SSH keys across ASN range (Module 0x03)")
    lines.append("=" * 60)

    return "\n".join(lines)


def format_json(data: Dict, token_validation: Optional[Dict] = None) -> str:
    """JSON output, optionally including token validation results."""
    output = dict(data)
    if token_validation:
        output["token_validation"] = token_validation
    return json.dumps(output, indent=2)


def format_csv(data: Dict) -> str:
    """
    CSV output with one row per indicator.
    Columns: type, value, victim_id (blank for merged output).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["indicator_type", "value", "note"])

    indicators = data.get("indicators", {})
    families = data.get("family_detections", [])
    family_str = ", ".join(sorted(set(families))) if families else "Unknown"

    for token in indicators.get("telegram_tokens", []):
        writer.writerow(["telegram_token", token, family_str])
    for wh in indicators.get("discord_webhooks", []):
        writer.writerow(["discord_webhook", wh, family_str])
    for ip in indicators.get("external_ips", []):
        writer.writerow(["external_ip", ip, family_str])
    for url in indicators.get("c2_panel_urls", []):
        writer.writerow(["c2_panel_url", url, family_str])
    for url in indicators.get("credential_urls", []):
        writer.writerow(["credential_url", url, family_str])

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def batch_process_directory(directory: Path) -> List[Tuple[Dict, str, str]]:
    """
    Process all files and subdirectories in a directory.
    - Subdirectories are treated as individual victim log folders.
    - .zip files are extracted and processed.
    - Loose .txt files are processed as individual files.
    """
    results = []
    directory = Path(directory)

    # Victim subdirectories
    for subdir in sorted(directory.iterdir()):
        if subdir.is_dir():
            indicators, family = process_directory(subdir)
            results.append((indicators, family, subdir.name))

    # Loose ZIP archives
    for zipf in sorted(directory.glob("*.zip")):
        tmp = directory / ("_extract_" + zipf.stem)
        victim_results = process_archive(zipf, tmp)
        results.extend(victim_results)

    # Loose text files (if no subdirs found)
    if not results:
        for txtf in sorted(directory.glob("*.txt")):
            indicators, family = process_single_file(txtf)
            results.append((indicators, family, txtf.name))

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 0x05 — Stealer Log Parser (educational, defensive use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python leak_parser.py --mock\n"
            "  python leak_parser.py -f raw_data/Important.txt\n"
            "  python leak_parser.py -d ./dumps/ --format json\n"
            "  python leak_parser.py -d ./dumps/ --format csv --validate-tokens\n"
        ),
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--mock", action="store_true",
        help="Generate a synthetic mock stealer dump and process it (safe demo mode)",
    )
    mode.add_argument(
        "-f", "--file", metavar="FILE",
        help="Path to a single stealer log file (.txt or .zip)",
    )
    mode.add_argument(
        "-d", "--directory", metavar="DIR",
        help="Directory of stealer log folders or loose files",
    )
    p.add_argument(
        "--format", choices=["text", "json", "csv"], default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--validate-tokens", action="store_true",
        help="Validate extracted Telegram bot tokens via the Bot API "
             "(uses mock responses in --mock mode; live API otherwise — "
             "see OPSEC guidance in Module 0x05)",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Default to mock mode if no mode selected
    if not args.mock and not args.file and not args.directory:
        print("[*] No input specified — running in mock/demo mode.")
        print("[*] Use --help for usage options.\n")
        args.mock = True

    use_mock_tokens = True  # Always mock tokens unless live mode explicitly requested
    results: List[Tuple[Dict, str, str]] = []

    if args.mock:
        print("[*] Mock mode: generating synthetic stealer log structure...")
        tmp_dir = Path("tmp") / "mock_stealer_dump"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        create_mock_stealer_dump(tmp_dir)
        results = batch_process_directory(tmp_dir)

    elif args.file:
        filepath = Path(args.file)
        if not filepath.exists():
            print(f"[x] File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        if filepath.suffix.lower() == ".zip":
            tmp_dir = Path("tmp") / ("extract_" + filepath.stem)
            results = process_archive(filepath, tmp_dir)
        else:
            indicators, family = process_single_file(filepath)
            results = [(indicators, family, filepath.name)]
        use_mock_tokens = False  # User is working with real files

    elif args.directory:
        directory = Path(args.directory)
        if not directory.is_dir():
            print(f"[x] Directory not found: {directory}", file=sys.stderr)
            sys.exit(1)
        results = batch_process_directory(directory)
        use_mock_tokens = False

    if not results:
        print("[!] No data found to process.", file=sys.stderr)
        sys.exit(1)

    # Merge all victim results
    data = merge_indicators(results)

    # Token validation
    token_validation = None
    if args.validate_tokens:
        tokens = data["indicators"].get("telegram_tokens", [])
        if tokens:
            print(f"\n[*] Validating {len(tokens)} Telegram token(s)...")
            if use_mock_tokens:
                print("[*] Using mock validation (no real API calls made)")
            token_validation = validate_tokens(tokens, use_mock=use_mock_tokens)
        else:
            print("[*] No Telegram tokens found to validate.")

    # Output
    print()
    if args.format == "json":
        print(format_json(data, token_validation))
    elif args.format == "csv":
        print(format_csv(data))
    else:
        print(format_text(data, token_validation))


if __name__ == "__main__":
    main()
