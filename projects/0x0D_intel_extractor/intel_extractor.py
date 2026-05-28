#!/usr/bin/env python3
"""
intel_extractor.py - Module 0x0D Capstone: LLM-Assisted Intel Extraction
========================================================================
Performs deterministic IOC extraction, optionally asks an LLM provider for
role labels, validates output, and emits the AIH-C IOC schema.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


PATTERNS = {
    "ip": re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|top|xyz|pw|cc|onion)\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "hash": re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "wallet": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,62}\b"),
}

ROLE_KEYWORDS = {
    "c2": ["c2", "command", "beacon", "callback"],
    "stager": ["stager", "payload", "loader", "download"],
    "panel": ["panel", "admin", "login"],
    "redirector": ["redirect", "front", "proxy"],
    "exfil": ["exfil", "upload", "drop"],
}


@dataclass
class ExtractedIndicator:
    type: str
    value: str
    confidence: str
    role: str
    source_span: str
    method: str


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_text(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    return args.text or (
        "C2 was observed at 185.220.101.77 and https://update-cdn.example.com/payload.bin. "
        "Payload SHA256 d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2. "
        "Ransom wallet bc1qactorwallet0000000000000000000000000 was listed in the note."
    )


def span_for(text: str, start: int, end: int, radius: int = 50) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return " ".join(text[left:right].split())


def infer_role(span: str) -> str:
    lowered = span.lower()
    for role, terms in ROLE_KEYWORDS.items():
        if any(term in lowered for term in terms):
            return role
    return "unknown"


def deterministic_extract(text: str) -> list[ExtractedIndicator]:
    seen: set[tuple[str, str]] = set()
    indicators: list[ExtractedIndicator] = []
    for kind, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(".,);]")
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)
            span = span_for(text, match.start(), match.end())
            indicators.append(
                ExtractedIndicator(
                    type=kind,
                    value=value,
                    confidence="high" if kind in {"ip", "hash", "cve"} else "medium",
                    role=infer_role(span),
                    source_span=span,
                    method="regex",
                )
            )
    return indicators


def query_provider(provider: str, text: str) -> dict:
    if provider == "mock":
        return {"roles": {"185.220.101.77": "c2", "update-cdn.example.com": "stager"}}

    prompt = (
        "Extract threat infrastructure roles from this report. Return JSON only with "
        'shape {"roles": {"indicator": "c2|stager|panel|redirector|exfil|unknown"}}.\n\n'
        f"{text}"
    )
    try:
        if provider == "ollama":
            import httpx

            response = httpx.post(
                "http://localhost:11434/api/generate",
                json={"model": "llama3", "prompt": prompt, "stream": False, "format": "json"},
                timeout=30,
            )
            return json.loads(response.json().get("response", "{}"))
        commands = {
            "claude": ["claude", "-p"],
            "gemini": ["gemini", "ask"],
            "codex": ["codex", "query"],
        }
        result = subprocess.run(commands[provider] + [prompt], capture_output=True, text=True, check=False)
        return json.loads(result.stdout or "{}")
    except Exception as exc:  # LLMs are optional in this lab.
        print(f"[!] Provider {provider} unavailable or returned invalid JSON: {exc}", file=sys.stderr)
        return {}


def apply_llm_roles(indicators: list[ExtractedIndicator], roles: dict) -> None:
    for item in indicators:
        llm_role = roles.get(item.value) or roles.get(item.value.lower())
        if llm_role in ROLE_KEYWORDS or llm_role == "unknown":
            item.role = llm_role
            item.method = f"{item.method}+llm"


def output_table(indicators: Iterable[ExtractedIndicator]) -> None:
    print(f"{'TYPE':8} {'ROLE':10} {'CONF':8} VALUE")
    print("-" * 88)
    for item in indicators:
        print(f"{item.type:8} {item.role:10} {item.confidence:8} {item.value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Schema-first IOC extractor")
    parser.add_argument("-f", "--file", help="Text report to parse")
    parser.add_argument("-t", "--text", help="Raw text to parse")
    parser.add_argument("-p", "--provider", choices=["mock", "ollama", "claude", "gemini", "codex", "none"], default="mock")
    parser.add_argument("--format", choices=["json", "table"], default="json")
    args = parser.parse_args()

    text = load_text(args)
    indicators = deterministic_extract(text)
    if args.provider != "none":
        apply_llm_roles(indicators, query_provider(args.provider, text).get("roles", {}))

    if args.format == "table":
        output_table(indicators)
        return

    print(
        json.dumps(
            {
                "metadata": {
                    "source_module": "0x0D_intel_extractor",
                    "provider": args.provider,
                    "generated_at": now_utc(),
                },
                "indicators": [
                    {"type": item.type, "value": item.value, "context": asdict(item)}
                    for item in indicators
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
