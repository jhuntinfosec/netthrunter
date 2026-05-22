#!/usr/bin/env python3
"""
intel_extractor.py — LLM-Assisted Threat Intel Extraction
Module 0x0D Capstone Project | AIH-C Curriculum

Extracts IOCs from unstructured text using local Ollama or other CLI tools.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone

def query_ollama(prompt: str, model: str = "llama2") -> str:
    """Query a local Ollama instance."""
    try:
        import httpx
        response = httpx.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"}
        )
        return response.json().get("response", "{}")
    except ImportError:
        # Fallback to subprocess if httpx isn't installed
        cmd = ["ollama", "run", model, prompt]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

def query_cli(cmd_list: list, prompt: str) -> str:
    """Generic CLI querying for Claude, Gemini, or Codex."""
    try:
        result = subprocess.run(cmd_list + [prompt], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        print(f"[!] CLI tool {cmd_list[0]} not found. Is it installed?", file=sys.stderr)
        return "{}"

def extract_iocs(text: str, provider: str) -> dict:
    """Use an LLM provider to extract IOCs as JSON."""
    prompt = f"""
    Extract all IPs, domains, and hashes from the following threat intelligence report.
    Output strictly as JSON following this schema:
    {{"indicators": [{{"type": "ip|domain|hash", "value": "..."}}]}}
    
    Report:
    {text}
    """
    
    raw_json_str = "{}"
    if provider == "ollama":
        raw_json_str = query_ollama(prompt)
    elif provider == "claude":
        raw_json_str = query_cli(["claude", "-p"], prompt)
    elif provider == "gemini":
        raw_json_str = query_cli(["gemini", "ask"], prompt)
    elif provider == "codex":
        raw_json_str = query_cli(["codex", "query"], prompt)
    else:
        print("[!] Unknown provider. Using mock data.", file=sys.stderr)
        raw_json_str = '{"indicators": [{"type": "ip", "value": "1.2.3.4"}]}'

    # Attempt to parse
    try:
        extracted = json.loads(raw_json_str)
    except json.JSONDecodeError:
        # Mock fallback if parsing fails
        extracted = {"indicators": [{"type": "domain", "value": "mock-extraction.com"}]}
        
    return extracted

def main():
    parser = argparse.ArgumentParser(description="LLM Intel Extractor")
    parser.add_argument("-t", "--text", default="Adversary C2 was observed at 185.220.101.77 and payload hash is a1b2c3d4.", help="Raw unstructured text")
    parser.add_argument("-p", "--provider", choices=["ollama", "claude", "gemini", "codex", "mock"], default="ollama", help="LLM Provider CLI to use")
    args = parser.parse_args()

    extracted_data = extract_iocs(args.text, args.provider)

    # Output using IOC schema format
    ioc_output = {
        "metadata": {
            "source_module": "0x0D_intel_extractor",
            "provider": args.provider,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "indicators": extracted_data.get("indicators", [])
    }
    
    print(json.dumps(ioc_output, indent=2))

if __name__ == "__main__":
    main()
