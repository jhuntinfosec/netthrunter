#!/usr/bin/env python3
# Module 0x02 Capstone Project: CT Log Async Parser
# Fully Working Reference Solution

import asyncio
import httpx
import json
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

async def fetch_ct_logs(keyword: str, limit: int = 50) -> List[Dict]:
    """
    Query the crt.sh JSON API for certificates containing the target keyword.
    """
    url = f"https://crt.sh/?q={keyword}&output=json"
    logging.info(f"Querying Certificate Transparency logs for keyword: '{keyword}'")
    
    # We use a custom timeout and standard headers to ensure API stability
    timeout = httpx.Timeout(20.0, connect=10.0)
    headers = {"User-Agent": "AIH-C-ThreatHunting-Curriculum"}
    
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            
            data = response.json()
            # Deduplicate by name_value
            unique_domains = []
            seen = set()
            for entry in data:
                domain = entry.get('name_value', '').lower()
                if domain and domain not in seen:
                    seen.add(domain)
                    unique_domains.append(entry)
                if len(unique_domains) >= limit:
                    break
                    
            return unique_domains
            
        except httpx.HTTPError as e:
            logging.error(f"HTTP Exception while querying crt.sh: {e}")
            return []
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode crt.sh response: {e}")
            return []

async def main():
    # Test tracking newly registered phishing/admin portals
    target_keyword = "admin-login"
    
    results = await fetch_ct_logs(target_keyword, limit=10)
    
    if not results:
        logging.warning(f"No results found for {target_keyword} or API was rate-limited.")
        return

    print("\n" + "="*50)
    print(f"[*] Top 10 Newly Discovered Domains For: '{target_keyword}'")
    print("="*50)
    
    for idx, r in enumerate(results, 1):
        domain = r.get('name_value')
        issuer = r.get('issuer_name', 'Unknown').split("O=")[-1].split(",")[0]
        print(f"[{idx}] {domain} (Issuer: {issuer})")

if __name__ == "__main__":
    asyncio.run(main())
