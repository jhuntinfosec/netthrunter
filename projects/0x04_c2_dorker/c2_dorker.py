#!/usr/bin/env python3
# Module 0x04 Capstone Project: C2 Open Directory Scanner
# Fully Working Reference Solution

import asyncio
import httpx
import re
import sys
import argparse

async def check_directory_listing(url: str, client: httpx.AsyncClient) -> list:
    """
    Fetches the URL and detects if it points to an exposed open directory index.
    """
    # Ensure scheme
    if not url.startswith("http"):
        url = f"http://{url}"
        
    try:
        response = await client.get(url)
        # Check standard Apache, Nginx, or Python open directory footprints
        if response.status_code == 200 and ("Index of /" in response.text or "Directory listing for" in response.text):
            print(f"[!] [OPEN DIR] Found exposed directory at: {url}")
            
            # Extract out any files via regex (Looking basically for href="somefile.bin")
            links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
            
            # Filter out standard directory ascending links like "../"
            interesting_files = [l for l in links if l not in ("/", "../", "?C=N;O=D", "?C=M;O=A", "?C=S;O=A", "?C=D;O=A")]
            return (url, interesting_files)
            
        print(f"[-] [CLOSED] {url} (Status: {response.status_code})")
        return None
        
    except httpx.RequestError as e:
        print(f"[x] [ERROR] Could not connect to {url}: {e}")
        return None

async def worker(queue: asyncio.Queue, client: httpx.AsyncClient, results: list):
    """
    Consumes URLs from the queue and runs the directory check.
    """
    while True:
        url = await queue.get()
        result = await check_directory_listing(url, client)
        if result:
            results.append(result)
        queue.task_done()

async def main(target_list: list, concurrency: int = 10):
    queue = asyncio.Queue()
    results = []
    
    # Fill the queue
    for t in target_list:
        queue.put_nowait(t)
        
    # Setup HTTP client with optimizations to avoid SSL errors on weird C2s
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    timeout = httpx.Timeout(5.0)
    # C2 servers often have invalid/expired/self-signed certs, we must ignore them!
    verify_certs = False 

    async with httpx.AsyncClient(limits=limits, timeout=timeout, verify=verify_certs) as client:
        # Create a pool of workers
        tasks = []
        for _ in range(concurrency):
            task = asyncio.create_task(worker(queue, client, results))
            tasks.append(task)
            
        # Wait until everything in the queue is processed
        await queue.join()
        
        # Stop workers
        for task in tasks:
            task.cancel()

    print("\n--- Summary Report ---")
    if not results:
        print("No open directories found.")
    else:
        for url, files in results:
            print(f"Target: {url}")
            print(f"Files exposed: {', '.join(files[:5])}{' ...' if len(files)>5 else ''}")
            print("-" * 20)

if __name__ == "__main__":
    # In a real scenario, this would read from a massive text file.
    # We will simulate a local server and some common testing endpoints.
    mock_targets = [
        "example.com",
        "google.com",
        # Using a public test URL that is known to list files, or localhost.
        "definitely-not-a-real-domain-1234.xyz" 
    ]
    
    print("[*] Starting Asynchronous C2 Dorker...")
    asyncio.run(main(mock_targets, concurrency=5))
