#!/usr/bin/env python3
# Module 0x05 Capstone Project: Automated Stealer Leak Parser
# Fully Working Reference Solution

import re
import json
import os

def create_mock_stealer_log(filename: str):
    """
    Writes a fabricated infostealer logs file to disk for our parser to test against.
    """
    content = """
    ======================
    BOT ID: 98127391-ABC
    SYS: Windows 10 x64
    IP: 198.51.100.42
    ======================
    [Credentials]
    url: https://discord.com/api/webhooks/111222333444/AbCdEfGhIjKlMnOpQrStUvWxYz
    url: https://api.telegram.org/bot1234567890:AAH-AbCdEfGhIjKlMnOpQrStUvWxYz/sendMessage
    [Connection]
    Connecting back to drop zone -> 203.0.113.88:8080
    ----------------------
    Another random config string...
    Some user text... token=5554443332:AABBCC_ddeeff112233
    Internal local IP: 192.168.1.10
    """
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        f.write(content)
    print(f"[+] Generated mock stealer artifact at '{filename}'.")

def parse_leak_file(filepath: str):
    """
    Loads text data and applies high-confidence regular expressions to extract C2 telemetry.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
            
        print(f"[*] Parsing {len(data)} bytes of unstructured leak data...")
        
        # Telegram Bot API Token Format: <Number>: <Alphanumeric_string>
        telegram_regex = re.compile(r"([0-9]{8,11}:[a-zA-Z0-9_-]{35})")
        # Standard IPv4 Format
        ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        # Discord Webhook
        discord_regex = re.compile(r"(https?://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+)")
        
        results = {
            "telegram_bots": list(set(telegram_regex.findall(data))),
            "discord_webhooks": list(set(discord_regex.findall(data))),
            "raw_ips": list(set(ip_regex.findall(data)))
        }
        
        # Filter logic to remove local / bogus IPs
        filtered_ips = []
        for ip in results["raw_ips"]:
            # Ignore standard local routing ranges
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
                continue
            filtered_ips.append(ip)
            
        results["external_ips"] = filtered_ips
        del results["raw_ips"]
        
        print("\n--- Extracted Telemetry ---")
        print(json.dumps(results, indent=3))
        
        print("\n[!] Take these Telegram Bot Tokens to the Telegram API: `https://api.telegram.org/bot<TOKEN>/getMe` to identify the threat actor!")
        
    except FileNotFoundError:
        print(f"[x] File {filepath} not found.")

if __name__ == "__main__":
    target_file = "raw_data/Important.txt"
    create_mock_stealer_log(target_file)
    
    parse_leak_file(target_file)
