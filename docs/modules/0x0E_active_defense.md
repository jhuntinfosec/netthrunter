# Module 0x0E: Active Defense & Deception

Instead of hunting for adversary infrastructure actively, threat hunters can deploy deception infrastructure (honeypots, canaries) to passively capture adversary scanners.

## Key Concepts

1. **High-Interaction vs Low-Interaction Honeypots:** Tradeoffs in operational security.
2. **Scanner Fingerprinting:** Capturing the JA3/JARM of the automated scanners hitting your infrastructure to attribute the scanning campaigns.
3. **Decoy Telemetry:** Logging and enriching inbound connections.

## Target Audience
Defenders wanting to transition from passive reconnaissance to active intelligence gathering by setting traps for automated adversary discovery tools.

## Boilerplate Setup
The capstone project, `decoy_listener.py`, sets up a mock HTTP server that simulates a vulnerable directory listing and logs the incoming IPs for enrichment.

```bash
cd projects/0x0E_decoy_listener
python decoy_listener.py --port 8080
```



```python
#!/usr/bin/env python3
"""
decoy_listener.py — Active Defense Honeypot
Module 0x0E Capstone Project | AIH-C Curriculum

A lightweight HTTP listener that logs incoming scanners into the IOC schema.
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone

IOC_LOG = []

class DecoyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # Log the scanning IP
        IOC_LOG.append({
            "type": "ip",
            "value": client_ip,
            "context": {"path": self.path, "user_agent": self.headers.get("User-Agent")}
        })
        
        # Respond with a fake directory listing
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Index of /</h1><ul><li><a href='config.json'>config.json</a></li></ul></body></html>")

def main():
    parser = argparse.ArgumentParser(description="Decoy Listener Honeypot")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--demo", action="store_true", help="Run a mock simulation instead of binding port")
    args = parser.parse_args()

    if args.demo:
        # Mock simulation
        IOC_LOG.extend([
            {"type": "ip", "value": "198.51.100.2", "context": {"path": "/", "user_agent": "masscan/1.3.2"}},
            {"type": "ip", "value": "203.0.113.15", "context": {"path": "/config.json", "user_agent": "python-requests/2.28.1"}}
        ])
    else:
        print(f"[*] Starting decoy listener on port {args.port}. Press Ctrl+C to stop and dump IOCs.")
        server = HTTPServer(('', args.port), DecoyHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        server.server_close()

    # Output using IOC schema format
    ioc_output = {
        "metadata": {
            "source_module": "0x0E_decoy_listener",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "indicators": IOC_LOG
    }
    
    print("\n" + json.dumps(ioc_output, indent=2))

if __name__ == "__main__":
    main()
```
