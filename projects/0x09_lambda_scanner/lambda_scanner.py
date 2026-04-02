#!/usr/bin/env python3
# Module 0x09 Capstone Project: Distributed AWS Lambda Scanner
# Fully Working Reference Solution

import urllib.request
import urllib.error
import ssl
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda entry point.
    By deploying this code to Lambda and calling it via API Gateway or boto3,
    the threat actor sees AWS IP addresses probing their infrastructure, 
    hiding your true research IP.
    """
    target = event.get('target', 'example.com')
    port = event.get('port', 443)
    
    logger.info(f"Initiating distributed scan against {target}:{port}")
    
    # Establish a barebones TLS connection and pull the certificate details
    # We ignore standard validations to inspect raw C2 configurations
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = f"https://{target}:{port}"
        
        # Spoof a standard Windows User-Agent to avoid immediate blocklists
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
        }
        
        req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=5.0, context=ctx) as response:
            server_header = response.getheader('Server', 'Unknown')
            cert = response.getpeercert()
            
            # Extract basic certificate issuing metadata
            issuer_data = None
            if cert and 'issuer' in cert:
                issuer_data = dict(x[0] for x in cert['issuer'])
                
            return {
                'statusCode': 200,
                'target': target,
                'status': 'SUCCESS',
                'server_header': server_header,
                'cert_issuer': issuer_data,
                'http_status_code': response.code
            }
            
    except urllib.error.HTTPError as e:
        # We still connected, but got an HTTP error (common with C2s returning 404/403)
        return {
            'statusCode': 200,
            'target': target,
            'status': 'HTTP_ERROR',
            'http_status_code': e.code,
            'server_header': e.headers.get('Server', 'Unknown'),
            'error_msg': str(e)
        }
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return {
            'statusCode': 500,
            'target': target,
            'status': 'CONNECTION_FAILED',
            'error': str(e)
        }

if __name__ == "__main__":
    # Local Test Execution simulating an AWS Lambda call
    print("[*] Simulating Serverless Lambda Scanner locally...")
    
    mock_event = {"target": "google.com", "port": 443}
    mock_context = {} # In AWS, this holds memory and timeout configs
    
    result = lambda_handler(mock_event, mock_context)
    
    print("\n--- Lambda Scan Results ---")
    print(json.dumps(result, indent=2))
    
    print("\n[+] To distribute this scan, zip this file and upload it to an AWS Lambda function!")
