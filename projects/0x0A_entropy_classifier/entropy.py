#!/usr/bin/env python3
# Module 0x0A Capstone Project: Shannon Entropy Classifier
# Fully Working Reference Solution

import pandas as pd
import math
import os
from collections import Counter

def shannon_entropy(data_string: str) -> float:
    """
    Calculates the Shannon Entropy ($H$) of a string.
    Higher entropy indicates more randomness (closer to 5.0).
    Normal english words score ~2.5 to 3.2.
    """
    if not data_string or pd.isna(data_string):
        return 0.0
        
    entropy = 0.0
    # The string length
    n = len(data_string)
    
    for count in Counter(data_string).values():
        p_x = float(count) / n
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
            
    return round(entropy, 3)

def generate_test_dataset(filename: str):
    """
    Generates a CSV simulating a log of resolved DNS queries.
    """
    data = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "azure.com",
        "aws.amazon.com",
        # Obvious Malicious DGA patterns
        "x18jdfx1zz.su",
        "ab0cx939js83n.ru",
        "jhsd88f3h12d.com",
        "1298418abcc22.xyz",
        # Borderline cases
        "login-auth-v2.tk",
        "service-update-99.net"
    ]
    
    df = pd.DataFrame({"domain": data})
    df.to_csv(filename, index=False)
    print(f"[+] Generated mock dataset '{filename}' with {len(data)} rows.")

def analyze_domains(file_path: str, threshold: float = 3.5):
    """
    Loads domains, calculates entropy, and flags those over the threshold.
    """
    df = pd.read_csv(file_path)
    
    # 1. Strip the TLD off to just calculate the root word entropy to avoid bias from ".com"
    df['root_domain'] = df['domain'].apply(lambda x: str(x).split(".")[0] if isinstance(x, str) else "")
    
    # 2. Apply the mathematical function to the column
    df['entropy_score'] = df['root_domain'].apply(shannon_entropy)
    
    # 3. Sort for human readability
    df = df.sort_values(by="entropy_score", ascending=False)
    
    print("\n[*} Full Dataset Entropy Analysis:")
    print(df[['domain', 'entropy_score']].to_string(index=False))
    
    # 4. Filter the dataframe to only show DGA candidates
    dga_candidates = df[df['entropy_score'] >= threshold]
    
    print(f"\n[!] ALERT: Extracted {len(dga_candidates)} HIGH ENTROPY domains (Threshold: {threshold}):")
    if not dga_candidates.empty:
        print(dga_candidates[['domain', 'entropy_score']].to_string(index=False))

if __name__ == "__main__":
    test_csv = "dns_logs.csv"
    
    print("--- Module 0x0A: Data Science for Hunting ---")
    
    try:
        import pandas
    except ImportError:
        print("Please install pandas to run this script: `pip install pandas`")
        exit(1)
        
    generate_test_dataset(test_csv)
    analyze_domains(test_csv, threshold=3.4)
    
    # Clean up the test file
    if os.path.exists(test_csv):
        os.remove(test_csv)
