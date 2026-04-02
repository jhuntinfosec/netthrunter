# Module 0x0A: Data Science for Hunting

## Overview

When the volume of data becomes too large for simple manual tracking or linear logic rules, we turn to math. Identifying malicious domains often relies on detecting high randomness in string generation.

## Key Concepts
* **Shannon Entropy**: Measuring the amount of mathematical randomness within hostnames or URIs.
* **K-Means Clustering**: Grouping adversary infrastructure mathematically by vectorizing their properties.
* **Anomaly Detection**: Flagging outliers in massive passive DNS logs.

### The Shannon Entropy Formula
$$H = -\sum_{i=1}^{n} P(x_i) \log_b P(x_i)$$

High entropy ($H$) in a sub-domain or a TLS certificate "Common Name" is a primary trigger for further investigation into automated infrastructure generation (DGAs).

---
## 🛠️ Module Project: Shannon Entropy Domain Classifier
*Reference: Data Engineering for Cybersecurity*

We will process thousands of domains and calculate their randomness to filter out standard, readable English sites (like `google.com`) and instantly identify DGA behavior (`x18jdfx1zz.su`).

### The Objective
1. Write a Python function calculating the Shannon Entropy of a string.
2. Read a massive CSV file using `pandas`.
3. Apply the function to the `Domain` column.
4. Output any domains whose Entropy score is higher than 3.5 (indicating non-standard language/randomness).

### Boilerplate Setup
```python
# math_hunter.py
import pandas as pd
import math
from collections import Counter

def shannon_entropy(data_string):
    if not data_string:
        return 0
    entropy = 0
    for x in Counter(data_string).values():
        p_x = float(x) / len(data_string)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_domains(file_path):
    # Imagine a CSV: Domain, IP, First_Seen
    df = pd.read_csv(file_path)
    
    # Calculate entropy and add as a new column
    df['Entropy'] = df['Domain'].apply(shannon_entropy)
    
    # Filter highly random domains
    dga_candidates = df[df['Entropy'] >= 3.5]
    return dga_candidates

if __name__ == "__main__":
    # Create fake test data on the fly if needed
    test_dict = {"Domain": ["microsoft.com", "jhsd88f3h12d.com", "apple.com", "qq-adminxyz-auth.tk"]}
    test_df = pd.DataFrame(test_dict)
    
    test_df['Entropy'] = test_df['Domain'].apply(shannon_entropy)
    print("\n--- Entropy Analysis ---")
    print(test_df.sort_values(by="Entropy", ascending=False))
```

**Takeaway:** A fully automated mechanism for classifying and alerting on machine-generated, randomly customized threat actor infrastructure!
