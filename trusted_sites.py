import pandas as pd
import re
from collections import defaultdict

def getSiteList(filepath="legitimate_domains.csv"):
    """
    Load trusted domains dynamically from the legitimacy analysis output.
    """
    df = pd.read_csv(filepath)
    # Just return the list of domains
    return df['domain'].tolist()

def extract_email_domain(sender):
    """
    Extract domain from email address like 'Name <user@example.com>'
    """
    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender)
    if match:
        return match.group(1).lower()
    return None