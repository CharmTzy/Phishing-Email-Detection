# Import Libraries
import os
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')
from urllib.parse import urlparse


# Create directory if it doesn't exist
def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)
    return path

# Join paths
def join_paths(*args):
    return os.path.join(*args)

# Write text to a file
def write_to_file(file_path, content):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

# Reads a text file and returns a set of cleaned lines.
def read_file(filepath):
    readText = set() # Auto remove duplicates
    with open(filepath, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip().lower()
            if line:   # only add non-empty lines
                readText.add(line)
    return readText

# Function to load the url and extract the domain from the txt file
def load_safe_hosts(filepath):
    """
    Reads safe_urls.txt where each line may contain comma-separated URLs.
    Returns a set of hostnames (netloc) in lowercase.
    If a URL has no scheme, https:// is assumed.
    """
    hosts = set()
    with open(filepath, "r", encoding="utf-8") as file:
        for line in file:
            for url in line.split(","):
                url = url.strip()

                # Check if its an url
                if not url:
                    continue

                # ensure scheme is present
                if "://" not in url:
                    url = "https://" + url
                
                # Parse the URL into components
                parsed = urlparse(url)

                # If hostname is present, add it in lowercase
                if parsed.hostname:
                    hosts.add(parsed.hostname.lower())
    return hosts
