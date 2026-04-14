from urllib.parse import urlparse

import tldextract

# Reads a text file and returns a set of cleaned lines.
def read_file(filepath):
    readText = set() # Auto remove duplicates
    
    # Check if it's a CSV file
    if filepath.endswith('.csv'):
        import csv
        with open(filepath, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                if 'domain' in row:
                    domain = row['domain'].strip().lower()
                    if domain:  # only add non-empty domains
                        readText.add(domain)
    else:
        # Regular text file processing
        with open(filepath, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip().lower()
                if line:  # only add non-empty lines
                    readText.add(line)
    return readText

# Function to load the url and extract the REGISTRABLE DOMAIN from the txt file
def load_safe_hosts(filepath):
    """
    Reads safe_urls.txt where each line may contain comma-separated URLs.
    Returns a set of registrable domains (e.g., 'apple.com', 'google.com') in lowercase.
    If a URL has no scheme, https:// is assumed.
    """
    domains = set()
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
                
                # If hostname is present, extract registrable domain
                if parsed.hostname:
                    try:
                        # Use tldextract to get registrable domain
                        ext = tldextract.extract(parsed.hostname)
                        if ext.domain and ext.suffix:
                            registrable_domain = f"{ext.domain}.{ext.suffix}".lower()
                            domains.add(registrable_domain)
                        else:
                            # Fallback to hostname if tldextract fails
                            domains.add(parsed.hostname.lower())
                    except:
                        # Fallback to hostname if tldextract fails  
                        domains.add(parsed.hostname.lower())
    return domains
