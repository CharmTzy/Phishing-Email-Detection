# Import libraries 
import re
from urllib.parse import urlparse
import tldextract  # pip install tldextract

# Function to extract registrable domains from any URLs in email text
def extract_urls(email):
    """
    Extracts domains from URLs found in an email string.
    Returns a list of registrable domains (e.g. 'paypal.com', 'google.com').
    """

    # Ensure the input is a string (avoid errors if input is None or other type)
    if not isinstance(email, str):
        return None
    
    # Regex pattern to capture links:
    # - start with http:// or https:// OR www.
    # - followed by any run of non-space, non-closing characters
    url_pattern = r'((?:https?://|www\.)[^\s,)\]>]+)'
    urls = re.findall(url_pattern, email)   # list of matched raw URLs

    domains = []

    for u in urls:
        # Normalise "www." links by adding scheme (urlparse needs it)
        if u.startswith("www."):
            u = "http://" + u   

        # Parse the URL into components (scheme, netloc, path, etc.)
        parsed = urlparse(u)
        host = parsed.hostname  # e.g. "secure-login.paypai.com"

        if host:
            # Use tldextract to split into (subdomain, domain, suffix)
            ext = tldextract.extract(host)

            if ext.domain and ext.suffix:
                # Recombine domain + suffix into registrable domain
                # e.g. "secure-login.paypai.com" → "paypai.com"
                domains.append(f"{ext.domain}.{ext.suffix}".lower())
            else:
                # Fallback: just use the raw hostname
                domains.append(host.lower())

    # Return None if no domains were found, else return the list
    return domains if domains else None


# Example of applying to a DataFrame column:
import pandas as pd

# Define your datasets and which column to use
datasets_info = {
    "cleaned_SA": {"path": r"Datasets\cleaned_SA.csv", "column": "body"},
    "cleaned_enron": {"path": r"Datasets\cleaned_enron.csv", "column": "body"},
    # "enronEmails": {"path": r"Datasets\enronEmails.csv", "column": "message"}, # got error fixed tmrw
    "spamAssassin": {"path": r"Datasets\spamAssassin.csv", "column": "message"}
}

# Function to test dataset
def test_dataset(name, info):
    print(f"\n--- Processing {name} ---")
    data_ds = pd.read_csv(info["path"])
    
    # Apply extract_urls() to the appropriate column
    data_ds['extracted_domains'] = data_ds[info["column"]].apply(extract_urls)
    
    # Count number of domains per message
    data_ds['num_domains'] = data_ds['extracted_domains'].apply(
        lambda x: len(x) if x is not None else 0
    )
    
    # Print the first 5 rows
    print(data_ds[[info["column"], 'extracted_domains', 'num_domains']].head())
    return data_ds

# Loop through all datasets
all_data = {}
for name, info in datasets_info.items():
    all_data[name] = test_dataset(name, info)
