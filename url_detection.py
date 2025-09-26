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
    url_pattern = r'((?:https?://|www\.)[^\s,\)\]>\[}]+)'
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

# Function to validate the url, returns true if valid, false if suspicious
def URLvalidator(url):
    try:
        result = urlparse(url.strip())  # strip spaces first

        # Scheme must be http or https
        if result.scheme not in ("http", "https"):
            return False

        # Netloc must look like a domain
        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        )

        # If the netloc (domain part) does not match this pattern,
        # then it’s not a proper domain → treat it as phishing.
        if not domain_pattern.match(result.netloc):
            return False

        return True
    except:
        return False


