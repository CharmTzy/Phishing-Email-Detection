# Import libraries 
import re
from urllib.parse import urlparse
import tldextract # pip install tldextract
from utilities import read_file, load_safe_hosts

# Load lists once at the top
TRUSTED_SITES = read_file("legitimate_domains.csv")  # Set of trusted domains
SAFE_URLS = load_safe_hosts("safe_urls.txt")    # Set of safe hostnames

# Function to extract registrable domains from any URLs in email text
def extract_urls(email):
    """
    Extracts domains from URLs found in an email string.
    Returns a list of registrable domains (e.g. 'paypal.com', 'google.com').
    """
    
    # Ensure the input is a string (avoid errors if input is None or other type)
    if not isinstance(email, str):
        return None

    # Improved regex pattern to capture URLs more accurately
    # Matches http://, https://, or www. followed by domain-like patterns
    url_pattern = r'(?:https?://|www\.)[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(?:[/?#][^\s]*)?'
    urls = re.findall(url_pattern, email)  # list of matched raw URLs

    domains = []

    for u in urls:
        # Normalise "www." links by adding scheme (urlparse needs it)
        if u.startswith("www."):
            u = "http://" + u 

        # Parse the URL into components (scheme, netloc, path, etc.)
        parsed = urlparse(u)
        host = parsed.hostname  # e.g. "secure-login.paypal.com"

        if host:
            # Use tldextract to split into (subdomain, domain, suffix)
            ext = tldextract.extract(host)

            if ext.domain and ext.suffix:
                # Recombine domain + suffix into registrable domain
                # e.g. "secure-login.paypal.com" → "paypal.com"
                registrable_domain = f"{ext.domain}.{ext.suffix}".lower()
                if registrable_domain not in domains:  # Avoid duplicates
                    domains.append(registrable_domain)
            else:
                # Fallback: just use the raw hostname
                host_lower = host.lower()
                if host_lower not in domains:  # Avoid duplicates
                    domains.append(host_lower)

    # Return None if no domains were found, else return the list
    return domains if domains else None


# Function to validate the url, returns true if valid, false if suspicious
def URLvalidator(url):
    """
    Validates a URL against trusted sites and safe URLs.
    Returns True if the URL is from a trusted/safe domain, False otherwise.
    """
    try:
        # Prepend https:// if missing scheme
        if "://" not in url:
            url = "https://" + url

        result = urlparse(url)

        # Scheme must be http or https
        if result.scheme not in ("http", "https"):
            return False

        # Must have a valid hostname
        if not result.hostname:
            return False

        hostname = result.hostname.lower()
        
        # Basic domain validation pattern
        domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

        # If the hostname doesn't match domain pattern, it's suspicious
        if not domain_pattern.match(hostname):
            return False 

        # Extract registrable domain for comparison
        registrable_domain = None
        try:
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix:
                registrable_domain = f"{ext.domain}.{ext.suffix}".lower()
        except:
            registrable_domain = hostname  # fallback to full hostname

        # Check if registrable domain is in trusted sites
        if registrable_domain and registrable_domain in TRUSTED_SITES:
            print("This is working")
            return True
            
        # Check if registrable domain is in safe URLs  
        if registrable_domain and registrable_domain in SAFE_URLS:
            return True
            
        # Also check if full hostname is in safe URLs (for exact hostname matches)
        if hostname in SAFE_URLS:
            return True

        # If we reach here, the URL is not in our trusted/safe lists
        return False
        
    except Exception:
        # Any parsing error makes it suspicious
        return False


# Helper function to check if a domain is trusted (for use in other parts of code)
def is_trusted_domain(domain):
    """
    Check if a domain (registrable domain like 'paypal.com') is in trusted sites.
    """
    if not domain:
        return False
    return domain.lower() in TRUSTED_SITES


# Helper function to check if a hostname is safe (for use in other parts of code)  
def is_safe_hostname(hostname):
    """
    Check if a hostname (full hostname like 'secure.paypal.com') is in safe URLs.
    """
    if not hostname:
        return False
    return hostname.lower() in SAFE_URLS
