from trusted_sites import getSiteList,extract_email_domain
from edit_distance import editDistance
from url_detection import extract_urls, URLvalidator
from keyword_detection import keyword_score, find_keywords, highlight_keywords
from domain_detection import check_domain_in_csv
import re

def extract_base_domain(url):
    """
    Extract the base domain from a URL by removing protocol and subdomain.
    Example: https://mail.example.com/path -> example.com
    """
    # Remove protocol (http://, https://, etc.)
    domain = re.sub(r'^.*?://', '', url)
    
    # Remove path, query parameters, and fragments
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    
    # Extract the base domain (last two parts of the domain)
    parts = domain.split('.')
    if len(parts) > 2:
        # Handle cases like .co.uk, .com.au
        if parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu'] and parts[-1] in ['uk', 'au', 'nz', 'jp', 'in']:
            base_domain = '.'.join(parts[-3:])
        else:
            base_domain = '.'.join(parts[-2:])
    else:
        base_domain = domain
        
    return base_domain

# Function to analyse an email for phishing risk using multiple checks.
def analyseEmails(email):
    """
    Analyse an email for phishing risk and return all check results + overall score.
    """
    # Seperate into the different parts 
    sender_email = email.get("sender_email", "")
    subject = email.get("subject", "")
    body = email.get("body", "")
    url = email.get("url", "")
   
    # keyword-based phishing risk scoring
    email_data = check_domain_in_csv(sender_email)
    keywordScore = float(keyword_score(subject, body))  # cast to float
    keywordLabel = "Spam" if keywordScore >= 50 else "Safe"

    # Highlight suspicious keywords in subject/body
    subject_highlighted = highlight_keywords(subject)
    body_highlighted = highlight_keywords(body)
    keywords = sorted(set(find_keywords()))

    # Load trusted sites/domains
    trustedSites = getSiteList()
    # Extract URLs from body/email text (always returns list, even if empty)
    extracted_urls = extract_urls(body) or []

    # Start with extracted URLs
    emailUrls = list(extracted_urls)

    # Also add the manually provided URL if present
    if url:
        emailUrls.append(url)
    
    sender = email.get("from", "")
    senderDomain = extract_email_domain(sender)
    if senderDomain:
        emailUrls.append(senderDomain)
    # Prepare lists to collect results
    urlCheck = []   # Boolean results from URLvalidator
    editCheck = []  # Edit distance results vs trusted domains

    # If URLs are present, check each one
    if emailUrls:
        for i in emailUrls:
            # Remove protocol and subdomain to get base domain
            base_domain = extract_base_domain(i)
            
            # Check if URL is trusted/safe
            urlCheck.append(URLvalidator(base_domain)) # returns True/False

            # Compare URL to trusted domains using Levenshtein edit distance
            # Smaller distance → higher chance of phishing lookalike
            editCheck.append(editDistance(trustedSites, base_domain))

    #To add, weigh the checks and return an output
    checks = [
        (keywordLabel == "Spam"),            # keyword detection label
        (keywordScore >= 70),                # high risk keyword score
        False in urlCheck,                   # any URL validator failed
        any(minEditDistance[0] <= 2 for minEditDistance in editCheck)    # edit distance <= 2
    ]
    # Check the counts 
    spamVotes = sum(checks)

    # Get the overall score and label
    overallLabel = "Spam" if spamVotes >= 3 or email_data["category"] != "legitimate" else "Safe"
    overallScore = round(spamVotes / 5, 2)  # 0.0 → 1.0
    
     # Return everything for frontend display
    return {
        "final_label": overallLabel,
        "overall_score": overallScore,
        "spam_votes": spamVotes,
        "email_data": email_data,
        "keyword_score": keywordScore,
        "keyword_label": keywordLabel,
        "keywords": keywords,
        "subject_highlighted": subject_highlighted,
        "body_highlighted": body_highlighted,
        "urls": emailUrls,
        "urlCheck": urlCheck,
        "editCheck": editCheck
    }
