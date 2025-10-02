# Import libraries 
from trusted_sites import getSiteList
from edit_distance import editDistance
from url_detection import extract_urls, URLvalidator
from keyword_detection import keyword_score, find_keywords, highlight_keywords

# Function to analyse an email for phishing risk using multiple checks.
def analyseEmails(email):
    """
    Analyse an email for phishing risk and return all check results + overall score.
    """
    # Seperate into the different parts
    subject = email.get("subject", "")
    body = email.get("body", "")
    url = email.get("url", "")
   
    # keyword-based phishing risk scoring
    keywordScore = float(keyword_score(subject, body))  # cast to float
    keywordLabel = "Spam" if keywordScore >= 50 else "Safe"

    # Highlight suspicious keywords in subject/body
    subject_highlighted = highlight_keywords(subject)
    body_highlighted = highlight_keywords(body)
    keywords = sorted(set(find_keywords(subject) + find_keywords(body)))

    # Load trusted domains from trusted_sites.txt
    trustedSites = getSiteList()
    # Extract URLs from body/email text (always returns list, even if empty)
    extracted_urls = extract_urls(body) or []

    # Start with extracted URLs
    emailUrls = list(extracted_urls)

    # Also add the manually provided URL if present
    if url:
        emailUrls.append(url)

    # Prepare lists to collect results
    urlCheck = []   # Boolean results from URLvalidator
    editCheck = []  # Edit distance results vs trusted domains

    # If URLs are present, check each one
    if emailUrls:
        for i in emailUrls:
            # Check if URL is trusted/safe
            urlCheck.append(URLvalidator(i)) # returns True/False

            # Compare URL to trusted domains using Levenshtein edit distance
            # Smaller distance → higher chance of phishing lookalike
            editCheck.append(editDistance(trustedSites,i))

    #To add, weigh the checks and return an output
    checks = [
        (keywordLabel == "Spam"),            # keyword detection label
        (keywordScore >= 70),                # high risk keyword score
        False in urlCheck,                   # any URL validator failed
        any(minEditDistance[0] <= 2 for minEditDistance in editCheck)    # edit distance <= 2
    ]
    print(f"Individual Check Results: {checks}")
    # Check the counts 
    spamVotes = sum(checks)

    # Get the overall score and label
    overallLabel = "Spam" if spamVotes >= 3 else "Safe"
    overallScore = round(spamVotes / 5, 2)  # 0.0 → 1.0
    
     # Return everything for frontend display
    return {
        "final_label": overallLabel,                 # Overall verdict after 5 checks ("Spam" or "Safe")
        "overall_score": overallScore,               # Normalized risk score between 0.0–1.0 (spamVotes/5)
        "spam_votes": spamVotes,                     # Number of checks (out of 5) that flagged suspicious
        "keyword_score": keywordScore,               # Numeric phishing score from keyword detection
        "keyword_label": keywordLabel,               # Verdict from keyword detection alone ("Spam"/"Safe")
        "keywords": keywords,                        # List of suspicious keywords found in subject/body
        "subject_highlighted": subject_highlighted,  # Subject string with suspicious keywords highlighted (HTML)
        "body_highlighted": body_highlighted,        # Body string with suspicious keywords highlighted (HTML)
        "urls": emailUrls,                           # All extracted URLs/domains from body + user input
        "urlCheck": urlCheck,                        # URL safety check results (True = safe, False = suspicious)
        "editCheck": editCheck                       # Edit distance results per URL → [minDistance, closestTrusted]
    }