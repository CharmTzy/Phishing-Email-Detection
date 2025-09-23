import re

# List of common phishing keywords
PHISHING_KEYWORDS = [
    # Urgency and Threats 
    "urgent", "immediate action required", "act now", 
    "important notification", "attention required", 
    "final notice", "last chance", "limited time offer", 
    "time-sensitive", "your action is needed", "critical alert",

    # Fear and Panic 
    "account locked", "unauthorized login attempt", 
    "suspicious activity detected", "payment failed", 
    "security compromised", "your account will be closed", 
    "legal action pending", "fraudulent activity", 
    "data breach", "compliance violation", "penalty warning",

    # Requests for Verification or Action 
    "verify your account", "confirm your password", 
    "update your information", "verify your identity", 
    "validate your login", "reset your credentials", 
    "unlock your account", "reactivate your account", 
    "action required", "secure your account", 
    "login to resolve", "check your details", 
    "account verification required", "identity confirmation needed",

    # Fake Opportunities
    "you have won", "prize", "lottery", "gift card", 
    "reward points", "cash back", "free trial", 
    "special offer", "bonus", "claim your prize", 
    "exclusive offer", "VIP access", "redeem now", 
    "get your refund", "win big", "receive funds",

    # Email and Attachment Lures
    "click here", "open attachment", "download invoice", 
    "open document", "secure link", "view statement", 
    "see details", "open this file", "attachment included", 
    "access your account", "follow the link", 
    "view message", "verify transaction", 
    "document awaiting signature",

    # Financial Scams
    "bank details", "credit card information", 
    "account number", "loan approval", 
    "tax refund", "overpayment", "wire transfer", 
    "secure transaction", "unpaid invoice", 
    "billing error", "payment required", "tax reminder", 
    "financial settlement", "claim payment", 
    "unexpected charge",

    # Posing as Authorities or Companies
    "support team", "official request", "banking alert", 
    "customer service", "IT department", "account security", 
    "trusted source", "system administrator", 
    "helpdesk", "technical support", 
    "service provider", "payment gateway", 
    "verification team", "fraud prevention unit", 
    "compliance team", "risk management", 
    "official communication", "important update",

    # Social Engineering Triggers
    "dear customer", "valued user", "trusted account holder", 
    "dear [username]", "greetings", "hello user", 
    "your trusted partner", "dear friend", "important client", 
    "personalized offer", "exclusive invitation", 
    "relationship update", "membership renewal", 
    "VIP customer alert",

    # Technical Jargon and Fake Security Terms
    "SSL certificate expired", "firewall alert", 
    "IP address mismatch", "malware detected", 
    "system scan required", "login attempt failed", 
    "DNS issue", "email server blocked", 
    "invalid credentials", "security token expired", 
    "two-factor authentication disabled", 
    "unauthorized device detected", "server downtime alert", 
    "software update required",

    # Miscellaneous
    "update your email", "confirm email address", 
    "password expiry", "access suspended", 
    "new feature activation", "trial ending soon", 
    "pending message", "storage limit exceeded", 
    "account migration", "new terms of service", 
    "renew your subscription", "membership expired", 
    "close your account", "pending approval",
]

# Precompile regex for all keywords (word boundaries, case-insensitive)
KEYWORD_REGEX = re.compile(
    r'\b(' + '|'.join(re.escape(kw) for kw in PHISHING_KEYWORDS) + r')\b',
    re.IGNORECASE
)

def keyword_score(subject, body):
    score = 0

    # Subject: high risk, each keyword = 3 points
    subject_matches = KEYWORD_REGEX.findall(str(subject))
    score += 3 * len(subject_matches)

    # Body: higher risk for keywords early in the message
    body_text = str(body)
    early_body = body_text[:200]  # First 200 characters
    early_matches = KEYWORD_REGEX.findall(early_body)
    score += 2 * len(early_matches)

    # Remaining body: lower risk
    remaining_body = body_text[200:]
    remaining_matches = KEYWORD_REGEX.findall(remaining_body)
    score += 1 * len(remaining_matches)

    return score

def find_keywords(text):
    # Return a list of unique phishing keywords found in the text
    return sorted(set(KEYWORD_REGEX.findall(str(text))))

def highlight_keywords(text):
    # Return text with phishing keywords wrapped in <mark> tags.
    def replacer(match):
        return f"<mark>{match.group(0)}</mark>"
    return KEYWORD_REGEX.sub(replacer, str(text))