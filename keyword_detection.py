import re

SUSPICIOUS_KEYWORDS = {
    'urgent', 'verify', 'account', 'password', 'click', 'offer', 'free', 'win',
    'money', 'prize', 'limited', 'guaranteed', 'risk', 'important', 'action required'
} 

# Precompile regex for all keywords (word boundaries, case-insensitive)
KEYWORD_REGEX = re.compile(
    r'\b(' + '|'.join(re.escape(kw) for kw in SUSPICIOUS_KEYWORDS) + r')\b',
    re.IGNORECASE
)

def keyword_score(subject, body):
    score = 0
    # Find all keyword matches in subject
    subject_matches = KEYWORD_REGEX.findall(str(subject))
    score += 3 * len(subject_matches)

    # Find all keyword matches in body
    body_matches = KEYWORD_REGEX.findall(str(body))
    # First 50 matches get weight 2, rest get weight 1
    score += sum(2 if i < 50 else 1 for i in range(len(body_matches)))
    return score