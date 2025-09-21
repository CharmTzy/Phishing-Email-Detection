import re

SUSPICIOUS_KEYWORDS = {
    'urgent', 'verify', 'account', 'password', 'click', 'offer', 'free', 'win',
    'money', 'prize', 'limited', 'guaranteed', 'risk', 'important', 'action required'
}

def keyword_score(subject, body):
    score = 0
    subject_tokens = re.findall(r'\w+', str(subject).lower())
    body_tokens = re.findall(r'\w+', str(body).lower())
    subject_matches = [kw for kw in subject_tokens if kw in SUSPICIOUS_KEYWORDS]
    score += 3 * len(subject_matches)
    for i, word in enumerate(body_tokens):
        if word in SUSPICIOUS_KEYWORDS:
            score += 2 if i < 50 else 1
    return score