import re
from pathlib import Path

import pandas as pd


DATASET_PATH = Path(__file__).resolve().parent / "Datasets" / "cleaned_SA.csv"

if DATASET_PATH.exists():
    df = pd.read_csv(DATASET_PATH)
else:
    df = pd.DataFrame(columns=["label", "subject", "body"])


suspicious_keywords = []

TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z'-]{2,}")

common_words = {
    "about",
    "account",
    "agenda",
    "business",
    "check",
    "company",
    "contact",
    "customer",
    "day",
    "dear",
    "discuss",
    "email",
    "hello",
    "help",
    "information",
    "mail",
    "meeting",
    "message",
    "office",
    "please",
    "project",
    "regards",
    "schedule",
    "service",
    "support",
    "team",
    "thanks",
    "time",
    "tomorrow",
    "update",
    "updates",
    "weekly",
}

positive_words = {
    "approved",
    "authentic",
    "confirmed",
    "genuine",
    "honest",
    "legitimate",
    "official",
    "protected",
    "reliable",
    "safe",
    "secure",
    "success",
    "trusted",
    "valid",
    "verified",
}

weak_signal_words = {
    "bring",
    "clicking",
    "discussing",
    "experience",
    "going",
    "imagine",
    "moved",
    "needed",
    "review",
    "status",
    "verify",
    "want",
    "wanted",
    "would",
}

SUSPICIOUS_KEYWORD_WEIGHTS = {
    "accept": 3,
    "access": 6,
    "adult": 18,
    "bank": 8,
    "bonus": 7,
    "cash": 7,
    "chat": 10,
    "claim": 8,
    "click": 5,
    "confirm": 7,
    "credentials": 10,
    "dating": 8,
    "date": 2,
    "disclaimer": 2,
    "exclusive": 8,
    "free": 6,
    "fun": 1,
    "gift": 7,
    "immediately": 4,
    "invoice": 6,
    "limited": 6,
    "login": 10,
    "moments": 1,
    "offer": 6,
    "otp": 8,
    "password": 10,
    "payment": 7,
    "photos": 8,
    "prize": 8,
    "private": 8,
    "reset": 8,
    "security": 7,
    "special": 2,
    "suspended": 10,
    "tonight": 2,
    "urgent": 8,
    "verify": 9,
    "wallet": 8,
    "website": 2,
    "winner": 8,
}

SUSPICIOUS_PHRASE_WEIGHTS = {
    "access your account": 18,
    "adult chat": 28,
    "click here": 12,
    "confirm your account": 18,
    "exclusive photos": 24,
    "limited time": 12,
    "password reset": 24,
    "private chat": 24,
    "reset your password": 28,
    "special moments": 14,
    "suspended account": 18,
    "urgent action": 16,
    "verify your account": 22,
}

ADULT_SPAM_CLUSTER = {"adult", "chat", "private", "exclusive", "photos", "dating"}
PHISHING_CLUSTER = {
    "access",
    "bank",
    "claim",
    "click",
    "confirm",
    "credentials",
    "login",
    "otp",
    "password",
    "payment",
    "reset",
    "security",
    "suspended",
    "urgent",
    "verify",
    "wallet",
}


def _normalize_text(text):
    return re.sub(r"\s+", " ", str(text or "").lower()).strip()


def _tokenize(text):
    return [token.lower().strip("'") for token in TOKEN_PATTERN.findall(str(text or ""))]


def _count_occurrences(text, term):
    if not text:
        return 0
    return len(re.findall(rf"\b{re.escape(term)}\b", text, flags=re.IGNORECASE))


def _ordered_matches(subject, body, matched_keywords):
    ordered = []
    seen = set()

    for token in _tokenize(f"{subject} {body}"):
        if token in matched_keywords and token not in seen:
            ordered.append(token)
            seen.add(token)

    for token in sorted(matched_keywords - seen):
        ordered.append(token)

    return ordered


def extract_keywords(text):
    extracted = []
    seen = set()

    for token in _tokenize(text):
        if token in seen:
            continue
        if token in common_words or token in positive_words or token in weak_signal_words:
            continue
        if token.endswith("ly"):
            continue

        seen.add(token)
        extracted.append(token)

    return extracted


def keyword_score(subject, body):
    subject_text = _normalize_text(subject)
    body_text = _normalize_text(body)
    combined_text = " ".join(part for part in [subject_text, body_text] if part).strip()

    global suspicious_keywords
    suspicious_keywords = []

    if not combined_text:
        return 0.0

    score = 0.0
    matched_keywords = set()

    for keyword, weight in SUSPICIOUS_KEYWORD_WEIGHTS.items():
        subject_hits = _count_occurrences(subject_text, keyword)
        body_hits = _count_occurrences(body_text, keyword)

        if not subject_hits and not body_hits:
            continue

        matched_keywords.add(keyword)
        score += weight

        if subject_hits:
            score += weight * 0.35

        if body_hits > 1:
            score += min(weight * 0.35, (body_hits - 1) * weight * 0.15)

    for phrase, weight in SUSPICIOUS_PHRASE_WEIGHTS.items():
        phrase_hits = _count_occurrences(combined_text, phrase)
        if not phrase_hits:
            continue

        score += weight * min(2, phrase_hits)
        matched_keywords.update(
            token for token in phrase.split() if token in SUSPICIOUS_KEYWORD_WEIGHTS
        )

    score += min(18, len(matched_keywords) * 1.75)

    if len(matched_keywords & ADULT_SPAM_CLUSTER) >= 3:
        score += 15

    if len(matched_keywords & PHISHING_CLUSTER) >= 3:
        score += 12

    suspicious_keywords = _ordered_matches(subject_text, body_text, matched_keywords)

    return round(min(score, 100.0), 2)


def find_keywords():
    return list(suspicious_keywords)


def highlight_keywords(text):
    highlighted = str(text or "")

    for keyword in sorted(suspicious_keywords, key=len, reverse=True):
        pattern = rf"\b({re.escape(keyword)})\b"
        highlighted = re.sub(
            pattern,
            (
                '<span style="background-color: #28a745; font-weight: bold; '
                'color: white; padding: 2px 4px; border-radius: 3px;">\\1</span>'
            ),
            highlighted,
            flags=re.IGNORECASE,
        )

    return highlighted
