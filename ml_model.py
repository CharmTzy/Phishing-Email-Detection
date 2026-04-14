import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT_DIR = Path(__file__).resolve().parent
DATASET_PATH = ROOT_DIR / "Datasets" / "cleaned_SA.csv"
MODEL_DIR = ROOT_DIR / "models"
MODEL_PATH = MODEL_DIR / "phishing_email_model.joblib"
METRICS_PATH = MODEL_DIR / "phishing_email_metrics.json"
MODEL_THRESHOLD = 0.42
REQUIRED_COLUMNS = ["subject", "body", "from", "urls", "label"]
GENERIC_TOKENS = {"subject", "body", "sender", "urls", "combined"}
FREE_MAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "msn.com",
    "proton.me",
    "protonmail.com",
}
URGENCY_TERMS = {
    "urgent",
    "immediately",
    "asap",
    "today",
    "now",
    "alert",
    "limited",
    "deadline",
    "expiring",
}
ACCOUNT_ACTION_TERMS = {
    "verify",
    "login",
    "log in",
    "password",
    "reset",
    "update",
    "confirm",
    "security",
    "account",
    "suspended",
}
OFFER_TERMS = {
    "free",
    "gift",
    "bonus",
    "prize",
    "winner",
    "deal",
    "discount",
    "promotion",
}
NUMERIC_FEATURE_COLUMNS = [
    "subject_length",
    "body_length",
    "url_count",
    "sender_domain_depth",
    "uppercase_token_count",
    "exclamation_count",
    "digit_ratio",
    "currency_symbol_count",
    "urgency_term_count",
    "account_term_count",
    "offer_term_count",
    "sender_is_free_mail",
    "ip_url_count",
    "hyphenated_url_count",
    "link_token_count",
]
NUMERIC_FEATURE_LABELS = {
    "subject_length": "Subject length added some phishing signal",
    "body_length": "Body length added some phishing signal",
    "url_count": "Email contains several links",
    "sender_domain_depth": "Sender domain depth looks unusual",
    "uppercase_token_count": "Email uses many uppercase words",
    "exclamation_count": "Email uses many exclamation marks",
    "digit_ratio": "Email has an unusually high digit ratio",
    "currency_symbol_count": "Email mentions money or currency symbols",
    "urgency_term_count": "Email uses urgent language",
    "account_term_count": "Email pushes account or login actions",
    "offer_term_count": "Email uses offer or giveaway language",
    "sender_is_free_mail": "Sender uses a free-mail domain",
    "ip_url_count": "Email includes an IP-based link",
    "hyphenated_url_count": "Email includes highly hyphenated links",
    "link_token_count": "Email repeats link-like text patterns",
}
IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def clean_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def extract_sender_domain(value):
    value = clean_text(value)
    match = re.search(r"@([^\s>]+)", value)
    return match.group(1).lower() if match else ""


def build_combined_text(subject, body, sender_domain, urls):
    parts = [
        f"subject {clean_text(subject)}",
        f"body {clean_text(body)}",
        f"sender {clean_text(sender_domain)}",
        f"urls {clean_text(urls)}",
    ]
    return " ".join(part for part in parts if part).strip()


def split_url_candidates(urls):
    raw_urls = clean_text(urls)
    if not raw_urls:
        return []

    candidates = []
    for part in re.split(r"[\s,]+", raw_urls):
        candidate = part.strip(" <>()[]{}\"'")
        if not candidate:
            continue
        candidates.append(candidate)
    return candidates


def extract_hostname(candidate):
    if not candidate:
        return ""

    prepared = candidate if "://" in candidate else f"https://{candidate}"
    parsed = urlparse(prepared)
    return (parsed.hostname or "").lower()


def count_term_hits(text, terms):
    lowered = clean_text(text).lower()
    return sum(len(re.findall(rf"\b{re.escape(term)}\b", lowered)) for term in terms)


def count_uppercase_tokens(text):
    return sum(1 for token in re.findall(r"\b[A-Z]{3,}\b", clean_text(text)) if token.isupper())


def compute_numeric_features(subject, body, sender_domain, urls):
    subject_text = clean_text(subject)
    body_text = clean_text(body)
    full_text = f"{subject_text} {body_text}".strip()
    full_text_no_space = re.sub(r"\s+", "", full_text)
    url_candidates = split_url_candidates(urls)
    hostnames = [extract_hostname(url) for url in url_candidates if extract_hostname(url)]

    digit_count = sum(character.isdigit() for character in full_text_no_space)
    currency_count = len(re.findall(r"[$€£¥]|sgd|usd|eur|gbp", full_text.lower()))
    link_token_count = len(re.findall(r"(?:https?://|www\.|bit\.ly|tinyurl|click)", full_text.lower()))

    return {
        "subject_length": float(len(subject_text)),
        "body_length": float(len(body_text)),
        "url_count": float(len(url_candidates)),
        "sender_domain_depth": float(max(sender_domain.count("."), 0)),
        "uppercase_token_count": float(count_uppercase_tokens(full_text)),
        "exclamation_count": float(full_text.count("!")),
        "digit_ratio": round(digit_count / max(len(full_text_no_space), 1), 4),
        "currency_symbol_count": float(currency_count),
        "urgency_term_count": float(count_term_hits(full_text, URGENCY_TERMS)),
        "account_term_count": float(count_term_hits(full_text, ACCOUNT_ACTION_TERMS)),
        "offer_term_count": float(count_term_hits(full_text, OFFER_TERMS)),
        "sender_is_free_mail": float(sender_domain in FREE_MAIL_DOMAINS),
        "ip_url_count": float(sum(bool(IPV4_PATTERN.fullmatch(hostname)) for hostname in hostnames)),
        "hyphenated_url_count": float(sum(hostname.count("-") >= 2 for hostname in hostnames)),
        "link_token_count": float(link_token_count),
    }


def prepare_training_features(dataset):
    prepared = dataset.copy()

    for column in ["subject", "body", "from", "urls"]:
        if column not in prepared.columns:
            prepared[column] = ""
        prepared[column] = prepared[column].fillna("").astype(str)

    prepared["sender_domain"] = prepared["from"].apply(extract_sender_domain)
    prepared["subject_text"] = prepared["subject"].astype(str)
    prepared["body_text"] = prepared["body"].astype(str)
    prepared["url_text"] = prepared["urls"].astype(str)
    prepared["combined_text"] = prepared.apply(
        lambda row: build_combined_text(
            row["subject"],
            row["body"],
            row["sender_domain"],
            row["urls"],
        ),
        axis=1,
    )
    numeric_features = prepared.apply(
        lambda row: compute_numeric_features(
            row["subject"],
            row["body"],
            row["sender_domain"],
            row["urls"],
        ),
        axis=1,
        result_type="expand",
    )

    return pd.concat(
        [
            prepared[["subject_text", "body_text", "sender_domain", "url_text", "combined_text"]],
            numeric_features[NUMERIC_FEATURE_COLUMNS],
        ],
        axis=1,
    )


def prepare_inference_features(email):
    sender_email = clean_text(email.get("sender_email") or email.get("from", ""))
    sender_domain = extract_sender_domain(sender_email)
    provided_url = clean_text(email.get("url", ""))
    url_text = ", ".join(
        value for value in [clean_text(email.get("urls", "")), provided_url] if value
    )
    subject = email.get("subject", "")
    body = email.get("body", "")
    numeric_features = compute_numeric_features(subject, body, sender_domain, url_text)

    return pd.DataFrame(
        [
            {
                "subject_text": clean_text(subject),
                "body_text": clean_text(body),
                "sender_domain": sender_domain,
                "url_text": url_text,
                "combined_text": build_combined_text(
                    subject,
                    body,
                    sender_domain,
                    url_text,
                ),
                **numeric_features,
            }
        ]
    )


def build_pipeline():
    feature_builder = ColumnTransformer(
        transformers=[
            (
                "subject_word",
                TfidfVectorizer(
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=5000,
                    sublinear_tf=True,
                ),
                "subject_text",
            ),
            (
                "body_word",
                TfidfVectorizer(
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=11000,
                    sublinear_tf=True,
                ),
                "body_text",
            ),
            (
                "combined_char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=9000,
                    sublinear_tf=True,
                ),
                "combined_text",
            ),
            (
                "numeric",
                Pipeline([("scale", StandardScaler())]),
                NUMERIC_FEATURE_COLUMNS,
            ),
        ]
    )

    return Pipeline(
        [
            ("preprocessor", feature_builder),
            (
                "classifier",
                LogisticRegression(
                    max_iter=3000,
                    class_weight="balanced",
                    random_state=42,
                    C=6.0,
                ),
            ),
        ]
    )


def classify_probabilities(probabilities, threshold):
    return (probabilities >= threshold).astype(int)


def summarise_metrics(y_true, probabilities, threshold):
    predictions = classify_probabilities(probabilities, threshold)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        predictions,
        average="binary",
        zero_division=0,
    )

    false_positives = int(((predictions == 1) & (np.asarray(y_true) == 0)).sum())
    false_negatives = int(((predictions == 0) & (np.asarray(y_true) == 1)).sum())

    return {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 4),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def train_model():
    dataset = pd.read_csv(DATASET_PATH)
    missing_columns = [column for column in REQUIRED_COLUMNS if column not in dataset.columns]

    if missing_columns:
        raise ValueError(
            "Training dataset is missing required columns: "
            + ", ".join(sorted(missing_columns))
        )

    features = prepare_training_features(dataset)
    labels = dataset["label"].astype(int)

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    pipeline = build_pipeline()
    pipeline.fit(x_train, y_train)

    probabilities = pipeline.predict_proba(x_test)[:, 1]
    metrics = summarise_metrics(y_test, probabilities, MODEL_THRESHOLD)

    return {
        "pipeline": pipeline,
        "threshold": MODEL_THRESHOLD,
        "metrics": metrics,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_rows": int(len(dataset)),
        "feature_count": int(
            len(pipeline.named_steps["preprocessor"].get_feature_names_out())
        ),
        "model_name": "hybrid_text_numeric_logistic_regression",
    }


def save_model_artifact(artifact):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, MODEL_PATH, compress=3)

    metrics_payload = {
        "model_name": artifact["model_name"],
        "threshold": artifact["threshold"],
        "trained_at": artifact["trained_at"],
        "training_rows": artifact["training_rows"],
        "feature_count": artifact["feature_count"],
        **artifact["metrics"],
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics_payload, file, indent=2)


def train_and_save_model(force=False):
    if MODEL_PATH.exists() and not force:
        return _load_model_artifact_uncached()

    artifact = train_model()
    save_model_artifact(artifact)
    load_model_artifact.cache_clear()
    return artifact


def _load_model_artifact_uncached():
    return joblib.load(MODEL_PATH)


@lru_cache(maxsize=1)
def load_model_artifact():
    if not MODEL_PATH.exists():
        return train_and_save_model(force=True)
    return _load_model_artifact_uncached()


def format_indicator(feature_name):
    source, _, raw_value = feature_name.partition("__")
    raw_value = re.sub(r"\s+", " ", raw_value.replace("_", " ")).strip()

    if not raw_value:
        return None
    if source == "numeric":
        return NUMERIC_FEATURE_LABELS.get(raw_value)

    if source not in {"subject_word", "body_word", "combined_char"}:
        return None

    if source == "combined_char":
        return None

    if raw_value in GENERIC_TOKENS:
        return None
    if len(raw_value) < 3 or not re.search(r"[A-Za-z]", raw_value):
        return None

    if source == "subject_word":
        return f'Subject mentions "{raw_value}"'
    if source == "body_word":
        return f'Body contains "{raw_value}"'

    return f'Model signal: "{raw_value}"'


def extract_top_indicators(pipeline, features_frame, limit=5):
    transformed = pipeline.named_steps["preprocessor"].transform(features_frame)
    coefficients = pipeline.named_steps["classifier"].coef_[0]
    contributions = transformed.multiply(coefficients).toarray().ravel()
    feature_names = pipeline.named_steps["preprocessor"].get_feature_names_out()

    indicators = []
    seen = set()

    for index in contributions.argsort()[::-1]:
        contribution = float(contributions[index])
        if contribution <= 0:
            break

        reason = format_indicator(feature_names[index])
        if not reason or reason in seen:
            continue

        indicators.append(
            {
                "reason": reason,
                "impact": round(contribution, 4),
            }
        )
        seen.add(reason)

        if len(indicators) >= limit:
            break

    return indicators


def predict_email(email):
    artifact = load_model_artifact()
    pipeline = artifact["pipeline"]
    features = prepare_inference_features(email)

    phishing_probability = float(pipeline.predict_proba(features)[0][1])
    confidence = max(phishing_probability, 1 - phishing_probability)

    return {
        "model_prediction": "Spam"
        if phishing_probability >= artifact["threshold"]
        else "Safe",
        "model_probability": round(phishing_probability, 4),
        "model_score": round(phishing_probability * 100, 1),
        "model_confidence": round(float(confidence), 4),
        "model_threshold": artifact["threshold"],
        "model_indicators": extract_top_indicators(pipeline, features),
        "model_metrics": artifact["metrics"],
        "model_trained_at": artifact["trained_at"],
        "model_name": artifact["model_name"],
    }
