import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT_DIR = Path(__file__).resolve().parent
DATASET_PATH = ROOT_DIR / "Datasets" / "cleaned_SA.csv"
MODEL_DIR = ROOT_DIR / "models"
MODEL_PATH = MODEL_DIR / "phishing_email_model.joblib"
METRICS_PATH = MODEL_DIR / "phishing_email_metrics.json"
MODEL_THRESHOLD = 0.40
REQUIRED_COLUMNS = ["subject", "body", "from", "urls", "label"]
GENERIC_TOKENS = {"subject", "body", "sender", "urls"}


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


def prepare_training_features(dataset):
    prepared = dataset.copy()

    for column in ["subject", "body", "from", "urls"]:
        if column not in prepared.columns:
            prepared[column] = ""
        prepared[column] = prepared[column].fillna("").astype(str)

    prepared["sender_domain"] = prepared["from"].apply(extract_sender_domain)
    prepared["combined_text"] = prepared.apply(
        lambda row: build_combined_text(
            row["subject"],
            row["body"],
            row["sender_domain"],
            row["urls"],
        ),
        axis=1,
    )

    return prepared[["combined_text"]]


def prepare_inference_features(email):
    sender_email = clean_text(email.get("sender_email") or email.get("from", ""))
    sender_domain = extract_sender_domain(sender_email)
    provided_url = clean_text(email.get("url", ""))
    url_text = ", ".join(
        value for value in [clean_text(email.get("urls", "")), provided_url] if value
    )

    return pd.DataFrame(
        [
            {
                "combined_text": build_combined_text(
                    email.get("subject", ""),
                    email.get("body", ""),
                    sender_domain,
                    url_text,
                )
            }
        ]
    )


def build_pipeline():
    feature_builder = ColumnTransformer(
        transformers=[
            (
                "word",
                TfidfVectorizer(
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=18000,
                    sublinear_tf=True,
                ),
                "combined_text",
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=12000,
                    sublinear_tf=True,
                ),
                "combined_text",
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
                    C=4.0,
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
        "model_name": "word_char_tfidf_logistic_regression",
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

    if source != "word" or not raw_value:
        return None
    if raw_value in GENERIC_TOKENS:
        return None
    if len(raw_value) < 3 or not re.search(r"[A-Za-z]", raw_value):
        return None

    if raw_value.startswith("subject "):
        keyword = raw_value.removeprefix("subject ").strip()
        return f'Subject mentions "{keyword}"' if keyword else None
    if raw_value.startswith("body "):
        keyword = raw_value.removeprefix("body ").strip()
        return f'Body contains "{keyword}"' if keyword else None
    if raw_value.startswith("sender "):
        keyword = raw_value.removeprefix("sender ").strip()
        return f'Sender resembles "{keyword}"' if keyword else None
    if raw_value.startswith("urls "):
        keyword = raw_value.removeprefix("urls ").strip()
        return f'URL text contains "{keyword}"' if keyword else None

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
