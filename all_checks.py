import re

from domain_detection import check_domain_in_csv
from edit_distance import editDistance
from keyword_detection import find_keywords, highlight_keywords, keyword_score
from ml_model import predict_email
from trusted_sites import extract_email_domain, getSiteList
from url_detection import analyze_url, extract_urls

RISKY_DOMAIN_CATEGORIES = {"spam", "suspicious"}
WATCH_DOMAIN_CATEGORIES = {"uncertain", "not found", "unknown"}


def extract_base_domain(url):
    """
    Extract the base domain from a URL by removing protocol and subdomain.
    Example: https://mail.example.com/path -> example.com
    """
    domain = re.sub(r"^.*?://", "", url)
    domain = domain.split("/")[0].split("?")[0].split("#")[0]

    parts = domain.split(".")
    if len(parts) > 2:
        if parts[-2] in ["co", "com", "org", "net", "gov", "edu"] and parts[-1] in [
            "uk",
            "au",
            "nz",
            "jp",
            "in",
        ]:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def dedupe_preserve_order(items):
    seen = set()
    deduped = []

    for item in items:
        if not item or item in seen:
            continue
        deduped.append(item)
        seen.add(item)

    return deduped


def clean_keywords(keywords):
    cleaned = []

    for keyword in keywords:
        normalized = str(keyword).strip().lower()
        if len(normalized) < 3 or len(normalized) > 30:
            continue
        if "http" in normalized or "www" in normalized:
            continue
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z-]*", normalized):
            continue
        cleaned.append(normalized)

    return sorted(set(cleaned))


def build_risk_level(score):
    if score >= 80:
        return "High"
    if score >= 55:
        return "Medium"
    return "Low"


def build_verdict_message(final_label, overall_score, ml_result):
    if final_label == "Spam":
        if overall_score >= 80:
            return "This email looks strongly suspicious and matches patterns seen in phishing emails."
        return "This email shows enough phishing signals that it should be treated with caution."

    if ml_result["model_probability"] < 0.2:
        return "This email looks safe based on the trained model and the supporting checks."
    return "This email leans safe overall, but you should still review any unexpected links carefully."


def build_reasons(
    final_label,
    ml_result,
    keyword_score_value,
    keywords,
    suspicious_urls,
    lookalikes,
    email_data,
):
    reasons = []

    phishing_probability = ml_result["model_probability"]
    if phishing_probability >= 0.7:
        reasons.append(
            f"The trained model found a strong phishing match ({ml_result['model_score']}% phishing likelihood)."
        )
    elif phishing_probability >= ml_result.get("model_threshold", 0.4):
        reasons.append(
            f"The trained model leaned toward phishing ({ml_result['model_score']}% phishing likelihood)."
        )

    if keyword_score_value >= 50 and keywords:
        reasons.append(f"Suspicious wording detected: {', '.join(keywords[:5])}.")

    if suspicious_urls:
        reasons.append(f"High-risk URL or domain found: {', '.join(suspicious_urls[:3])}.")

    if lookalikes:
        source, distance, closest = lookalikes[0]
        reasons.append(
            f'Lookalike domain detected: "{source}" is close to trusted site "{closest}" (distance {distance}).'
        )

    domain_category = str(email_data.get("category", "")).lower()
    domain_name = email_data.get("domain", "Unknown")
    if domain_category in RISKY_DOMAIN_CATEGORIES:
        reasons.append(f"Sender domain {domain_name} is marked as {email_data['category']}.")
    elif domain_category in WATCH_DOMAIN_CATEGORIES and domain_name != "Not Found":
        reasons.append(f"Sender domain {domain_name} is not strongly trusted in the domain dataset.")

    if not reasons and final_label == "Safe":
        reasons.append("No strong phishing wording, link issues, or sender-domain risks were found.")

    return reasons[:5]


def build_check_breakdown(
    ml_result,
    keyword_score_value,
    keywords,
    suspicious_urls,
    unlisted_urls,
    lookalikes,
    email_data,
):
    domain_category = str(email_data.get("category", "")).lower()

    if domain_category in RISKY_DOMAIN_CATEGORIES:
        domain_status = "Suspicious"
        domain_detail = f"Sender domain is marked as {email_data['category']}."
    elif domain_category in WATCH_DOMAIN_CATEGORIES:
        domain_status = "Unknown"
        domain_detail = "Sender domain was not strongly verified in the domain dataset."
    else:
        domain_status = "Trusted"
        domain_detail = "Sender domain matched a known legitimate domain."

    return [
        {
            "name": "Trained Model",
            "status": "Suspicious" if ml_result["model_prediction"] == "Spam" else "Clear",
            "detail": f"{ml_result['model_score']}% phishing probability.",
        },
        {
            "name": "Keyword Scan",
            "status": "Suspicious" if keyword_score_value >= 50 else "Clear",
            "detail": (
                f"Score {keyword_score_value} with keywords: {', '.join(keywords[:4])}."
                if keywords
                else f"Score {keyword_score_value} with no strong keyword hits."
            ),
        },
        {
            "name": "URL Safety",
            "status": "Suspicious" if suspicious_urls else ("Neutral" if unlisted_urls else "Clear"),
            "detail": (
                f"High-risk links found: {', '.join(suspicious_urls[:3])}."
                if suspicious_urls
                else (
                    f"Links were valid but not in the trusted list yet: {', '.join(unlisted_urls[:3])}."
                    if unlisted_urls
                    else "No high-risk links were found."
                )
            ),
        },
        {
            "name": "Lookalike Domains",
            "status": "Suspicious" if lookalikes else "Clear",
            "detail": (
                f'{lookalikes[0][0]} is similar to {lookalikes[0][2]}.'
                if lookalikes
                else "No close impersonation domains were detected."
            ),
        },
        {
            "name": "Sender Domain",
            "status": domain_status,
            "detail": domain_detail,
        },
    ]


def analyseEmails(email):
    """
    Analyse an email for phishing risk and return the hybrid model + rules result.
    """
    sender_email = email.get("sender_email") or email.get("from", "")
    subject = email.get("subject", "")
    body = email.get("body", "")
    url = email.get("url", "")

    ml_result = predict_email(
        {
            "sender_email": sender_email,
            "subject": subject,
            "body": body,
            "url": url,
        }
    )

    email_data = check_domain_in_csv(sender_email)
    keyword_score_value = float(keyword_score(subject, body))
    keyword_label = "Spam" if keyword_score_value >= 50 else "Safe"

    subject_highlighted = highlight_keywords(subject)
    body_highlighted = highlight_keywords(body)
    keywords = clean_keywords(find_keywords())

    trusted_sites = getSiteList()
    extracted_urls = extract_urls(body) or []

    email_urls = dedupe_preserve_order(
        list(extracted_urls) + ([url] if url else [])
    )

    sender_domain = extract_email_domain(sender_email)
    if sender_domain:
        email_urls = dedupe_preserve_order(email_urls + [sender_domain])

    url_check = []
    url_status = []
    edit_check = []
    suspicious_urls = []
    unlisted_urls = []
    lookalikes = []

    for url_candidate in email_urls:
        base_domain = extract_base_domain(url_candidate)
        analysis = analyze_url(base_domain)
        is_safe = analysis["status"] == "trusted"
        url_check.append(is_safe)
        url_status.append(analysis["status"])

        edit_result = editDistance(trusted_sites, base_domain)
        edit_check.append(edit_result)

        if analysis["status"] == "suspicious":
            suspicious_urls.append(base_domain)
        elif analysis["status"] == "unlisted":
            unlisted_urls.append(base_domain)

        if edit_result[0] <= 2 and edit_result[0] != 0:
            lookalikes.append((base_domain, edit_result[0], edit_result[1]))

    suspicious_urls = dedupe_preserve_order(suspicious_urls)
    unlisted_urls = dedupe_preserve_order(unlisted_urls)

    domain_category = str(email_data.get("category", "")).lower()
    risky_domain_flag = domain_category in RISKY_DOMAIN_CATEGORIES

    checks = [
        ml_result["model_prediction"] == "Spam",
        keyword_score_value >= 50,
        bool(suspicious_urls),
        any(distance <= 2 and distance != 0 for distance, _ in edit_check),
        risky_domain_flag,
    ]
    spam_votes = sum(checks)
    rule_score = spam_votes / len(checks)

    critical_url_flag = bool(suspicious_urls or lookalikes)
    phishing_probability = ml_result["model_probability"]
    overall_score = round((phishing_probability * 0.78 + rule_score * 0.22) * 100, 1)

    final_label = "Safe"
    if (
        phishing_probability >= 0.50
        or critical_url_flag
        or (phishing_probability >= 0.40 and spam_votes >= 2)
        or (risky_domain_flag and suspicious_urls)
    ):
        final_label = "Spam"

    if final_label == "Spam":
        overall_score = max(overall_score, 60.0)

    risk_level = build_risk_level(overall_score)
    reasons = build_reasons(
        final_label,
        ml_result,
        keyword_score_value,
        keywords,
        suspicious_urls,
        lookalikes,
        email_data,
    )

    return {
        "final_label": final_label,
        "overall_score": overall_score,
        "risk_level": risk_level,
        "spam_votes": spam_votes,
        "email_data": email_data,
        "keyword_score": keyword_score_value,
        "keyword_label": keyword_label,
        "keywords": keywords,
        "subject_highlighted": subject_highlighted,
        "body_highlighted": body_highlighted,
        "urls": email_urls,
        "urlCheck": url_check,
        "urlStatus": url_status,
        "editCheck": edit_check,
        "model_prediction": ml_result["model_prediction"],
        "model_probability": ml_result["model_probability"],
        "model_score": ml_result["model_score"],
        "model_confidence": ml_result["model_confidence"],
        "model_indicators": ml_result["model_indicators"],
        "model_metrics": ml_result["model_metrics"],
        "model_trained_at": ml_result["model_trained_at"],
        "model_name": ml_result["model_name"],
        "checks_breakdown": build_check_breakdown(
            ml_result,
            keyword_score_value,
            keywords,
            suspicious_urls,
            unlisted_urls,
            lookalikes,
            email_data,
        ),
        "reasons": reasons,
        "verdict_message": build_verdict_message(final_label, overall_score, ml_result),
    }
