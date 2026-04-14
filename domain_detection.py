import csv
import os
from email.utils import parseaddr


def not_found_result():
    return {
        "domain": "Not Found",
        "legitimacy_score": "Not Found",
        "total_occurrences": "Not Found",
        "in_spam": "Not Found",
        "in_ham": "Not Found",
        "sources": "Not Found",
        "category": "Not Found"
    }


def unknown_domain_result(domain: str):
    return {
        "domain": domain,
        "legitimacy_score": 0,
        "total_occurrences": 0,
        "in_spam": 0,
        "in_ham": 0,
        "sources": "none",
        "category": "unknown"
    }


def extract_domain(email: str) -> str:
    parsed_email = parseaddr(email or "")[1] or (email or "")
    if "@" not in parsed_email:
        return ""
    return parsed_email.split("@", 1)[1].strip().lower().strip(">")

def check_domain_in_csv(email: str) -> dict:
    """
    Accepts an email string, extracts the domain, and checks if it exists
    in the first column of domain_analysis_full.csv.
    
    Returns a dictionary with column titles as keys and corresponding data as values.
    If the domain is not found, returns 'Not Found' for each value.
    
    Applies additional classification criteria:
    - Domains with low occurrence (≤ 5) are treated with caution
    - Domains with legitimacy score < 90 and low occurrence are classified as suspicious
    """
    # Extract domain from email
    domain = extract_domain(email)
    if not domain:
        return not_found_result()
    
    csv_path = "domain_analysis_full.csv"
    
    # Check if CSV file exists
    if not os.path.isfile(csv_path):
        return unknown_domain_result(domain)
    
    # Read CSV and search for domain
    with open(csv_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        
        # Check if required columns exist
        required_columns = {"domain", "legitimacy_score", "total_occurrences", "in_spam", "in_ham", "sources", "category"}
        if not required_columns.issubset(reader.fieldnames or []):
            return unknown_domain_result(domain)
        
        for row in reader:
            if row["domain"].strip().lower() == domain:
                # Apply enhanced classification logic
                result = {
                    "domain": row["domain"],
                    "legitimacy_score": row["legitimacy_score"],
                    "total_occurrences": row["total_occurrences"],
                    "in_spam": row["in_spam"],
                    "in_ham": row["in_ham"],
                    "sources": row["sources"],
                    "category": row["category"]
                }
                
                # Apply stricter criteria for low-occurrence domains
                try:
                    legitimacy_score = int(row["legitimacy_score"])
                    total_occurrences = int(row["total_occurrences"])
                    
                    # Reclassify low-occurrence domains with moderate legitimacy scores
                    if total_occurrences <= 5 and legitimacy_score < 90:
                        result["category"] = "suspicious"
                except (ValueError, TypeError):
                    # If conversion fails, keep original classification
                    pass
                
                return result
    
    # Domain not found in the lookup file, but we still return the extracted domain
    # so the UI can show something useful to the user.
    return unknown_domain_result(domain)
