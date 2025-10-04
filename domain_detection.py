import csv
import os

def check_domain_in_csv(email: str) -> dict:
    """
    Accepts an email string, extracts the domain, and checks if it exists
    in the first column of domain_analysis_full.csv.
    
    Returns a dictionary with column titles as keys and corresponding data as values.
    If the domain is not found, returns 'Not Found' for each value.
    """
    # Extract domain from email
    try:
        domain = email.split('@')[1].strip().lower()
    except IndexError:
        # Invalid email format
        return {
            "domain": "Not Found",
            "legitimacy_score": "Not Found",
            "total_occurrences": "Not Found",
            "in_spam": "Not Found",
            "in_ham": "Not Found",
            "sources": "Not Found",
            "category": "Not Found"
        }
    
    csv_path = "domain_analysis_full.csv"
    
    # Check if CSV file exists
    if not os.path.isfile(csv_path):
        return {
            "domain": "Not Found",
            "legitimacy_score": "Not Found",
            "total_occurrences": "Not Found",
            "in_spam": "Not Found",
            "in_ham": "Not Found",
            "sources": "Not Found",
            "category": "Not Found"
        }
    
    # Read CSV and search for domain
    with open(csv_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        
        # Check if required columns exist
        required_columns = {"domain", "legitimacy_score", "total_occurrences", "in_spam", "in_ham", "sources", "category"}
        if not required_columns.issubset(reader.fieldnames or []):
            return {
                "domain": "Not Found",
                "legitimacy_score": "Not Found",
                "total_occurrences": "Not Found",
                "in_spam": "Not Found",
                "in_ham": "Not Found",
                "sources": "Not Found",
                "category": "Not Found"
            }
        
        for row in reader:
            if row["domain"].strip().lower() == domain:
                return {
                    "domain": row["domain"],
                    "legitimacy_score": row["legitimacy_score"],
                    "total_occurrences": row["total_occurrences"],
                    "in_spam": row["in_spam"],
                    "in_ham": row["in_ham"],
                    "sources": row["sources"],
                    "category": row["category"]
                }
    
    # Domain not found
    return {
        "domain": "Not Found",
        "legitimacy_score": "Not Found",
        "total_occurrences": "Not Found",
        "in_spam": "Not Found",
        "in_ham": "Not Found",
        "sources": "Not Found",
        "category": "Not Found"
    }
