import pandas as pd
import string

# Load dataset
df = pd.read_csv(r"Datasets/cleaned_SA.csv")

class Colors:
    BLUE = '\033[94m'
    RESET = '\033[0m'

stop_words = {
    "the","is","in","at","of","a","an","and","to","for","on","with","by","from",
    "this","that","it","as","be","or","are","was","were","we"
}

# Global variables that will be set by the server functions
keywords = []
matched_keywords = []

def process_email(subject, body):
    """Process email and set global variables - EXACT same logic as original"""
    global keywords, matched_keywords
    
    text = f"{subject} {body}"
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # unique keywords (lowercase, no stopwords) - EXACT same logic
    keywords = list(dict.fromkeys(
        w.lower() for w in text.split() if w.lower() not in stop_words
    ))
    
    matched_keywords = []

def calc_score(sub_df):
    """EXACT same function as original"""
    if len(sub_df) == 0:
        return 0
    count = 0
    for kw in keywords:
        if df["subject"].str.contains(kw, case=False, na=False).any():
            subj_hits = sub_df["subject"].str.contains(kw, case=False, na=False)
            count += subj_hits.sum()
            matched_keywords.append(kw)
        elif df["body"].str.contains(kw, case=False, na=False).any():
            body_hits = sub_df["body"].str.contains(kw, case=False, na=False)
            count += body_hits.sum()
            matched_keywords.append(kw)
    return count / len(sub_df)

def output(subject, body):
    """EXACT same function as original"""
    for i in subject.split():
        if i.lower() in matched_keywords:
            subject = subject.replace(i, Colors.BLUE + i + Colors.RESET)
    
    for j in body.split():
        if j.lower() in matched_keywords:
            body = body.replace(j, Colors.BLUE + j + Colors.RESET)
    print("Subject: " + subject)
    print("Body: " + body)

def keyword_score(subject, body):
    """Main function for server - runs EXACT same logic"""
    process_email(subject, body)
    
    safe_df = df[df["label"] == 0]
    spam_df = df[df["label"] == 1]
    score_safe = calc_score(safe_df)
    score_spam = calc_score(spam_df)
    
    risk_score = (score_safe + score_spam) / 2
    return round(risk_score, 4) * 100

def find_keywords(text):
    """Return keywords found in the text"""
    return list(set(matched_keywords))

def highlight_keywords(text):
    """Highlight keywords for web display"""
    if not text or not matched_keywords:
        return text
    
    highlighted_text = text
    for keyword in set(matched_keywords):
        # Case-insensitive replacement with HTML highlighting
        import re
        pattern = r'\b' + re.escape(keyword) + r'\b'
        highlighted_text = re.sub(
            pattern, 
            f'<span style="background-color: #007bff; color: white; padding: 2px 4px; border-radius: 3px;">{keyword}</span>', 
            highlighted_text, 
            flags=re.IGNORECASE
        )
    
    return highlighted_text
