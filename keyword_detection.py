import pandas as pd
import string
import re

# Load dataset
df = pd.read_csv(r"Datasets/cleaned_SA.csv")

 # Terminal color codes for highlighting text in console output.
class Colors:   
    GREEN = '\033[92m'
    RESET = '\033[0m'

# Common stop words to exclude from keyword extraction
stop_words = {
    "the","is","in","at","of","a","an","and","to","for","on","with","by","from",
    "this","that","it","as","be","or","are","was","were","we","you","he","she",
    "they","them","his","her","its","my","your","our"
}

# Global variables for storing keywords detected in the email
keywords = []
matched_keywords = []

def process_email(subject, body):
    """
    Extract unique keywords from email subject and body.
    Updates global 'keywords' and clears 'matched_keywords'.
    """
    global keywords, matched_keywords
    
    # Combine subject and body text
    text = f"{subject} {body}"
    # Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # Extract unique lowercase keywords, ignoring stop words
    keywords = list(dict.fromkeys(
        w.lower() for w in text.split() if w.lower() not in stop_words
    ))
    
    # Reset matched keywords for this email
    matched_keywords = []

def calc_score(sub_df):
    """
    Calculate the proportion of rows in sub_df that match any keyword.
    Updates global 'matched_keywords'.
    """
    if len(sub_df) == 0:
        return 0

    count = 0
    for kw in keywords:
        # Check for keyword matches in subject
        if df["subject"].str.contains(kw, case=False, na=False).any():
            subj_hits = sub_df["subject"].str.contains(kw, case=False, na=False)
            count += subj_hits.sum()
            matched_keywords.append(kw)
        # Check for keyword matches in body
        elif df["body"].str.contains(kw, case=False, na=False).any():
            body_hits = sub_df["body"].str.contains(kw, case=False, na=False)
            count += body_hits.sum()
            matched_keywords.append(kw)
    
    # Return proportion of matching rows
    return count / len(sub_df)

def output(subject, body):
    # Print the subject and body to console with matched keywords highlighted in green.
    for i in subject.split():
        if i.lower() in matched_keywords:
            subject = subject.replace(i, Colors.GREEN + i + Colors.RESET)
    
    for j in body.split():
        if j.lower() in matched_keywords:
            body = body.replace(j, Colors.GREEN + j + Colors.RESET)
    
    print("Subject: " + subject)
    print("Body: " + body)

def keyword_score(subject, body):
    """
    Main function to calculate the risk score for an email.
    Returns a percentage score indicating likelihood of keywords appearing in safe/spam emails.
    """
    process_email(subject, body)
    
    # Split dataset into safe and spam
    safe_df = df[df["label"] == 0]
    spam_df = df[df["label"] == 1]
    
    # Calculate keyword match scores
    score_safe = calc_score(safe_df)
    score_spam = calc_score(spam_df)
    
    # Risk score is average of both
    risk_score = (score_safe + score_spam) / 2
    return round(risk_score, 4) * 100

def find_keywords(text):
    # Return a list of keywords found in the text.
    return list(set(matched_keywords))

def highlight_keywords(text):
    # Return text with matched keywords highlighted for web display using HTML <span>.
    if not text or not matched_keywords:
        return text
    
    highlighted_text = text
    for keyword in set(matched_keywords):
        pattern = r'\b' + re.escape(keyword) + r'\b'
        highlighted_text = re.sub(
            pattern, 
            f'<span style="background-color: #28a745; font-weight: bold; color: white; padding: 2px 4px; border-radius: 3px;">{keyword}</span>', 
            highlighted_text, 
            flags=re.IGNORECASE
        )
    
    return highlighted_text