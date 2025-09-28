import pandas as pd
import string
import spacy
import re
import requests
from io import StringIO

nlp = spacy.load("en_core_web_sm")

# Correct raw CSV URL from GitHub
url = "https://raw.githubusercontent.com/CharmTzy/cleaned-SA-dataset/main/cleaned_SA.csv"

response = requests.get(url, verify=False)
df = pd.read_csv(StringIO(response.text))

suspicious_keywords = []

class Colors:   
    GREEN = '\033[92m'
    RESET = '\033[0m'
    
# Extract nouns and proper nouns from text
def extract_keywords(text):
    text = text.translate(str.maketrans('', '', string.punctuation))
    doc = nlp(text)
    return list({token.text.lower() for token in doc if token.pos_ in ["NOUN", "PROPN"]})

# Calculate risk score for spam
def keyword_score(subject, body):
    text = f"{subject} {body}"
    keywords = extract_keywords(text)
    keyword_counts = {}

    spam_df = df[df["label"] == 1]

    def calc_score(sub_df):
        if len(sub_df) == 0:
            return 0
        count = 0
        
        for kw in keywords:
            # Subject hits → weight 2
            subj_hits = sub_df["subject"].str.contains(kw, case=False, na=False)
            subj_total = subj_hits.sum() * 2  # subject has higher weight
            
            # Body hits → check first 100 words separately
            body_words = sub_df["body"].str.split()
            body_hits_weighted = 0
            for body_list in body_words:
                if not isinstance(body_list, list):
                    continue
                first_100 = body_list[:100]
                remaining = body_list[100:]
                body_hits_weighted += sum(1 for w in first_100 if kw.lower() in w.lower()) * 1.5
                body_hits_weighted += sum(1 for w in remaining if kw.lower() in w.lower()) * 1

            total_hits = subj_total + body_hits_weighted

            if total_hits > 0:
                keyword_counts[kw] = keyword_counts.get(kw, 0) + total_hits
                count += total_hits
                suspicious_keywords.append(kw)
            elif total_hits == 0:
                suspicious_keywords.append(kw)
        return count * 10 / len(sub_df)

    score_spam = calc_score(spam_df)
    return round(score_spam, 2)  # final risk score

# Find keywords in a text that are considered suspicious
def find_keywords(text):
    keywords_in_text = extract_keywords(text)
    return [kw for kw in keywords_in_text if kw]

# Highlight keywords in HTML
def highlight_keywords(text):
    for kw in suspicious_keywords:
        pattern = r'\b({})\b'.format(re.escape(kw))
        text = re.sub(
            pattern,
            f'<span style="background-color: #28a745; font-weight: bold; color: white; padding: 2px 4px; border-radius: 3px;">{kw}</span>',
            text,
            flags=re.IGNORECASE
        )
    return text
