import pandas as pd
import string
import spacy
import re

nlp = spacy.load("en_core_web_sm")

# Load dataset once
df = pd.read_csv(r"Datasets/cleaned_SA.csv")

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

    # Check the spam emails column in the dataset
    spam_df = df[df["label"] == 1]

    def calc_score(sub_df):
        if len(sub_df) == 0:
            return 0
        count = 0
    
    #If the incoming keywords is found in the spam dataset subject/body, increase the count by the number of occurrences
        for kw in keywords:
            subj_hits = sub_df["subject"].str.contains(kw, case=False, na=False)
            body_hits = sub_df["body"].str.contains(kw, case=False, na=False)
            total_hits = subj_hits.sum() + body_hits.sum()
            if total_hits > 0:
                keyword_counts[kw] = keyword_counts.get(kw, 0) + total_hits
                count += total_hits
                suspicious_keywords.append(kw)
            #If the keyword is not found in spam dataset, add to suspicious_keywords list
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
