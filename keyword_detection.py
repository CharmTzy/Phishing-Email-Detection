import pandas as pd
import string

subject = input("Email Subject: ")
body = input("Email Body: ")

text = f"{subject} {body}"
text = text.translate(str.maketrans('', '', string.punctuation))

class Colors:
    BLUE = '\033[94m'
    RESET = '\033[0m'

stop_words = {
    "the","is","in","at","of","a","an","and","to","for","on","with","by","from",
    "this","that","it","as","be","or","are","was","were","hello", "hi","dear",
}

# unique keywords (lowercase, no stopwords)
keywords = list(dict.fromkeys(
    w.lower() for w in text.split() if w.lower() not in stop_words
))

df = pd.read_csv(r"Datasets/cleaned_SA.csv")
matched_keywords = []

def calc_score(sub_df):
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
    for i in subject.split():
        if i.lower() in matched_keywords:
            subject = subject.replace(i, Colors.BLUE + i + Colors.RESET)
    
    for j in body.split():
        if j.lower() in matched_keywords:
            body = body.replace(j, Colors.BLUE + j + Colors.RESET)

    print("Subject: " + subject)
    print("Body: " + body)

if __name__ == "__main__":
    safe_df = df[df["label"] == 0]
    spam_df = df[df["label"] == 1]

    score_safe = calc_score(safe_df)
    score_spam = calc_score(spam_df)

    output(subject, body)

    risk_score = (score_safe + score_spam) / 2
    print("Risk Score: " + str(round(risk_score, 4) * 100) + "%")