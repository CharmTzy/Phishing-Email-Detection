import pandas as pd
import string
import re
df = pd.read_csv(r"Datasets/cleaned_SA.csv")
stop_words = {
    "the","is","in","at","of","a","an","and","to","for","on","with","by","from",
    "this","that","it","as","be","or","are","was","were","we","you","he","she",
    "they","them","his","her","its","my","your","our"
}

def createTxtFiles():
    keywords = []
    txtString=""
    #Creates Text File for safe subject keywords
    for i in df[df["label"] == 0]["subject"]:  
        row=str(i)
        # Remove punctuation
        row = row.translate(str.maketrans('', '', string.punctuation))
        # Extract unique lowercase keywords, ignoring stop words
        keywords = list(dict.fromkeys(
            w.lower() for w in row.split() if w.lower() not in stop_words
        ))
        for x in keywords:
            txtString+=x
    #writes to file
    with open("safe_subject.txt", "w",encoding="utf-8") as f:
        f.write(txtString)
    #clears the text string
    txtString=""
    #Creates Text File for safe body keywords
    for i in df[df["label"] == 0]["body"]:  
        row=str(i)
        # Remove punctuation
        row = row.translate(str.maketrans('', '', string.punctuation))
        # Extract unique lowercase keywords, ignoring stop words
        keywords = list(dict.fromkeys(
            w.lower() for w in row.split() if w.lower() not in stop_words
        ))
        for x in keywords:
            txtString+=x
    #writes to file
    with open("safe_body.txt", "w",encoding="utf-8") as f:
        f.write(txtString)
    #clears the text string
    txtString=""
    #Creates Text File for spam subject keywords
    for i in df[df["label"] == 1]["subject"]:  
        row=str(i)
        # Remove punctuation
        row = row.translate(str.maketrans('', '', string.punctuation))
        # Extract unique lowercase keywords, ignoring stop words
        keywords = list(dict.fromkeys(
            w.lower() for w in row.split() if w.lower() not in stop_words
        ))
        for x in keywords:
            txtString+=x
    #writes to file
    with open("spam_subject.txt", "w",encoding="utf-8") as f:
        f.write(txtString)
    #clears the text string
    txtString=""
    #Creates Text File for spam body keywords
    for i in df[df["label"] == 1]["body"]:  
        row=str(i)
        # Remove punctuation
        row = row.translate(str.maketrans('', '', string.punctuation))
        # Extract unique lowercase keywords, ignoring stop words
        keywords = list(dict.fromkeys(
            w.lower() for w in row.split() if w.lower() not in stop_words
        ))
        for x in keywords:
            txtString+=x
    #writes to file
    with open("spam_body.txt", "w",encoding="utf-8") as f:
        f.write(txtString)
    #clears the text string
    txtString=""
    #write safe urls to a file
    for i in df[df["label"] == 0]["urls"]:  
        row=str(i)
        if row!="nan":
            txtString+=row+"\n"
    with open("safe_urls.txt", "w",encoding="utf-8") as f:
        f.write(txtString)
    #clears the text string
    txtString=""

if __name__=="__main__":
    createTxtFiles()