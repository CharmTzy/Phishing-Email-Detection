import pandas as pd
import string
import re
df = pd.read_csv(r"Datasets/cleaned_SA.csv")

def createTxtFiles():
    txtString=""
    #write safe urls to a file
    for i in df[df["label"] == 0]["urls"]:  
        row=str(i)
        if row!="nan":
            txtString+=row+"\n"
    with open("safe_urls.txt", "w",encoding="utf-8") as f:
        f.write(txtString)



if __name__=="__main__":
    createTxtFiles()