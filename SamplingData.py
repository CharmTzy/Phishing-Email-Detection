# importing of library
import pandas as pd
import warnings
warnings.filterwarnings('ignore')
from utilities import create_directory, join_paths, write_to_file
from sklearn.model_selection import train_test_split

# Purpose
"""
We are going through all four datasets and randomly selecting a small number of emails from each for manual testing. 
These emails will serve as test data to quickly check how well our logic performs.

Processing 
For each dataset, we manually pick a few random emails (around 20–50, depending on the dataset size) and 
save them into folders according to their file type.

# Saving the Sampled Datasets

The sampled emails are saved into separate folders based on dataset and type, for example:  
- Test Datasets/cleaned SA
- Test Datasets/raw SA

Each email is saved as an individual '.txt' file, labeled sequentially from 1 to 20.
Each email is saved as an individual '.eml' file, labeled sequentially from 1 to 20.

"""
# function to combine email fields (for cleaned datasets)
def combine_email_fields(row):
    return f"""
Date: {row.get('date', '')}
From: {row.get('from', '')}
To: {row.get('to', '')}
Subject: {row.get('subject', '')}
Sender: {row.get('sender', '')}

{row.get('body', '')}
"""

# Save sampled datasets to eml and txt files
def saveSampledEmails(df, folder_path, prefix, isCleaned=False):
    # Initailise the counter
    emlCounter = txtCounter = 1

    # Create directory if it doesn't exist
    create_directory(folder_path)

    # Create subdirectories for txt and eml files
    txtFolder = create_directory(join_paths(folder_path, "txt"))
    emlFolder = create_directory(join_paths(folder_path, "eml"))

    # Split it into traing and testing (using the machine learning logic but not splitting intox-train, y-train, 
    # x-test, y-test as the prj not doing machine learning. but will be nice and consistent idf we split it that way)
    train, test = train_test_split(df, test_size=0.2, random_state=42)

    # Save each email as a separate txt file
    for i, (_, row) in enumerate(test.iterrows(), start=1):

        # Determine which column to use
        if isCleaned:
            content = combine_email_fields(row)
        else:
            content = None
            if 'body' in row:
                content = row['body']
            elif 'message' in row:
                content = row['message']
            else:
                content = ""  # fallback if neither exists

        # Split the data into txt and eml files 
        # Odd -> txt
        # Even -> eml
        if i % 2 == 1:  
            txtFilePath = join_paths(txtFolder, f"{prefix}_{txtCounter}.txt")

            # Write to .txt file
            write_to_file(txtFilePath, str(content))

            # Increment the counter
            txtCounter += 1
        else:
            emlFilePath = join_paths(emlFolder, f"{prefix}_{emlCounter}.eml")

            # Write to .eml file
            write_to_file(emlFilePath, str(content))

            # Increment the counter
            emlCounter += 1
         
# Initialize number of samples
num_samples = 40  # total

# File paths
cleaned_SA = pd.read_csv(r'Datasets\cleaned_SA.csv')
raw_SA = pd.read_csv(r'Datasets\spamAssassin.csv')

# Read, sample, and save each dataset
saveSampledEmails(cleaned_SA, join_paths("Test Datasets", "cleaned SA"), "cleanedSA", isCleaned=True)
saveSampledEmails(raw_SA, join_paths("Test Datasets", "raw SA"), "rawSA")







