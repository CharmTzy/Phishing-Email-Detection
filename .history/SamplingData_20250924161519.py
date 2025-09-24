# importing of library
import pandas as pd
import warnings
warnings.filterwarnings('ignore')
from utilities import create_directory, join_paths, write_to_file

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
- Test Datasets/cleaned Enron
- Test Datasets/raw SA
- Test Datasets/raw Enron

Each email is saved as an individual '.txt' file, labeled sequentially from 1 to 20.
Each email is saved as an individual '.eml' file, labeled sequentially from 1 to 20.

"""
# Initialize number of samples
num_samples = 40  # total

# List dataset of the csv files
csv_datasets = {
    "cleaned_spamAssassin": r'Datasets\cleaned_SA.csv',
    "cleaned_enron": r'Datasets\cleaned_enron.csv',
    "raw_spamAssassin": r'Datasets\spamAssassin.csv',
    "raw_enron": r'Datasets\enronEmails.csv'
}

# Save sampled datasets to eml and txt files
def saveSampledEmails(df, folder_path, prefix):
    # Initailise the counter
    emlCounter = txtCounter = 1

    # Create directory if it doesn't exist
    create_directory(folder_path)

    # Create subdirectories for txt and eml files
    txtFolder = create_directory(join_paths(folder_path, "txt"))
    emlFolder = create_directory(join_paths(folder_path, "eml"))

    # Sample the data
    sampled = df.sample(n=num_samples, random_state=42) 

    # Save each email as a separate txt file
    for i, (_, row) in enumerate(sampled.iterrows(), start=1):

        # Determine which column to use
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
         
# Read, sample, and save each dataset
for name, fileName in csv_datasets.items():
    df = pd.read_csv(fileName)
    saveSampledEmails(df, join_paths('..', 'Test Datasets', name.replace('_', ' ')), name)





