# Project Title: Phishing Email Detection

## Group Members

| Name         | Student ID |
| ------------ | ---------- |
| Lam Jing Hai | 2501051    |
| Lim Ze Kai   | 2501273    |
| Wai Yan Aung | 2502245    |
| Teng Tze Hui | 2502437    |
| Chia Yu Wei  | 2503191    |

**Module:** SIT INF1002 – Programming Fundamentals  
**Class:** Lab-P1 - 1  
**Semester:** AY2024/2025 Trimester [1]  
**Group Number:** 5

**Hosted Website** https://phishing-email-detection-s0sg.onrender.com

## 1. Project Title and Overview

**Phishing Email Detection** – A Python-based tool designed to identify phishing emails through rule-based analysis.  
The system examines email text, keywords, and URLs using string-processing and logical checks to detect suspicious patterns such as deceptive wording, irregular links, and domain impersonation.  
This project reinforces fundamental programming skills, problem decomposition, and analytical thinking in Python.

---

## 2. Objectives / Purpose

The objective of this project is to design and implement a **rule-based system** that accurately detects phishing emails by combining **content-based** and **URL-based** techniques.  
It aims to help users understand how linguistic and structural elements in emails—like specific keywords, strange URLs, or mimic domains—can reveal potential phishing threats.

---

## 3. Project Structure

```
Phishing-Email-Detection/
│
├── server.py # Main execution file for the phishing detection system
├── set_up.py # Initializes the trusted URL database and generates safe_urls.txt
│── trusted_sites.py # Generates the legitimate_domains.csv and the domain_analysis_full.csv for email domains
├── app.py # Streamlit web interface for interactive testing
├── requirements.txt # List of required dependencies
│
├── Datasets/
│ └── cleaned_SA.csv # Input dataset used for analysis
│
│── keyword_detection.py # Handles keyword scoring and classification logic
│── url_detection.py # Checks URL patterns and structure for suspicious structures
│── edit_distance.py # Compares URLs against trusted websites to detect impersonations
│── domain_detection.py # Compares email domains against legitimate domains
│── all_checks.py # Consolidates all other phishing logic into one file
│
└── README.md # Project documentation and description
```

This structure separates the main logic, data, and output clearly, making the project easy to navigate and maintain.

---

## 4. System Features

The system generates several outputs that contribute to phishing detection:

- **Final Label:** Classification result — phishing or legitimate.
- **Overall Score:** Numerical safety rating (lower = safer).
- **Spam Votes:** Number of checks that flagged the email as suspicious.
- **Keyword Score and Label:** Frequency of phishing-related keywords and spam/ham classification.
- **Suspicious Keywords:** List of flagged words.
- **Highlighted Body and Subject:** Email text with suspicious terms highlighted.
- **URL Check:** Identifies suspicious or irregular URLs.
- **Edit Distance Check:** Compares URLs with trusted domains to detect impersonations.

---

## 5. Installation / Setup Instructions

### Prerequisites

- Python 3.9 or higher (Recommended Version - Python 3.13)
- Required libraries: `pandas`, `re`, `difflib`, `streamlit`

### Setup

Install dependencies:

```bash
pip install -r requirements.txt
```
Run set up files
```
python set_up.py
trusted_sites.py
```

---

### Commands to run the code

In this project, we need to run Frontend Streamlit and Flask server separately.
Please run both these command lines in the separate terminal to see the full features.

For Flask Server:

```bash
python server.py
```

For Streamlit interface:

```bash
streamlit run app.py
```

---

## How it works (Brief Explanation)

1. Preprocessing:
   Cleans and standardizes email text, removing HTML tags and irrelevant characters.

2. Keyword Detection & Scoring:
   Identifies suspicious words (e.g., “urgent,” “verify,” “password”) and calculates a score based on their frequency and position.

3. Domain Legitimacy Check:
   Validates sender domains against a trusted domain list using a reference CSV file.

4. URL Extraction & Validation:
   Detects URLs within email content and checks whether they belong to known safe domains.

5. Edit Distance Analysis:
   Uses the Levenshtein distance algorithm to detect lookalike domains (e.g., paypa1.com vs paypal.com).

6. Unified Risk Scoring:
   Aggregates results from all modules (keyword, URL, edit distance, domain) to calculate a total phishing risk score.

7. Frontend Visualization:
   A Streamlit-based interface displays the results, highlights risky terms, and explains why an email is flagged.

## 6. Results and Insights

The system produces several key outputs to determine whether an email is phishing or legitimate. The Final Label provides the overall result, indicating whether the email is identified as a phishing attempt or a legitimate message. The Overall Score represents a numerical rating of the email’s safety, where a lower score signifies a safer email. Supporting this, the Spam Votes show how many detection checks flagged the email as suspicious, offering a breakdown of how the overall rating was derived.

The Keyword Score measures the frequency of suspicious or phishing-related terms within the email’s content, while the Keyword Label classifies the message as spam or ham based solely on that score. The system also lists all Suspicious Keywords detected and visually presents them within the Highlighted Body and Subject, allowing users to see exactly where these keywords appear for better context and understanding.

In addition to text analysis, the system examines all links found in the email. The URL section lists these links, while the URL Check identifies any that appear suspicious, such as those containing excessive numbers or irregular patterns. The Edit Distance Check then compares each URL against a database of trusted websites to detect possible impersonation attempts. It shows the calculated edit distance, indicating how similar the suspicious URL is to a legitimate one and highlights the closest trusted match. Together, these outputs provide a detailed and transparent evaluation, offering users a clear view of how the system determines whether an email poses a phishing risk.

## 7. License

This project was developed for academic purposes under the SIT INF1002: Programming Fundamentals module.
All content is intended for educational use only.
