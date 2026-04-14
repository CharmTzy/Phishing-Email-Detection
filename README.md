---
title: Phishing Email Detection
emoji: 🛡️
colorFrom: blue
colorTo: cyan
sdk: docker
app_port: 7860
pinned: false
---

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

**Phishing Email Detection** – A Python-based tool designed to identify phishing emails through a trained machine-learning model plus supporting security checks.  
The system now examines email text, sender domains, keywords, and URLs using a saved phishing classifier together with logical checks to detect suspicious wording, irregular links, and domain impersonation.  
This project reinforces fundamental programming skills, problem decomposition, and analytical thinking in Python.

---

## 2. Objectives / Purpose

The objective of this project is to design and implement a **model-driven phishing detector** that accurately identifies suspicious emails by combining **machine learning**, **content-based analysis**, and **URL/domain checks**.  
It aims to help users understand how linguistic and structural elements in emails, like specific keywords, strange URLs, sender-domain trust, or mimic domains, can reveal phishing threats.

---

## 3. Project Structure

```
Phishing-Email-Detection/
│
├── main.py # Main execution file for the phishing detection system
├── set_up.py # Initializes the trusted URL database and generates safe_urls.txt
├── app.py # Streamlit web interface for interactive testing
├── requirements.txt # List of required dependencies
│
├── Datasets/
│ └── cleaned_SA.csv # Input dataset used for analysis
│
│── keyword_analysis.py # Handles keyword scoring and classification logic
│── url_analysis.py # Checks URL patterns and structure for suspicious behavior
│── edit_distance.py # Compares URLs against trusted domains to detect impersonations
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

---

### Commands to run the code

In this project, we run model training once, then start the Flask backend and Streamlit frontend in separate terminals.

Train or retrain the saved model:

```bash
python3 train_model.py --force
```

This creates the saved model artifact in `models/`.

Then run the backend and frontend:

For Flask Server:

```bash
python3 server.py
```

For Streamlit interface:

```bash
streamlit run app.py
```

Sample `.eml` files for quick testing are available in `samples/`.

For a single-command deployment-style run on platforms like Hugging Face Spaces:

```bash
./start.sh
```

---

## How it works (Brief Explanation)

1. Preprocessing:
   Cleans and standardizes email text, removing HTML tags and irrelevant characters.

2. Machine-Learning Prediction:
   Uses the trained phishing email classifier to estimate phishing probability from subject, body, sender domain, and URL patterns.

3. Keyword Detection & Scoring:
   Identifies suspicious words (e.g., “urgent,” “verify,” “password”) and calculates a supporting score.

4. Domain Legitimacy Check:
   Validates sender domains against a trusted domain list using a reference CSV file.

5. URL Extraction & Validation:
   Detects URLs within email content and checks whether they belong to known safe domains.

6. Edit Distance Analysis:
   Uses the Levenshtein distance algorithm to detect lookalike domains (e.g., paypa1.com vs paypal.com).

7. Unified Risk Scoring:
   Aggregates the model output with keyword, URL, edit distance, and domain checks to calculate a final phishing risk score.

8. Frontend Visualization:
   A Streamlit-based interface displays the final verdict, confidence, supporting reasons, highlighted risky terms, and detailed link/domain analysis.

## 6. Results and Insights

The system produces several key outputs to determine whether an email is phishing or legitimate. The Final Label provides the overall result, indicating whether the email is identified as a phishing attempt or a legitimate message. The Overall Score represents a numerical rating of the email’s safety, where a lower score signifies a safer email. Supporting this, the Spam Votes show how many detection checks flagged the email as suspicious, offering a breakdown of how the overall rating was derived.

The Keyword Score measures the frequency of suspicious or phishing-related terms within the email’s content, while the Keyword Label classifies the message as spam or ham based solely on that score. The system also lists all Suspicious Keywords detected and visually presents them within the Highlighted Body and Subject, allowing users to see exactly where these keywords appear for better context and understanding.

In addition to text analysis, the system examines all links found in the email. The URL section lists these links, while the URL Check identifies any that appear suspicious, such as those containing excessive numbers or irregular patterns. The Edit Distance Check then compares each URL against a database of trusted websites to detect possible impersonation attempts. It shows the calculated edit distance, indicating how similar the suspicious URL is to a legitimate one and highlights the closest trusted match. Together, these outputs provide a detailed and transparent evaluation, offering users a clear view of how the system determines whether an email poses a phishing risk.

## 7. License

This project was developed for academic purposes under the SIT INF1002: Programming Fundamentals module.
All content is intended for educational use only.

## 8. Deploy To Hugging Face Spaces

This repository is now prepared for a Docker Space deployment.

Files used for Hugging Face Spaces:

- `Dockerfile`
- `start.sh`
- `requirements-space.txt`
- `.dockerignore`
- This `README.md` front matter

### Option A: Upload through the Hugging Face website

1. Sign in to [Hugging Face](https://huggingface.co/).
2. Click **New Space**.
3. Choose a Space name.
4. Select **Docker** as the SDK.
5. Set visibility to public or private.
6. Create the Space.
7. Upload the full project contents into the Space repository.
8. Wait for the build logs to finish.
9. Open the Space URL after the status becomes **Running**.

### Option B: Push with Git

```bash
git remote add hf https://huggingface.co/spaces/YOUR_USERNAME/YOUR_SPACE_NAME
git push hf main
```

If your local branch is not `main`, replace `main` with your branch name.

### Notes

- The app listens on port `7860`, which matches the Hugging Face Docker Space setting in this README.
- `start.sh` starts the Flask backend first, then the Streamlit frontend.
- Streamlit XSRF protection is disabled in `start.sh` so file upload works correctly in Docker Spaces.
- The saved model in `models/` is used directly, so the Space does not need to retrain the model during startup.

### Local Docker Test Before Pushing

```bash
docker build -t phishing-email-detection .
docker run -p 7860:7860 phishing-email-detection
```

Then open:

```text
http://localhost:7860
```
