# Project Title: Phishing Email Detection

## Group Members
|     Name     | Student ID |
|--------------|------------|
| Lam Jing Hai |   2501051  |
|  Lim Ze Kai  |   2501273  |
| Wai Yan Aung |   2502245  |
| Teng Tze Hui |   2502437  |
| Chia Yu Wei  |   2503191  |

**Module:** SIT INF1002 – Programming Fundamentals  
**Class:** Lab-P1 - 1  
**Semester:** AY2024/2025 Trimester [1]  
**Group Number:** 5

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
- Python 3.9 or higher  
- Required libraries: `pandas`, `re`, `difflib`, `streamlit`  

### Setup
Install dependencies:
```bash
pip install -r requirements.txt
```

```python
python set_up.py
```

This creates `a.txt` file of safe URLs based on data from the database. You may change the file path on line 4 of set_up.py to use different database. 

---

### Commands to run the code 
For terminal use:
```bash
python main.py
```

For Streamlit interface:
```bash
streamlit run app.py
```

---

## 6. Input and Output?

## How it works (Brief Explanation)

## 7. Results and Insights

## 8. License
This project was developed for academic purposes under the SIT INF1002: Programming Fundamentals module.
All content is intended for educational use only.