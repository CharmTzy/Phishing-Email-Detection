import streamlit as st
import requests
import re

st.set_page_config(page_title="Phishing Email Keyword Detection", page_icon=":shield:", layout="centered")

st.markdown(
    """
    <style>
    .main {background: linear-gradient(120deg, #e0eafc 0%, #cfdef3 100%);}
    .result-box {
        background: #e3f6ff;
        border-radius: 10px;
        border: 1px solid #b3e0ff;
        box-shadow: 0 2px 8px rgba(44, 62, 80, 0.04);
        padding: 20px;
        margin-top: 24px;
        color: #007bff;
        font-size: 1.13em;
        font-weight: 500;
        letter-spacing: 0.5px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🔎 Phishing Email Keyword Detection")

with st.form("email_form"):
    subject = st.text_input("Email Subject")
    body = st.text_area("Email Body", height=120)
    uploaded_file = st.file_uploader("Or upload email file (.eml)", type=["eml"])
    submitted = st.form_submit_button("Check Email")

    if uploaded_file is not None:
        eml_text = uploaded_file.read().decode("utf-8", errors="ignore")
        subject_match = re.search(r"^Subject:\s*(.*)$", eml_text, re.MULTILINE)
        subject = subject_match.group(1) if subject_match else subject
        plain_text_match = re.search(r"Content-Type:\s*text/plain[^]*?(\r?\n\r?\n)([^]*?)(?=\r?\n--|$)", eml_text, re.IGNORECASE)
        if plain_text_match:
            body = plain_text_match.group(2).replace("=\r\n", "").replace("=3D", "=").strip()
        else:
            split_parts = re.split(r"\r?\n\r?\n", eml_text)
            body = "\n\n".join(split_parts[1:]).strip() if len(split_parts) > 1 else body

if submitted:
    if not subject and not body:
        st.error("Please provide either subject/body or upload an email file.")
    else:
        try:
            response = requests.post(
                "http://127.0.0.1:5000/detect_keywords",
                json={"subject": subject, "body": body},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            # Build the entire result HTML
            result_html = f"""
            <div class="result-box">
                <strong>Matched Keywords:</strong> <span style='color:#d9534f'>{', '.join(data['keywords']) if data['keywords'] else 'None'}</span><br><br>
                <strong>Email Subject:</strong><br>{data['subject_highlighted']}<br><br>
                <strong>Email Body:</strong><br><span style='white-space: pre-line'>{data['body_highlighted']}</span><br><br>
                <strong>Risk Score:</strong> {data['score']}<br>
                <strong>Label:</strong> {data['label']}
            </div>
            """
            st.markdown(result_html, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error connecting to backend: {e}")