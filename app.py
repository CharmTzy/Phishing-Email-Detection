import streamlit as st
import requests
import re

st.set_page_config(page_title="Phishing Email Keyword Detection", page_icon=":shield:", layout="wide")

# ===== Custom CSS =====
st.markdown(
    """
    <style>
    /* Force full width */
    .block-container {
        max-width: 100% !important;
        padding-left: 3rem;
        padding-right: 3rem;
    }

    .big-title {
        font-size: 2rem;
        font-weight: 700;
        color: #2c3e50;
        margin-bottom: 10px;
    }
    .subtitle {
        font-size: 1.1rem;
        color: #555;
        margin-bottom: 25px;
    }
    .step-title {
        font-size: 1.3rem;
        font-weight: 600;
        margin-top: 30px;
        margin-bottom: 12px;
        color: #2c3e50;
    }
    .result-card {
        flex: 1;
        background: #f9f9f9;
        border: 1px solid #ddd;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        font-size: 1.1rem;
        font-weight: 500;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }
    .result-card span {
        font-size: 1.3rem;
    }
    .btn-analyze {
        background-color: #e74c3c;
        color: white;
        font-size: 1.1rem;
        font-weight: 600;
        padding: 12px;
        border-radius: 6px;
        width: 100%;
    }
    div.stForm button[type="submit"] {
        font-size: 0.9rem !important;
        font-weight: 600 !important;
        padding: 6px 18px !important;
        border-radius: 6px !important;
        border: none !important;
        width: auto !important;
        display: inline-block !important;
    }
    div.stForm button[type="submit"]:hover {
        background-color: #c0392b !important;  /* darker red on hover */
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ===== Page Title =====
st.markdown("<div class='big-title'>🔎 Phishing Email Keyword Detection</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='subtitle'>This tool analyzes email subjects and bodies to detect common phishing-related keywords and assigns a risk score.</div>",
    unsafe_allow_html=True
)

# ===== Step 1: Enter Email Details =====
st.markdown("<div class='step-title'>1. Enter Email Details</div>", unsafe_allow_html=True)

with st.form("email_form"):
    subject = st.text_input("Email Subject")
    body = st.text_area("Email Body", height=120)
    uploaded_file = st.file_uploader("Or upload email file (.eml)", type=["eml"])
    submitted = st.form_submit_button("Analyze Email", type="primary")

    if uploaded_file is not None:
        eml_text = uploaded_file.read().decode("utf-8", errors="ignore")
        subject_match = re.search(r"^Subject:\s*(.*)$", eml_text, re.MULTILINE)
        subject = subject_match.group(1) if subject_match else subject
        plain_text_match = re.search(
            r"Content-Type:\s*text/plain.*?(\r?\n\r?\n)(.*?)(?=\r?\n--|$)",
            eml_text,
            re.IGNORECASE | re.DOTALL
        )
        if plain_text_match:
            body = plain_text_match.group(2).replace("=\r\n", "").replace("=3D", "=").strip()
        else:
            split_parts = re.split(r"\r?\n\r?\n", eml_text)
            body = "\n\n".join(split_parts[1:]).strip() if len(split_parts) > 1 else body

# ===== Step 2: Analysis Results =====
if submitted:
    if not subject and not body:
        st.error("⚠️ Please provide either subject/body or upload an email file.")
    else:
        try:
            response = requests.post(
                "http://127.0.0.1:5000/detect_keywords",
                json={"subject": subject, "body": body},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            st.markdown("<div class='step-title'>2. Analysis Results</div>", unsafe_allow_html=True)

            # Result Summary (keep only Risk Score + Label in cards)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(
                    f"<div class='result-card'><span>⚖️</span><br>Risk Score<br><strong>{data['score']}</strong></div>",
                    unsafe_allow_html=True
                )
            with col2:
                st.markdown(
                    f"<div class='result-card'><span>🏷️</span><br>Label<br><strong>{data['label']}</strong></div>",
                    unsafe_allow_html=True
                )

            # Detailed Breakdown
            st.markdown("### Detailed Breakdown")
            st.markdown(f"**Email Subject:** {data['subject_highlighted']}", unsafe_allow_html=True)
            st.markdown(f"**Email Body:**\n\n{data['body_highlighted']}", unsafe_allow_html=True)

            # Matched Keywords AFTER body
            st.markdown("---")
            st.markdown("**Matched Keywords:**")
            if data['keywords']:
                st.markdown(f"<span style='color:#d9534f'>{', '.join(data['keywords'])}</span>", unsafe_allow_html=True)
            else:
                st.markdown("✅ None found")

        except Exception as e:
            st.error(f"❌ Error connecting to backend: {e}")
