import streamlit as st
import requests
import re

#slide 1
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
     
    }
    .subtitle {
        font-size: 1.1rem;
        color: #555;
       
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
        background-color: #c0392b !important; 
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
#slide 2
with st.form("email_form"):
    sender_email = st.text_input("Sender Email")
    subject = st.text_input("Email Subject")
    body = st.text_area("Email Body", height=120)
    url = st.text_input("URL") 
    uploaded_file = st.file_uploader("Or upload email file (.eml)", type=["eml"])
    submitted = st.form_submit_button("Analyze Email", type="primary")

    if uploaded_file is not None:
        eml_text = uploaded_file.read().decode("utf-8", errors="ignore")
        
        # Extract subject
        subject_match = re.search(r"^Subject:\s*(.*)$", eml_text, re.MULTILINE)
        subject = subject_match.group(1) if subject_match else subject
        
        # Extract sender email if the input field is empty
        if not sender_email:
            from_match = re.search(r"^From:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}).*$", eml_text, re.MULTILINE | re.IGNORECASE)
            if from_match:
                sender_email = from_match.group(1)
        
        # Extract body
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
    print(f"Submitted: subject='{subject}', body length={body}, url='{url}'")
    if not subject and not body and not url:
        st.error("⚠️ Please provide either subject/body, URL, or upload an email file.")
    else:
        try:
            # Call unified backend
            #slide 3
            response = requests.post(
                "http://127.0.0.1:5000/analyse_email",
                json={"sender_email": sender_email, "subject": subject, "body": body, "url": url},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            st.markdown("<div class='step-title'>2. Analysis Results</div>", unsafe_allow_html=True)

            # Summary
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(
                    f"<div class='result-card'><span>⚖️</span><br>Overall Score<br><strong>{data['overall_score']}</strong></div>",
                    unsafe_allow_html=True
                )
            with col2:
                st.markdown(
                    f"<div class='result-card'><span>🏷️</span><br>Final Label<br><strong>{data['final_label']}</strong></div>",
                    unsafe_allow_html=True
                )

            # Detailed breakdown
            st.markdown("### Detailed Breakdown")
            st.markdown(f"**Email Domain:** {data['email_data']['domain']}")
            st.markdown(f"**Category:** {data['email_data']['category']}")
            st.markdown(f"**Legitimacy Score:** {data['email_data']['legitimacy_score']}")
            st.markdown(f"**Total Occurrences:** {data['email_data']['total_occurrences']}")
            st.markdown(f"**No. of times shown in Spam Inbox:** {data['email_data']['in_spam']}")
            st.markdown(f"**No. of times shown in Safe Inbox:** {data['email_data']['in_ham']}")
            st.markdown(f"**Sources:** {data['email_data']['sources']}")

            st.markdown(f"**Keyword Score:** {data['keyword_score']} ({data['keyword_label']})")
            st.markdown(f"**Spam Votes:** {data['spam_votes']} / 5")

            # Keywords
            st.markdown("---")
            st.markdown("**Suspicious Keywords:**")
            if data['keywords']:
                st.markdown(f"<span style='color:#d9534f'>{', '.join(data['keywords'])}</span>", unsafe_allow_html=True)
            else:
                st.markdown("✅ None found")

            # Highlighted subject/body
            st.markdown("---")
            st.markdown("**Email Subject (highlighted):**")
            st.markdown(data['subject_highlighted'], unsafe_allow_html=True)
            st.markdown("**Email Body (highlighted):**")
            st.markdown(data['body_highlighted'], unsafe_allow_html=True)

            # URL Analysis
            st.markdown("---")
            st.markdown("**URL Analysis:**")
            if data['urls']:
                for i, u in enumerate(data['urls']):
                    safe = data.get("urlCheck", [])[i] if i < len(data.get("urlCheck", [])) else False
                    status = "Safe ✅" if safe else "Suspicious ❌"
                    st.markdown(f"- {u} → {status}")

                    if i < len(data.get("editCheck", [])):
                        dist, closest = data["editCheck"][i]
                        st.markdown(f"   ↳ Closest Trusted: {closest} (distance {dist})")
            else:
                st.markdown("✅ No URLs found")

        except Exception as e:
            st.error(f"❌ Error connecting to backend: {e}")