import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:5000/analyse_email")

#slide 1
st.set_page_config(page_title="Phishing Email Keyword Detection", page_icon=":shield:", layout="wide")

# ===== Custom CSS =====
st.markdown(
    """
    <style>
    :root {
        --title-color: var(--text-color, #2c3e50);
        --subtitle-color: var(--text-color, #555);
        --card-bg: var(--secondary-background-color, #f9f9f9);
        --card-border: rgba(127, 127, 127, 0.22);
        --card-text: var(--text-color, #1f2933);
        --card-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }

    @media (prefers-color-scheme: dark) {
        :root {
            --subtitle-color: var(--text-color, #cbd5e1);
            --card-border: rgba(255, 255, 255, 0.14);
            --card-shadow: 0 8px 24px rgba(0,0,0,0.35);
        }
    }

    /* Force full width */
    .block-container {
        max-width: 100% !important;
        padding-left: 3rem;
        padding-right: 3rem;
    }

    .big-title {
        font-size: 2rem;
        font-weight: 700;
        color: var(--title-color);
     
    }
    .subtitle {
        font-size: 1.1rem;
        color: var(--subtitle-color);
        opacity: 0.88;
       
    }
    .step-title {
        font-size: 1.3rem;
        font-weight: 600;
        margin-top: 30px;
        margin-bottom: 12px;
        color: var(--title-color);
    }
    .result-card {
        flex: 1;
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        font-size: 1.1rem;
        font-weight: 500;
        color: var(--card-text);
        box-shadow: var(--card-shadow);
    }
    .result-card span {
        font-size: 1.3rem;
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


def strip_html_tags(text):
    text = re.sub(r"<(script|style).*?>.*?</\1>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_eml_fields(uploaded_file, sender_email, subject, body):
    if uploaded_file is None:
        return sender_email, subject, body

    raw_bytes = uploaded_file.getvalue()
    if not raw_bytes:
        return sender_email, subject, body

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        parsed_subject = str(message.get("Subject", "")).strip() or subject
        parsed_sender_email = sender_email or parseaddr(str(message.get("From", "")))[1]
        parsed_body = body

        body_part = message.get_body(preferencelist=("plain", "html"))
        if body_part is not None:
            content = body_part.get_content()
            if body_part.get_content_type() == "text/html":
                parsed_body = strip_html_tags(str(content)) or parsed_body
            else:
                parsed_body = str(content).strip() or parsed_body
        elif message.is_multipart():
            parts = []
            for part in message.walk():
                if part.get_content_disposition() == "attachment":
                    continue
                if part.get_content_type() not in {"text/plain", "text/html"}:
                    continue

                content = str(part.get_content())
                if part.get_content_type() == "text/html":
                    content = strip_html_tags(content)
                else:
                    content = content.strip()

                if content:
                    parts.append(content)

            if parts:
                parsed_body = "\n\n".join(parts)
        else:
            content = str(message.get_content())
            if message.get_content_type() == "text/html":
                parsed_body = strip_html_tags(content) or parsed_body
            else:
                parsed_body = content.strip() or parsed_body

        return parsed_sender_email, parsed_subject, parsed_body
    except Exception:
        eml_text = raw_bytes.decode("utf-8", errors="ignore")

        subject_match = re.search(r"^Subject:\s*(.*)$", eml_text, re.MULTILINE)
        fallback_subject = subject_match.group(1).strip() if subject_match else subject

        fallback_sender = sender_email
        if not fallback_sender:
            from_match = re.search(
                r"^From:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}).*$",
                eml_text,
                re.MULTILINE | re.IGNORECASE,
            )
            if from_match:
                fallback_sender = from_match.group(1)

        plain_text_match = re.search(
            r"Content-Type:\s*text/plain.*?(\r?\n\r?\n)(.*?)(?=\r?\n--|$)",
            eml_text,
            re.IGNORECASE | re.DOTALL,
        )
        if plain_text_match:
            fallback_body = plain_text_match.group(2).replace("=\r\n", "").replace("=3D", "=").strip()
        else:
            split_parts = re.split(r"\r?\n\r?\n", eml_text)
            fallback_body = "\n\n".join(split_parts[1:]).strip() if len(split_parts) > 1 else body

        return fallback_sender, fallback_subject, fallback_body


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

sender_email, subject, body = extract_eml_fields(uploaded_file, sender_email, subject, body)
            
# ===== Step 2: Analysis Results =====
if submitted:
    if not subject and not body and not url:
        st.error("⚠️ Please provide either subject/body, URL, or upload an email file.")
    else:
        try:
            # Call unified backend
            #slide 3
            response = requests.post(
                BACKEND_URL,
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
                    url_status = data.get("urlStatus", [])[i] if i < len(data.get("urlStatus", [])) else ""
                    safe = data.get("urlCheck", [])[i] if i < len(data.get("urlCheck", [])) else False

                    if url_status == "trusted" or safe:
                        status = "Safe ✅"
                    elif url_status == "unlisted":
                        status = "Valid but unlisted ⚪"
                    else:
                        status = "Suspicious ❌"
                    st.markdown(f"- {u} → {status}")

                    if i < len(data.get("editCheck", [])):
                        dist, closest = data["editCheck"][i]
                        if closest and dist <= 2 and dist != 0:
                            st.markdown(f"   ↳ Closest Trusted: {closest} (distance {dist})")
            else:
                st.markdown("✅ No URLs found")

        except Exception as e:
            st.error(f"❌ Error connecting to backend: {e}")
