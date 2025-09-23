from flask import Flask, request, jsonify
from keyword_detection import keyword_score, find_keywords, highlight_keywords
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/detect_keywords', methods=['POST'])
def detect_keywords_api():
    data = request.get_json()
    subject = data.get('subject', '')
    body = data.get('body', '')
    score = keyword_score(subject, body)
    label = "Phishing" if score >= 5 else "Safe"
    subject_highlighted = highlight_keywords(subject)
    body_highlighted = highlight_keywords(body)
    keywords = sorted(set(find_keywords(subject) + find_keywords(body)))
    return jsonify({
        "score": score,
        "label": label,
        "keywords": keywords,
        "subject_highlighted": subject_highlighted,
        "body_highlighted": body_highlighted
    })

if __name__ == '__main__':
    app.run(debug=True)