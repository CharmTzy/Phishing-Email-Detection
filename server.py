from flask import Flask, request, jsonify
from keyword_detection import keyword_score
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
    return jsonify({"score": score, "label": label})

if __name__ == '__main__':
    app.run(debug=True)