from flask import Flask, request, jsonify
from keyword_detection import keyword_score, find_keywords, highlight_keywords
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/detect_keywords', methods=['POST'])
def detect_keywords_api():
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        body = data.get('body', '')
        
        # Calculate the risk score
        score = keyword_score(subject, body)
        
        # Determine label based on score threshold
        label = "Phishing" if score >= 50 else "Safe"
        
        # Get highlighted text for display
        subject_highlighted = highlight_keywords(subject)
        body_highlighted = highlight_keywords(body)
        
        # Get all keywords found in both subject and body
        keywords = sorted(set(find_keywords(subject) + find_keywords(body)))
        
        return jsonify({
            "score": score,
            "label": label,
            "keywords": keywords,
            "subject_highlighted": subject_highlighted,
            "body_highlighted": body_highlighted
        })
    
    except Exception as e:
        return jsonify({
            "error": str(e),
            "score": 0,
            "label": "Error",
            "keywords": [],
            "subject_highlighted": "",
            "body_highlighted": ""
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
