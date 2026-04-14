import os

from flask import Flask, request, jsonify
from flask_cors import CORS
from all_checks import analyseEmails

app = Flask(__name__)
CORS(app)

@app.route('/analyse_email', methods=['POST'])
def analyse_email_api():
    """
    Unified API endpoint that analyses an email for phishing risk.
    Runs all checks (keywords, highlighting, URL validation, edit distance)
    and returns a single combined JSON result.
    """
    try:
        # Get JSON input from frontend (subject, body, url)
        data = request.get_json() or {}
        # Run the main analysis function
        result = analyseEmails(data)

        # Return results as JSON for frontend to render
        return jsonify(result)
    except Exception as e:
        # Return a safe default JSON in case of error
        return jsonify({
            "error": str(e),
            "final_label": "Error",
            "email_data": {},
            "overall_score": 0,             # default score
            "risk_level": "Unknown",
            "spam_votes": 0,                # no checks passed
            "keyword_score": 0,
            "keyword_label": "Error",
            "keywords": [],
            "subject_highlighted": "",
            "body_highlighted": "",
            "urls": [],
            "urlCheck": [],
            "editCheck": [],
            "model_prediction": "Error",
            "model_probability": 0,
            "model_score": 0,
            "model_confidence": 0,
            "model_indicators": [],
            "model_metrics": {},
            "model_trained_at": "",
            "model_name": "",
            "checks_breakdown": [],
            "reasons": [],
            "verdict_message": ""
        }) #, 500

  
if __name__ == '__main__':
    app.run(
        host=os.getenv("BACKEND_HOST", "127.0.0.1"),
        port=int(os.getenv("BACKEND_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1",
    )
