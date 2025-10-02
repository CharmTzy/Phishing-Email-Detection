from flask import Flask, request, jsonify
from keyword_detection import keyword_score, find_keywords, highlight_keywords
from flask_cors import CORS
from url_detection import extract_urls, URLvalidator
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
        print("Received data:", data)
        # Run the main analysis function
        result = analyseEmails(data)
        print("Result:",result)
        print(jsonify(result))

        # Return results as JSON for frontend to render
        return jsonify(result)
    except Exception as e:
        # Return a safe default JSON in case of error
        return jsonify({
            "error": str(e),
            "final_label": "Error",         # error fallback
            "overall_score": 0,             # default score
            "spam_votes": 0,                # no checks passed
            "keyword_score": 0,
            "keyword_label": "Error",
            "keywords": [],
            "subject_highlighted": "",
            "body_highlighted": "",
            "urls": [],
            "urlCheck": [],
            "editCheck": []
        }) #, 500

  
if __name__ == '__main__':
    app.run(debug=True)
