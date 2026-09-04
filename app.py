from flask import Flask, jsonify, request, render_template
from datetime import datetime
from url_analyzer import analyze_url
from attack_intent import detect_attack_intent

app = Flask(__name__)
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    url = data.get("url", "").strip() if data else ""

    if not url:
        return jsonify({
            "error": "URL is required"
        }), 400

    risk_score, risk_level = analyze_url(url)
    attack_intents = detect_attack_intent(url)

    return jsonify({
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "attack_intents": attack_intents,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")

          })


if __name__ == "__main__":
    app.run(debug=True)