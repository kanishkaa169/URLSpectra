# URLSpectra 🔐

URLSpectra is a simple cybersecurity project that analyzes URLs and checks for common suspicious patterns.

The idea behind this project is to make URL analysis easier to understand. Instead of just giving a result, URLSpectra looks at different parts of a URL, calculates a risk score, and gives a risk level based on the indicators it finds.

## What does URLSpectra do?

URLSpectra analyzes a URL and checks for things such as:

- Suspicious keywords
- IP addresses used as domains
- URL shorteners
- Unusual ports
- Suspicious domain structures
- Multiple subdomains
- Suspicious redirects
- URL encoding
- Suspicious file extensions
- Query parameters
- Other unusual URL patterns

It also checks for possible attack intent based on the patterns found in the URL.

## Features

- 🔎 URL pattern analysis
- 🛡️ Risk score calculation
- 🟢 LOW / 🟡 MEDIUM / 🔴 HIGH risk levels
- 🎯 Attack intent detection
- 🌐 Flask-based web application
- 💻 Simple web interface
- ⚠️ Empty and invalid input handling
- 📊 Easy-to-understand analysis results

## Tech Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- Git & GitHub

## How to Run

### 1. Clone the repository

    git clone https://github.com/kanishkaa169/URLSpectra.git
    cd URLSpectra

### 2. Install the required packages

    pip install -r requirements.txt

### 3. Start the application

    python app.py

### 4. Open it in your browser

    http://127.0.0.1:5000

## How to Use

1. Open URLSpectra in the browser.
2. Enter the URL you want to analyze.
3. Click Analyze URL.
4. The application checks the URL for suspicious patterns.
5. The risk score and risk level are displayed.
6. If applicable, potential attack intent is also shown.

## Testing

The current version has been tested with:

- ✅ Low-risk URLs
- ✅ Medium-risk URLs
- ✅ High-risk URLs
- ✅ Attack intent detection
- ✅ Empty input
- ✅ Invalid input
- ✅ Flask API responses

## Project Structure

    URLSpectra/
    ├── app.py
    ├── url_analyzer.py
    ├── risk_engine.py
    ├── attack_intent.py
    ├── requirements.txt
    ├── README.md
    ├── .gitignore
    ├── static/
    │   └── style.css
    └── templates/
        └── index.html

## Note

URLSpectra is mainly built as a learning and portfolio project to explore URL analysis and basic cybersecurity concepts.

The result should not be considered a guaranteed indication that a URL is safe or malicious.

## Project

Built as a hands-on cybersecurity project using Python and Flask.

**URLSpectra — Analyze. Understand. Stay Aware. 🔐**