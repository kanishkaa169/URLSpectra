import ipaddress
from urllib.parse import urlparse
from risk_engine import RiskEngine, get_risk_level
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly"
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".online",
    ".site"
]

SUSPICIOUS_PATH_WORDS = [
    "signin",
    "verify",
    "confirm",
    "reset",
    "billing"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd"
]

SUSPICIOUS_REDIRECT_PARAMS = [
    "redirect",
    "url",
    "next",
    "return",
    "continue"
]

SENSITIVE_PARAMS = [
    "user",
    "username",
    "password",
    "pass",
    "email",
    "token"
]

SUSPICIOUS_PORTS = [
    21,
    22,
    23,
    25,
    110,
    143,
    445,
    3389
]


def analyze_url(url):
    engine = RiskEngine()
    risk_score = 0

    parsed = urlparse(url)
    
    if parsed.scheme not in ["http", "https"] or not parsed.hostname:
        print("⚠️ Invalid URL format")
        return 0, "INVALID"

    print("\n" + "=" * 50)
    print("PhishGuard - URL Analysis")
    print("=" * 50)

    print("\nAnalyzing URL:", url)

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    domain = hostname.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    print("\nScheme:", parsed.scheme)
    print("Domain:", parsed.netloc)
    print("Path:", parsed.path)

    # 1. HTTPS
    if parsed.scheme != "https":
        risk_score += add_warning(
            "URL is not using HTTPS",
            2
        )
    else:
        print("✅ HTTPS is enabled")

    # 2. IP address
    try:
        ipaddress.ip_address(hostname)
        risk_score += add_warning(
            "URL uses an IP address",
            2
        )
    except ValueError:
        print("🟩 Domain name detected")

    # 3. @ symbol
    if "@" in url:
        risk_score += add_warning(
            "URL contains @ symbol",
            1
        )
    else:
        print("🟩 No @ symbol detected")

    # 4. URL length
    if len(url) > 100:
        risk_score += add_warning(
            "URL is unusually long",
            1
        )
    else:
        print("🟩 URL length looks normal")

    # 5. Suspicious keywords
    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in url.lower()
    ]

    if found_words:
        print(
            "⚠️ Warning: Suspicious keywords detected:",
            found_words
        )
        risk_score += 1
    else:
        print("🟩 No suspicious keywords detected")

    # 6. URL shortener
    if any(shortener in domain for shortener in SHORTENERS):
        risk_score += add_warning(
            "URL uses a shortened link",
            2
        )
    else:
        print("🟩 No URL shortener detected")

    # 7. Subdomain analysis
    domain_parts = domain.split(".") if domain else []

    if len(domain_parts) > 3:
        risk_score += add_warning(
            "URL contains multiple subdomains",
            2
        )
    elif len(domain_parts) > 2:
        risk_score += add_warning(
            "URL contains a subdomain",
            1
        )
    else:
        print("🟩 Domain structure looks normal")

    # 8. Multiple hyphens
    if domain.count("-") >= 2:
        risk_score += add_warning(
            "Domain contains multiple hyphens",
            1
        )
    else:
        print("🟩 No excessive hyphens detected")

    # 9. Double slash in path
    if "//" in path:
        risk_score += add_warning(
            "URL path contains double slashes",
            1
        )
    else:
        print("🟩 No double slashes detected in URL path")

    # 10. URL encoding
    if "%" in url:
        risk_score += add_warning(
            "URL contains encoded characters",
            1
        )
    else:
        print("🟩 No URL encoding detected")

    # 11. Port analysis
    try:
        port = parsed.port

        if port and port not in [80, 443]:
            risk_score += add_warning(
                "URL uses a non-standard port",
                1
            )
        else:
            print("🟩 No non-standard port detected")

        if port in SUSPICIOUS_PORTS:
            risk_score += add_warning(
                f"Suspicious port number detected: {port}",
                1
            )

    except ValueError:
        risk_score += add_warning(
            "URL contains an invalid port",
            2
        )

    # 12. Domain length
    if len(domain) > 30:
        risk_score += add_warning(
            "Domain name is unusually long",
            1
        )
    else:
        print("🟩 Domain name length looks normal")

    # 13. Suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk_score += add_warning(
            "Suspicious top-level domain detected",
            1
        )
    else:
        print("🟩 No suspicious top-level domain detected")

    # 14. Suspicious redirect parameters
    found_redirect_params = []

    for parameter in query.split("&"):
        name = parameter.split("=", 1)[0]

        if name in SUSPICIOUS_REDIRECT_PARAMS:
            found_redirect_params.append(name)

    if found_redirect_params:
        print(
            "⚠️ Warning: Suspicious redirect parameters detected:",
            found_redirect_params
        )
        risk_score += 1
    else:
        print("🟩 No suspicious redirect parameters detected")

    # 15. Suspicious domain prefix
    suspicious_prefixes = [
        "secure-",
        "login-",
        "verify-",
        "account-"
    ]

    if any(domain.startswith(prefix) for prefix in suspicious_prefixes):
        risk_score += add_warning(
            "Suspicious domain prefix detected",
            1
        )
    else:
        print("🟩 No suspicious domain prefix detected")

    # 16. Punycode
    if "xn--" in domain:
        risk_score += add_warning(
            "Domain uses Punycode encoding",
            2
        )
    else:
        print("🟩 No Punycode encoding detected")

    # 17. Suspicious file extension
    if any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        risk_score += add_warning(
            "Suspicious file extension detected",
            2
        )
    else:
        print("🟩 No suspicious file extension detected")

    # 18. Suspicious path words
    found_path_words = [
        word for word in SUSPICIOUS_PATH_WORDS
        if word in path
    ]

    if found_path_words:
        print(
            "⚠️ Warning: Suspicious path keywords detected:",
            found_path_words
        )
        risk_score += 1
    else:
        print("🟩 No suspicious path keywords detected")

    # 19. Suspicious characters
    suspicious_chars = [
        "<",
        ">",
        "{",
        "}",
        "[",
        "]",
        "\\"
    ]

    found_chars = [
        char for char in suspicious_chars
        if char in url
    ]

    if found_chars:
        print(
            "⚠️ Warning: Suspicious special characters detected:",
            found_chars
        )
        risk_score += 1
    else:
        print("🟩 No suspicious special characters detected")

    # 20. Consecutive dots
    if ".." in domain:
        risk_score += add_warning(
            "Domain contains consecutive dots",
            1
        )
    else:
        print("🟩 No consecutive dots detected")

    # 21. Non-ASCII domain
    if any(ord(char) > 127 for char in domain):
        risk_score += add_warning(
            "Domain contains non-ASCII characters",
            2
        )
    else:
        print("🟩 No non-ASCII characters detected")

    # 22. Fragment
    if parsed.fragment:
        risk_score += add_warning(
            "URL contains a fragment",
            1
        )
    else:
        print("🟩 No URL fragment detected")

    # 23. Embedded username/password
    if parsed.username or parsed.password:
        print("⚠️ Warning: URL contains embedded user information")
    else:
        print("🟩 No embedded user information detected")
   
    # 24. Query parameters
    query_parameters = (
        parsed.query.split("&")
        if parsed.query
        else []
    )

    if len(query_parameters) >= 4:
        risk_score += add_warning(
            "URL contains many query parameters",
            1
        )
    else:
        print("🟩 Query parameter count looks normal")

    # 25. Empty query parameters
    empty_parameters = [
        parameter
        for parameter in query_parameters
        if "=" in parameter
        and parameter.split("=", 1)[1] == ""
    ]

    if empty_parameters:
        print(
            "⚠️ Warning: URL contains empty query parameters:",
            empty_parameters
        )
        risk_score += 1
    else:
        print("🟩 No empty query parameters detected")

    # 26. Sensitive query parameters
    found_sensitive_params = []

    for parameter in query_parameters:
        name = parameter.split("=", 1)[0]

        if name in SENSITIVE_PARAMS:
            found_sensitive_params.append(name)

    if found_sensitive_params:
        print(
            "⚠️ Warning: Sensitive query parameters detected:",
            found_sensitive_params
        )
        risk_score += 1
    else:
        print("🟩 No sensitive query parameters detected")

    # 27. Query length
    if len(parsed.query) > 100:
        risk_score += add_warning(
            "Query string is unusually long",
            1
        )
    else:
        print("🟩 Query string length looks normal")

    # 28. Path length
    if len(parsed.path) > 50:
        risk_score += add_warning(
            "URL path is unusually long",
            1
        )
    else:
        print("🟩 URL path length looks normal")

    # 29. Many path segments
    path_segments = [
        segment
        for segment in parsed.path.split("/")
        if segment
    ]

    if len(path_segments) >= 6:
        risk_score += add_warning(
            "URL contains many path segments",
            1
        )
    else:
        print("🟩 URL path structure looks normal")

    # 30. Numeric-only subdomain
    subdomain_parts = (
        domain_parts[:-2]
        if len(domain_parts) > 2
        else []
    )

    if any(part.isdigit() for part in subdomain_parts):
        risk_score += add_warning(
            "Numeric-only subdomain detected",
            1
        )
    else:
        print("🟩 No numeric-only subdomain detected")

    # 31. Repeated domain words
    domain_words = (
        domain.replace("-", ".").split(".")
    )

    repeated_words = []

    for word in set(domain_words):
        if word and domain_words.count(word) >= 2:
            repeated_words.append(word)

    if repeated_words:
        print(
            "⚠️ Warning: Repeated words detected in domain:",
            repeated_words
        )
        risk_score += 1
    else:
        print("🟩 No repeated domain words detected")

    # 32. Repeated suspicious keywords
    repeated_keywords = {}

    for word in SUSPICIOUS_WORDS:
        count = url.lower().count(word)

        if count >= 2:
            repeated_keywords[word] = count

    if repeated_keywords:
        print(
            "⚠️ Warning: Repeated suspicious keywords detected:",
            repeated_keywords
        )
        risk_score += 1
    else:
        print("🟩 No repeated suspicious keywords detected")

    # 33. Domain digit ratio
    letters = sum(char.isalpha() for char in domain)
    digits = sum(char.isdigit() for char in domain)

    if digits > letters:
        risk_score += add_warning(
            "Domain contains more digits than letters",
            1
        )
    else:
        print("🟩 Domain has a normal letter-to-digit ratio")

    # Final result
    print("\n" + "=" * 50)
    print("Risk Score:", risk_score)

    risk_level = get_risk_level(risk_score)

    if risk_level == "LOW":
        print("🟢 Risk Level: LOW")
    elif risk_level == "MEDIUM":
        print("🟡 Risk Level: MEDIUM")
    else:
        print("🔴 Risk Level: HIGH")

    print("=" * 50)
    return risk_score, risk_level


    if __name__ == "__main__":
        url = input("\nEnter a URL: ")
        analyze_url(url)