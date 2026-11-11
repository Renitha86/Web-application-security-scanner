import requests


REQUIRED_HEADERS = {
    "Content-Security-Policy": "Missing CSP — increases XSS impact",
    "Strict-Transport-Security": "Missing HSTS — allows protocol downgrade",
    "X-Content-Type-Options": "Missing nosniff — allows MIME sniffing attacks",
    "X-Frame-Options": "Missing — page can be framed (clickjacking risk)",
}


def check_headers(url):
    findings = []

    try:
        response = requests.get(url, timeout=5)

        for header, issue in REQUIRED_HEADERS.items():
            if header not in response.headers:
                findings.append({
                    "severity": "medium",
                    "issue": issue,
                    "header": header,
                })

        cookies = response.headers.get("Set-Cookie", "")

        if cookies and "HttpOnly" not in cookies:
            findings.append({
                "severity": "medium",
                "issue": "Cookie missing HttpOnly flag",
            })

        if cookies and "Secure" not in cookies:
            findings.append({
                "severity": "low",
                "issue": "Cookie missing Secure flag",
            })

    except requests.RequestException as error:
        findings.append({
            "severity": "high",
            "issue": f"Unable to connect to target: {error}",
        })

    return findings