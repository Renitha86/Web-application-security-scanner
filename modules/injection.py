import requests
from bs4 import BeautifulSoup


SQLI_PROBES = [
    "'",
    "' OR '1'='1",
    "' -- "
]

XSS_PROBES = [
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>"
]


SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "sqlite3.operationalerror"
]


def discover_forms(url):
    """
    Find HTML forms and their input parameters.
    """

    forms = []

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):

            action = form.get("action") or url
            method = form.get("method", "get").lower()

            inputs = []

            for field in form.find_all("input"):
                name = field.get("name")

                if name:
                    inputs.append(name)

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

    except requests.RequestException:
        pass

    return forms


def sql_error_indicator(response):
    """
    Detect common database error signatures.
    """

    response_text = response.text.lower()

    return any(
        signature in response_text
        for signature in SQL_ERROR_SIGNATURES
    )


def xss_reflection_indicator(response, payload):
    """
    Detect whether the exact test payload is reflected.
    """

    return payload in response.text


def test_parameter(url, parameter):
    """
    Test one parameter with safe SQLi and XSS indicators.
    """

    findings = []

    # SQL injection indicators
    for payload in SQLI_PROBES:

        try:
            response = requests.get(
                url,
                params={parameter: payload},
                timeout=5
            )

            if sql_error_indicator(response):

                findings.append({
                    "type": "SQL Injection Indicator",
                    "parameter": parameter,
                    "payload": payload,
                    "severity": "high",
                    "evidence": "Database error signature detected"
                })

        except requests.RequestException:
            continue

    # XSS reflection indicators
    for payload in XSS_PROBES:

        try:
            response = requests.get(
                url,
                params={parameter: payload},
                timeout=5
            )

            if xss_reflection_indicator(response, payload):

                findings.append({
                    "type": "XSS Reflection Indicator",
                    "parameter": parameter,
                    "payload": payload,
                    "severity": "high",
                    "evidence": "Test payload reflected in response"
                })

        except requests.RequestException:
            continue

    return findings