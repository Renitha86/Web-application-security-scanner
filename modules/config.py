import requests


def check_server_headers(response):
    """
    Check whether the server reveals software/version information.
    """

    findings = []

    server = response.headers.get("Server")
    powered_by = response.headers.get("X-Powered-By")

    if server:
        findings.append({
            "severity": "low",
            "issue": "Server banner disclosure",
            "header": "Server",
            "value": server
        })

    if powered_by:
        findings.append({
            "severity": "low",
            "issue": "Technology disclosure",
            "header": "X-Powered-By",
            "value": powered_by
        })

    return findings


def check_directory_listing(url):
    """
    Check whether the response appears to contain
    a directory listing.
    """

    findings = []

    try:
        response = requests.get(
            url,
            timeout=5
        )

        if "Index of /" in response.text:
            findings.append({
                "severity": "medium",
                "issue": "Directory listing enabled",
                "url": url
            })

    except requests.RequestException:
        pass

    return findings


def check_verbose_errors(url):
    """
    Request a deliberately malformed path and look
    for common verbose error indicators.
    """

    findings = []

    malformed_url = url.rstrip("/") + "/__scanner_malformed_path_xyz123__"

    try:
        response = requests.get(
            malformed_url,
            timeout=5
        )

        error_indicators = [
            "stack trace",
            "traceback",
            "at /",
            "exception",
            "file path"
        ]

        response_text = response.text.lower()

        for indicator in error_indicators:

            if indicator in response_text:
                findings.append({
                    "severity": "medium",
                    "issue": "Verbose error information disclosed",
                    "indicator": indicator,
                    "url": malformed_url
                })
                break

    except requests.RequestException:
        pass

    return findings


def check_configuration(url):
    """
    Run all configuration weakness checks.
    """

    findings = []

    try:
        response = requests.get(
            url,
            timeout=5
        )

        findings.extend(
            check_server_headers(response)
        )

    except requests.RequestException:
        return findings

    findings.extend(
        check_directory_listing(url)
    )

    findings.extend(
        check_verbose_errors(url)
    )

    return findings