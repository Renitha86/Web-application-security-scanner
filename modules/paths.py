import requests


# Paths that should receive higher severity if actually discovered
HIGH_VALUE_PATHS = {
    "admin",
    ".env",
    ".git/config",
    "backup.zip",
    "config.php.bak",
}


def get_baseline(base_url):
    """
    Request a path that should not exist.
    This helps detect soft-404 responses from single-page applications.
    """

    fake_path = "__scanner_nonexistent_path_xyz123__"
    url = f"{base_url.rstrip('/')}/{fake_path}"

    try:
        response = requests.get(
            url,
            timeout=2,
            allow_redirects=False
        )

        return {
            "status": response.status_code,
            "length": len(response.text)
        }

    except requests.RequestException:
        return None


def check_path(base_url, path, baseline):
    """
    Check one path and return a finding if it appears to be accessible.
    """

    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    try:
        response = requests.get(
            url,
            timeout=2,
            allow_redirects=False
        )

        # Only consider interesting HTTP responses
        if response.status_code not in (200, 301, 302, 403):
            return None

        # Ignore SPA soft-404 responses
        if (
            response.status_code == 200
            and baseline
            and baseline["status"] == 200
            and abs(len(response.text) - baseline["length"]) < 100
        ):
            return None

        path_name = path.lstrip("/").lower()

        # Assign severity
        if path_name in HIGH_VALUE_PATHS:
            severity = "high"
        else:
            severity = "medium"

        return {
    "severity": severity,
    "issue": "Accessible path discovered",
    "url": url,
    "status": response.status_code,
    "length": len(response.text),
}

    except requests.RequestException:
        return None


def discover_paths(base_url, wordlist):
    """
    Scan all paths in the supplied wordlist.

    Requests are performed sequentially to keep the scanner
    lightweight and stable on the lab machine.
    """

    results = []

    # Establish the baseline before scanning
    baseline = get_baseline(base_url)

    if baseline is None:
        print("Could not establish baseline response.")
        return results

    for path in wordlist:

        # Ignore empty lines
        path = path.strip()

        if not path:
            continue

        result = check_path(
            base_url,
            path,
            baseline
        )

        if result:
            results.append(result)

    return results