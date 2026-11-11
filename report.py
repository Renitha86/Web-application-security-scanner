from datetime import datetime
from pathlib import Path
from html import escape

from colorama import Fore, Style, init

init(autoreset=True)


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# Qualitative CVSS-style scores.
# These are lab-oriented severity estimates, not official CVSS calculations.
SEVERITY_SCORES = {
    "critical": "9.0",
    "high": "8.0",
    "medium": "5.3",
    "low": "3.1",
    "info": "0.0",
}

REMEDIATIONS = {
    "Missing CSP — increases XSS impact":
        "Implement a restrictive Content-Security-Policy appropriate for the application.",

    "Missing HSTS — allows protocol downgrade":
        "Enable Strict-Transport-Security after confirming the application is fully served over HTTPS.",

    "Accessible path discovered":
        "Review the discovered resource and restrict or remove it if it exposes unnecessary information.",

    "Cookie missing HttpOnly flag":
        "Set the HttpOnly attribute on sensitive session cookies to reduce client-side script access.",

    "Cookie missing Secure flag":
        "Set the Secure attribute on sensitive cookies so they are transmitted only over HTTPS.",

    "Server banner disclosure":
        "Remove or minimize unnecessary server version information from HTTP response headers.",

    "Technology disclosure":
        "Remove unnecessary X-Powered-By or technology-identifying response headers.",

    "Directory listing enabled":
        "Disable directory indexing unless it is explicitly required.",

    "Verbose error information disclosed":
        "Disable verbose/debug errors in production and return generic error responses.",

    "SQL Injection Indicator":
        "Use parameterized queries/prepared statements and validate server-side input.",

    "XSS Reflection Indicator":
        "Apply contextual output encoding and appropriate input validation. Deploy a restrictive CSP as defense in depth.",
}

def sort_findings(findings):
    return sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(
            finding.get("severity", "info").lower(),
            99
        )
    )


def get_severity_color(severity):
    severity = severity.lower()

    if severity == "critical":
        return Fore.RED + Style.BRIGHT

    if severity == "high":
        return Fore.RED

    if severity == "medium":
        return Fore.YELLOW

    if severity == "low":
        return Fore.CYAN

    return Fore.WHITE


def get_score(severity):
    return SEVERITY_SCORES.get(
        severity.lower(),
        "0.0"
    )

def get_remediation(finding):
    issue = (
        finding.get("issue")
        or finding.get("type")
        or "Unknown"
    )

    return REMEDIATIONS.get(
        issue,
        "Review the finding manually and apply appropriate security controls."
    )

def print_cli_report(findings, target):

    findings = sort_findings(findings)

    print("\n" + "=" * 100)
    print("WEB APPLICATION SECURITY SCAN REPORT")
    print("=" * 100)

    print(f"Target     : {target}")
    print(
        f"Scan time  : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    print(f"Findings   : {len(findings)}")

    print("=" * 100)

    if not findings:
        print(Fore.GREEN + "No findings detected.")
        print("=" * 100)
        return

    print(
        f"{'SEVERITY':<12}"
        f"{'SCORE':<8}"
        f"{'TYPE / ISSUE':<42}"
        f"{'LOCATION':<32}"
    )

    print("-" * 100)

    for finding in findings:

        severity = finding.get(
            "severity",
            "info"
        ).lower()

        issue = (
            finding.get("issue")
            or finding.get("type")
            or "Unknown"
        )

        location = (
            finding.get("url")
            or finding.get("parameter")
            or finding.get("header")
            or "-"
        )

        score = get_score(severity)
        remediation = get_remediation(finding)

        color = get_severity_color(severity)

        print(
            color
            + f"{severity.upper():<12}"
            f"{score:<8}"
            f"{issue[:40]:<42}"
            f"{str(location)[:30]:<32}"
            + Style.RESET_ALL
        )

    print("=" * 100)


def generate_html_report(findings, target, output_file):

    findings = sort_findings(findings)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    rows = ""

    for finding in findings:

        severity = finding.get(
            "severity",
            "info"
        ).lower()

        issue = (
            finding.get("issue")
            or finding.get("type")
            or "Unknown"
        )

        location = (
            finding.get("url")
            or finding.get("parameter")
            or finding.get("header")
            or "-"
        )

        evidence = (
            finding.get("evidence")
            or finding.get("payload")
            or finding.get("value")
            or "-"
        )

        score = get_score(severity)
        remediation = get_remediation(finding)
        rows += f"""
        <tr>
            <td>
                <span class="severity {escape(severity)}">
                    {escape(severity.upper())}
                </span>
            </td>

            <td>
                <strong>{escape(score)}</strong>
            </td>

            <td>{escape(str(issue))}</td>

            <td>
                <code>{escape(str(location))}</code>
            </td>

            <td>{escape(str(evidence))}</td>

            <td class="remediation">
    {escape(str(remediation))}
</td>
        </tr>
        """

    if not rows:

        rows = """
        <tr>
            <td colspan="6" class="no-findings">
                No findings detected.
            </td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
Web Application Security Scan Report
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    margin: 0;

    padding: 40px;

    background: #f4f6f8;

    color: #222;
}}

.container {{

    max-width: 1300px;

    margin: auto;

    background: white;

    padding: 35px;

    border-radius: 12px;

    box-shadow:
        0 4px 20px rgba(0,0,0,0.08);
}}

h1 {{

    margin-top: 0;

    margin-bottom: 8px;

    font-size: 30px;
}}

.subtitle {{

    color: #666;

    margin-bottom: 30px;
}}

.metadata {{

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 15px;

    margin-bottom: 30px;
}}

.card {{

    background: #f7f8fa;

    border: 1px solid #e2e5e8;

    border-radius: 8px;

    padding: 15px;
}}

.card-label {{

    display: block;

    font-size: 12px;

    color: #777;

    text-transform: uppercase;

    margin-bottom: 6px;
}}

.card-value {{

    font-weight: bold;

    word-break: break-word;
}}

table {{

    width: 100%;

    border-collapse: collapse;

    margin-top: 20px;
}}

th {{

    background: #202124;

    color: white;

    padding: 13px;

    text-align: left;
}}

td {{

    border-bottom:
        1px solid #ddd;

    padding: 13px;

    vertical-align: top;
}}

tr:nth-child(even) {{

    background: #fafafa;
}}

code {{

    font-family:
        Consolas,
        monospace;

    font-size: 13px;

    word-break: break-all;
}}

.remediation {{
    max-width: 350px;
    line-height: 1.5;
}}

.severity {{

    display: inline-block;

    padding: 5px 9px;

    border-radius: 5px;

    font-size: 12px;

    font-weight: bold;
}}

.severity.critical {{

    background: #7f1d1d;

    color: white;
}}

.severity.high {{

    background: #dc2626;

    color: white;
}}

.severity.medium {{

    background: #f59e0b;

    color: #111;
}}

.severity.low {{

    background: #0891b2;

    color: white;
}}

.severity.info {{

    background: #6b7280;

    color: white;
}}

.no-findings {{

    text-align: center;

    padding: 30px;

    color: #16803c;

    font-weight: bold;
}}

.footer {{

    margin-top: 30px;

    padding-top: 15px;

    border-top: 1px solid #ddd;

    color: #777;

    font-size: 12px;
}}

@media (max-width: 800px) {{

    body {{
        padding: 15px;
    }}

    .container {{
        padding: 20px;
    }}

    .metadata {{
        grid-template-columns: 1fr;
    }}

    table {{
        font-size: 13px;
    }}
}}

</style>

</head>

<body>

<div class="container">

    <h1>
        Web Application Security Scan Report
    </h1>

    <div class="subtitle">
        Controlled security assessment report
    </div>

    <div class="metadata">

        <div class="card">

            <span class="card-label">
                Target
            </span>

            <span class="card-value">
                {escape(target)}
            </span>

        </div>

        <div class="card">

            <span class="card-label">
                Scan Time
            </span>

            <span class="card-value">
                {timestamp}
            </span>

        </div>

        <div class="card">

            <span class="card-label">
                Total Findings
            </span>

            <span class="card-value">
                {len(findings)}
            </span>

        </div>

    </div>

    <table>

        <thead>

            <tr>

                <th>Severity</th>
<th>Score</th>
<th>Issue</th>
<th>Location</th>
<th>Evidence</th>
<th>Remediation</th>

            </tr>

        </thead>

        <tbody>

            {rows}

        </tbody>

    </table>

    <div class="footer">

        Qualitative CVSS-style scores are provided
        for prioritization within this controlled lab.
        They are not official CVSS calculations.

    </div>

</div>

</body>

</html>
"""

    output_path = Path(output_file)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path.write_text(
        html,
        encoding="utf-8"
    )

    return output_path