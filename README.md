# BCSSL Project #08 — Web Application Security Scanner

## 1. Project Overview

This project implements a controlled Python-based Web Application Security Scanner for authorized targets.

The scanner is designed for use in a controlled lab environment such as OWASP Juice Shop or DVWA. It performs HTTP-based security checks and produces both a CLI report and a self-contained HTML report.

### Learning Objectives

The project demonstrates:

- HTTP request/response handling using Python `requests`
- Security header analysis
- Basic exposed-path discovery
- Safe SQL injection and XSS reflection indicators
- Configuration and information-disclosure checks
- Prioritized security reporting
- Manual verification using Burp Suite Community Edition

> **Authorized use only:** Run this scanner only against applications that you own or have explicit permission to test. For this project, testing was performed against a locally hosted OWASP Juice Shop instance.

---

## 2. Project Architecture

```text
                         +----------------------+
                         |      scanner.py      |
                         |    CLI / Controller  |
                         +----------+-----------+
                                    |
              +---------------------+---------------------+
              |                     |                     |
              v                     v                     v
      +---------------+     +---------------+     +---------------+
      | Header Check  |     | Path Discovery |     | Injection     |
      |   headers.py  |     |    paths.py   |     | injection.py  |
      +---------------+     +---------------+     +---------------+
              |                     |                     |
              +---------------------+---------------------+
                                    |
                                    v
                           +----------------+
                           | Config Check   |
                           |   config.py    |
                           +--------+-------+
                                    |
                                    v
                           +----------------+
                           |  report.py     |
                           | CLI + HTML     |
                           +----------------+
```

---

## 3. Scanner Modules

### Header Security Checks

Checks for the presence of important HTTP security headers:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`

It also checks cookie security attributes when cookies are present:

- `HttpOnly`
- `Secure`

### Path Discovery

Requests entries from a controlled wordlist and identifies potentially accessible resources based on HTTP responses such as:

- `200 OK`
- `301`
- `302`
- `403`

High-value paths such as configuration files, backup files, and administrative resources are treated with higher severity when discovered.

A soft-404 baseline is used to reduce false positives from single-page applications that return `200 OK` for arbitrary routes.

### Injection Indicators

The injection module performs safe indicator checks only.

SQL injection probes include:

```text
'
' OR '1'='1
' -- 
```

XSS reflection probes include:

```text
<script>alert(1)</script>
"><svg onload=alert(1)>
```

The scanner checks for database error signatures and exact reflection of test payloads.

No data extraction, privilege escalation, destructive actions, or write operations are performed.

### Configuration Weakness Checks

Checks include:

- `Server` banner disclosure
- `X-Powered-By` disclosure
- Directory listing indicators
- Verbose error information
- Stack-trace or file-path disclosure indicators

### Reporting Engine

The reporting engine:

- Aggregates findings from all selected modules
- Prioritizes findings by severity
- Assigns qualitative CVSS-style scores for lab prioritization
- Displays a colorized CLI report
- Generates a self-contained HTML report
- Includes evidence and remediation guidance

The qualitative scores are prioritization estimates and are not official CVSS calculations.

---

## 4. Requirements

### Software

- Python 3.10 or newer
- Docker Desktop
- OWASP Juice Shop or another authorized lab target
- Burp Suite Community Edition
- SecLists wordlists

### Python Packages

Install the required packages with:

```powershell
pip install requests beautifulsoup4 colorama jinja2
```

---

## 5. Lab Target Setup

OWASP Juice Shop was hosted locally using Docker.

Example:

```powershell
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

The target used for testing was:

```text
http://localhost:3000
```

Verify that the application is reachable:

```powershell
curl.exe -I http://localhost:3000
```

---

## 6. Project Structure

```text
websecurityscanner/
│
├── scanner.py
├── report.py
│
├── modules/
│   ├── headers.py
│   ├── paths.py
│   ├── injection.py
│   └── config.py
│
├── reports/
│   └── scan_report.html
│
├── wordlists/
│   └── lab_common.txt
│
└── README.md
```

---

## 7. Usage

Run all scanner modules:

```powershell
python scanner.py --url http://localhost:3000 --modules headers,paths,injection,config
```

Run an individual module:

```powershell
python scanner.py --url http://localhost:3000 --modules headers
```

```powershell
python scanner.py --url http://localhost:3000 --modules paths
```

```powershell
python scanner.py --url http://localhost:3000 --modules injection
```

```powershell
python scanner.py --url http://localhost:3000 --modules config
```

Specify a different path-discovery wordlist:

```powershell
python scanner.py --url http://localhost:3000 --modules paths --wordlist wordlists/lab_common.txt
```

---

## 8. Output

The scanner produces:

### CLI Report

The terminal report includes:

- Severity
- Qualitative score
- Issue
- Location

### HTML Report

The generated report is saved to:

```text
reports/scan_report.html
```

The HTML report includes:

- Target
- Scan timestamp
- Total findings
- Severity
- Qualitative score
- Issue
- Location
- Evidence
- Remediation

---

## 9. Example Lab Results

During testing against the local OWASP Juice Shop instance, the scanner identified:

### Missing Content-Security-Policy

```text
Severity: MEDIUM
Score: 5.3
Location: Content-Security-Policy
```

### Missing Strict-Transport-Security

```text
Severity: MEDIUM
Score: 5.3
Location: Strict-Transport-Security
```

### Accessible Path

```text
Severity: MEDIUM
Score: 5.3
Location: http://localhost:3000/.well-known/security.txt
```

The injection module did not report a finding during the tested homepage scan because no traditional HTML forms were discovered and no safe indicator was triggered.

The configuration module did not report a finding during the tested scan.

A lack of findings from a module does not by itself indicate that an application is secure.

---

## 10. Manual Verification with Burp Suite

Burp Suite Community Edition was used to manually verify scanner findings against the local Juice Shop instance.

### Verified Finding 1 — Missing CSP

The intercepted HTTP response contained headers such as:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
```

but did not contain:

```text
Content-Security-Policy
```

This manually verified the scanner's missing CSP finding.

### Verified Finding 2 — Missing HSTS

The intercepted HTTP response did not contain:

```text
Strict-Transport-Security
```

This manually verified the scanner's missing HSTS finding.

### Verified Finding 3 — Accessible security.txt

Burp HTTP history captured:

```text
GET /.well-known/security.txt
```

with:

```text
HTTP/1.1 200 OK
```

This manually verified that the discovered resource was accessible.

---

## 11. Safety and Ethics

This scanner is intended for authorized security testing and educational lab environments.

The scanner must not be used to:

- Scan systems without permission
- Extract sensitive data
- Perform destructive actions
- Modify production systems
- Escalate privileges
- Deploy malware
- Circumvent access controls

Injection testing uses non-destructive indicator probes only.

The recommended practice is to test against a deliberately vulnerable local application such as OWASP Juice Shop or DVWA.

---

## 12. Limitations

This is a controlled educational scanner rather than a replacement for a professional web application security testing platform.

Known limitations include:

- No authenticated scanning
- No full application crawler
- No complete API schema analysis
- No complete CVSS calculation engine
- Injection checks are indicator-based
- Single-page applications may require additional route discovery
- Path discovery depends on the supplied wordlist
- Findings require manual validation before being treated as confirmed vulnerabilities

---

## 13. Troubleshooting

### Target is unavailable

Check that the Juice Shop container is running:

```powershell
docker ps
```

Then verify:

```powershell
curl.exe -I http://localhost:3000
```

### Path scan produces excessive false positives

Single-page applications may return the same `200 OK` response for nonexistent routes. The scanner uses a soft-404 baseline to reduce this behavior.

Use a small controlled wordlist for lab testing rather than unnecessarily large scans.

### Injection module reports no findings

A clean result is possible. The target endpoint may not expose a vulnerable parameter or the safe indicator probes may not trigger a recognizable error/reflection.

### HTML report is not visible

After running the scanner, open:

```text
reports/scan_report.html
```

---

## 14. Deliverables

The completed project should contain:

- Scanner source code
- Header check module
- Path discovery module
- Injection indicator module
- Configuration weakness module
- Reporting engine
- CLI entry point
- HTML scan report
- Wordlist
- README
- CLI scan evidence
- Burp Suite manual verification evidence

---

## 15. Disclaimer

This project was developed for cybersecurity education and controlled testing.

All testing described in this README was performed against an authorized, locally hosted lab application.

Do not use the scanner against systems for which you do not have explicit authorization.
