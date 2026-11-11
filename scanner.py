import argparse
from pathlib import Path
from urllib.parse import urljoin

from modules.headers import check_headers
from modules.paths import discover_paths
from modules.injection import discover_forms, test_parameter
from modules.config import check_configuration
from report import print_cli_report, generate_html_report


def load_wordlist(wordlist_path):
    path = Path(wordlist_path)

    if not path.exists():
        print(f"Wordlist not found: {wordlist_path}")
        return []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        return [line.strip() for line in file if line.strip()]


def run_headers(target):
    print("\n[+] Running header security checks...")
    return check_headers(target)


def run_paths(target, wordlist_path):
    print("\n[+] Running path discovery...")

    wordlist = load_wordlist(wordlist_path)

    if not wordlist:
        return []

    print(f"[+] Loaded {len(wordlist)} paths")

    return discover_paths(target, wordlist)


def run_injection(target):
    print("\n[+] Running injection indicator checks...")

    findings = []

    forms = discover_forms(target)

    print(f"[+] Forms discovered: {len(forms)}")

    for form in forms:
        action = urljoin(target, form["action"])
        method = form["method"]

        print(f"[+] Testing form: {action}")

        # The current injection module uses GET requests.
        # Skip non-GET forms to keep the lab scanner safe.
        if method != "get":
            continue

        for parameter in form["inputs"]:
            results = test_parameter(action, parameter)
            findings.extend(results)

    return findings


def run_config(target):
    print("\n[+] Running configuration weakness checks...")
    return check_configuration(target)


def main():
    parser = argparse.ArgumentParser(
        description="Controlled Web Application Security Scanner"
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Authorized target URL"
    )

    parser.add_argument(
        "--modules",
        default="headers,paths,injection,config",
        help="Comma-separated modules to run"
    )

    parser.add_argument(
        "--wordlist",
        default="wordlists/lab_common.txt",
        help="Path discovery wordlist"
    )

    args = parser.parse_args()

    target = args.url.rstrip("/")
    selected_modules = [
        module.strip().lower()
        for module in args.modules.split(",")
    ]

    print("=" * 80)
    print("WEB APPLICATION SECURITY SCANNER")
    print("=" * 80)
    print(f"Target  : {target}")
    print(f"Modules : {', '.join(selected_modules)}")
    print("=" * 80)

    all_findings = []

    # --------------------------------------------------
    # HEADER CHECK
    # --------------------------------------------------

    if "headers" in selected_modules:
        findings = run_headers(target)
        all_findings.extend(findings)

        print(f"[+] Header findings: {len(findings)}")

    # --------------------------------------------------
    # PATH DISCOVERY
    # --------------------------------------------------

    if "paths" in selected_modules:
        findings = run_paths(target, args.wordlist)
        all_findings.extend(findings)

        print(f"[+] Path findings: {len(findings)}")

    # --------------------------------------------------
    # INJECTION INDICATORS
    # --------------------------------------------------

    if "injection" in selected_modules:
        findings = run_injection(target)
        all_findings.extend(findings)

        print(f"[+] Injection findings: {len(findings)}")

    # --------------------------------------------------
    # CONFIGURATION CHECK
    # --------------------------------------------------

    if "config" in selected_modules:
        findings = run_config(target)
        all_findings.extend(findings)

        print(f"[+] Configuration findings: {len(findings)}")

    # --------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------

    print_cli_report(all_findings, target)

    report_file = "reports/scan_report.html"

    generate_html_report(
        all_findings,
        target,
        report_file
    )

    print("\n[+] HTML report generated:")
    print(f"    {report_file}")

    print("\n[+] Scan completed.")


if __name__ == "__main__":
    main()