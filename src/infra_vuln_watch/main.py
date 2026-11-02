"""infra-vuln-watch: check the inventory against NVD and open issues for new CVEs.

Run these from the top folder of the repo.
Run it with:        python -m infra_vuln_watch
Try it safely with: python -m infra_vuln_watch --dry-run
"""

import argparse
import os

import requests

from infra_vuln_watch import cve_details, github_client, issue_format, nvd_client
from infra_vuln_watch.inventory import load_inventory
from infra_vuln_watch.version_check import NOT_AFFECTED, UNKNOWN, check_version


def find_problems(item):
    """Return a list of (cve, result) for every CVE we should report for this item."""
    problems = []
    for cve in nvd_client.fetch_cves(item):
        if cve.get("vulnStatus") == "Rejected":
            continue
        result = check_version(cve, item["vendor"], item["product"], item["version"])
        if result["status"] != NOT_AFFECTED:
            problems.append((cve, result))
    return problems


def report(item, cve, result, github, reported_ids):
    """Open an issue for one CVE, or print it during a dry run."""
    marker_id = f"{item['name']}/{cve['id']}"
    if marker_id in reported_ids:
        print(f"  Already reported: {cve['id']}")
        return

    title = issue_format.make_title(item, cve)
    if github is None:
        print(f"  [dry run] {title}")
        return

    severity = cve_details.get_score(cve)["severity"]
    labels = [
        github_client.MAIN_LABEL,
        github_client.severity_label(severity),
        github_client.tool_label(item["name"]),
    ]
    if result["status"] == UNKNOWN:
        labels.append(github_client.REVIEW_LABEL)

    url = github.create_issue(title, issue_format.make_body(item, cve, result), labels)
    reported_ids.add(marker_id)
    print(f"  Opened {url}")


def main():
    parser = argparse.ArgumentParser(description="Check the inventory for known CVEs.")
    parser.add_argument("--inventory", default="inventory", help="directory of YAML files")
    parser.add_argument("--dry-run", action="store_true", help="print findings, do not open issues")
    args = parser.parse_args()

    # Read the inventory first, so a typo fails before anything else happens.
    try:
        items = load_inventory(args.inventory)
    except ValueError as error:
        print(f"Inventory problem: {error}")
        return 1

    github = None
    reported_ids = set()
    if not args.dry_run:
        token = os.environ.get("GITHUB_TOKEN")
        repository = os.environ.get("GITHUB_REPOSITORY")
        if not token or not repository:
            print("GITHUB_TOKEN and GITHUB_REPOSITORY must be set. Use --dry-run to skip issues.")
            return 1
        github = github_client.GitHubClient(token, repository)
        try:
            github.create_missing_labels([item["name"] for item in items])
            reported_ids = github.get_reported_ids()
        except requests.RequestException as error:
            print(f"Could not read from GitHub: {error}")
            return 1

    # One failing item should not stop the others from being checked. The run
    # still fails at the end, so a broken check never looks like "no CVEs found".
    failed = []
    for item in items:
        print(f"Checking {item['name']} {item['version']}")
        try:
            problems = find_problems(item)
            print(f"  Found {len(problems)} CVE(s) to report")
            for cve, result in problems:
                report(item, cve, result, github, reported_ids)
        except requests.RequestException as error:
            print(f"  FAILED: {error}")
            failed.append(item["name"])

    if failed:
        print(f"Could not finish checking: {', '.join(failed)}")
        return 1
    return 0

