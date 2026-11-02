"""Create and list issues in this GitHub repository."""

import re
import time

import requests

API_URL = "https://api.github.com"
MAIN_LABEL = "vuln-watch"
REVIEW_LABEL = "needs-review"
SEVERITY_LABELS = {
    "critical": "b60205",
    "high": "d93f0b",
    "medium": "fbca04",
    "low": "0e8a16",
    "none": "c5def5",
    "unknown": "bfd4f2",
}

# GitHub blocks accounts that create many issues too quickly.
WAIT_AFTER_CREATE_SECONDS = 3


def severity_label(severity):
    return f"severity-{severity}"


class GitHubClient:
    def __init__(self, token, repository):
        self.repo_url = f"{API_URL}/repos/{repository}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }

    def get_all_pages(self, path, params):
        """Download every page of a GitHub list."""
        results = []
        page = 1
        while True:
            response = requests.get(
                f"{self.repo_url}/{path}",
                headers=self.headers,
                params={**params, "per_page": 100, "page": page},
                timeout=30,
            )
            response.raise_for_status()
            page_results = response.json()
            results.extend(page_results)
            if len(page_results) < 100:
                return results
            page += 1

    def create_missing_labels(self):
        """Create our labels the first time the tool runs."""
        existing = {label["name"] for label in self.get_all_pages("labels", {})}

        wanted = {MAIN_LABEL: "5319e7", REVIEW_LABEL: "e99695"}
        for severity, color in SEVERITY_LABELS.items():
            wanted[severity_label(severity)] = color

        for name, color in wanted.items():
            if name not in existing:
                response = requests.post(
                    f"{self.repo_url}/labels",
                    headers=self.headers,
                    json={"name": name, "color": color},
                    timeout=30,
                )
                response.raise_for_status()

    def get_reported_ids(self):
        """Return the ids of everything already reported, including closed issues.

        We only trust issues with our label. In a public repo anyone can open an
        issue, but only people with write access can label it. Without this check,
        a stranger could copy our marker and stop a real CVE from being reported.
        """
        issues = self.get_all_pages("issues", {"state": "all", "labels": MAIN_LABEL})
        reported = set()
        for issue in issues:
            reported.update(re.findall(r"<!-- vuln-watch-id: (\S+) -->", issue.get("body") or ""))
        return reported

    def create_issue(self, title, body, labels):
        """Open one issue and return its web address."""
        response = requests.post(
            f"{self.repo_url}/issues",
            headers=self.headers,
            json={"title": title[:256], "body": body, "labels": labels},
            timeout=30,
        )
        response.raise_for_status()
        time.sleep(WAIT_AFTER_CREATE_SECONDS)
        return response.json()["html_url"]
