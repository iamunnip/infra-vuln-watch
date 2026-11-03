"""Create and list issues in this GitHub repository."""

import time

import requests

from infra_vuln_watch.configuration.config import DEFAULT_CONFIG
from infra_vuln_watch.domain.identity import MARKER_PATTERN

MAIN_LABEL = "vuln-watch"
REVIEW_LABEL = "needs-review"
KNOWN_EXPLOITED_LABEL = "known-exploited"
TOOL_LABEL_COLOR = "1d76db"
SEVERITY_LABELS = {
    "critical": "b60205",
    "high": "d93f0b",
    "medium": "fbca04",
    "low": "0e8a16",
    "unknown": "bfd4f2",
}


def severity_label(severity):
    return f"severity-{severity}"


def tool_label(name):
    return f"tool-{name}"


def deployment_label(identifier):
    return f"deployment-{identifier}"


class GitHubClient:
    def __init__(self, token, repository, config=None):
        self.config = config or DEFAULT_CONFIG["outputs"]["github"]
        self.repo_url = f"{self.config['api_url'].rstrip('/')}/repos/{repository}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }
        self.reported_links = {}

    def get_all_pages(self, path, params):
        """Download every page of a GitHub list."""
        results = []
        page = 1
        while True:
            response = requests.get(
                f"{self.repo_url}/{path}",
                headers=self.headers,
                params={**params, "per_page": 100, "page": page},
                timeout=self.config["timeout"],
            )
            response.raise_for_status()
            page_results = response.json()
            if not isinstance(page_results, list) or any(not isinstance(row, dict) for row in page_results):
                raise requests.RequestException("GitHub returned an invalid list response")
            results.extend(page_results)
            if len(page_results) < 100:
                return results
            page += 1

    def create_missing_labels(self, tool_names, deployment_ids=()):
        """Create any of our labels that do not exist yet."""
        # GitHub label names ignore case, so "Prod" and "prod" are the same label.
        existing = {label["name"].casefold() for label in self.get_all_pages("labels", {})}

        wanted = {MAIN_LABEL: "5319e7", REVIEW_LABEL: "e99695", KNOWN_EXPLOITED_LABEL: "b60205"}
        for severity, color in SEVERITY_LABELS.items():
            wanted[severity_label(severity)] = color
        for name in tool_names:
            wanted[tool_label(name)] = TOOL_LABEL_COLOR
        for identifier in deployment_ids:
            wanted[deployment_label(identifier)] = TOOL_LABEL_COLOR

        for name, color in wanted.items():
            if name.casefold() not in existing:
                response = requests.post(
                    f"{self.repo_url}/labels",
                    headers=self.headers,
                    json={"name": name, "color": color},
                    timeout=self.config["timeout"],
                )
                response.raise_for_status()
                existing.add(name.casefold())

    def get_reported_ids(self):
        """Return the ids of everything already reported, including closed issues.

        We only trust issues with our label. In a public repo anyone can open an
        issue, but only people with write access can label it. Without this check,
        a stranger could copy our marker and stop a real CVE from being reported.
        """
        issues = self.get_all_pages("issues", {"state": "all", "labels": MAIN_LABEL})
        reported = set()
        for issue in issues:
            for marker in MARKER_PATTERN.findall(issue.get("body") or ""):
                reported.add(marker)
                if issue.get("html_url"):
                    self.reported_links[marker] = issue["html_url"]
        return reported

    def create_issue(self, title, body, labels):
        """Open one issue and return its web address."""
        time.sleep(self.config["create_wait"])
        response = requests.post(
            f"{self.repo_url}/issues",
            headers=self.headers,
            json={"title": title[:256], "body": body, "labels": labels},
            timeout=self.config["timeout"],
        )
        response.raise_for_status()
        return response.json()["html_url"]
