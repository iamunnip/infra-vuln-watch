# 7. Deployment view

See the [Deployment diagram](../c4/deployment.md).

`.github/workflows/tests.yml` runs the tests on each push and pull request.

`.github/workflows/scan.yml` runs the scan on a GitHub hosted runner when someone starts it, one
scan at a time.
Actions provides `GITHUB_TOKEN` and `GITHUB_REPOSITORY`; `NVD_API_KEY` is an optional secret.
The token has `contents: read` and `issues: write`. Runner files disappear after the job;
repository history and issues remain on GitHub. A local installation can run the CLI too;
normal delivery requires credentials only for enabled destinations. Jira uses `JIRA_EMAIL`
and `JIRA_API_TOKEN`; Slack uses `SLACK_WEBHOOK_URL`, mapped from Actions secrets by default.
`--dry-run` requires no output credentials. The default `.vuln-watch/` Slack receipt directory
is restored and saved using a branch-specific Actions cache, including on failed scans.
Caches are best effort and may be evicted. Custom receipt paths require corresponding workflow
cache changes. External tickets persist in their respective services.
Workflow concurrency serialises Actions scans; it does not lock independent local executions.

[Architecture index](README.md)
