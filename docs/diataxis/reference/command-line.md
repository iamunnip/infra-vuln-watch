# Command line and settings

```bash
python -m infra_vuln_watch [--dry-run] [--inventory DIRECTORY] [--config PATH]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--dry-run` | Off | Print findings and open no issues. Needs no GitHub token |
| `--config` | `config.yaml` if present, otherwise built-in defaults | Global policy file; an explicitly selected file must exist |
| `--inventory` | `inventory`, in the folder you run from | Directory of YAML files |

## Environment variables

| Name | Needed | Meaning |
| --- | --- | --- |
| `GITHUB_TOKEN` | When GitHub output is enabled and not dry run | Token that can write issues |
| `GITHUB_REPOSITORY` | When GitHub output has no configured repository and not dry run | Where to open issues, like `iamunnip/infra-vuln-watch`. GitHub Actions sets it |
| `NVD_API_KEY` | No | Allows faster NVD requests |
| `JIRA_EMAIL` | When Jira output is enabled and not dry run | Jira Cloud account email |
| `JIRA_API_TOKEN` | When Jira output is enabled and not dry run | Jira Cloud API token |
| `SLACK_WEBHOOK_URL` | When Slack is enabled and not dry run | Slack incoming webhook URL |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every tool was checked. Finding CVEs still counts as success |
| `1` | Configuration, source retrieval, output setup or delivery failed |



## Tests

Run these from the top folder of the repo.

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

See [configuration](configuration.md) for global settings and per-tool precedence. Invalid
configuration or inventory exits with code 1 before any API requests.

Credential environment variable names can be overridden globally, per tool or per deployment. A tool can also
be disabled or previewed independently with `scan.enabled` and `scan.dry_run`.
