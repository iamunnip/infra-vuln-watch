# Command line and settings

```bash
python -m infra_vuln_watch [--dry-run] [--inventory DIRECTORY] [--config PATH]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--dry-run` | Off | Print findings, and open, update and notify nothing. Needs no output credentials |
| `--config` | `config.yaml` if present, otherwise built-in defaults | Global policy file; an explicitly selected file must exist |
| `--inventory` | `inventory`, in the folder you run from | Directory of `.yaml` and `.yml` files |

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
| `1` | Configuration, source retrieval, output setup, delivery or a ticket update failed, a destination rate limited the scan, or a CVE record was malformed |



## Tests

The tests use mocks and cannot reach a network, because `tests/conftest.py` fails any test that tries.
`tests/test_delivery_mock.py` runs the real CLI and clients against fake GitHub, Jira, Slack, NVD, EPSS
and CISA KEV services, including failures, rate limits and repeat scans.

`tests/test_mermaid.py` parses every Mermaid diagram in the repository's Markdown files, so a diagram GitHub
cannot draw fails the tests. It needs Node.js and the parser, installed once with this command:

```bash
npm ci --ignore-scripts --prefix scripts/mermaid
```

Without them, the parser tests skip on your machine and fail in CI. A check for semicolons in sequence
diagram messages, the mistake that has broken a diagram here, always runs.

Run these from the top folder of the repo.

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check src tests scripts
.venv/bin/mypy
.venv/bin/python -m pytest --cov --cov-fail-under=90
```

After changing a dependency in `pyproject.toml`, regenerate the lockfile that the scan installs. Run
this with pip-tools installed:

```bash
pip-compile --generate-hashes --strip-extras --all-build-deps --allow-unsafe --no-emit-index-url --output-file=requirements.txt pyproject.toml
```

See [configuration](configuration.md) for global settings and per-tool precedence. Invalid
configuration or inventory exits with code 1 before any API requests.

Credential environment variable names can be overridden globally, per tool or per deployment. A tool can also
be disabled or previewed independently with `scan.enabled` and `scan.dry_run`.
