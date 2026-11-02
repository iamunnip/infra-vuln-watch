# Command line and settings

```bash
python -m infra_vuln_watch [--dry-run] [--inventory DIRECTORY]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--dry-run` | Off | Print findings and open no issues. Needs no GitHub token |
| `--inventory` | `inventory`, in the folder you run from | Directory of YAML files |

## Environment variables

| Name | Needed | Meaning |
| --- | --- | --- |
| `GITHUB_TOKEN` | Unless `--dry-run` | Token that can write issues |
| `GITHUB_REPOSITORY` | Unless `--dry-run` | Where to open issues, like `iamunnip/infra-vuln-watch`. GitHub Actions sets it |
| `NVD_API_KEY` | No | Allows faster NVD requests |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every tool was checked. Finding CVEs still counts as success |
| `1` | At least one tool could not be checked, or the settings are missing |



## Tests

Run these from the top folder of the repo.

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```
