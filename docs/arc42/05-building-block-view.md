# 5. Building block view

### 5.1 C4 level 2: container view

See the [Containers (C4 level 2) diagram](../c4/02-containers.md).

The scanner is one process. Its modules are components within that process. Inventory files
are checked out onto the runner before execution; Git keeps their history. GitHub Issues and/or Jira Cloud hold ticket history, including closed findings. Optional Slack
receipts live in a local JSON file persisted between runs. There is no application database.
In local dry runs the same scanner reads inventory and external risk sources, prints finding
titles, and skips every output API operation and receipt write.

### 5.2 C4 level 3: component view

Scope: the Scanner application container. Every internal box in the linked view is a Python module component;
relationships between components are in-process calls. External API calls use HTTPS JSON.

See the [Components (C4 level 3) diagram](../c4/03-components.md).

The package lives in `src/infra_vuln_watch/`, with tests in `tests/`. See
[ADR 0006](../adr/0006-use-the-python-src-layout.md).

| File | Job |
| --- | --- |
| `__main__.py` | Lets the tool run with `python -m infra_vuln_watch` |
| `cli/main.py` | Parses CLI options, loads global configuration, validates and resolves tool policy |
| `application/scanner.py` | Applies scan filters, enriches findings, routes delivery and returns the exit code |
| `configuration/config.py` | Validates and recursively merges defaults, global settings and tool overrides |
| `persistence/state.py` | Atomically persists successful Slack notification receipts |
| `application/router.py` | Routes each finding independently to configured trackers and Slack |
| `clients/jira_client.py` | Reads Jira Cloud reporting history and creates tickets using REST v3 |
| `clients/slack_client.py` | Sends plain-text Slack webhook payloads and records delivery |
| `configuration/inventory.py` | Validates tool files and expands deployment-specific scan targets |
| `domain/identity.py` | Defines stable scan target IDs, finding IDs and scoped display names |
| `clients/nvd_client.py` | Downloads CVEs, with paging, waiting and retries |
| `domain/version_check.py` | Decides affected, not affected or unknown, and finds the fix |
| `domain/cve_details.py` | Pulls the score, description and links out of a CVE |
| `clients/risk_data.py` | Downloads EPSS scores and the CISA KEV list |
| `domain/fix_deadline.py` | Works out the fix date from the severity |
| `reporting/issue_format.py` | Writes the issue title and body, and cleans NVD text |
| `clients/github_client.py` | Creates labels and issues, and lists what is already reported |

[Architecture index](README.md)

## Package layout

```text
src/infra_vuln_watch/
├── __init__.py
├── __main__.py
├── application/
│   ├── __init__.py
│   ├── router.py
│   └── scanner.py
├── cli/
│   ├── __init__.py
│   └── main.py
├── clients/
│   ├── __init__.py
│   ├── github_client.py
│   ├── jira_client.py
│   ├── nvd_client.py
│   ├── risk_data.py
│   └── slack_client.py
├── configuration/
│   ├── __init__.py
│   ├── config.py
│   └── inventory.py
├── domain/
│   ├── __init__.py
│   ├── cve_details.py
│   ├── fix_deadline.py
│   ├── identity.py
│   └── version_check.py
├── persistence/
│   ├── __init__.py
│   └── state.py
└── reporting/
    ├── __init__.py
    └── issue_format.py
```

| Package | Responsibility |
| --- | --- |
| `cli/` | Argument parsing and the installed command entry point |
| `application/` | Scan orchestration and delivery routing |
| `configuration/` | Global settings, inventory validation and override resolution |
| `domain/` | Stable finding identities, CVE interpretation, version matching and deadline policy |
| `clients/` | External HTTP integrations |
| `persistence/` | Atomic local delivery state |
| `reporting/` | Finding presentation and sanitisation |

Only package initialisation and `__main__.py` remain at the package root. Domain CVE details
are shared by scanning and presentation; the output router belongs with application orchestration.
The installed CLI uses `infra_vuln_watch.cli.main:main`; `python -m infra_vuln_watch` delegates
to the same function. Reinstall an existing editable installation after entry-point changes:

```bash
.venv/bin/pip install -e ".[dev]"
```

Internal import paths changed; CLI options, configuration and finding behaviour are unchanged.
See [ADR 0020](../adr/0020-group-source-by-responsibility.md), extending
[ADR 0019](../adr/0019-layer-source-and-configure-scans-and-delivery.md).

Inventory expansion produces one scan target per deployment before global settings are resolved.
Tool and deployment override mappings merge without injecting defaults, preserving the precedence
of built-in, global, tool and deployment layers. Each target has its own version and ownership.
NVD candidates are cached in memory by vendor, product, keyword and source settings, then
matched separately. Route keys, tracker markers and Slack receipts use the shared identity
helpers, so different deployments of one product cannot overwrite each other's routes.
See [ADR 0021](../adr/0021-track-deployments-independently.md).
