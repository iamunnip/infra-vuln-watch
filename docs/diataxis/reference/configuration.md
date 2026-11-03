# Configuration

The scanner resolves settings in this order, with later values taking precedence:

1. Built-in defaults.
2. `config.yaml` in the current working directory, if it exists.
3. The individual tool's `config` mapping in its inventory YAML.
4. The individual deployment's `config` mapping, when `deployments` is used.

Use `--config PATH` to select a different global file. An explicitly selected file must exist.
Nested mappings merge recursively; overriding `fix_days.high` leaves other values inherited.
Lists such as `scan.ignore_cves` replace the inherited list. Use an empty list to clear it.
All supported settings can be overridden under a tool or deployment's `config` mapping.
No configuration is written back to inventory. All policy and inventory files are validated
before network requests, including in dry runs.

## Global file

```yaml
fix_days:
  critical: 2
  high: 7
  medium: 14
  low: 21
  unknown: null
  known_exploited: 2
scan:
  enabled: true
  dry_run: false
  min_severity: low
  include_unknown_severity: true
  report_unknown_versions: true
  ignore_cves: []
  update_existing: true
sources:
  nvd:
    product_search: true
    keyword_search: true
    timeout: 60
    max_attempts: 5
    retry_wait: 30
    interval_without_key: 6.5
    interval_with_key: 0.7
    api_key_env: NVD_API_KEY
  epss:
    enabled: true
    timeout: 60
    max_attempts: 3
    retry_wait: 5
    batch_size: 100
  kev:
    enabled: true
    nvd_fallback: true
    timeout: 60
    max_attempts: 3
    retry_wait: 5
outputs:
  github:
    enabled: true
    repository: null
    token_env: GITHUB_TOKEN
    api_url: https://api.github.com
    timeout: 30
    create_wait: 3
    max_rate_limit_wait: 120
  jira:
    enabled: false
    base_url: ''
    project: ''
    issue_type: Task
    email_env: JIRA_EMAIL
    token_env: JIRA_API_TOKEN
    timeout: 30
    create_wait: 1
    max_rate_limit_wait: 120
    fields: {}
notifications:
  slack:
    enabled: false
    webhook_env: SLACK_WEBHOOK_URL
    timeout: 30
    repeat: false
    notify_updates: true
    state_file: .vuln-watch/slack.json
    send_wait: 1
    max_rate_limit_wait: 120
```

These are also the built-in defaults. `{}` is a valid empty configuration; an empty file or
`null` is rejected. Unknown settings and severity names are rejected to catch misspellings.
Days must be integers from 1 to 36500; booleans, fractions and numeric strings are rejected.
Only `unknown` accepts `null`, meaning no deadline for an unscored CVE.

## Per-tool override

Add this mapping as a sibling of `tool` and `deployments` in the inventory file:

```yaml
config:
  fix_days:
    high: 3
    known_exploited: 1
```

This tool gets three days for high severity and one day for known exploitation. Other values
come from the global file or built-in defaults. Another tool without this mapping inherits
the global policy unchanged.

`known_exploited` takes precedence over severity, including for unscored CVEs. It is independent
of `critical`: changing the critical deadline does not change the known exploitation deadline.
Deadlines count calendar days from the UTC date when an issue is opened. Policy changes apply
to newly created issues; existing issues are not updated. Deadlines are informational and are
not enforced by the scanner. CVSS 0.0 findings remain excluded regardless of policy.

Credentials remain in environment variables; YAML contains only variable names. Choose a policy
appropriate to your team; these are project deadlines, not CISA deadlines.

## Scanning and data sources

`scan.enabled: false` skips a tool and all its API calls. `scan.dry_run: true` previews that
tool's outputs, even in a normal run. CLI `--dry-run` forces preview for every enabled tool;
YAML cannot override it. Dry runs still read enabled vulnerability data sources.

`min_severity` accepts `low`, `medium`, `high` or `critical`. Unknown severity is controlled
separately by `include_unknown_severity`. `report_unknown_versions` controls whether uncertain
version matches are reported. Rejected records and score 0.0 remain excluded.

`ignore_cves` suppresses the listed CVEs. An entry is a CVE ID, or a mapping that records why and for
how long:

```yaml
scan:
  ignore_cves:
    - CVE-2026-1111
    - id: CVE-2026-2222
      reason: The affected plugin is not installed
      expires: 2027-01-31
```

An ignore lasts through its `expires` date, and the finding can be reported again after that. Entries
must look like CVE IDs, so a typing mistake fails validation. Each scan prints its ignores, with
their reasons and any that have expired. See
[ADR 0030](../../adr/0030-give-ignored-cves-reasons-and-expiry-dates.md).

`update_existing`, on by default, keeps open tickets current on each normal scan. See
[keeping tickets current](issue-format.md#keeping-tickets-current).

`min_severity` and `include_unknown_severity` do not apply to known exploited CVEs, so a strict
severity filter can still produce a low-severity issue when the CVE is under attack. Known exploited
means listed in the CISA KEV catalog, or in NVD's copy of it when `nvd_fallback` is on.
`ignore_cves` and `report_unknown_versions` still apply to them. See
[ADR 0026](../../adr/0026-known-exploited-cves-pass-severity-filters.md).

At least one of NVD's product or keyword searches must remain enabled for an enabled tool.
Disabling one reduces coverage. NVD's request intervals cannot be configured below 6.5 seconds
without a key or 0.7 seconds with one. `api_key_env` chooses the environment variable holding
the key. Rate limits can still apply across processes sharing a key or outbound IP.

EPSS and KEV downloads can be disabled independently. KEV's `nvd_fallback` separately controls
whether NVD's copied exploitation fields are used. Issues distinguish disabled downloads from
unavailable sources. KEV catalogs are shared within a run when their source settings match.

Timeouts accept 1 to 300 seconds; attempts accept integers 1 to 10; retry waits accept 0 to 3600 seconds.
EPSS batch size accepts integers 1 to 100. HTTP endpoints for NVD, EPSS and KEV remain the official
sources. Only operational options are configurable; raw secrets are not accepted in YAML.

## Destinations

GitHub, Jira Cloud and Slack are independent toggles. Any combination is supported, including
Jira without GitHub, Slack without tickets, or console-only output with all destinations off.
An enabled destination requires its configured environment variables unless the tool is in
dry-run mode. Disabled tools need no destination credentials. Jira connection settings must
still be structurally complete for an enabled Jira destination, including in dry runs.

- **GitHub:** `repository: null` uses `GITHUB_REPOSITORY`; an explicit `owner/repo` routes to
  another repository. Its token must have access to that repository. `api_url` supports an
  HTTPS GitHub API base URL. `create_wait` is at least 3 seconds.
- **Jira Cloud:** set an HTTPS `base_url`, project key and issue type name. Authentication uses
  the account email and API token referenced by `email_env` and `token_env`. `fields` supplies
  additional Jira create fields, such as `priority` or `customfield_12345`. The configured issue
  type must allow them on its create screen. Project, issue type, summary, description and
  labels are controlled by the scanner and cannot be overridden through `fields`.
  Descriptions use Atlassian Document Format with panels, tables, headings and lists, and fall
  back to plain text if Jira rejects that with a 400 response. CVE text cannot create mentions or
  media. `create_wait` is at least 1 second.
- **Slack:** set `enabled: true` and provide an incoming webhook in the variable named by
  `webhook_env`. It must be a Slack HTTPS incoming webhook URL, including GovSlack if used.
  The webhook determines the channel. Messages use plain-text blocks and an escaped title as notification fallback text to prevent
  CVE text from triggering Slack mentions. `send_wait` is at least 1 second.

All three accept `max_rate_limit_wait`, which defaults to 120 seconds and accepts 0 to 3600. When a
service asks the scanner to slow down, it waits as asked and retries once. If the wait would be longer
than this setting, or the retry is limited too, nothing more goes to that destination during the run.
Other destinations continue, the run exits with 1, and the next scan catches up. See
[ADR 0031](../../adr/0031-respect-rate-limits-on-outputs.md).

Score 0.0 exclusion, search endpoint URLs, identity markers and required tracker labels are implementation
invariants rather than configurable values. The inventory path and selected config path remain
CLI options.

## History, retries and notifications

Each ticket destination reads its own finding history, including closed tickets. Legacy records
use `tool/CVE`; deployments use `tool/deployment-id/CVE`. Environments are tracked independently.
A finding reported to GitHub can still create a missing Jira ticket, and vice versa. Open tickets
are updated when their facts change, and tickets are never closed or reopened. Output setup fails before scanning if a selected
tracker's history cannot be read. During reporting, a failed destination does not prevent
attempts to the others or later findings, but makes the run exit with code 1.

Slack uses a separate atomic receipt file at `state_file`. Receipts include a hash of the
webhook destination and the finding identity, never the secret URL. Successfully notified
findings are skipped on later runs; failed notifications can retry without recreating tickets.
A successful notification also adds a `slack-<hash>` label to the finding's tickets, using a short
one-way hash of the webhook, and a finding with that label is treated as delivered. Each scan also adds it
to tickets whose delivery is recorded only in the receipt file. See
[ADR 0032](../../adr/0032-record-slack-delivery-on-tickets.md).
Set `repeat: true` to notify about every selected finding on every run and bypass receipts and labels.
Slack does not read channel history. A notification retry links the finding's existing tickets.

`notify_updates`, on by default, also sends a message when a scan updates an open ticket. See
[keeping tickets current](issue-format.md#keeping-tickets-current).

Persist the receipt file between runs for deduplication. The supplied GitHub workflow restores
and saves `.vuln-watch/` through a branch-specific Actions cache, including after partial failures.
If you choose a different directory, update the workflow's cache path. With a tracker enabled, ticket
labels prevent repeats when the file is lost. With Slack alone, cache eviction or a missing receipt file
can cause repeat notifications, and GitHub evicts caches unused for 7 days. A process interruption after a successful
remote write but before its receipt is saved can also cause a repeat; delivery is not exactly
once. Atomic writes prevent torn state files, but separate processes must not write the same
file concurrently. The workflow serialises its scan jobs; local invocations require the same
care. Jira indexing delays or parallel scans can also lead to duplicate tickets.

Ticket and Slack writes are not automatically retried within a run because a network timeout
can occur after the service accepted the write. Run again after inspecting the destination.
Secrets and webhook URLs are omitted from delivery failure output.

## Run with a custom file

```bash
python -m infra_vuln_watch --config ./config.yaml --inventory ./inventory --dry-run
```

Paths resolve from the current working directory, not from the configuration file's directory.
A configuration file should live outside the inventory directory, whose `.yaml` and `.yml` files are all
interpreted as tool records. See [inventory format](inventory-format.md) and
[command line](command-line.md).

## Deployment-specific settings

When using multiple versions or environments, add `config` to the deployment entry:

```yaml
deployments:
  - id: production
    environment: production
    version: "2.5.5"
    owner: production-owner
    config:
      fix_days:
        high: 3
      outputs:
        jira:
          project: PRODSEC
```

This fragment belongs in a product file with shared metadata and defaults. Product ownership
is inherited unless overridden. The scanner resolves defaults, global settings, tool settings,
then deployment settings. CLI `--dry-run` still forces preview for every enabled target.
NVD candidates are cached within a run for targets sharing vendor, product, keyword and NVD
request/search settings, then matched separately against each installed version.
See [inventory format](inventory-format.md) for the complete schema and identity migration rules.
