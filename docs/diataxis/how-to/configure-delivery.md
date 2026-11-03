# Configure GitHub, Jira Cloud and Slack delivery

Start with the global [config.yaml](../../../config.yaml). Keep credentials in environment
variables or GitHub Actions secrets, never in inventory or configuration YAML.

## Select destinations

To create Jira Cloud tickets and notify Slack, while disabling GitHub issues:

```yaml
outputs:
  github:
    enabled: false
  jira:
    enabled: true
    base_url: https://your-team.atlassian.net
    project: SEC
    issue_type: Task
    email_env: JIRA_EMAIL
    token_env: JIRA_API_TOKEN
    fields:
      priority:
        name: High
notifications:
  slack:
    enabled: true
    webhook_env: SLACK_WEBHOOK_URL
    state_file: .vuln-watch/slack.json
```

Provide `JIRA_EMAIL`, `JIRA_API_TOKEN` and `SLACK_WEBHOOK_URL` in the environment. The supplied
scan workflow maps GitHub secrets with these names. A Jira account needs Browse Projects and
Create Issues permissions, and access to the chosen issue type and required create fields.
Use `fields` to supply any additional required fields, in the JSON shape Jira expects.

Set up an incoming webhook for the desired Slack channel and keep its full URL secret. Follow
[Slack's setup guide](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/).
For Jira fields and API requirements, see the
[Jira Cloud create issue documentation](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post).
The integration supports Jira Cloud REST API v3, not Jira Server or Data Center.

Keep `outputs.github.enabled: true` if both trackers should receive findings. For another
GitHub repository, set `outputs.github.repository: owner/repo` and provide a token with issue
write access there; the default Actions token is limited to the workflow's repository.

## Override one tool

Add the same schema under `config` in the tool's inventory file:

```yaml
config:
  scan:
    min_severity: high
  outputs:
    jira:
      project: PLATFORM
  notifications:
    slack:
      enabled: false
```

This tool inherits Jira's URL, issue type and credential variable names, routes tickets to
`PLATFORM`, filters scored findings below high severity unless they are known to be exploited, and disables Slack. Unknown severity
remains reportable unless explicitly disabled. Other tools keep their global settings.
A separate Slack channel can be selected per tool by setting `webhook_env` to a different
variable name and mapping that secret into the workflow environment.

Rate limits, and how many scans a large backlog can need, are covered in the
[configuration reference](../reference/configuration.md#destinations).

## Preview and run

```bash
python -m infra_vuln_watch --config config.yaml --dry-run
```

The preview names each selected destination and creates no tickets, notifications, labels or
receipt files. It still contacts enabled vulnerability sources. Review the output, then run
the same command without `--dry-run` when you intend to deliver findings.

Preserve the Slack receipt directory between executions, which matters most for Slack without a
tracker, because tickets otherwise record delivery with a `slack-<hash>` label. The supplied workflow caches
the default `.vuln-watch/` path; do not commit receipts. Failed deliveries make the run fail, while
successful deliveries to the other destinations are retained. See the
[configuration reference](../reference/configuration.md) for all settings and retry limitations.

## Route one environment differently

Every deployment entry accepts the same `config` schema as the product. For example, set
`outputs.jira.project` to a production project inside the production deployment while routing
staging elsewhere. Deployment ownership, version and ticket history remain separate. See the
[inventory deployment schema](../reference/inventory-format.md#multiple-versions-and-environments).
