# 8. Crosscutting concepts

- **Untrusted input:** CVE text can be written by anyone. It is cleaned before it reaches an
  issue, so it cannot mention users or fake the marker.
- **Duplicate protection:** workflow scans are serialised, and each issue holds a hidden `vuln-watch-id`. GitHub history is restricted to the `vuln-watch` label. Jira history uses its project and that
  label without a status filter. Slack uses local atomic receipts, persisted in an Actions
  cache in the supplied workflow, plus a delivery label on each ticket. Cache loss can allow
  repeats only for Slack without a tracker.
- **Least privilege:** the workflow token can only read code and write issues. Actions are
  pinned to commit SHAs.
- **Human remediation:** people upgrade tools and close issues, and the scan never does either. It
  only adds comments and labels to open tickets and updates their titles when facts change.
  The inventory only changes through a pull request, so each fix leaves a record.
- **Configuration:** defaults < global YAML < tool overrides < deployment overrides, merged recursively; lists replace.
  Invalid policy fails before networking. Credentials remain in environment variables.
- **Failure handling:** a failed tool, destination or malformed CVE record does not stop the
  others, but fails the run. Output errors omit credentials and webhook URLs. Source enrichment
  outages are warnings.
- **Notification safety:** Slack payloads use plain-text blocks and an escaped title as fallback
  text with Markdown disabled; Jira descriptions use ADF panels, tables, lists and text marks,
  with plain text as a fallback. Neither is built from mentions, media or executable markup. Secrets are referenced only
  by environment variable name in configuration.

[Architecture index](README.md)

- **Deployment identity:** `tool/deployment-id/CVE` scopes markers and receipts independently of
  installed version. Single-version records retain `tool/CVE`. Use shared identity helpers in
  routing and presentation. Product metadata and NVD keyword remain shared across deployments.

- **Heading visibility:** a shared formatter puts severity, uppercase environment/deployment,
  score and unbracketed CVE ID before the tool and summary. The title aliases `production`
  to `PROD` without changing stored scope. Labels remain separate. Rendering
  changes do not alter identity markers or modify existing tickets.
