# 8. Crosscutting concepts

- **Untrusted input:** CVE text can be written by anyone. It is cleaned before it reaches an
  issue, so it cannot mention users or fake the marker.
- **Duplicate protection:** workflow scans are serialised, and each issue holds a hidden `vuln-watch-id`. GitHub history is restricted to the `vuln-watch` label. Jira history uses its project and that
  label without a status filter. Slack uses local atomic receipts, persisted in an Actions
  cache in the supplied workflow; cache loss can allow repeats.
- **Least privilege:** the workflow token can only read code and write issues. Actions are
  pinned to commit SHAs.
- **Human remediation:** people upgrade tools and close issues, and the scan never does either.
  The inventory only changes through a pull request, so each fix leaves a record.
- **Configuration:** defaults < global YAML < tool overrides < deployment overrides, merged recursively; lists replace.
  Invalid policy fails before networking. Credentials remain in environment variables.
- **Failure handling:** a failed tool or destination does not stop the others, but fails the
  run. Output errors omit credentials and webhook URLs. Source enrichment outages are warnings.
- **Notification safety:** Slack payloads use plain-text blocks; Jira descriptions use plain
  ADF text. Neither is built from mentions or executable markup. Secrets are referenced only
  by environment variable name in configuration.

[Architecture index](README.md)

- **Deployment identity:** `tool/deployment-id/CVE` scopes markers and receipts independently of
  installed version. Single-version records retain `tool/CVE`. Use shared identity helpers in
  routing and presentation. Product metadata and NVD keyword remain shared across deployments.
