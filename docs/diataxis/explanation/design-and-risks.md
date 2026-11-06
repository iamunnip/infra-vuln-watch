# Design and risks

This page explains what the scanner is built to achieve, the limits it works within, the
principles that shape its code and the risks it accepts. The diagrams are in the
[C4 views](../../c4/README.md), and the reasons for each choice are in the
[decision records](../../adr/README.md).

## Goals

infra-vuln-watch tells the owners of infrastructure tools when a known CVE affects the version
they run.

| Priority | Quality goal | What it means here |
| --- | --- | --- |
| 1 | Reliability of results | A broken scan must never look like "no CVEs found" |
| 2 | Low noise | Suppress previously reported tool/deployment/CVE findings (legacy tool/CVE retained) per destination |
| 3 | Simplicity | Beginner friendly Python that anyone on the team can change |

Stakeholders: tool owners read issues, tickets and notifications, and maintainers edit the inventory and code.

## Constraints

- Runs on GitHub Actions or locally with no server and no database.
- Optional Slack receipts use persistent file storage, through an Actions cache in the workflow. Tickets also record delivery, so only Slack without a tracker depends on that storage.
- Python, with few libraries.
- NVD rate limits: 5 requests per 30 seconds, or 50 with a key.
- Must show the NVD attribution notice.

## Approach

- Run the scan by hand ([ADR 0016](../../adr/0016-run-the-scan-by-hand.md)). GitHub Issues and/or Jira Cloud remember reported tickets
  ([ADR 0004](../../adr/0004-use-github-issues-as-state.md), extended by
  [ADR 0019](../../adr/0019-layer-source-and-configure-scans-and-delivery.md)). Optional Slack
  receipts and a label on each ticket track notification delivery independently
  ([ADR 0032](../../adr/0032-record-slack-delivery-on-tickets.md)).
- Keep open tickets current when their facts change, but leave closing them to people
  ([ADR 0028](../../adr/0028-update-open-tickets-on-each-scan.md)).
- Search NVD twice and compare versions locally
  ([ADR 0002](../../adr/0002-search-nvd-twice-and-compare-versions-locally.md)).
- When unsure, report and ask a human ([ADR 0003](../../adr/0003-report-unknown-results.md)).
- People do the fixing, through a pull request ([ADR 0013](../../adr/0013-how-a-vulnerability-gets-fixed.md)).
- Resolve defaults, global YAML and tool overrides before networking. Ticket and notification
  destinations are independently selectable. A delivery failure fails the run while other
  destinations and findings continue. Optional enrichment failures remain warnings.

## Principles

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
- **Deployment identity:** `tool/deployment-id/CVE` scopes markers and receipts independently of
  installed version. Single-version records retain `tool/CVE`. Use shared identity helpers in
  routing and presentation. Product metadata and NVD keyword remain shared across deployments.
- **Heading visibility:** a shared formatter puts severity, uppercase environment/deployment,
  score and unbracketed CVE ID before the tool and summary. The title aliases `production`
  to `PROD` without changing stored scope. Labels remain separate. Rendering
  changes do not alter identity markers or modify existing tickets.

## Expected behaviour

| Scenario | Expected result |
| --- | --- |
| NVD is down during a run | Retries, then the run fails and shows red |
| The scan runs twice in a day | No duplicate issues |
| A scan is started while another is running | It waits, then opens no duplicate issues |
| An owner closes an issue | It is not reopened |
| An upgrade is merged | The next scan stops reporting the fixed CVEs |
| A CVE has no version data | An issue with `needs-review` is opened |
| A CVE description contains `@someone` | Nobody is notified |
| EPSS or CISA KEV is down | The issue still opens and says `Could not check` |
| An NVD page is malformed or unexpectedly empty | The tool scan fails; other tools are still checked |
| A tool overrides only its high deadline | Other severity values inherit global policy and defaults |
| A configuration value is misspelled or invalid | The run fails before any API requests |
| A matching affected range has no upper bound | No numeric fixed version is claimed |
| GitHub succeeded but Jira failed | The run fails; retry creates only the missing Jira ticket |
| Slack failed after ticket creation | The run fails; a later run can retry notification independently |
| A tool disables Slack or Jira | That destination receives no API calls for that tool |
| A tool or CLI enables dry run | No output API calls or receipt writes occur |
| Production and staging run different versions | Match each version independently and show its own owner |
| Both environments share a CVE | Track two scoped findings without one suppressing the other |
| Two deployments share product and search settings | Fetch NVD candidates once per run, then match independently |
| Deployment config overrides a deadline | Preserve other tool and global values |
| A CVE scores 0.0 | No issue is opened |
| A reporter names the tool differently and its text mentions the tool | A `needs-review` issue is opened, not silently dropped |
| A severity filter would hide a known exploited CVE | The finding is still reported |
| One CVE record is malformed | The run fails, and other findings are still delivered |
| A CVE joins KEV, its score changes, its date passes or it stops matching | The open ticket gets one comment and its labels change. It is never closed |
| The Slack receipt cache is lost and a tracker is enabled | Ticket labels prevent repeat notifications |
| A destination keeps rate limiting the scan | It gets no more requests that run, and the others continue |
| Jira rejects a formatted ticket | The ticket is sent again as plain text |
| A Mermaid diagram has a syntax error | The tests fail in CI |
| A link would not be found on GitHub, or text names a file that does not exist | The documentation check and tests fail |

## Risks

| Risk | Impact | Response |
| --- | --- | --- |
| NVD data arrives late or incomplete | Late alerts | Keyword search and unknown results reduce this. A second source can be added later |
| Legacy inventory is converted to deployments | New scoped findings may duplicate earlier unscoped tickets | Reconcile old tickets manually; IDs are not inferred |
| Inventory version goes stale | Wrong results | The fix process updates it with each upgrade. Automatic detection is not built |
| A fix date passes unnoticed | Late fixes | Each scan adds an `overdue` label and comment, but only when a scan runs ([ADR 0028](../../adr/0028-update-open-tickets-on-each-scan.md)) |
| Nobody runs the scan | New CVEs go unnoticed | Accepted, because the scan runs by hand. The schedule can come back ([ADR 0016](../../adr/0016-run-the-scan-by-hand.md)) |
| A CVE joins the KEV list after its issue opened | Urgency is missed | The next scan adds `known-exploited` and a comment. Its fix date is left for a person to review |
| Requests grow with the inventory, up to 2 searches per distinct product/search configuration per scan | Slow scans or rate limiting past about 100 tools | Add an API key first, then revisit [ADR 0014](../../adr/0014-keep-full-product-searches.md) |
| Slack cache is evicted or receipts are lost | Repeat notifications, only for Slack without a tracker | Ticket labels record delivery ([ADR 0032](../../adr/0032-record-slack-delivery-on-tickets.md)). Accepted for Slack alone, where GitHub evicting a cache after 7 unused days can still cause repeats |
| Jira search indexing lags or independent scans overlap | Duplicate tickets | Workflow concurrency reduces overlap; inspect ambiguous writes before retrying |
| Filters or disabled sources reduce coverage | Important findings can be missed | Severity filters never hide known exploited CVEs. Defaults retain broad searches and unknown findings; review overrides |
| Wrong vendor or product name in the inventory | Missed CVEs | The how-to guide shows how to look up names. A description that names the tool still opens a review issue when no analyst data exists |
| Reporter and CPE names differ | Review issues instead of exact answers, and some false alarms | Add `tool.aliases`, or use `ignore_cves` for an unrelated product ([ADR 0025](../../adr/0025-widen-reporter-name-and-status-matching.md)) |
| Lockfile falls behind `pyproject.toml` | Scan runs other versions than declared | A test fails when they disagree ([ADR 0027](../../adr/0027-lock-scan-dependencies-and-add-quality-checks.md)) |
| Scans write to existing tickets and tell Slack | Comments and messages notify people, and a first scan can be noisy, and a failed label can repeat a comment | Changes are made only when facts change, and `scan.update_existing` turns them off |
| A diagram parses but looks wrong, or GitHub uses another Mermaid version | Unreadable or undrawn diagram | Every diagram is parsed in CI, but not drawn. Check new diagrams on GitHub ([ADR 0034](../../adr/0034-parse-mermaid-diagrams-in-tests.md)) |
| Fake services differ from the real ones | A delivery bug passes the mock tests | Mock tests apply each service's main rules, and Jira falls back to plain text. Check the first real run |
| A large backlog meets rate limits | Delivery takes several scans | The scan stops sending to that destination and fails, and the next one catches up ([ADR 0031](../../adr/0031-respect-rate-limits-on-outputs.md)) |
