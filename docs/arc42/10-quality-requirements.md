# 10. Quality requirements

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

[Architecture index](README.md)
