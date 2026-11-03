# 0012. Add EPSS and CISA KEV

Date: 2026-11-02

Status: Accepted

## Context

CVSS only says how severe a CVE is. The project owner wants each issue to also show the chance of
an attack (EPSS) and whether attacks are already known (CISA KEV). NVD copies KEV details into its
records, but this tool exists partly because NVD can lag, so it should not be the only source.

## Decision

- Read EPSS from the FIRST API, and KEV from the CISA feed with the NVD copy as a backup.
- Show CVSS, EPSS and KEV side by side in a risk summary.
- If either source is down, still open the issue and say `Could not check`, and keep the run green
  with a warning in the log.
- Give a KEV listed CVE the red box and a `known-exploited` label.
- Keep severity based on CVSS only.
- Give a KEV listed CVE the critical fix window of 2 days, whatever its score, because attacks are
  already known. Other fix deadlines follow CVSS.

## Consequences

- Readers can see which issues really need attention first.
- There are two more outside services, but neither can stop a CVE being reported.
- An issue opened during an outage keeps `Could not check`, because issues are not updated later.
- A CVE added to the KEV list after its issue opened is not flagged.
