# Architecture decision records

Each record explains one important decision and why it was made. Records are not edited after
they are accepted. To change a decision, add a new record that replaces the old one. Copy
[the template](template.md) to start a new record.

| Number | Decision | Status |
| --- | --- | --- |
| [0001](0001-use-nvd-as-the-cve-source.md) | Use NVD as the CVE source | Accepted |
| [0002](0002-search-nvd-twice-and-compare-versions-locally.md) | Search NVD twice and compare versions locally | Accepted |
| [0003](0003-report-unknown-results.md) | Report results we cannot confirm | Accepted |
| [0004](0004-use-github-issues-as-state.md) | Use GitHub Issues as the only state | Accepted |
| [0005](0005-organise-docs-with-diataxis-okf-arc42-and-adr.md) | Organise docs with Diataxis, OKF, arc42 and ADRs | Accepted |
| [0006](0006-use-the-python-src-layout.md) | Use the Python src layout | Accepted |
| [0007](0007-scan-twice-a-day.md) | Scan twice a day | Replaced by 0016 |
| [0008](0008-issue-title-format.md) | Issue title format | Replaced by 0009 |
| [0009](0009-issue-title-and-labels.md) | Issue title and labels | Accepted |
| [0010](0010-fix-deadlines-by-severity.md) | Fix deadlines by severity | Accepted |
| [0011](0011-severity-comes-from-the-score.md) | Severity comes from the CVSS score | Accepted |
| [0012](0012-add-epss-and-cisa-kev.md) | Add EPSS and CISA KEV | Accepted |
| [0013](0013-how-a-vulnerability-gets-fixed.md) | How a vulnerability gets fixed | Accepted |
| [0014](0014-keep-full-product-searches.md) | Keep full product searches instead of date filtered ones | Accepted |
| [0015](0015-read-nvd-and-not-cve-org.md) | Read NVD and not CVE.org | Accepted |
| [0016](0016-run-the-scan-by-hand.md) | Run the scan by hand | Accepted |
