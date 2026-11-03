# 1. Introduction and goals

infra-vuln-watch tells the owners of infrastructure tools when a known CVE affects the version
they run.

| Priority | Quality goal | What it means here |
| --- | --- | --- |
| 1 | Reliability of results | A broken scan must never look like "no CVEs found" |
| 2 | Low noise | Suppress previously reported tool/deployment/CVE findings (legacy tool/CVE retained) per destination |
| 3 | Simplicity | Beginner friendly Python that anyone on the team can change |

Stakeholders: tool owners read issues, tickets and notifications, and maintainers edit the inventory and code.

[Architecture index](README.md)
