# 3. Context and scope

### C4 level 1: system context

See the [System context (C4 level 1) diagram](../c4/01-system-context.md).

GitHub Actions starts the scanner on behalf of the maintainer. Tool owners remediate the real
infrastructure outside this system and update the recorded version through a pull request. Findings can be routed to GitHub Issues,
Jira Cloud, Slack, or console output according to global and tool settings.
The scanner never connects to the installed tools.

Out of scope: fixing vulnerabilities, scanning running systems, and scanning libraries inside
a tool.

[Architecture index](README.md)
