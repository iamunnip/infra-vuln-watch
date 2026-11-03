# System context (C4 level 1)

Scope: infra-vuln-watch and the people and external systems it interacts with.

```mermaid
flowchart LR
    maintainer["Maintainer — Person<br/>Maintains inventory and policy; starts scans"]
    owner["Tool owner — Person<br/>Reviews findings and upgrades tools"]
    watch["infra-vuln-watch — Software system<br/>Finds CVEs and routes selected findings"]
    nvd["NVD — External software system<br/>CVE records and version data"]
    epss["FIRST EPSS — External software system<br/>Exploitation probability"]
    kev["CISA KEV — External software system<br/>Known exploited vulnerabilities"]
    github["GitHub — External software system<br/>Repository, Actions and optional Issues"]
    jira["Jira Cloud — External software system<br/>Optional tickets and reporting history"]
    slack["Slack — External software system<br/>Optional incoming webhook notifications"]
    maintainer -->|Configures and invokes scans via GitHub or CLI| watch
    maintainer -->|Edits repository and dispatches workflow| github
    watch -->|Searches CVEs over HTTPS JSON| nvd
    watch -->|Optionally requests scores over HTTPS JSON| epss
    watch -->|Optionally downloads catalog over HTTPS JSON| kev
    watch -->|Optionally reads history, and writes and updates issues via HTTPS REST| github
    watch -->|Optionally reads history, and writes and updates tickets via HTTPS REST v3| jira
    watch -->|Optionally posts notifications via HTTPS JSON| slack
    owner -->|Reads and closes issues| github
    owner -->|Reads and resolves tickets| jira
    owner -->|Reads notifications| slack
```

See [the arc42 explanation](../arc42/03-context-and-scope.md) and the [view index](README.md).
