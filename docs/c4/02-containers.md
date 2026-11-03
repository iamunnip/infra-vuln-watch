# Containers (C4 level 2)

Scope: the infra-vuln-watch system. The CLI is an application container and inventory is a file store. GitHub provides execution and issue persistence externally.

```mermaid
flowchart LR
    maintainer["Maintainer — Person"]
    github["GitHub — External software system<br/>Actions execution and persistent issue history"]
    nvd["NVD — External software system"]
    epss["FIRST EPSS — External software system"]
    kev["CISA KEV — External software system"]
    jira["Jira Cloud — External software system"]
    slack["Slack — External software system"]
    subgraph system["infra-vuln-watch — System boundary"]
        scanner["Scanner — Application container<br/>Python 3.13 CLI<br/>Matches versions, reports new findings and updates open tickets"]
        inventory[("Inventory — File store<br/>Versioned YAML files<br/>Product and deployment identities, versions, ownership and overrides")]
        config[("Global policy — File store<br/>config.yaml or selected YAML path")]
        receipts[("Slack receipts — Optional file store<br/>Atomic JSON delivery records")]
        scanner -->|Reads and saves notification receipts| receipts
        scanner -->|Reads and validates policy| config
        scanner -->|Reads local YAML using PyYAML| inventory
    end
    maintainer -->|Changes inventory through GitHub pull requests| inventory
    github -->|Starts python -m infra_vuln_watch on Actions runner| scanner
    scanner -->|Searches product and keyword via HTTPS JSON| nvd
    scanner -->|Requests new finding scores via HTTPS JSON| epss
    scanner -->|Downloads catalog once per run via HTTPS JSON| kev
    scanner -->|Optionally reads markers and writes labels, issues, comments and titles via HTTPS REST| github
    scanner -->|Optionally reads markers and writes tickets, comments and labels via HTTPS REST v3| jira
    scanner -->|Optionally posts plain-text webhook payloads via HTTPS JSON| slack
```

See [the arc42 explanation](../arc42/05-building-block-view.md) and the [view index](README.md).
