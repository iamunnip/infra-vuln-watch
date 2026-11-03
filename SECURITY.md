# Security policy

This policy covers bugs in infra-vuln-watch itself, such as a way for CVE text to inject content
into an issue, or a leak of a token or webhook URL. It does not cover vulnerabilities in the tools
listed in `inventory/`: report those to their own projects.

## Reporting a vulnerability

Do not open a public issue. Use **Report a vulnerability** on this repository's
[Security tab](https://github.com/iamunnip/infra-vuln-watch/security), which keeps the report
private until a fix is ready.

Include the affected version or commit, the steps to reproduce it and what an attacker could do.

## Supported versions

Only the latest commit on `main` receives fixes.

## Scan results

Findings come from public data and may be incomplete, delayed or wrong. A wrong or missed finding
is an ordinary bug, so please open a normal issue for it.
