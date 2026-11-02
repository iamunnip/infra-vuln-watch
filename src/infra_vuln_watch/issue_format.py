"""Write the title and description of a GitHub issue for a CVE."""

from infra_vuln_watch import cve_details
from infra_vuln_watch.version_check import UNKNOWN


def clean_text(text):
    """Make text from NVD safe to put in a GitHub issue.

    Anyone can write CVE text, so we do not trust it:
    - "@name" would notify that GitHub user, so we break the mention.
    - "<" could hide content or fake our marker, so we escape it.
    - Links to github.com would add a "mentioned this" note on the other
      project's issues. Renovate uses the redirect address to avoid this too.
    """
    text = text.replace("<", "&lt;").replace("@", "@​")
    return text.replace("https://github.com/", "https://redirect.github.com/")


def issue_marker(item, cve):
    """Return the hidden text that lets us find this issue again on later runs."""
    return f"<!-- vuln-watch-id: {item['name']}/{cve['id']} -->"


def make_title(item, cve):
    """Return a title like: [low][2.1][cve-2026-1234] - openbao: what went wrong"""
    score = cve_details.get_score(cve)
    description = cve_details.get_description(cve)
    summary = clean_text(cve_details.get_summary(description, item["name"]))
    return f"[{score['severity']}][{score['score']}][{cve['id'].lower()}] - {item['name']}: {summary}"


def make_fix_section(item, result):
    """Explain how to fix the vulnerability."""
    releases = f"https://redirect.github.com/{item['repo']}/releases"

    if result["fix"]:
        return (
            f"Upgrade `{item['name']}` to {result['fix']}, then update its version in the inventory.\n\n"
            "A newer release branch can need its own fix, so read the description and prefer the latest release.\n\n"
            f"Releases: {releases}"
        )
    return f"NVD does not list a fixed version. Check the references below and the releases page.\n\nReleases: {releases}"


def make_references_section(cve):
    """List the reference links, with any tags NVD gave them."""
    references = cve_details.get_references(cve)
    if not references:
        return "None listed."

    lines = []
    for reference in references:
        tags = f" ({', '.join(reference['tags'])})" if reference["tags"] else ""
        lines.append(f"- {clean_text(reference['url'])}{clean_text(tags)}")
    return "\n".join(lines)


def make_body(item, cve, result):
    """Return the full issue description in markdown."""
    score = cve_details.get_score(cve)
    weaknesses = ", ".join(cve_details.get_weaknesses(cve)) or "None listed"
    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve['id']}"

    warning = ""
    if result["status"] == UNKNOWN:
        warning = (
            "> [!WARNING]\n"
            "> NVD does not give enough version data to confirm this. "
            "Please check by hand whether the installed version is affected.\n\n"
        )

    return f"""{warning}## Summary

| Field | Value |
| --- | --- |
| CVE | [{cve['id']}]({nvd_link}) |
| Severity | {score['severity']} |
| CVSS score | {score['score']} (CVSS {score['cvss_version']}) |
| CVSS vector | `{score['vector']}` |
| Weakness | {weaknesses} |
| NVD status | {cve.get('vulnStatus', 'unknown')} |
| Published | {cve.get('published', 'unknown')} |

## Affected item

| Field | Value |
| --- | --- |
| Name | {item['name']} |
| Installed version | {item['version']} |
| Repository | https://redirect.github.com/{item['repo']} |
| Owner | `{item['owner']}` |

## Description

{clean_text(cve_details.get_description(cve))}

## Fix

{make_fix_section(item, result)}

## References

{make_references_section(cve)}

{issue_marker(item, cve)}
"""
