"""Write the title and description of a GitHub issue for a CVE."""

from infra_vuln_watch import cve_details
from infra_vuln_watch.version_check import UNKNOWN

# The coloured box at the top of the issue, using GitHub's alert styles.
SEVERITY_STYLES = {
    "critical": {"alert": "CAUTION", "dot": "🔴"},
    "high": {"alert": "CAUTION", "dot": "🟠"},
    "medium": {"alert": "WARNING", "dot": "🟡"},
    "low": {"alert": "NOTE", "dot": "🟢"},
}
DEFAULT_STYLE = {"alert": "IMPORTANT", "dot": "⚪"}

# Reference links are shown in this order, most useful first.
REFERENCE_TYPES = [
    ("advisor", "Security advisory"),
    ("/releases/", "Release notes"),
    ("changelog", "Changelog"),
    ("/pull/", "Pull request"),
    ("/commit/", "Commit"),
    ("/issues/", "Issue"),
]


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
    """Return a title like: [LOW] [2.1] [CVE-2026-1234] OpenBao - what went wrong"""
    score = cve_details.get_score(cve)
    description = cve_details.get_description(cve)
    summary = clean_text(cve_details.get_summary(description, item["name"]))
    return f"[{score['severity'].upper()}] [{score['score']}] [{cve['id']}] {item['display_name']} - {summary}"


def make_alert(item, cve, score):
    """Return the coloured box that sums up the issue in one line."""
    style = SEVERITY_STYLES.get(score["severity"], DEFAULT_STYLE)
    link = f"[{cve['id']}](https://nvd.nist.gov/vuln/detail/{cve['id']})"
    return (
        f"> [!{style['alert']}]\n"
        f"> {style['dot']} **{score['severity'].upper()}, score {score['score']} out of 10.** "
        f"{item['display_name']} `{item['version']}` is affected by {link}."
    )


def make_fix_section(item, result):
    """Explain how to fix the vulnerability."""
    releases = f"[releases page](https://redirect.github.com/{item['repo']}/releases)"
    current = f"{item['display_name']} `{item['version']}`"

    if result["fix"]:
        return (
            f"Upgrade {current} to **{result['fix']}**, then update `version` in the inventory.\n\n"
            f"A newer release branch can need its own fix, so prefer the latest version on the {releases}."
        )
    return f"NVD does not list a fixed version for {current}. Check the links below and the {releases}."


def make_cwe_links(cve):
    """Return the weaknesses as links to their explanations."""
    links = []
    for cwe in cve_details.get_weaknesses(cve):
        number = cwe.removeprefix("CWE-")
        links.append(f"[{cwe}](https://cwe.mitre.org/data/definitions/{number}.html)")
    return ", ".join(links) or "None listed"


def make_details_table(item, cve, score):
    """Return the table of facts about the CVE and the affected tool."""
    rows = [
        ("Tool", item["display_name"]),
        ("Installed version", f"`{item['version']}`"),
        ("Repository", f"[{item['repo']}](https://redirect.github.com/{item['repo']})"),
        ("Owner", f"`{item['owner']}`"),
        ("Severity", f"{score['severity'].capitalize()} ({score['score']}, CVSS {score['cvss_version']})"),
    ]
    rows.extend((label, clean_text(value)) for label, value in score["attack"].items())
    rows.extend(
        [
            ("Weakness", make_cwe_links(cve)),
            ("NVD status", cve.get("vulnStatus", "Unknown")),
            ("Published", cve.get("published", "Unknown")[:10]),
        ]
    )
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {label} | {value} |" for label, value in rows)
    return "\n".join(lines)


def describe_reference(url):
    """Return (position in the list, link text) for a reference link."""
    lowered = url.lower()
    last_part = url.rstrip("/").split("/")[-1]

    for position, (word, label) in enumerate(REFERENCE_TYPES):
        if word in lowered:
            # A commit id is very long, so keep only the start of it.
            name = last_part[:7] if label == "Commit" else last_part
            return position, f"{label}: {name}"
    return len(REFERENCE_TYPES), url.split("/")[2]


def make_references_section(cve):
    """List the reference links, most useful first."""
    references = cve_details.get_references(cve)
    if not references:
        return "None listed."

    entries = []
    for reference in references:
        position, text = describe_reference(reference["url"])
        # These characters would break a markdown link.
        text = text.replace("[", "").replace("]", "")
        url = reference["url"].replace(" ", "%20").replace("(", "%28").replace(")", "%29")
        entries.append((position, f"- [{clean_text(text)}]({clean_text(url)})"))

    entries.sort(key=lambda entry: entry[0])
    return "\n".join(line for _, line in entries)


def make_body(item, cve, result):
    """Return the full issue description in markdown."""
    score = cve_details.get_score(cve)

    warning = ""
    if result["status"] == UNKNOWN:
        warning = (
            "\n\n> [!WARNING]\n"
            "> NVD does not give enough version data to confirm this. "
            "Please check by hand whether the installed version is affected."
        )

    return f"""{make_alert(item, cve, score)}{warning}

## What is the problem?

{clean_text(cve_details.get_description(cve))}

## How to fix it

{make_fix_section(item, result)}

## Details

{make_details_table(item, cve, score)}

## Learn more

{make_references_section(cve)}

<details>
<summary>CVSS vector</summary>

`{score['vector']}`

</details>

{issue_marker(item, cve)}
"""
