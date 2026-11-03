"""Write the title and description of a GitHub issue for a CVE."""

from datetime import datetime, timezone
import re

from infra_vuln_watch.domain import cve_details
from infra_vuln_watch.domain.fix_deadline import get_deadline
from infra_vuln_watch.domain.version_check import UNKNOWN
from infra_vuln_watch.domain.identity import finding_marker, target_name

# The coloured box at the top of the issue, using GitHub's alert styles.
SEVERITY_STYLES = {
    "critical": {"alert": "CAUTION", "dot": "🔴"},
    "high": {"alert": "CAUTION", "dot": "🟠"},
    "medium": {"alert": "WARNING", "dot": "🟡"},
    "low": {"alert": "NOTE", "dot": "🟢"},
}
DEFAULT_STYLE = {"alert": "IMPORTANT", "dot": "⚪"}

MAX_LINK_TEXT_LENGTH = 40

ZERO_WIDTH_SPACE = "\u200b"
# Any spelling of a github.com address, but not a subdomain such as redirect.github.com.
GITHUB_ADDRESS = re.compile(r"(?<![\w.\-/])(?:https?://)?(?:www\.)?github\.com/", re.IGNORECASE)
# A whole URL is matched first, so that an issue reference is only found outside one.
ISSUE_REFERENCE = re.compile(r"[a-z][a-z0-9+.\-]*://\S+|\bGH-(?=\d)|#(?=\d)", re.IGNORECASE)

# Reference links are shown in this order, most useful first.
REFERENCE_TYPES = [
    ("advisor", "Security advisory"),
    ("/releases/", "Release notes"),
    ("changelog", "Changelog"),
    ("/pull/", "Pull request"),
    ("/commit/", "Commit"),
    ("/issues/", "Issue"),
]


def neutralise(text):
    """Stop markup and GitHub links, in text or a URL, from acting on anything."""
    text = text.replace("<", "&lt;").replace("@", f"@{ZERO_WIDTH_SPACE}")
    return GITHUB_ADDRESS.sub("https://redirect.github.com/", text)


def clean_text(text):
    """Make text from NVD safe to put in a GitHub issue.

    Anyone can write CVE text, so we do not trust it:
    - "@name" would notify that GitHub user, so we break the mention.
    - "<" could hide content or fake our marker, so we escape it.
    - Links to github.com would add a "mentioned this" note on the other
      project's issues. Renovate uses the redirect address to avoid this too.
    - "#12", "owner/repo#12" and "GH-12" would link to issues in the same way,
      so we break those too. Other URLs are left whole, so their fragments work.
    """
    return ISSUE_REFERENCE.sub(break_reference, neutralise(text))


def break_reference(match):
    """Break an issue reference with a zero width space, and leave a URL alone."""
    return match[0] if "://" in match[0] else f"{match[0]}{ZERO_WIDTH_SPACE}"


def safe_url(url):
    """Make a link from NVD safe to use inside a markdown link."""
    # These characters would end the link early.
    return neutralise(url.replace(" ", "%20").replace("(", "%28").replace(")", "%29"))


def issue_marker(item, cve):
    """Return the hidden text that lets us find this issue again on later runs."""
    return finding_marker(item, cve)


def make_title(item, cve):
    """Return [severity] [environment/deployment] [score] CVE Tool - summary."""
    score = cve_details.get_score(cve)
    description = cve_details.get_description(cve)
    summary = clean_text(cve_details.get_summary(description, item["name"]))
    parts = [f"[{score['severity'].upper()}]"]
    if item.get('deployment_id'):
        environment = item['environment']
        deployment = item['deployment_id']
        scope = 'PROD' if environment.casefold() == 'production' else environment.upper()
        if environment.casefold() != deployment.casefold():
            scope += f'/{deployment}'
        parts.append(f'[{clean_text(scope)}]')
    parts.extend([f"[{score['score']}]", cve['id'], clean_text(item['display_name'])])
    return f"{' '.join(parts)} - {summary}"


def describe_deadline(deadline):
    """Return the deadline as text."""
    if deadline is None:
        return "No deadline for this severity"
    return f"{deadline['date']} ({deadline['days']} days after this issue was opened)"


def table_text(text):
    """Make free text from outside safe to put in a markdown table cell."""
    return clean_text(str(text)).replace("|", "\\|").replace("\n", " ")


def describe_epss(cve, epss, enabled=True):
    """Return the EPSS result as text."""
    if not enabled:
        return "Disabled"
    if epss is None:
        return "Could not check"
    if cve["id"] not in epss:
        return "No score yet"
    entry = epss[cve["id"]]
    # Stop rounding from claiming a 100% chance, which EPSS never means.
    chance = min(entry["score"] * 100, 99.99)
    higher_than = min(entry["percentile"] * 100, 99)
    return f"{chance:.2f}% chance, higher than {higher_than:.0f}% of all CVEs"


def describe_kev(kev_entry, kev, enabled=True):
    """Return the CISA KEV result as text."""
    if kev_entry:
        return f"**Yes**, added {table_text(kev_entry['date_added'])}"
    if not enabled:
        return "Catalog disabled"
    if kev is None:
        return "Could not check"
    return "Not listed"


def make_risk_table(cve, score, risk, kev_entry):
    """Return the three measures of risk side by side."""
    severity = score["severity"].capitalize()
    lines = [
        "| Measure | Result | What it tells you |",
        "| --- | --- | --- |",
        f"| CVSS | {score['score']} ({severity}) | How severe the vulnerability is |",
        f"| EPSS | {describe_epss(cve, risk['epss'], risk.get('epss_enabled', True))} | How likely exploitation is in the next 30 days |",
        f"| CISA KEV | {describe_kev(kev_entry, risk['kev'], risk.get('kev_enabled', True))} | Whether it is known to have been exploited in the wild |",
    ]
    return "\n".join(lines)


def make_alert(item, cve, score, deadline, kev_entry):
    """Return the coloured box that sums up the issue."""
    style = SEVERITY_STYLES.get(score["severity"], DEFAULT_STYLE)
    # A known attack is urgent whatever the score says, so always use the strongest box.
    alert_type = "CAUTION" if kev_entry else style["alert"]
    known_exploited = "> **Known to be exploited in the wild** (CISA KEV).\n>\n" if kev_entry else ""
    link = f"[{cve['id']}](https://nvd.nist.gov/vuln/detail/{cve['id']})"
    return (
        f"> [!{alert_type}]\n"
        f"> {style['dot']} **{score['severity'].upper()}, score {score['score']} out of 10.** "
        f"{clean_text(target_name(item))} `{item['version']}` is affected by {link}.\n"
        ">\n"
        f"{known_exploited}"
        f"> **Fix by:** {describe_deadline(deadline)}"
    )


def find_advisory_url(cve):
    """Return the first security advisory link of a CVE, if it has one."""
    for reference in cve_details.get_references(cve):
        if "advisor" in reference["url"].lower():
            return safe_url(reference["url"])
    return None


def make_fix_section(item, cve, result):
    """Explain step by step how to fix the vulnerability."""
    releases = f"[releases page](https://redirect.github.com/{item['repo']}/releases)"
    current = f"{clean_text(target_name(item))} `{item['version']}`"
    advisory = find_advisory_url(cve)

    if result["fix"]:
        first_step = f"Upgrade {current} to **{result['fix']}**. The latest version on the {releases} is usually the best choice."
    else:
        first_step = f"NVD does not list a fixed version for {current}. Check the links under Learn more and the {releases}."

    update = "Update `version` in the inventory file for this tool."
    verify = "Run `python -m infra_vuln_watch --dry-run` and check that this CVE is no longer listed."
    if item.get('deployment_id'):
        update = f"Update `version` for deployment `{item['deployment_id']}` in this tool's inventory file."
        verify = "Run `python -m infra_vuln_watch --dry-run` and check that this CVE is no longer listed for this deployment."
    lines = [
        f"1. {first_step}",
        f"2. {update}",
        f"3. {verify}",
        "4. Close this issue.",
    ]
    if len(result["affected_versions"]) > 1:
        lines.append("\nBefore you pick a version, check Affected versions above, because more than one release branch is affected.")
    if advisory:
        lines.append(f"\nIf you cannot upgrade yet, check the [security advisory]({advisory}) for a workaround.")
    return "\n".join(lines)


def make_table(rows):
    """Turn label and value pairs into a markdown table."""
    lines = ["| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {label} | {value} |" for label, value in rows)
    return "\n".join(lines)


def make_cwe_links(cve):
    """Return the weaknesses as links to their explanations."""
    links = []
    for cwe in cve_details.get_weaknesses(cve):
        number = cwe.removeprefix("CWE-")
        links.append(f"[{cwe}](https://cwe.mitre.org/data/definitions/{number}.html)")
    return ", ".join(links) or "None listed"


def make_affected_versions(result):
    """List the affected version ranges and point out the one we are in."""
    if not result["affected_versions"]:
        return "NVD does not list usable version data for this CVE."

    lines = []
    for version in result["affected_versions"]:
        note = " **(includes your version)**" if version["includes_installed"] else ""
        lines.append(f"- `{version['text']}`{note}")
    return "\n".join(lines)


def make_details_section(item, cve, score, result, deadline, risk, kev_entry):
    """Return everything we know about the CVE, grouped into small tables."""
    tool_rows = [
        ("Tool", item["display_name"]),
        ("Installed version", f"`{item['version']}`"),
        ("Repository", f"[{item['repo']}](https://redirect.github.com/{item['repo']})"),
        ("Team", clean_text(item["team"])),
        ("Owner", f"`{table_text(item['owner'])}`"),
    ]
    if item.get('deployment_id'):
        tool_rows.extend([
            ("Deployment", table_text(item['deployment_id'])),
            ("Environment", table_text(item['environment'])),
        ])
    tool = make_table(tool_rows)

    all_scores = "<br>".join(f"CVSS {text}" for text in cve_details.get_all_scores(cve)) or "None listed"
    severity = make_table([
        ("Severity", score["severity"].capitalize()),
        ("Score used in the title", f"{score['score']} (CVSS {score['cvss_version']})"),
        ("All scores", all_scores),
        ("Fix by", describe_deadline(deadline)),
    ])

    attack_rows = {**score["attack"], **score["impact"]}
    attack = make_table([(label, clean_text(value)) for label, value in attack_rows.items()])
    ssvc_rows = cve_details.get_exploit_status(cve)
    ssvc = make_table([(label, clean_text(value)) for label, value in ssvc_rows.items()])

    record = make_table([
        ("Weakness", make_cwe_links(cve)),
        ("Reported by", clean_text(cve.get("sourceIdentifier", "Unknown"))),
        ("NVD status", clean_text(cve.get("vulnStatus", "Unknown"))),
        ("Published", cve.get("published", "Unknown")[:10]),
        ("Last changed", cve.get("lastModified", "Unknown")[:10]),
    ])

    sections = [("Risk summary", make_risk_table(cve, score, risk, kev_entry))]
    if kev_entry:
        kev_details = make_table([
            ("Added to the list", table_text(kev_entry["date_added"])),
            ("CISA fix deadline", table_text(kev_entry["due_date"])),
            ("CISA required action", table_text(kev_entry["required_action"])),
            ("Used in ransomware", table_text(kev_entry["ransomware"])),
        ])
        sections.append(("CISA KEV details", kev_details))
    sections += [
        ("Affected tool", tool),
        ("Affected versions", make_affected_versions(result)),
        ("Severity", severity),
    ]
    if attack_rows:
        sections.append(("Attack and impact", attack))
    if ssvc_rows:
        sections.append(("SSVC assessment", ssvc))
    sections.append(("CVE record", record))
    return "\n\n".join(f"### {title}\n\n{content}" for title, content in sections)


def describe_reference(url):
    """Return (position in the list, link text) for a reference link."""
    lowered = url.lower()
    last_part = url.rstrip("/").split("/")[-1]
    if len(last_part) > MAX_LINK_TEXT_LENGTH:
        last_part = last_part[:MAX_LINK_TEXT_LENGTH - 3] + "..."

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
        entries.append((position, f"- [{clean_text(text)}]({safe_url(reference['url'])})"))

    entries.sort(key=lambda entry: entry[0])
    return "\n".join(line for _, line in entries)


def make_body(item, cve, result, risk=None, opened_on=None):
    """Return the full issue description in markdown.

    risk holds the EPSS and KEV data. Without it, the issue says "Could not check".
    """
    score = cve_details.get_score(cve)
    risk = risk or {"epss": None, "kev": None}
    kev_entry = cve_details.find_kev_entry(cve, risk["kev"], allow_nvd=risk.get("allow_nvd_kev", True))
    if opened_on is None:
        opened_on = datetime.now(timezone.utc).date()
    deadline = get_deadline(
        score["severity"], opened_on, known_exploited=bool(kev_entry), config=item.get("config")
    )

    warning = ""
    if result["status"] == UNKNOWN:
        warning = (
            "\n\n> [!WARNING]\n"
            "> NVD does not give enough version data to confirm this. "
            "Please check by hand whether the installed version is affected."
        )

    return f"""{make_alert(item, cve, score, deadline, kev_entry)}{warning}

## What is the problem?

{clean_text(cve_details.get_description(cve))}

## Details

{make_details_section(item, cve, score, result, deadline, risk, kev_entry)}

## How to fix it

{make_fix_section(item, cve, result)}

These risk results show what was known when this issue was written, and they can change.

## Learn more

{make_references_section(cve)}

<details>
<summary>CVSS vector</summary>

`{score['vector']}`

</details>

{issue_marker(item, cve)}
"""
