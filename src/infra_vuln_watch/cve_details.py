"""Pull the useful details out of a raw NVD CVE record."""

# Newest CVSS version first, because we prefer the newest score available.
CVSS_KEYS = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

MAX_SUMMARY_LENGTH = 120

# The parts of a CVSS score that are easy for a person to read.
ATTACK_FIELDS = {
    "attackVector": "Attack from",
    "attackComplexity": "Attack complexity",
    "privilegesRequired": "Privileges needed",
    "userInteraction": "User interaction",
}


def get_score(cve):
    """Return the severity, score, CVSS version, vector and attack details of a CVE."""
    metrics = cve.get("metrics", {})

    for key in CVSS_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue

        # "Primary" means NVD scored it, so prefer that over the reporter's score.
        primary = [entry for entry in entries if entry.get("type") == "Primary"]
        entry = primary[0] if primary else entries[0]
        data = entry["cvssData"]
        return {
            # CVSS v2 keeps the severity outside of cvssData.
            "severity": (data.get("baseSeverity") or entry.get("baseSeverity") or "unknown").lower(),
            "score": str(data["baseScore"]),
            "cvss_version": data.get("version", "unknown"),
            "vector": data.get("vectorString", "unknown"),
            "attack": {
                label: data[field].replace("_", " ").capitalize()
                for field, label in ATTACK_FIELDS.items()
                if field in data
            },
        }

    return {"severity": "unknown", "score": "n/a", "cvss_version": "n/a", "vector": "n/a", "attack": {}}


def get_description(cve):
    """Return the English description of a CVE."""
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description["value"].strip()
    return "No English description available."


def get_summary(description, name):
    """Make a one line summary that fits in an issue title."""
    sentences = description.replace("\n", " ").split(". ")

    # Many CVEs start by explaining the product, like "OpenBao is an open source...".
    # That says nothing about the bug, so use the next sentence instead.
    first = sentences[0].lower()
    if len(sentences) > 1 and (first.startswith(f"{name.lower()} is ") or first.startswith(f"{name.lower()} exists ")):
        summary = sentences[1]
    else:
        summary = sentences[0]

    summary = summary.rstrip(". ")
    if len(summary) > MAX_SUMMARY_LENGTH:
        summary = summary[:MAX_SUMMARY_LENGTH - 3].rstrip() + "..."
    return summary


def get_weaknesses(cve):
    """Return the CWE ids of a CVE, like ["CWE-532"], without duplicates."""
    found = []
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def get_references(cve):
    """Return the reference links of a CVE as a list of {"url", "tags"}, without duplicates."""
    found = {}
    for reference in cve.get("references", []):
        url = reference.get("url", "")
        if url.startswith(("https://", "http://")):
            found.setdefault(url, []).extend(reference.get("tags", []))
    return [{"url": url, "tags": tags} for url, tags in found.items()]
