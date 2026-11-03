"""Pull the useful details out of a raw NVD CVE record."""

# Newest CVSS version first, because we prefer the newest score available.
CVSS_KEYS = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

MAX_SUMMARY_LENGTH = 120

# The parts of a CVSS score that are easy for a person to read.
ATTACK_FIELDS = {
    "attackVector": "Attack from",
    "attackComplexity": "Attack complexity",
    "attackRequirements": "Attack requirements",
    "privilegesRequired": "Privileges needed",
    "userInteraction": "User interaction",
}

# CVSS 4.0 and CVSS 3 use different names for the same three impacts.
IMPACT_FIELDS = {
    "Confidentiality impact": ["vulnConfidentialityImpact", "confidentialityImpact"],
    "Integrity impact": ["vulnIntegrityImpact", "integrityImpact"],
    "Availability impact": ["vulnAvailabilityImpact", "availabilityImpact"],
}


def readable(value):
    """Turn NVD text like ADJACENT_NETWORK into Adjacent network."""
    return str(value).replace("_", " ").capitalize()


def severity_from_score(score):
    """Turn a CVSS score into a severity name, using one scale for every CVSS version."""
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def get_impact(data):
    """Return what an attacker could affect, from the CVSS data."""
    impact = {}
    for label, fields in IMPACT_FIELDS.items():
        for field in fields:
            if field in data:
                impact[label] = readable(data[field])
                break
    return impact


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
            "severity": severity_from_score(data["baseScore"]),
            "score": str(data["baseScore"]),
            "cvss_version": data.get("version", "unknown"),
            "vector": data.get("vectorString", "unknown"),
            "attack": {
                label: readable(data[field])
                for field, label in ATTACK_FIELDS.items()
                if field in data
            },
            "impact": get_impact(data),
        }

    return {"severity": "unknown", "score": "n/a", "cvss_version": "n/a", "vector": "n/a", "attack": {}, "impact": {}}


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
    found: dict[str, list] = {}
    for reference in cve.get("references", []):
        url = reference.get("url", "")
        if url.startswith(("https://", "http://")):
            found.setdefault(url, []).extend(reference.get("tags", []))
    return [{"url": url, "tags": tags} for url, tags in found.items()]


def get_all_scores(cve):
    """Return every CVSS score of a CVE, like ["4.0: 2.1 (Low)", "3.1: 3.3 (Low)"], without duplicates."""
    metrics = cve.get("metrics", {})
    scores = []
    for key in CVSS_KEYS:
        for entry in metrics.get(key, []):
            data = entry["cvssData"]
            severity = readable(severity_from_score(data["baseScore"]))
            text = f"{data.get('version', '?')}: {data['baseScore']} ({severity})"
            if text not in scores:
                scores.append(text)
    return scores


def get_exploit_status(cve):
    """Return the SSVC assessment of a CVE, as label and value pairs."""
    status = {}

    # SSVC is a separate assessment of how urgent a CVE is.
    ssvc_entries = cve.get("metrics", {}).get("ssvcV203", [])
    if ssvc_entries:
        ssvc = ssvc_entries[0].get("ssvcData", {})
        options = {}
        for option in ssvc.get("options", []):
            options.update(option)
        if "exploitation" in options:
            status["Exploitation seen"] = readable(options["exploitation"])
        if "automatable" in options:
            status["Can be automated"] = readable(options["automatable"])
        if "technicalImpact" in options:
            status["Technical impact"] = readable(options["technicalImpact"])
        if ssvc.get("timestamp"):
            status["Assessed on"] = ssvc["timestamp"][:10]

    return status


def find_kev_entry(cve, kev, allow_nvd=True):
    """Return the KEV details of a CVE, or None if it is not known to be listed.

    NVD also copies these details into its records, so we can still spot a
    listed CVE when the CISA list could not be downloaded.
    """
    if kev and cve["id"] in kev:
        return kev[cve["id"]]
    if allow_nvd and cve.get("cisaExploitAdd"):
        return {
            "date_added": cve["cisaExploitAdd"],
            "due_date": cve.get("cisaActionDue", "Unknown"),
            "required_action": cve.get("cisaRequiredAction", "Unknown"),
            "ransomware": "Unknown",
        }
    return None
