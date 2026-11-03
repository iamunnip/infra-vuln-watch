"""Decide if an installed version is affected by a CVE.

NVD describes affected versions in two places:
- "configurations": added by NVD analysts, but missing on many new CVEs.
- "affected": sent by whoever reported the CVE, in several text formats.

We read both, turn them into simple version ranges, and check the installed
version against each range.
"""

from packaging.version import InvalidVersion, Version

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNKNOWN = "unknown"

# Reporters use these when they give no real version. "0" means "from the start".
NO_VERSION_WORDS = ["", "0", "*", "-", "n/a", "unspecified", "unknown"]


def make_range(start=None, start_included=True, end=None, end_included=False):
    """Build a version range. A missing start or end means no limit on that side."""
    return {
        "start": Version(start) if start else None,
        "start_included": start_included,
        "end": Version(end) if end else None,
        "end_included": end_included,
    }


def is_in_range(version, version_range):
    """Return True if the version is inside the range."""
    start = version_range["start"]
    end = version_range["end"]

    if start is not None:
        if version < start or (version == start and not version_range["start_included"]):
            return False
    if end is not None:
        if version > end or (version == end and not version_range["end_included"]):
            return False
    return True


def range_from_cpe_match(match, cpe_version):
    """Turn one NVD "cpeMatch" entry into a range."""
    start_including = match.get("versionStartIncluding")
    start_excluding = match.get("versionStartExcluding")
    end_including = match.get("versionEndIncluding")
    end_excluding = match.get("versionEndExcluding")

    if any([start_including, start_excluding, end_including, end_excluding]):
        return make_range(
            start=start_including or start_excluding,
            start_included=bool(start_including),
            end=end_including or end_excluding,
            end_included=bool(end_including),
        )

    if cpe_version == "*":
        return make_range()  # Every version is affected.
    return make_range(start=cpe_version, end=cpe_version, end_included=True)


def ranges_from_configurations(cve, vendor, product):
    """Return (ranges, could_not_read, products_seen) from the NVD analyst data."""
    ranges = []
    could_not_read = False
    products_seen = False

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # A CPE looks like cpe:2.3:a:vendor:product:version:...
                products_seen = True
                criteria = match.get("criteria")
                if not isinstance(criteria, str) or len(criteria.split(":")) < 6:
                    could_not_read = True
                    continue
                parts = criteria.split(":")
                if parts[3].lower() != vendor.lower() or parts[4].lower() != product.lower():
                    continue
                if not match.get("vulnerable"):
                    continue
                try:
                    ranges.append(range_from_cpe_match(match, parts[5]))
                except InvalidVersion:
                    could_not_read = True

    return ranges, could_not_read, products_seen


def range_from_text(text):
    """Read version text like "< 2.3.0", ">= 0.1.0, < 2.3.2" or "1.2.3"."""
    start = end = None
    start_included = end_included = True

    for condition in text.split(","):
        condition = condition.strip()
        # Check two character operators first, so ">=" is not read as ">".
        if condition.startswith(">="):
            start, start_included = condition[2:].strip(), True
        elif condition.startswith("<="):
            end, end_included = condition[2:].strip(), True
        elif condition.startswith(">"):
            start, start_included = condition[1:].strip(), False
        elif condition.startswith("<"):
            end, end_included = condition[1:].strip(), False
        else:
            start = end = condition.lstrip("= ")

    return make_range(start, start_included, end, end_included)


def range_from_affected_entry(entry):
    """Turn one entry of the "affected" data into a range."""
    version = str(entry.get("version", "")).strip()
    less_than = entry.get("lessThan")
    less_than_or_equal = entry.get("lessThanOrEqual")

    # With no real start version, the range begins at the very first version.
    start = None if version.lower() in NO_VERSION_WORDS else version

    if less_than and less_than != "*":
        return make_range(start=start, end=less_than)
    if less_than_or_equal and less_than_or_equal != "*":
        return make_range(start=start, end=less_than_or_equal, end_included=True)
    if less_than or less_than_or_equal:
        return make_range(start=start)
    return range_from_text(version)


def ranges_from_affected(cve, vendor, product):
    """Return (ranges, could_not_read, products_seen) from the reporter data."""
    ranges = []
    could_not_read = False
    products_seen = False

    for source in cve.get("affected", []):
        for data in source.get("affectedData", []):
            products_seen = True
            if str(data.get("vendor")).lower() != vendor.lower():
                continue
            if str(data.get("product")).lower() != product.lower():
                continue

            for entry in data.get("versions") or []:
                if entry.get("status") != "affected":
                    continue
                if str(entry.get("version", "")).strip().lower() in NO_VERSION_WORDS:
                    if not entry.get("lessThan") and not entry.get("lessThanOrEqual"):
                        could_not_read = True
                        continue
                try:
                    ranges.append(range_from_affected_entry(entry))
                except InvalidVersion:
                    could_not_read = True

    return ranges, could_not_read, products_seen


def describe_range(version_range):
    """Turn a range into text like ">= 2.2.0 and < 2.6.4"."""
    start = version_range["start"]
    end = version_range["end"]

    if start is None and end is None:
        return "All versions"
    if start is not None and start == end:
        return str(start)

    parts = []
    if start is not None:
        parts.append(f"{'>=' if version_range['start_included'] else '>'} {start}")
    if end is not None:
        parts.append(f"{'<=' if version_range['end_included'] else '<'} {end}")
    return " and ".join(parts)


def list_affected_versions(ranges, installed):
    """Return each affected range once, lowest first, and say if it includes us."""
    def lowest_first(version_range):
        return version_range["end"] or version_range["start"] or Version("0")

    versions = {}
    for version_range in sorted(ranges, key=lowest_first):
        text = describe_range(version_range)
        versions[text] = versions.get(text, False) or is_in_range(installed, version_range)
    return [{"text": text, "includes_installed": found} for text, found in versions.items()]


def fix_text(matching_ranges):
    """Describe the fix, using the highest end version so that every range is cleared."""
    if any(r["end"] is None for r in matching_ranges):
        return None
    with_end = matching_ranges

    highest = max(with_end, key=lambda r: (r["end"], r["end_included"]))
    if highest["end_included"]:
        return f"a version newer than {highest['end']}"
    return f"version {highest['end']} or later"


def check_version(cve, vendor, product, installed_version):
    """Return the status, fix and affected versions for this CVE and installed version.

    When NVD does not give us enough to decide, the status is UNKNOWN. We report
    those for a human to check, because hiding a real vulnerability is worse
    than asking someone to look at a false alarm.
    """
    config_ranges, config_unread, config_seen = ranges_from_configurations(cve, vendor, product)
    affected_ranges, affected_unread, affected_seen = ranges_from_affected(cve, vendor, product)

    ranges = config_ranges + affected_ranges
    could_not_read = config_unread or affected_unread
    installed = Version(installed_version)

    affected_versions = list_affected_versions(ranges, installed)

    def answer(status, fix=None):
        return {"status": status, "fix": fix, "affected_versions": affected_versions}

    matching = [r for r in ranges if is_in_range(installed, r)]
    if matching:
        return answer(AFFECTED, fix_text(matching))

    if could_not_read:
        return answer(UNKNOWN)

    # Our product is listed and our version is outside every listed range.
    if ranges:
        return answer(NOT_AFFECTED)

    # NVD lists products, but ours has no version data or is not one of them.
    if config_seen or affected_seen:
        if product_is_listed(cve, vendor, product):
            return answer(UNKNOWN)
        return answer(NOT_AFFECTED)

    # No product data at all, so the keyword match is the only clue we have.
    return answer(UNKNOWN)


def product_is_listed(cve, vendor, product):
    """Return True if the CVE's "affected" data names this vendor and product."""
    for source in cve.get("affected", []):
        for data in source.get("affectedData", []):
            same_vendor = str(data.get("vendor")).lower() == vendor.lower()
            same_product = str(data.get("product")).lower() == product.lower()
            if same_vendor and same_product:
                return True
    return False
