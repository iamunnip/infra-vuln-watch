"""Download EPSS scores and the CISA known exploited list.

CVSS says how severe a CVE is. These two sources add what CVSS cannot:
- EPSS says how likely an attack is in the next 30 days.
- CISA KEV says if the CVE is already known to have been attacked.

They add detail to an issue but are not needed to find a CVE. So if one of them
is down, these functions return None and the scan carries on. The issue then says
"Could not check", which is different from a CVE that was checked and not listed.
"""

import time

import requests

from infra_vuln_watch.configuration.config import DEFAULT_CONFIG

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH_SIZE = 100
MAX_ATTEMPTS = 3
RETRY_WAIT_SECONDS = 5
HEADERS = {"User-Agent": "infra-vuln-watch"}


def get_json(url, params=None, config=None):
    """Download JSON, trying a few times before giving up."""
    settings = config or DEFAULT_CONFIG["sources"]["kev"]
    last_error = None
    for attempt in range(1, settings["max_attempts"] + 1):
        try:
            response = requests.get(url, params=params, headers=HEADERS, timeout=settings["timeout"])
            response.raise_for_status()
            return response.json()
        except requests.RequestException as error:
            last_error = error
            if attempt < settings["max_attempts"]:
                time.sleep(settings["retry_wait"])
    raise requests.RequestException(f"failed after {settings['max_attempts']} attempts: {last_error}")


def fetch_epss(cve_ids, config=None):
    """Return {cve id: {"score", "percentile"}}, or None if EPSS could not be read."""
    settings = config or DEFAULT_CONFIG["sources"]["epss"]
    if not settings["enabled"]:
        return None
    scores = {}
    try:
        for start in range(0, len(cve_ids), settings["batch_size"]):
            batch = cve_ids[start:start + settings["batch_size"]]
            page = get_json(EPSS_URL, {"cve": ",".join(batch), "limit": settings["batch_size"]}, config=settings)
            for entry in page["data"]:
                scores[entry["cve"]] = {
                    "score": float(entry["epss"]),
                    "percentile": float(entry["percentile"]),
                }
    except (requests.RequestException, KeyError, TypeError, ValueError) as error:
        print(f"  WARNING: could not read EPSS: {error}")
        return None
    return scores


def fetch_kev(config=None):
    """Return {cve id: details} from the CISA list, or None if it could not be read."""
    settings = config or DEFAULT_CONFIG["sources"]["kev"]
    if not settings["enabled"]:
        return None
    try:
        catalog = get_json(KEV_URL, config=settings)
        return {
            entry["cveID"]: {
                "date_added": entry.get("dateAdded", "Unknown"),
                "due_date": entry.get("dueDate", "Unknown"),
                "required_action": entry.get("requiredAction", "Unknown"),
                "ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
            }
            for entry in catalog["vulnerabilities"]
        }
    except (requests.RequestException, KeyError, TypeError) as error:
        print(f"  WARNING: could not read the CISA KEV list: {error}")
        return None


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
