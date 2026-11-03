"""Download CVE records from the National Vulnerability Database (NVD)."""

import os
import time

import requests

from infra_vuln_watch.configuration.config import DEFAULT_CONFIG

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# NVD uses these when it is busy or rate limiting, so trying again can work.
RETRY_STATUS_CODES = [403, 429, 500, 502, 503, 504]


def get_page(params, config=None):
    """Download one page of results, trying again if NVD is having trouble."""
    settings = config or DEFAULT_CONFIG["sources"]["nvd"]
    api_key = os.environ.get(settings["api_key_env"])
    headers = {"apiKey": api_key} if api_key else {}
    last_error = None

    for attempt in range(1, settings["max_attempts"] + 1):
        time.sleep(settings["interval_with_key"] if api_key else settings["interval_without_key"])
        try:
            response = requests.get(NVD_URL, params=params, headers=headers, timeout=settings["timeout"])
            if response.status_code not in RETRY_STATUS_CODES:
                response.raise_for_status()
                return response.json()
            last_error = f"HTTP {response.status_code}"
        except requests.exceptions.HTTPError:
            raise  # A request NVD will never accept, so trying again cannot help.
        except requests.RequestException as error:
            last_error = str(error)

        print(f"  NVD attempt {attempt} of {settings['max_attempts']} failed: {last_error}")
        if attempt < settings["max_attempts"]:
            time.sleep(settings["retry_wait"])

    raise requests.RequestException(f"NVD failed after {settings['max_attempts']} attempts: {last_error}")


def search(params, config=None):
    """Run one search and return the CVEs from every page of results."""
    cves: list[dict] = []
    start_index = 0

    while True:
        page_params = {**params, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
        page = get_page(page_params, config=config) if config is not None else get_page(page_params)
        try:
            entries = page["vulnerabilities"]
            count, total = page["resultsPerPage"], page["totalResults"]
            if (not isinstance(entries, list) or type(count) is not int or type(total) is not int
                    or count < 0 or total < 0 or count != len(entries)):
                raise ValueError("invalid pagination")
            if any(not isinstance(entry["cve"]["id"], str) for entry in entries):
                raise ValueError("invalid CVE identifier")
        except (KeyError, TypeError, ValueError) as error:
            raise requests.RequestException("NVD returned an invalid results page") from error
        if not page["vulnerabilities"] and start_index < page["totalResults"]:
            raise requests.RequestException("NVD returned an empty page before all results were read")
        cves.extend(entry["cve"] for entry in page["vulnerabilities"])
        start_index += page["resultsPerPage"]
        if start_index >= page["totalResults"] or page["resultsPerPage"] == 0:
            return cves


def fetch_cves(item):
    """Return every CVE that could be about this inventory item.

    We need two searches because each one misses CVEs the other one finds:
    - The product search misses new CVEs that NVD has not analysed yet.
    - The keyword search misses CVEs whose text never names the product.
    See docs/adr/0002-search-nvd-twice-and-compare-versions-locally.md
    """
    settings = item.get("config", DEFAULT_CONFIG)["sources"]["nvd"]
    options = {"config": settings} if "config" in item else {}
    by_product = search({"virtualMatchString": f"cpe:2.3:a:{item['vendor']}:{item['product']}"}, **options) if settings["product_search"] else []
    by_keyword = search({"keywordSearch": item["keyword"]}, **options) if settings["keyword_search"] else []

    # Using the CVE id as the key removes the ones found by both searches.
    return list({cve["id"]: cve for cve in by_product + by_keyword}.values())
