"""Download CVE records from the National Vulnerability Database (NVD)."""

import os
import time

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
MAX_ATTEMPTS = 5
RETRY_WAIT_SECONDS = 30

# NVD allows 5 requests per 30 seconds, or 50 per 30 seconds with an API key.
WAIT_WITHOUT_KEY_SECONDS = 6.5
WAIT_WITH_KEY_SECONDS = 0.7

# NVD uses these when it is busy or rate limiting, so trying again can work.
RETRY_STATUS_CODES = [403, 429, 500, 502, 503, 504]


def get_page(params):
    """Download one page of results, trying again if NVD is having trouble."""
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        time.sleep(WAIT_WITH_KEY_SECONDS if api_key else WAIT_WITHOUT_KEY_SECONDS)
        try:
            response = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
            if response.status_code not in RETRY_STATUS_CODES:
                response.raise_for_status()
                return response.json()
            last_error = f"HTTP {response.status_code}"
        except requests.exceptions.HTTPError:
            raise  # A request NVD will never accept, so trying again cannot help.
        except requests.RequestException as error:
            last_error = str(error)

        print(f"  NVD attempt {attempt} of {MAX_ATTEMPTS} failed: {last_error}")
        if attempt < MAX_ATTEMPTS:
            time.sleep(RETRY_WAIT_SECONDS)

    raise requests.RequestException(f"NVD failed after {MAX_ATTEMPTS} attempts: {last_error}")


def search(params):
    """Run one search and return the CVEs from every page of results."""
    cves = []
    start_index = 0

    while True:
        page = get_page({**params, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index})
        cves.extend(entry["cve"] for entry in page["vulnerabilities"])
        start_index += page["resultsPerPage"]
        if start_index >= page["totalResults"] or page["resultsPerPage"] == 0:
            return cves


def fetch_cves(item):
    """Return every CVE that could be about this inventory item.

    We need two searches because each one misses CVEs the other one finds:
    - The product search misses new CVEs that NVD has not analysed yet.
    - The keyword search misses CVEs whose text never names the product.
    See adr/0002-search-nvd-twice-and-compare-versions-locally.md
    """
    by_product = search({"virtualMatchString": f"cpe:2.3:a:{item['vendor']}:{item['product']}"})
    by_keyword = search({"keywordSearch": item["keyword"]})

    # Using the CVE id as the key removes the ones found by both searches.
    return list({cve["id"]: cve for cve in by_product + by_keyword}.values())
