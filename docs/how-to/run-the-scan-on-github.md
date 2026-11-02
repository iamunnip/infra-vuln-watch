# Run the scan on GitHub

The scan only runs when someone starts it. It has no schedule, so new CVEs are found the next time
you run it.

1. Make sure the workflow is on `main`. GitHub lists manual workflows from the default branch.

2. Optional: add an NVD API key, which makes scans about ten times faster.
   - Request one at <https://nvd.nist.gov/developers/request-an-api-key>.
   - Save it in **Settings > Secrets and variables > Actions** as `NVD_API_KEY`.

3. Start the scan, in either of these ways:
   - On GitHub, go to **Actions > scan > Run workflow**.
   - From a terminal, run `gh workflow run scan.yml --ref main`.

## Good to know

- The workflow can write issues because it asks for `issues: write`, so no extra token is needed.
- A CVE that is already reported is skipped, so running the scan again opens no duplicates.
- Only one scan runs at a time. If you start another, it waits for the first to finish. At most one
  can wait, and a newer one replaces it.
- About once a day is plenty, because new CVEs do not appear that fast and each scan uses NVD's
  rate limit.
- A failed NVD or GitHub request makes the run fail. A green run means every tool was checked.
