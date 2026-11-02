# Set up the daily scan

1. Merge the workflow into `main`. GitHub only runs scheduled workflows from the default branch.

2. Allow the workflow to write issues. The workflow asks for this itself with `issues: write`,
   so no extra token is needed.

3. Optional: add an NVD API key, which makes scans about ten times faster.
   - Request one at <https://nvd.nist.gov/developers/request-an-api-key>.
   - Save it in **Settings > Secrets and variables > Actions** as `NVD_API_KEY`.

4. Run it once by hand: **Actions > daily-scan > Run workflow**.

## Good to know

- GitHub can start scheduled runs late when it is busy, so 00:00 and 12:00 IST are the earliest times and
  not a promise.
- GitHub turns off schedules after 60 days without activity in a public repo. It warns you by
  email. Turn the workflow back on from the Actions tab.
- A failed NVD or GitHub request makes the run fail. A green run means every tool was checked.
