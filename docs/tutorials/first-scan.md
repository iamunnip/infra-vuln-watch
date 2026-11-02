# Your first scan

In this tutorial you run a scan on your own computer and read the results. It opens no
issues, so it is safe to try. You need Python 3.13 and git.

## 1. Get the code

```bash
git clone git@github.com:iamunnip/infra-vuln-watch.git
cd infra-vuln-watch
```

## 2. Install the libraries

Run every command from the top folder of the repo.

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

## 3. Look at the inventory

Open `inventory/openbao.yaml`. It says which version of OpenBao we run:

```yaml
version: "2.5.5"
```

## 4. Run the scan

```bash
.venv/bin/python -m infra_vuln_watch --dry-run
```

The scan waits between requests to respect the NVD rate limit, so it takes about 15 seconds
for each tool. You will see lines like this:

```text
Checking openbao 2.5.5
  Found 16 CVE(s) to report
  [dry run] [HIGH] [7.5] [CVE-2026-115365] OpenBao - OpenBao from 2.3.0 before 2.6.3 contains...
```

The count on your screen may differ, because new CVEs are published all the time.

## 5. See the result change

Edit the file so it says `version: "2.7.2"` and run the scan again. A newer version has fewer
matching CVEs. This is the same check that runs twice a day.

Change the version back when you are done.

## Next steps

- [Fix your first vulnerability](fix-your-first-vulnerability.md).
- [Add a tool](../how-to/add-a-tool.md) to the inventory.
- [Set up the daily scan](../how-to/set-up-the-daily-scan.md) on GitHub.
