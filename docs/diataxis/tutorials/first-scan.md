# Your first scan

In this tutorial you run a scan on your own computer and read the results. It creates no issues, tickets or notifications. You need Python 3.13 and git.

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

Open `inventory/openbao.yaml`. Its demo deployments record versions and environments:

```yaml
deployments:
  - id: production
    environment: production
    version: "2.5.5"
  - id: staging
    environment: staging
    version: "2.6.4"
```

## 4. Run the scan

```bash
.venv/bin/python -m infra_vuln_watch --dry-run
```

The scan waits between NVD requests. Deployments sharing the same search settings reuse the
retrieved records, while matching each version separately. You will see lines like this:

```text
Checking openbao/production 2.5.5
  Found 16 CVE(s) to report
  [dry run; github] [HIGH] [PROD] [7.5] CVE-2026-115365 openbao - OpenBao from 2.3.0 before 2.6.3 contains...
```

The count on your screen may differ, because new CVEs are published all the time.

## 5. See the result change

Edit only the production deployment's `version` to another version you want to compare, then
run the scan again. Its findings may change while staging retains its own version. Compare
the results by deployment; a newer version is not automatically free of vulnerabilities.

Change the version back when you are done.

## Next steps

- [Fix your first vulnerability](fix-your-first-vulnerability.md).
- [Add a tool](../how-to/add-a-tool.md) to the inventory.
- [Run the scan on GitHub](../how-to/run-the-scan-on-github.md).
