# Add a tool to the inventory

1. Find the vendor and product names NVD uses. Replace `vault` with your tool:

   ```bash
   curl -s "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=vault&resultsPerPage=5" \
     | python -c "import json,sys; [print(p['cpe']['cpeName']) for p in json.load(sys.stdin)['products']]"
   ```

   A result looks like `cpe:2.3:a:hashicorp:vault:1.15.0:...`. Here the vendor is `hashicorp`
   and the product is `vault`.

2. Create `inventory/vault.yaml`:

   ```yaml
   name: vault
   repo: hashicorp/vault
   version: "1.15.0"
   team: sre
   owner: your-github-name
   vendor: hashicorp
   product: vault
   ```

   Keep the quotes around the version. See the [inventory format](../reference/inventory-format.md).
   Optionally add a `config` mapping alongside those fields to override global scan, source,
   deadline, ticket or notification settings for this tool. Use `config: {}` to inherit
   everything. The [OpenBao inventory](../../../inventory/openbao.yaml) has a complete active configuration;
   [configuration](../reference/configuration.md) lists all supported settings.

3. Check it:

   ```bash
   .venv/bin/python -m infra_vuln_watch --dry-run
   ```

4. If the first run would report a lot of CVEs, check that the names and version are right
   before you merge. Each selected finding is sent to the configured destinations.

## More than one installation

Use `deployments` instead of top-level `version` when a tool runs in multiple environments or
clusters. Each entry has a stable ID and version, and can override ownership and configuration.
Follow the [multi-deployment example](../reference/inventory-format.md#multiple-versions-and-environments).
Keep IDs stable across upgrades. Existing single-version tickets are not automatically assigned
to deployments when converting a file; reconcile those older unscoped tickets manually.
