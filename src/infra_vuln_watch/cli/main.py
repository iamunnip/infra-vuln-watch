"""Command-line entry point for infra-vuln-watch."""

import argparse

from infra_vuln_watch.configuration.config import load_config, merge_config, validate_effective
from infra_vuln_watch.configuration.inventory import load_inventory
from infra_vuln_watch.application.scanner import run_scan
from infra_vuln_watch.domain.identity import inventory_id


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the inventory for known CVEs.")
    parser.add_argument("--inventory", default="inventory", help="directory of YAML files")
    parser.add_argument("--config", help="global YAML configuration (default: config.yaml if present)")
    parser.add_argument("--dry-run", action="store_true", help="print findings, do not open issues")
    args = parser.parse_args(argv)

    try:
        settings = load_config(args.config)
        items = load_inventory(args.inventory)
        items = [{**item, "config": merge_config(settings, item.get("config", {}))} for item in items]
        for item in items:
            validate_effective(item["config"], inventory_id(item))
    except ValueError as error:
        print(f"Configuration or inventory problem: {error}")
        return 1
    return run_scan(items, dry_run=args.dry_run)
