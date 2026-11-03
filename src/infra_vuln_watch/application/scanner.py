"""Scan orchestration independent of argument parsing and output destinations."""

import json

import requests

from infra_vuln_watch.clients import nvd_client, risk_data
from infra_vuln_watch.configuration.config import SEVERITIES
from infra_vuln_watch.domain import cve_details
from infra_vuln_watch.domain.identity import inventory_id
from infra_vuln_watch.application.router import OutputRouter
from infra_vuln_watch.domain.version_check import NOT_AFFECTED, UNKNOWN, check_version


def find_problems(item, candidates=None):
    """Find candidate CVEs and apply the tool's scan and version-matching policy."""
    policy = item['config']['scan']
    problems = []
    if candidates is None:
        candidates = nvd_client.fetch_cves(item)
    for cve in candidates:
        if cve.get('vulnStatus') == 'Rejected' or cve['id'] in policy['ignore_cves']:
            continue
        severity = cve_details.get_score(cve)['severity']
        if severity == 'none':
            continue
        if severity == 'unknown':
            if not policy['include_unknown_severity']:
                continue
        elif SEVERITIES[severity] < SEVERITIES[policy['min_severity']]:
            continue
        result = check_version(cve, item['vendor'], item['product'], item['version'])
        if result['status'] == UNKNOWN and not policy['report_unknown_versions']:
            continue
        if result['status'] != NOT_AFFECTED:
            problems.append((cve, result))
    return problems


def run_scan(items, dry_run=False):
    """Run enabled tools; output failures fail the run without stopping other tools."""
    items = [item for item in items if item['config']['scan']['enabled']]
    if not items:
        print('No enabled inventory tools to scan')
        return 0
    try:
        router = OutputRouter(items, dry_run=dry_run)
    except (ValueError, requests.RequestException) as error:
        print(f'Output setup problem: {error}')
        return 1

    failed = []
    kev_catalogs = {}
    cve_catalogs = {}
    for item in items:
        target = inventory_id(item)
        print(f"Checking {target} {item['version']}")
        try:
            kev_config = item['config']['sources']['kev']
            key = json.dumps(kev_config, sort_keys=True)
            if key not in kev_catalogs:
                kev_catalogs[key] = risk_data.fetch_kev(config=kev_config)
            cve_key = json.dumps([item['vendor'], item['product'], item.get('keyword', item['name']),
                                  item['config']['sources']['nvd']], sort_keys=True)
            if cve_key not in cve_catalogs:
                cve_catalogs[cve_key] = nvd_client.fetch_cves(item)
            problems = find_problems(item, candidates=cve_catalogs[cve_key])
            print(f'  Found {len(problems)} CVE(s) to report')
            new_ids = [cve['id'] for cve, _ in problems if router.needs_reporting(item, cve)]
            risk = {'kev': kev_catalogs[key], 'allow_nvd_kev': kev_config['nvd_fallback'],
                    'kev_enabled': kev_config['enabled'], 'epss_enabled': item['config']['sources']['epss']['enabled'],
                    'epss': risk_data.fetch_epss(
                new_ids, config=item['config']['sources']['epss'])}
            for cve, result in problems:
                if not router.report(item, cve, result, risk):
                    if target not in failed:
                        failed.append(target)
        except requests.RequestException:
            print(f"  FAILED: vulnerability source request for {target}")
            failed.append(target)
        except (KeyError, TypeError, ValueError) as error:
            print(f"  FAILED: invalid vulnerability data for {target} ({type(error).__name__})")
            failed.append(target)
    if failed:
        print(f"Could not finish checking: {', '.join(failed)}")
        return 1
    return 0
