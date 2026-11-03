"""Independently route findings to configured trackers and Slack."""

import json
import os
from pathlib import Path

import requests

from infra_vuln_watch.clients import github_client, jira_client, slack_client, risk_data
from infra_vuln_watch.domain import cve_details
from infra_vuln_watch.reporting import issue_format
from infra_vuln_watch.persistence.state import DeliveryState
from infra_vuln_watch.domain.version_check import UNKNOWN
from infra_vuln_watch.domain.identity import finding_id, inventory_id


def required_env(name):
    value = os.environ.get(name)
    if not value or not value.strip():
        raise ValueError(f'{name} must be set for an enabled destination; use --dry-run to preview')
    return value


class OutputRouter:
    def __init__(self, items, dry_run=False):
        self.routes = {}
        trackers = {}
        slacks = {}
        states = {}
        for item in items:
            config = item['config']
            preview = dry_run or config['scan']['dry_run']
            route = {'preview': preview, 'trackers': [], 'slack': None}
            self.routes[inventory_id(item)] = route
            if preview:
                continue
            for kind in ('github', 'jira'):
                settings = config['outputs'][kind]
                if not settings['enabled']:
                    continue
                key = (kind, json.dumps(settings))
                if key not in trackers:
                    if kind == 'github':
                        repository = settings['repository'] or required_env('GITHUB_REPOSITORY')
                        client = github_client.GitHubClient(required_env(settings['token_env']), repository, config=settings)
                    else:
                        client = jira_client.JiraClient(required_env(settings['email_env']),
                                                       required_env(settings['token_env']), settings)
                    trackers[key] = {'kind': kind, 'client': client, 'reported': set(), 'tools': [], 'deployments': []}
                trackers[key]['tools'].append(item['name'])
                if item.get('deployment_id'):
                    trackers[key]['deployments'].append(item['deployment_id'])
                route['trackers'].append(trackers[key])
            settings = config['notifications']['slack']
            if settings['enabled']:
                key = json.dumps(settings)
                if key not in slacks:
                    state = None
                    if not settings['repeat']:
                        path = str(Path(settings['state_file']).resolve())
                        if path not in states:
                            states[path] = DeliveryState(path)
                        state = states[path]
                    slacks[key] = slack_client.SlackClient(required_env(settings['webhook_env']), settings, state=state)
                route['slack'] = slacks[key]
        # Validate every credential and local state before the first remote mutation.
        for tracker in trackers.values():
            try:
                if tracker['kind'] == 'github':
                    if tracker['deployments']:
                        tracker['client'].create_missing_labels(tracker['tools'], deployment_ids=tracker['deployments'])
                    else:
                        tracker['client'].create_missing_labels(tracker['tools'])
                tracker['reported'] = tracker['client'].get_reported_ids()
            except (requests.RequestException, KeyError, TypeError, ValueError):
                raise requests.RequestException(f"Could not initialise {tracker['kind']} reporting history") from None

    def needs_reporting(self, item, cve):
        route = self.routes[inventory_id(item)]
        marker = finding_id(item, cve)
        return (route['preview'] or (not route['trackers'] and route['slack'] is None)
                or any(marker not in tracker['reported'] for tracker in route['trackers'])
                or (route['slack'] is not None and route['slack'].needs_delivery(marker)))

    def report(self, item, cve, result, risk):
        route = self.routes[inventory_id(item)]
        marker = finding_id(item, cve)
        title = issue_format.make_title(item, cve)
        if route['preview']:
            channels = [name for name, value in item['config']['outputs'].items() if value['enabled']]
            if item['config']['notifications']['slack']['enabled']:
                channels.append('slack')
            print(f"  [dry run; {', '.join(channels) or 'console'}] {title}")
            return True
        if not route['trackers'] and route['slack'] is None:
            print(f'  [console] {title}')
            return True
        if not self.needs_reporting(item, cve):
            print(f"  Already reported: {cve['id']}")
            return True
        severity = cve_details.get_score(cve)['severity']
        labels = [github_client.MAIN_LABEL, github_client.severity_label(severity), github_client.tool_label(item['name'])]
        if item.get('deployment_id'):
            labels.append(github_client.deployment_label(item['deployment_id']))
        if result['status'] == UNKNOWN:
            labels.append(github_client.REVIEW_LABEL)
        if risk_data.find_kev_entry(cve, risk['kev'], allow_nvd=risk.get('allow_nvd_kev', True)):
            labels.append(github_client.KNOWN_EXPLOITED_LABEL)
        body = issue_format.make_body(item, cve, result, risk)
        links = [f"https://nvd.nist.gov/vuln/detail/{cve['id']}"]
        success = True
        for tracker in route['trackers']:
            if marker in tracker['reported']:
                continue
            try:
                url = tracker['client'].create_issue(title, body, labels)
                tracker['reported'].add(marker)
                links.append(url)
                print(f"  Opened {tracker['kind']}: {url}")
            except (requests.RequestException, KeyError, TypeError, ValueError):
                print(f"  FAILED: {tracker['kind']} delivery for {cve['id']}")
                success = False
        slack = route['slack']
        if slack is not None and slack.needs_delivery(marker):
            try:
                slack.send(marker, title, links)
                print(f"  Sent Slack notification for {cve['id']}")
            except (requests.RequestException, OSError):
                print(f"  FAILED: Slack delivery or receipt persistence for {cve['id']}")
                success = False
        return success
