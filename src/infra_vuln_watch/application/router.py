"""Independently route findings to configured trackers and Slack."""

import json
import os
from pathlib import Path
from typing import Any

import requests

from infra_vuln_watch.application.ticket_updates import plan_update
from infra_vuln_watch.clients import github_client, jira_client, slack_client
from infra_vuln_watch.clients.rate_limit import RateLimited
from infra_vuln_watch.domain import cve_details
from infra_vuln_watch.reporting import issue_format
from infra_vuln_watch.persistence.state import DeliveryState
from infra_vuln_watch.domain import ignore_list
from infra_vuln_watch.domain.version_check import UNKNOWN, check_version
from infra_vuln_watch.domain.identity import finding_id, inventory_id


def required_env(name):
    value = os.environ.get(name)
    if not value or not value.strip():
        raise ValueError(f'{name} must be set for an enabled destination; use --dry-run to preview')
    return value


class OutputRouter:
    def __init__(self, items, dry_run=False):
        self.routes = {}
        # Destinations that are still rate limiting us get no more requests this run.
        self.limited = set()
        self.notified_updates = set()
        trackers: dict[tuple[str, str], dict] = {}
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
                tracker_key = (kind, json.dumps(settings))
                if tracker_key not in trackers:
                    if kind == 'github':
                        repository = settings['repository'] or required_env('GITHUB_REPOSITORY')
                        client: Any = github_client.GitHubClient(required_env(settings['token_env']), repository, config=settings)
                    else:
                        client = jira_client.JiraClient(required_env(settings['email_env']),
                                                       required_env(settings['token_env']), settings)
                    trackers[tracker_key] = {'kind': kind, 'client': client, 'reported': set(), 'tools': [], 'deployments': []}
                trackers[tracker_key]['tools'].append(item['name'])
                if item.get('deployment_id'):
                    trackers[tracker_key]['deployments'].append(item['deployment_id'])
                route['trackers'].append(trackers[tracker_key])
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
                or self.slack_pending(route, marker))

    @staticmethod
    def slack_pending(route, marker):
        """Return True if Slack still needs this finding, by local receipt or by ticket label.

        A ticket label outlives a lost receipt file, so a lost cache cannot repeat notifications.
        """
        slack = route['slack']
        if slack is None or not slack.needs_delivery(marker):
            return False
        if slack.state is None:
            return True  # Repeat mode notifies on every run.
        return not any(slack.receipt_label in tracker['client'].all_findings.get(marker, {}).get('labels', ())
                       for tracker in route['trackers'])

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
        if cve_details.find_kev_entry(cve, risk['kev'], allow_nvd=risk.get('allow_nvd_kev', True)):
            labels.append(github_client.KNOWN_EXPLOITED_LABEL)
        body = issue_format.make_body(item, cve, result, risk)
        links = [f"https://nvd.nist.gov/vuln/detail/{cve['id']}"]
        success = True
        for tracker in route['trackers']:
            if id(tracker) in self.limited and marker not in tracker['reported']:
                print(f"  SKIPPED: {tracker['kind']} is rate limited, so {cve['id']} waits for the next scan")
                success = False
                continue
            if marker in tracker['reported']:
                # A retried Slack notification should still point at the existing ticket.
                existing = tracker['client'].reported_links.get(marker)
                if existing:
                    links.append(existing)
                continue
            try:
                url = tracker['client'].create_issue(title, body, labels)
                tracker['reported'].add(marker)
                tracker['client'].all_findings[marker] = {'ref': tracker['client'].ref_from_url(url), 'labels': list(labels)}
                links.append(url)
                print(f"  Opened {tracker['kind']}: {url}")
            except RateLimited:
                self.limited.add(id(tracker))
                print(f"  FAILED: {tracker['kind']} is rate limiting us, so no more will be sent this run")
                success = False
            except (requests.RequestException, KeyError, TypeError, ValueError):
                print(f"  FAILED: {tracker['kind']} delivery for {cve['id']}")
                success = False
        slack = route['slack']
        if id(slack) in self.limited and self.slack_pending(route, marker):
            print(f"  SKIPPED: Slack is rate limited, so {cve['id']} waits for the next scan")
            success = False
        elif self.slack_pending(route, marker):
            try:
                slack.send(marker, title, links)
                print(f"  Sent Slack notification for {cve['id']}")
                if slack.state is not None:
                    self.label_slack_delivery(route, marker)
            except RateLimited:
                self.limited.add(id(slack))
                print('  FAILED: Slack is rate limiting us, so no more will be sent this run')
                success = False
            except (requests.RequestException, OSError):
                print(f"  FAILED: Slack delivery or receipt persistence for {cve['id']}")
                success = False
        return success

    def label_slack_delivery(self, route, marker):
        """Record a delivered notification on its tickets. Failure only risks a later repeat."""
        slack = route['slack']
        for tracker in route['trackers']:
            record = tracker['client'].all_findings.get(marker)
            if record is None or slack.receipt_label in record['labels'] or id(tracker) in self.limited:
                continue
            try:
                tracker['client'].update_ticket(record, add_labels=[slack.receipt_label])
                record['labels'] = [*record['labels'], slack.receipt_label]
            except RateLimited:
                self.limited.add(id(tracker))
                print(f"  WARNING: {tracker['kind']} is rate limiting us, so Slack delivery labels wait for the next scan")
            except (requests.RequestException, KeyError, TypeError, ValueError):
                print(f"  WARNING: could not record Slack delivery on the {tracker['kind']} ticket for {marker}")

    def backfill_slack_labels(self, item):
        """Label tickets whose notification is only recorded in the local receipt file."""
        route = self.routes[inventory_id(item)]
        slack = route['slack']
        if route['preview'] or slack is None or slack.state is None:
            return
        for tracker in route['trackers']:
            for marker in list(tracker['client'].all_findings):
                if marker.rpartition('/')[0] == inventory_id(item) and not slack.needs_delivery(marker):
                    self.label_slack_delivery(route, marker)

    def notify_update(self, item, route, marker, title, note, link):
        """Tell Slack once per run about a ticket update, and return False if that failed."""
        slack = route['slack']
        settings = item['config']['notifications']['slack']
        if slack is None or not settings['notify_updates'] or (marker, note) in self.notified_updates:
            return True
        self.notified_updates.add((marker, note))
        if id(slack) in self.limited:
            print(f'  SKIPPED: Slack is rate limited, so the update for {marker} is only on the ticket')
            return False
        try:
            slack.notify_update(title, note, [link] if link else [])
            print(f'  Sent Slack update for {marker}')
            return True
        except RateLimited:
            self.limited.add(id(slack))
            print('  FAILED: Slack is rate limiting us, so no more will be sent this run')
        except requests.RequestException:
            print(f'  FAILED: Slack update for {marker}; the change is still on the ticket')
        return False

    def update_existing(self, item, candidates, kev, today):
        """Bring this target's open tickets up to date, and return False if any update failed."""
        route = self.routes[inventory_id(item)]
        if route['preview'] or not item['config']['scan']['update_existing']:
            return True
        success = True
        by_id = {cve['id']: cve for cve in candidates}
        for tracker in route['trackers']:
            for marker, record in tracker['client'].open_findings.items():
                scope, _, cve_id = marker.rpartition('/')
                if scope != inventory_id(item) or ignore_list.is_ignored(cve_id, item['config']['scan']['ignore_cves'], today):
                    continue
                plan = self.plan_for(item, record, by_id.get(cve_id), kev, today)
                if plan is None:
                    continue
                if id(tracker) in self.limited:
                    print(f"  SKIPPED: {tracker['kind']} is rate limited, so {cve_id} is not updated")
                    success = False
                    continue
                try:
                    tracker['client'].update_ticket(record, **plan)
                    print(f"  Updated {tracker['kind']} ticket for {cve_id}")
                    if not self.notify_update(item, route, marker, plan['title'] or record['title'], plan['comment'],
                                              tracker['client'].reported_links.get(marker)):
                        success = False
                except RateLimited:
                    self.limited.add(id(tracker))
                    print(f"  FAILED: {tracker['kind']} is rate limiting us, so no more will be sent this run")
                    success = False
                except (requests.RequestException, KeyError, TypeError, ValueError):
                    print(f"  FAILED: {tracker['kind']} update for {cve_id}")
                    success = False
        return success

    @staticmethod
    def plan_for(item, record, cve, kev, today):
        """Plan a ticket update. A CVE that is missing, rejected or unreadable only has its date checked."""
        if cve is not None and cve.get('vulnStatus') != 'Rejected':
            try:
                result = check_version(cve, item['vendor'], item['product'], item['version'],
                                       aliases=item.get('aliases', ()), keyword=item.get('keyword'))
                return plan_update(
                    record, today, item['version'], score=cve_details.get_score(cve), status=result['status'],
                    known_exploited=bool(cve_details.find_kev_entry(
                        cve, kev, allow_nvd=item['config']['sources']['kev']['nvd_fallback'])),
                    new_title=issue_format.make_title(item, cve),
                )
            except (AttributeError, KeyError, TypeError, ValueError):
                pass
        return plan_update(record, today, item['version'])
