"""Run the real CLI and clients against fake services, replacing only the HTTP transport.

Nothing here reaches a network. An unexpected address raises an assertion, so these tests also
prove which services each scan contacts. The fake Jira rejects ADF that the real one would reject.
"""

from datetime import date, datetime, timedelta, timezone
import io
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from infra_vuln_watch.cli import main

WEBHOOK = 'https://hooks.slack.com/services/T000/B000/mock-webhook-secret'
GITHUB_TOKEN = 'mock-github-token'
JIRA_TOKEN = 'mock-jira-token'
NVD_KEY = 'mock-nvd-key'
SECRETS = ['mock-webhook-secret', GITHUB_TOKEN, JIRA_TOKEN, NVD_KEY]
TODAY = datetime.now(timezone.utc).date()


def make_cve(identifier, score=7.5, end='2.0.0', **extra):
    return {
        'id': identifier,
        'vulnStatus': 'Awaiting Analysis',
        'published': '2026-10-01T00:00:00.000',
        'lastModified': '2026-10-02T00:00:00.000',
        'sourceIdentifier': 'cna@example.test',
        'descriptions': [{'lang': 'en', 'value': f'Tool before {end} leaks keys to @someone, see owner/repo#12.'}],
        'metrics': {'cvssMetricV31': [{'type': 'Secondary', 'cvssData': {
            'version': '3.1', 'baseScore': score, 'vectorString': 'CVSS:3.1/AV:N', 'attackVector': 'NETWORK'}}]},
        'affected': [{'affectedData': [{'vendor': 'acme', 'product': 'tool', 'versions': [
            {'version': '0', 'lessThan': end, 'status': 'affected'}]}]}],
        'references': [{'url': 'https://github.com/acme/tool/security/advisories/GHSA-1'}],
        **extra,
    }


def validate_adf(node):
    """Apply the ADF rules that Jira enforces and a formatter could plausibly break."""
    if node['type'] == 'text' and not node.get('text'):
        return False
    if node['type'] in {'tableCell', 'tableHeader', 'listItem', 'panel'} and not node.get('content'):
        return False
    if node['type'] == 'heading' and node['attrs']['level'] not in range(1, 7):
        return False
    return all(validate_adf(child) for child in node.get('content', []))


class Services:
    """In-memory GitHub, Jira, Slack, NVD, EPSS and CISA KEV."""

    def __init__(self):
        self.cves = [make_cve('CVE-2026-0001')]
        self.kev = []
        self.calls = []
        self.issues = []
        self.comments = []
        self.labels = set()
        self.tickets = []
        self.jira_comments = []
        self.slack = []
        self.slack_responses = []
        self.github_create_responses = []
        self.jira_reject_rich = False
        self.jira_create_attempts = []

    def handle(self, request):
        url = urlsplit(request.url)
        self.calls.append((request.method, url.hostname))
        handler = {
            'services.nvd.nist.gov': self.nvd, 'api.first.org': self.epss, 'www.cisa.gov': self.cisa,
            'api.github.com': self.github, 'mock.atlassian.net': self.jira, 'hooks.slack.com': self.slack_hook,
        }.get(url.hostname)
        assert handler, f'unexpected request to {request.url}'
        status, data, headers = handler(request, url)
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers)
        response.url = request.url
        response.request = request
        response._content = data if isinstance(data, bytes) else json.dumps(data).encode()
        response.raw = io.BytesIO()
        return response

    def nvd(self, request, url):
        assert request.headers['apiKey'] == NVD_KEY
        return 200, {'resultsPerPage': len(self.cves), 'totalResults': len(self.cves),
                     'vulnerabilities': [{'cve': cve} for cve in self.cves]}, {}

    def epss(self, request, url):
        wanted = parse_qs(url.query)['cve'][0].split(',')
        return 200, {'data': [{'cve': cve, 'epss': '0.5', 'percentile': '0.9'} for cve in wanted]}, {}

    def cisa(self, request, url):
        return 200, {'vulnerabilities': [{'cveID': cve, 'dateAdded': '2026-11-01'} for cve in self.kev]}, {}

    def github(self, request, url):
        assert request.headers['Authorization'] == f'Bearer {GITHUB_TOKEN}'
        path = url.path.removeprefix('/repos/acme/scans/')
        body = json.loads(request.body) if request.body else {}
        if request.method == 'GET' and path == 'labels':
            return 200, [{'name': name} for name in self.labels], {}
        if request.method == 'POST' and path == 'labels':
            self.labels.add(body['name'])
            return 201, {}, {}
        if request.method == 'GET' and path == 'issues':
            return 200, self.issues, {}
        if request.method == 'POST' and path == 'issues':
            if self.github_create_responses:
                status, headers = self.github_create_responses.pop(0)
                return status, {'message': 'limited'}, headers
            number = len(self.issues) + 1
            self.issues.append({'number': number, 'state': 'open', 'title': body['title'], 'body': body['body'],
                                'labels': [{'name': name} for name in body['labels']],
                                'html_url': f'https://github.com/acme/scans/issues/{number}'})
            return 201, self.issues[-1], {}
        match = re.fullmatch(r'issues/(\d+)(?:/(comments|labels)(?:/(.+))?)?', path)
        assert match, f'unexpected GitHub request {request.method} {path}'
        issue = self.issues[int(match[1]) - 1]
        if match[2] == 'comments':
            self.comments.append((issue['number'], body['body']))
        elif match[2] == 'labels' and request.method == 'POST':
            issue['labels'] += [{'name': name} for name in body['labels']]
        elif match[2] == 'labels':
            issue['labels'] = [label for label in issue['labels'] if label['name'] != match[3]]
        else:
            issue['title'] = body['title']
        return 200, {}, {}

    def jira(self, request, url):
        assert request.headers['Authorization'].startswith('Basic ')
        body = json.loads(request.body) if request.body else {}
        if request.method == 'GET':
            return 200, {'issues': self.tickets, 'isLast': True}, {}
        if request.method == 'POST' and url.path == '/rest/api/3/issue':
            description = body['fields']['description']
            self.jira_create_attempts.append(description)
            if not validate_adf(description):
                return 400, {'errors': {'description': 'invalid ADF'}}, {}
            if self.jira_reject_rich and any(node['type'] != 'paragraph' for node in description['content']):
                return 400, {'errors': {'description': 'too long'}}, {}
            key = f'SEC-{len(self.tickets) + 1}'
            self.tickets.append({'key': key, 'fields': {**body['fields'], 'status': {'statusCategory': {'key': 'new'}}}})
            return 201, {'key': key}, {}
        key = url.path.split('/')[5]
        ticket = next(ticket for ticket in self.tickets if ticket['key'] == key)
        if url.path.endswith('/comment'):
            self.jira_comments.append((key, body['body']))
            return 201, {}, {}
        for change in body.get('update', {}).get('labels', []):
            if 'add' in change:
                ticket['fields']['labels'].append(change['add'])
            else:
                ticket['fields']['labels'].remove(change['remove'])
        ticket['fields'].update(body.get('fields', {}))
        return 204, {}, {}

    def slack_hook(self, request, url):
        assert url.path == urlsplit(WEBHOOK).path
        if self.slack_responses:
            status, headers = self.slack_responses.pop(0)
            return status, b'rate_limited', headers
        self.slack.append(json.loads(request.body))
        return 200, b'ok', {}

    def output_calls(self):
        hosts = {'api.github.com', 'mock.atlassian.net', 'hooks.slack.com'}
        return [call for call in self.calls if call[1] in hosts]


@pytest.fixture
def services(monkeypatch):
    fake = Services()
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', lambda adapter, request, **kwargs: fake.handle(request))
    return fake


@pytest.fixture
def waits(monkeypatch):
    slept = []
    monkeypatch.setattr('time.sleep', slept.append)
    return slept


@pytest.fixture
def scan(tmp_path, monkeypatch, services, waits, capsys):
    """Return a function that runs the CLI and gives back (exit code, printed output)."""
    for name, value in {'GITHUB_TOKEN': GITHUB_TOKEN, 'GITHUB_REPOSITORY': 'acme/scans', 'JIRA_EMAIL': 'me@example.test',
                        'JIRA_API_TOKEN': JIRA_TOKEN, 'SLACK_WEBHOOK_URL': WEBHOOK, 'NVD_API_KEY': NVD_KEY}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    inventory = tmp_path / 'inventory'
    inventory.mkdir()

    def run(version='1.0.0', extra=(), config=''):
        (inventory / 'tool.yaml').write_text(
            f'tool:\n  name: tool\n  repo: acme/tool\n  vendor: acme\n  product: tool\n  team: sre\n  owner: me\n'
            f'deployments:\n  - id: production\n    environment: production\n    version: "{version}"\n')
        settings = tmp_path / 'settings.yaml'
        settings.write_text(
            'outputs:\n  jira:\n    enabled: true\n    base_url: https://mock.atlassian.net\n    project: SEC\n'
            'notifications:\n  slack:\n    enabled: true\n' + config)
        code = main.main(['--inventory', str(inventory), '--config', str(settings), *extra])
        output = capsys.readouterr().out
        for secret in SECRETS:
            assert secret not in output
        return code, output
    return run


def labels_of(issue):
    return {label['name'] for label in issue['labels']}


def text_of(payload):
    return payload['blocks'][0]['text']['text']


def test_first_scan_delivers_to_github_jira_and_slack(scan, services, tmp_path):
    code, output = scan()
    assert code == 0
    assert 'Opened github' in output and 'Opened jira' in output and 'Sent Slack' in output

    issue, = services.issues
    assert issue['title'].startswith('[HIGH] [PROD] [7.5] CVE-2026-0001 tool -')
    assert {'vuln-watch', 'severity-high', 'tool-tool', 'deployment-production'} <= labels_of(issue)
    assert '<!-- vuln-watch-id: tool/production/CVE-2026-0001 -->' in issue['body']
    assert '@someone' not in issue['body'] and 'owner/repo#12' not in issue['body']

    ticket, = services.tickets
    assert ticket['fields']['project'] == {'key': 'SEC'}
    assert 'panel' in [node['type'] for node in ticket['fields']['description']['content']]

    message, = services.slack
    assert message['mrkdwn'] is False
    assert message['blocks'][0]['text']['type'] == 'plain_text'
    assert 'https://github.com/acme/scans/issues/1' in text_of(message)
    assert 'https://mock.atlassian.net/browse/SEC-1' in text_of(message)

    saved = (tmp_path / '.vuln-watch' / 'slack.json').read_text()
    assert 'tool/production/CVE-2026-0001' in saved and 'mock-webhook-secret' not in saved


def test_second_scan_creates_and_sends_nothing_new(scan, services):
    scan()
    code, output = scan()
    assert code == 0
    assert (len(services.issues), len(services.tickets), len(services.slack)) == (1, 1, 1)
    assert 'Already reported' in output


def test_dry_run_calls_no_output_service_and_writes_no_receipt(scan, services, tmp_path):
    code, output = scan(extra=['--dry-run'])
    assert code == 0
    assert '[dry run; github, jira, slack]' in output
    assert services.output_calls() == []
    assert not (tmp_path / '.vuln-watch' / 'slack.json').exists()


def test_slack_failure_fails_the_run_keeps_tickets_and_retries_with_their_links(scan, services, tmp_path):
    services.slack_responses = [(500, {})]
    code, output = scan()
    assert code == 1
    assert 'FAILED: Slack delivery' in output
    assert (len(services.issues), len(services.tickets), len(services.slack)) == (1, 1, 0)
    assert not (tmp_path / '.vuln-watch' / 'slack.json').exists()

    code, _ = scan()
    assert code == 0
    assert (len(services.issues), len(services.tickets)) == (1, 1)
    message, = services.slack
    assert 'https://github.com/acme/scans/issues/1' in text_of(message)
    assert 'https://mock.atlassian.net/browse/SEC-1' in text_of(message)


def test_slack_rate_limit_waits_as_asked_then_succeeds(scan, services, waits):
    services.slack_responses = [(429, {'Retry-After': '17'})]
    code, _ = scan()
    assert code == 0
    assert 17 in waits
    assert len(services.slack) == 1


def test_slack_that_stays_rate_limited_gets_no_more_requests(scan, services):
    services.cves = [make_cve('CVE-2026-0001'), make_cve('CVE-2026-0002')]
    services.slack_responses = [(429, {'Retry-After': '1'}), (429, {'Retry-After': '1'})]
    code, output = scan()
    assert code == 1
    assert 'Slack is rate limiting' in output and 'SKIPPED: Slack' in output
    assert services.calls.count(('POST', 'hooks.slack.com')) == 2
    assert len(services.tickets) == 2


def test_github_rate_limit_stops_github_only_and_the_next_scan_catches_up(scan, services):
    services.cves = [make_cve('CVE-2026-0001'), make_cve('CVE-2026-0002')]
    services.github_create_responses = [(403, {'Retry-After': '100000'})]
    code, output = scan()
    assert code == 1
    assert 'github is rate limiting' in output and 'SKIPPED: github' in output
    assert services.issues == []
    assert len(services.tickets) == 2 and len(services.slack) == 2

    code, _ = scan()
    assert code == 0
    assert len(services.issues) == 2
    assert (len(services.tickets), len(services.slack)) == (2, 2)


def test_cve_joining_kev_later_updates_both_trackers_once(scan, services):
    scan()
    services.kev = ['CVE-2026-0001']
    code, output = scan()
    assert code == 0
    assert 'Updated github' in output and 'Updated jira' in output
    assert 'known-exploited' in labels_of(services.issues[0])
    assert 'known-exploited' in services.tickets[0]['fields']['labels']
    assert 'CISA KEV' in services.comments[0][1]
    assert services.jira_comments[0][0] == 'SEC-1'
    assert len(services.slack) == 2

    scan()
    assert len(services.comments) == 1 and len(services.jira_comments) == 1
    assert len(services.slack) == 2


def test_changed_score_updates_title_and_severity_label(scan, services):
    scan()
    services.cves = [make_cve('CVE-2026-0001', score=9.8)]
    assert scan()[0] == 0
    issue = services.issues[0]
    assert issue['title'].startswith('[CRITICAL] [PROD] [9.8] CVE-2026-0001')
    assert 'severity-critical' in labels_of(issue) and 'severity-high' not in labels_of(issue)
    fields = services.tickets[0]['fields']
    assert fields['summary'].startswith('[CRITICAL]')
    assert 'severity-critical' in fields['labels'] and 'severity-high' not in fields['labels']


def test_upgrade_flags_open_tickets_but_never_closes_them(scan, services):
    scan()
    assert scan(version='2.0.0')[0] == 0
    issue = services.issues[0]
    assert 'no-longer-affected' in labels_of(issue)
    assert issue['state'] == 'open'
    assert '`2.0.0`' in services.comments[0][1]
    assert 'no-longer-affected' in services.tickets[0]['fields']['labels']


def test_missed_fix_date_marks_tickets_overdue_even_if_nvd_stops_returning_the_cve(scan, services):
    scan()
    late = (TODAY - timedelta(days=1)).isoformat()
    services.issues[0]['body'] = re.sub(r'\*\*Fix by:\*\* \d{4}-\d{2}-\d{2}', f'**Fix by:** {late}', services.issues[0]['body'], count=1)
    services.cves = []
    assert scan()[0] == 0
    assert 'overdue' in labels_of(services.issues[0])
    assert late in services.comments[0][1]


def test_closed_tickets_are_left_alone(scan, services):
    scan()
    services.issues[0]['state'] = 'closed'
    services.tickets[0]['fields']['status'] = {'statusCategory': {'key': 'done'}}
    services.kev = ['CVE-2026-0001']
    assert scan()[0] == 0
    assert services.comments == [] and services.jira_comments == []


def test_update_existing_can_be_turned_off(scan, services):
    scan()
    services.kev = ['CVE-2026-0001']
    assert scan(config='scan:\n  update_existing: false\n')[0] == 0
    assert services.comments == [] and services.jira_comments == []


def test_ignored_cve_is_not_reported_or_updated_until_it_expires(scan, services):
    tomorrow = (TODAY + timedelta(days=1)).isoformat()
    ignore = f'scan:\n  ignore_cves:\n    - id: CVE-2026-0001\n      reason: Not deployed\n      expires: {tomorrow}\n'
    code, output = scan(config=ignore)
    assert code == 0
    assert f'Ignoring CVE-2026-0001 until {tomorrow}: Not deployed' in output
    assert services.issues == []

    yesterday = (TODAY - timedelta(days=1)).isoformat()
    code, output = scan(config=ignore.replace(tomorrow, yesterday))
    assert code == 0
    assert 'expired' in output
    assert len(services.issues) == 1


def test_jira_rejecting_a_formatted_ticket_falls_back_to_plain_text(scan, services):
    services.jira_reject_rich = True
    code, _ = scan()
    assert code == 0
    first, second = services.jira_create_attempts
    assert any(node['type'] == 'panel' for node in first['content'])
    assert {node['type'] for node in second['content']} == {'paragraph'}
    assert len(services.tickets) == 1


def test_every_formatted_ticket_passes_the_fake_jira_adf_rules(scan, services):
    services.jira_reject_rich = False
    services.cves = [make_cve('CVE-2026-0001', references=[]), make_cve('CVE-2026-0002', metrics={}),
                     make_cve('CVE-2026-0003', cisaExploitAdd=date(2026, 1, 1).isoformat())]
    assert scan()[0] == 0
    assert len(services.jira_create_attempts) == 3
    assert len(services.tickets) == 3


def slack_label(services):
    labels = [label for label in labels_of(services.issues[0]) if label.startswith('slack-')]
    assert len(labels) == 1
    return labels[0]


def test_delivery_is_recorded_on_tickets_without_revealing_the_webhook(scan, services):
    scan()
    label = slack_label(services)
    assert label in services.tickets[0]['fields']['labels']
    assert 'mock-webhook-secret' not in label


def test_lost_receipt_file_does_not_repeat_notifications(scan, services, tmp_path):
    scan()
    (tmp_path / '.vuln-watch' / 'slack.json').unlink()
    code, _ = scan()
    assert code == 0
    assert len(services.slack) == 1


def test_lost_receipt_file_does_not_repeat_for_a_closed_ticket(scan, services, tmp_path):
    scan()
    services.issues[0]['state'] = 'closed'
    services.tickets[0]['fields']['status'] = {'statusCategory': {'key': 'done'}}
    (tmp_path / '.vuln-watch' / 'slack.json').unlink()
    assert scan()[0] == 0
    assert len(services.slack) == 1


def test_failed_slack_delivery_leaves_no_label_and_still_retries(scan, services):
    services.slack_responses = [(500, {})]
    assert scan()[0] == 1
    assert not [label for label in labels_of(services.issues[0]) if label.startswith('slack-')]
    assert scan()[0] == 0
    assert len(services.slack) == 1
    assert slack_label(services)


def test_tickets_delivered_before_labels_existed_get_labelled_from_the_receipt(scan, services, tmp_path):
    scan()
    label = slack_label(services)
    services.issues[0]['labels'] = [item for item in services.issues[0]['labels'] if item['name'] != label]
    services.tickets[0]['fields']['labels'].remove(label)
    assert scan()[0] == 0
    assert len(services.slack) == 1
    assert slack_label(services) == label
    assert label in services.tickets[0]['fields']['labels']


def test_a_different_webhook_is_still_notified(scan, services, monkeypatch):
    scan()
    other = 'https://hooks.slack.com/services/T000/B000/mock-webhook-secret-2'
    monkeypatch.setenv('SLACK_WEBHOOK_URL', other)
    monkeypatch.setattr(Services, 'slack_hook', lambda self, request, url: (self.slack.append(json.loads(request.body)), (200, b'ok', {}))[1])
    assert scan()[0] == 0
    assert len(services.slack) == 2


def test_repeat_mode_ignores_ticket_labels_and_adds_none(scan, services):
    repeat = '    repeat: true\n'
    scan(config=repeat)
    assert not [label for label in labels_of(services.issues[0]) if label.startswith('slack-')]
    scan(config=repeat)
    assert len(services.slack) == 2


def test_failure_to_label_a_ticket_only_warns(scan, services):
    original = services.github

    def refuse_labels(request, url):
        if request.method == 'POST' and url.path.endswith('/labels') and 'issues' in url.path:
            return 500, {}, {}
        return original(request, url)
    services.github = refuse_labels
    code, output = scan()
    assert code == 0
    assert 'WARNING: could not record Slack delivery' in output


def test_slack_hears_about_a_ticket_update_once_across_both_trackers(scan, services):
    scan()
    services.kev = ['CVE-2026-0001']
    assert scan()[0] == 0
    update = services.slack[-1]
    assert len(services.slack) == 2
    text = text_of(update)
    assert text.startswith('Updated: [HIGH] [PROD] [7.5] CVE-2026-0001')
    assert 'CISA KEV' in text
    assert 'https://github.com/acme/scans/issues/1' in text
    assert update['blocks'][0]['text']['type'] == 'plain_text'


def test_slack_update_shows_the_new_title_when_the_score_changes(scan, services):
    scan()
    services.cves = [make_cve('CVE-2026-0001', score=9.8)]
    assert scan()[0] == 0
    assert text_of(services.slack[-1]).startswith('Updated: [CRITICAL] [PROD] [9.8]')


def test_slack_update_notifications_can_be_turned_off(scan, services):
    scan()
    services.kev = ['CVE-2026-0001']
    assert scan(config='    notify_updates: false\n')[0] == 0
    assert len(services.slack) == 1
    assert services.comments


def test_failed_slack_update_fails_the_run_but_keeps_the_ticket_change(scan, services):
    scan()
    services.kev = ['CVE-2026-0001']
    services.slack_responses = [(500, {})]
    code, output = scan()
    assert code == 1
    assert 'FAILED: Slack update' in output
    assert 'known-exploited' in labels_of(services.issues[0])


def test_dry_run_sends_no_slack_update(scan, services):
    scan()
    services.kev = ['CVE-2026-0001']
    calls = len(services.output_calls())
    assert scan(extra=['--dry-run'])[0] == 0
    assert len(services.output_calls()) == calls
