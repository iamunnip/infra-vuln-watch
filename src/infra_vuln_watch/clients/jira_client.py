"""Jira Cloud REST v3 ticket creation and reporting history."""

import re
import time

import requests

from infra_vuln_watch.clients.rate_limit import send
from infra_vuln_watch.domain.fix_deadline import read_fix_date
from infra_vuln_watch.domain.identity import MARKER_PATTERN
from infra_vuln_watch.reporting.jira_format import markdown_to_adf


def adf_text(value):
    """Extract plain text recursively from a Jira Atlassian Document Format document."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return '\n'.join(adf_text(child) for child in value)
    if isinstance(value, dict):
        return value.get('text', '') + adf_text(value.get('content', []))
    return ''


def description_document(body):
    """Format the finding for Jira. Untrusted text never becomes mentions or executable markup."""
    return markdown_to_adf(body)


def plain_document(body):
    """Keep the finding as plain text, for when Jira will not accept the formatted version."""
    return {'type': 'doc', 'version': 1, 'content': [
        {'type': 'paragraph', 'content': [{'type': 'text', 'text': line}]} if line
        else {'type': 'paragraph', 'content': []}
        for line in body.splitlines()
    ]}


class JiraClient:
    def __init__(self, email, token, config):
        self.config = config
        self.base_url = config['base_url'].rstrip('/')
        self.auth = (email, token)
        self.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        self.reported_links = {}
        self.open_findings = {}

    def request(self, method, path, **kwargs):
        """Send one request, waiting once if Jira asks, and return the response unchecked."""
        return send(lambda: getattr(requests, method.lower())(
            f'{self.base_url}{path}', auth=self.auth, headers=self.headers,
            timeout=self.config['timeout'], **kwargs,
        ), self.config['max_rate_limit_wait'])

    def get_reported_ids(self):
        reported = set()
        token = None
        seen_tokens = set()
        while True:
            params: dict = {'jql': f'project = "{self.config["project"]}" AND labels = "vuln-watch"',
                      'fields': 'description,summary,labels,status', 'maxResults': 100}
            if token:
                params['nextPageToken'] = token
            response = self.request('GET', '/rest/api/3/search/jql', params=params)
            response.raise_for_status()
            try:
                page = response.json()
                issues = page['issues']
                if not isinstance(issues, list) or type(page['isLast']) is not bool:
                    raise ValueError('invalid Jira search response')
                for issue in issues:
                    fields = issue['fields']
                    description = adf_text(fields.get('description'))
                    for marker in MARKER_PATTERN.findall(description):
                        reported.add(marker)
                        if issue.get('key'):
                            self.reported_links[marker] = f"{self.base_url}/browse/{issue['key']}"
                            if ((fields.get('status') or {}).get('statusCategory') or {}).get('key') != 'done':
                                self.open_findings[marker] = {
                                    'ref': issue['key'],
                                    'title': fields.get('summary') or '',
                                    'labels': fields.get('labels') or [],
                                    'fix_by': read_fix_date(description),
                                }
                if page['isLast']:
                    return reported
                token = page.get('nextPageToken')
                if not isinstance(token, str) or not token or token in seen_tokens:
                    raise ValueError('Jira search did not advance')
                seen_tokens.add(token)
            except (KeyError, TypeError, ValueError) as error:
                raise requests.RequestException('Jira returned invalid reporting history') from error

    def create_issue(self, title, body, labels):
        fields = {**self.config['fields'], 'project': {'key': self.config['project']},
                  'issuetype': {'name': self.config['issue_type']}, 'summary': title[:255],
                  'description': description_document(body), 'labels': labels}
        time.sleep(self.config['create_wait'])
        response = self.request('POST', '/rest/api/3/issue', json={'fields': fields})
        if response.status_code == 400:
            # A rejected request created nothing, so a plain text retry cannot duplicate the ticket.
            fields['description'] = plain_document(body)
            response = self.request('POST', '/rest/api/3/issue', json={'fields': fields})
        response.raise_for_status()
        try:
            key = response.json()['key']
            if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*-\d+', key):
                raise ValueError('invalid issue key')
        except (KeyError, TypeError, ValueError) as error:
            raise requests.RequestException('Jira did not return a valid created ticket key') from error
        return f'{self.base_url}/browse/{key}'

    def update_ticket(self, record, add_labels=(), remove_labels=(), title=None, comment=None):
        """Apply a planned update. The comment goes first, because the labels stop it repeating."""
        path = f"/rest/api/3/issue/{record['ref']}"
        time.sleep(self.config['create_wait'])
        if comment:
            self.request('POST', f'{path}/comment', json={'body': plain_document(comment)}).raise_for_status()
        changes = {}
        if add_labels or remove_labels:
            changes['update'] = {'labels': [*({'add': label} for label in add_labels),
                                            *({'remove': label} for label in remove_labels)]}
        if title:
            changes['fields'] = {'summary': title[:255]}
        if changes:
            self.request('PUT', path, json=changes).raise_for_status()
