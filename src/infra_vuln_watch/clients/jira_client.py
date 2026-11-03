"""Jira Cloud REST v3 ticket creation and reporting history."""

import re
import time

import requests

MARKER = re.compile(r'<!-- vuln-watch-id: (\S+) -->')


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
    """Keep untrusted Markdown as plain text; never construct mentions or executable markup."""
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

    def get_reported_ids(self):
        reported = set()
        token = None
        seen_tokens = set()
        while True:
            params = {'jql': f'project = "{self.config["project"]}" AND labels = "vuln-watch"',
                      'fields': 'description', 'maxResults': 100}
            if token:
                params['nextPageToken'] = token
            response = requests.get(f'{self.base_url}/rest/api/3/search/jql', params=params,
                                    auth=self.auth, headers=self.headers, timeout=self.config['timeout'])
            response.raise_for_status()
            try:
                page = response.json()
                issues = page['issues']
                if not isinstance(issues, list) or type(page['isLast']) is not bool:
                    raise ValueError('invalid Jira search response')
                for issue in issues:
                    reported.update(MARKER.findall(adf_text(issue['fields'].get('description'))))
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
        response = requests.post(f'{self.base_url}/rest/api/3/issue', json={'fields': fields},
                                 auth=self.auth, headers=self.headers, timeout=self.config['timeout'])
        response.raise_for_status()
        try:
            key = response.json()['key']
            if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*-\d+', key):
                raise ValueError('invalid issue key')
        except (KeyError, TypeError, ValueError) as error:
            raise requests.RequestException('Jira did not return a valid created ticket key') from error
        return f'{self.base_url}/browse/{key}'
