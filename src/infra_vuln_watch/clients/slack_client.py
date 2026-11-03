"""Slack incoming webhooks with plain-text messages and redacted errors."""

from hashlib import sha256
import time
from urllib.parse import urlsplit

import requests

from infra_vuln_watch.persistence.state import DeliveryState


class SlackClient:
    def __init__(self, webhook, config, state=None):
        try:
            parsed = urlsplit(webhook)
            valid = (parsed.scheme == 'https' and parsed.hostname in {'hooks.slack.com', 'hooks.slack-gov.com'}
                     and parsed.path.startswith('/services/') and not parsed.username and not parsed.password
                     and not parsed.query and not parsed.fragment)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError('Slack webhook environment variable must contain a Slack HTTPS incoming webhook URL')
        self.webhook = webhook
        self.config = config
        self.destination = sha256(webhook.encode()).hexdigest()
        self.state = None if config['repeat'] else (state or DeliveryState(config['state_file']))

    def receipt(self, marker):
        return f'{self.destination}/{marker}'

    def needs_delivery(self, marker):
        return self.state is None or self.receipt(marker) not in self.state.delivered

    def send(self, marker, title, links):
        text = '\n'.join([title, *links, 'This product uses the NVD API but is not endorsed or certified by the NVD.'])
        # Plain-text blocks prevent untrusted CVE text from becoming Slack mentions or markup.
        fallback = title.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        payload = {'text': fallback, 'mrkdwn': False, 'blocks': [
            {'type': 'section', 'text': {'type': 'plain_text', 'text': text[:3000], 'emoji': False}}
        ], 'unfurl_links': False, 'unfurl_media': False}
        time.sleep(self.config['send_wait'])
        try:
            response = requests.post(self.webhook, json=payload, timeout=self.config['timeout'], allow_redirects=False)
            response.raise_for_status()
            if response.status_code != 200 or response.text.strip() != 'ok':
                raise requests.RequestException('Slack rejected the notification')
        except requests.RequestException:
            # requests errors contain the secret URL; never propagate them to CLI output.
            raise requests.RequestException('Slack delivery failed; check webhook, permissions and rate limits') from None
        if self.state is not None:
            self.state.remember(self.receipt(marker))
