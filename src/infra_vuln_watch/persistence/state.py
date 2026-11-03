"""Atomic local delivery receipts for Slack, separate from tracker-owned ticket history."""

import json
import os
from pathlib import Path
import tempfile


class DeliveryState:
    def __init__(self, path):
        self.path = Path(path)
        try:
            if self.path.exists():
                data = json.loads(self.path.read_text(encoding='utf-8'))
                if (not isinstance(data, dict) or data.get('version') != 1
                        or not isinstance(data.get('delivered'), list)
                        or any(not isinstance(key, str) for key in data['delivered'])):
                    raise ValueError('invalid delivery state format')
                self.delivered = set(data['delivered'])
            else:
                self.delivered = set()
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except (OSError, UnicodeError, ValueError) as error:
            raise ValueError(f'Could not load Slack delivery state: {self.path}') from error

    def remember(self, key):
        delivered = self.delivered | {key}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.path.parent,
                                             prefix='.delivery-', delete=False) as file:
                temporary = file.name
                json.dump({'version': 1, 'delivered': sorted(delivered)}, file)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.path)
            self.delivered = delivered
        finally:
            if temporary and Path(temporary).exists():
                Path(temporary).unlink()
