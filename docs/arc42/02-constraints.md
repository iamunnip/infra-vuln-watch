# 2. Constraints

- Runs on GitHub Actions or locally with no server and no database.
- Optional Slack receipts use persistent file storage, through an Actions cache in the workflow. Tickets also record delivery, so only Slack without a tracker depends on that storage.
- Python, with few libraries.
- NVD rate limits: 5 requests per 30 seconds, or 50 with a key.
- Must show the NVD attribution notice.

[Architecture index](README.md)
