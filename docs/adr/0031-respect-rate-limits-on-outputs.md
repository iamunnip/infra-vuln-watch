# 0031. Respect rate limits on outputs

Date: 2026-11-03

Status: Accepted

## Context

GitHub, Jira and Slack can answer with a 429, or GitHub with a 403, when asked to slow down. The scanner
treated this as an ordinary failure and went on to the next finding. A large first scan therefore kept
sending requests to a service that had asked it to stop, which GitHub can punish with longer blocks.

## Decision

- Recognise a 429, or a 403 with `Retry-After`, `X-RateLimit-Remaining: 0` or a rate limit message.
- Wait for the time the service asks for and retry once. A limited request was not carried out, so
  repeating a write cannot duplicate it.
- If the wait would exceed `max_rate_limit_wait`, which defaults to 120 seconds, or the retry is limited
  too, send nothing more to that destination for the rest of the run. Other destinations continue.
- Report skipped work and fail the run, so nothing is mistaken for success. The next scan catches up.

## Consequences

- A limited destination no longer delays or blocks the others.
- A scan can take longer because it waits, up to the limit for each request, within the job's timeout.
- A large backlog can need more than one scan to deliver, and those scans exit with 1.
- Each destination is limited on its own, even if several clients share one account's limit.
