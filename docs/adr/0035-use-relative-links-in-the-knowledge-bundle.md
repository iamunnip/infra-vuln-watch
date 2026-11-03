# 0035. Use relative links in the knowledge bundle

Date: 2026-11-03

Status: Accepted

## Context

The bundle in `knowledge/` used links with a leading `/`, which the OKF specification recommends and reads
from the bundle root. GitHub reads the same links from the repository root, so 50 links led to a 404 page
for anyone browsing there. The documentation check also read them from the bundle root, so it passed.

## Decision

- Use relative links in `knowledge/`. The specification allows them, and they work both on GitHub and for
  OKF consumers.
- The documentation check resolves links the way GitHub does and rejects a leading `/` link in the bundle,
  even if the repository root happens to hold that file.
- It covers Markdown files anywhere in the repository, not only the root, `docs/` and `knowledge/`.
- It also requires files named in plain text, and files in this repository's own GitHub URLs, to exist.
  Tests are skipped because they hold made-up paths, and ADRs are skipped for plain paths because they are history.
- `tests/test_docs.py` runs the check against the repository itself, so `pytest` finds these problems too.

## Consequences

- Links work where people follow them, and the same mistake now fails CI.
- This departs from the form the specification recommends, so moving a file means updating its relative
  links. The check reports any that it misses.
- Other remote URLs are still not checked, because that needs a network and would make tests flaky.
- A guide that names a file for the reader to create must be listed as an example in the check.
