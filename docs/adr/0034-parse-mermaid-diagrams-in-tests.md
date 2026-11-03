# 0034. Parse Mermaid diagrams in tests

Date: 2026-11-03

Status: Accepted

## Context

The documentation check did not read Mermaid, so a diagram could be merged that GitHub could not draw. A
semicolon in a sequence diagram message did this to the runtime view, and it stayed unnoticed through
several pull requests. Only the Mermaid parser, which runs on Node.js, can reliably say whether a diagram
is valid.

## Decision

`tests/test_mermaid.py` finds every Mermaid block in the repository's Markdown files and parses each one with
the real parser, as its own test case. The parser and jsdom are pinned in `scripts/mermaid`, with a
lockfile, and are installed in the tests workflow with install scripts turned off.

Without Node.js the parser tests skip on a local machine, because this is a Python project, but they fail
in CI so that they cannot be lost by accident. A semicolon check for sequence diagrams needs no Node.js and
always runs. Tests also confirm that the parser rejects the original mistake.

## Consequences

- A diagram with a syntax error fails CI, and new diagrams are covered without changing any test.
- The project now has a small Node.js dependency for development, which Dependabot watches. The scan job does
  not use it.
- The tests parse diagrams without drawing them, so a diagram can pass and still look wrong.
- GitHub may run a different Mermaid version from the pinned one, so a rare difference is possible.
