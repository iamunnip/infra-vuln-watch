"""Check local documentation links, heading anchors and repository OKF conventions.

Run from any directory: python scripts/check_docs.py
This is a repository check, not a complete Markdown parser or OKF specification validator.
"""

from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?\[[^\]\n]*\]\(<?([^\s>)]+)>?(?:\s+"[^"]*")?\)')
REFERENCE = re.compile(r'^ {0,3}\[[^\]\n]+\]:\s*<?([^\s>]+)>?', re.MULTILINE)


def prose(text, keep_inline=False):
    """Ignore fenced examples and inline code when finding links and headings."""
    lines = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            lines.append('')
        elif fence is None:
            lines.append(line if keep_inline else re.sub(r'(`+).*?\1', '', line))
        else:
            lines.append('')
    return '\n'.join(lines)


def anchors(text):
    """GitHub-style IDs for ATX headings, including duplicate suffixes."""
    result = set()
    counts = {}
    # Preserve inline code text in headings, which GitHub includes in the ID.
    for line in prose(text, keep_inline=True).splitlines():
        match = re.match(r'^ {0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$', line)
        if not match:
            continue
        heading = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', match[1])
        heading = re.sub(r'<[^>]*>', '', heading)
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        suffix = counts.get(slug, 0)
        candidate = f'{slug}-{suffix}' if suffix else slug
        while candidate in result:
            suffix += 1
            candidate = f'{slug}-{suffix}'
        counts[slug] = suffix + 1
        result.add(candidate)
    return result


def metadata(text):
    if not text.startswith('---\n'):
        raise ValueError('missing YAML frontmatter')
    end = re.search(r'^---\s*$', text[4:], re.MULTILINE)
    if not end:
        raise ValueError('unclosed YAML frontmatter')
    data = yaml.safe_load(text[4:4 + end.start()])
    if not isinstance(data, dict):
        raise ValueError('frontmatter must be a mapping')
    return data


def check(root):
    root = root.resolve()
    knowledge = root / 'knowledge'
    files = sorted(set(root.glob('*.md')) | set((root / 'docs').rglob('*.md'))
                   | set(knowledge.rglob('*.md')))
    errors = []
    for path in files:
        text = path.read_text(encoding='utf-8')
        label = path.relative_to(root)
        if path.is_relative_to(knowledge):
            try:
                if path == knowledge / 'index.md':
                    if str(metadata(text).get('okf_version')) != '0.2':
                        raise ValueError('bundle index must declare okf_version: "0.2"')
                elif path.name not in {'index.md', 'log.md'}:
                    data = metadata(text)
                    for key in ('type', 'title', 'description'):
                        if not isinstance(data.get(key), str) or not data[key].strip():
                            raise ValueError(f'concept requires non-empty string {key}')
            except (ValueError, yaml.YAMLError) as error:
                errors.append(f'{label}: {error}')
        body = prose(text)
        targets = [m[1] for m in LINK.finditer(body)] + REFERENCE.findall(body)
        for target in targets:
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            name = unquote(url.path)
            if name.startswith('/'):
                base = knowledge if path.is_relative_to(knowledge) else root
                destination = base / name.lstrip('/')
            else:
                destination = path.parent / name if name else path
            destination = destination.resolve()
            if not destination.is_relative_to(root):
                errors.append(f'{label}: link escapes repository: {target}')
            elif not destination.exists():
                errors.append(f'{label}: missing link target: {target}')
            elif url.fragment and destination.suffix == '.md':
                if unquote(url.fragment) not in anchors(destination.read_text(encoding='utf-8')):
                    errors.append(f'{label}: missing heading anchor: {target}')
    for required in (knowledge / 'index.md', knowledge / 'log.md'):
        if not required.is_file():
            errors.append(f'{required.relative_to(root)}: required OKF bundle file missing')
    return errors


def main():
    errors = check(ROOT)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Documentation links, heading anchors and OKF metadata checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
