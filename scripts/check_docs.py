"""Check local documentation links, heading anchors and repository OKF conventions.

Links are resolved the way GitHub resolves them when someone reads the file there, because that is
where people follow them. Files named in plain text and this repository's own GitHub URLs are checked too.

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
SKIPPED_FOLDERS = {'.git', '.venv', 'node_modules', '.pytest_cache', 'build', 'dist', '__pycache__'}
TEXT_SUFFIXES = {'.md', '.py', '.yaml', '.yml', '.toml', '.mjs'}
FILE_MENTION = re.compile(
    r'(?<![\w./\-])((?:docs|knowledge|scripts|src|tests|inventory|\.github)/[\w./\-]*\w\.(?:md|py|ya?ml|mjs|json|toml))')
OWN_GITHUB_URL = re.compile(
    r'github\.com/iamunnip/infra-vuln-watch/(?:(?:blob|tree)/[^/\s)>"\']+/([^\s)>"\'#?]+)'
    r'|actions/workflows/([^\s)>"\'#?/]+))')
# A file that a guide tells the reader to create.
EXAMPLE_FILES = {'inventory/vault.yaml'}


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


def repository_files(root, suffixes):
    return sorted(path for path in root.rglob('*') if path.is_file() and path.suffix in suffixes
                  and not SKIPPED_FOLDERS & set(path.relative_to(root).parts))


def check_mentions(root):
    """Report files named in plain text, and files in this repository's own URLs, that do not exist.

    Tests hold made-up paths, so they are skipped. ADRs are a historical record, so their plain paths are too.
    """
    errors = []
    for path in repository_files(root, TEXT_SUFFIXES):
        label = path.relative_to(root)
        if label.parts[0] == 'tests':
            continue
        text = path.read_text(encoding='utf-8')
        if label.parts[:2] != ('docs', 'adr'):
            for mention in FILE_MENTION.findall(text):
                if mention not in EXAMPLE_FILES and not (root / mention).exists():
                    errors.append(f'{label}: names a file that does not exist: {mention}')
        for blob, workflow in OWN_GITHUB_URL.findall(text):
            target = blob or f'.github/workflows/{workflow}'
            if not (root / unquote(target)).exists():
                errors.append(f'{label}: links to a repository file that does not exist: {target}')
    return errors


def check(root):
    root = root.resolve()
    knowledge = root / 'knowledge'
    files = repository_files(root, {'.md'})
    errors = check_mentions(root)
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
                # GitHub reads these from the repository root, not from the OKF bundle root.
                if path.is_relative_to(knowledge):
                    errors.append(f'{label}: leading / link is not found on GitHub, use a relative path: {target}')
                    continue
                destination = root / name.lstrip('/')
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
