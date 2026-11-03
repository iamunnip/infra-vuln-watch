"""The scan workflow installs requirements.txt, so it must agree with pyproject.toml."""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def normalise(requirement):
    return re.sub(r'[-_.]+', '-', requirement).lower()


def test_lockfile_pins_the_declared_runtime_dependencies():
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
    locked = {normalise(line.split(' ')[0]) for line in (ROOT / 'requirements.txt').read_text(encoding='utf-8').splitlines()
              if re.match(r'[A-Za-z0-9]', line)}
    assert {normalise(requirement) for requirement in project['dependencies']} <= locked


def test_every_locked_package_has_a_hash():
    text = (ROOT / 'requirements.txt').read_text(encoding='utf-8')
    packages = re.findall(r'^[A-Za-z0-9][^\s]*==[^\s]+', text, re.MULTILINE)
    assert packages
    assert all(f'{package} \\\n    --hash=sha256:' in text for package in packages)


def test_setuptools_is_locked_for_the_offline_build():
    text = (ROOT / 'requirements.txt').read_text(encoding='utf-8')
    assert re.search(r'^setuptools==', text, re.MULTILINE)
