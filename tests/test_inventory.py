from pathlib import Path

import pytest

from infra_vuln_watch.inventory import load_inventory, load_item

GOOD = 'name: a\nrepo: o/a\nversion: "1.2.3"\nowner: me\nvendor: o\nproduct: a\n'


def write(tmp_path, text):
    path = tmp_path / "item.yaml"
    path.write_text(text)
    return path


def test_good_file_defaults_keyword_and_display_name_to_name(tmp_path):
    item = load_item(write(tmp_path, GOOD))
    assert item["keyword"] == "a"
    assert item["display_name"] == "a"


def test_missing_field(tmp_path):
    with pytest.raises(ValueError, match="owner"):
        load_item(write(tmp_path, GOOD.replace("owner: me\n", "")))


def test_unquoted_version_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="quotes"):
        load_item(write(tmp_path, GOOD.replace('"1.2.3"', "2.10")))


def test_empty_directory(tmp_path):
    with pytest.raises(ValueError):
        load_inventory(tmp_path)


def test_real_inventory_is_valid():
    assert load_inventory(Path(__file__).parents[1] / "inventory")[0]["name"] == "openbao"


def test_name_with_spaces_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="spaces"):
        load_item(write(tmp_path, GOOD.replace("name: a", "name: my tool")))


def test_duplicate_names_are_rejected(tmp_path):
    (tmp_path / "one.yaml").write_text(GOOD)
    (tmp_path / "two.yaml").write_text(GOOD)
    with pytest.raises(ValueError, match="Two inventory files"):
        load_inventory(tmp_path)
