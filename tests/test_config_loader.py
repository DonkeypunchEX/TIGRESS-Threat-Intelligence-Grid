import pytest

from src.utils.config_loader import ConfigLoader


def test_load_yaml_returns_dict(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("a: 1\nb: two\n")
    assert ConfigLoader.load_yaml(str(p)) == {"a": 1, "b": "two"}


def test_load_yaml_empty_file_returns_empty_dict(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    assert ConfigLoader.load_yaml(str(p)) == {}


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ConfigLoader.load_yaml(str(tmp_path / "nope.yaml"))
