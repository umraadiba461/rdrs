import pytest

from app.core.config import load_config


def test_load_default_config():
    s = load_config("config.yaml")
    assert s.simulation_mode is True
    assert s.weights.rapid_encryption == 40


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config("nope.yaml")
