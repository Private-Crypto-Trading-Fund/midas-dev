from __future__ import annotations

from midas_dev import main


def test_stuff():
    assert main.Flake8.config_ext == "cfg"
