from __future__ import annotations

from midas_dev.main import CommonCLITool
from midas_dev.utils import TCfg


class TestCLITool(CommonCLITool):
    concatenated_list_paths = (("root_list",),)


COMMON_CONFIG: TCfg = {"root_list": [11, 22]}


def test_list_merge_empty() -> None:
    merge_empty = TestCLITool.merge_configs(COMMON_CONFIG, {})
    assert merge_empty == COMMON_CONFIG

    merge_empty_replace = TestCLITool.merge_configs(COMMON_CONFIG, {"root_list__replace": True})
    assert merge_empty_replace == COMMON_CONFIG


def test_list_merge_some() -> None:
    cfg: TCfg = {"root_list": [22, 33]}
    merge_some = TestCLITool.merge_configs(COMMON_CONFIG, cfg)
    assert merge_some == {"root_list": [11, 22, 22, 33]}


def test_list_merge_replace() -> None:
    cfg: TCfg = {"root_list": [22, 33], "root_list__replace": True}
    merge_replace = TestCLITool.merge_configs(COMMON_CONFIG, cfg)
    assert merge_replace == {"root_list": [22, 33]}
